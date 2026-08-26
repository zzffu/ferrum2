use super::contract::{
    ExecutionResult, PARTIAL_ACTIVE_FLOWS, Phase, PhaseKind, SESSIONS, ScaleCommand, TOUCH_ROUNDS,
    initialize_payload,
};
use super::flow::{
    await_task_readiness, collect_phase, join_tasks, run_application_flow, run_target_flow,
    validate_phase_accounting,
};
use super::setup::{collect_active_samples, collect_quiescent_samples, release_phase};
use crate::m4_support::process_support::{ProcessGuard, clean_io};
use crate::m4_support::profile_contract::{ProfileArgs, ProfileScenario, ReadyFile};
use crate::m4_support::resource_sampling::PairSample;
use std::net::{SocketAddrV4, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{mpsc as tokio_mpsc, watch};
use tokio::task::JoinSet;

pub(crate) fn to_tokio_streams(streams: Vec<TcpStream>) -> Result<Vec<TokioTcpStream>, String> {
    streams
        .into_iter()
        .map(|stream| {
            stream.set_nonblocking(true).map_err(clean_io)?;
            TokioTcpStream::from_std(stream).map_err(clean_io)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute(
    applications: Vec<TcpStream>,
    targets: Vec<TcpStream>,
    arguments: &ProfileArgs,
    ready_file: &Path,
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    client_metrics: SocketAddrV4,
    server_metrics: SocketAddrV4,
    owner_identity: PairSample,
) -> Result<ExecutionResult, String> {
    if applications.len() != SESSIONS || targets.len() != SESSIONS {
        return Err("scale executor did not receive exact stream sets".to_owned());
    }
    let applications = to_tokio_streams(applications)?;
    let targets = to_tokio_streams(targets)?;
    let (commands, receiver) = watch::channel(ScaleCommand::Idle);
    let (result_sender, mut result_receiver) = tokio_mpsc::channel(SESSIONS);
    let (application_ready_sender, mut application_ready_receiver) = tokio_mpsc::channel(SESSIONS);
    let (target_ready_sender, mut target_ready_receiver) = tokio_mpsc::channel(SESSIONS);
    let (error_sender, mut error_receiver) = tokio_mpsc::unbounded_channel();
    let payload = initialize_payload();
    let mut application_tasks = JoinSet::new();
    for (index, stream) in applications.into_iter().enumerate() {
        let task_errors = error_sender.clone();
        let task_payload = Arc::clone(&payload);
        let task = run_application_flow(
            index,
            stream,
            receiver.clone(),
            result_sender.clone(),
            application_ready_sender.clone(),
            task_payload,
        );
        application_tasks.spawn(async move {
            let result = task.await;
            if let Err(error) = &result {
                let _ = task_errors.send(format!("scale application task {index}: {error}"));
            }
            result
        });
    }
    drop(receiver);
    drop(result_sender);
    drop(application_ready_sender);
    let mut target_tasks = JoinSet::new();
    for (index, stream) in targets.into_iter().enumerate() {
        let task_errors = error_sender.clone();
        let task_ready = target_ready_sender.clone();
        target_tasks.spawn(async move {
            let result = run_target_flow(index, stream, task_ready).await;
            if let Err(error) = &result {
                let _ = task_errors.send(format!("scale target task {index}: {error}"));
            }
            result
        });
    }
    drop(target_ready_sender);
    drop(error_sender);

    let execution = async {
        await_task_readiness(
            "application",
            SESSIONS,
            &mut application_ready_receiver,
            &mut error_receiver,
        )
        .await?;
        await_task_readiness(
            "target",
            SESSIONS,
            &mut target_ready_receiver,
            &mut error_receiver,
        )
        .await?;
        let mut harness_peak = 0_u64;
        let established = collect_quiescent_samples(
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;

        let touch_phase = Phase::new(1, PhaseKind::Touch, None);
        commands
            .send(ScaleCommand::Run(Arc::clone(&touch_phase)))
            .map_err(|_| "scale application tasks ended before touch".to_owned())?;
        release_phase(&touch_phase, &mut error_receiver).await?;
        let touch = collect_phase(&touch_phase, &mut result_receiver, &mut error_receiver).await?;
        validate_phase_accounting(&touch, SESSIONS, true)?;
        let expected_touch_completions =
            u64::try_from(SESSIONS * TOUCH_ROUNDS).expect("touch completion count fits u64");
        if touch.completions != expected_touch_completions {
            return Err("scale touch did not complete two rounds on every flow".to_owned());
        }
        let touched = collect_quiescent_samples(
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;

        let partial_duration = Duration::from_secs(arguments.warmup_seconds);
        let partial_phase = Phase::new(2, PhaseKind::Partial, Some(partial_duration));
        commands
            .send(ScaleCommand::Run(Arc::clone(&partial_phase)))
            .map_err(|_| "scale application tasks ended before partial phase".to_owned())?;
        let partial_started = release_phase(&partial_phase, &mut error_receiver).await?;
        let partial_active = collect_active_samples(
            partial_started,
            partial_duration,
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;
        let partial =
            collect_phase(&partial_phase, &mut result_receiver, &mut error_receiver).await?;
        validate_phase_accounting(&partial, PARTIAL_ACTIVE_FLOWS, false)?;

        let full_duration = Duration::from_secs(arguments.active_seconds);
        let full_phase = Phase::new(3, PhaseKind::Full, Some(full_duration));
        commands
            .send(ScaleCommand::Run(Arc::clone(&full_phase)))
            .map_err(|_| "scale application tasks ended before full phase".to_owned())?;
        let full_started = tokio::select! {
            result = full_phase.prepare_release() => result?,
            error = error_receiver.recv() => {
                return Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned()));
            }
        };
        let mut ready = Some(ReadyFile::publish(
            ready_file,
            ProfileScenario::TcpScale10k,
            client.id(),
            Some(server.id()),
            arguments.warmup_seconds,
            arguments.active_seconds,
        )?);
        if Instant::now() >= full_started {
            return Err("scale ready publication missed the common full start".to_owned());
        }
        tokio::select! {
            () = tokio::time::sleep_until(full_started.into()) => {}
            error = error_receiver.recv() => {
                return Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned()));
            }
        }
        let full_active = collect_active_samples(
            full_started,
            full_duration,
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;
        let full_deadline = *full_phase.deadline.get().expect("full phase deadline");
        tokio::time::sleep_until(full_deadline.into()).await;
        ready.take().expect("scale ready owner").remove()?;
        let full = collect_phase(&full_phase, &mut result_receiver, &mut error_receiver).await?;
        validate_phase_accounting(&full, SESSIONS, false)?;
        let full_elapsed =
            full_deadline.duration_since(*full_phase.started.get().expect("full phase start"));
        let post_full = collect_quiescent_samples(
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;
        Ok::<_, String>((
            established,
            touched,
            partial_active,
            full_active,
            post_full,
            touch,
            partial,
            full,
            full_elapsed,
            harness_peak,
        ))
    }
    .await;

    let failed = execution.is_err();
    let _ = commands.send(ScaleCommand::Shutdown);
    if failed {
        application_tasks.abort_all();
    }
    let application_tasks_joined =
        join_tasks(&mut application_tasks, SESSIONS, "application", failed).await;
    let target_tasks_joined = join_tasks(&mut target_tasks, SESSIONS, "target", false).await;
    let joined = match (application_tasks_joined, target_tasks_joined) {
        (Ok(applications), Ok(targets)) => Ok((applications, targets)),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(format!("{first}; {second}")),
    };
    let (execution, joined) = match (execution, joined) {
        (Ok(execution), Ok(joined)) => (execution, joined),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => return Err(error),
        (Err(execution_error), Err(join_error)) => {
            return Err(format!("{execution_error}; cleanup: {join_error}"));
        }
    };
    let (
        established,
        touched,
        partial_active,
        full_active,
        post_full,
        touch,
        partial,
        full,
        full_elapsed,
        harness_peak_rss_kib,
    ) = execution;
    let (application_tasks_joined, target_tasks_joined) = joined;
    Ok(ExecutionResult {
        established,
        touched,
        partial_active,
        full_active,
        post_full,
        touch,
        partial,
        full,
        full_elapsed,
        application_tasks_joined,
        target_tasks_joined,
        harness_peak_rss_kib,
    })
}
