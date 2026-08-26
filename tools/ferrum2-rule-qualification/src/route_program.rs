use std::sync::Arc;
use std::time::Instant;

use ferrum2_core::route::Network;
use ferrum2_core::{DomainName, TargetAddr};
use ferrum2_rule::{
    MatchSetBuilder, OrderedRouteProgram, OrderedRouteRule, RouteMatchField, RouteMatchObservation,
    RouteMatchSource, RouteMatchType, RouteMatcher, RouteMetadata, RouteProgramAction,
    RouteRuleAction, RuleEngineSnapshot, RuleEngineSnapshotBuilder, RuleProgramMode,
};

use crate::cli::{QualificationError, Result};
use crate::measurement::allocation::{allocation_region, finish_build};
use crate::measurement::statistics::measurement;
use crate::measurement::timing::{benchmark, benchmark_operation_pair};
use crate::report::{BuildEvidence, Measurement};

#[cfg(test)]
use crate::measurement::allocation::allocator_test_lock;

#[derive(Clone, Copy)]
pub(crate) enum RouteSource {
    Ordinary,
    RuleSet,
    Mixed,
}

pub(crate) struct RouteFixture {
    pub(crate) program: OrderedRouteProgram<(), usize>,
    pub(crate) snapshot: Option<Arc<RuleEngineSnapshot>>,
    build: BuildEvidence,
}

pub(crate) fn run_route_programs(
    sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &count in sizes {
        let ordinary = build_route_fixture(count, RouteSource::Ordinary)?;
        let ruleset = build_route_fixture(count, RouteSource::RuleSet)?;
        let mixed = build_route_fixture(count, RouteSource::Mixed)?;
        let expected_mode = if count <= 64 {
            RuleProgramMode::SmallLinear
        } else {
            RuleProgramMode::Indexed
        };
        if [
            ordinary.program.mode(),
            ruleset.program.mode(),
            mixed.program.mode(),
        ]
        .into_iter()
        .any(|mode| mode != expected_mode)
        {
            return Err(QualificationError::new(
                "route program selected an unexpected execution mode",
            ));
        }
        let iterations = scaled_iterations(base_iterations, 1, count);
        let mut ordinary_scratch = ordinary.program.evaluation_scratch().map_err(|error| {
            QualificationError::new(format!("ordinary route scratch failed: {error}"))
        })?;
        let mut ruleset_scratch = ruleset.program.evaluation_scratch().map_err(|error| {
            QualificationError::new(format!("RuleSet route scratch failed: {error}"))
        })?;
        let mut mixed_scratch = mixed.program.evaluation_scratch().map_err(|error| {
            QualificationError::new(format!("mixed route scratch failed: {error}"))
        })?;
        let reserved = [
            ordinary_scratch.reserved_words(),
            ruleset_scratch.reserved_words(),
            mixed_scratch.reserved_words(),
        ];
        for (case, position) in [
            ("first", Some(0_usize)),
            ("middle", Some(count / 2)),
            ("last", Some(count - 1)),
            ("miss", None),
        ] {
            let index = position.unwrap_or(count);
            let target = TargetAddr::domain(&format!("route-{index}.bench.invalid"), 443)
                .map_err(|_| QualificationError::new("route target is invalid"))?;
            let expected = position.unwrap_or(usize::MAX);
            for (source, fixture, scratch) in [
                ("ordinary_only", &ordinary, &mut ordinary_scratch),
                ("ruleset_only", &ruleset, &mut ruleset_scratch),
                ("mixed", &mixed, &mut mixed_scratch),
            ] {
                let actual = evaluate_route(
                    &fixture.program,
                    fixture.snapshot.as_ref(),
                    &target,
                    index,
                    scratch,
                );
                if actual != expected {
                    return Err(QualificationError::new(format!(
                        "route {source}/{count}/{case} returned {actual}, expected {expected}"
                    )));
                }
            }

            let scenario = format!(
                "{}/{case}",
                match expected_mode {
                    RuleProgramMode::SmallLinear => "small_linear",
                    RuleProgramMode::Indexed => "indexed",
                }
            );
            let (ordinary_result, ruleset_result) = benchmark_operation_pair(
                || {
                    evaluate_route(
                        &ordinary.program,
                        ordinary.snapshot.as_ref(),
                        &target,
                        index,
                        &mut ordinary_scratch,
                    ) as u64
                },
                || {
                    evaluate_route(
                        &ruleset.program,
                        ruleset.snapshot.as_ref(),
                        &target,
                        index,
                        &mut ruleset_scratch,
                    ) as u64
                },
                samples,
                iterations,
                format!("route_program/{count}/{scenario}"),
            );
            let mixed_result = benchmark(
                || {
                    evaluate_route(
                        &mixed.program,
                        mixed.snapshot.as_ref(),
                        &target,
                        index,
                        &mut mixed_scratch,
                    ) as u64
                },
                samples,
                iterations,
            );
            for (source, build, result) in [
                ("ordinary_only", ordinary.build, ordinary_result),
                ("ruleset_only", ruleset.build, ruleset_result),
                ("mixed", mixed.build, mixed_result),
            ] {
                measurements.push(measurement(
                    format!("route_program/{source}/{count}/{scenario}"),
                    "route_program",
                    source,
                    scenario.clone(),
                    count,
                    None,
                    Some(expected_mode),
                    iterations,
                    build,
                    Some(count),
                    result,
                ));
            }
        }
        // Production enables category observation for every Route evaluation,
        // so every profile exercises the selected-rule category recheck.
        for (case, index) in [("first_observed", 0_usize), ("last_observed", count - 1)] {
            let target = TargetAddr::domain(&format!("route-{index}.bench.invalid"), 443)
                .map_err(|_| QualificationError::new("observed route target is invalid"))?;
            let actual = evaluate_route_observed(
                &mixed.program,
                mixed.snapshot.as_ref(),
                &target,
                index,
                &mut mixed_scratch,
            );
            if actual.selected != index {
                return Err(QualificationError::new(format!(
                    "observed route {count}/{case} returned {}, expected {index}",
                    actual.selected
                )));
            }
            let scenario = format!(
                "{}/{case}",
                match expected_mode {
                    RuleProgramMode::SmallLinear => "small_linear",
                    RuleProgramMode::Indexed => "indexed",
                }
            );
            let result = benchmark(
                || {
                    evaluate_route_observed(
                        &mixed.program,
                        mixed.snapshot.as_ref(),
                        &target,
                        index,
                        &mut mixed_scratch,
                    )
                    .checksum()
                },
                samples,
                iterations,
            );
            measurements.push(measurement(
                format!("route_program/mixed_observed/{count}/{scenario}"),
                "route_program",
                "mixed_observed",
                scenario,
                count,
                None,
                Some(expected_mode),
                iterations,
                mixed.build,
                Some(count),
                result,
            ));
        }
        if ordinary_scratch.reserved_words() != reserved[0]
            || ruleset_scratch.reserved_words() != reserved[1]
            || mixed_scratch.reserved_words() != reserved[2]
        {
            return Err(QualificationError::new(
                "route evaluation scratch grew on the measured path",
            ));
        }
    }
    Ok(())
}

pub(crate) fn build_route_fixture(count: usize, source: RouteSource) -> Result<RouteFixture> {
    let allocation_region = allocation_region();
    let started = Instant::now();
    let mut snapshot_builder = RuleEngineSnapshotBuilder::new(1);
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(count)
        .map_err(|_| QualificationError::new("route fixture allocation failed"))?;
    for index in 0..count {
        let mut fields = Vec::new();
        if matches!(source, RouteSource::Ordinary | RouteSource::Mixed) {
            fields.push(RouteMatchField::Domain(vec![
                DomainName::new(&format!("route-{index}.bench.invalid")).map_err(|_| {
                    QualificationError::new("route ordinary domain value is invalid")
                })?,
            ]));
        }
        if matches!(source, RouteSource::RuleSet | RouteSource::Mixed) {
            let mut builder = MatchSetBuilder::new();
            builder
                .add_exact_domain(&format!("route-{index}.bench.invalid"))
                .map_err(|error| {
                    QualificationError::new(format!("route MatchSet value failed: {error}"))
                })?;
            let match_set = snapshot_builder
                .add_match_set(builder.build().map_err(|error| {
                    QualificationError::new(format!("route MatchSet build failed: {error}"))
                })?)
                .map_err(|error| {
                    QualificationError::new(format!("route snapshot add failed: {error}"))
                })?;
            let rule_set = snapshot_builder
                .add_rule_set(&format!("route-{index}"), match_set)
                .map_err(|error| {
                    QualificationError::new(format!("route RuleSet add failed: {error}"))
                })?;
            fields.push(RouteMatchField::RuleSet(vec![rule_set]));
        }
        let matcher = RouteMatcher::try_new(fields).map_err(|error| {
            QualificationError::new(format!("route matcher build failed: {error}"))
        })?;
        rules.push(OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal(index),
        ));
    }
    let program = OrderedRouteProgram::try_new(rules, usize::MAX)
        .map_err(|error| QualificationError::new(format!("route program build failed: {error}")))?;
    let snapshot = if matches!(source, RouteSource::Ordinary) {
        None
    } else {
        Some(Arc::new(snapshot_builder.build().map_err(|error| {
            QualificationError::new(format!("route snapshot build failed: {error}"))
        })?))
    };
    let build = finish_build(started, &allocation_region)?;
    Ok(RouteFixture {
        program,
        snapshot,
        build,
    })
}

pub(crate) fn evaluate_route(
    program: &OrderedRouteProgram<(), usize>,
    snapshot: Option<&Arc<RuleEngineSnapshot>>,
    target: &TargetAddr,
    inbound: usize,
    scratch: &mut ferrum2_rule::RuleEvaluationScratch,
) -> usize {
    let action = match snapshot {
        Some(snapshot) => {
            let mut evaluation = program.evaluate_with_snapshot_and_scratch(
                inbound,
                Network::Tcp,
                target,
                Arc::clone(snapshot),
                scratch,
            );
            evaluation.next(RouteMetadata::new(None, None))
        }
        None => {
            let mut evaluation =
                program.evaluate_with_scratch(inbound, Network::Tcp, target, scratch);
            evaluation.next(RouteMetadata::new(None, None))
        }
    };
    match action {
        Some(RouteProgramAction::Terminal(value)) | Some(RouteProgramAction::Final(value)) => {
            *value
        }
        Some(RouteProgramAction::Continue(_)) | None => usize::MAX - 1,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ObservedRouteOutcome {
    selected: usize,
    telemetry: u64,
}

impl ObservedRouteOutcome {
    fn checksum(self) -> u64 {
        u64::try_from(self.selected)
            .unwrap_or(u64::MAX)
            .wrapping_mul(4_099)
            ^ self.telemetry
    }
}

pub(crate) fn evaluate_route_observed(
    program: &OrderedRouteProgram<(), usize>,
    snapshot: Option<&Arc<RuleEngineSnapshot>>,
    target: &TargetAddr,
    inbound: usize,
    scratch: &mut ferrum2_rule::RuleEvaluationScratch,
) -> ObservedRouteOutcome {
    match snapshot {
        Some(snapshot) => {
            let mut evaluation = program.evaluate_with_snapshot_and_scratch(
                inbound,
                Network::Tcp,
                target,
                Arc::clone(snapshot),
                scratch,
            );
            evaluation.enable_match_observation();
            let action = evaluation.next(RouteMetadata::new(None, None));
            finish_observed_route(action, evaluation.last_match_observation())
        }
        None => {
            let mut evaluation =
                program.evaluate_with_scratch(inbound, Network::Tcp, target, scratch);
            evaluation.enable_match_observation();
            let action = evaluation.next(RouteMetadata::new(None, None));
            finish_observed_route(action, evaluation.last_match_observation())
        }
    }
}

pub(crate) fn finish_observed_route(
    action: Option<RouteProgramAction<'_, usize>>,
    observation: RouteMatchObservation,
) -> ObservedRouteOutcome {
    let mut telemetry = 0_u64;
    for source in RouteMatchSource::ALL {
        for r#type in RouteMatchType::ALL {
            telemetry = telemetry.rotate_left(3)
                ^ u64::from(observation.evaluated(source, r#type))
                ^ (u64::from(observation.matched(source, r#type)) << 1);
        }
    }
    let selected = match action {
        Some(RouteProgramAction::Terminal(value)) | Some(RouteProgramAction::Final(value)) => {
            *value
        }
        Some(RouteProgramAction::Continue(_)) | None => usize::MAX - 1,
    };
    ObservedRouteOutcome {
        selected,
        telemetry,
    }
}

pub(crate) fn scaled_iterations(base: u64, numerator: usize, scale: usize) -> u64 {
    let numerator = u64::try_from(numerator).unwrap_or(u64::MAX);
    let scale = u64::try_from(scale).unwrap_or(u64::MAX);
    base.saturating_mul(numerator)
        .checked_div(scale)
        .unwrap_or(1)
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_mode_boundary_and_ruleset_evaluation_are_callable() {
        let _guard = allocator_test_lock();
        let small = build_route_fixture(64, RouteSource::RuleSet).expect("small route");
        let indexed = build_route_fixture(65, RouteSource::Mixed).expect("indexed route");
        assert_eq!(small.program.mode(), RuleProgramMode::SmallLinear);
        assert_eq!(indexed.program.mode(), RuleProgramMode::Indexed);

        let target = TargetAddr::domain("route-64.bench.invalid", 443).expect("target");
        let mut scratch = indexed.program.evaluation_scratch().expect("scratch");
        assert_eq!(
            evaluate_route(
                &indexed.program,
                indexed.snapshot.as_ref(),
                &target,
                64,
                &mut scratch,
            ),
            64
        );
        let measured = benchmark(
            || {
                evaluate_route(
                    &indexed.program,
                    indexed.snapshot.as_ref(),
                    &target,
                    64,
                    &mut scratch,
                ) as u64
            },
            5,
            32,
        );
        assert_eq!(measured.samples.len(), 5);
        assert_eq!(measured.allocation_samples.len(), 5);
        assert!(
            measured
                .allocation_samples
                .iter()
                .all(|sample| sample.iterations == 1)
        );
    }

    #[test]
    fn every_route_scale_covers_enabled_production_match_observation() {
        let _guard = allocator_test_lock();
        let mut rows = Vec::new();
        run_route_programs(&[64, 1_000], 5, 1, &mut rows).expect("route observation evidence");
        let observed = rows
            .iter()
            .filter(|row| row.source == "mixed_observed")
            .collect::<Vec<_>>();
        assert_eq!(observed.len(), 4);
        assert!(
            observed.iter().all(|row| {
                row.allocation_gate_passed == Some(true) && row.outcome_checksum != 0
            })
        );
        assert_eq!(
            observed
                .iter()
                .filter(|row| { row.scale == 64 && row.rule_program_mode == Some("small_linear") })
                .count(),
            2
        );
        assert_eq!(
            observed
                .iter()
                .filter(|row| row.scale == 1_000 && row.rule_program_mode == Some("indexed"))
                .count(),
            2
        );
    }
}
