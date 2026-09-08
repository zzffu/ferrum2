use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use super::controller::{ControlRequest, RequestKind};

const HTML: &[u8] = include_bytes!("../../../../ui/dashboard/embedded/index.html");
const CSP: &str = include_str!("../../../../ui/dashboard/embedded/csp.txt");
const MAX_BODY: usize = ferrum2_config::MAX_CONFIG_BYTES * 6 + 4096;
const MAX_CLIENTS: usize = 32;
type Body = Full<Bytes>;

pub(super) struct HttpState {
    pub(super) address: SocketAddr,
    pub(super) token: Vec<u8>,
    pub(super) commands: mpsc::Sender<ControlRequest>,
    pub(super) snapshot: Arc<std::sync::RwLock<Bytes>>,
}

pub(super) async fn serve(
    listener: TcpListener,
    state: Arc<HttpState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), &'static str> {
    let mut clients = JoinSet::new();
    let mut result = Ok(());
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            Some(_) = clients.join_next(), if !clients.is_empty() => {},
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(_) => { result = Err("dashboard.accept"); break; }
                };
                if !peer.ip().is_loopback() || clients.len() >= MAX_CLIENTS { continue; }
                let state = Arc::clone(&state);
                let mut stopped = shutdown.clone();
                clients.spawn(async move {
                    let connection = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(5))
                        .keep_alive(false)
                        .max_headers(32)
                        .max_buf_size(16 * 1024)
                        .serve_connection(TokioIo::new(socket), service_fn(move |request| {
                            handle(request, Arc::clone(&state))
                        }));
                    tokio::select! {
                        _ = stopped.changed() => {},
                        _ = tokio::time::timeout(Duration::from_secs(360), connection) => {},
                    }
                });
            }
        }
    }
    drop(listener);
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    result
}

fn response(status: StatusCode, body: impl Into<Bytes>, content_type: &str) -> Response<Body> {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        content_type.parse().expect("static content type"),
    );
    headers.insert("cache-control", "no-store".parse().expect("static header"));
    headers.insert(
        "x-content-type-options",
        "nosniff".parse().expect("static header"),
    );
    headers.insert(
        "referrer-policy",
        "no-referrer".parse().expect("static header"),
    );
    headers.insert("x-frame-options", "DENY".parse().expect("static header"));
    response
}

fn json_response(status: StatusCode, value: Value) -> Response<Body> {
    response(status, value.to_string(), "application/json; charset=utf-8")
}

fn failure(status: StatusCode, code: &'static str) -> Response<Body> {
    json_response(status, json!({"error":{"code":code}}))
}

fn trusted_request(request: &Request<Incoming>, address: SocketAddr) -> bool {
    let authority = address.to_string();
    let canonical = if address.port() == 80 {
        authority.strip_suffix(":80").unwrap_or(&authority)
    } else {
        &authority
    };
    let host = request.headers().get(HOST).and_then(|h| h.to_str().ok());
    if host != Some(authority.as_str()) && host != Some(canonical) {
        return false;
    }
    // Public static HTML contains no credentials/state. Navigation from another site
    // must work; only private API requests need same-origin fetch metadata.
    if request.method() == Method::GET && request.uri().path() == "/" {
        return true;
    }
    if let Some(origin) = request.headers().get(ORIGIN) {
        let expected = format!("http://{canonical}");
        if origin.to_str().ok() != Some(expected.as_str()) {
            return false;
        }
    }
    if let Some(site) = request.headers().get("sec-fetch-site")
        && !matches!(site.to_str().ok(), Some("same-origin" | "none"))
    {
        return false;
    }
    true
}

async fn handle(
    request: Request<Incoming>,
    state: Arc<HttpState>,
) -> Result<Response<Body>, Infallible> {
    if !trusted_request(&request, state.address) {
        return Ok(failure(StatusCode::FORBIDDEN, "dashboard.origin"));
    }
    if request.method() == Method::GET && request.uri().path() == "/" {
        let mut document = response(
            StatusCode::OK,
            Bytes::from_static(HTML),
            "text/html; charset=utf-8",
        );
        match CSP.trim().parse() {
            Ok(policy) => {
                document
                    .headers_mut()
                    .insert("content-security-policy", policy);
            }
            Err(_) => {
                return Ok(failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "dashboard.asset",
                ));
            }
        }
        return Ok(document);
    }
    if request.method() == Method::GET && request.uri().path() == "/favicon.ico" {
        return Ok(response(
            StatusCode::NO_CONTENT,
            Bytes::new(),
            "image/x-icon",
        ));
    }
    let supplied = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "));
    if !supplied
        .is_some_and(|token| constant_time_eq::constant_time_eq(token.as_bytes(), &state.token))
    {
        return Ok(failure(
            StatusCode::UNAUTHORIZED,
            "dashboard.authentication",
        ));
    }
    let kind = match (request.method(), request.uri().path()) {
        (&Method::GET, "/api/snapshot") => {
            let snapshot = state
                .snapshot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            return Ok(response(
                StatusCode::OK,
                snapshot,
                "application/json; charset=utf-8",
            ));
        }
        (&Method::GET, "/api/config") => RequestKind::Config,
        (&Method::POST, "/api/command") => {
            if request
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.split(';').next())
                .map(str::trim)
                != Some("application/json")
            {
                return Ok(failure(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "dashboard.content_type",
                ));
            }
            let body = match tokio::time::timeout(
                Duration::from_secs(5),
                Limited::new(request.into_body(), MAX_BODY).collect(),
            )
            .await
            {
                Ok(Ok(body)) => body.to_bytes(),
                Ok(Err(_)) => return Ok(failure(StatusCode::PAYLOAD_TOO_LARGE, "dashboard.body")),
                Err(_) => return Ok(failure(StatusCode::REQUEST_TIMEOUT, "dashboard.timeout")),
            };
            let value = match serde_json::from_slice::<Value>(&body) {
                Ok(value) if value.is_object() => value,
                _ => return Ok(failure(StatusCode::BAD_REQUEST, "dashboard.json")),
            };
            RequestKind::Command(value)
        }
        _ => return Ok(failure(StatusCode::NOT_FOUND, "dashboard.not_found")),
    };
    let (reply, result) = oneshot::channel();
    if state
        .commands
        .try_send(ControlRequest {
            kind,
            reply,
            submitted: std::time::Instant::now(),
        })
        .is_err()
    {
        return Ok(failure(StatusCode::TOO_MANY_REQUESTS, "dashboard.busy"));
    }
    let response = match result.await {
        Ok(Ok(value)) => json_response(StatusCode::OK, value),
        Ok(Err(code)) => failure(error_status(code), code),
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "dashboard.stopping"),
    };
    Ok(response)
}

fn error_status(code: &'static str) -> StatusCode {
    if code.contains("conflict") || code.contains("generation") || code.contains("revision") {
        StatusCode::CONFLICT
    } else if code.contains("unavailable") || code.contains("stopped") {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    }
}
