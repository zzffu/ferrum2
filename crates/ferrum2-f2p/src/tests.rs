use super::*;
use base64::Engine;
use std::{fs, path::Path};

const CERT: &[u8] = include_bytes!("../../../tests/fixtures/dns-tls/m12-resolver-test.der");
const KEY: &[u8] = include_bytes!("../../../tests/fixtures/dns-tls/m12-resolver-test.pk8");
const ROOT: &[u8] = include_bytes!("../../../tests/fixtures/dns-tls/m12-test-ca.der");

fn pem(path: &Path, label: &str, der: &[u8]) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    fs::write(
        path,
        format!("-----BEGIN {label}-----\n{encoded}\n-----END {label}-----\n"),
    )
    .unwrap();
}
pub(super) fn configs(
    wrong_token: bool,
    name: &str,
    trusted: bool,
) -> (ClientConfig, ServerConfig) {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    let other = dir.path().join("other");
    let cert = dir.path().join("cert");
    let key = dir.path().join("key");
    let root = dir.path().join("root");
    fs::write(
        &token,
        base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
    )
    .unwrap();
    fs::write(
        &other,
        base64::engine::general_purpose::STANDARD.encode([8u8; 32]),
    )
    .unwrap();
    pem(&cert, "CERTIFICATE", CERT);
    pem(&key, "PRIVATE KEY", KEY);
    pem(&root, "CERTIFICATE", ROOT);
    let mut client = ClientConfig::load(
        if wrong_token { &other } else { &token },
        name,
        trusted.then_some(root.as_path()),
    )
    .unwrap();
    // Deterministic certificate-time validation, retaining the real verifier.
    #[derive(Debug)]
    struct Time;
    impl rustls::time_provider::TimeProvider for Time {
        fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
            Some(rustls::pki_types::UnixTime::since_unix_epoch(
                Duration::from_secs(1_785_974_400),
            ))
        }
    }
    Arc::make_mut(&mut client.tls).time_provider = Arc::new(Time);
    (client, ServerConfig::load(&token, &cert, &key).unwrap())
}
use std::sync::Arc;

#[tokio::test]
async fn tcp_relay_preserves_half_close_and_raw_bytes() {
    let (client, server) = configs(false, "resolver.test", true);
    let (left, right) = tokio::io::duplex(128);
    let target = TargetAddr::domain("destination.test", 80).unwrap();
    let server_target = target.clone();
    let server = async move {
        let Accepted::Tcp {
            mut stream,
            target,
            profile,
        } = accept(right, &server).await.unwrap()
        else {
            panic!("TCP mode");
        };
        assert_eq!(target, server_target);
        assert_eq!(profile, Profile::Realtime);
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request without F2P frames");
        respond_tcp(&mut stream, Ok("127.0.0.1:8080".parse().unwrap()))
            .await
            .unwrap();
        stream
            .write_all(b"response after request EOF")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    };
    let client = async move {
        let mut stream = connect_tcp(left, &client, Profile::Realtime, &target)
            .await
            .unwrap();
        stream
            .write_all(b"request without F2P frames")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response after request EOF");
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(client, server);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wrong_token_and_invalid_certificates_never_accept() {
    for (wrong_token, name, trusted) in [
        (true, "resolver.test", true),
        (false, "wrong.test", true),
        (false, "resolver.test", false),
    ] {
        let (client, server) = configs(wrong_token, name, trusted);
        let (left, right) = tokio::io::duplex(8192);
        let (client, server) = tokio::join!(
            connect_udp(left, &client, Profile::Balanced),
            accept(right, &server)
        );
        assert!(client.is_err());
        assert!(server.is_err());
    }
}

#[tokio::test]
async fn target_failure_is_read_error_and_reply_is_one_shot() {
    let (client, server) = configs(false, "resolver.test", true);
    let (left, right) = tokio::io::duplex(8192);
    let target = TargetAddr::domain("blocked.test", 443).unwrap();
    let server = async {
        let Accepted::Tcp { mut stream, .. } = accept(right, &server).await.unwrap() else {
            panic!("TCP mode");
        };
        respond_tcp(&mut stream, Err(ConnectErrorKind::PolicyDenied))
            .await
            .unwrap();
        assert!(
            respond_tcp(&mut stream, Ok("127.0.0.1:80".parse().unwrap()))
                .await
                .is_err()
        );
        assert!(stream.write_all(b"must not become relay").await.is_err());
    };
    let (client, ()) = tokio::join!(
        connect_tcp(left, &client, Profile::Balanced, &target),
        server
    );
    let mut client = client.unwrap();
    assert_eq!(
        client.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(client.write_all(b"after failure").await.is_err());
}

#[test]
fn token_file_requires_exact_decoded_size_and_redacts_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret-sentinel");
    for bytes in [vec![1u8; 31], vec![1u8; 33], vec![]] {
        fs::write(
            &path,
            base64::engine::general_purpose::STANDARD.encode(bytes),
        )
        .unwrap();
        let error = ClientConfig::load(&path, "resolver.test", None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!format!("{error:?}").contains("secret-sentinel"));
    }
}
