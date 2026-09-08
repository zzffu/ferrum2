use base64::Engine;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::Path,
    sync::Arc,
};
use zeroize::Zeroizing;

pub(crate) const ALPN: &[u8] = b"f2p/1";
const MAX_PEM_BYTES: u64 = 1024 * 1024;

#[derive(Clone)]
pub struct ClientConfig {
    pub(crate) tls: Arc<rustls::ClientConfig>,
    pub(crate) name: ServerName<'static>,
    pub(crate) token: Arc<Zeroizing<[u8; 32]>>,
}
#[derive(Clone)]
pub struct ServerConfig {
    pub(crate) tls: Arc<rustls::ServerConfig>,
    pub(crate) token: Arc<Zeroizing<[u8; 32]>>,
}
impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientConfig([redacted])")
    }
}
impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerConfig([redacted])")
    }
}
pub(crate) fn closed(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "F2P I/O failed")
}
fn configuration() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid F2P configuration")
}
fn read_bounded(path: &Path, limit: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(closed)?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(closed)?;
    if bytes.len() as u64 > limit {
        return Err(configuration());
    }
    Ok(bytes)
}
fn load_token(path: &Path) -> io::Result<Arc<Zeroizing<[u8; 32]>>> {
    let text = read_bounded(path, 128)?;
    let text = std::str::from_utf8(&text)
        .map_err(|_| configuration())?
        .trim();
    let mut decoded = Zeroizing::new([0u8; 33]);
    let len = base64::engine::general_purpose::STANDARD
        .decode_slice(text, &mut decoded[..])
        .map_err(|_| configuration())?;
    if len != 32 {
        return Err(configuration());
    }
    let mut token = Zeroizing::new([0u8; 32]);
    token.copy_from_slice(&decoded[..32]);
    Ok(Arc::new(token))
}
impl ClientConfig {
    /// Loads the token and normal certificate verifier. A supplied CA file replaces
    /// the built-in public roots, allowing a private, least-privilege trust store.
    pub fn load(token_file: &Path, server_name: &str, ca_file: Option<&Path>) -> io::Result<Self> {
        let token = load_token(token_file)?;
        let name = ServerName::try_from(server_name.to_owned()).map_err(|_| configuration())?;
        let mut roots = RootCertStore::empty();
        if let Some(path) = ca_file {
            let pem = read_bounded(path, MAX_PEM_BYTES)?;
            for cert in CertificateDer::pem_slice_iter(&pem) {
                roots
                    .add(cert.map_err(|_| configuration())?)
                    .map_err(|_| configuration())?;
            }
            if roots.is_empty() {
                return Err(configuration());
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| configuration())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.enable_early_data = false;
        Ok(Self {
            tls: Arc::new(tls),
            name,
            token,
        })
    }
}
impl ServerConfig {
    pub fn load(
        token_file: &Path,
        certificate_file: &Path,
        private_key_file: &Path,
    ) -> io::Result<Self> {
        let token = load_token(token_file)?;
        let pem = read_bounded(certificate_file, MAX_PEM_BYTES)?;
        let certs = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| configuration())?;
        let pem_key = read_bounded(private_key_file, MAX_PEM_BYTES)?;
        let key = PrivateKeyDer::from_pem_slice(&pem_key).map_err(|_| configuration())?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| configuration())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| configuration())?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.max_early_data_size = 0;
        Ok(Self {
            tls: Arc::new(tls),
            token,
        })
    }
}
