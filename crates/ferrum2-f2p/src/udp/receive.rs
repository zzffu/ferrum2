use super::*;

/// One tunnel-wide allocation, borrowed only for nonblocking receive and copy.
/// Field order keeps the partition resources alive until the allocation and its
/// charge are actually destroyed, including when the last worker is aborted.
pub(super) struct Scratch {
    buffer: Mutex<Box<[u8]>>,
    _charge: Charge,
    shared: Arc<Shared>,
}

impl Scratch {
    pub(super) fn new(shared: Arc<Shared>) -> io::Result<Self> {
        let charge = shared.charge(None, MAX_DATA + 1 + PACKET_OVERHEAD)?;
        Ok(Self {
            buffer: Mutex::new(vec![0; MAX_DATA + 1].into_boxed_slice()),
            _charge: charge,
            shared,
        })
    }

    pub(super) fn receive(&self, socket: &impl UdpSocket, session: &Session) -> io::Result<Packet> {
        let mut buffer = lock(&self.buffer);
        let length = socket.try_receive(&mut buffer)?;
        if length > MAX_DATA {
            return Err(invalid());
        }
        self.shared
            .packet(Some(session), DATA, session.id, &buffer[..length])
    }
}
