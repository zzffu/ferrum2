use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::Ipv4Addr;

#[derive(Debug, Eq, PartialEq)]
enum Timeout {
    Read(Duration),
    Write(Duration),
}

struct Script {
    input: VecDeque<u8>,
    written: Vec<u8>,
    timeouts: RefCell<Vec<Timeout>>,
    write_errors: VecDeque<io::ErrorKind>,
}

impl Script {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.iter().copied().collect(),
            written: Vec::new(),
            timeouts: RefCell::new(Vec::new()),
            write_errors: VecDeque::new(),
        }
    }
}

impl Read for Script {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self.input.pop_front() {
            Some(byte) => {
                output[0] = byte;
                Ok(1)
            }
            None => Ok(0),
        }
    }
}

impl Write for Script {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if let Some(error) = self.write_errors.pop_front() {
            return Err(error.into());
        }
        self.written.push(input[0]);
        Ok(1)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineIo for Script {
    fn read_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.timeouts.borrow_mut().push(Timeout::Read(timeout));
        Ok(())
    }
    fn write_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.timeouts.borrow_mut().push(Timeout::Write(timeout));
        Ok(())
    }
}

#[test]
fn bounded_probe_deadline_contract_socks_partial_progress_and_handoff() {
    let started = Instant::now();
    let mut clock = started;
    let mut now = || {
        let result = clock;
        clock += Duration::from_millis(1);
        result
    };
    let mut script = Script::new(&[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080);
    negotiate(
        &mut script,
        target,
        started + Duration::from_secs(1),
        &mut now,
    )
    .unwrap();
    assert_eq!(script.written, [5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 31, 144]);
    let timeouts = script.timeouts.borrow();
    assert_eq!(
        &timeouts[timeouts.len() - 2..],
        &[Timeout::Read(IO_TIMEOUT), Timeout::Write(IO_TIMEOUT)]
    );
    let operation_timeouts: Vec<_> = timeouts[..timeouts.len() - 2]
        .iter()
        .map(|value| match value {
            Timeout::Read(duration) | Timeout::Write(duration) => *duration,
        })
        .collect();
    assert!(operation_timeouts.windows(2).all(|pair| pair[0] > pair[1]));
}

#[test]
fn bounded_probe_deadline_contract_partial_and_final_progress_cannot_extend_deadline() {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(2);
    let mut clock = started;
    let mut now = || {
        let result = clock;
        clock += Duration::from_millis(1);
        result
    };
    let mut script = Script::new(b"");
    assert_eq!(
        write_until(&mut script, b"ab", deadline, &mut now)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(script.written, b"ab");
    let mut script = Script::new(b"abc");
    let mut clock = started;
    let mut now = || {
        let result = clock;
        clock += Duration::from_millis(1);
        result
    };
    let mut bytes = [0; 3];
    assert_eq!(
        read_until(&mut script, &mut bytes, deadline, &mut now)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(bytes, [b'a', b'b', 0]);
}

#[test]
fn bounded_probe_deadline_contract_interrupted_and_oversized_echo_are_finite() {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(1);
    let mut clock = started;
    let mut now = || {
        let result = clock;
        clock += Duration::from_millis(1);
        result
    };
    let mut script = Script::new(b"");
    script.write_errors.push_back(io::ErrorKind::Interrupted);
    assert_eq!(
        write_until(&mut script, b"a", deadline, &mut now)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(script.written.is_empty());
    let mut script = Script::new(b"ab");
    let mut output = Vec::new();
    assert_eq!(
        read_end_until(&mut script, &mut output, 1, deadline, &mut || started)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(output, b"a");
    assert!(script.input.is_empty());
    let mut script = Script::new(b"");
    read_end_until(&mut script, &mut Vec::new(), 0, deadline, &mut || started).unwrap();
}
