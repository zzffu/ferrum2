use std::io::{self, Cursor, Read, Seek, SeekFrom};

use super::{DLL_BYTES, Error, read_pinned_artifact};

struct ObservedReader {
    cursor: Cursor<Vec<u8>>,
    requests: Vec<usize>,
    bytes_read: usize,
    seeks: Vec<SeekFrom>,
}

impl ObservedReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            cursor: Cursor::new(bytes),
            requests: Vec::new(),
            bytes_read: 0,
            seeks: Vec::new(),
        }
    }
}

impl Read for ObservedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.requests.push(buffer.len());
        let limit = buffer.len().min(257);
        let read = self.cursor.read(&mut buffer[..limit])?;
        self.bytes_read += read;
        Ok(read)
    }
}

impl Seek for ObservedReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.seeks.push(position);
        self.cursor.seek(position)
    }
}

#[test]
fn wrong_metadata_size_rejects_before_touching_the_held_reader() {
    struct NoAccess;
    impl Read for NoAccess {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("wrong metadata size must not read artifact bytes");
        }
    }
    impl Seek for NoAccess {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            panic!("wrong metadata size must not seek the artifact");
        }
    }
    for size in [0, DLL_BYTES - 1, DLL_BYTES + 1, u64::MAX] {
        assert_eq!(read_pinned_artifact(&mut NoAccess, size), Err(Error));
    }
}

#[test]
fn exact_artifact_reads_from_start_through_partial_reads_then_checks_eof() {
    let expected: Vec<_> = (0..DLL_BYTES).map(|index| index as u8).collect();
    let mut reader = ObservedReader::new(expected.clone());
    reader.cursor.set_position(19);
    assert_eq!(read_pinned_artifact(&mut reader, DLL_BYTES), Ok(expected));
    assert_eq!(reader.seeks, [SeekFrom::Start(0)]);
    assert_eq!(reader.bytes_read, DLL_BYTES as usize);
    assert_eq!(reader.cursor.position(), DLL_BYTES);
    assert_eq!(reader.requests.last(), Some(&1));
}

#[test]
fn stale_metadata_cannot_allow_short_or_excess_artifact_bytes() {
    let mut short = ObservedReader::new(vec![0; DLL_BYTES as usize - 1]);
    assert_eq!(read_pinned_artifact(&mut short, DLL_BYTES), Err(Error));
    assert_eq!(short.bytes_read, DLL_BYTES as usize - 1);

    let mut oversized = ObservedReader::new(vec![0; DLL_BYTES as usize + 512]);
    assert_eq!(read_pinned_artifact(&mut oversized, DLL_BYTES), Err(Error));
    assert_eq!(oversized.bytes_read, DLL_BYTES as usize + 1);
    assert_eq!(oversized.cursor.position(), DLL_BYTES + 1);
    assert_eq!(oversized.requests.last(), Some(&1));
}

#[derive(Clone, Copy)]
enum Failure {
    Seek,
    Body,
    EofProbe,
}

struct FailedReader {
    cursor: Cursor<Vec<u8>>,
    failure: Failure,
}

impl Seek for FailedReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        match self.failure {
            Failure::Seek => Err(io::Error::other("injected reader identity")),
            Failure::Body | Failure::EofProbe => self.cursor.seek(position),
        }
    }
}

impl Read for FailedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.failure {
            Failure::Body => Err(io::Error::other("injected reader identity")),
            Failure::EofProbe if self.cursor.position() == DLL_BYTES => {
                Err(io::Error::other("injected reader identity"))
            }
            Failure::Seek | Failure::EofProbe => self.cursor.read(buffer),
        }
    }
}

#[test]
fn seek_body_and_eof_probe_failures_stay_closed() {
    for failure in [Failure::Seek, Failure::Body, Failure::EofProbe] {
        let mut reader = FailedReader {
            cursor: Cursor::new(vec![0; DLL_BYTES as usize]),
            failure,
        };
        let error = read_pinned_artifact(&mut reader, DLL_BYTES).unwrap_err();
        assert_eq!(error, Error);
        assert_eq!(error.to_string(), "Wintun operation failed");
    }
}
