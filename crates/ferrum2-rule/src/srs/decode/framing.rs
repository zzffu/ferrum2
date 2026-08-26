use std::io::{self, BufRead, Read};

use flate2::{Decompress, FlushDecompress, Status};

/// `flate2`'s `Read` adapters intentionally treat a `BufError` at source EOF
/// as ordinary EOF.  That is convenient for best-effort decompression, but it
/// would accept a zlib stream with a truncated trailer.  SRS is configuration
/// input, so require the decoder to report an actual `StreamEnd`.
pub(super) struct StrictZlibDecoder<R> {
    source: R,
    decoder: Decompress,
    ended: bool,
}

impl<R: BufRead> StrictZlibDecoder<R> {
    pub(super) fn new(source: R) -> Self {
        Self {
            source,
            decoder: Decompress::new(true),
            ended: false,
        }
    }

    pub(super) fn into_inner(self) -> R {
        self.source
    }
}

impl<R: BufRead> Read for StrictZlibDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.ended || output.is_empty() {
            return Ok(0);
        }

        loop {
            let (consumed, written, status, source_eof) = {
                let input = self.source.fill_buf()?;
                let source_eof = input.is_empty();
                let before_in = self.decoder.total_in();
                let before_out = self.decoder.total_out();
                let flush = if source_eof {
                    FlushDecompress::Finish
                } else {
                    FlushDecompress::None
                };
                let status = self.decoder.decompress(input, output, flush).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid zlib stream")
                })?;
                let consumed = usize::try_from(self.decoder.total_in() - before_in)
                    .map_err(|_| io::Error::other("zlib input counter overflow"))?;
                let written = usize::try_from(self.decoder.total_out() - before_out)
                    .map_err(|_| io::Error::other("zlib output counter overflow"))?;
                (consumed, written, status, source_eof)
            };
            self.source.consume(consumed);

            if status == Status::StreamEnd {
                self.ended = true;
                return Ok(written);
            }
            if written != 0 {
                return Ok(written);
            }
            if source_eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated zlib stream",
                ));
            }
            if consumed == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stalled zlib stream",
                ));
            }
        }
    }
}
