#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeadlineError {
    Timeout,
    TooLarge,
    Unavailable,
}

impl From<DeadlineError> for crate::risk::TransportError {
    fn from(error: DeadlineError) -> Self {
        match error {
            DeadlineError::Timeout => Self::Timeout,
            DeadlineError::TooLarge => Self::TooLarge,
            DeadlineError::Unavailable => Self::Unavailable,
        }
    }
}

pub(crate) enum ReadChunk {
    Data(Vec<u8>),
    Closed,
}

pub(crate) trait DeadlineWait {
    fn wait_until(&mut self, deadline_ns: u64) -> Result<bool, ()>;
}

pub(crate) trait DeadlineRead: DeadlineWait {
    fn read_chunk(&mut self, max_bytes: u64) -> Result<ReadChunk, ()>;
}

pub(crate) fn wait_ready_until<W: DeadlineWait + ?Sized>(
    waiter: &mut W,
    deadline_ns: u64,
) -> Result<(), DeadlineError> {
    if waiter
        .wait_until(deadline_ns)
        .map_err(|()| DeadlineError::Unavailable)?
    {
        Ok(())
    } else {
        Err(DeadlineError::Timeout)
    }
}

pub(crate) fn read_all_bounded<R: DeadlineRead + ?Sized>(
    reader: &mut R,
    deadline_ns: u64,
    chunk_bytes: u64,
    max_bytes: usize,
) -> Result<Vec<u8>, DeadlineError> {
    let mut body = Vec::new();
    loop {
        wait_ready_until(reader, deadline_ns)?;
        match reader
            .read_chunk(chunk_bytes)
            .map_err(|()| DeadlineError::Unavailable)?
        {
            ReadChunk::Data(chunk) => {
                if body.len().saturating_add(chunk.len()) > max_bytes {
                    return Err(DeadlineError::TooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            ReadChunk::Closed => return Ok(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        read_all_bounded, wait_ready_until, DeadlineError, DeadlineRead, DeadlineWait, ReadChunk,
    };
    use crate::model::Verdict;
    use crate::risk::{analyze_with, Config, ReadTransport, Request, Response, TransportError};

    const MS: u64 = 1_000_000;

    struct TimedWait {
        started: Instant,
        ready_at_ns: u64,
    }

    impl DeadlineWait for TimedWait {
        fn wait_until(&mut self, deadline_ns: u64) -> Result<bool, ()> {
            let now = self.started.elapsed().as_nanos() as u64;
            let wake_at = self.ready_at_ns.min(deadline_ns);
            if wake_at > now {
                thread::sleep(Duration::from_nanos(wake_at - now));
            }
            let elapsed = self.started.elapsed().as_nanos() as u64;
            Ok(elapsed < deadline_ns && elapsed >= self.ready_at_ns)
        }
    }

    struct TimedReader {
        started: Instant,
        chunks: VecDeque<(u64, Vec<u8>)>,
        reads: usize,
    }

    struct DelayedFirstByteTransport {
        waiter: TimedWait,
        deadline_ns: u64,
    }

    impl ReadTransport for DelayedFirstByteTransport {
        fn send(&mut self, _request: Request) -> Result<Response, TransportError> {
            wait_ready_until(&mut self.waiter, self.deadline_ns).map_err(TransportError::from)?;
            Err(TransportError::Unavailable)
        }
    }

    impl DeadlineWait for TimedReader {
        fn wait_until(&mut self, deadline_ns: u64) -> Result<bool, ()> {
            let ready_at_ns = self
                .chunks
                .front()
                .map(|(ready_at_ns, _)| *ready_at_ns)
                .unwrap_or(deadline_ns);
            let now = self.started.elapsed().as_nanos() as u64;
            let wake_at = ready_at_ns.min(deadline_ns);
            if wake_at > now {
                thread::sleep(Duration::from_nanos(wake_at - now));
            }
            let elapsed = self.started.elapsed().as_nanos() as u64;
            Ok(elapsed < deadline_ns && elapsed >= ready_at_ns)
        }
    }

    impl DeadlineRead for TimedReader {
        fn read_chunk(&mut self, _max_bytes: u64) -> Result<ReadChunk, ()> {
            self.reads += 1;
            Ok(self
                .chunks
                .pop_front()
                .map(|(_, bytes)| ReadChunk::Data(bytes))
                .unwrap_or(ReadChunk::Closed))
        }
    }

    #[test]
    fn delayed_first_byte_stops_at_deadline() {
        let started = Instant::now();
        let mut transport = DelayedFirstByteTransport {
            waiter: TimedWait {
                started,
                ready_at_ns: 500 * MS,
            },
            deadline_ns: 20 * MS,
        };
        let assessment = analyze_with(
            "So11111111111111111111111111111111111111112",
            &Config::new("https://rpc.example"),
            &mut transport,
        )
        .unwrap();
        assert_eq!(assessment.verdict, Verdict::Amber);
        assert!(!assessment.complete);
        assert_eq!(assessment.reasons[0].code, "MINT_HTTP_TIMEOUT");
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn slow_between_byte_path_stops_at_total_deadline() {
        let started = Instant::now();
        let mut reader = TimedReader {
            started,
            chunks: VecDeque::from([
                (5 * MS, b"first".to_vec()),
                (15 * MS, b"second".to_vec()),
                (500 * MS, b"too-late".to_vec()),
            ]),
            reads: 0,
        };
        assert_eq!(
            read_all_bounded(&mut reader, 30 * MS, 16 * 1024, 64 * 1024),
            Err(DeadlineError::Timeout)
        );
        assert_eq!(reader.reads, 2);
        assert!(started.elapsed() < Duration::from_millis(250));
    }
}
