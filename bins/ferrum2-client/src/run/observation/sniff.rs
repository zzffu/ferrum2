use ferrum2_observability::{Metrics, Role, SniffOutcome, SniffProtocol, Transport};
use ferrum2_runtime::SniffPrefixOutcome;
use ferrum2_sniff::{Metadata, Progress};

pub(in crate::run) enum SniffAttempt<'a> {
    Parsed {
        transport: Transport,
        progress: &'a Progress,
    },
    Limit(Transport),
    TcpTimeout,
    TcpUnavailable,
}

impl<'a> SniffAttempt<'a> {
    pub(in crate::run) fn tcp_collection(
        progress: &'a Progress,
        outcome: SniffPrefixOutcome,
    ) -> Self {
        match outcome {
            SniffPrefixOutcome::Complete => Self::Parsed {
                transport: Transport::Tcp,
                progress,
            },
            SniffPrefixOutcome::Limit => Self::Limit(Transport::Tcp),
            SniffPrefixOutcome::Timeout => Self::TcpTimeout,
            SniffPrefixOutcome::Unavailable
            | SniffPrefixOutcome::Cancelled
            | SniffPrefixOutcome::ReadError => Self::TcpUnavailable,
        }
    }
}

pub(in crate::run) fn record_sniff(metrics: &Metrics, attempt: SniffAttempt<'_>) {
    let (transport, outcome, protocol) = match attempt {
        SniffAttempt::Parsed {
            transport,
            progress,
        } => {
            let (outcome, protocol) = match progress {
                Progress::Matched(Metadata::Dns { .. }) => {
                    (SniffOutcome::Matched, SniffProtocol::Dns)
                }
                Progress::Matched(Metadata::Tls { .. }) => {
                    (SniffOutcome::Matched, SniffProtocol::Tls)
                }
                Progress::Matched(Metadata::Http { .. }) => {
                    (SniffOutcome::Matched, SniffProtocol::Http)
                }
                Progress::NoMatch | Progress::NeedMore => {
                    (SniffOutcome::Unknown, SniffProtocol::None)
                }
                Progress::Invalid => (SniffOutcome::Invalid, SniffProtocol::None),
            };
            (transport, outcome, protocol)
        }
        SniffAttempt::Limit(transport) => (transport, SniffOutcome::Limit, SniffProtocol::None),
        SniffAttempt::TcpTimeout => (Transport::Tcp, SniffOutcome::Timeout, SniffProtocol::None),
        SniffAttempt::TcpUnavailable => (
            Transport::Tcp,
            SniffOutcome::Unavailable,
            SniffProtocol::None,
        ),
    };
    metrics.sniff(Role::Client, transport, outcome, protocol);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_attempt_emits_one_transport_correct_redacted_counter() {
        let progress_cases = [
            (
                Progress::Matched(Metadata::Dns {
                    domain: "private.example".into(),
                }),
                "matched",
                "dns",
            ),
            (
                Progress::Matched(Metadata::Tls {
                    domain: Some("private.example".into()),
                }),
                "matched",
                "tls",
            ),
            (
                Progress::Matched(Metadata::Http {
                    domain: Some("private.example".into()),
                }),
                "matched",
                "http",
            ),
            (Progress::NoMatch, "unknown", "none"),
            (Progress::NeedMore, "unknown", "none"),
            (Progress::Invalid, "invalid", "none"),
        ];
        let mut cases = Vec::new();
        for (progress, outcome, protocol) in &progress_cases {
            for (transport, label) in [(Transport::Tcp, "tcp"), (Transport::Udp, "udp")] {
                cases.push((
                    SniffAttempt::Parsed {
                        transport,
                        progress,
                    },
                    label,
                    *outcome,
                    *protocol,
                ));
            }
        }
        for (end, label) in [
            (SniffPrefixOutcome::Timeout, "timeout"),
            (SniffPrefixOutcome::Limit, "limit"),
            (SniffPrefixOutcome::Unavailable, "unavailable"),
            (SniffPrefixOutcome::Cancelled, "unavailable"),
            (SniffPrefixOutcome::ReadError, "unavailable"),
            (SniffPrefixOutcome::Complete, "unknown"),
        ] {
            cases.push((
                SniffAttempt::tcp_collection(&Progress::NoMatch, end),
                "tcp",
                label,
                "none",
            ));
        }
        cases.push((SniffAttempt::Limit(Transport::Udp), "udp", "limit", "none"));
        for (attempt, transport, outcome, protocol) in cases {
            let metrics = Metrics::new();
            record_sniff(&metrics, attempt);
            let encoded = metrics.encode_text().unwrap();
            let actual = encoded
                .lines()
                .filter(|line| line.starts_with("ferrum2_sniff_total{"))
                .collect::<Vec<_>>();
            let expected = format!(
                "ferrum2_sniff_total{{role=\"client\",transport=\"{transport}\",stage=\"sniff\",outcome=\"{outcome}\",protocol=\"{protocol}\"}} 1"
            );
            assert_eq!(actual, vec![expected.as_str()]);
            assert!(!encoded.contains("private.example"));
        }
    }
}
