//! The only translation of CrabCode frames into engine provider events and session row fields.
use crate::protocol::{Block, Frame};
use openbot_application::{ProviderEvent, ProviderOutputKind, ProviderUsage};
use serde_json::Value;

/// What one frame asks of the session.
#[derive(Debug, PartialEq)]
pub(crate) enum Mapped {
    Events(Vec<ProviderEvent>),
    /// The first `system/init`: the row's native session id and `ResponseStarted`.
    Init {
        session_id: String,
        event: ProviderEvent,
    },
    Permission {
        request_id: String,
        tool_name: String,
        input: Value,
    },
    Refuse {
        request_id: String,
        code: &'static str,
    },
    /// A successful result: events to send before `Completed`, and the row's result summary.
    Success {
        events: Vec<ProviderEvent>,
        summary: Option<String>,
    },
    ResultError,
    /// Duplicate init, output before init, or a success without any text.
    Violation,
}

/// Per-run mapping state; the counters stay in this process.
#[derive(Default)]
pub(crate) struct Mapper {
    /// Parsed stdout objects.
    pub(crate) seq: u64,
    pub(crate) tool_uses: u64,
    pub(crate) tool_names: Vec<String>,
    pub(crate) tool_results: u64,
    pub(crate) ignored: u64,
    pub(crate) init: bool,
    next_index: u32,
    text_seen: bool,
}
impl Mapper {
    fn text(&mut self, text: String, events: &mut Vec<ProviderEvent>) {
        let index = self.next_index;
        self.next_index += 1;
        self.text_seen |= !text.trim().is_empty();
        events.push(ProviderEvent::OutputItemAdded {
            index,
            kind: ProviderOutputKind::Message,
        });
        events.push(ProviderEvent::TextDelta { index, delta: text });
    }
    pub(crate) fn map(&mut self, frame: Frame) -> Mapped {
        self.seq += 1;
        match frame {
            Frame::Init { .. } if self.init => Mapped::Violation,
            Frame::Init { session_id } => {
                self.init = true;
                Mapped::Init {
                    event: ProviderEvent::ResponseStarted {
                        response_id: session_id.clone(),
                    },
                    session_id,
                }
            }
            Frame::Assistant(_) | Frame::Result(_) if !self.init => Mapped::Violation,
            Frame::Assistant(blocks) => {
                let mut events = Vec::new();
                for block in blocks {
                    match block {
                        Block::Text(text) => self.text(text, &mut events),
                        Block::ToolUse(name) => {
                            self.tool_uses += 1;
                            self.tool_names.push(name);
                        }
                        Block::Other => self.ignored += 1,
                    }
                }
                Mapped::Events(events)
            }
            Frame::User { tool_results } => {
                self.tool_results += tool_results;
                Mapped::Events(Vec::new())
            }
            Frame::Result(outcome) if !outcome.success => Mapped::ResultError,
            Frame::Result(outcome) => {
                let mut events = Vec::new();
                if !self.text_seen {
                    match outcome.text.clone().filter(|text| !text.trim().is_empty()) {
                        Some(text) => self.text(text, &mut events),
                        None => return Mapped::Violation,
                    }
                }
                if let Some((input_tokens, output_tokens)) = outcome.usage {
                    events.push(ProviderEvent::Usage(ProviderUsage {
                        input_tokens,
                        output_tokens,
                        total_tokens: input_tokens.saturating_add(output_tokens),
                    }));
                }
                // PostgreSQL text holds no NUL.
                Mapped::Success {
                    events,
                    summary: outcome.text.map(|text| text.replace('\0', "")),
                }
            }
            Frame::CanUseTool {
                request_id,
                tool_name,
                input,
            } => Mapped::Permission {
                request_id,
                tool_name,
                input,
            },
            Frame::Refuse { request_id, code } => Mapped::Refuse { request_id, code },
            Frame::System | Frame::ControlResponse | Frame::Unknown => {
                self.ignored += 1;
                Mapped::Events(Vec::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::parse_line;
    use openbot_application::ProviderFailure;

    fn run(lines: &[&str]) -> (Mapper, Vec<Mapped>) {
        let mut mapper = Mapper::default();
        let mapped = lines
            .iter()
            .map(|line| mapper.map(parse_line(line.as_bytes(), crate::CC_LINE_MAX).unwrap()))
            .collect();
        (mapper, mapped)
    }
    const INIT: &str = r#"{"type":"system","subtype":"init","session_id":"s-1"}"#;
    fn assistant(texts: &[&str]) -> String {
        let blocks: Vec<String> = texts
            .iter()
            .map(|text| format!(r#"{{"type":"text","text":"{text}"}}"#))
            .collect();
        format!(
            r#"{{"type":"assistant","message":{{"content":[{}]}}}}"#,
            blocks.join(",")
        )
    }
    fn text_events(index: u32, text: &str) -> [ProviderEvent; 2] {
        [
            ProviderEvent::OutputItemAdded {
                index,
                kind: ProviderOutputKind::Message,
            },
            ProviderEvent::TextDelta {
                index,
                delta: text.into(),
            },
        ]
    }

    #[test]
    fn init_yields_response_started_once() {
        let (_, mapped) = run(&[INIT, INIT]);
        assert_eq!(
            mapped[0],
            Mapped::Init {
                session_id: "s-1".into(),
                event: ProviderEvent::ResponseStarted {
                    response_id: "s-1".into()
                }
            }
        );
        assert_eq!(mapped[1], Mapped::Violation);
    }

    #[test]
    fn text_blocks_use_running_index_across_assistant_messages() {
        let (_, mapped) = run(&[INIT, &assistant(&["a", "b"]), &assistant(&["c"])]);
        let mut first = text_events(0, "a").to_vec();
        first.extend(text_events(1, "b"));
        assert_eq!(mapped[1], Mapped::Events(first));
        assert_eq!(mapped[2], Mapped::Events(text_events(2, "c").to_vec()));
    }

    #[test]
    fn result_success_after_text_completes_with_usage_total() {
        let (_, mapped) = run(&[
            INIT,
            &assistant(&["hello"]),
            r#"{"type":"result","subtype":"success","is_error":false,"result":"hello","usage":{"input_tokens":12,"output_tokens":30}}"#,
        ]);
        assert_eq!(
            mapped[2],
            Mapped::Success {
                events: vec![ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 12,
                    output_tokens: 30,
                    total_tokens: 42
                })],
                summary: Some("hello".into())
            }
        );
    }

    #[test]
    fn result_success_without_text_uses_result_text_else_invalid_response() {
        let (_, mapped) = run(&[
            INIT,
            &assistant(&["x"]),
            r#"{"type":"result","subtype":"success","result":"a\u0000b"}"#,
        ]);
        assert!(matches!(&mapped[2], Mapped::Success { summary: Some(s), .. } if s == "ab"));
        let (_, mapped) = run(&[
            INIT,
            &assistant(&["  "]),
            r#"{"type":"result","subtype":"success","result":"final"}"#,
        ]);
        assert_eq!(
            mapped[2],
            Mapped::Success {
                events: text_events(1, "final").to_vec(),
                summary: Some("final".into())
            }
        );
        for result in [
            r#"{"type":"result","subtype":"success","result":" \n"}"#,
            r#"{"type":"result","subtype":"success"}"#,
        ] {
            let (_, mapped) = run(&[INIT, result]);
            assert_eq!(mapped[1], Mapped::Violation, "{result}");
        }
    }

    #[test]
    fn result_error_and_is_error_are_generation_failed() {
        for result in [
            r#"{"type":"result","subtype":"error_during_execution","result":"x"}"#,
            r#"{"type":"result","subtype":"success","is_error":true,"result":"x"}"#,
        ] {
            let (_, mapped) = run(&[INIT, result]);
            assert_eq!(mapped[1], Mapped::ResultError, "{result}");
        }
        assert_eq!(
            crate::session::failure(omb_store::EndReason::ResultError),
            Some(ProviderFailure::GenerationFailed)
        );
    }

    #[test]
    fn exit_before_result_is_transport_and_missing_init_is_invalid_response() {
        let (_, mapped) = run(&[
            &assistant(&["early"]),
            r#"{"type":"result","subtype":"success","result":"x"}"#,
        ]);
        assert_eq!(mapped, vec![Mapped::Violation, Mapped::Violation]);
        assert_eq!(
            crate::session::failure(omb_store::EndReason::ProtocolError),
            Some(ProviderFailure::InvalidResponse)
        );
        assert_eq!(
            crate::session::failure(omb_store::EndReason::ChildExited),
            Some(ProviderFailure::Transport)
        );
    }

    #[test]
    fn no_tool_or_reasoning_events_are_produced() {
        let (_, mapped) = run(&[
            INIT,
            r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"t"},{"type":"tool_use","id":"t1","name":"Write","input":{}},{"type":"text","text":"ok"}]}}"#,
            r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"done"}]}}"#,
            r#"{"type":"stream_event","event":{"type":"content_block_delta"}}"#,
            r#"{"type":"result","subtype":"success","result":"ok","usage":{"input_tokens":1,"output_tokens":2}}"#,
        ]);
        let events: Vec<&ProviderEvent> = mapped
            .iter()
            .flat_map(|m| match m {
                Mapped::Events(events) | Mapped::Success { events, .. } => events.iter().collect(),
                Mapped::Init { event, .. } => vec![event],
                _ => Vec::new(),
            })
            .collect();
        assert!(events.iter().all(|event| matches!(
            event,
            ProviderEvent::ResponseStarted { .. }
                | ProviderEvent::OutputItemAdded { .. }
                | ProviderEvent::TextDelta { .. }
                | ProviderEvent::Usage(_)
        )));
        use omb_store::EndReason::*;
        for reason in [
            ResultSuccess,
            ResultError,
            StopRequested,
            OutputLimit,
            LineLimit,
            Stalled,
            ProtocolError,
            ChildExited,
            SpawnFailed,
            VersionRejected,
            InitTimeout,
            ResumeFailed,
        ] {
            assert!(!matches!(
                crate::session::failure(reason),
                Some(
                    ProviderFailure::RateLimited { .. }
                        | ProviderFailure::ServerUnavailable { .. }
                        | ProviderFailure::Authentication
                )
            ));
        }
    }

    #[test]
    fn counters_stay_in_process_and_last_event_seq_counts_parsed_objects() {
        let (mapper, _) = run(&[
            INIT,
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Write"},{"type":"tool_use","name":"Bash"}]}}"#,
            r#"{"type":"user","message":{"content":[{"type":"tool_result"},{"type":"tool_result"},{"type":"text","text":"x"}]}}"#,
            r#"{"type":"stream_event"}"#,
            r#"{"type":"system","subtype":"status"}"#,
        ]);
        assert_eq!(mapper.seq, 5);
        assert_eq!(mapper.tool_uses, 2);
        assert_eq!(mapper.tool_names, ["Write", "Bash"]);
        assert_eq!(mapper.tool_results, 2);
        assert_eq!(mapper.ignored, 2);
    }
}
