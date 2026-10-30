use super::*;
use crate::{RunFailureCode, RunTerminal};
use std::marker::PhantomData;
use std::time::{Duration, UNIX_EPOCH};

struct DefaultSession;
#[async_trait]
impl ProviderSession for DefaultSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        panic!("stopping must not consume the stream")
    }
}

#[tokio::test]
async fn default_request_stop_is_unsupported_without_polling_stream() {
    let mut session: Box<dyn ProviderSession> = Box::new(DefaultSession);
    assert_eq!(session.request_stop().await, Ok(StopOutcome::Unsupported));
}

struct SerializeProbe<T>(PhantomData<T>);
impl<T: serde::Serialize> SerializeProbe<T> {
    fn implemented(&self) -> bool {
        true
    }
}
trait SerializeFallback {
    fn implemented(&self) -> bool {
        false
    }
}
impl<T> SerializeFallback for SerializeProbe<T> {}
struct DeserializeProbe<T>(PhantomData<T>);
impl<T: serde::de::DeserializeOwned> DeserializeProbe<T> {
    fn implemented(&self) -> bool {
        true
    }
}
trait DeserializeFallback {
    fn implemented(&self) -> bool {
        false
    }
}
impl<T> DeserializeFallback for DeserializeProbe<T> {}

#[test]
fn stop_outcome_is_closed_nonserde_and_preserves_confirmation_time() {
    fn traits<T: Clone + Copy + core::fmt::Debug + PartialEq + Eq>() {}
    traits::<StopOutcome>();
    assert!(SerializeProbe::<String>(PhantomData).implemented());
    assert!(DeserializeProbe::<String>(PhantomData).implemented());
    assert!(!SerializeProbe::<StopOutcome>(PhantomData).implemented());
    assert!(!DeserializeProbe::<StopOutcome>(PhantomData).implemented());
    let at = UNIX_EPOCH + Duration::from_secs(912_345_678);
    for (value, expected) in [
        (StopOutcome::Confirmed { at }, 0),
        (StopOutcome::Unknown, 1),
        (StopOutcome::Unsupported, 2),
    ] {
        let copied = value;
        assert_eq!(copied, value);
        let kind = match value {
            StopOutcome::Confirmed { at: actual } => {
                assert_eq!(actual, at);
                0
            }
            StopOutcome::Unknown => 1,
            StopOutcome::Unsupported => 2,
        };
        assert_eq!(kind, expected);
        assert!(!format!("{value:?}").is_empty());
    }
}

#[test]
fn stop_unknown_failure_code_uses_existing_reconciliation_terminal_shape() {
    let reason = RunFailureCode::ProviderStopUnknown;
    assert_eq!(reason.as_str(), "provider_stop_unknown");
    let terminal = RunTerminal::ReconciliationRequired(reason);
    assert_eq!(terminal.as_str(), "reconciliation_required");
    assert_eq!(terminal.error_code(), Some(reason));
    assert_eq!(RunTerminal::Cancelled.error_code(), None);
    assert_eq!(
        RunTerminal::Failed(RunFailureCode::ProviderStreamStalled)
            .error_code()
            .unwrap()
            .as_str(),
        "agent_stream_stalled"
    );
}
