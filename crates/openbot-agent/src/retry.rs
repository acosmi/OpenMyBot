//! Provider pre-stream retry wrapper；mid-stream/commit-unknown 永不自动重放。

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use openbot_application::{
    ProviderAdapter, ProviderEvent, ProviderFailure, ProviderPortError, ProviderRequest,
    ProviderSession, StopOutcome,
};

/// Fixed upstream LangChain AsyncCaller parity defaults：6 retries, 1s factor-2 backoff。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryingProviderConfig {
    /// Number of retries after the first attempt。
    pub max_retries: u8,
    /// First retry delay。
    pub base_delay: Duration,
    /// Exponential delay cap；Retry-After may exceed it and is bounded by run deadline。
    pub max_delay: Duration,
    /// Fixed upstream p-retry uses a random factor in `[1,2)`。
    pub jitter: bool,
}

impl Default for RetryingProviderConfig {
    fn default() -> Self {
        Self {
            max_retries: 6,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(64),
            jitter: true,
        }
    }
}

impl RetryingProviderConfig {
    fn validate(self) -> Result<Self, ProviderPortError> {
        if self.max_retries > 16 || self.base_delay.is_zero() || self.max_delay < self.base_delay {
            Err(ProviderPortError::InvalidRequest {
                field: "provider_retry_config",
            })
        } else {
            Ok(self)
        }
    }
}

/// Retries only pre-stream connection failures and immediate HTTP 429/5xx normalized terminals。
pub struct RetryingProvider {
    inner: Arc<dyn ProviderAdapter>,
    config: RetryingProviderConfig,
}

impl RetryingProvider {
    /// Construct a bounded retry adapter。
    pub fn new(
        inner: Arc<dyn ProviderAdapter>,
        config: RetryingProviderConfig,
    ) -> Result<Self, ProviderPortError> {
        Ok(Self {
            inner,
            config: config.validate()?,
        })
    }
}

impl core::fmt::Debug for RetryingProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RetryingProvider")
            .field("config", &self.config)
            .field("inner", &"provider/[redacted]")
            .finish()
    }
}

#[async_trait]
impl ProviderAdapter for RetryingProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let mut retries_consumed = 0_u8;
        loop {
            let session = match self.inner.start(request.clone()).await {
                Ok(session) => session,
                Err(ProviderPortError::Unavailable)
                    if retries_consumed < self.config.max_retries =>
                {
                    self.wait_before_retry(retries_consumed, None).await;
                    retries_consumed += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let mut session = session;
            let first = session.next_event().await;
            let retry_after = match &first {
                Ok(Some(ProviderEvent::Failed(ProviderFailure::RateLimited { retry_after })))
                | Ok(Some(ProviderEvent::Failed(ProviderFailure::ServerUnavailable {
                    retry_after,
                }))) if retries_consumed < self.config.max_retries => Some(*retry_after),
                _ => None,
            };
            if let Some(retry_after) = retry_after {
                self.wait_before_retry(retries_consumed, retry_after).await;
                retries_consumed += 1;
                continue;
            }
            return Ok(Box::new(PrefetchedSession {
                first: Some(first),
                inner: session,
            }));
        }
    }
}

impl RetryingProvider {
    async fn wait_before_retry(&self, retry_index: u8, retry_after: Option<Duration>) {
        let delay = retry_delay(self.config, retry_index, retry_after);
        metrics::counter!("openbot_agent_provider_retry_total").increment(1);
        metrics::histogram!("openbot_agent_provider_retry_delay_seconds")
            .record(delay.as_secs_f64());
        tracing::warn!(
            retry = u64::from(retry_index) + 1,
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "provider pre-stream retry scheduled"
        );
        tokio::time::sleep(delay).await;
    }
}

fn retry_delay(
    config: RetryingProviderConfig,
    retry_index: u8,
    retry_after: Option<Duration>,
) -> Duration {
    let exponent = u32::from(retry_index.min(31));
    let factor = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
    let exponential = config
        .base_delay
        .checked_mul(factor)
        .unwrap_or(config.max_delay)
        .min(config.max_delay);
    let exponential = if config.jitter {
        jittered(exponential, config.max_delay)
    } else {
        exponential
    };
    retry_after.map_or(exponential, |hint| hint.max(exponential))
}

fn jittered(base: Duration, max: Duration) -> Duration {
    let mut random = [0_u8; 8];
    if getrandom::fill(&mut random).is_err() {
        return base;
    }
    let fraction = u64::from_le_bytes(random);
    let base_nanos = base.as_nanos();
    let extra = base_nanos.saturating_mul(u128::from(fraction)) / (u128::from(u64::MAX) + 1);
    duration_from_nanos(base_nanos.saturating_add(extra)).min(max)
}

fn duration_from_nanos(value: u128) -> Duration {
    let seconds = value / 1_000_000_000;
    let nanos = (value % 1_000_000_000) as u32;
    Duration::new(u64::try_from(seconds).unwrap_or(u64::MAX), nanos)
}

struct PrefetchedSession {
    first: Option<Result<Option<ProviderEvent>, ProviderPortError>>,
    inner: Box<dyn ProviderSession>,
}

#[async_trait]
impl ProviderSession for PrefetchedSession {
    async fn request_stop(&mut self) -> Result<StopOutcome, ProviderPortError> {
        self.inner.request_stop().await
    }

    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        match self.first.take() {
            Some(first) => first,
            None => self.inner.next_event().await,
        }
    }
}

#[cfg(test)]
#[path = "retry_stop_tests.rs"]
mod stop_tests;

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use openbot_application::{ProviderMessage, ProviderMessageRole, ProviderRoute};

    use super::*;

    enum Outcome {
        Port(ProviderPortError),
        Event(ProviderEvent),
    }

    struct ScriptedProvider {
        outcomes: Mutex<VecDeque<Outcome>>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ProviderAdapter for ScriptedProvider {
        async fn start(
            &self,
            _request: ProviderRequest,
        ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.outcomes.lock().expect("script lock").pop_front() {
                Some(Outcome::Port(error)) => Err(error),
                Some(Outcome::Event(event)) => Ok(Box::new(ScriptedSession(Some(event)))),
                None => panic!("script exhausted"),
            }
        }
    }

    struct ScriptedSession(Option<ProviderEvent>);

    #[async_trait]
    impl ProviderSession for ScriptedSession {
        async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
            Ok(self.0.take())
        }
    }

    fn request() -> ProviderRequest {
        ProviderRequest {
            route: ProviderRoute::Managed,
            messages: vec![ProviderMessage {
                role: ProviderMessageRole::User,
                content: "hello".to_owned(),
                tool_call_id: None,
                tool_name: None,
                tool_calls: Vec::new(),
            }],
            tools: Vec::new(),
            max_output_tokens: None,
            rate_card: None,
            cost_cap: None,
        }
    }

    fn test_config() -> RetryingProviderConfig {
        RetryingProviderConfig {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
            jitter: false,
        }
    }

    #[tokio::test]
    async fn retries_pre_stream_connect_429_and_5xx_then_preserves_first_success_event() {
        let inner = Arc::new(ScriptedProvider {
            outcomes: Mutex::new(VecDeque::from([
                Outcome::Port(ProviderPortError::Unavailable),
                Outcome::Event(ProviderEvent::Failed(ProviderFailure::RateLimited {
                    retry_after: Some(Duration::from_millis(2)),
                })),
                Outcome::Event(ProviderEvent::Failed(ProviderFailure::ServerUnavailable {
                    retry_after: None,
                })),
                Outcome::Event(ProviderEvent::ResponseStarted {
                    response_id: "ok".to_owned(),
                }),
            ])),
            calls: AtomicUsize::new(0),
        });
        let adapter = RetryingProvider::new(inner.clone(), test_config()).unwrap();
        let mut session = adapter.start(request()).await.unwrap();
        assert!(matches!(
            session.next_event().await.unwrap(),
            Some(ProviderEvent::ResponseStarted { response_id }) if response_id == "ok"
        ));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn authentication_schema_and_commit_unknown_are_never_retried() {
        for outcome in [
            Outcome::Event(ProviderEvent::Failed(ProviderFailure::Authentication)),
            Outcome::Event(ProviderEvent::Failed(ProviderFailure::InvalidResponse)),
            Outcome::Port(ProviderPortError::CommitUnknown),
        ] {
            let inner = Arc::new(ScriptedProvider {
                outcomes: Mutex::new(VecDeque::from([outcome])),
                calls: AtomicUsize::new(0),
            });
            let adapter = RetryingProvider::new(inner.clone(), test_config()).unwrap();
            match adapter.start(request()).await {
                Ok(mut session) => {
                    assert!(matches!(
                        session.next_event().await.unwrap(),
                        Some(ProviderEvent::Failed(
                            ProviderFailure::Authentication | ProviderFailure::InvalidResponse
                        ))
                    ));
                }
                Err(ProviderPortError::CommitUnknown) => {}
                Err(error) => panic!("unexpected error: {error}"),
            }
            assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn exponential_delay_and_retry_after_are_bounded_and_ordered() {
        let config = RetryingProviderConfig {
            max_retries: 6,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(64),
            jitter: false,
        };
        assert_eq!(retry_delay(config, 0, None), Duration::from_secs(1));
        assert_eq!(retry_delay(config, 5, None), Duration::from_secs(32));
        assert_eq!(
            retry_delay(config, 2, Some(Duration::from_secs(10))),
            Duration::from_secs(10)
        );
    }
}
