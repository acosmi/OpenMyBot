use super::*;
use crate::ProviderRouter;
use openbot_application::{ProviderMessage, ProviderMessageRole, ProviderRoute};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Inner {
    result: Result<StopOutcome, ProviderPortError>,
    calls: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
}
#[async_trait]
impl ProviderSession for Inner {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(Some(ProviderEvent::Completed))
    }
    async fn request_stop(&mut self) -> Result<StopOutcome, ProviderPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result
    }
}
fn wrapper(
    result: Result<StopOutcome, ProviderPortError>,
    first: Result<Option<ProviderEvent>, ProviderPortError>,
) -> (PrefetchedSession, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    (
        PrefetchedSession {
            first: Some(first),
            inner: Box::new(Inner {
                result,
                calls: calls.clone(),
                reads: reads.clone(),
            }),
        },
        calls,
        reads,
    )
}
#[tokio::test]
async fn prefetched_stop_forwards_each_inner_outcome_without_consuming_first() {
    for outcome in [
        StopOutcome::Confirmed {
            at: std::time::UNIX_EPOCH,
        },
        StopOutcome::Unknown,
        StopOutcome::Unsupported,
    ] {
        for consumed in [false, true] {
            let first = ProviderEvent::ResponseStarted {
                response_id: "first".into(),
            };
            let (mut session, calls, reads) = wrapper(Ok(outcome), Ok(Some(first.clone())));
            if consumed {
                assert_eq!(session.next_event().await, Ok(Some(first.clone())));
            }
            assert_eq!(session.request_stop().await, Ok(outcome));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            if !consumed {
                assert_eq!(session.next_event().await, Ok(Some(first)));
            }
            assert_eq!(
                session.next_event().await,
                Ok(Some(ProviderEvent::Completed))
            );
            assert_eq!(reads.load(Ordering::SeqCst), 1);
        }
    }
}
#[tokio::test]
async fn prefetched_stop_preserves_inner_errors_before_and_after_first_event() {
    for error in [
        ProviderPortError::InvalidRequest { field: "fixture" },
        ProviderPortError::Unavailable,
        ProviderPortError::CommitUnknown,
    ] {
        for consumed in [false, true] {
            for first in [
                Ok(Some(ProviderEvent::Completed)),
                Err(ProviderPortError::Unavailable),
            ] {
                let (mut session, calls, reads) = wrapper(Err(error), first.clone());
                if consumed {
                    assert_eq!(session.next_event().await, first);
                }
                assert_eq!(session.request_stop().await, Err(error));
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(reads.load(Ordering::SeqCst), 0);
                if !consumed {
                    assert_eq!(session.next_event().await, first);
                }
            }
        }
    }
}
struct Adapter {
    result: StopOutcome,
    calls: Arc<AtomicUsize>,
}
#[async_trait]
impl ProviderAdapter for Adapter {
    async fn start(
        &self,
        _request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        Ok(Box::new(Inner {
            result: Ok(self.result),
            calls: self.calls.clone(),
            reads: Arc::new(AtomicUsize::new(0)),
        }))
    }
}
fn request(route: ProviderRoute) -> ProviderRequest {
    ProviderRequest {
        route,
        messages: vec![ProviderMessage {
            role: ProviderMessageRole::User,
            content: "fixture".into(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: vec![],
        }],
        tools: vec![],
        max_output_tokens: None,
        rate_card: None,
        cost_cap: None,
    }
}
#[tokio::test]
async fn router_returns_original_stop_capability_without_wrapping_or_fallback() {
    let package = Arc::new(AtomicUsize::new(0));
    let managed = Arc::new(AtomicUsize::new(0));
    let router = ProviderRouter::new(
        Arc::new(Adapter {
            result: StopOutcome::Unknown,
            calls: package.clone(),
        }),
        Some(Arc::new(Adapter {
            result: StopOutcome::Confirmed {
                at: std::time::UNIX_EPOCH,
            },
            calls: managed.clone(),
        })),
    );
    let mut a = router
        .start(request(ProviderRoute::PackageOpenAi))
        .await
        .unwrap();
    let mut b = router.start(request(ProviderRoute::Managed)).await.unwrap();
    assert_eq!(a.request_stop().await, Ok(StopOutcome::Unknown));
    assert_eq!(
        b.request_stop().await,
        Ok(StopOutcome::Confirmed {
            at: std::time::UNIX_EPOCH
        })
    );
    assert_eq!(
        (
            package.load(Ordering::SeqCst),
            managed.load(Ordering::SeqCst)
        ),
        (1, 1)
    );
    let missing = ProviderRouter::new(
        Arc::new(Adapter {
            result: StopOutcome::Unsupported,
            calls: package.clone(),
        }),
        None,
    );
    assert!(matches!(
        missing.start(request(ProviderRoute::Managed)).await,
        Err(ProviderPortError::Unavailable)
    ));
    assert_eq!(package.load(Ordering::SeqCst), 1);
}
