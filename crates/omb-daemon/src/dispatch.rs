//! Turns pending accepted messages into delegated runs through the engine's single entry.
use crate::{ChannelError, Connection, OMB_EXPIRY_NOTICE_V1, STORE_BUDGET, Task, Timings};
use omb_store::{
    Claim, DispatchItem, DispatchOutcome, claim_dispatch, expire_pending, lock_dispatch,
    record_dispatch,
};
use openbot_application::{BeginDelegatedThreadRun, DelegatedRunEntry, DelegatedUntrustedMaterial};
use openbot_contracts::{
    auth::DelegationSource,
    command::ThreadRunStarted,
    error::AppError,
    ids::{BotId, RunId, ThreadId},
};
use std::{collections::HashSet, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::{
    sync::{Mutex, Notify, oneshot},
    time::Instant,
};

const BOT_ID: &str = "omb-crabcode";

/// `min` doubled per attempt, capped at `max`.
pub(crate) fn backoff_ceiling(attempt: u32, min: Duration, max: Duration) -> Duration {
    min.checked_mul(2u32.saturating_pow(attempt))
        .unwrap_or(max)
        .min(max)
}
/// Full jitter: uniform in `[0, backoff_ceiling]`.
pub(crate) fn backoff(attempt: u32, min: Duration, max: Duration) -> Duration {
    let ceiling = backoff_ceiling(attempt, min, max);
    let nanos = u64::try_from(ceiling.as_nanos()).unwrap_or(u64::MAX);
    getrandom::u64().map_or(ceiling, |random| {
        Duration::from_nanos(random % nanos.saturating_add(1))
    })
}

fn request(item: DispatchItem) -> BeginDelegatedThreadRun {
    BeginDelegatedThreadRun {
        source: DelegationSource::ExternalBinding {
            binding_id: item.binding_id.to_string(),
        },
        revision: item.revision,
        trigger_id: item.record_id.to_string(),
        thread_id: ThreadId::new(item.thread_id),
        run_id: RunId::new(item.run_id),
        bot_id: BotId::new(BOT_ID),
        untrusted_material: Some(DelegatedUntrustedMaterial {
            source_ref: format!("omb:channel_events:{}", item.record_id),
            text: item.text,
        }),
    }
}
/// Receipt mapping: started or replayed runs are dispatched; lease conflicts, an unavailable
/// dependency and accepted reconciliation retry the same run id; a stale grant cancels; every
/// other refusal is a final conflict.
fn outcome(
    receipt: &Result<ThreadRunStarted, AppError>,
    attempts: u32,
    timings: &Timings,
) -> DispatchOutcome {
    match receipt {
        Ok(_) => DispatchOutcome::Dispatched,
        Err(AppError::LeaseConflict { .. }) => DispatchOutcome::RetryAfter(timings.dispatch_retry),
        Err(AppError::PolicyRefused { rule, .. }) if rule == "delegation_not_current" => {
            DispatchOutcome::GrantStale
        }
        Err(
            AppError::DependencyUnavailable { .. }
            | AppError::ReconciliationRequired { accepted: true },
        ) => {
            DispatchOutcome::RetryAfter(backoff(attempts, timings.backoff_min, timings.backoff_max))
        }
        Err(_) => DispatchOutcome::Conflict,
    }
}

/// Starts the dispatcher; it wakes on `wake`, at the nearest retry or expiry time, or on stop.
/// Each dispatch holds `gate`, which the daemon's run canceller shares, from before its event lock
/// until `record_dispatch` returns. A COMMIT already sent can still land after this client gives
/// up; the canceller asks the engine first, so the begun run is still stopped, and at worst its
/// store update waits up to 2 s on the event's row lock and answers `internal_error`. The gate
/// also holds the run ids whose begin outcome is unknown.
pub(crate) fn start_dispatcher(
    connection: Connection,
    entry: DelegatedRunEntry,
    timings: Timings,
    wake: Arc<Notify>,
    gate: Arc<Mutex<HashSet<String>>>,
) -> Task {
    Task::spawn(connection, move |client, stop| {
        dispatch(client, entry, timings, wake, gate, stop)
    })
}
async fn dispatch(
    mut client: tokio_postgres::Client,
    entry: DelegatedRunEntry,
    timings: Timings,
    wake: Arc<Notify>,
    gate: Arc<Mutex<HashSet<String>>>,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), ChannelError> {
    let store = |_| ChannelError::StoreFailed;
    while matches!(stop.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
        let expired = expire_pending(
            &mut client,
            timings.pending_ttl,
            OMB_EXPIRY_NOTICE_V1,
            Instant::now() + STORE_BUDGET,
        )
        .await
        .map_err(store)?;
        match claim_dispatch(&client).await.map_err(store)? {
            Claim::Item(item) => {
                let (record_id, attempts, run_id) =
                    (item.record_id, item.attempts, item.run_id.clone());
                // Held until `record_dispatch` returns, on every exit of this dispatch: a cancel
                // waits for the begin to settle, also when this connection is lost mid-dispatch.
                // It also holds the run ids whose begin outcome is unknown.
                let mut unknown = gate.lock().await;
                // The event stays locked from before the begin until its receipt is recorded.
                let Some(dispatch) =
                    lock_dispatch(&mut client, record_id, Instant::now() + STORE_BUDGET)
                        .await
                        .map_err(store)?
                else {
                    continue;
                };
                let receipt = entry.begin(request(item)).await;
                // A begin whose COMMIT outcome is unknown may still land; a started run settles it.
                match &receipt {
                    Err(AppError::ReconciliationRequired { accepted: true }) => {
                        unknown.insert(run_id);
                    }
                    Ok(_) => {
                        unknown.remove(&run_id);
                    }
                    Err(_) => {}
                }
                record_dispatch(
                    dispatch,
                    record_id,
                    outcome(&receipt, attempts, &timings),
                    Instant::now() + STORE_BUDGET,
                )
                .await
                .map_err(store)?;
            }
            Claim::Idle { wake_at } => {
                let next = wake_at.into_iter().chain(expired.next_due).min();
                let due = async {
                    match next {
                        Some(at) => {
                            let delay = (at - OffsetDateTime::now_utc())
                                .try_into()
                                .unwrap_or_default();
                            tokio::time::sleep(delay).await;
                        }
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    _ = &mut stop => return Ok(()),
                    () = wake.notified() => {}
                    () = due => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn item() -> DispatchItem {
        DispatchItem {
            record_id: Uuid::parse_str("0192f1a2-3b4c-7d5e-8f60-000000000001").unwrap(),
            binding_id: Uuid::parse_str("0192f1a2-3b4c-7d5e-8f60-718293a4b5c6").unwrap(),
            revision: 3,
            thread_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            run_id: "3b5a3661-5a30-58d9-9995-50796e16f538".into(),
            text: "please refactor the parser".into(),
            attempts: 2,
        }
    }
    #[test]
    fn begin_request_carries_event_fields_and_source_ref() {
        let request = request(item());
        assert!(matches!(
            &request.source,
            DelegationSource::ExternalBinding { binding_id } if binding_id == "0192f1a2-3b4c-7d5e-8f60-718293a4b5c6"
        ));
        assert_eq!(request.revision, 3);
        assert_eq!(request.trigger_id, "0192f1a2-3b4c-7d5e-8f60-000000000001");
        assert_eq!(
            request.thread_id.as_str(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(
            request.run_id.as_str(),
            "3b5a3661-5a30-58d9-9995-50796e16f538"
        );
        assert_eq!(request.bot_id.as_str(), "omb-crabcode");
        let material = request.untrusted_material.as_ref().unwrap();
        assert_eq!(
            material.source_ref,
            "omb:channel_events:0192f1a2-3b4c-7d5e-8f60-000000000001"
        );
        assert_eq!(material.text, "please refactor the parser");
        // The original text travels only as untrusted material.
        assert!(!format!("{request:?}").contains("refactor"));
        assert!(
            !material.source_ref.contains("refactor") && !request.trigger_id.contains("refactor")
        );
    }
    #[test]
    fn receipt_mapping_follows_section_5_5_item_5() {
        let timings = Timings::default();
        let started = ThreadRunStarted {
            thread_id: ThreadId::new("t"),
            run_id: RunId::new("r"),
            message_sequence: 1,
            event_sequence: 1,
            replayed: false,
        };
        let map = |receipt: Result<ThreadRunStarted, AppError>| outcome(&receipt, 0, &timings);
        assert_eq!(map(Ok(started.clone())), DispatchOutcome::Dispatched);
        assert_eq!(
            map(Ok(ThreadRunStarted {
                replayed: true,
                ..started
            })),
            DispatchOutcome::Dispatched
        );
        assert_eq!(
            map(Err(AppError::RequestConflict { resource: "run" })),
            DispatchOutcome::Conflict
        );
        assert_eq!(
            map(Err(AppError::LeaseConflict { holder: None })),
            DispatchOutcome::RetryAfter(Duration::from_secs(5))
        );
        assert_eq!(
            map(Err(AppError::PolicyRefused {
                rule: "delegation_not_current".into(),
                decision: None
            })),
            DispatchOutcome::GrantStale
        );
        for retried in [
            AppError::DependencyUnavailable {
                dependency: "delegation_authority",
            },
            AppError::ReconciliationRequired { accepted: true },
        ] {
            assert!(
                matches!(map(Err(retried)), DispatchOutcome::RetryAfter(d) if d <= Duration::from_secs(1))
            );
        }
        for refused in [
            AppError::MalformedPayload {
                field: "delegation",
            },
            AppError::NotVisible,
            AppError::ReconciliationRequired { accepted: false },
            AppError::PolicyRefused {
                rule: "delegated_authority_refused".into(),
                decision: None,
            },
            AppError::Unauthenticated,
            AppError::VendorFailure { vendor: "x" },
        ] {
            assert_eq!(map(Err(refused)), DispatchOutcome::Conflict);
        }
    }
    #[test]
    fn retry_delay_is_dispatch_retry_for_lease_conflict_and_backoff_for_dependency() {
        let timings = Timings {
            dispatch_retry: Duration::from_millis(1234),
            ..Timings::default()
        };
        for attempts in [0, 3, 30] {
            assert_eq!(
                outcome(
                    &Err(AppError::LeaseConflict { holder: None }),
                    attempts,
                    &timings
                ),
                DispatchOutcome::RetryAfter(Duration::from_millis(1234))
            );
            let ceiling = backoff_ceiling(attempts, timings.backoff_min, timings.backoff_max);
            for _ in 0..50 {
                let DispatchOutcome::RetryAfter(delay) = outcome(
                    &Err(AppError::DependencyUnavailable {
                        dependency: "database",
                    }),
                    attempts,
                    &timings,
                ) else {
                    panic!("dependency failure retries");
                };
                assert!(delay <= ceiling);
            }
        }
        assert_eq!(
            backoff_ceiling(3, timings.backoff_min, timings.backoff_max),
            Duration::from_secs(8)
        );
    }
    #[test]
    fn backoff_ceiling_doubles_from_one_to_sixty_seconds() {
        let (min, max) = (Duration::from_secs(1), Duration::from_secs(60));
        let ceilings: Vec<u64> = (0..8)
            .map(|a| backoff_ceiling(a, min, max).as_secs())
            .collect();
        assert_eq!(ceilings, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(backoff_ceiling(u32::MAX, min, max), max);
        assert_eq!(backoff_ceiling(40, min, max), max);
    }
    #[test]
    fn backoff_is_drawn_within_zero_and_ceiling() {
        let (min, max) = (Duration::from_secs(1), Duration::from_secs(60));
        for attempt in 0..10 {
            let ceiling = backoff_ceiling(attempt, min, max);
            let draws: Vec<Duration> = (0..200).map(|_| backoff(attempt, min, max)).collect();
            assert!(draws.iter().all(|d| *d <= ceiling));
            assert!(draws.iter().any(|d| *d < ceiling / 2), "attempt {attempt}");
        }
    }
}
