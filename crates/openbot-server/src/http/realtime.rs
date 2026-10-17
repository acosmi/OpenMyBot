//! Retain the original host/session authority across replay, idle periods and delivery.
//!
//! The binding contains the verified session row identity, not its bearer cookie. Its real
//! host guard checks current role, deny, generation, absolute/idle expiry and owner lifetime.
//! A subscription never renews idle activity merely by remaining connected.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use futures_core::Stream;
use openbot_application::AppEventStream;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppEvent, SubscriptionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::HostRequestBindingError;

use super::ServerState;

const CHECK_PERIOD: Duration = Duration::from_secs(1);
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct RealtimeAuthority {
    auth: AuthContext,
}

impl RealtimeAuthority {
    async fn verify_current(&self) -> Result<(), AppError> {
        let binding = self
            .auth
            .request_binding()
            .ok_or(AppError::Unauthenticated)?;
        let deadline = Instant::now() + CHECK_TIMEOUT;
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            binding.verify_current_before(&self.auth, deadline),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|error| match error {
            HostRequestBindingError::NotCurrent | HostRequestBindingError::Missing => {
                AppError::Unauthenticated
            }
            HostRequestBindingError::Unavailable => unavailable(),
        })
    }

    async fn invalidated(&self) {
        loop {
            tokio::time::sleep(CHECK_PERIOD).await;
            if self.verify_current().await.is_err() {
                return;
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ActivityKind {
    Thread,
    Channel,
    Approval,
}

impl ActivityKind {
    fn error(self, error: AppError) -> AppEvent {
        let code = error.code().as_str().to_owned();
        match self {
            Self::Thread => AppEvent::ThreadStreamError { code },
            Self::Channel => AppEvent::ChannelStreamError { code },
            Self::Approval => AppEvent::ToolApprovalStreamError { code },
        }
    }
}

/// Authentication bookends the real application subscription before headers/upgrade.
pub(super) async fn subscribe(
    state: &ServerState,
    auth: AuthContext,
    request: SubscriptionRequest,
) -> Result<(AppEventStream, RealtimeAuthority), AppError> {
    let kind = match &request {
        SubscriptionRequest::ThreadEvents { .. } => ActivityKind::Thread,
        SubscriptionRequest::ChannelActivity => ActivityKind::Channel,
        SubscriptionRequest::ToolApprovalActivity => ActivityKind::Approval,
        SubscriptionRequest::Health => return Err(unavailable()),
    };
    let authority = RealtimeAuthority { auth: auth.clone() };
    authority.verify_current().await?;
    let inner = state.application().subscribe(auth, request).await?;
    authority.verify_current().await?;
    Ok((
        Box::pin(CurrentEventStream {
            inner: Some(inner),
            pending: None,
            authority: authority.clone(),
            kind,
            done: false,
        }),
        authority,
    ))
}

/// A blocked socket cannot hold a previously authorized frame indefinitely. Dropping this
/// send on invalidation/timeout also prevents later frames from using the old authorization.
pub(super) async fn send(
    socket: &mut WebSocket,
    message: Message,
    authority: &RealtimeAuthority,
) -> Result<(), ()> {
    authority.verify_current().await.map_err(|_| ())?;
    tokio::select! {
        biased;
        () = authority.invalidated() => Err(()),
        result = tokio::time::timeout(SEND_TIMEOUT, socket.send(message)) => {
            result.map_err(|_| ())?.map_err(|_| ())
        }
    }
}

type CurrentRead =
    Pin<Box<dyn Future<Output = (AppEventStream, Result<Option<AppEvent>, AppError>)> + Send>>;

struct CurrentEventStream {
    inner: Option<AppEventStream>,
    pending: Option<CurrentRead>,
    authority: RealtimeAuthority,
    kind: ActivityKind,
    done: bool,
}

async fn next_current(
    authority: &RealtimeAuthority,
    inner: &mut AppEventStream,
) -> Result<Option<AppEvent>, AppError> {
    // Before consuming even a frame already queued under an earlier authorization.
    authority.verify_current().await?;
    loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep(CHECK_PERIOD) => {
                authority.verify_current().await?;
            }
            event = poll_fn(|cx| inner.as_mut().poll_next(cx)) => {
                // The producer may have waited while logout/revocation committed. Never
                // hand off that result using the authorization from before the wait.
                authority.verify_current().await?;
                return Ok(event);
            }
        }
    }
}

impl Stream for CurrentEventStream {
    type Item = AppEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        if self.pending.is_none() {
            let Some(mut inner) = self.inner.take() else {
                self.done = true;
                return Poll::Ready(None);
            };
            let authority = self.authority.clone();
            self.pending = Some(Box::pin(async move {
                let result = next_current(&authority, &mut inner).await;
                (inner, result)
            }));
        }
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(None);
        };
        let Poll::Ready((inner, result)) = pending.as_mut().poll(cx) else {
            return Poll::Pending;
        };
        self.pending = None;
        match result {
            Ok(Some(event)) => {
                self.inner = Some(inner);
                Poll::Ready(Some(event))
            }
            Ok(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Err(error) => {
                // Drop the real bounded receiver before yielding the terminal error. Its
                // Drop stops the producer and discards every previously queued body.
                drop(inner);
                self.done = true;
                Poll::Ready(Some(self.kind.error(error)))
            }
        }
    }
}

fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "realtime_authority",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::request_binding::{
        HostRequestBindingGuard, HostRequestBindingKind, RequestBindingOwnerLease,
        ServerSessionBindingIdentity,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    struct Guard(AtomicU8);
    impl HostRequestBindingGuard for Guard {
        fn verify_current<'a>(
            &'a self,
            _: &'a AuthContext,
        ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>
        {
            Box::pin(async move {
                match self.0.load(Ordering::SeqCst) {
                    0 => Ok(()),
                    1 => Err(HostRequestBindingError::NotCurrent),
                    _ => Err(HostRequestBindingError::Unavailable),
                }
            })
        }
        fn verify_current_before<'a>(
            &'a self,
            auth: &'a AuthContext,
            _: Instant,
        ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>
        {
            self.verify_current(auth)
        }
    }

    fn bound() -> (RequestBindingOwnerLease, RealtimeAuthority, Arc<Guard>) {
        let (owner, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        let auth = AuthContextBuilder::from_verified_session(
            DeploymentId::new("realtime-test"),
            TenantId::new("realtime-test"),
            ActorId::new("realtime-test"),
            AuthGeneration::new(0),
            false,
        )
        .with_role(Role::User)
        .build();
        let guard = Arc::new(Guard(AtomicU8::new(0)));
        let epoch = ServerSessionBindingIdentity::from_verified_row(
            "synthetic-realtime-session".into(),
            auth.actor().clone(),
            "synthetic-hash-column".into(),
            time::OffsetDateTime::UNIX_EPOCH,
            auth.auth_generation(),
        );
        let binding = issuer
            .bind_server_session(&auth, epoch, guard.clone())
            .unwrap();
        let authority = RealtimeAuthority {
            auth: auth.with_verified_request_binding(binding).unwrap(),
        };
        (owner, authority, guard)
    }

    struct Queued {
        guard: Arc<Guard>,
        revoke_during_read: bool,
        dropped: Arc<AtomicBool>,
    }
    impl Stream for Queued {
        type Item = AppEvent;
        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<AppEvent>> {
            if self.revoke_during_read {
                self.guard.0.store(1, Ordering::SeqCst);
            }
            Poll::Ready(Some(AppEvent::Heartbeat { seq: 7 }))
        }
    }
    impl Drop for Queued {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn queued(
        authority: RealtimeAuthority,
        guard: Arc<Guard>,
        revoke_during_read: bool,
    ) -> (CurrentEventStream, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        (
            CurrentEventStream {
                inner: Some(Box::pin(Queued {
                    guard,
                    revoke_during_read,
                    dropped: dropped.clone(),
                })),
                pending: None,
                authority,
                kind: ActivityKind::Thread,
                done: false,
            },
            dropped,
        )
    }

    #[tokio::test]
    async fn revocation_discards_queued_frames_and_closes_the_original_receiver() {
        let (_owner, authority, guard) = bound();
        let (mut stream, dropped) = queued(authority, guard.clone(), false);
        assert!(matches!(
            poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await,
            Some(AppEvent::Heartbeat { seq: 7 })
        ));
        guard.0.store(1, Ordering::SeqCst);
        assert!(matches!(
            poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await,
            Some(AppEvent::ThreadStreamError { code }) if code == "unauthenticated"
        ));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(
            poll_fn(|cx| Pin::new(&mut stream).poll_next(cx))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn revocation_while_the_producer_returns_cannot_handoff_its_frame() {
        let (_owner, authority, guard) = bound();
        let (mut stream, dropped) = queued(authority, guard, true);
        assert!(matches!(
            poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await,
            Some(AppEvent::ThreadStreamError { code }) if code == "unauthenticated"
        ));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn unavailable_authority_is_a_dependency_error_and_never_delivers_a_body() {
        let (_owner, authority, guard) = bound();
        guard.0.store(2, Ordering::SeqCst);
        let (mut stream, dropped) = queued(authority, guard, false);
        assert!(matches!(
            poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await,
            Some(AppEvent::ThreadStreamError { code }) if code == "dependency_unavailable"
        ));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn closing_the_real_host_ends_an_idle_subscription_without_a_new_event() {
        struct Idle;
        impl Stream for Idle {
            type Item = AppEvent;
            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<AppEvent>> {
                Poll::Pending
            }
        }
        let (owner, authority, _) = bound();
        let mut stream = CurrentEventStream {
            inner: Some(Box::pin(Idle)),
            pending: None,
            authority,
            kind: ActivityKind::Channel,
            done: false,
        };
        let mut read = Box::pin(poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut read)
                .await
                .is_err()
        );
        owner.close();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), read).await.unwrap(),
            Some(AppEvent::ChannelStreamError { code }) if code == "unauthenticated"
        ));
    }
}
