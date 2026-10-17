//! Retain the original host/session authority across replay, idle periods and delivery.
//!
//! The binding contains the verified session row identity, not its bearer cookie. Its real
//! host guard checks current role, deny, generation, absolute/idle expiry and owner lifetime.
//! A subscription never renews idle activity merely by remaining connected.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
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
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

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
        Box::pin(CurrentEventStream::new(inner, authority.clone(), kind)),
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

/// Stop the original subscription before attempting even a terminal control frame. A peer
/// that never accepts a Close frame must not retain the receiver or keep the task forever.
pub(super) async fn close(
    socket: &mut WebSocket,
    stream: AppEventStream,
    code: u16,
    reason: &'static str,
) {
    close_after_stream_drop(
        stream,
        socket.send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }))),
    )
    .await;
}

async fn close_after_stream_drop(stream: AppEventStream, close: impl Future) {
    drop(stream);
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, close).await;
}

type CurrentRead = Pin<Box<dyn Future<Output = Result<Option<AppEvent>, AppError>> + Send>>;

struct SourceState {
    inner: Option<AppEventStream>,
    error: Option<AppError>,
}

struct SharedSource(Mutex<SourceState>);

impl SharedSource {
    fn state(&self) -> MutexGuard<'_, SourceState> {
        self.0.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            state.error = Some(unavailable());
            state.inner = None;
            state
        })
    }

    fn check(&self) -> Result<(), AppError> {
        self.state().error.clone().map_or(Ok(()), Err)
    }

    fn close(&self, error: Option<AppError>) {
        let inner = {
            let mut state = self.state();
            if state.error.is_none() {
                state.error = error;
            }
            state.inner.take()
        };
        // The original receiver is dropped synchronously, before a Close frame is polled.
        drop(inner);
    }

    fn poll_next(&self, cx: &mut Context<'_>) -> Poll<Result<Option<AppEvent>, AppError>> {
        let mut state = self.state();
        if let Some(error) = &state.error {
            return Poll::Ready(Err(error.clone()));
        }
        let Some(inner) = state.inner.as_mut() else {
            return Poll::Ready(Ok(None));
        };
        // Stream::poll_next must not block. The lock never spans an await or a DB check.
        inner.as_mut().poll_next(cx).map(Ok)
    }
}

struct CurrentEventStream {
    source: Arc<SharedSource>,
    monitor: tokio::task::JoinHandle<()>,
    pending: Option<CurrentRead>,
    authority: RealtimeAuthority,
    kind: ActivityKind,
    done: bool,
}

impl CurrentEventStream {
    fn new(inner: AppEventStream, authority: RealtimeAuthority, kind: ActivityKind) -> Self {
        let source = Arc::new(SharedSource(Mutex::new(SourceState {
            inner: Some(inner),
            error: None,
        })));
        let weak = Arc::downgrade(&source);
        let current = authority.clone();
        let monitor = tokio::spawn(async move {
            loop {
                tokio::time::sleep(CHECK_PERIOD).await;
                let Some(source) = weak.upgrade() else {
                    return;
                };
                if source.state().inner.is_none() {
                    return;
                }
                if let Err(error) = current.verify_current().await {
                    source.close(Some(error));
                    return;
                }
            }
        });
        Self {
            source,
            monitor,
            pending: None,
            authority,
            kind,
            done: false,
        }
    }

    fn stop(&mut self) {
        self.source.close(None);
        self.monitor.abort();
        self.done = true;
    }
}

impl Drop for CurrentEventStream {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn next_current(
    authority: &RealtimeAuthority,
    source: &SharedSource,
) -> Result<Option<AppEvent>, AppError> {
    // Before consuming even a frame already queued under an earlier authorization.
    source.check()?;
    authority.verify_current().await?;
    source.check()?;
    loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep(CHECK_PERIOD) => {
                source.check()?;
                authority.verify_current().await?;
                source.check()?;
            }
            event = poll_fn(|cx| source.poll_next(cx)) => {
                // The producer may have waited while logout/revocation committed. Never
                // hand off that result using the authorization from before the wait.
                let event = event?;
                authority.verify_current().await?;
                source.check()?;
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
            let source = self.source.clone();
            let authority = self.authority.clone();
            self.pending = Some(Box::pin(
                async move { next_current(&authority, &source).await },
            ));
        }
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(None);
        };
        let Poll::Ready(result) = pending.as_mut().poll(cx) else {
            return Poll::Pending;
        };
        self.pending = None;
        match result {
            Ok(Some(event)) => Poll::Ready(Some(event)),
            Ok(None) => {
                self.stop();
                Poll::Ready(None)
            }
            Err(error) => {
                // Drop the real bounded receiver before yielding the terminal error. Its
                // Drop stops the producer and discards every previously queued body.
                self.stop();
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
            CurrentEventStream::new(
                Box::pin(Queued {
                    guard,
                    revoke_during_read,
                    dropped: dropped.clone(),
                }),
                authority,
                ActivityKind::Thread,
            ),
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
        let mut stream = CurrentEventStream::new(Box::pin(Idle), authority, ActivityKind::Channel);
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

    #[tokio::test]
    async fn blocked_terminal_close_drops_the_subscription_before_owner_invalidation() {
        struct BlockedTransport {
            source_dropped: Arc<AtomicBool>,
            polled: Arc<AtomicBool>,
            dropped: Arc<AtomicBool>,
        }
        impl Future for BlockedTransport {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                assert!(self.source_dropped.load(Ordering::SeqCst));
                self.polled.store(true, Ordering::SeqCst);
                Poll::Pending
            }
        }
        impl Drop for BlockedTransport {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
        let (owner, authority, guard) = bound();
        let (stream, source_dropped) = queued(authority.clone(), guard, false);
        let polled = Arc::new(AtomicBool::new(false));
        let transport_dropped = Arc::new(AtomicBool::new(false));
        let mut finish = Box::pin(close_after_stream_drop(
            Box::pin(stream),
            BlockedTransport {
                source_dropped: source_dropped.clone(),
                polled: polled.clone(),
                dropped: transport_dropped.clone(),
            },
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut finish)
                .await
                .is_err()
        );
        assert!(source_dropped.load(Ordering::SeqCst));
        assert!(polled.load(Ordering::SeqCst));
        owner.close();
        assert!(matches!(
            authority.verify_current().await,
            Err(AppError::Unauthenticated)
        ));
        tokio::time::timeout(CLOSE_TIMEOUT + Duration::from_millis(250), finish)
            .await
            .expect("a permanently blocked Close must finish within its fixed budget");
        assert!(transport_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn unpolled_consumer_releases_the_original_source_when_its_host_closes() {
        let (owner, authority, guard) = bound();
        let (stream, dropped) = queued(authority, guard, false);
        // Deliberately never poll the body, matching an SSE transport under backpressure.
        assert!(!dropped.load(Ordering::SeqCst));
        owner.close();
        tokio::time::timeout(CHECK_PERIOD + Duration::from_millis(500), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("host closure must release the receiver without a body poll");
        assert!(matches!(
            stream.source.check(),
            Err(AppError::Unauthenticated)
        ));
    }
}
