//! Engine-backed multi-viewer ScreenHub and one-time viewer-ticket authority.

pub mod coordinates;
pub mod engine_owner;

use core::fmt;
use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use openbot_application::{ScreenSessionAdministration, ScreenSessionAdministrationError};
use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::engine::MAX_ENGINE_IMAGE_BYTES;
use openbot_contracts::ids::{ActorId, ComputerGeneration, ComputerId, TabId, TenantId};
use openbot_contracts::screen::{
    ScreenSessionRequest, ScreenSessionTicket, ScreenViewerBindingRequest,
};
use openbot_domain::vault::SecretBytes;
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

use crate::engine::{EngineFrame, EngineScreenSource, ScreenAudience, ScreenStreamKey};

/// Base WebSocket subprotocol selected by the host. The one-time ticket is a separate requested
/// subprotocol and must never be echoed in the upgrade response.
pub const SCREEN_VIEWER_PROTOCOL: &str = "openbot.screen.v1";
/// Fixed first-source viewer ticket lifetime.
pub const SCREEN_TICKET_TTL: Duration = Duration::seconds(30);
/// Conservative Server production default; explicit hosts remain bounded by the closed ceiling.
pub const DEFAULT_SCREEN_VIEWERS_PER_STREAM: usize = 8;
const TICKET_PREFIX: &str = "obot_screen_";
const VIEWER_FRAME_MAGIC: &[u8; 8] = b"OBSCRN01";
const VIEWER_FRAME_VERSION: u16 = 1;
/// Fixed binary viewer header size.
pub const SCREEN_VIEWER_HEADER_BYTES: usize = 68;
/// Maximum authenticated viewer binary frame including its fixed header.
pub const SCREEN_VIEWER_MAX_BINARY_BYTES: usize =
    MAX_ENGINE_IMAGE_BYTES + SCREEN_VIEWER_HEADER_BYTES;
const MAX_VIEWERS_PER_STREAM: usize = 256;

/// Host-verified binding carried by one ticket and exact viewer connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenViewerBinding {
    origin: String,
    desktop_window: Option<(String, u64)>,
}

impl ScreenViewerBinding {
    /// Bind a Server viewer after the same-origin session extractor has verified `origin`.
    pub fn verified_server(origin: impl Into<String>) -> Result<Self, ScreenHubError> {
        Self::new(origin.into(), None)
    }

    /// Bind a Desktop viewer to the current window label and host-minted binding generation.
    pub fn verified_desktop(
        origin: impl Into<String>,
        window_label: impl Into<String>,
        window_binding: u64,
    ) -> Result<Self, ScreenHubError> {
        let label = window_label.into();
        if !bounded(&label, 256) || window_binding == 0 {
            return Err(ScreenHubError::InvalidBinding);
        }
        Self::new(origin.into(), Some((label, window_binding)))
    }

    fn new(origin: String, desktop_window: Option<(String, u64)>) -> Result<Self, ScreenHubError> {
        if !bounded(&origin, 512) || origin.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(ScreenHubError::InvalidBinding);
        }
        Ok(Self {
            origin,
            desktop_window,
        })
    }
}

/// One newly issued 128-bit ticket. Debug never prints the ticket protocol value.
pub struct IssuedScreenTicket {
    token: SecretBytes,
    expires_at: OffsetDateTime,
}

impl IssuedScreenTicket {
    /// Non-secret base protocol the server should select.
    #[must_use]
    pub const fn base_protocol(&self) -> &'static str {
        SCREEN_VIEWER_PROTOCOL
    }

    /// Secret second requested subprotocol. Callers must not log it or place it in a URL.
    #[must_use]
    pub fn ticket_protocol(&self) -> String {
        format!("{TICKET_PREFIX}{}", hex(self.token.expose()))
    }

    /// Absolute expiry.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

impl fmt::Debug for IssuedScreenTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedScreenTicket")
            .field("ticket", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone)]
struct PendingTicket {
    key: ScreenStreamKey,
    tenant: TenantId,
    actor: ActorId,
    auth_generation: AuthGeneration,
    binding: ScreenViewerBinding,
    expires_at: OffsetDateTime,
}

/// Rust-only viewer demand. Closing a stream is irreversible even while old viewer handles live.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScreenDemand {
    viewers: usize,
    closed: bool,
}

impl ScreenDemand {
    /// Whether this exact live stream has an attached viewer (pending tickets are not viewers).
    #[must_use]
    pub const fn has_viewers(self) -> bool {
        self.viewers != 0 && !self.closed
    }

    /// Whether the source was detached, invalidated or ended.
    #[must_use]
    pub const fn is_closed(self) -> bool {
        self.closed
    }
}

/// Read-only demand handle minted at source attachment, never from a renderer or a stream ID.
#[derive(Debug)]
pub struct ScreenDemandObserver {
    receiver: watch::Receiver<ScreenDemand>,
}

impl ScreenDemandObserver {
    fn is_closed(&self) -> bool {
        self.receiver.borrow().closed
    }

    /// Current demand, marking this revision observed.
    pub fn current(&mut self) -> ScreenDemand {
        *self.receiver.borrow_and_update()
    }

    /// Await a viewer-count or terminal change. Producer loss is terminal, not an idle request.
    pub async fn changed(&mut self) -> ScreenDemand {
        if self.receiver.changed().await.is_err() {
            return ScreenDemand {
                viewers: 0,
                closed: true,
            };
        }
        self.current()
    }
}

struct StreamEntry {
    audience: ScreenAudience,
    sender: watch::Sender<Option<Arc<ScreenViewerFrame>>>,
    viewers: watch::Sender<ScreenDemand>,
    task: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct HubState {
    streams: BTreeMap<ScreenStreamKey, StreamEntry>,
    tickets: BTreeMap<[u8; 32], PendingTicket>,
}

impl Drop for HubState {
    fn drop(&mut self) {
        for stream in self.streams.values_mut() {
            stream.viewers.send_modify(|demand| demand.closed = true);
            stream.sender.send_replace(None);
            if let Some(task) = stream.task.take() {
                task.abort();
            }
        }
    }
}

/// Process-wide ScreenHub. Each stream owns one latest frame and all viewers clone that same watch
/// value; there is no per-viewer queue that can grow with frame rate.
#[derive(Clone)]
pub struct ScreenHub {
    state: Arc<Mutex<HubState>>,
    max_viewers_per_stream: usize,
}

/// Computer-owned ApplicationService port for issuing ScreenHub tickets.
#[derive(Clone)]
pub struct ScreenSessionService {
    hub: ScreenHub,
}

impl ScreenSessionService {
    /// Bind ticket issuance to the exact process-wide ScreenHub used by the frame transport.
    #[must_use]
    pub const fn new(hub: ScreenHub) -> Self {
        Self { hub }
    }

    async fn issue_at(
        &self,
        auth: &AuthContext,
        request: ScreenSessionRequest,
        now: OffsetDateTime,
    ) -> Result<ScreenSessionTicket, ScreenSessionAdministrationError> {
        let binding = match request.binding {
            ScreenViewerBindingRequest::Server { origin } => {
                ScreenViewerBinding::verified_server(origin)
            }
            ScreenViewerBindingRequest::Desktop {
                origin,
                window_label,
                window_binding,
            } => ScreenViewerBinding::verified_desktop(origin, window_label, window_binding),
        }
        .map_err(|_| ScreenSessionAdministrationError::InvalidInput { field: "binding" })?;
        // The original request's admission, borrowed (and so verified) right
        // before the ticket insert and held through it (5 s precedent). The
        // WebSocket send path holds its own.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let _admission = auth
            .request_binding()
            .ok_or(ScreenSessionAdministrationError::Unavailable)?
            .borrow_recovery_admission_before(auth, deadline)
            .await
            .map_err(|_| ScreenSessionAdministrationError::Unavailable)?;
        let issued = self
            .hub
            .issue_ticket_for_target(
                auth,
                &request.target.computer_id,
                request.target.computer_generation,
                &request.target.tab_id,
                binding,
                now,
            )
            .await
            .map_err(screen_session_error)?;
        let expires_at_ms = i64::try_from(issued.expires_at().unix_timestamp_nanos() / 1_000_000)
            .map_err(|_| ScreenSessionAdministrationError::Unavailable)?;
        Ok(ScreenSessionTicket::new(
            issued.base_protocol(),
            issued.ticket_protocol(),
            expires_at_ms,
        ))
    }
}

#[async_trait::async_trait]
impl ScreenSessionAdministration for ScreenSessionService {
    async fn issue(
        &self,
        auth: &AuthContext,
        request: ScreenSessionRequest,
    ) -> Result<ScreenSessionTicket, ScreenSessionAdministrationError> {
        self.issue_at(auth, request, OffsetDateTime::now_utc())
            .await
    }
}

impl ScreenHub {
    /// Construct with an explicit host-selected cap. Zero and values above 256 are rejected rather
    /// than silently becoming unlimited.
    pub fn new(max_viewers_per_stream: usize) -> Result<Self, ScreenHubError> {
        if max_viewers_per_stream == 0 || max_viewers_per_stream > MAX_VIEWERS_PER_STREAM {
            return Err(ScreenHubError::InvalidViewerLimit);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(HubState::default())),
            max_viewers_per_stream,
        })
    }

    /// Attach the sole source minted by one live EngineProcess session.
    pub async fn attach(
        &self,
        mut source: EngineScreenSource,
    ) -> Result<ScreenDemandObserver, ScreenHubError> {
        let key = source.key().clone();
        let audience = source.audience().clone();
        let first = ScreenViewerFrame::new(&key, source.latest().await.map_err(source_error)?)?;
        let (sender, _receiver) = watch::channel(Some(Arc::new(first)));
        let (viewers, demand) = watch::channel(ScreenDemand::default());
        {
            let mut state = self.state.lock().await;
            if state.streams.contains_key(&key) {
                return Err(ScreenHubError::DuplicateStream);
            }
            state.streams.insert(
                key.clone(),
                StreamEntry {
                    audience,
                    sender,
                    viewers: viewers.clone(),
                    task: None,
                },
            );
        }

        let weak = Arc::downgrade(&self.state);
        let task_key = key.clone();
        let task_viewers = viewers.clone();
        let task = tokio::spawn(async move {
            while let Ok(frame) = source.next().await {
                let Ok(frame) = ScreenViewerFrame::new(&task_key, frame) else {
                    break;
                };
                let Some(state) = weak.upgrade() else {
                    return;
                };
                let locked = state.lock().await;
                let Some(stream) = locked.streams.get(&task_key) else {
                    return;
                };
                if !stream.viewers.same_channel(&task_viewers) {
                    return;
                }
                stream.sender.send_replace(Some(Arc::new(frame)));
            }
            close_source(weak, task_key, task_viewers).await;
        });

        let mut state = self.state.lock().await;
        let Some(stream) = state.streams.get_mut(&key) else {
            task.abort();
            return Err(ScreenHubError::SourceClosed);
        };
        if !stream.viewers.same_channel(&viewers) {
            task.abort();
            return Err(ScreenHubError::SourceClosed);
        }
        stream.task = Some(task);
        Ok(ScreenDemandObserver { receiver: demand })
    }

    /// Issue a hash-only, 128-bit, 30-second ticket for one exact auth/binding/stream tuple.
    pub async fn issue_ticket(
        &self,
        auth: &AuthContext,
        key: &ScreenStreamKey,
        binding: ScreenViewerBinding,
        now: OffsetDateTime,
    ) -> Result<IssuedScreenTicket, ScreenHubError> {
        let mut state = self.state.lock().await;
        purge_expired(&mut state, now);
        let stream = state.streams.get(key).ok_or(ScreenHubError::NotVisible)?;
        ensure_audience(&stream.audience, auth)?;
        let pending = state
            .tickets
            .values()
            .filter(|ticket| ticket.key == *key)
            .count();
        let viewers = stream.viewers.borrow().viewers;
        if viewers
            .checked_add(pending)
            .is_none_or(|count| count >= self.max_viewers_per_stream)
        {
            return Err(ScreenHubError::ViewerLimit);
        }
        let expires_at = now
            .checked_add(SCREEN_TICKET_TTL)
            .ok_or(ScreenHubError::ClockOverflow)?;
        for _ in 0..4 {
            let mut token = vec![0_u8; 16];
            getrandom::fill(&mut token).map_err(|_| ScreenHubError::RandomFailed)?;
            let digest: [u8; 32] = Sha256::digest(&token).into();
            if state.tickets.contains_key(&digest) {
                continue;
            }
            state.tickets.insert(
                digest,
                PendingTicket {
                    key: key.clone(),
                    tenant: auth.tenant().clone(),
                    actor: auth.actor().clone(),
                    auth_generation: auth.auth_generation(),
                    binding,
                    expires_at,
                },
            );
            return Ok(IssuedScreenTicket {
                token: SecretBytes::new(token),
                expires_at,
            });
        }
        Err(ScreenHubError::RandomCollision)
    }

    /// Resolve one caller-visible stream without accepting its opaque scope digest from transport.
    pub async fn issue_ticket_for_target(
        &self,
        auth: &AuthContext,
        computer_id: &ComputerId,
        generation: ComputerGeneration,
        tab_id: &TabId,
        binding: ScreenViewerBinding,
        now: OffsetDateTime,
    ) -> Result<IssuedScreenTicket, ScreenHubError> {
        let key = {
            let state = self.state.lock().await;
            let mut visible = state.streams.iter().filter(|(key, stream)| {
                key.computer_id() == computer_id
                    && key.generation() == generation
                    && key.tab_id() == tab_id
                    && ensure_audience(&stream.audience, auth).is_ok()
            });
            let Some((key, _)) = visible.next() else {
                return Err(ScreenHubError::NotVisible);
            };
            if visible.next().is_some() {
                return Err(ScreenHubError::NotVisible);
            }
            key.clone()
        };
        self.issue_ticket(auth, &key, binding, now).await
    }

    /// Consume a ticket exactly once after the live connection repeats the same authority tuple.
    pub async fn consume_ticket(
        &self,
        auth: &AuthContext,
        binding: &ScreenViewerBinding,
        ticket_protocol: &str,
        now: OffsetDateTime,
    ) -> Result<ScreenViewer, ScreenHubError> {
        let digest = ticket_digest(ticket_protocol)?;
        let mut state = self.state.lock().await;
        let pending = state
            .tickets
            .get(&digest)
            .cloned()
            .ok_or(ScreenHubError::TicketInvalid)?;
        if pending.expires_at <= now {
            state.tickets.remove(&digest);
            return Err(ScreenHubError::TicketExpired);
        }
        if pending.tenant != *auth.tenant()
            || pending.actor != *auth.actor()
            || pending.auth_generation != auth.auth_generation()
            || pending.binding != *binding
        {
            return Err(ScreenHubError::NotVisible);
        }
        let stream = state
            .streams
            .get(&pending.key)
            .ok_or(ScreenHubError::SourceClosed)?;
        ensure_audience(&stream.audience, auth)?;
        if !stream.viewers.send_if_modified(|demand| {
            if demand.closed || demand.viewers >= self.max_viewers_per_stream {
                return false;
            }
            demand.viewers += 1;
            true
        }) {
            return Err(ScreenHubError::ViewerLimit);
        }
        let receiver = stream.sender.subscribe();
        let last_sequence = receiver.borrow().as_ref().map(|frame| frame.sequence());
        let viewers = stream.viewers.clone();
        let key = pending.key.clone();
        state.tickets.remove(&digest);
        Ok(ScreenViewer {
            key,
            receiver,
            viewers,
            last_sequence,
            skipped_frames: 0,
        })
    }

    /// Invalidate every stream/ticket for an actor when the current auth generation advances.
    pub async fn invalidate_actor(
        &self,
        tenant: &TenantId,
        actor: &ActorId,
        current_generation: AuthGeneration,
    ) -> usize {
        let mut state = self.state.lock().await;
        state.tickets.retain(|_, ticket| {
            ticket.tenant != *tenant
                || ticket.actor != *actor
                || ticket.auth_generation == current_generation
        });
        let keys = state
            .streams
            .iter()
            .filter(|(_, stream)| {
                stream.audience.tenant_id() == tenant
                    && stream.audience.actor_id() == actor
                    && stream.audience.auth_generation() != current_generation
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &keys {
            if let Some(mut stream) = state.streams.remove(key) {
                stream.viewers.send_modify(|demand| demand.closed = true);
                stream.sender.send_replace(None);
                if let Some(task) = stream.task.take() {
                    task.abort();
                }
            }
        }
        keys.len()
    }

    /// Detach one exact engine stream and close all viewers.
    pub async fn detach(&self, key: &ScreenStreamKey) -> bool {
        let mut state = self.state.lock().await;
        detach_stream(&mut state, key)
    }

    async fn detach_registered(
        &self,
        key: &ScreenStreamKey,
        registration: &ScreenDemandObserver,
    ) -> bool {
        let mut state = self.state.lock().await;
        if !state.streams.get(key).is_some_and(|stream| {
            stream
                .viewers
                .subscribe()
                .same_channel(&registration.receiver)
        }) {
            return false;
        }
        detach_stream(&mut state, key)
    }
}

fn detach_stream(state: &mut HubState, key: &ScreenStreamKey) -> bool {
    state.tickets.retain(|_, ticket| ticket.key != *key);
    let Some(mut stream) = state.streams.remove(key) else {
        return false;
    };
    stream.viewers.send_modify(|demand| demand.closed = true);
    stream.sender.send_replace(None);
    if let Some(task) = stream.task.take() {
        task.abort();
    }
    true
}

async fn close_source(
    state: Weak<Mutex<HubState>>,
    key: ScreenStreamKey,
    viewers: watch::Sender<ScreenDemand>,
) {
    let Some(state) = state.upgrade() else {
        return;
    };
    let mut state = state.lock().await;
    if !state
        .streams
        .get(&key)
        .is_some_and(|stream| stream.viewers.same_channel(&viewers))
    {
        return;
    }
    if let Some(mut stream) = state.streams.remove(&key) {
        stream.viewers.send_modify(|demand| demand.closed = true);
        stream.sender.send_replace(None);
        stream.task.take();
    }
    state.tickets.retain(|_, ticket| ticket.key != key);
}

/// Sanitized binary viewer frame shared by every authorized viewer.
pub struct ScreenViewerFrame {
    sequence: u64,
    captured_at_ms: i64,
    width: u32,
    height: u32,
    device_scale_factor: f32,
    page_scale_factor: f32,
    scroll_x: f32,
    scroll_y: f32,
    bytes: Arc<[u8]>,
}

impl ScreenViewerFrame {
    fn new(key: &ScreenStreamKey, frame: Arc<EngineFrame>) -> Result<Self, ScreenHubError> {
        let payload_len = u32::try_from(frame.bytes().len()).map_err(|_| ScreenHubError::Frame)?;
        let mut bytes = vec![0_u8; SCREEN_VIEWER_HEADER_BYTES];
        bytes[..8].copy_from_slice(VIEWER_FRAME_MAGIC);
        bytes[8..10].copy_from_slice(&VIEWER_FRAME_VERSION.to_le_bytes());
        bytes[10] = 1;
        bytes[12..16].copy_from_slice(
            &u32::try_from(SCREEN_VIEWER_HEADER_BYTES)
                .map_err(|_| ScreenHubError::Frame)?
                .to_le_bytes(),
        );
        bytes[16..20].copy_from_slice(&payload_len.to_le_bytes());
        bytes[20..28].copy_from_slice(&key.generation().get().to_le_bytes());
        bytes[28..36].copy_from_slice(&frame.sequence().to_le_bytes());
        bytes[36..44].copy_from_slice(&frame.captured_at_ms().to_le_bytes());
        bytes[44..48].copy_from_slice(&frame.width().to_le_bytes());
        bytes[48..52].copy_from_slice(&frame.height().to_le_bytes());
        bytes[52..56].copy_from_slice(&frame.device_scale_factor().to_le_bytes());
        bytes[56..60].copy_from_slice(&frame.page_scale_factor().to_le_bytes());
        bytes[60..64].copy_from_slice(&frame.scroll_x().to_le_bytes());
        bytes[64..68].copy_from_slice(&frame.scroll_y().to_le_bytes());
        bytes.extend_from_slice(frame.bytes());
        Ok(Self {
            sequence: frame.sequence(),
            captured_at_ms: frame.captured_at_ms(),
            width: frame.width(),
            height: frame.height(),
            device_scale_factor: frame.device_scale_factor(),
            page_scale_factor: frame.page_scale_factor(),
            scroll_x: frame.scroll_x(),
            scroll_y: frame.scroll_y(),
            bytes: bytes.into(),
        })
    }

    /// Source sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Source capture timestamp.
    #[must_use]
    pub const fn captured_at_ms(&self) -> i64 {
        self.captured_at_ms
    }

    /// Screencast device width in device-independent pixels (DIP).
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Screencast device height in device-independent pixels (DIP).
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Renderer device-pixel ratio sampled by the fixed engine probe.
    #[must_use]
    pub const fn device_scale_factor(&self) -> f32 {
        self.device_scale_factor
    }

    /// Page scale reported with the exact screencast frame.
    #[must_use]
    pub const fn page_scale_factor(&self) -> f32 {
        self.page_scale_factor
    }

    /// Horizontal document scroll in CSS pixels for the exact frame.
    #[must_use]
    pub const fn scroll_x(&self) -> f32 {
        self.scroll_x
    }

    /// Vertical document scroll in CSS pixels for the exact frame.
    #[must_use]
    pub const fn scroll_y(&self) -> f32 {
        self.scroll_y
    }

    /// Sanitized binary wire without scope IDs, ticket, or internal CDP session ID.
    #[must_use]
    pub fn binary(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ScreenViewerFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScreenViewerFrame")
            .field("sequence", &self.sequence)
            .field("captured_at_ms", &self.captured_at_ms)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// One authorized viewer. Clone is intentionally absent; every connection consumes one ticket.
pub struct ScreenViewer {
    key: ScreenStreamKey,
    receiver: watch::Receiver<Option<Arc<ScreenViewerFrame>>>,
    viewers: watch::Sender<ScreenDemand>,
    last_sequence: Option<u64>,
    skipped_frames: u64,
}

impl ScreenViewer {
    /// Bound stream identity retained only in Rust.
    #[must_use]
    pub fn key(&self) -> &ScreenStreamKey {
        &self.key
    }

    /// Current latest frame, marking skipped older values consumed.
    pub fn current(&mut self) -> Result<Arc<ScreenViewerFrame>, ScreenHubError> {
        let frame = self
            .receiver
            .borrow_and_update()
            .as_ref()
            .cloned()
            .ok_or(ScreenHubError::ViewerRevoked)?;
        if let Some(previous) = self.last_sequence {
            self.skipped_frames = self
                .skipped_frames
                .saturating_add(frame.sequence().saturating_sub(previous).saturating_sub(1));
        }
        self.last_sequence = Some(frame.sequence());
        Ok(frame)
    }

    /// Wait for the next latest frame. Revocation/source close is explicit.
    pub async fn next(&mut self) -> Result<Arc<ScreenViewerFrame>, ScreenHubError> {
        self.receiver
            .changed()
            .await
            .map_err(|_| ScreenHubError::ViewerRevoked)?;
        self.current()
    }

    /// Count of older sequence values coalesced before this viewer observed the latest frame.
    #[must_use]
    pub const fn skipped_frames(&self) -> u64 {
        self.skipped_frames
    }
}

impl Drop for ScreenViewer {
    fn drop(&mut self) {
        self.viewers.send_modify(|demand| {
            if let Some(remaining) = demand.viewers.checked_sub(1) {
                demand.viewers = remaining;
            } else {
                demand.closed = true;
            }
        });
    }
}

/// Stable ScreenHub failures; no token, origin, actor, or stream discriminator is included.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScreenHubError {
    /// Viewer cap was zero or above the closed ceiling.
    #[error("screen_viewer_limit_invalid")]
    InvalidViewerLimit,
    /// Origin/window binding was empty, malformed, or unbounded.
    #[error("screen_viewer_binding_invalid")]
    InvalidBinding,
    /// Stream is not visible under the supplied authority.
    #[error("screen_not_visible")]
    NotVisible,
    /// One Engine source may attach only once.
    #[error("screen_stream_duplicate")]
    DuplicateStream,
    /// Engine source ended or was invalidated.
    #[error("screen_source_closed")]
    SourceClosed,
    /// Viewer capacity, including pending tickets, was exhausted.
    #[error("screen_viewer_limit")]
    ViewerLimit,
    /// Ticket protocol shape/hash was invalid or already consumed.
    #[error("screen_ticket_invalid")]
    TicketInvalid,
    /// Ticket expired before the handshake.
    #[error("screen_ticket_expired")]
    TicketExpired,
    /// OS CSPRNG failed.
    #[error("screen_ticket_random_failed")]
    RandomFailed,
    /// Four consecutive CSPRNG collisions indicate an invariant failure.
    #[error("screen_ticket_random_collision")]
    RandomCollision,
    /// Clock arithmetic overflowed.
    #[error("screen_ticket_clock_overflow")]
    ClockOverflow,
    /// Viewer binary frame could not be represented in the closed format.
    #[error("screen_frame_invalid")]
    Frame,
    /// Active viewer was revoked or its source ended.
    #[error("screen_viewer_revoked")]
    ViewerRevoked,
}

fn ensure_audience(audience: &ScreenAudience, auth: &AuthContext) -> Result<(), ScreenHubError> {
    if audience.tenant_id() != auth.tenant()
        || audience.actor_id() != auth.actor()
        || audience.auth_generation() != auth.auth_generation()
    {
        Err(ScreenHubError::NotVisible)
    } else {
        Ok(())
    }
}

fn purge_expired(state: &mut HubState, now: OffsetDateTime) {
    state.tickets.retain(|_, ticket| ticket.expires_at > now);
}

fn ticket_digest(protocol: &str) -> Result<[u8; 32], ScreenHubError> {
    let value = protocol
        .strip_prefix(TICKET_PREFIX)
        .ok_or(ScreenHubError::TicketInvalid)?;
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ScreenHubError::TicketInvalid);
    }
    let mut token = [0_u8; 16];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ScreenHubError::TicketInvalid);
    }
    for (index, pair) in pairs.iter().enumerate() {
        token[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(Sha256::digest(token).into())
}

fn nibble(value: u8) -> Result<u8, ScreenHubError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ScreenHubError::TicketInvalid),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.contains('\0')
}

fn source_error(_error: crate::engine::EngineProcessError) -> ScreenHubError {
    ScreenHubError::SourceClosed
}

fn screen_session_error(error: ScreenHubError) -> ScreenSessionAdministrationError {
    match error {
        ScreenHubError::InvalidBinding | ScreenHubError::InvalidViewerLimit => {
            ScreenSessionAdministrationError::InvalidInput { field: "binding" }
        }
        ScreenHubError::NotVisible
        | ScreenHubError::SourceClosed
        | ScreenHubError::TicketInvalid
        | ScreenHubError::TicketExpired
        | ScreenHubError::ViewerRevoked => ScreenSessionAdministrationError::NotVisible,
        ScreenHubError::ViewerLimit => ScreenSessionAdministrationError::ViewerLimit,
        ScreenHubError::DuplicateStream
        | ScreenHubError::RandomFailed
        | ScreenHubError::RandomCollision
        | ScreenHubError::ClockOverflow
        | ScreenHubError::Frame => ScreenSessionAdministrationError::Unavailable,
    }
}

/// Cross-crate source fixture, absent from default/product feature graphs.
#[cfg(any(test, feature = "testkit"))]
pub mod testing {
    use std::sync::Arc;

    use openbot_contracts::auth::AuthContext;
    use openbot_contracts::ids::{ComputerGeneration, ComputerId, TabId};
    use tokio::sync::watch;

    use super::{ScreenHub, ScreenHubError};
    use crate::engine::{EngineFrame, EngineScreenSource, ScreenAudience, ScreenStreamKey};

    /// Sender half retained by a transport test to advance the exact shared latest frame.
    pub struct TestScreenFeed {
        sender: watch::Sender<Option<Arc<EngineFrame>>>,
    }

    impl TestScreenFeed {
        /// Publish one deterministic JPEG-shaped frame with a monotonic sequence.
        pub fn publish(&self, sequence: u64, scroll_y: f32) {
            self.sender
                .send_replace(Some(Arc::new(EngineFrame::for_test(
                    sequence,
                    1_788_499_200_000_i64
                        .saturating_add(i64::try_from(sequence).unwrap_or(i64::MAX)),
                    scroll_y,
                ))));
        }
    }

    /// Attach a deterministic Engine-shaped source to the real ScreenHub implementation.
    pub async fn attach_test_stream(
        hub: &ScreenHub,
        auth: &AuthContext,
        computer_id: ComputerId,
        generation: ComputerGeneration,
        tab_id: TabId,
    ) -> Result<TestScreenFeed, ScreenHubError> {
        let key = ScreenStreamKey::for_test([7; 32], computer_id, generation, tab_id);
        let (sender, receiver) = watch::channel(Some(Arc::new(EngineFrame::for_test(
            1,
            1_788_499_200_000,
            0.0,
        ))));
        hub.attach(EngineScreenSource::for_test(
            key,
            ScreenAudience::from_auth(auth),
            receiver,
        ))
        .await?;
        Ok(TestScreenFeed { sender })
    }
}

#[cfg(test)]
mod tests {
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::ids::{
        ActorId, ComputerGeneration, ComputerId, DeploymentId, TabId, TenantId,
    };
    use time::macros::datetime;

    use super::*;

    const NOW: OffsetDateTime = datetime!(2026-09-04 12:00 UTC);

    fn auth(actor: &str, generation: u64) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("deployment"),
            TenantId::new("tenant"),
            ActorId::new(actor),
            [Role::User],
            AuthGeneration::new(generation),
            false,
        )
    }

    fn source(
        actor: &str,
        generation: u64,
    ) -> (
        EngineScreenSource,
        watch::Sender<Option<Arc<EngineFrame>>>,
        ScreenStreamKey,
    ) {
        let key = ScreenStreamKey::for_test(
            [7; 32],
            ComputerId::new("computer"),
            ComputerGeneration::new(3),
            TabId::new("tab"),
        );
        let audience = ScreenAudience::from_auth(&auth(actor, generation));
        let (sender, receiver) = watch::channel(Some(Arc::new(EngineFrame::for_test(
            1,
            1_788_499_200_000,
            0.0,
        ))));
        (
            EngineScreenSource::for_test(key.clone(), audience, receiver),
            sender,
            key,
        )
    }

    #[tokio::test]
    async fn demand_counts_only_consumed_tickets_and_closes_with_live_handles() {
        let hub = ScreenHub::new(2).expect("hub");
        let (source, _sender, key) = source("actor", 4);
        let mut demand = hub.attach(source).await.expect("attach");
        assert!(!demand.current().has_viewers());
        let actor = auth("actor", 4);
        let binding =
            ScreenViewerBinding::verified_server("https://app.example.test").expect("binding");
        let first = hub
            .issue_ticket(&actor, &key, binding.clone(), NOW)
            .await
            .expect("ticket");
        assert!(
            !demand.current().has_viewers(),
            "pending ticket is not viewer demand"
        );
        let viewer = hub
            .consume_ticket(&actor, &binding, &first.ticket_protocol(), NOW)
            .await
            .expect("viewer");
        assert!(demand.changed().await.has_viewers());
        drop(viewer);
        assert!(!demand.changed().await.has_viewers());
        let next = hub
            .issue_ticket(&actor, &key, binding.clone(), NOW)
            .await
            .expect("ticket");
        let viewer = hub
            .consume_ticket(&actor, &binding, &next.ticket_protocol(), NOW)
            .await
            .expect("viewer");
        assert!(demand.changed().await.has_viewers());
        hub.detach(&key).await;
        assert!(
            demand.changed().await.is_closed(),
            "detach does not wait for the old viewer to drop"
        );
        drop(viewer);
        assert!(
            demand.changed().await.is_closed(),
            "last drop cannot reopen a terminal demand"
        );
    }

    #[tokio::test]
    async fn old_source_completion_cannot_close_or_publish_into_a_replacement() {
        let hub = ScreenHub::new(2).expect("hub");
        let (old, old_feed, key) = source("actor", 4);
        let mut old_demand = hub.attach(old).await.expect("old");
        let old_sender = hub.state.lock().await.streams[&key].viewers.clone();
        hub.detach(&key).await;
        assert!(old_demand.changed().await.is_closed());
        let (new, _new_feed, _) = source("actor", 5);
        let mut new_demand = hub.attach(new).await.expect("new");
        let actor = auth("actor", 5);
        let binding =
            ScreenViewerBinding::verified_server("https://app.example.test").expect("binding");
        let ticket = hub
            .issue_ticket(&actor, &key, binding.clone(), NOW)
            .await
            .expect("new ticket");
        assert!(
            !hub.detach_registered(&key, &old_demand).await,
            "old engine owner cannot detach replacement"
        );
        close_source(Arc::downgrade(&hub.state), key, old_sender).await;
        old_feed.send_replace(Some(Arc::new(EngineFrame::for_test(
            99,
            1_788_499_200_100,
            99.0,
        ))));
        let mut viewer = hub
            .consume_ticket(&actor, &binding, &ticket.ticket_protocol(), NOW)
            .await
            .expect("new ticket survives old close");
        assert!(new_demand.changed().await.has_viewers());
        assert_eq!(viewer.current().expect("new frame").sequence(), 1);
        drop(hub);
        assert!(
            new_demand.changed().await.is_closed(),
            "last Hub owner closes its streams"
        );
    }

    #[tokio::test]
    async fn ticket_is_hash_only_exactly_bound_expiring_and_single_use() {
        let hub = ScreenHub::new(2).expect("hub");
        let (source, _sender, key) = source("actor", 4);
        hub.attach(source).await.expect("attach");
        let actor = auth("actor", 4);
        let binding = ScreenViewerBinding::verified_server("https://app.example.test")
            .expect("server binding");
        let ticket = hub
            .issue_ticket(&actor, &key, binding.clone(), NOW)
            .await
            .expect("ticket");
        let protocol = ticket.ticket_protocol();
        assert_eq!(ticket.base_protocol(), SCREEN_VIEWER_PROTOCOL);
        assert_eq!(ticket.expires_at(), NOW + SCREEN_TICKET_TTL);
        assert!(!format!("{ticket:?}").contains(&protocol));
        assert!(matches!(
            hub.consume_ticket(
                &actor,
                &ScreenViewerBinding::verified_server("https://other.example.test")
                    .expect("other binding"),
                &protocol,
                NOW,
            )
            .await,
            Err(ScreenHubError::NotVisible)
        ));
        let mut viewer = hub
            .consume_ticket(&actor, &binding, &protocol, NOW)
            .await
            .expect("consume after wrong binding did not burn ticket");
        assert!(matches!(
            hub.consume_ticket(&actor, &binding, &protocol, NOW).await,
            Err(ScreenHubError::TicketInvalid)
        ));
        let frame = viewer.current().expect("initial latest frame");
        assert_eq!(&frame.binary()[..8], VIEWER_FRAME_MAGIC);
        assert_eq!(frame.sequence(), 1);
        assert_eq!(frame.captured_at_ms(), 1_788_499_200_000);
        assert!(!frame.binary().windows(8).any(|bytes| bytes == b"computer"));

        let expiring = hub
            .issue_ticket(&actor, &key, binding.clone(), NOW)
            .await
            .expect("expiring ticket");
        assert!(matches!(
            hub.consume_ticket(
                &actor,
                &binding,
                &expiring.ticket_protocol(),
                NOW + SCREEN_TICKET_TTL,
            )
            .await,
            Err(ScreenHubError::TicketExpired)
        ));
    }

    #[tokio::test]
    async fn two_viewers_share_latest_frames_and_generation_invalidation_closes_both() {
        let hub = ScreenHub::new(2).expect("hub");
        let (source, sender, key) = source("actor", 4);
        hub.attach(source).await.expect("attach");
        let actor = auth("actor", 4);
        let binding_a = ScreenViewerBinding::verified_desktop("openbot://localhost", "a", 1)
            .expect("binding a");
        let binding_b = ScreenViewerBinding::verified_desktop("openbot://localhost", "b", 2)
            .expect("binding b");
        let ticket_a = hub
            .issue_ticket(&actor, &key, binding_a.clone(), NOW)
            .await
            .expect("ticket a");
        let ticket_b = hub
            .issue_ticket(&actor, &key, binding_b.clone(), NOW)
            .await
            .expect("ticket b");
        let mut viewer_a = hub
            .consume_ticket(&actor, &binding_a, &ticket_a.ticket_protocol(), NOW)
            .await
            .expect("viewer a");
        let mut viewer_b = hub
            .consume_ticket(&actor, &binding_b, &ticket_b.ticket_protocol(), NOW)
            .await
            .expect("viewer b");
        assert!(matches!(
            hub.issue_ticket(&actor, &key, binding_a.clone(), NOW).await,
            Err(ScreenHubError::ViewerLimit)
        ));

        sender.send_replace(Some(Arc::new(EngineFrame::for_test(
            2,
            1_788_499_200_010,
            10.0,
        ))));
        assert_eq!(
            viewer_b.next().await.expect("viewer b frame2").sequence(),
            2
        );
        sender.send_replace(Some(Arc::new(EngineFrame::for_test(
            3,
            1_788_499_200_020,
            20.0,
        ))));
        assert_eq!(
            viewer_b.next().await.expect("viewer b frame3").sequence(),
            3
        );
        assert_eq!(
            viewer_a.next().await.expect("viewer a latest").sequence(),
            3
        );
        assert_eq!(viewer_a.skipped_frames(), 1);
        assert_eq!(viewer_b.skipped_frames(), 0);

        assert_eq!(
            hub.invalidate_actor(actor.tenant(), actor.actor(), actor.auth_generation())
                .await,
            0
        );
        assert_eq!(
            hub.invalidate_actor(actor.tenant(), actor.actor(), AuthGeneration::new(5))
                .await,
            1
        );
        assert!(matches!(
            viewer_a.next().await,
            Err(ScreenHubError::ViewerRevoked)
        ));
        assert!(matches!(
            viewer_b.next().await,
            Err(ScreenHubError::ViewerRevoked)
        ));
        assert!(matches!(
            hub.issue_ticket(&auth("other", 4), &key, binding_a, NOW)
                .await,
            Err(ScreenHubError::NotVisible)
        ));
    }

    struct AdmittingGuard;
    struct AdmittedLease;
    impl openbot_contracts::recovery::RecoveryAdmissionWitness for AdmittedLease {
        fn purpose(&self) -> openbot_contracts::recovery::RecoveryAdmissionPurpose {
            openbot_contracts::recovery::RecoveryAdmissionPurpose::Normal
        }
        fn verify_current_before(
            &self,
            _: &openbot_contracts::request_binding::VerifiedHostRequestBinding,
            _: &AuthContext,
            _: std::time::Instant,
        ) -> Result<(), openbot_contracts::request_binding::HostRequestBindingError> {
            Ok(())
        }
        fn restore_cohort(&self) -> Option<openbot_contracts::recovery::RestoreCohortRef> {
            None
        }
    }
    impl openbot_contracts::request_binding::HostRequestBindingGuard for AdmittingGuard {
        fn verify_current<'a>(
            &'a self,
            _: &'a AuthContext,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            (),
                            openbot_contracts::request_binding::HostRequestBindingError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(()) })
        }
        fn borrow_recovery_admission_before<'a>(
            &'a self,
            _: &'a openbot_contracts::request_binding::VerifiedHostRequestBinding,
            _: &'a AuthContext,
            _: std::time::Instant,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            openbot_contracts::recovery::RecoveryAdmissionLease<'a>,
                            openbot_contracts::request_binding::HostRequestBindingError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(Box::new(AdmittedLease) as _) })
        }
    }

    // Implements only the required check: admission keeps the closed default.
    struct DefaultGuard;
    impl openbot_contracts::request_binding::HostRequestBindingGuard for DefaultGuard {
        fn verify_current<'a>(
            &'a self,
            _: &'a AuthContext,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            (),
                            openbot_contracts::request_binding::HostRequestBindingError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn application_port_resolves_target_and_never_logs_issued_protocol() {
        let hub = ScreenHub::new(3).expect("hub");
        let (source, _sender, key) = source("actor", 4);
        hub.attach(source).await.expect("attach");
        let service = ScreenSessionService::new(hub);
        let unbound = auth("actor", 4);
        let (_owner, issuer) =
            openbot_contracts::request_binding::RequestBindingOwnerLease::for_trusted_host(
                openbot_contracts::request_binding::HostRequestBindingKind::DesktopWindow,
            );
        let binding = issuer
            .bind_desktop_window(&unbound, "main".into(), 1, Arc::new(AdmittingGuard))
            .expect("binding");
        let actor = unbound
            .clone()
            .with_verified_request_binding(binding)
            .expect("bound");
        let request = ScreenSessionRequest {
            target: openbot_contracts::screen::ScreenSessionTarget {
                computer_id: key.computer_id().clone(),
                computer_generation: key.generation(),
                tab_id: key.tab_id().clone(),
            },
            binding: ScreenViewerBindingRequest::Server {
                origin: "https://app.example.test".to_owned(),
            },
        };
        let ticket = service
            .issue_at(&actor, request.clone(), NOW)
            .await
            .expect("application ticket");
        assert_eq!(ticket.base_protocol(), SCREEN_VIEWER_PROTOCOL);
        assert_eq!(
            ticket.expires_at_ms(),
            (NOW + SCREEN_TICKET_TTL).unix_timestamp() * 1000
        );
        assert!(!format!("{ticket:?}").contains(ticket.ticket_protocol()));
        assert_eq!(
            service.issue_at(&unbound, request.clone(), NOW).await,
            Err(ScreenSessionAdministrationError::Unavailable)
        );
        let closed = issuer
            .bind_desktop_window(&unbound, "closed".into(), 2, Arc::new(DefaultGuard))
            .expect("closed binding");
        let closed = unbound
            .clone()
            .with_verified_request_binding(closed)
            .expect("bound");
        assert_eq!(
            service.issue_at(&closed, request.clone(), NOW).await,
            Err(ScreenSessionAdministrationError::Unavailable)
        );

        let mut stale = request.clone();
        stale.target.computer_generation = ComputerGeneration::new(4);
        assert_eq!(
            service.issue_at(&actor, stale, NOW).await,
            Err(ScreenSessionAdministrationError::NotVisible)
        );
        let mut invalid = request;
        invalid.binding = ScreenViewerBindingRequest::Server {
            origin: String::new(),
        };
        assert_eq!(
            service.issue_at(&actor, invalid, NOW).await,
            Err(ScreenSessionAdministrationError::InvalidInput { field: "binding" })
        );
    }
}
