//! typed in-process transport —— v3 §13.2「Tauri `setup` 创建一个
//! `Arc<dyn ApplicationService>`。普通 request 直接 typed 调用，server request/stream
//! 使用有界 channel」。
//!
//! # 它做的四件事，以及它**不**做的那一件
//!
//! §5.2 给 transport 的活恰好四样：认证、framing、输入大小限制、错误映射。本类型逐条对应：
//!
//! | transport 职责 | 在这里的形态 |
//! | --- | --- |
//! | 认证 | 不在 G1（见 crate 文档）。身份以 `AuthContext` 的形式**传入**，本 crate 不铸造 |
//! | framing | [`crate::event::AppEventRef`]：序号、gap 说明、终止帧 |
//! | 输入大小限制 | 有界队列（每窗口 256）与 command 并发预算（256） |
//! | 错误映射 | in-process 的映射是**恒等**：`AppError` 原样穿过（理由见 [`InProcessTransport::execute`]） |
//!
//! **不做的那一件是业务判定**（§5.2 逐字禁止）。可判定形式：本模块里没有一处 `match` 是
//! 在看 [`AppCommand`] 的变体，也没有一处在看 [`AppReply`] 的内容 —— 命令原样递给
//! [`ApplicationService::execute`]，应答原样返回。`in_process_execute_equals_a_direct_service_call`
//! 把这条钉成"经 transport 与直连 service 的结果逐字段相等"。
//!
//! # 「不复制 JSON-RPC」是构造性的
//!
//! §13.2 的标题就是「typed in-process，不复制 JSON-RPC」。[`InProcessTransport`] 本身不
//! 引用任何 codec，命令逐类型直接进入 service。G6 的 opt-in `tauri-host` custom protocol
//! 必须为 WebView HTTP framing 使用 serde_json，但它在本模块之外且依赖全为 optional；由
//! `the_in_process_lane_has_no_json_codec` 同时扫源码与 feature 边界。

use std::sync::{Arc, Mutex};
use std::time::Instant;

use core::time::Duration;

use openbot_application::{AppEventStream, ApplicationService, CurrentArtifactReadChunk};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppEvent, AppReply, SubscriptionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::telemetry::Transport;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
use openbot_domain::backup::{WholePgCarrierBounds, WholePgCarrierFault};

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
use crate::tauri_background::capture::{
    CaptureResourceTotals, remaining_capture_resources, reserve_capture_resources,
};

use crate::broker::{DeliveryOutcome, EventBroker, WindowAlreadyOpen};
use crate::budget::{COMMAND_QUEUE_CAPACITY, EventQueueBudget};
use crate::cancel::{CancellationToken, SHUTDOWN_DEADLINE};
use crate::event::BrokerEvent;
use crate::session::DesktopSession;
use crate::window::{EventScope, ThreadSubscriptions, WindowIdentity, WindowLabel};

/// 打开一条窗口会话失败。
#[derive(Debug, thiserror::Error)]
pub enum OpenSessionError {
    /// application 拒绝了这次订阅（未登录 / 不可见 / 依赖不可用……）。
    ///
    /// **原样上抛**：transport 不改写业务判定的结果，也不替它决定该给用户看什么
    /// （文案由 GUI 按 code 本地化，§15.3）。
    #[error(transparent)]
    Application(#[from] AppError),

    /// 该窗口标签在本 broker 内已存在（见 [`WindowAlreadyOpen`]）。
    #[error(transparent)]
    WindowAlreadyOpen(#[from] WindowAlreadyOpen),

    /// transport 正在关停。
    #[error("shutting_down")]
    ShuttingDown,
}

/// 一次关停的结果（§13.2「shutdown deadline 5 秒」）。
///
/// 它是**报告**不是日志：`within_deadline` 为假意味着有事件泵没能在 5 秒内停下、
/// 被强制 abort —— 那是一条需要有人去看的事实，不该只留在一行 warn 里。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownReport {
    /// 被关掉的窗口数。
    pub windows_closed: usize,
    /// 关停时在跑的事件泵总数。
    pub pumps_total: usize,
    /// 在 deadline 内自行停下的事件泵数。
    pub pumps_joined: usize,
    /// 超过 deadline 被 abort 的事件泵数。
    pub pumps_aborted: usize,
    /// 实际耗时。
    pub elapsed: Duration,
    /// 是否在 [`SHUTDOWN_DEADLINE`] 内干净停住（没有任何 abort）。
    pub within_deadline: bool,
}

/// 把一个 [`ApplicationService`] 包成 Desktop 的 in-process 通道。
///
/// 一个进程一个实例（Tauri 的 `setup` 里建，放进 managed state），服务全部窗口。
pub struct InProcessTransport {
    service: Arc<dyn ApplicationService>,
    broker: Arc<EventBroker>,
    commands: Semaphore,
    pumps: Mutex<PumpRegistry>,
}

#[derive(Default)]
struct PumpRegistry {
    legacy: Vec<PumpHandle>,
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    capture_requested: bool,
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    legacy_history: bool,
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    capture: Option<CapturePumpRegistry>,
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    capture_resources: Option<Arc<Mutex<CaptureResourceTotals>>>,
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    capture_fixed_metadata: u64,
}

struct PumpHandle {
    label: WindowLabel,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureTransportFault {
    Poisoned,
    Cancelled,
    Panicked,
}

// Each slot retains the actual result, including the original JoinError/panic payload.
#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
enum CapturePumpOutcome {
    Joined(Result<(), tokio::task::JoinError>),
    PollPanicked { _payload: Box<dyn std::any::Any + Send + 'static> },
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
struct CapturePumpSlot {
    original: PumpHandle,
    actual: Option<CapturePumpOutcome>,
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
struct CapturePumpRegistry {
    originals: Vec<CapturePumpSlot>,
    slot_limit: usize,
    label_limit: usize,
    metadata_limit: u64,
    // Includes fixed requested layouts, all actual admission fees and each complete replacement
    // backing. Old backing is never refunded, covering old+new during a reallocation.
    metadata_reserved: u64,
    // Cumulative reservations are never refunded, including cancelled subscribe callers.
    admissions: usize,
    pending: usize,
    closed: bool,
    taken: bool,
    fault: Option<CaptureTransportFault>,
}

/// Resident ownership of the original pumps, their actual results and the join cursor.
/// The original caller stores this owner before awaiting; it is not a closure grant.
#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
pub(crate) struct RetainedTransportClosing {
    originals: Vec<CapturePumpSlot>,
    cursor: usize,
    fault: Option<CaptureTransportFault>,
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
struct CapturePumpAdmission<'a> {
    transport: &'a InProcessTransport,
    active: bool,
    // Retained handle label, pump label and the original pump's EventScope label.
    labels: Option<(WindowLabel, WindowLabel, WindowLabel)>,
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
fn fail_capture(registry: &mut PumpRegistry, fault: CaptureTransportFault) {
    if let Some(capture) = registry.capture.as_mut() {
        capture.closed = true;
        capture.fault.get_or_insert(fault);
    }
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
fn finish_capture_admission(registry: &mut PumpRegistry) {
    if let Some(capture) = registry.capture.as_mut() {
        if let Some(remaining) = capture.pending.checked_sub(1) {
            capture.pending = remaining;
        } else {
            capture.closed = true;
            capture.fault.get_or_insert(CaptureTransportFault::Poisoned);
        }
    }
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
impl Drop for CapturePumpAdmission<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut registry = match self.transport.pumps.lock() {
            Ok(registry) => registry,
            Err(poisoned) => {
                let mut registry = poisoned.into_inner();
                fail_capture(&mut registry, CaptureTransportFault::Poisoned);
                registry
            }
        };
        // Release only the pending-call count, never the cumulative original slot budget.
        finish_capture_admission(&mut registry);
    }
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
fn capture_label(label: &WindowLabel, limit: usize) -> Result<WindowLabel, OpenSessionError> {
    if label.as_str().len() > limit {
        return Err(OpenSessionError::ShuttingDown);
    }
    let mut value = String::new();
    value.try_reserve_exact(label.as_str().len())
        .map_err(|_| OpenSessionError::ShuttingDown)?;
    if value.capacity() != label.as_str().len() {
        return Err(OpenSessionError::ShuttingDown);
    }
    value.push_str(label.as_str());
    Ok(WindowLabel::new(value))
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
impl InProcessTransport {
    /// Bind the original pre-t0 owner's numeric DATA once, before use or arming.
    /// The component gate always precedes the book gate; neither lock contains an await or I/O.
    pub(crate) fn bind_original_capture_resources(
        &self,
        resources: Arc<Mutex<CaptureResourceTotals>>,
    ) -> Result<(), WholePgCarrierFault> {
        let mut registry = match self.pumps.lock() {
            Ok(registry) => registry,
            Err(poisoned) => {
                poisoned.into_inner().capture_requested = true;
                return Err(WholePgCarrierFault::ClosingPending);
            }
        };
        if registry.capture_resources.is_some() || registry.capture_requested {
            return Err(WholePgCarrierFault::IntentMismatch);
        }
        if registry.legacy_history || !registry.legacy.is_empty()
            || self.shutdown_token().is_cancelled()
        {
            return Err(WholePgCarrierFault::ClosingPending);
        }
        let fixed = core::mem::size_of::<Mutex<PumpRegistry>>()
            .checked_add(core::mem::size_of::<RetainedTransportClosing>())
            .ok_or(WholePgCarrierFault::BoundsOverflow)?;
        let fixed = u64::try_from(fixed).map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
        // This is requested Rust backing only. Unproved allocator/runtime/subscribe internals
        // remain outside this component fact and cannot be treated as a whole-operation GO.
        reserve_capture_resources(&resources, 0, fixed)?;
        registry.capture_fixed_metadata = fixed;
        registry.capture_resources = Some(resources);
        Ok(())
    }

    /// Arm before the first subscription. The same book is retained; the profile is a ceiling,
    /// not a separately spendable allowance. No maximum-size slot Vec is allocated here.
    pub(crate) fn arm_capture_retention(
        &self,
        bounds: &WholePgCarrierBounds,
    ) -> Result<(), WholePgCarrierFault> {
        let mut registry = match self.pumps.lock() {
            Ok(registry) => registry,
            Err(poisoned) => {
                // Even a rejected arm must never fall back to consuming legacy shutdown.
                poisoned.into_inner().capture_requested = true;
                return Err(WholePgCarrierFault::ClosingPending);
            }
        };
        if registry.capture_requested {
            return Err(WholePgCarrierFault::IntentMismatch);
        }
        registry.capture_requested = true;
        if registry.legacy_history || !registry.legacy.is_empty()
            || self.shutdown_token().is_cancelled()
        {
            return Err(WholePgCarrierFault::ClosingPending);
        }
        let bounds = (*bounds).check()?;
        let resources = registry.capture_resources.as_ref().ok_or(WholePgCarrierFault::ProfileMissing)?;
        remaining_capture_resources(resources)?;
        let metadata_limit = bounds.max_metadata_bytes.min(bounds.max_total_allocation_bytes);
        let label_limit = usize::try_from(bounds.max_path_bytes)
            .map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
        let slot_limit = usize::try_from(bounds.max_open_files)
            .map_err(|_| WholePgCarrierFault::BoundsOverflow)?;
        let metadata_reserved = registry.capture_fixed_metadata;
        if metadata_reserved > metadata_limit || slot_limit == 0 {
            return Err(WholePgCarrierFault::CapacityExceeded);
        }
        registry.capture = Some(CapturePumpRegistry {
            originals: Vec::new(), slot_limit, label_limit, metadata_limit, metadata_reserved,
            admissions: 0, pending: 0, closed: false, taken: false, fault: None,
        });
        Ok(())
    }

    /// Cumulative known requested backing retained/reserved by this component; no new OS FD
    /// is opened by the transport itself. This is not an opaque-runtime or global peak claim.
    pub(crate) fn retained_resource_usage(&self) -> Result<(u64, u64), WholePgCarrierFault> {
        let registry = self.pumps.lock().map_err(|_| WholePgCarrierFault::ClosingPending)?;
        let capture = registry.capture.as_ref().ok_or(WholePgCarrierFault::ClosingPending)?;
        if registry.capture_resources.is_none() || capture.metadata_reserved > capture.metadata_limit {
            return Err(WholePgCarrierFault::IntentMismatch);
        }
        Ok((0, capture.metadata_reserved))
    }

    fn reserve_capture_session(
        &self,
        label: &WindowLabel,
    ) -> Result<Option<CapturePumpAdmission<'_>>, OpenSessionError> {
        let label_limit = {
            let mut registry = match self.pumps.lock() {
                Ok(registry) => registry,
                Err(poisoned) => {
                    let registry = poisoned.into_inner();
                    if registry.capture_requested {
                        return Err(OpenSessionError::ShuttingDown);
                    }
                    panic!("事件泵句柄锁不会中毒");
                }
            };
            if !registry.capture_requested {
                // Mark before subscribe awaits: even a later empty/reaped Vec is unknown history.
                registry.legacy_history = true;
                return Ok(None);
            }
            let PumpRegistry { capture_resources, capture, .. } = &mut *registry;
            let resources = capture_resources.as_ref().ok_or(OpenSessionError::ShuttingDown)?;
            let capture = capture.as_mut().ok_or(OpenSessionError::ShuttingDown)?;
            if capture.closed || capture.taken || capture.fault.is_some()
                || self.shutdown_token().is_cancelled()
                || capture.admissions >= capture.slot_limit
            {
                return Err(OpenSessionError::ShuttingDown);
            }
            let label_bytes = label.as_str().len();
            if label_bytes > capture.label_limit {
                return Err(OpenSessionError::ShuttingDown);
            }
            let admissions = capture.admissions.checked_add(1).ok_or(OpenSessionError::ShuttingDown)?;
            let pending = capture.pending.checked_add(1).ok_or(OpenSessionError::ShuttingDown)?;
            let old_capacity = capture.originals.capacity();
            let new_capacity = if admissions > old_capacity {
                old_capacity.checked_mul(2)
                    .map(|doubled| doubled.max(admissions).min(capture.slot_limit))
                    .ok_or(OpenSessionError::ShuttingDown)?
            } else {
                old_capacity
            };
            let backing = if new_capacity > old_capacity {
                new_capacity.checked_mul(core::mem::size_of::<CapturePumpSlot>())
                    .ok_or(OpenSessionError::ShuttingDown)?
            } else {
                0
            };
            let additional = new_capacity.checked_sub(capture.originals.len())
                .ok_or(OpenSessionError::ShuttingDown)?;
            let admission_bytes = core::mem::size_of::<CapturePumpAdmission<'_>>()
                .checked_add(label_bytes.checked_mul(3).ok_or(OpenSessionError::ShuttingDown)?)
                .ok_or(OpenSessionError::ShuttingDown)?;
            let delta = u64::try_from(backing.checked_add(admission_bytes)
                .ok_or(OpenSessionError::ShuttingDown)?)
                .map_err(|_| OpenSessionError::ShuttingDown)?;
            let metadata = capture.metadata_reserved.checked_add(delta)
                .ok_or(OpenSessionError::ShuttingDown)?;
            if metadata > capture.metadata_limit {
                return Err(OpenSessionError::ShuttingDown);
            }
            // Rust 1.98.0's pinned RawVec::grow_exact requests len+additional and records
            // exactly that logical capacity. Prepay the COMPLETE new backing: the old charge
            // is retained so old+new reallocation coexistence cannot spend unreserved bytes.
            // This still does not prove opaque allocator or Tokio/subscribe internal peaks.
            reserve_capture_resources(resources, 0, delta)
                .map_err(|_| OpenSessionError::ShuttingDown)?;
            capture.metadata_reserved = metadata;
            capture.admissions = admissions;
            if new_capacity > old_capacity {
                if capture.originals.try_reserve_exact(additional).is_err()
                    || capture.originals.capacity() != new_capacity
                {
                    // try_reserve_exact leaves existing elements unchanged on allocation Err.
                    // Refuse without refund/reconstruction, and retain every original handle.
                    capture.closed = true;
                    capture.fault.get_or_insert(CaptureTransportFault::Cancelled);
                    return Err(OpenSessionError::ShuttingDown);
                }
            }
            capture.pending = pending;
            capture.label_limit
        };
        let mut admission = CapturePumpAdmission { transport: self, active: true, labels: None };
        // Fallible owned copies precede subscribe and are all bounded; RAII retains the reservation
        // and releases only pending if allocation fails or the subscribe future is dropped.
        admission.labels = Some((
            capture_label(label, label_limit)?,
            capture_label(label, label_limit)?,
            capture_label(label, label_limit)?,
        ));
        Ok(Some(admission))
    }

    fn publish_capture_session(
        &self,
        mut admission: CapturePumpAdmission<'_>,
        identity: WindowIdentity,
        subscribed: Result<AppEventStream, AppError>,
        subscriptions: ThreadSubscriptions,
        queue_budget: Option<Arc<EventQueueBudget>>,
    ) -> Result<DesktopSession, OpenSessionError> {
        let mut registry = match self.pumps.lock() {
            Ok(registry) => registry,
            Err(_) => return Err(OpenSessionError::ShuttingDown),
        };
        let capture = registry.capture.as_mut().ok_or(OpenSessionError::ShuttingDown)?;
        // This is the same mutex as begin_capture_closing, after the original subscribe await.
        if capture.closed || capture.taken || capture.fault.is_some()
            || self.shutdown_token().is_cancelled()
            || capture.originals.len() >= capture.slot_limit
            || capture.originals.len() >= capture.originals.capacity()
        {
            return Err(OpenSessionError::ShuttingDown);
        }
        let stream = subscribed?;
        let (retained_label, pump_label, scope_label) = admission.labels.take()
            .ok_or(OpenSessionError::ShuttingDown)?;
        let session = match queue_budget {
            Some(queue_budget) => self.broker.open_window_with_budget(
                identity.clone(), subscriptions, queue_budget,
            )?,
            None => self.broker.open_window(identity.clone(), subscriptions)?,
        };
        let session_cancellation = CancellationToken::new();
        let scope = EventScope::window(identity.tenant().clone(), scope_label);
        let task = tokio::spawn(pump(
            Arc::clone(&self.broker), self.shutdown_token().clone(), session_cancellation.clone(),
            pump_label, scope, identity.auth_generation(), stream,
        ));
        // Capacity and all owned label buffers already exist: no await/reallocation/finished reap
        // occurs between this exact original spawn and registration under the closing gate.
        capture.originals.push(CapturePumpSlot {
            original: PumpHandle { label: retained_label, cancellation: session_cancellation, task },
            actual: None,
        });
        finish_capture_admission(&mut registry);
        admission.active = false;
        Ok(session)
    }

    /// Called only at the original caller's same-clock first-stop. No wait or new timer here.
    pub(crate) fn begin_capture_closing(
        &self,
    ) -> Result<RetainedTransportClosing, CaptureTransportFault> {
        let mut registry = self.pumps.lock().map_err(|_| CaptureTransportFault::Poisoned)?;
        let capture = registry.capture.as_mut().ok_or(CaptureTransportFault::Cancelled)?;
        if capture.taken {
            return Err(CaptureTransportFault::Cancelled);
        }
        capture.closed = true;
        self.shutdown_token().cancel();
        // Keep the original Vec resident until the original cancel/route closure has returned.
        // A panic here poisons the gate while leaving all originals in the transport.
        self.broker.close_all();
        capture.taken = true;
        Ok(RetainedTransportClosing {
            originals: core::mem::take(&mut capture.originals), cursor: 0, fault: capture.fault,
        })
    }
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
impl RetainedTransportClosing {
    pub(crate) async fn join_originals(&mut self) -> Result<(), CaptureTransportFault> {
        while self.cursor < self.originals.len() {
            core::future::poll_fn(|cx| {
                let slot = &mut self.originals[self.cursor];
                if slot.actual.is_some() {
                    return core::task::Poll::Ready(());
                }
                let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    core::future::Future::poll(core::pin::Pin::new(&mut slot.original.task), cx)
                }));
                match polled {
                    Ok(core::task::Poll::Pending) => return core::task::Poll::Pending,
                    Ok(core::task::Poll::Ready(actual)) => {
                        slot.actual = Some(CapturePumpOutcome::Joined(actual));
                    }
                    Err(payload) => {
                        slot.actual = Some(CapturePumpOutcome::PollPanicked { _payload: payload });
                    }
                }
                // Cache the actual result in the resident slot before returning from this poll.
                core::task::Poll::Ready(())
            }).await;
            let fault = match self.originals[self.cursor].actual.as_ref() {
                Some(CapturePumpOutcome::Joined(Ok(()))) => None,
                Some(CapturePumpOutcome::Joined(Err(error))) if error.is_cancelled() => {
                    Some(CaptureTransportFault::Cancelled)
                }
                Some(CapturePumpOutcome::Joined(Err(error))) if error.is_panic() => {
                    Some(CaptureTransportFault::Panicked)
                }
                Some(CapturePumpOutcome::PollPanicked { .. }) => Some(CaptureTransportFault::Panicked),
                _ => Some(CaptureTransportFault::Poisoned),
            };
            if let Some(fault) = fault {
                self.fault.get_or_insert(fault);
            }
            // No await between cached result, permanent failure and cursor advancement. A dropped
            // waiter keeps the same original handle, and no consumed result is polled a second time.
            self.cursor += 1;
        }
        self.fault.map_or(Ok(()), Err)
    }
}

impl InProcessTransport {
    /// 用一个新的取消信号包起来。
    #[must_use]
    pub fn new(service: Arc<dyn ApplicationService>) -> Self {
        Self::with_shutdown(service, CancellationToken::new())
    }

    /// 用调用方给定的取消信号包起来（宿主已有一个全局关停信号时用这个）。
    #[must_use]
    pub fn with_shutdown(
        service: Arc<dyn ApplicationService>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            service,
            broker: Arc::new(EventBroker::new(shutdown)),
            commands: Semaphore::new(COMMAND_QUEUE_CAPACITY),
            pumps: Mutex::new(PumpRegistry::default()),
        }
    }

    /// 底下那个 service。
    ///
    /// 公开它是为了让「Axum 与 Tauri 穿的是**同一个** `ApplicationService`」可以被断言
    /// （`Arc::ptr_eq`），而不是只能被相信。§24 的 G1 判据「ApplicationService 经
    /// Axum/Tauri 结果一致」的前提正是这个"同一个"。
    #[must_use]
    pub fn service(&self) -> &Arc<dyn ApplicationService> {
        &self.service
    }

    /// Rust-only sealed first-chunk forwarding through the same application service.
    /// A transport without the actual producer keeps its default unavailable response.
    pub async fn read_current_artifact_chunk(
        &self,
        auth: AuthContext,
        artifact_id: String,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        if self.broker.shutdown_token().is_cancelled() {
            return Err(AppError::DependencyUnavailable {
                dependency: "desktop_transport",
            });
        }
        self.service
            .read_current_artifact_chunk(auth, artifact_id)
            .await
    }

    /// Forward an owned Rust read through this exact application service.
    pub async fn open_current_artifact_read(
        &self,
        auth: AuthContext,
        artifact_id: String,
    ) -> Result<openbot_application::CurrentArtifactReadOperation, AppError> {
        if self.broker.shutdown_token().is_cancelled() {
            return Err(AppError::DependencyUnavailable {
                dependency: "desktop_transport",
            });
        }
        self.service
            .open_current_artifact_read(auth, artifact_id)
            .await
    }

    /// 事件 broker（多窗口 ACL 与有界队列都在它那里）。
    #[must_use]
    pub fn broker(&self) -> &Arc<EventBroker> {
        &self.broker
    }

    /// 关停信号。
    #[must_use]
    pub fn shutdown_token(&self) -> &CancellationToken {
        self.broker.shutdown_token()
    }

    /// command 通道此刻还剩几个并发额度（§13.2「command 256」）。
    #[must_use]
    pub fn available_command_permits(&self) -> usize {
        self.commands.available_permits()
    }

    /// 执行一条命令 —— **直接 typed 调用，不经任何序列化**。
    ///
    /// # 背压而不是报错
    ///
    /// 在飞命令达到 [`COMMAND_QUEUE_CAPACITY`] 时，第 257 个调用**等待**而不是失败。
    /// 理由见该常量的文档：命令是用户动作，丢一次点击没有正确的用户可见语义；
    /// 事件流那边才是"满即显式断开"。
    ///
    /// # 错误映射为什么是恒等
    ///
    /// §5.2 把"错误映射"列为 transport 的活，但映射的**目标**由通道决定：Axum 要映射到
    /// HTTP 状态码，因为那头是 HTTP；in-process 这头是同一个进程里的 Rust GUI，它消费的
    /// 就是 [`AppError`] 的稳定 code。在这里插一层自定义错误类型只会多一份必须与
    /// `AppError` 同步的枚举，而每一次不同步都是一次静默的语义漂移。
    ///
    /// # Errors
    ///
    /// 原样返回 [`ApplicationService::execute`] 的 [`AppError`]。
    pub async fn execute(
        &self,
        auth: AuthContext,
        command: AppCommand,
    ) -> Result<AppReply, AppError> {
        let _permit = self
            .commands
            .acquire()
            .await
            .expect("command 信号量从不关闭");
        // 这一行是本模块的全部业务参与度：把参数原样递过去。
        self.service.execute(auth, command).await
    }

    /// 为一个窗口打开订阅，返回它的 [`DesktopSession`]。
    ///
    /// 流程：`subscribe` 拿到 [`AppEventStream`] → 在 broker 上开一条有界路由 → spawn 一个
    /// 事件泵把流抽进那条路由。泵的三个退出条件缺一不可：
    ///
    /// 1. 关停信号被取消；
    /// 2. 上游流结束；
    /// 3. 该窗口的路由没了（接收端被 drop、或被显式断开）。
    ///
    /// 第 3 条是「drop 接收端让生产侧停止」的落点。少了它，一个关掉的窗口会让上游流
    /// 继续跑到进程退出为止。
    ///
    /// # Errors
    ///
    /// 见 [`OpenSessionError`]。
    pub async fn open_session(
        &self,
        label: WindowLabel,
        auth: &AuthContext,
        request: SubscriptionRequest,
        subscriptions: ThreadSubscriptions,
    ) -> Result<DesktopSession, OpenSessionError> {
        self.open_session_inner(label, auth, request, subscriptions, None)
            .await
    }

    /// Open an internal route that shares the caller's aggregate event-ref budget.
    #[cfg(feature = "tauri-host")]
    pub(crate) async fn open_session_with_budget(
        &self,
        label: WindowLabel,
        auth: &AuthContext,
        request: SubscriptionRequest,
        subscriptions: ThreadSubscriptions,
        queue_budget: Arc<EventQueueBudget>,
    ) -> Result<DesktopSession, OpenSessionError> {
        self.open_session_inner(label, auth, request, subscriptions, Some(queue_budget))
            .await
    }

    async fn open_session_inner(
        &self,
        label: WindowLabel,
        auth: &AuthContext,
        request: SubscriptionRequest,
        subscriptions: ThreadSubscriptions,
        queue_budget: Option<Arc<EventQueueBudget>>,
    ) -> Result<DesktopSession, OpenSessionError> {
        if self.shutdown_token().is_cancelled() {
            return Err(OpenSessionError::ShuttingDown);
        }

        #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
        let admission = self.reserve_capture_session(&label)?;
        let identity = WindowIdentity::bind(label, auth);
        let subscribed = self.service.subscribe(auth.clone(), request).await;
        #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
        if let Some(admission) = admission {
            return self.publish_capture_session(admission, identity, subscribed, subscriptions, queue_budget);
        }
        let stream = subscribed?;
        let mut pumps = match self.pumps.lock() {
            Ok(pumps) => pumps,
            Err(poisoned) => {
                let _pumps = poisoned.into_inner();
                #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
                if _pumps.capture_requested {
                    return Err(OpenSessionError::ShuttingDown);
                }
                panic!("事件泵句柄锁不会中毒");
            }
        };
        #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
        if pumps.capture_requested {
            // An arm rejected for pre-existing legacy history also closes future admission.
            return Err(OpenSessionError::ShuttingDown);
        }
        let session = match queue_budget {
            Some(queue_budget) => self.broker.open_window_with_budget(
                identity.clone(),
                subscriptions,
                queue_budget,
            )?,
            None => self.broker.open_window(identity.clone(), subscriptions)?,
        };
        let session_cancellation = CancellationToken::new();

        // 订阅流是**这个窗口自己的**，所以 scope 就是这个窗口。换成 actor scope 会让同一
        // 个 actor 的第二个窗口收到第一个窗口的订阅帧 —— 两条独立订阅会互相灌帧。
        let scope = EventScope::window(identity.tenant().clone(), identity.label().clone());
        let handle = tokio::spawn(pump(
            Arc::clone(&self.broker),
            self.shutdown_token().clone(),
            session_cancellation.clone(),
            identity.label().clone(),
            scope,
            identity.auth_generation(),
            stream,
        ));
        pumps.legacy.retain(|pump| !pump.task.is_finished());
        pumps.legacy.push(PumpHandle {
            label: identity.label().clone(),
            cancellation: session_cancellation,
            task: handle,
        });

        Ok(session)
    }

    /// Close one host-owned subscription without shutting down the process.
    ///
    /// The exact broker route is synchronously removed after receiving one explicit terminal frame,
    /// then its upstream pump is cancelled. Returning `true` therefore proves that the route is no
    /// longer eligible for delivery; callers do not need to wait for another upstream event.
    pub fn close_session(&self, label: &WindowLabel) -> bool {
        let (mut pumps, poisoned) = match self.pumps.lock() {
            Ok(pumps) => (pumps, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
        if pumps.capture_requested {
            if poisoned {
                fail_capture(&mut pumps, CaptureTransportFault::Poisoned);
            }
            let closed = self.broker
                .close_window(label, crate::broker::DisconnectReason::SubscriptionClosed);
            if let Some(capture) = pumps.capture.as_ref() {
                for slot in &capture.originals {
                    if &slot.original.label == label {
                        slot.original.cancellation.cancel();
                    }
                }
            }
            // A rejected retrospective arm keeps any actual legacy originals too.
            for original in &pumps.legacy {
                if &original.label == label {
                    original.cancellation.cancel();
                }
            }
            return closed;
        }
        assert!(!poisoned, "事件泵句柄锁不会中毒");
        let cancellations = pumps.legacy.iter()
            .filter(|pump| &pump.label == label)
            .map(|pump| pump.cancellation.clone()).collect::<Vec<_>>();
        drop(pumps);
        let closed = self.broker
            .close_window(label, crate::broker::DisconnectReason::SubscriptionClosed);
        for cancellation in cancellations {
            cancellation.cancel();
        }
        closed
    }

    /// 关停：取消信号 → 给每个窗口投终止帧 → 在 [`SHUTDOWN_DEADLINE`] 内收拢事件泵。
    ///
    /// 顺序是有讲究的：**先取消再关窗口**。反过来的话，一个正阻塞在上游流上的泵不会被
    /// 唤醒，它要等到下一次上游产帧才发现路由没了 —— 而对一条 30 秒心跳的流来说，那就是
    /// 最多 30 秒，远超 5 秒 deadline。
    ///
    /// deadline 到了仍未停下的泵会被 `abort`：**deadline 是 deadline，不是建议**。
    /// 被 abort 的数量如实记进 [`ShutdownReport::pumps_aborted`]，不掩盖。
    /// Capture-armed transports instead retain originals and return an unsuccessful legacy report;
    /// their original caller must use `begin_capture_closing` and its resident owner.
    pub async fn shutdown(&self) -> ShutdownReport {
        let started = Instant::now();
        let (mut handles, windows_closed) = {
            let (mut pumps, poisoned) = match self.pumps.lock() {
                Ok(pumps) => (pumps, false),
                Err(poisoned) => (poisoned.into_inner(), true),
            };
            #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
            if pumps.capture_requested {
                // This legacy entry cannot take an armed owner, abort it, or claim closure.
                fail_capture(&mut pumps, if poisoned {
                    CaptureTransportFault::Poisoned
                } else {
                    CaptureTransportFault::Cancelled
                });
                self.shutdown_token().cancel();
                let windows_closed = self.broker.close_all();
                let retained = pumps.capture.as_ref().map_or(0, |capture| capture.originals.len());
                return ShutdownReport {
                    windows_closed,
                    pumps_total: pumps.legacy.len().saturating_add(retained),
                    pumps_joined: 0,
                    pumps_aborted: 0,
                    elapsed: started.elapsed(),
                    within_deadline: false,
                };
            }
            assert!(!poisoned, "事件泵句柄锁不会中毒");
            self.shutdown_token().cancel();
            let windows_closed = self.broker.close_all();
            #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
            { pumps.legacy_history = true; }
            (core::mem::take(&mut pumps.legacy), windows_closed)
        };
        let pumps_total = handles.len();

        let deadline = tokio::time::sleep(SHUTDOWN_DEADLINE);
        tokio::pin!(deadline);
        let mut pumps_joined = 0_usize;
        for handle in &mut handles {
            tokio::select! {
                () = &mut deadline => break,
                _ = &mut handle.task => pumps_joined += 1,
            }
        }

        let mut pumps_aborted = 0_usize;
        for handle in handles {
            if !handle.task.is_finished() {
                handle.task.abort();
                pumps_aborted += 1;
            }
        }
        if pumps_aborted > 0 {
            tracing::warn!(
                transport = Transport::InProcess.as_str(),
                pumps_aborted,
                pumps_total,
                "有事件泵未能在 shutdown deadline 内停下，已强制中止（§13.2）"
            );
        }

        let elapsed = started.elapsed();
        ShutdownReport {
            windows_closed,
            pumps_total,
            pumps_joined,
            pumps_aborted,
            elapsed,
            within_deadline: pumps_aborted == 0 && elapsed <= SHUTDOWN_DEADLINE,
        }
    }
}

/// 事件泵：把一条 [`AppEventStream`] 抽进某个窗口的有界路由。
async fn pump(
    broker: Arc<EventBroker>,
    shutdown: CancellationToken,
    session_cancellation: CancellationToken,
    label: WindowLabel,
    scope: EventScope,
    auth_generation: u64,
    mut stream: AppEventStream,
) {
    loop {
        enum PumpInput {
            Shutdown,
            SessionClosed,
            Event(Option<AppEvent>),
        }
        let next = tokio::select! {
            () = shutdown.cancelled() => PumpInput::Shutdown,
            () = session_cancellation.cancelled() => PumpInput::SessionClosed,
            item = next_event(&mut stream) => PumpInput::Event(item),
        };
        let event = match next {
            PumpInput::Shutdown => break,
            PumpInput::SessionClosed => {
                broker.close_window(&label, crate::broker::DisconnectReason::SubscriptionClosed);
                break;
            }
            PumpInput::Event(Some(event)) => event,
            PumpInput::Event(None) => {
                broker.close_window(&label, crate::broker::DisconnectReason::UpstreamEnded);
                break;
            }
        };

        let Ok(report) = broker.publish(BrokerEvent::new(scope.clone(), auth_generation, event))
        else {
            // broker 拒收（关停 / screen）—— 没有继续抽这条流的理由。
            break;
        };
        match report.outcome_for(&label) {
            // 路由已经不在报告里 = 它被摘除了（接收端 drop / 已断开）。
            None
            | Some(DeliveryOutcome::ReceiverGone)
            | Some(DeliveryOutcome::AlreadyDisconnected)
            | Some(DeliveryOutcome::Disconnected { .. }) => break,
            Some(
                DeliveryOutcome::Delivered { .. }
                | DeliveryOutcome::Superseded { .. }
                | DeliveryOutcome::Filtered(_),
            ) => {}
        }
    }
}

/// 从 [`AppEventStream`] 取下一项。
///
/// 手写 `poll_fn` 而不是 `futures::StreamExt::next`：本 crate 只依赖 `futures-core`
/// （`Stream` trait 本身），为一个辅助函数把 `futures-util` 拉进依赖图不划算 ——
/// `openbot-application` 在同一处做了同样的选择。
async fn next_event(stream: &mut AppEventStream) -> Option<AppEvent> {
    core::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SequenceTracker;
    use crate::testing::{TEST_AUTH_GENERATION, auth_for};
    use async_trait::async_trait;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use openbot_application::{ChannelReader, OpenBotApplication, PortError};
    use openbot_contracts::command::{ChannelSummary, HealthReport};
    use openbot_contracts::ids::{ActorId, BotId, ChannelId};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use time::OffsetDateTime;
    use tokio::time::{Duration as TokioDuration, timeout};

    // -----------------------------------------------------------------------
    // 一个真实业务实现（不是 mock）：真的 OpenBotApplication + 内存 port
    // -----------------------------------------------------------------------

    struct FakeChannels {
        rows: Vec<ChannelSummary>,
        calls: AtomicUsize,
    }

    impl FakeChannels {
        fn with_one_row() -> Self {
            Self {
                rows: vec![ChannelSummary {
                    id: ChannelId::new("c-1"),
                    name: "总控".to_owned(),
                    agent_ids: vec![BotId::new("bot-1")],
                    last_message: Some("上一条".to_owned()),
                    last_message_at: Some(OffsetDateTime::UNIX_EPOCH),
                    last_message_agent_id: Some(BotId::new("bot-1")),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                    thread_id: None,
                    active: true,
                }],
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ChannelReader for FakeChannels {
        async fn list_visible_channels(
            &self,
            _actor: &ActorId,
            _limit: u32,
            _cursor: Option<openbot_application::ChannelCursor>,
        ) -> Result<Vec<ChannelSummary>, PortError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.rows.clone())
        }
    }

    fn application() -> Arc<dyn ApplicationService> {
        Arc::new(
            OpenBotApplication::new(FakeChannels::with_one_row())
                .with_heartbeat_period(Duration::from_millis(1)),
        )
    }

    /// 一个**会失败**的 service：用来证明 transport 不改写业务判定的结果。
    struct AlwaysRefuses;

    #[async_trait]
    impl ApplicationService for AlwaysRefuses {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Err(AppError::NotVisible)
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Err(AppError::NotVisible)
        }
    }

    struct FiniteEventStream(VecDeque<AppEvent>);

    impl futures_core::Stream for FiniteEventStream {
        type Item = AppEvent;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    struct FiniteSubscriptionService;

    #[async_trait]
    impl ApplicationService for FiniteSubscriptionService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(HealthReport { ok: true }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Ok(Box::pin(FiniteEventStream(VecDeque::from([
                AppEvent::Heartbeat { seq: 41 },
            ]))))
        }
    }

    // -----------------------------------------------------------------------
    // G1 判据的本地一半：经 transport == 直连 service
    // -----------------------------------------------------------------------

    /// 同一个 `(AuthContext, AppCommand)` 经 in-process 调用与直连
    /// [`ApplicationService::execute`] 的结果**逐字段相等**。
    ///
    /// 这是 §24 G1「ApplicationService 经 Axum/Tauri 结果一致」在本 crate 能证到的那一半
    /// （跨 transport 的另一半由 `openbot-testkit` 做）。
    #[tokio::test]
    async fn in_process_execute_equals_a_direct_service_call() {
        let service = application();
        let transport = InProcessTransport::new(Arc::clone(&service));
        let auth = auth_for("actor-1");

        // 探活。
        let via_transport = transport
            .execute(auth.clone(), AppCommand::Health)
            .await
            .expect("探活成功");
        let direct = service
            .execute(auth.clone(), AppCommand::Health)
            .await
            .expect("探活成功");
        assert_eq!(via_transport, direct);
        assert_eq!(via_transport, AppReply::Health(HealthReport { ok: true }));

        // 一条真实读用例。
        let command = AppCommand::ListVisibleChannels {
            limit: None,
            cursor: None,
        };
        let via_transport = transport
            .execute(auth.clone(), command.clone())
            .await
            .expect("列表成功");
        let direct = service.execute(auth, command).await.expect("列表成功");
        assert_eq!(via_transport, direct);

        // 逐字段对：不只比一个 `==`，把投影里的每一项都点名。
        let (AppReply::Channels(page), AppReply::Channels(reference)) = (&via_transport, &direct)
        else {
            panic!("命令与应答必须一一对应");
        };
        assert_eq!(page.channels.len(), reference.channels.len());
        assert_eq!(page.next_cursor, reference.next_cursor);
        let (row, expected) = (&page.channels[0], &reference.channels[0]);
        assert_eq!(row.id, expected.id);
        assert_eq!(row.name, expected.name);
        assert_eq!(row.agent_ids, expected.agent_ids);
        assert_eq!(row.last_message, expected.last_message);
        assert_eq!(row.last_message_at, expected.last_message_at);
        assert_eq!(row.last_message_agent_id, expected.last_message_agent_id);
        assert_eq!(row.created_at, expected.created_at);
        assert_eq!(row.thread_id, expected.thread_id);
        assert_eq!(row.active, expected.active);
    }

    /// transport 持有的是**同一个** `Arc`，不是一层包装或一份拷贝。
    #[tokio::test]
    async fn the_transport_holds_the_very_same_service_arc() {
        let service = application();
        let transport = InProcessTransport::new(Arc::clone(&service));
        assert!(Arc::ptr_eq(transport.service(), &service));
    }

    /// 业务拒绝原样穿过 transport —— 不被改写、不被吞、不被翻译成别的 code。
    #[tokio::test]
    async fn a_business_refusal_passes_through_verbatim() {
        let transport = InProcessTransport::new(Arc::new(AlwaysRefuses));
        let error = transport
            .execute(auth_for("actor-1"), AppCommand::Health)
            .await
            .expect_err("service 拒绝了");
        assert_eq!(error, AppError::NotVisible);
        assert_eq!(error.http_status(), 404);

        // 订阅路径同样原样上抛。
        let opened = transport
            .open_session(
                WindowLabel::new("main"),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await;
        assert!(matches!(
            opened,
            Err(OpenSessionError::Application(AppError::NotVisible))
        ));
        assert_eq!(
            transport.broker().window_count(),
            0,
            "订阅失败不留下半开的窗口"
        );
    }

    // -----------------------------------------------------------------------
    // command 并发预算（§13.2「command 256」）
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn the_command_budget_is_the_spec_256_and_is_really_taken() {
        let transport = InProcessTransport::new(application());
        assert_eq!(
            transport.available_command_permits(),
            COMMAND_QUEUE_CAPACITY
        );

        // 正向对照：额度确实会被占用（否则上一行在"信号量根本没接上"的世界里也成立）。
        let permit = transport.commands.acquire().await.expect("信号量从不关闭");
        assert_eq!(
            transport.available_command_permits(),
            COMMAND_QUEUE_CAPACITY - 1
        );
        drop(permit);
        assert_eq!(
            transport.available_command_permits(),
            COMMAND_QUEUE_CAPACITY
        );
    }

    /// 命令跑完之后额度必须还回去 —— 否则 256 次调用之后整个通道就永久卡死。
    #[tokio::test]
    async fn a_finished_command_returns_its_permit() {
        let transport = InProcessTransport::new(application());
        for _ in 0..8 {
            transport
                .execute(auth_for("actor-1"), AppCommand::Health)
                .await
                .expect("探活成功");
        }
        assert_eq!(
            transport.available_command_permits(),
            COMMAND_QUEUE_CAPACITY
        );
    }

    // -----------------------------------------------------------------------
    // 订阅 → 有界队列
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn open_session_pumps_the_subscription_into_the_bounded_queue() {
        let transport = InProcessTransport::new(application());
        let auth = auth_for("actor-1");
        let mut session = transport
            .open_session(
                WindowLabel::new("main"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗成功");

        assert_eq!(session.auth_generation, TEST_AUTH_GENERATION);
        assert_eq!(transport.broker().window_count(), 1);

        let mut tracker = SequenceTracker::new();
        for expected in 0..3_u64 {
            let frame = timeout(TokioDuration::from_secs(5), session.next_frame())
                .await
                .expect("心跳必须在 5 秒内到")
                .expect("流未结束");
            tracker.observe(&frame).expect("序列合法");
            assert_eq!(frame.event(), Some(&AppEvent::Heartbeat { seq: expected }));
            assert_eq!(frame.seq(), expected);
        }
        assert_eq!(tracker.missing_total(), 0);

        transport.shutdown().await;
    }

    /// 同一个 actor 的两个窗口是**两条独立订阅**，互不灌帧。
    #[tokio::test]
    async fn two_windows_of_the_same_actor_get_independent_streams() {
        let transport = InProcessTransport::new(application());
        let auth = auth_for("actor-1");
        let mut a = transport
            .open_session(
                WindowLabel::new("a"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗 a");
        let mut b = transport
            .open_session(
                WindowLabel::new("b"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗 b");

        // 两条流各自从 seq 0 开始 —— 若两条订阅串到一起，其中一条会看到跳号。
        for session in [&mut a, &mut b] {
            let frame = timeout(TokioDuration::from_secs(5), session.next_frame())
                .await
                .expect("心跳必须在 5 秒内到")
                .expect("流未结束");
            assert_eq!(frame.seq(), 0);
            assert_eq!(frame.event(), Some(&AppEvent::Heartbeat { seq: 0 }));
        }

        transport.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // 取消与 deadline
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upstream_end_is_an_explicit_terminal_before_receiver_close() {
        let transport = InProcessTransport::new(Arc::new(FiniteSubscriptionService));
        let mut session = transport
            .open_session(
                WindowLabel::new("finite"),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("finite subscription opens");

        let event = session.next_frame().await.expect("event frame");
        let terminal = session.next_frame().await.expect("terminal frame");
        assert_eq!(event.seq(), 0);
        assert_eq!(event.event(), Some(&AppEvent::Heartbeat { seq: 41 }));
        assert_eq!(terminal.seq(), 1);
        assert_eq!(
            terminal.terminal_reason(),
            Some(crate::broker::DisconnectReason::UpstreamEnded)
        );
        assert!(session.next_frame().await.is_none());
        assert_eq!(transport.broker().window_count(), 0);
        let report = transport.shutdown().await;
        assert_eq!(report.pumps_aborted, 0);
    }

    #[tokio::test]
    async fn close_session_removes_the_exact_route_and_wakes_its_pump() {
        let transport = InProcessTransport::new(application());
        let label = WindowLabel::new("main");
        let mut session = transport
            .open_session(
                label.clone(),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("subscription opens");

        assert!(transport.close_session(&label));
        assert!(!transport.close_session(&label));
        assert_eq!(transport.broker().window_count(), 0);
        let reason = timeout(TokioDuration::from_secs(2), async {
            loop {
                let frame = session
                    .next_frame()
                    .await
                    .expect("receiver cannot close before terminal");
                if let Some(reason) = frame.terminal_reason() {
                    break reason;
                }
            }
        })
        .await
        .expect("close must wake receiver");
        assert_eq!(reason, crate::broker::DisconnectReason::SubscriptionClosed);
        assert!(session.next_frame().await.is_none());

        let report = transport.shutdown().await;
        assert_eq!(report.pumps_aborted, 0);
        assert!(report.within_deadline);
    }

    /// 取消之后：生产停止、在 deadline 内停住、没有任何泵被 abort。
    ///
    /// 「不再产生事件」的证据是：终止帧之后流就结束了（`next_frame()` 返回 `None`），
    /// 而不是又冒出新的心跳。
    #[tokio::test]
    async fn cancelling_stops_production_within_the_deadline() {
        let transport = InProcessTransport::new(application());
        let auth = auth_for("actor-1");
        let mut session = transport
            .open_session(
                WindowLabel::new("main"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗成功");

        // 正向对照：关停之前它确实在产事件。
        timeout(TokioDuration::from_secs(5), session.next_frame())
            .await
            .expect("关停前必须有心跳")
            .expect("流未结束");

        let report = timeout(
            SHUTDOWN_DEADLINE + TokioDuration::from_secs(2),
            transport.shutdown(),
        )
        .await
        .expect("shutdown 本身不能超过 deadline 还不返回");

        assert!(report.within_deadline, "拿到 {report:?}");
        assert_eq!(report.pumps_total, 1);
        assert_eq!(report.pumps_joined, 1);
        assert_eq!(report.pumps_aborted, 0);
        assert!(
            report.elapsed < SHUTDOWN_DEADLINE,
            "耗时 {:?}",
            report.elapsed
        );
        assert_eq!(report.windows_closed, 1);
        assert!(transport.shutdown_token().is_cancelled());

        // 抽干：最后一帧必须是终止帧，之后流结束，**不再有新事件**。
        let mut saw_terminal = false;
        while let Some(frame) = session.next_frame().await {
            assert!(
                !saw_terminal,
                "终止帧之后不该再有任何帧，却拿到 {:?}",
                frame.event()
            );
            saw_terminal = frame.is_terminal();
        }
        assert!(saw_terminal, "流结束前必须先收到终止帧");
    }

    /// 关停之后不再开得出新窗口。
    #[tokio::test]
    async fn no_new_session_after_shutdown() {
        let transport = InProcessTransport::new(application());
        transport.shutdown().await;
        let opened = transport
            .open_session(
                WindowLabel::new("main"),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await;
        assert!(matches!(opened, Err(OpenSessionError::ShuttingDown)));
    }

    /// drop 掉 session ⇒ 事件泵自己退出（不需要任何人去调 close）。
    #[tokio::test]
    async fn dropping_the_session_stops_the_pump() {
        let transport = InProcessTransport::new(application());
        let session = transport
            .open_session(
                WindowLabel::new("main"),
                &auth_for("actor-1"),
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("开窗成功");
        assert_eq!(transport.broker().window_count(), 1);

        drop(session);

        // 心跳周期 1 ms：泵会在下一拍发现接收端没了，然后退出。给它一个宽裕的上界。
        let deadline = Instant::now() + Duration::from_secs(5);
        while transport.broker().window_count() > 0 && Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            transport.broker().window_count(),
            0,
            "drop 接收端必须让生产侧停下来并摘除路由"
        );

        // 泵已经自行结束，所以关停时它是"joined"而不是"aborted"。
        let report = transport.shutdown().await;
        assert_eq!(report.pumps_aborted, 0);
        assert!(report.within_deadline);
    }

    /// 重名窗口在 transport 这一层同样被拒。
    #[tokio::test]
    async fn a_duplicate_window_label_is_rejected_at_the_transport_too() {
        let transport = InProcessTransport::new(application());
        let auth = auth_for("actor-1");
        let _first = transport
            .open_session(
                WindowLabel::new("main"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await
            .expect("首次开窗成功");
        let second = transport
            .open_session(
                WindowLabel::new("main"),
                &auth,
                SubscriptionRequest::Health,
                ThreadSubscriptions::none(),
            )
            .await;
        assert!(matches!(
            second,
            Err(OpenSessionError::WindowAlreadyOpen(_))
        ));
        transport.shutdown().await;
    }

    // -----------------------------------------------------------------------
    // 「不复制 JSON-RPC」的构造性证据
    // -----------------------------------------------------------------------

    /// In-process 模块没有任何序列化调用；Tauri WebView framing 的 codec 只在显式 host
    /// feature 内，默认 typed lane 不会把 DTO 抄成 JSON 再抄回来。
    #[test]
    fn the_in_process_lane_has_no_json_codec() {
        let source = include_str!("transport.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let code = production
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in ["serde::", "serde_json::", "bincode::", "prost::"] {
            assert!(
                !code.contains(forbidden),
                "typed lane contains codec {forbidden}"
            );
        }

        let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
            .expect("读得到本 crate 的 Cargo.toml");
        assert!(manifest.contains("tauri-host = ["));
        assert!(manifest.contains("serde_json = { workspace = true, optional = true }"));
        assert!(!manifest.contains("serde_json.workspace = true"));
    }

    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    mod capture_retention {
        use super::*;
        use tokio::sync::Notify;

        fn bounds(slots: u64) -> WholePgCarrierBounds {
            WholePgCarrierBounds {
                max_material_files: 16, max_directories: 16, max_path_bytes: 64,
                max_path_depth: 8, max_single_plain_bytes: 4096, max_material_plain_bytes: 65536,
                max_manifest_bytes: 4096, max_header_bytes: 128, max_data_chunks: 32,
                max_chunk_plain_bytes: 4096, max_wire_bytes: 131072,
                max_metadata_bytes: 1048576, max_open_files: slots,
                max_snapshot_bytes: 65536, max_spool_bytes: 131072,
                max_retained_prior_bytes: 65536, max_journal_bytes: 4096,
                max_total_allocation_bytes: 1048576, capacity_reserve_bytes: 4096,
                free_floor_bytes: 4096, max_key_medium_allocation_bytes: 4096,
                key_medium_reserve_bytes: 4096, key_medium_free_floor_bytes: 4096,
            }
        }

        fn arm_with_original_resources(
            transport: &InProcessTransport,
            slots: u64,
        ) -> Arc<Mutex<CaptureResourceTotals>> {
            let bounds = bounds(slots);
            let resources = crate::tauri_background::capture::original_capture_resources_for_test(&bounds).unwrap();
            transport.bind_original_capture_resources(Arc::clone(&resources)).unwrap();
            transport.arm_capture_retention(&bounds).unwrap();
            resources
        }

        struct HeldSubscription {
            started: Notify,
            release: Notify,
            calls: AtomicUsize,
        }

        impl HeldSubscription {
            fn new() -> Self {
                Self { started: Notify::new(), release: Notify::new(), calls: AtomicUsize::new(0) }
            }
        }

        #[async_trait]
        impl ApplicationService for HeldSubscription {
            async fn execute(&self, _auth: AuthContext, _command: AppCommand) -> Result<AppReply, AppError> {
                Ok(AppReply::Health(HealthReport { ok: true }))
            }

            async fn subscribe(&self, _auth: AuthContext, _request: SubscriptionRequest) -> Result<AppEventStream, AppError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.started.notify_one();
                self.release.notified().await;
                Ok(Box::pin(FiniteEventStream(VecDeque::new())))
            }
        }

        #[tokio::test]
        async fn a_late_subscribe_cannot_publish_after_the_original_closing_gate() {
            let service = Arc::new(HeldSubscription::new());
            let transport = Arc::new(InProcessTransport::new(service.clone()));
            arm_with_original_resources(&transport, 2);
            let caller_transport = transport.clone();
            let caller = tokio::spawn(async move {
                caller_transport.open_session(
                    WindowLabel::new("late"), &auth_for("actor-1"),
                    SubscriptionRequest::Health, ThreadSubscriptions::none(),
                ).await
            });
            service.started.notified().await;
            let mut closing = transport.begin_capture_closing().unwrap();
            assert!(closing.originals.is_empty());
            service.release.notify_one();
            assert!(matches!(caller.await.unwrap(), Err(OpenSessionError::ShuttingDown)));
            assert_eq!(transport.broker().window_count(), 0);
            assert_eq!(closing.join_originals().await, Ok(()));
            assert_eq!(transport.pumps.lock().unwrap().capture.as_ref().unwrap().pending, 0);
            // Caller completion is explicitly joined above; an empty pump Vec alone does not
            // prove that the original subscribing caller/global writer has drained.
        }

        #[tokio::test]
        async fn cancelled_subscribe_keeps_its_bounded_reservation_before_another_subscribe() {
            let service = Arc::new(HeldSubscription::new());
            let transport = InProcessTransport::new(service.clone());
            arm_with_original_resources(&transport, 1);
            let auth = auth_for("actor-1");
            let mut first = Box::pin(transport.open_session(
                WindowLabel::new("first"), &auth, SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ));
            core::future::poll_fn(|cx| {
                assert!(core::future::Future::poll(first.as_mut(), cx).is_pending());
                Poll::Ready(())
            }).await;
            assert_eq!(service.calls.load(Ordering::SeqCst), 1);
            drop(first);
            let second = transport.open_session(
                WindowLabel::new("second"), &auth, SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ).await;
            assert!(matches!(second, Err(OpenSessionError::ShuttingDown)));
            assert_eq!(service.calls.load(Ordering::SeqCst), 1);
            {
                let pumps = transport.pumps.lock().unwrap();
                let capture = pumps.capture.as_ref().unwrap();
                assert_eq!(capture.pending, 0);
                assert_eq!(capture.admissions, 1);
                assert!(capture.originals.is_empty());
            }
            let mut closing = transport.begin_capture_closing().unwrap();
            assert_eq!(closing.join_originals().await, Ok(()));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn dropping_a_pending_join_waiter_preserves_the_original_and_consumed_result() {
            let transport = InProcessTransport::new(Arc::new(FiniteSubscriptionService));
            arm_with_original_resources(&transport, 1);
            let _session = transport.open_session(
                WindowLabel::new("main"), &auth_for("actor-1"),
                SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ).await.unwrap();
            let mut closing = transport.begin_capture_closing().unwrap();
            // Tokio spawn does not synchronously poll the spawned pump; this test task has
            // not yielded, so the first original join is genuinely pending on this runtime.
            let mut waiter = Box::pin(closing.join_originals());
            core::future::poll_fn(|cx| {
                assert!(core::future::Future::poll(waiter.as_mut(), cx).is_pending());
                Poll::Ready(())
            }).await;
            drop(waiter);
            assert_eq!(closing.cursor, 0);
            assert_eq!(closing.originals.len(), 1);
            assert!(closing.originals[0].actual.is_none());
            assert_eq!(closing.join_originals().await, Ok(()));
            assert_eq!(closing.cursor, 1);
            assert!(matches!(closing.originals[0].actual.as_ref(), Some(CapturePumpOutcome::Joined(Ok(())))));
            // A second poll of a consumed JoinHandle would panic. The same actual result is used.
            assert_eq!(closing.join_originals().await, Ok(()));
        }

        struct PanickingStream(Arc<Notify>);

        impl futures_core::Stream for PanickingStream {
            type Item = AppEvent;
            fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<AppEvent>> {
                self.0.notify_one();
                panic!("original-stream-panic-payload");
            }
        }

        struct FirstPumpPanics {
            panicked: Arc<Notify>,
            calls: AtomicUsize,
        }

        #[async_trait]
        impl ApplicationService for FirstPumpPanics {
            async fn execute(&self, _auth: AuthContext, _command: AppCommand) -> Result<AppReply, AppError> {
                Ok(AppReply::Health(HealthReport { ok: true }))
            }
            async fn subscribe(&self, _auth: AuthContext, _request: SubscriptionRequest) -> Result<AppEventStream, AppError> {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(Box::pin(PanickingStream(self.panicked.clone())))
                } else {
                    Ok(Box::pin(FiniteEventStream(VecDeque::new())))
                }
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn a_finished_panicked_original_is_not_reaped_by_the_next_session() {
            let panicked = Arc::new(Notify::new());
            let service = Arc::new(FirstPumpPanics { panicked: panicked.clone(), calls: AtomicUsize::new(0) });
            let transport = InProcessTransport::new(service);
            arm_with_original_resources(&transport, 2);
            let auth = auth_for("actor-1");
            let _first = transport.open_session(
                WindowLabel::new("first"), &auth, SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ).await.unwrap();
            panicked.notified().await;
            assert!(transport.pumps.lock().unwrap().capture.as_ref().unwrap().originals[0].original.task.is_finished());
            let _second = transport.open_session(
                WindowLabel::new("second"), &auth, SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ).await.unwrap();
            let mut closing = transport.begin_capture_closing().unwrap();
            assert_eq!(closing.originals.len(), 2);
            assert_eq!(closing.join_originals().await, Err(CaptureTransportFault::Panicked));
            let Some(CapturePumpOutcome::Joined(Err(error))) = closing.originals[0].actual.as_ref() else {
                panic!("must retain the actual first JoinError");
            };
            assert!(error.is_panic());
            assert_eq!(closing.cursor, 2);
            assert_eq!(closing.join_originals().await, Err(CaptureTransportFault::Panicked));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn poisoned_gate_and_legacy_shutdown_keep_the_armed_original_resident() {
            let transport = InProcessTransport::new(Arc::new(FiniteSubscriptionService));
            arm_with_original_resources(&transport, 1);
            let _session = transport.open_session(
                WindowLabel::new("main"), &auth_for("actor-1"),
                SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ).await.unwrap();
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _gate = transport.pumps.lock().unwrap();
                panic!("original-pumps-gate-poison");
            }));
            assert!(panicked.is_err());
            assert!(matches!(transport.begin_capture_closing(), Err(CaptureTransportFault::Poisoned)));
            let report = transport.shutdown().await;
            assert_eq!(report.pumps_total, 1);
            assert_eq!(report.pumps_joined, 0);
            assert_eq!(report.pumps_aborted, 0);
            assert!(!report.within_deadline);
            let retained = match transport.pumps.lock() {
                Err(poisoned) => poisoned.into_inner(),
                Ok(_) => panic!("the original gate must remain poisoned"),
            };
            assert_eq!(retained.capture.as_ref().unwrap().originals.len(), 1);
            assert!(retained.capture.as_ref().unwrap().originals[0].actual.is_none());
        }

        #[tokio::test]
        async fn retrospective_arm_failure_does_not_consume_legacy_originals() {
            let transport = InProcessTransport::new(Arc::new(FiniteSubscriptionService));
            let resources = crate::tauri_background::capture::original_capture_resources_for_test(&bounds(1)).unwrap();
            transport.bind_original_capture_resources(resources).unwrap();
            let _session = transport.open_session(
                WindowLabel::new("legacy"), &auth_for("actor-1"),
                SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ).await.unwrap();
            assert!(matches!(transport.arm_capture_retention(&bounds(1)), Err(WholePgCarrierFault::ClosingPending)));
            let report = transport.shutdown().await;
            assert_eq!(report.pumps_total, 1);
            assert_eq!(report.pumps_aborted, 0);
            assert!(!report.within_deadline);
            assert_eq!(transport.pumps.lock().unwrap().legacy.len(), 1);
        }

        #[tokio::test]
        async fn binding_and_arm_do_not_preallocate_the_full_slot_ceiling() {
            let service = Arc::new(HeldSubscription::new());
            let transport = InProcessTransport::new(service.clone());
            let resources = arm_with_original_resources(&transport, 8);
            let before = remaining_capture_resources(&resources).unwrap();
            assert_eq!(transport.pumps.lock().unwrap().capture.as_ref().unwrap().originals.capacity(), 0);
            let auth = auth_for("actor-1");
            let mut subscribing = Box::pin(transport.open_session(
                WindowLabel::new("one"), &auth, SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ));
            core::future::poll_fn(|cx| {
                assert!(core::future::Future::poll(subscribing.as_mut(), cx).is_pending());
                Poll::Ready(())
            }).await;
            let after = remaining_capture_resources(&resources).unwrap();
            assert_eq!(service.calls.load(Ordering::SeqCst), 1);
            assert!(after.1 < before.1);
            assert_eq!(transport.pumps.lock().unwrap().capture.as_ref().unwrap().originals.capacity(), 1);
            drop(subscribing);
            assert_eq!(remaining_capture_resources(&resources), Ok(after));
            assert_eq!(transport.pumps.lock().unwrap().capture.as_ref().unwrap().pending, 0);
            let mut closing = transport.begin_capture_closing().unwrap();
            assert_eq!(closing.join_originals().await, Ok(()));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn another_owner_spending_remaining_prevents_subscribe_and_keeps_the_original() {
            let panicked = Arc::new(Notify::new());
            let service = Arc::new(FirstPumpPanics { panicked: panicked.clone(), calls: AtomicUsize::new(0) });
            let transport = InProcessTransport::new(service.clone());
            let resources = arm_with_original_resources(&transport, 2);
            let auth = auth_for("actor-1");
            let _first = transport.open_session(
                WindowLabel::new("first"), &auth, SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ).await.unwrap();
            panicked.notified().await;
            let (_, remaining_metadata) = remaining_capture_resources(&resources).unwrap();
            reserve_capture_resources(&resources, 0, remaining_metadata).unwrap();
            let component_before = transport.retained_resource_usage().unwrap();
            let second = transport.open_session(
                WindowLabel::new("second"), &auth, SubscriptionRequest::Health, ThreadSubscriptions::none(),
            ).await;
            assert!(matches!(second, Err(OpenSessionError::ShuttingDown)));
            assert_eq!(service.calls.load(Ordering::SeqCst), 1);
            assert_eq!(transport.retained_resource_usage().unwrap(), component_before);
            assert_eq!(transport.pumps.lock().unwrap().capture.as_ref().unwrap().originals.len(), 1);
            let mut closing = transport.begin_capture_closing().unwrap();
            assert_eq!(closing.join_originals().await, Err(CaptureTransportFault::Panicked));
            let Some(CapturePumpOutcome::Joined(Err(error))) = closing.originals[0].actual.as_ref() else {
                panic!("the actual original JoinError must remain resident");
            };
            assert!(error.is_panic());
            assert_eq!(closing.join_originals().await, Err(CaptureTransportFault::Panicked));
        }

    }
}
