//! 原连接资源监督。登记的是实际 stock Object ID 和本次 create 的原 owner；不推测地址、
//! backend PID 或 label，也不把 Fast、abort、timeout 或 Pool 状态当成关闭证明。
//!
//! 观察只在原 connect future / 原 Connection 被实际 drop 后记录。本地资源析构与远端 PG
//! 物理断开是不同事实；事务结果和服务端断开还须由调用方的实际协议及受控测试核验。

use std::collections::HashMap;
use std::fmt;
use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Instant;

use deadpool_postgres::{Client, ClientWrapper, Connect, ObjectId, Pool};
use tokio::sync::{OwnedSemaphorePermit, oneshot, watch};
use tokio::task::{AbortHandle, JoinHandle};
use tokio_postgres::{Client as PgClient, Config as PgConfig, Error as PgError, NoTls};

use super::PoolError;

tokio::task_local! {
    /// 只有实际本 Pool checkout scope 可登记原 create；取消 guard 留在该 scope 外。
    static CHECKOUT_TRACE: Arc<CheckoutTrace>;
}

/// 原拥有资源的最后一项析构事实；不携带配置、身份、SQL 或网络地址。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionDestruction {
    /// 建连 owner 在首次 poll 前被销毁，原 Config::connect future 尚未创建。
    ConnectingOwnerDestroyedBeforeStart,
    /// 原 Config::connect future 已实际析构，且没有交付原 Connection。
    ConnectingFutureDestroyed,
    /// 实际交付的原 Connection 已析构。
    ConnectionDestroyed,
}

/// 一个原 owner 的本地资源事实。只有析构路径能够写 destruction。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionSnapshot {
    /// 原 Config::connect future 确实已创建。
    pub connecting_future_started: bool,
    /// 原 Config::connect future 确实已析构；成功建连时也单独记录该事实。
    pub connecting_future_destroyed: bool,
    /// 已得到并持有该原 Connection。
    pub connection_started: bool,
    /// 该原 Connection 已实际析构。
    pub connection_destroyed: bool,
    /// 已请求永久退役；请求本身不是析构 ACK。
    pub retirement_requested: bool,
    /// 原 owner 的实际终结析构事实；None 表示尚未观察到终结。
    pub destruction: Option<ConnectionDestruction>,
}

/// 可在 checkout / 事务 future 取消前保留的原拥有资源观察。
#[derive(Clone)]
pub struct ConnectionObservation {
    owner: Arc<DriverOwner>,
}

impl fmt::Debug for ConnectionObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ConnectionObservation")
            .field(&self.snapshot())
            .finish()
    }
}

impl ConnectionObservation {
    /// 获取已记录的原资源事实；不把未完成或退役请求推断为已关闭。
    pub fn snapshot(&self) -> ConnectionSnapshot {
        self.owner.snapshot()
    }

    /// 等到原资源析构实际记录。调用方应自行持有总体预算，或使用 before 版本。
    ///
    /// # Errors
    /// 观察通道没有实际析构事实就终止时封闭拒绝。
    pub async fn wait_for_destruction(&self) -> Result<ConnectionDestruction, PoolError> {
        let mut changes = self.owner.state.subscribe();
        loop {
            let snapshot = *changes.borrow_and_update();
            if let Some(destruction) = snapshot.destruction {
                return Ok(destruction);
            }
            changes
                .changed()
                .await
                .map_err(|_| PoolError::ObservationUnavailable)?;
        }
    }

    /// 在传入的原绝对期限内观察实际析构，不重设预算，也不把 timeout 记为析构。
    ///
    /// # Errors
    /// 预算耗尽或缺少实际析构观察时返回固定错误。
    pub async fn wait_for_destruction_before(
        &self,
        deadline: Instant,
    ) -> Result<ConnectionDestruction, PoolError> {
        if Instant::now() >= deadline {
            return Err(PoolError::DeadlineExceeded);
        }
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.wait_for_destruction(),
        )
        .await
        .map_err(|_| PoolError::DeadlineExceeded)??;
        if Instant::now() >= deadline {
            return Err(PoolError::DeadlineExceeded);
        }
        Ok(result)
    }
}

/// 本 Pool 原 owner 的固定计数；不是 PG 活性、事务或服务端关闭证明。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnershipSnapshot {
    /// 尚未记录终结析构的 owner 总数。
    pub active_resources: usize,
    /// 其中仍处于原建连阶段的 owner 数。
    pub connecting: usize,
    /// 其中已持有原 Connection 的 owner 数。
    pub driving: usize,
    /// 其中已请求退役的 owner 数。
    pub retiring: usize,
    /// 已真实析构的原建连 future 数，包含已成功切换至 Connection 的 future。
    pub destroyed_connecting_futures: usize,
    /// 已真实析构的原 Connection 数。
    pub destroyed_connections: usize,
    /// 在原 connect future 创建前已销毁的建连 owner 数。
    pub destroyed_before_start: usize,
}

#[derive(Default)]
struct Registry {
    // 仍持有原资源的 owner；即使 checkout future 取消，也一直保留到实际析构。
    pending: HashMap<usize, Arc<DriverOwner>>,
    bound: HashMap<ObjectId, Arc<DriverOwner>>,
    destroyed_connecting_futures: usize,
    destroyed_connections: usize,
    destroyed_before_start: usize,
}

pub(super) struct OwnerSupervisor {
    registry: Mutex<Registry>,
    creations: AtomicUsize,
    fault: watch::Sender<Option<PoolError>>,
    #[cfg(feature = "desktop-local-vault")]
    retention: Option<retained::SupervisorRetention>,
}

impl OwnerSupervisor {
    pub(super) fn new() -> Arc<Self> {
        let (fault, _) = watch::channel(None);
        Arc::new(Self {
            registry: Mutex::new(Registry::default()),
            creations: AtomicUsize::new(0),
            fault,
            #[cfg(feature = "desktop-local-vault")]
            retention: None,
        })
    }

    #[cfg(feature = "desktop-local-vault")]
    fn new_retained(retention: retained::SupervisorRetention, registry: Registry) -> Arc<Self> {
        let (fault, _) = watch::channel(None);
        Arc::new(Self {
            registry: Mutex::new(registry),
            creations: AtomicUsize::new(0),
            fault,
            retention: Some(retention),
        })
    }

    fn fail(&self, error: PoolError) {
        self.fault.send_if_modified(|fault| {
            if fault.is_none() {
                *fault = Some(error);
                true
            } else {
                false
            }
        });
    }

    fn current_fault(&self) -> Option<PoolError> {
        *self.fault.borrow()
    }

    /// 先检查创造次数，再允许 stock Manager 真正创建。成功 stock ID 的分配次数只可能更少，
    /// 因而底层从 0 递增的 usize ID 不会回绕；ObjectId 本身不做算术或文本解析。
    fn reserve_creation(&self) -> Result<usize, PoolError> {
        self.creations
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_add(1)
            })
            .map_err(|_| {
                self.fail(PoolError::CreationLimit);
                PoolError::CreationLimit
            })
    }

    fn register(&self, owner: Arc<DriverOwner>) -> Result<(), PoolError> {
        let mut registry = self.registry.lock().map_err(|_| {
            self.fail(PoolError::OwnershipUnavailable);
            PoolError::OwnershipUnavailable
        })?;
        if registry.pending.contains_key(&owner.sequence) {
            self.fail(PoolError::IdentityCollision);
            return Err(PoolError::IdentityCollision);
        }
        #[cfg(feature = "desktop-local-vault")]
        if self.retention.is_some() && registry.pending.len() >= registry.pending.capacity() {
            return Err(PoolError::CreationLimit);
        }
        registry.pending.insert(owner.sequence, owner);
        Ok(())
    }

    fn finish(&self, sequence: usize, snapshot: ConnectionSnapshot) {
        // 毒化只能按原 owner 做清理，不能批准借用或归池。
        let mut registry = self.registry.lock().unwrap_or_else(|error| {
            self.fail(PoolError::OwnershipUnavailable);
            error.into_inner()
        });
        if registry.pending.remove(&sequence).is_none() {
            return;
        }
        registry.bound.retain(|_, owner| owner.sequence != sequence);
        if snapshot.connecting_future_destroyed {
            registry.destroyed_connecting_futures =
                registry.destroyed_connecting_futures.saturating_add(1);
        }
        if snapshot.connection_destroyed {
            registry.destroyed_connections = registry.destroyed_connections.saturating_add(1);
        }
        if snapshot.destruction == Some(ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart)
        {
            registry.destroyed_before_start = registry.destroyed_before_start.saturating_add(1);
        }
    }

    fn unbind(&self, id: ObjectId, owner: &Arc<DriverOwner>) {
        let mut registry = self.registry.lock().unwrap_or_else(|error| {
            self.fail(PoolError::OwnershipUnavailable);
            error.into_inner()
        });
        if registry
            .bound
            .get(&id)
            .is_some_and(|bound| Arc::ptr_eq(bound, owner))
        {
            registry.bound.remove(&id);
        }
    }

    fn can_return(&self, id: ObjectId, owner: &Arc<DriverOwner>) -> bool {
        #[cfg(feature = "desktop-local-vault")]
        if self
            .retention
            .as_ref()
            .is_some_and(|retention| retention.ensure_running().is_err())
        {
            return false;
        }
        if self.current_fault().is_some() || !owner.live() {
            return false;
        }
        let Ok(registry) = self.registry.lock() else {
            self.fail(PoolError::OwnershipUnavailable);
            return false;
        };
        registry
            .bound
            .get(&id)
            .is_some_and(|bound| Arc::ptr_eq(bound, owner))
    }

    fn bind(&self, id: ObjectId, trace: &CheckoutTrace) -> Result<Arc<DriverOwner>, PoolError> {
        if let Some(error) = self.current_fault() {
            return Err(error);
        }
        let created = trace.created_owner()?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| PoolError::OwnershipUnavailable)?;
        let owner = if let Some(owner) = created {
            if registry.bound.contains_key(&id) {
                return Err(PoolError::IdentityCollision);
            }
            let pending = registry
                .pending
                .get(&owner.sequence)
                .ok_or(PoolError::OwnershipUnavailable)?;
            if !Arc::ptr_eq(pending, &owner) || !owner.live() {
                return Err(PoolError::OwnershipUnavailable);
            }
            #[cfg(feature = "desktop-local-vault")]
            if self.retention.is_some() && registry.bound.len() >= registry.bound.capacity() {
                return Err(PoolError::CreationLimit);
            }
            registry.bound.insert(id, Arc::clone(&owner));
            owner
        } else {
            let owner = registry
                .bound
                .get(&id)
                .ok_or(PoolError::OwnershipUnavailable)?;
            if !owner.live() {
                return Err(PoolError::OwnershipUnavailable);
            }
            Arc::clone(owner)
        };
        Ok(owner)
    }

    pub(super) async fn checkout(self: &Arc<Self>, stock: &Pool) -> Result<ClientLease, PoolError> {
        self.checkout_inner(stock, None).await
    }

    #[cfg(feature = "server-runtime")]
    pub(super) async fn checkout_with_session_permit(
        self: &Arc<Self>,
        stock: &Pool,
        permit: OwnedSemaphorePermit,
    ) -> Result<ClientLease, PoolError> {
        self.checkout_inner(stock, Some(permit)).await
    }

    async fn checkout_inner(
        self: &Arc<Self>,
        stock: &Pool,
        session_permit: Option<OwnedSemaphorePermit>,
    ) -> Result<ClientLease, PoolError> {
        if let Some(error) = self.current_fault() {
            stock.close();
            return Err(error);
        }
        if stock.is_closed() {
            return Err(PoolError::Closed);
        }
        #[cfg(feature = "desktop-local-vault")]
        if let Some(retention) = self.retention.as_ref() {
            retention.ensure_running()?;
        }
        #[cfg(feature = "desktop-local-vault")]
        let metadata_ticket = match self.retention.as_ref() {
            Some(retention) => Some(retention.reserve_checkout()?),
            None => None,
        };
        let trace = Arc::new(CheckoutTrace::new(
            self,
            session_permit,
            #[cfg(feature = "desktop-local-vault")]
            metadata_ticket,
        ));
        let mut cancellation = CheckoutCancellation {
            trace: Arc::clone(&trace),
            armed: true,
        };
        let get = CHECKOUT_TRACE.scope(Arc::clone(&trace), stock.get());
        tokio::pin!(get);
        let mut fault = self.fault.subscribe();
        let result = tokio::select! {
            biased;
            error = async {
                loop {
                    let current = *fault.borrow_and_update();
                    if let Some(error) = current { break error; }
                    if fault.changed().await.is_err() { break PoolError::OwnershipUnavailable; }
                }
            } => { stock.close(); return Err(error); }
            result = &mut get => result,
        };
        let object = result.map_err(|error| match error {
            deadpool_postgres::PoolError::Closed => PoolError::Closed,
            _ => self.current_fault().unwrap_or(PoolError::Unavailable),
        })?;
        #[cfg(feature = "desktop-local-vault")]
        let _retained_gate = match self.retention.as_ref() {
            Some(retention) => match retention.lock_running() {
                Ok(guard) => Some(guard),
                Err(error) => {
                    drop(Client::take(object));
                    return Err(error);
                }
            },
            None => None,
        };
        // actual get → actual ID → registry bind → lease 移交连续完成；其间没有 await。
        let id = Client::id(&object);
        let owner = match self.bind(id, &trace).and_then(|owner| {
            // bind's registry guard is gone before taking owner/custody locks.
            trace.attach_session_permit(&owner)?;
            Ok(owner)
        }) {
            Ok(owner) => owner,
            Err(error) => {
                self.fail(error);
                #[cfg(feature = "desktop-local-vault")]
                drop(_retained_gate);
                let wrapper = Client::take(object);
                drop(wrapper);
                stock.close();
                return Err(error);
            }
        };
        let lease = ClientLease {
            object: Some(object),
            id,
            owner,
            supervisor: Arc::clone(self),
        };
        cancellation.armed = false;
        Ok(lease)
    }

    pub(super) fn observations(&self) -> Vec<ConnectionObservation> {
        let registry = self.registry.lock().unwrap_or_else(|error| {
            self.fail(PoolError::OwnershipUnavailable);
            error.into_inner()
        });
        registry
            .pending
            .values()
            .map(|owner| ConnectionObservation {
                owner: Arc::clone(owner),
            })
            .collect()
    }

    pub(super) fn snapshot(&self) -> OwnershipSnapshot {
        let registry = self.registry.lock().unwrap_or_else(|error| {
            self.fail(PoolError::OwnershipUnavailable);
            error.into_inner()
        });
        let mut snapshot = OwnershipSnapshot {
            destroyed_connecting_futures: registry.destroyed_connecting_futures,
            destroyed_connections: registry.destroyed_connections,
            destroyed_before_start: registry.destroyed_before_start,
            ..OwnershipSnapshot::default()
        };
        for owner in registry.pending.values() {
            let state = owner.snapshot();
            snapshot.destroyed_connecting_futures += usize::from(state.connecting_future_destroyed);
            snapshot.destroyed_connections += usize::from(state.connection_destroyed);
            snapshot.destroyed_before_start += usize::from(
                state.destruction
                    == Some(ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart),
            );
            if state.destruction.is_some() {
                continue;
            }
            snapshot.active_resources += 1;
            snapshot.driving += usize::from(state.connection_started);
            snapshot.connecting += usize::from(!state.connection_started);
            snapshot.retiring += usize::from(state.retirement_requested);
        }
        snapshot
    }
}

/// One existing gateway-session permit, held by at most one original driver.
/// It neither creates capacity nor treats wrapper Drop as original destruction.
struct SessionPermitCustody {
    state: Mutex<SessionPermitState>,
}

enum SessionPermitState {
    Unattached(OwnedSemaphorePermit),
    Attached {
        original_sequence: usize,
        permit: OwnedSemaphorePermit,
    },
    Released,
}

impl SessionPermitCustody {
    fn new(permit: OwnedSemaphorePermit) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(SessionPermitState::Unattached(permit)),
        })
    }

    // Caller holds DriverOwner.session_custody: fixed owner -> custody lock order.
    fn attach(&self, original_sequence: usize) -> Result<(), PoolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PoolError::OwnershipUnavailable)?;
        match &*state {
            SessionPermitState::Attached {
                original_sequence: attached,
                ..
            } if *attached == original_sequence => return Ok(()),
            SessionPermitState::Unattached(_) => {}
            _ => return Err(PoolError::OwnershipUnavailable),
        }
        let previous = std::mem::replace(&mut *state, SessionPermitState::Released);
        if let SessionPermitState::Unattached(permit) = previous {
            *state = SessionPermitState::Attached {
                original_sequence,
                permit,
            };
            Ok(())
        } else {
            Err(PoolError::OwnershipUnavailable)
        }
    }

    // Only the exact original resource's actual destruction path may release it.
    fn finish(&self, original_sequence: usize) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !matches!(&*state, SessionPermitState::Attached { original_sequence: attached, .. }
            if *attached == original_sequence)
        {
            return;
        }
        let previous = std::mem::replace(&mut *state, SessionPermitState::Released);
        if let SessionPermitState::Attached { permit, .. } = previous {
            drop(permit);
        }
    }
}

struct CheckoutTrace {
    supervisor: Weak<OwnerSupervisor>,
    created: Mutex<Vec<Arc<DriverOwner>>>,
    session_custody: Option<Arc<SessionPermitCustody>>,
    // Last: refund only after the actual trace vector/session state is dropped.
    #[cfg(feature = "desktop-local-vault")]
    metadata_ticket: Option<retained::CheckoutMetadataTicket>,
}

impl CheckoutTrace {
    fn new(
        supervisor: &Arc<OwnerSupervisor>,
        permit: Option<OwnedSemaphorePermit>,
        #[cfg(feature = "desktop-local-vault")] metadata_ticket: Option<
            retained::CheckoutMetadataTicket,
        >,
    ) -> Self {
        #[cfg(feature = "desktop-local-vault")]
        let created = if metadata_ticket.is_some() {
            Vec::with_capacity(1)
        } else {
            Vec::new()
        };
        #[cfg(not(feature = "desktop-local-vault"))]
        let created = Vec::new();
        Self {
            supervisor: Arc::downgrade(supervisor),
            created: Mutex::new(created),
            session_custody: permit.map(SessionPermitCustody::new),
            #[cfg(feature = "desktop-local-vault")]
            metadata_ticket,
        }
    }

    fn belongs_to(&self, supervisor: &Arc<OwnerSupervisor>) -> bool {
        self.supervisor.ptr_eq(&Arc::downgrade(supervisor))
    }

    fn attach_session_permit(&self, owner: &DriverOwner) -> Result<(), PoolError> {
        match &self.session_custody {
            Some(custody) => owner.attach_session_custody(custody),
            None => Ok(()),
        }
    }

    fn record(&self, owner: Arc<DriverOwner>) -> Result<(), PoolError> {
        // Before spawn/first original-connect poll, without registry/created locks.
        self.attach_session_permit(&owner)?;
        let mut created = self
            .created
            .lock()
            .map_err(|_| PoolError::OwnershipUnavailable)?;
        #[cfg(feature = "desktop-local-vault")]
        if self.metadata_ticket.is_some() && !created.is_empty() {
            return Err(PoolError::OwnershipUnavailable);
        }
        created.push(owner);
        if created.len() != 1 {
            return Err(PoolError::OwnershipUnavailable);
        }
        Ok(())
    }

    fn created_owner(&self) -> Result<Option<Arc<DriverOwner>>, PoolError> {
        let created = self
            .created
            .lock()
            .map_err(|_| PoolError::OwnershipUnavailable)?;
        match created.as_slice() {
            [] => Ok(None),
            [owner] => Ok(Some(Arc::clone(owner))),
            _ => Err(PoolError::OwnershipUnavailable),
        }
    }

    fn retire_created(&self) {
        #[cfg(feature = "desktop-local-vault")]
        if self.metadata_ticket.is_some() {
            let owner = self
                .created
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .first()
                .map(Arc::clone);
            if let Some(owner) = owner {
                owner.request_retirement();
            }
            return;
        }
        let created = self
            .created
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        // Do not invert the creation gate -> trace lock order during cancellation.
        for owner in created {
            owner.request_retirement();
        }
    }
}

/// 位于 task-local scope 外；scope future 无论在哪个 TLS 环境析构都不会丢失原 owner。
struct CheckoutCancellation {
    trace: Arc<CheckoutTrace>,
    armed: bool,
}

impl Drop for CheckoutCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.trace.retire_created();
        }
    }
}

struct DriverOwner {
    sequence: usize,
    supervisor: Weak<OwnerSupervisor>,
    state: watch::Sender<ConnectionSnapshot>,
    abort: Mutex<Option<AbortHandle>>,
    session_custody: Mutex<Option<Arc<SessionPermitCustody>>>,
    #[cfg(feature = "desktop-local-vault")]
    retention: Option<retained::DriverRetention>,
}

impl DriverOwner {
    fn new(sequence: usize, supervisor: &Arc<OwnerSupervisor>) -> Arc<Self> {
        let (state, _) = watch::channel(ConnectionSnapshot::default());
        Arc::new(Self {
            sequence,
            supervisor: Arc::downgrade(supervisor),
            state,
            abort: Mutex::new(None),
            session_custody: Mutex::new(None),
            #[cfg(feature = "desktop-local-vault")]
            retention: None,
        })
    }

    #[cfg(feature = "desktop-local-vault")]
    fn new_retained(
        sequence: usize,
        supervisor: &Arc<OwnerSupervisor>,
        retention: retained::DriverRetention,
    ) -> Arc<Self> {
        let mut owner = Self::new(sequence, supervisor);
        Arc::get_mut(&mut owner)
            .expect("new original owner is exclusive")
            .retention = Some(retention);
        owner
    }

    fn attach_session_custody(&self, custody: &Arc<SessionPermitCustody>) -> Result<(), PoolError> {
        let mut held = self
            .session_custody
            .lock()
            .map_err(|_| PoolError::OwnershipUnavailable)?;
        if self.snapshot().destruction.is_some() {
            return Err(PoolError::OwnershipUnavailable);
        }
        if held
            .as_ref()
            .is_some_and(|current| !Arc::ptr_eq(current, custody))
        {
            return Err(PoolError::OwnershipUnavailable);
        }
        custody.attach(self.sequence)?;
        *held = Some(Arc::clone(custody));
        Ok(())
    }

    fn snapshot(&self) -> ConnectionSnapshot {
        *self.state.borrow()
    }

    fn live(&self) -> bool {
        let state = self.snapshot();
        state.connection_started && state.destruction.is_none() && !state.retirement_requested
    }

    fn install_abort(&self, abort: AbortHandle) {
        let mut slot = self.abort.lock().unwrap_or_else(|error| error.into_inner());
        let requested = self.snapshot().retirement_requested;
        *slot = Some(abort);
        drop(slot);
        if requested {
            #[cfg(feature = "desktop-local-vault")]
            if let Some(retention) = self.retention.as_ref() {
                retention.wake();
                return;
            }
            self.abort_original();
        }
    }

    fn request_retirement(&self) {
        self.state
            .send_modify(|state| state.retirement_requested = true);
        #[cfg(feature = "desktop-local-vault")]
        if let Some(retention) = self.retention.as_ref() {
            retention.retirement_requested();
            return;
        }
        self.abort_original();
    }

    fn abort_original(&self) {
        let slot = self.abort.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(abort) = slot.as_ref() {
            abort.abort();
        }
    }

    fn connecting_started(&self) {
        self.state
            .send_modify(|state| state.connecting_future_started = true);
    }

    fn connecting_destroyed(&self) {
        self.state
            .send_modify(|state| state.connecting_future_destroyed = true);
    }

    fn driving_started(&self) {
        self.state
            .send_modify(|state| state.connection_started = true);
        #[cfg(feature = "desktop-local-vault")]
        if let Some(retention) = self.retention.as_ref() {
            retention.driving_started();
        }
    }

    /// 调用者必须已经 drop 原资源；这里仅登记之后的事实，并从 held registry 移走它。
    fn finish_after_drop(&self, destruction: ConnectionDestruction) {
        // Serialize late attachment with actual destruction; never nest registry locks.
        let held = self
            .session_custody
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut first = false;
        self.state.send_modify(|state| {
            if state.destruction.is_some() {
                return;
            }
            match destruction {
                ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart => {}
                ConnectionDestruction::ConnectingFutureDestroyed => {
                    state.connecting_future_destroyed = true
                }
                ConnectionDestruction::ConnectionDestroyed => state.connection_destroyed = true,
            }
            state.destruction = Some(destruction);
            first = true;
        });
        if first && let Some(custody) = held.as_ref() {
            custody.finish(self.sequence);
        }
        drop(held);
        #[cfg(feature = "desktop-local-vault")]
        if first && let Some(retention) = self.retention.as_ref() {
            retention.after_drop(destruction);
        }
        if first && let Some(supervisor) = self.supervisor.upgrade() {
            supervisor.finish(self.sequence, self.snapshot());
        }
    }
}

pub(super) struct SupervisedConnect {
    supervisor: Weak<OwnerSupervisor>,
}

impl SupervisedConnect {
    pub(super) fn new(supervisor: &Arc<OwnerSupervisor>) -> Self {
        Self {
            supervisor: Arc::downgrade(supervisor),
        }
    }
}

type DrivingFuture = Pin<Box<dyn Future<Output = Result<(), PgError>> + Send>>;
type ConnectingFuture =
    Pin<Box<dyn Future<Output = Result<(PgClient, DrivingFuture), PgError>> + Send>>;
type ConnectResultFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(PgClient, JoinHandle<()>), PgError>> + Send + 'a>>;

impl Connect for SupervisedConnect {
    fn connect(&self, pg_config: &PgConfig) -> ConnectResultFuture<'_> {
        let Some(supervisor) = self.supervisor.upgrade() else {
            return Box::pin(pending());
        };
        let trace = match CHECKOUT_TRACE.try_with(Arc::clone) {
            Ok(trace) if trace.belongs_to(&supervisor) => trace,
            _ => {
                supervisor.fail(PoolError::OwnershipUnavailable);
                return Box::pin(pending());
            }
        };
        #[cfg(feature = "desktop-local-vault")]
        if let Some(retention) = supervisor.retention.as_ref() {
            return retention.connect(Arc::clone(&supervisor), pg_config, trace);
        }
        let sequence = match supervisor.reserve_creation() {
            Ok(sequence) => sequence,
            Err(_) => return Box::pin(pending()),
        };
        let owner = DriverOwner::new(sequence, &supervisor);
        let configuration = pg_config.clone();
        let connecting_owner = Arc::clone(&owner);
        let connecting: ConnectingFuture = Box::pin(async move {
            let original = configuration.connect(NoTls);
            let mut original = Box::pin(original);
            connecting_owner.connecting_started();
            let result = original.as_mut().await;
            drop(original);
            connecting_owner.connecting_destroyed();
            result.map(|(client, connection)| (client, Box::pin(connection) as DrivingFuture))
        });
        let (ready, receiver) = oneshot::channel();
        // OriginalDriver 先在异步体外构造；task 在首次 poll 前取消也会实际 drop 它。
        let driver = OriginalDriver {
            resource: OriginalResource::Connecting(connecting),
            ready: Some(ready),
            owner: Arc::clone(&owner),
        };
        if let Err(error) = supervisor.register(Arc::clone(&owner)) {
            supervisor.fail(error);
            drop(driver);
            return Box::pin(pending());
        }
        if let Err(error) = trace.record(Arc::clone(&owner)) {
            supervisor.fail(error);
            // 未 spawn 的实际建连 owner 也先析构资源；不倒记不存在的 Config::connect future。
            drop(driver);
            return Box::pin(pending());
        }
        let task = tokio::spawn(driver);
        owner.install_abort(task.abort_handle());
        let guard = CreationCancellation {
            owner,
            task: Some(task),
        };
        Box::pin(async move {
            let mut guard = guard;
            match receiver.await {
                Ok(Ok(client)) => {
                    let task = guard
                        .task
                        .take()
                        .expect("original task transfer is single use");
                    Ok((client, task))
                }
                Ok(Err(error)) => Err(error),
                Err(_) => {
                    // 不造 PgError / stock timeout；原 owner 仍 held，由 facade 的固定 fault 取消。
                    supervisor.fail(PoolError::OwnershipUnavailable);
                    pending().await
                }
            }
        })
    }
}

struct CreationCancellation {
    owner: Arc<DriverOwner>,
    task: Option<JoinHandle<()>>,
}

impl Drop for CreationCancellation {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.owner.request_retirement();
            task.abort();
            // abort / JoinHandle Drop 都不是析构 ACK；只有 OriginalDriver 的原资源 drop 写观察。
            drop(task);
        }
    }
}

enum OriginalResource {
    Connecting(ConnectingFuture),
    Driving(DrivingFuture),
    Empty,
}

/// 始终持有并 poll 同一个原 Config::connect / Connection；不另起“关闭探针”。
struct OriginalDriver {
    resource: OriginalResource,
    ready: Option<oneshot::Sender<Result<PgClient, PgError>>>,
    owner: Arc<DriverOwner>,
}

impl OriginalDriver {
    fn destroy_original(&mut self) {
        let original = std::mem::replace(&mut self.resource, OriginalResource::Empty);
        let kind = match &original {
            OriginalResource::Connecting(_) => {
                if self.owner.snapshot().connecting_future_started {
                    Some(ConnectionDestruction::ConnectingFutureDestroyed)
                } else {
                    Some(ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart)
                }
            }
            OriginalResource::Driving(_) => Some(ConnectionDestruction::ConnectionDestroyed),
            OriginalResource::Empty => None,
        };
        drop(original);
        // 此写入严格在上述原 future / Connection 析构之后。
        if let Some(kind) = kind {
            self.owner.finish_after_drop(kind);
        }
    }
}

impl Future for OriginalDriver {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        #[cfg(feature = "desktop-local-vault")]
        if this
            .owner
            .retention
            .as_ref()
            .is_some_and(|retention| retention.poll_retirement(&this.owner, cx))
        {
            this.destroy_original();
            return Poll::Ready(());
        }
        loop {
            match &mut this.resource {
                OriginalResource::Connecting(connecting) => {
                    let result = match connecting.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result,
                    };
                    let original = std::mem::replace(&mut this.resource, OriginalResource::Empty);
                    drop(original);
                    match result {
                        Ok((client, connection)) => {
                            this.resource = OriginalResource::Driving(connection);
                            this.owner.driving_started();
                            let ready = this
                                .ready
                                .take()
                                .expect("original create reply is single use");
                            if ready.send(Ok(client)).is_err() {
                                this.owner.request_retirement();
                                this.destroy_original();
                                return Poll::Ready(());
                            }
                            // 安装原 Connection 与交付 client 之间没有 await，继续驱动原连接。
                        }
                        Err(error) => {
                            this.owner.finish_after_drop(
                                ConnectionDestruction::ConnectingFutureDestroyed,
                            );
                            if let Some(ready) = this.ready.take() {
                                let _ = ready.send(Err(error));
                            }
                            return Poll::Ready(());
                        }
                    }
                }
                OriginalResource::Driving(connection) => {
                    if connection.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    this.destroy_original();
                    return Poll::Ready(());
                }
                OriginalResource::Empty => return Poll::Ready(()),
            }
        }
    }
}

impl Drop for OriginalDriver {
    fn drop(&mut self) {
        self.destroy_original();
    }
}

/// 只有这里持有可永久 take 的原 stock Object；不对外公开或可替换。
pub(super) struct ClientLease {
    object: Option<Client>,
    id: ObjectId,
    owner: Arc<DriverOwner>,
    supervisor: Arc<OwnerSupervisor>,
}

impl ClientLease {
    pub(super) fn stock(&self) -> &Client {
        self.object.as_ref().expect("unconsumed original object")
    }

    pub(super) fn stock_mut(&mut self) -> &mut Client {
        self.object.as_mut().expect("unconsumed original object")
    }

    pub(super) fn observation(&self) -> ConnectionObservation {
        ConnectionObservation {
            owner: Arc::clone(&self.owner),
        }
    }

    pub(super) fn detach(mut self) -> ClientWrapper {
        let object = self.object.take().expect("unconsumed original object");
        self.supervisor.unbind(self.id, &self.owner);
        // legacy 永久 detach 保留原 Wrapper/driver 行为；没有回池出口或 014 ACK 声称。
        Client::take(object)
    }

    pub(super) fn release(mut self, reusable: bool) {
        let Some(object) = self.object.take() else {
            return;
        };
        if reusable
            && Client::id(&object) == self.id
            && self.supervisor.can_return(self.id, &self.owner)
        {
            drop(object);
        } else {
            self.retire_object(object);
        }
    }

    fn retire_object(&self, object: Client) {
        self.supervisor.unbind(self.id, &self.owner);
        let wrapper = Client::take(object);
        self.owner.request_retirement();
        drop(wrapper);
    }
}

impl Drop for ClientLease {
    fn drop(&mut self) {
        if let Some(object) = self.object.take() {
            self.retire_object(object);
        }
    }
}

#[cfg(feature = "desktop-local-vault")]
mod capture_io {
    use super::*;
    use crate::db::capture_materials::{CaptureDecodeBudget, CaptureSqlFailure};
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Clone, Copy)]
    enum Endpoint {
        Tcp(SocketAddr),
        #[cfg(unix)]
        Unix { bytes: [u8; 104], len: usize },
    }
    #[derive(Clone, Copy)]
    struct TcpOptions {
        keepalive: bool,
        idle: Duration,
        interval: Option<Duration>,
        retries: Option<u32>,
    }
    impl TcpOptions {
        fn from_original(config: &PgConfig) -> Self {
            Self {
                keepalive: config.get_keepalives(),
                idle: config.get_keepalives_idle(),
                interval: config.get_keepalives_interval(),
                retries: config.get_keepalives_retries(),
            }
        }
    }
    enum OriginalSocket {
        Tcp(tokio::net::TcpStream),
        #[cfg(unix)]
        Unix(tokio::net::UnixStream),
    }
    type SocketFuture = Pin<Box<dyn Future<Output = io::Result<OriginalSocket>> + Send>>;
    enum SocketState {
        Connecting(SocketFuture),
        Connected(OriginalSocket),
        Failed,
    }
    fn endpoint(config: &PgConfig) -> Result<Endpoint, CaptureSqlFailure> {
        if config.get_ports().len() != 1
            || !config.get_hostaddrs().is_empty()
            || config.get_ssl_mode() == tokio_postgres::config::SslMode::Require
            || config.get_channel_binding() == tokio_postgres::config::ChannelBinding::Require
            || config.get_target_session_attrs()
                != tokio_postgres::config::TargetSessionAttrs::Any
        {
            return Err(CaptureSqlFailure::Bounds);
        }
        let port = config.get_ports()[0];
        match config.get_hosts() {
            [tokio_postgres::config::Host::Tcp(host)] if host == "127.0.0.1" => {
                Ok(Endpoint::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))))
            }
            #[cfg(unix)]
            [tokio_postgres::config::Host::Unix(root)] => {
                use std::os::unix::ffi::OsStrExt;
                let root = root.as_os_str().as_bytes();
                if root.is_empty() || root.contains(&0) {
                    return Err(CaptureSqlFailure::Bounds);
                }
                let mut bytes = [0u8; 104];
                let mut digits = [0u8; 5];
                let mut n = port;
                let mut first = 5usize;
                loop {
                    first -= 1;
                    digits[first] = b'0' + (n % 10) as u8;
                    n /= 10;
                    if n == 0 { break; }
                }
                let slash = usize::from(!root.ends_with(b"/"));
                let len = root.len().checked_add(slash)
                    .and_then(|n| n.checked_add(b".s.PGSQL.".len()))
                    .and_then(|n| n.checked_add(5 - first))
                    .filter(|len| *len < bytes.len()).ok_or(CaptureSqlFailure::Bounds)?;
                bytes[..root.len()].copy_from_slice(root);
                let mut at = root.len();
                if slash != 0 { bytes[at] = b'/'; at += 1; }
                bytes[at..at + 9].copy_from_slice(b".s.PGSQL.");
                at += 9;
                bytes[at..len].copy_from_slice(&digits[first..]);
                Ok(Endpoint::Unix { bytes, len })
            }
            _ => Err(CaptureSqlFailure::Bounds),
        }
    }

    // All endpoint/option inputs are copied nonsecret DATA. This is the one actual
    // lazy factory used both for the connection and its unpolled Layout calculation.
    fn original_socket(
        endpoint: Endpoint, timeout: Option<Duration>, options: TcpOptions,
    ) -> impl Future<Output = io::Result<OriginalSocket>> + Send {
        async move {
            async fn connect(endpoint: Endpoint, options: TcpOptions) -> io::Result<OriginalSocket> {
                match endpoint {
                    Endpoint::Tcp(address) => {
                        let stream = tokio::net::TcpStream::connect(address).await?;
                        preserve_captured_tcp_options(&stream, &options)?;
                        Ok(OriginalSocket::Tcp(stream))
                    }
                    #[cfg(unix)]
                    Endpoint::Unix { bytes, len } => {
                        use std::os::unix::ffi::OsStrExt;
                        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&bytes[..len]));
                        Ok(OriginalSocket::Unix(tokio::net::UnixStream::connect(path).await?))
                    }
                }
            }
            match timeout {
                Some(duration) => tokio::time::timeout(duration, connect(endpoint, options))
                    .await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
                None => connect(endpoint, options).await,
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)] // Only this locked-platform FFI helper; crate/workspace deny stays.
    fn preserve_captured_tcp_options(
        original: &tokio::net::TcpStream, options: &TcpOptions,
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::raw::{c_int, c_void};
        unsafe extern "C" {
            fn setsockopt(fd: c_int, level: c_int, name: c_int,
                value: *const c_void, length: u32) -> c_int;
        }
        fn set(fd: c_int, level: c_int, name: c_int, value: c_int) -> io::Result<()> {
            // SAFETY: fd is borrowed from the live original TcpStream for this synchronous
            // call and is never closed/replaced here. value points to an aligned live c_int;
            // setsockopt only reads exactly size_of::<c_int>() bytes during this call. The
            // macOS ABI uses u32 socklen_t; no pointer or reference escapes to C. level/name
            // are the locked Darwin SOL_SOCKET/TCP constants below; errno is read immediately.
            // The declaration is scoped to this audited helper and no other unsafe is allowed.
            let result = unsafe {
                setsockopt(fd, level, name, (&value as *const c_int).cast(),
                    std::mem::size_of::<c_int>() as u32)
            };
            if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
        }
        // tokio-postgres 0.7.18 connect_socket and socket2 0.6.5 perform this exact
        // NODELAY / KEEPALIVE sequence. TCP_USER_TIMEOUT is ignored on macOS upstream.
        original.set_nodelay(true)?;
        if options.keepalive {
            let fd = original.as_raw_fd();
            set(fd, 0xffff, 0x0008, 1)?;
            let secs = |d: Duration| d.as_secs().min(i32::MAX as u64) as i32;
            set(fd, 6, 0x10, secs(options.idle))?;
            if let Some(interval) = options.interval { set(fd, 6, 0x101, secs(interval))?; }
            if let Some(retries) = options.retries { set(fd, 6, 0x102, retries as i32)?; }
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    fn preserve_captured_tcp_options(
        _original: &tokio::net::TcpStream, _options: &TcpOptions,
    ) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn poll_connect(state: &mut SocketState, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let SocketState::Connecting(future) = state {
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(socket)) => *state = SocketState::Connected(socket),
                Poll::Ready(Err(error)) => { *state = SocketState::Failed; return Poll::Ready(Err(error)); }
            }
        }
        match state {
            SocketState::Connected(_) => Poll::Ready(Ok(())),
            _ => Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected))),
        }
    }
    fn read_socket(
        state: &mut SocketState, cx: &mut Context<'_>, dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match state {
            SocketState::Connected(OriginalSocket::Tcp(stream)) => Pin::new(stream).poll_read(cx, dst),
            #[cfg(unix)]
            SocketState::Connected(OriginalSocket::Unix(stream)) => Pin::new(stream).poll_read(cx, dst),
            _ => Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected))),
        }
    }

    /// Original bounded socket DATA; it grants neither a source nor a capture operation.
    #[doc(hidden)]
    pub struct CapturePgIo {
        socket: SocketState,
        decode: Arc<CaptureDecodeBudget>,
        header: [u8; 5],
        header_read: usize,
        header_sent: usize,
        body_remaining: usize,
        max_frame: usize,
        credit: bool,
        failed: bool,
    }
    impl Unpin for CapturePgIo {}
    impl CapturePgIo {
        pub fn prepare(config: &PgConfig, decode: Arc<CaptureDecodeBudget>)
            -> Result<Self, CaptureSqlFailure>
        {
            if !cfg!(target_os = "macos") { return Err(CaptureSqlFailure::Bounds); }
            let endpoint = endpoint(config)?;
            let options = TcpOptions::from_original(config);
            // This initial charge precedes both the lazy future Box and Framed::new.
            let m = decode.reserve_wire_credit()?;
            let frame = m.checked_div(4).and_then(|n| n.checked_sub(1))
                .filter(|n| *n >= 5).ok_or(CaptureSqlFailure::Bounds)?;
            let max_frame = usize::try_from(frame).map_err(|_| CaptureSqlFailure::Bounds)?;
            let original = original_socket(endpoint, config.get_connect_timeout().copied(), options);
            Ok(Self {
                socket: SocketState::Connecting(Box::pin(original)),
                decode, header: [0; 5], header_read: 0, header_sent: 0,
                body_remaining: 0, max_frame, credit: false, failed: false,
            })
        }

        // New pure DATA bridge, pending the Root-approved R475 supplement.
        // The same actual lazy factory is instantiated but never polled or boxed.
        pub fn checked_metadata_bytes(originals: u64) -> Result<u64, CaptureSqlFailure> {
            let original = original_socket(
                Endpoint::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
                None, TcpOptions { keepalive: false, idle: Duration::ZERO,
                    interval: None, retries: None },
            );
            let layout = std::alloc::Layout::for_value(&original);
            let unit = std::mem::size_of::<Self>().checked_add(layout.size())
                .ok_or(CaptureSqlFailure::Bounds)?;
            u64::try_from(unit).map_err(|_| CaptureSqlFailure::Bounds)?
                .checked_mul(originals).ok_or(CaptureSqlFailure::Bounds)
        }
        fn guard(&mut self) -> io::Result<()> {
            if self.failed { return Err(io::Error::from(io::ErrorKind::InvalidData)); }
            self.decode.reserve_allocations(&[]).map_err(|failure| {
                self.failed = true;
                io::Error::from(if failure == CaptureSqlFailure::Clock {
                    io::ErrorKind::TimedOut
                } else { io::ErrorKind::InvalidData })
            })
        }
        fn ensure_credit(&mut self) -> io::Result<()> {
            if !self.credit {
                self.decode.reserve_wire_credit().map_err(|failure| {
                    self.failed = true;
                    io::Error::from(if failure == CaptureSqlFailure::Clock {
                        io::ErrorKind::TimedOut
                    } else { io::ErrorKind::InvalidData })
                })?;
                self.credit = true;
            }
            Ok(())
        }
    }
    impl AsyncRead for CapturePgIo {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, dst: &mut ReadBuf<'_>)
            -> Poll<io::Result<()>>
        {
            let this = self.get_mut();
            if dst.remaining() == 0 { return Poll::Ready(Ok(())); }
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            let connecting = poll_connect(&mut this.socket, cx);
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            match connecting {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            if this.header_sent == 5 && this.body_remaining == 0 {
                this.header_read = 0;
                this.header_sent = 0;
            }
            while this.header_read < 5 {
                let (result, n) = {
                    let mut header = ReadBuf::new(&mut this.header[this.header_read..]);
                    let result = read_socket(&mut this.socket, cx, &mut header);
                    (result, header.filled().len())
                };
                this.header_read += n;
                if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
                match result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if n == 0 => {
                        return Poll::Ready(if this.header_read == 0 { Ok(()) }
                            else { Err(io::Error::from(io::ErrorKind::UnexpectedEof)) });
                    }
                    Poll::Ready(Ok(())) => {}
                }
            }
            if this.header_sent == 0 {
                let length = i32::from_be_bytes(this.header[1..5].try_into().expect("fixed header"));
                let total = usize::try_from(length).ok().and_then(|n| n.checked_add(1));
                match total {
                    Some(total) if length >= 4 && total <= this.max_frame => {
                        this.body_remaining = total - 5;
                    }
                    _ => {
                        this.failed = true;
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidData)));
                    }
                }
            }
            if let Err(error) = this.ensure_credit() { return Poll::Ready(Err(error)); }
            if this.header_sent < 5 {
                let n = (5 - this.header_sent).min(dst.remaining());
                dst.put_slice(&this.header[this.header_sent..this.header_sent + n]);
                this.header_sent += n;
                this.credit = false;
                if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
                return Poll::Ready(Ok(()));
            }
            let len = this.body_remaining.min(dst.remaining());
            let (result, n) = {
                let mut body = ReadBuf::new(dst.initialize_unfilled_to(len));
                let result = read_socket(&mut this.socket, cx, &mut body);
                (result, body.filled().len())
            };
            this.body_remaining -= n;
            if n != 0 { this.credit = false; }
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            match result {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if n == 0 => {
                    this.failed = true;
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                }
                Poll::Ready(Ok(())) => { dst.advance(n); Poll::Ready(Ok(())) }
            }
        }
    }
    impl AsyncWrite for CapturePgIo {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, src: &[u8])
            -> Poll<io::Result<usize>>
        {
            let this = self.get_mut();
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            let connecting = poll_connect(&mut this.socket, cx);
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            match connecting {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            let result = match &mut this.socket {
                SocketState::Connected(OriginalSocket::Tcp(stream)) => Pin::new(stream).poll_write(cx, src),
                #[cfg(unix)]
                SocketState::Connected(OriginalSocket::Unix(stream)) => Pin::new(stream).poll_write(cx, src),
                _ => Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected))),
            };
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            result
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            let connecting = poll_connect(&mut this.socket, cx);
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            match connecting {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            let result = match &mut this.socket {
                SocketState::Connected(OriginalSocket::Tcp(stream)) => Pin::new(stream).poll_flush(cx),
                #[cfg(unix)]
                SocketState::Connected(OriginalSocket::Unix(stream)) => Pin::new(stream).poll_flush(cx),
                _ => Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected))),
            };
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            result
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            let connecting = poll_connect(&mut this.socket, cx);
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            match connecting {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            let result = match &mut this.socket {
                SocketState::Connected(OriginalSocket::Tcp(stream)) => Pin::new(stream).poll_shutdown(cx),
                #[cfg(unix)]
                SocketState::Connected(OriginalSocket::Unix(stream)) => Pin::new(stream).poll_shutdown(cx),
                _ => Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected))),
            };
            if let Err(error) = this.guard() { return Poll::Ready(Err(error)); }
            result
        }
    }
}
#[cfg(feature = "desktop-local-vault")]
pub use capture_io::CapturePgIo;

// The armed Local graph retains original tasks independently of the stock lifecycle proxy.
// This module does not authorize capture, construct a source, or interpret a transaction result.
#[cfg(feature = "desktop-local-vault")]
mod retained {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::task::Waker;
    use tokio::task::{Id, JoinError, JoinSet};

    pub struct DesktopPoolJoinBounds {
        live: usize,
        unjoined: usize,
        pending: usize,
        proxies: usize,
        metadata: usize,
    }
    impl DesktopPoolJoinBounds {
        // This configuration-only constructor becomes public only after the ABI registration.
        /// Validate all five explicit positive retention limits without starting I/O.
        pub fn checked(
            live: u64,
            unjoined: u64,
            pending: u64,
            proxies: u64,
            metadata: u64,
        ) -> Result<Self, PoolError> {
            let convert = |n: u64| -> Result<usize, PoolError> {
                if n == 0 {
                    return Err(PoolError::CreationLimit);
                }
                usize::try_from(n).map_err(|_| PoolError::CreationLimit)
            };
            let value = Self {
                live: convert(live)?,
                unjoined: convert(unjoined)?,
                pending: convert(pending)?,
                proxies: convert(proxies)?,
                metadata: convert(metadata)?,
            };
            if value.metadata < std::mem::size_of::<QueueEntry>() {
                return Err(PoolError::CreationLimit);
            }
            Ok(value)
        }
    }

    // One aggregate reservation is computed before any retained heap allocation. It remains
    // charged for this custody lifetime, including empty-but-retained backing capacities.
    #[derive(Clone, Copy)]
    struct MetadataReservation {
        prepaid: usize,
        originals: usize,
        queue: usize,
        map_upper: usize,
        queue_upper: usize,
        retirement_upper: usize,
        checkouts: usize,
    }
    fn metadata_add(values: &[usize]) -> Result<usize, PoolError> {
        values.iter().try_fold(0usize, |total, value| {
            total.checked_add(*value).ok_or(PoolError::CreationLimit)
        })
    }
    fn metadata_mul(a: usize, b: usize) -> Result<usize, PoolError> {
        a.checked_mul(b).ok_or(PoolError::CreationLimit)
    }
    fn capacity_ceiling(n: usize) -> Result<usize, PoolError> {
        n.checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(PoolError::CreationLimit)
    }
    fn table_charge<K, V>(upper: usize) -> Result<usize, PoolError> {
        // The charged envelope includes spare hash buckets, control bytes and alignment.
        metadata_add(&[
            metadata_mul(
                metadata_mul(upper, 2)?,
                metadata_add(&[std::mem::size_of::<(K, V)>(), 1])?,
            )?,
            64,
        ])
    }
    fn reserved_table<K: Eq + std::hash::Hash, V>(
        logical: usize,
        upper: usize,
    ) -> Result<HashMap<K, V>, PoolError> {
        let mut table = HashMap::new();
        table
            .try_reserve(logical)
            .map_err(|_| PoolError::CreationLimit)?;
        if table.capacity() > upper {
            return Err(PoolError::CreationLimit);
        }
        Ok(table)
    }
    impl MetadataReservation {
        fn checked(bounds: &DesktopPoolJoinBounds) -> Result<Self, PoolError> {
            let originals = bounds.live.min(bounds.unjoined);
            let queue = originals
                .checked_add(bounds.proxies)
                .ok_or(PoolError::CreationLimit)?;
            let map_upper = capacity_ceiling(originals)?;
            let queue_upper = capacity_ceiling(queue)?;
            let retirement_upper = capacity_ceiling(originals)?;
            let fixed_pool = crate::db::desktop_local::APPLICATION_POOL_SIZE
                .checked_add(1)
                .ok_or(PoolError::CreationLimit)?;
            // Driver futures are separately sized. The locked Tokio task/JoinSet/channel/watch
            // administration is conservatively prepaid at 8KiB per original and 1KiB per proxy;
            // PG protocol buffers/password payloads remain in their separate actual budgets.
            let original_charge = metadata_add(&[
                std::mem::size_of::<DriverOwner>(),
                std::mem::size_of::<OriginalDriver>(),
                std::mem::size_of::<OriginalDriverJoinFact>(),
                std::mem::size_of::<SessionPermitCustody>(),
                std::mem::size_of::<DriverRetention>(),
                8192,
                std::mem::size_of_val(&retained_original_connect(None)),
                usize::try_from(CapturePgIo::checked_metadata_bytes(1)
                    .map_err(|_| PoolError::CreationLimit)?)
                    .map_err(|_| PoolError::CreationLimit)?,
                std::mem::size_of::<tokio_postgres::Connection<
                    CapturePgIo, tokio_postgres::tls::NoTlsStream>>(),
            ])?;
            let proxy_charge = metadata_add(&[
                std::mem::size_of::<ProxyFuture>(),
                std::mem::size_of::<ProxyMetadata>(),
                std::mem::size_of::<JoinHandle<()>>(),
                1024,
            ])?;
            let checkout_charge = metadata_add(&[
                std::mem::size_of::<CheckoutTrace>(),
                std::mem::size_of::<SessionPermitCustody>(),
                metadata_mul(std::mem::size_of::<Arc<DriverOwner>>(), 4)?,
                1024,
            ])?;
            let prepaid = metadata_add(&[
                std::mem::size_of::<CustodyCore>(),
                std::mem::size_of::<RetirementGate>(),
                std::mem::size_of::<Counters>(),
                metadata_mul(2, std::mem::size_of::<OwnerSupervisor>())?,
                metadata_mul(2, std::mem::size_of::<OriginalTasks>())?,
                4096,
                metadata_mul(originals, original_charge)?,
                metadata_mul(
                    queue
                        .checked_add(fixed_pool)
                        .ok_or(PoolError::CreationLimit)?,
                    proxy_charge,
                )?,
                metadata_mul(bounds.pending, checkout_charge)?,
                metadata_mul(2, table_charge::<usize, Arc<DriverOwner>>(map_upper)?)?,
                metadata_mul(2, table_charge::<ObjectId, Arc<DriverOwner>>(map_upper)?)?,
                metadata_mul(2, table_charge::<Id, Arc<DriverOwner>>(map_upper)?)?,
                table_charge::<DriverKey, QueueEntry>(queue_upper)?,
                metadata_mul(retirement_upper, std::mem::size_of::<Arc<DriverOwner>>())?,
            ])?;
            if prepaid > bounds.metadata {
                return Err(PoolError::CreationLimit);
            }
            Ok(Self {
                prepaid,
                originals,
                queue,
                map_upper,
                queue_upper,
                retirement_upper,
                checkouts: bounds.pending,
            })
        }
        fn check(&self, bounds: &DesktopPoolJoinBounds) -> Result<(), PoolError> {
            if self.prepaid != Self::checked(bounds)?.prepaid {
                return Err(PoolError::CreationLimit);
            }
            Ok(())
        }
    }
    pub(super) struct CheckoutMetadataTicket {
        counts: Arc<Counters>,
    }
    impl Drop for CheckoutMetadataTicket {
        fn drop(&mut self) {
            Counters::decrement(&self.counts.checkouts, &self.counts.fault);
        }
    }
    struct DriverMetadataTicket {
        counts: Arc<Counters>,
    }
    impl Drop for DriverMetadataTicket {
        fn drop(&mut self) {
            Counters::decrement(&self.counts.owner_allocations, &self.counts.fault);
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum RetainedPoolKind {
        Admin,
        Application,
    }
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    struct DriverKey {
        pool: RetainedPoolKind,
        sequence: usize,
    }
    #[derive(Clone, Copy)]
    struct CopyDestructionFact {
        pool: RetainedPoolKind,
        sequence: usize,
        kind: ConnectionDestruction,
    }

    // No I/O owner or strong task waker is reachable through the proxy's weak mailbox view.
    struct RetirementWake {
        waker: Mutex<Option<Waker>>,
    }
    impl RetirementWake {
        fn register(&self, waker: &Waker) {
            if let Ok(mut slot) = self.waker.lock() {
                *slot = Some(waker.clone());
            }
        }
        fn wake(&self) {
            let waker = self
                .waker
                .lock()
                .ok()
                .and_then(|slot| slot.as_ref().cloned());
            if let Some(waker) = waker {
                waker.wake();
            }
        }
        fn clear(&self) {
            if let Ok(mut slot) = self.waker.lock() {
                slot.take();
            }
        }
    }
    struct ProxyMetadata {
        destroyed: AtomicBool,
    }
    struct QueueEntry {
        requested: bool,
        joined: bool,
        proxy: Arc<ProxyMetadata>,
        wake: Weak<RetirementWake>,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Phase {
        Running,
        Frozen,
    }
    pub(super) struct GateState {
        phase: Phase,
        entries: HashMap<DriverKey, QueueEntry>,
    }
    struct Counters {
        originals: AtomicUsize,
        pending: AtomicUsize,
        live_proxies: AtomicUsize,
        joined: AtomicU64,
        missing_destruction: AtomicU64,
        owner_allocations: AtomicUsize,
        checkouts: AtomicUsize,
        fault: AtomicBool,
    }
    impl Counters {
        fn new() -> Self {
            Self {
                originals: AtomicUsize::new(0),
                pending: AtomicUsize::new(0),
                live_proxies: AtomicUsize::new(0),
                joined: AtomicU64::new(0),
                missing_destruction: AtomicU64::new(0),
                owner_allocations: AtomicUsize::new(0),
                checkouts: AtomicUsize::new(0),
                fault: AtomicBool::new(false),
            }
        }
        fn increment(counter: &AtomicU64, fault: &AtomicBool) {
            if counter
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                .is_err()
            {
                fault.store(true, Ordering::Release);
            }
        }
        fn decrement(counter: &AtomicUsize, fault: &AtomicBool) {
            if counter
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                .is_err()
            {
                fault.store(true, Ordering::Release);
            }
        }
    }
    struct RetirementGate {
        state: Mutex<GateState>,
        bounds: DesktopPoolJoinBounds,
        metadata: MetadataReservation,
        counts: Arc<Counters>,
        original_decode: Arc<crate::db::capture_materials::CaptureDecodeBudget>,
    }
    struct QueueOnlyRetirement {
        gate: Weak<RetirementGate>,
        key: DriverKey,
    }
    impl QueueOnlyRetirement {
        fn enqueue(&self) {
            let Some(gate) = self.gate.upgrade() else {
                return;
            };
            let wake = match gate.state.lock() {
                Ok(mut state) => match state.entries.get_mut(&self.key) {
                    Some(entry) => {
                        entry.requested = true;
                        entry.wake.clone()
                    }
                    None => {
                        gate.counts.fault.store(true, Ordering::Release);
                        return;
                    }
                },
                Err(_) => {
                    gate.counts.fault.store(true, Ordering::Release);
                    return;
                }
            };
            // Only schedule the existing owner. This path cannot issue an abort or any I/O.
            if let Some(wake) = wake.upgrade() {
                wake.wake();
            }
        }
    }
    struct ProxyDropAck {
        metadata: Arc<ProxyMetadata>,
        counts: Arc<Counters>,
    }
    impl ProxyDropAck {
        fn released(self) {
            if self.metadata.destroyed.swap(true, Ordering::AcqRel) {
                self.counts.fault.store(true, Ordering::Release);
            } else {
                Counters::decrement(&self.counts.live_proxies, &self.counts.fault);
            }
        }
    }
    struct PassiveProxyView {
        destruction: Option<oneshot::Receiver<CopyDestructionFact>>,
        retirement: Option<QueueOnlyRetirement>,
        drop_ack: Option<ProxyDropAck>,
    }
    struct ProxyFuture {
        view: PassiveProxyView,
        observed: Option<CopyDestructionFact>,
    }
    impl Future for ProxyFuture {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let this = self.get_mut();
            let Some(receiver) = this.view.destruction.as_mut() else {
                return Poll::Ready(());
            };
            match Pin::new(receiver).poll(cx) {
                Poll::Ready(Ok(fact)) => {
                    this.observed = Some(fact);
                    Poll::Ready(())
                }
                Poll::Ready(Err(_)) => Poll::Ready(()),
                Poll::Pending => Poll::Pending,
            }
        }
    }
    impl Drop for ProxyFuture {
        fn drop(&mut self) {
            let receiver = self.view.destruction.take();
            let queue = self.view.retirement.take();
            if self.observed.is_none()
                && let Some(queue) = queue.as_ref()
            {
                queue.enqueue();
            }
            drop(receiver);
            drop(queue);
            // Last non-Copy state is now gone. The ticket itself has no automatic success Drop.
            if let Some(ack) = self.view.drop_ack.take() {
                ack.released();
            }
        }
    }

    pub(super) struct DriverRetention {
        gate: Arc<RetirementGate>,
        key: DriverKey,
        wake: Arc<RetirementWake>,
        pending: AtomicBool,
        destruction: Mutex<Option<oneshot::Sender<CopyDestructionFact>>>,
        // Last non-Copy field: actual owner-header custody, not cancellation, releases the slot.
        metadata_ticket: DriverMetadataTicket,
    }
    impl DriverRetention {
        fn queue(&self) {
            QueueOnlyRetirement {
                gate: Arc::downgrade(&self.gate),
                key: self.key,
            }
            .enqueue();
        }
        fn leave_connecting(&self) {
            if self.pending.swap(false, Ordering::AcqRel) {
                Counters::decrement(&self.gate.counts.pending, &self.gate.counts.fault);
            }
        }
        pub(super) fn after_drop(&self, kind: ConnectionDestruction) {
            self.leave_connecting();
            self.wake.clear();
            let sender = self
                .destruction
                .lock()
                .ok()
                .and_then(|mut sender| sender.take());
            if let Some(sender) = sender {
                let _receiver = sender.send(CopyDestructionFact {
                    pool: self.key.pool,
                    sequence: self.key.sequence,
                    kind,
                });
            }
        }
        pub(super) fn retirement_requested(&self) {
            self.queue();
        }
        pub(super) fn driving_started(&self) {
            self.leave_connecting();
        }
        pub(super) fn wake(&self) {
            self.wake.wake();
        }
        pub(super) fn poll_retirement(&self, owner: &DriverOwner, cx: &Context<'_>) -> bool {
            self.wake.register(cx.waker());
            let Ok(state) = self.gate.state.lock() else {
                self.gate.counts.fault.store(true, Ordering::Release);
                return false;
            };
            if state.phase == Phase::Running
                && state
                    .entries
                    .get(&self.key)
                    .is_some_and(|entry| entry.requested)
            {
                // The actual original I/O owner performs its normal retirement under the gate.
                owner.abort_original();
                return true;
            }
            false
        }
    }

    struct OriginalTasks {
        set: JoinSet<()>,
        owners: HashMap<Id, Arc<DriverOwner>>,
    }
    impl OriginalTasks {
        fn new(metadata: &MetadataReservation) -> Result<Self, PoolError> {
            Ok(Self {
                set: JoinSet::new(),
                owners: reserved_table(metadata.originals, metadata.map_upper)?,
            })
        }
        fn record_join(
            &mut self,
            result: Result<(Id, ()), JoinError>,
            kind: RetainedPoolKind,
            state: &mut GateState,
            counts: &Counters,
        ) -> Result<OriginalDriverJoinFact, PoolError> {
            let (id, outcome) = match result {
                Ok((id, ())) => (id, OriginalDriverJoinOutcome::Returned),
                Err(error) => {
                    let outcome = if error.is_cancelled() {
                        OriginalDriverJoinOutcome::Cancelled
                    } else {
                        OriginalDriverJoinOutcome::Panicked
                    };
                    (error.id(), outcome)
                }
            };
            let owner = self
                .owners
                .remove(&id)
                .ok_or(PoolError::OwnershipUnavailable)?;
            let destruction = owner.snapshot().destruction;
            if outcome == OriginalDriverJoinOutcome::Panicked {
                counts.fault.store(true, Ordering::Release);
            }
            if destruction.is_none() {
                Counters::increment(&counts.missing_destruction, &counts.fault);
            }
            Counters::increment(&counts.joined, &counts.fault);
            Counters::decrement(&counts.originals, &counts.fault);
            if let Some(entry) = state.entries.get_mut(&DriverKey {
                pool: kind,
                sequence: owner.sequence,
            }) {
                entry.joined = true;
            } else {
                counts.fault.store(true, Ordering::Release);
            }
            Ok(OriginalDriverJoinFact {
                pool: kind,
                sequence: owner.sequence,
                id,
                outcome,
                destruction,
            })
        }
    }

    pub(super) struct SupervisorRetention {
        gate: Arc<RetirementGate>,
        kind: RetainedPoolKind,
        tasks: Mutex<Option<OriginalTasks>>,
    }
    impl SupervisorRetention {
        pub(super) fn reserve_checkout(&self) -> Result<CheckoutMetadataTicket, PoolError> {
            let state = self
                .gate
                .state
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            self.gate.metadata.check(&self.gate.bounds)?;
            if state.phase != Phase::Running || self.gate.counts.fault.load(Ordering::Acquire) {
                return Err(PoolError::Closed);
            }
            if self.gate.counts.checkouts.load(Ordering::Acquire) >= self.gate.metadata.checkouts {
                return Err(PoolError::CreationLimit);
            }
            self.gate.counts.checkouts.fetch_add(1, Ordering::AcqRel);
            Ok(CheckoutMetadataTicket {
                counts: Arc::clone(&self.gate.counts),
            })
        }
        pub(super) fn lock_running(
            &self,
        ) -> Result<std::sync::MutexGuard<'_, GateState>, PoolError> {
            let state = self
                .gate
                .state
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            if state.phase != Phase::Running {
                return Err(PoolError::Closed);
            }
            if self.gate.counts.fault.load(Ordering::Acquire) {
                return Err(PoolError::OwnershipUnavailable);
            }
            Ok(state)
        }
        pub(super) fn ensure_running(&self) -> Result<(), PoolError> {
            let state = self
                .gate
                .state
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            if state.phase != Phase::Running {
                return Err(PoolError::Closed);
            }
            if self.gate.counts.fault.load(Ordering::Acquire) {
                return Err(PoolError::OwnershipUnavailable);
            }
            Ok(())
        }
        pub(super) fn connect(
            &self,
            supervisor: Arc<OwnerSupervisor>,
            config: &PgConfig,
            trace: Arc<CheckoutTrace>,
        ) -> ConnectResultFuture<'static> {
            let attempt = || -> Result<(PgClientReady, JoinHandle<()>), PoolError> {
                let mut state = self
                    .gate
                    .state
                    .lock()
                    .map_err(|_| PoolError::OwnershipUnavailable)?;
                if state.phase != Phase::Running {
                    return Err(PoolError::Closed);
                }
                let mut stored = self
                    .tasks
                    .lock()
                    .map_err(|_| PoolError::OwnershipUnavailable)?;
                let tasks = stored.as_mut().ok_or(PoolError::Closed)?;
                while let Some(result) = tasks.set.try_join_next_with_id() {
                    tasks.record_join(result, self.kind, &mut state, &self.gate.counts)?;
                }
                state.entries.retain(|_, entry| {
                    !(entry.joined && entry.proxy.destroyed.load(Ordering::Acquire))
                });
                let bounds = &self.gate.bounds;
                let counts = &self.gate.counts;
                self.gate.metadata.check(bounds)?;
                // All original tables were pre-reserved and retain their backing charge.
                if state.entries.len() >= self.gate.metadata.queue
                    || state.entries.len() >= state.entries.capacity()
                    || tasks.owners.len() >= self.gate.metadata.originals
                    || tasks.owners.len() >= tasks.owners.capacity()
                {
                    return Err(PoolError::CreationLimit);
                }
                if counts.fault.load(Ordering::Acquire)
                    || counts.originals.load(Ordering::Acquire) >= bounds.live
                    || counts.originals.load(Ordering::Acquire) >= bounds.unjoined
                    || counts.pending.load(Ordering::Acquire) >= bounds.pending
                    || counts.live_proxies.load(Ordering::Acquire) >= bounds.proxies
                    || counts.owner_allocations.load(Ordering::Acquire)
                        >= self.gate.metadata.originals
                {
                    return Err(PoolError::CreationLimit);
                }
                let sequence = supervisor.reserve_creation()?;
                let key = DriverKey {
                    pool: self.kind,
                    sequence,
                };
                let wake = Arc::new(RetirementWake {
                    waker: Mutex::new(None),
                });
                let proxy = Arc::new(ProxyMetadata {
                    destroyed: AtomicBool::new(false),
                });
                let (destruction, destroyed) = oneshot::channel();
                let retention = DriverRetention {
                    gate: Arc::clone(&self.gate),
                    key,
                    wake: Arc::clone(&wake),
                    pending: AtomicBool::new(true),
                    destruction: Mutex::new(Some(destruction)),
                    metadata_ticket: DriverMetadataTicket {
                        counts: Arc::clone(counts),
                    },
                };
                counts.owner_allocations.fetch_add(1, Ordering::AcqRel);
                counts.pending.fetch_add(1, Ordering::AcqRel);
                let owner = DriverOwner::new_retained(sequence, &supervisor, retention);
                let (ready, receiver) = oneshot::channel();
                let configuration = config.clone();
                let original_io = CapturePgIo::prepare(
                    &configuration, Arc::clone(&self.gate.original_decode),
                ).map_err(|_| PoolError::CreationLimit)?;
                let connecting: ConnectingFuture = Box::pin(retained_original_connect(
                    Some((configuration, original_io, Arc::clone(&owner))),
                ));
                let driver = OriginalDriver {
                    resource: OriginalResource::Connecting(connecting),
                    ready: Some(ready),
                    owner: Arc::clone(&owner),
                };
                if let Err(error) = supervisor
                    .register(Arc::clone(&owner))
                    .and_then(|()| trace.record(Arc::clone(&owner)))
                {
                    drop(stored);
                    drop(state);
                    drop(driver);
                    return Err(error);
                }
                state.entries.insert(
                    key,
                    QueueEntry {
                        requested: false,
                        joined: false,
                        proxy: Arc::clone(&proxy),
                        wake: Arc::downgrade(&wake),
                    },
                );
                counts.originals.fetch_add(1, Ordering::AcqRel);
                let abort = tasks.set.spawn(driver);
                let id = abort.id();
                owner.install_abort(abort);
                tasks.owners.insert(id, owner);
                counts.live_proxies.fetch_add(1, Ordering::AcqRel);
                let proxy = ProxyFuture {
                    view: PassiveProxyView {
                        destruction: Some(destroyed),
                        retirement: Some(QueueOnlyRetirement {
                            gate: Arc::downgrade(&self.gate),
                            key,
                        }),
                        drop_ack: Some(ProxyDropAck {
                            metadata: proxy,
                            counts: Arc::clone(counts),
                        }),
                    },
                    observed: None,
                };
                let handle = tokio::spawn(proxy);
                Ok((receiver, handle))
            };
            match attempt() {
                Ok((receiver, proxy)) => Box::pin(async move {
                    let mut proxy = ProxyCreationCancellation { task: Some(proxy) };
                    match receiver.await {
                        Ok(Ok(client)) => {
                            Ok((client, proxy.task.take().expect("single proxy transfer")))
                        }
                        Ok(Err(error)) => Err(error),
                        Err(_) => {
                            supervisor.fail(PoolError::OwnershipUnavailable);
                            pending().await
                        }
                    }
                }),
                Err(error) => {
                    supervisor.fail(error);
                    Box::pin(pending())
                }
            }
        }
    }
    // The real factory is also instantiated with None for Layout only, never polled.
    // The original raw connect future is scoped inline so it is actually dropped before
    // connecting_destroyed; no additional erased inner Box needs a guessed size.
    fn retained_original_connect(
        original: Option<(PgConfig, CapturePgIo, Arc<DriverOwner>)>,
    ) -> impl Future<Output = Result<(PgClient, DrivingFuture), PgError>> + Send {
        async move {
            let (configuration, original_io, connecting_owner) =
                original.expect("only admitted original inputs are polled");
            let result = {
                let original = configuration.connect_raw(original_io, NoTls);
                tokio::pin!(original);
                connecting_owner.connecting_started();
                original.as_mut().await
            };
            connecting_owner.connecting_destroyed();
            result.map(|(client, connection)| (client, Box::pin(connection) as DrivingFuture))
        }
    }
    type PgClientReady = oneshot::Receiver<Result<PgClient, PgError>>;
    struct ProxyCreationCancellation {
        task: Option<JoinHandle<()>>,
    }
    impl Drop for ProxyCreationCancellation {
        fn drop(&mut self) {
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }

    struct CustodyCore {
        gate: Arc<RetirementGate>,
        admin: Arc<OwnerSupervisor>,
        application: Arc<OwnerSupervisor>,
        stocks: Mutex<[Option<Pool>; 2]>,
        freeze_retirements: Mutex<Option<VecDeque<Arc<DriverOwner>>>>,
    }
    pub struct DesktopLocalDriverCustody {
        core: Arc<CustodyCore>,
    }
    impl DesktopLocalDriverCustody {
        pub fn prepare(
            bounds: DesktopPoolJoinBounds,
            original_decode: Arc<crate::db::capture_materials::CaptureDecodeBudget>,
        ) -> Result<Self, PoolError> {
            // Admission covers both fixed stocks. It never lowers their original capacities.
            let fixed = crate::db::desktop_local::APPLICATION_POOL_SIZE
                .checked_add(1)
                .ok_or(PoolError::CreationLimit)?;
            if bounds.live < fixed
                || bounds.unjoined < fixed
                || bounds.proxies < fixed
                || bounds.pending < crate::db::desktop_local::APPLICATION_POOL_SIZE
            {
                return Err(PoolError::CreationLimit);
            }
            let metadata = MetadataReservation::checked(&bounds)?;
            let counts = Arc::new(Counters::new());
            let entries = reserved_table(metadata.queue, metadata.queue_upper)?;
            let mut retirements = VecDeque::new();
            retirements
                .try_reserve_exact(metadata.originals)
                .map_err(|_| PoolError::CreationLimit)?;
            if retirements.capacity() > metadata.retirement_upper {
                return Err(PoolError::CreationLimit);
            }
            let gate = Arc::new(RetirementGate {
                state: Mutex::new(GateState {
                    phase: Phase::Running,
                    entries,
                }),
                bounds,
                metadata,
                counts,
                original_decode,
            });
            let supervisor = |kind| -> Result<Arc<OwnerSupervisor>, PoolError> {
                let registry = Registry {
                    pending: reserved_table(metadata.originals, metadata.map_upper)?,
                    bound: reserved_table(metadata.originals, metadata.map_upper)?,
                    destroyed_connecting_futures: 0,
                    destroyed_connections: 0,
                    destroyed_before_start: 0,
                };
                Ok(OwnerSupervisor::new_retained(
                    SupervisorRetention {
                        gate: Arc::clone(&gate),
                        kind,
                        tasks: Mutex::new(Some(OriginalTasks::new(&metadata)?)),
                    },
                    registry,
                ))
            };
            Ok(Self {
                core: Arc::new(CustodyCore {
                    admin: supervisor(RetainedPoolKind::Admin)?,
                    application: supervisor(RetainedPoolKind::Application)?,
                    gate,
                    stocks: Mutex::new([None, None]),
                    freeze_retirements: Mutex::new(Some(retirements)),
                }),
            })
        }
        pub(in crate::db) fn shared(&self) -> Self {
            Self {
                core: Arc::clone(&self.core),
            }
        }
        pub(in crate::db) fn supervisor(&self, application: bool) -> Arc<OwnerSupervisor> {
            Arc::clone(if application {
                &self.core.application
            } else {
                &self.core.admin
            })
        }
        pub(in crate::db) fn register_stock(
            &self,
            application: bool,
            stock: Pool,
        ) -> Result<(), PoolError> {
            let state = self
                .core
                .gate
                .state
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            if state.phase != Phase::Running {
                return Err(PoolError::Closed);
            }
            let mut stocks = self
                .core
                .stocks
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            let slot = &mut stocks[usize::from(application)];
            if slot.is_some() {
                return Err(PoolError::IdentityCollision);
            }
            *slot = Some(stock);
            Ok(())
        }
        pub fn freeze(&mut self) -> Result<DesktopCaptureDrivers, PoolError> {
            let gate = &self.core.gate;
            let mut state = gate
                .state
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            if state.phase != Phase::Running {
                return Err(PoolError::Closed);
            }
            if gate.counts.fault.load(Ordering::Acquire) {
                return Err(PoolError::OwnershipUnavailable);
            }
            let admin_slot = self
                .core
                .admin
                .retention
                .as_ref()
                .ok_or(PoolError::OwnershipUnavailable)?;
            let app_slot = self
                .core
                .application
                .retention
                .as_ref()
                .ok_or(PoolError::OwnershipUnavailable)?;
            let mut admin = admin_slot
                .tasks
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            let mut application = app_slot
                .tasks
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            let stock_guard = self
                .core
                .stocks
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            if admin.is_none() || application.is_none() {
                return Err(PoolError::OwnershipUnavailable);
            }
            // Startup may fail before one stock pool is ever published. Only an actually empty
            // original set/map/mailbox establishes that uncreated slot; never manufacture a set.
            for (index, kind, tasks) in [
                (
                    0,
                    RetainedPoolKind::Admin,
                    admin.as_ref().expect("checked original admin set"),
                ),
                (
                    1,
                    RetainedPoolKind::Application,
                    application
                        .as_ref()
                        .expect("checked original application set"),
                ),
            ] {
                if stock_guard[index].is_none()
                    && (!tasks.set.is_empty()
                        || !tasks.owners.is_empty()
                        || state.entries.keys().any(|key| key.pool == kind))
                {
                    return Err(PoolError::OwnershipUnavailable);
                }
            }
            gate.metadata.check(&gate.bounds)?;
            let mut scratch = self
                .core
                .freeze_retirements
                .lock()
                .map_err(|_| PoolError::OwnershipUnavailable)?;
            let owner_count = admin
                .as_ref()
                .expect("checked admin set")
                .owners
                .len()
                .checked_add(application.as_ref().expect("checked app set").owners.len())
                .ok_or(PoolError::CreationLimit)?;
            let queue = scratch.as_mut().ok_or(PoolError::OwnershipUnavailable)?;
            if !queue.is_empty()
                || owner_count > gate.metadata.originals
                || owner_count > queue.capacity()
                || queue.capacity() > gate.metadata.retirement_upper
            {
                return Err(PoolError::CreationLimit);
            }
            for owner in admin
                .as_ref()
                .into_iter()
                .chain(application.as_ref())
                .flat_map(|tasks| tasks.owners.values())
            {
                queue.push_back(Arc::clone(owner)); // Pre-reserved; no allocation under the freeze gate.
            }
            let retirements = scratch.take().expect("checked original freeze staging");
            drop(scratch);
            state.phase = Phase::Frozen;
            let drivers = DesktopCaptureDrivers {
                admin: admin.take().expect("checked original admin set"),
                application: application
                    .take()
                    .expect("checked original application set"),
                retirements,
                gate: Arc::clone(gate),
                joined_before: gate.counts.joined.load(Ordering::Acquire),
            };
            let stocks: [Option<Pool>; 2] = std::array::from_fn(|index| stock_guard[index].clone());
            drop(stock_guard);
            drop(application);
            drop(admin);
            drop(state);
            for stock in stocks.into_iter().flatten() {
                stock.close();
            }
            Ok(drivers)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    /// Actual terminal result of one retained original task, independent of stock proxy joins.
    pub enum OriginalDriverJoinOutcome {
        /// The original task returned normally.
        Returned,
        /// The original task's real JoinError reports cancellation.
        Cancelled,
        /// The original task's real JoinError reports panic.
        Panicked,
    }
    pub struct OriginalDriverJoinFact {
        pool: RetainedPoolKind,
        sequence: usize,
        id: Id,
        outcome: OriginalDriverJoinOutcome,
        destruction: Option<ConnectionDestruction>,
    }
    impl OriginalDriverJoinFact {
        /// Fixed retained pool identity.
        pub fn pool_name(&self) -> &'static str {
            match self.pool {
                RetainedPoolKind::Admin => "admin",
                RetainedPoolKind::Application => "application",
            }
        }
        /// Original supervisor sequence, never a stock/proxy sequence.
        pub fn sequence(&self) -> usize {
            self.sequence
        }
        /// Tokio ID recovered from the actual original join.
        pub fn task_id(&self) -> tokio::task::Id {
            self.id
        }
        /// Actual original join outcome.
        pub fn outcome(&self) -> OriginalDriverJoinOutcome {
            self.outcome
        }
        /// Destruction observation recorded only after the original connection is dropped.
        pub fn destruction(&self) -> Option<ConnectionDestruction> {
            self.destruction
        }
    }

    pub struct OriginalDriverRetirement {
        owner: Arc<DriverOwner>,
    }
    impl OriginalDriverRetirement {
        pub fn request(self) {
            // Only the original closing owner calls this after its original C-clock check.
            self.owner
                .state
                .send_modify(|snapshot| snapshot.retirement_requested = true);
            self.owner.abort_original();
        }
    }
    pub struct DesktopCaptureDrivers {
        admin: OriginalTasks,
        application: OriginalTasks,
        retirements: VecDeque<Arc<DriverOwner>>,
        gate: Arc<RetirementGate>,
        joined_before: u64,
    }
    impl DesktopCaptureDrivers {
        /// Number of actual original task joins completed before the freeze transfer.
        pub fn joined_before_freeze(&self) -> u64 {
            self.joined_before
        }
        /// Retained original tasks that still lack an actual join, including identity faults.
        pub fn original_tasks_remaining(&self) -> usize {
            if self.gate.counts.fault.load(Ordering::Acquire) {
                return usize::MAX;
            }
            usize::try_from(self.gate.counts.originals.load(Ordering::Acquire))
                .unwrap_or(usize::MAX)
        }
        /// Original joins whose actual Connection destruction fact is unavailable.
        pub fn original_destructions_missing(&self) -> u64 {
            if self.gate.counts.fault.load(Ordering::Acquire) {
                return u64::MAX;
            }
            self.gate.counts.missing_destruction.load(Ordering::Acquire)
        }
        pub fn next_retirement(&mut self) -> Option<OriginalDriverRetirement> {
            while let Some(owner) = self.retirements.pop_front() {
                if owner.snapshot().destruction.is_none() {
                    return Some(OriginalDriverRetirement { owner });
                }
            }
            None
        }
        pub async fn join_next_original(&mut self) -> Option<OriginalDriverJoinFact> {
            let result = match (self.admin.set.is_empty(), self.application.set.is_empty()) {
                (true, true) => return None,
                (false, true) => (
                    RetainedPoolKind::Admin,
                    self.admin.set.join_next_with_id().await,
                ),
                (true, false) => (
                    RetainedPoolKind::Application,
                    self.application.set.join_next_with_id().await,
                ),
                (false, false) => tokio::select! {
                    result = self.admin.set.join_next_with_id() => (RetainedPoolKind::Admin, result),
                    result = self.application.set.join_next_with_id() => (RetainedPoolKind::Application, result),
                },
            };
            let Some(joined) = result.1 else {
                return None;
            };
            let mut state = match self.gate.state.lock() {
                Ok(state) => state,
                Err(_) => {
                    self.gate.counts.fault.store(true, Ordering::Release);
                    return None;
                }
            };
            let tasks = if result.0 == RetainedPoolKind::Admin {
                &mut self.admin
            } else {
                &mut self.application
            };
            match tasks.record_join(joined, result.0, &mut state, &self.gate.counts) {
                Ok(fact) => Some(fact),
                Err(_) => {
                    self.gate.counts.fault.store(true, Ordering::Release);
                    None
                }
            }
        }
        pub fn live_proxy_future_count(&self) -> u64 {
            u64::try_from(self.gate.counts.live_proxies.load(Ordering::Acquire)).unwrap_or(u64::MAX)
        }
    }
}
#[cfg(feature = "desktop-local-vault")]
pub use retained::{
    DesktopCaptureDrivers, DesktopLocalDriverCustody, DesktopPoolJoinBounds,
    OriginalDriverJoinFact, OriginalDriverJoinOutcome, OriginalDriverRetirement,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p09_one_session_permit_cannot_bind_two_original_owners() {
        // Pure custody state model; no PG resource or physical-close credit.
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let custody = SessionPermitCustody::new(Arc::clone(&permits).try_acquire_owned().unwrap());
        let supervisor = OwnerSupervisor::new();
        let first = DriverOwner::new(1, &supervisor);
        let second = DriverOwner::new(2, &supervisor);
        assert_eq!(first.attach_session_custody(&custody), Ok(()));
        assert_eq!(first.attach_session_custody(&custody), Ok(()));
        assert_eq!(
            second.attach_session_custody(&custody),
            Err(PoolError::OwnershipUnavailable)
        );
        assert_eq!(permits.available_permits(), 0);
        second.finish_after_drop(ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart);
        assert_eq!(permits.available_permits(), 0);
        first.finish_after_drop(ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart);
        assert_eq!(permits.available_permits(), 1);
    }

    #[test]
    fn p10_finished_owner_cannot_capture_a_late_session_hold() {
        // Pure attach/finish ordering, not an actual driver-destruction observation.
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let custody = SessionPermitCustody::new(Arc::clone(&permits).try_acquire_owned().unwrap());
        let supervisor = OwnerSupervisor::new();
        let finished = DriverOwner::new(1, &supervisor);
        finished.finish_after_drop(ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart);
        assert_eq!(
            finished.attach_session_custody(&custody),
            Err(PoolError::OwnershipUnavailable)
        );
        assert_eq!(permits.available_permits(), 0);
        drop(custody);
        assert_eq!(permits.available_permits(), 1);
    }

    #[test]
    fn creation_counter_rejects_exhaustion_without_id_wrap() {
        // 纯计数边界测试，既不创建 PG 资源，也不作为物理关闭验收。
        let supervisor = OwnerSupervisor::new();
        supervisor
            .creations
            .store(usize::MAX - 1, Ordering::Relaxed);
        assert_eq!(supervisor.reserve_creation(), Ok(usize::MAX - 1));
        assert_eq!(supervisor.reserve_creation(), Err(PoolError::CreationLimit));
        assert_eq!(supervisor.creations.load(Ordering::Relaxed), usize::MAX);
        assert_eq!(supervisor.current_fault(), Some(PoolError::CreationLimit));
        assert_eq!(supervisor.reserve_creation(), Err(PoolError::CreationLimit));
        assert_eq!(supervisor.snapshot(), OwnershipSnapshot::default());
    }
}
