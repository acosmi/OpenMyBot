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
}

impl OwnerSupervisor {
    pub(super) fn new() -> Arc<Self> {
        let (fault, _) = watch::channel(None);
        Arc::new(Self {
            registry: Mutex::new(Registry::default()),
            creations: AtomicUsize::new(0),
            fault,
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
        let trace = Arc::new(CheckoutTrace::new(self, session_permit));
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
}

impl CheckoutTrace {
    fn new(supervisor: &Arc<OwnerSupervisor>, permit: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            supervisor: Arc::downgrade(supervisor),
            created: Mutex::new(Vec::new()),
            session_custody: permit.map(SessionPermitCustody::new),
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
        let created = self
            .created
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for owner in created.iter() {
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
        })
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
        if self.snapshot().retirement_requested {
            abort.abort();
        }
        *slot = Some(abort);
    }

    fn request_retirement(&self) {
        self.state
            .send_modify(|state| state.retirement_requested = true);
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
