//! `deadpool-postgres` 连接池。
//!
//! 连接参数由调用方以 [`DatabaseConfig`] **显式**传入。本模块一行 `std::env` 都不读：
//! env 的三档裁决（preserve / rename / remove，v3 §15.4）属于启动 / transport 层，
//! 被 remove 的变量出现在生产配置里要**启动报错**，那条判断做不到"库里顺手读一下"。
//!
//! TLS 走 [`tokio_postgres::NoTls`]：v3 §14.1 的部署形态是本机 / 同一信任域内的 PostgreSQL
//! （Desktop 由 Rust 监管本机 sidecar）。要跨网连库是另一件事，须连同证书校验一起立项，
//! 不在这里留一个"传 None 就明文"的开关。

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use deadpool_postgres::{ClientWrapper, Manager, ManagerConfig, RecyclingMethod, Runtime};

use crate::db::InfraError;

mod owner;

use owner::{ClientLease, OwnerSupervisor, SupervisedConnect};
pub use owner::{
    ConnectionDestruction, ConnectionObservation, ConnectionSnapshot, OwnershipSnapshot,
};

/// 封闭连接层错误。底层 PG 错误、SQL、连接配置和秘密不进入这个诊断接口。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PoolError {
    /// 底层建池、建连或 checkout 失败。
    #[error("database_pool_unavailable")]
    Unavailable,
    /// 实际底层 Pool 已关闭。
    #[error("database_pool_closed")]
    Closed,
    /// 原始 checkout / driver 的拥有关系不能核同。
    #[error("database_pool_ownership_unavailable")]
    OwnershipUnavailable,
    /// 本 Pool 的 Object ID 发生不允许的碰撞。
    #[error("database_pool_identity_collision")]
    IdentityCollision,
    /// 已检查的创造计数耗尽，禁止底层 usize ID 回绕。
    #[error("database_pool_creation_limit")]
    CreationLimit,
    /// 调用方原绝对期限耗尽。
    #[error("database_pool_deadline_exceeded")]
    DeadlineExceeded,
    /// 没有收到原资源析构观察；这不是已关闭。
    #[error("database_connection_observation_unavailable")]
    ObservationUnavailable,
}

/// 同一个实际 stock Manager/Pool 的封闭外壳。
///
/// 所有 clone 共享底层 Pool 和原连接监督者；没有裸 Pool、任意 Manager、hooks 或 builder
/// 出口。Fast 仅保持既有 checkout 行为，不是事务 ACK 或物理关闭证明。
#[derive(Clone)]
pub struct DatabasePool {
    stock: deadpool_postgres::Pool,
    supervisor: Arc<OwnerSupervisor>,
}

impl fmt::Debug for DatabasePool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DatabasePool(<supervised>)")
    }
}

impl DatabasePool {
    /// 仅按显式 typed 配置建封闭 Pool，不取连接、不 probe，也不证明当前权限或可用性。
    ///
    /// # Errors
    /// 不能建立该封闭 Pool 时返回固定 [`PoolError`]。
    pub fn build_unprobed(config: &DatabaseConfig) -> Result<Self, PoolError> {
        Self::build_config(
            config.to_pg_config(),
            config.max_pool_size,
            config.connect_timeout,
        )
    }

    fn build_config(
        config: tokio_postgres::Config,
        max_pool_size: usize,
        connect_timeout: Duration,
    ) -> Result<Self, PoolError> {
        let supervisor = OwnerSupervisor::new();
        let manager = Manager::from_connect(
            config,
            SupervisedConnect::new(&supervisor),
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let stock = deadpool_postgres::Pool::builder(manager)
            .max_size(max_pool_size)
            .runtime(Runtime::Tokio1)
            .create_timeout(Some(connect_timeout))
            .build()
            .map_err(|_| PoolError::Unavailable)?;
        Ok(Self { stock, supervisor })
    }

    /// 兼容既有调用的 checkout；真实 Object ID 的登记在 stock get 后连续完成，无 await。
    ///
    /// # Errors
    /// 底层失败或拥有关系不闭合时封闭拒绝，不伪造 stock timeout。
    pub async fn get(&self) -> Result<PooledClient, PoolError> {
        let lease = self.supervisor.checkout(&self.stock).await?;
        Ok(PooledClient { lease: Some(lease) })
    }

    /// 使用入口传来的原绝对期限；取消期间的 trace 由 scope 外 guard 移交监督者。
    pub(crate) async fn get_guarded(&self, deadline: Instant) -> Result<GuardedClient, PoolError> {
        if Instant::now() >= deadline {
            return Err(PoolError::DeadlineExceeded);
        }
        let lease = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.supervisor.checkout(&self.stock),
        )
        .await
        .map_err(|_| PoolError::DeadlineExceeded)??;
        let client = GuardedClient {
            lease: Some(lease),
            deadline,
            disposition: TransactionDisposition::Unstarted,
            always_retire: false,
        };
        if Instant::now() >= deadline {
            return Err(PoolError::DeadlineExceeded);
        }
        Ok(client)
    }

    /// Same original session permit is transferred before the first stock checkout poll.
    /// This path permanently retires its original resource, including timely-ACK cancellation.
    #[cfg(feature = "server-runtime")]
    pub(crate) async fn get_guarded_with_session_permit(
        &self,
        original_deadline: Instant,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<GuardedClient, PoolError> {
        if Instant::now() >= original_deadline {
            return Err(PoolError::DeadlineExceeded);
        }
        let lease = tokio::time::timeout_at(
            tokio::time::Instant::from_std(original_deadline),
            self.supervisor
                .checkout_with_session_permit(&self.stock, permit),
        )
        .await
        .map_err(|_| PoolError::DeadlineExceeded)??;
        let client = GuardedClient {
            lease: Some(lease),
            deadline: original_deadline,
            disposition: TransactionDisposition::Unstarted,
            always_retire: true,
        };
        if Instant::now() >= original_deadline {
            return Err(PoolError::DeadlineExceeded);
        }
        Ok(client)
    }

    /// 不可变借用原实际 Manager，仅用于既有组合根的精确身份比较。
    pub fn manager(&self) -> &Manager {
        self.stock.manager()
    }

    /// 转发实际 Pool 状态；size 或 available 不是原连接关闭证明。
    pub fn status(&self) -> deadpool_postgres::Status {
        self.stock.status()
    }

    /// 转发实际 Pool 关闭；返回只表示停止准入，不表示所有 driver 已析构。
    pub fn close(&self) {
        self.stock.close();
    }

    /// 实际 stock Pool 的准入关闭状态，不是 socket / driver 析构证明。
    pub fn is_closed(&self) -> bool {
        self.stock.is_closed()
    }

    /// 捕获当前仍由监督者持有的原资源观察；应在取消前保留所需观察句柄。
    pub fn connection_observations(&self) -> Vec<ConnectionObservation> {
        self.supervisor.observations()
    }

    /// 不含配置、地址、用户或 SQL 的监督计数。
    pub fn ownership_snapshot(&self) -> OwnershipSnapshot {
        self.supervisor.snapshot()
    }
}

/// 既有 repository 的 legacy client。公开只借 Wrapper，不借可恢复裸 Pool 的 stock Object。
pub struct PooledClient {
    lease: Option<ClientLease>,
}

impl fmt::Debug for PooledClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PooledClient(<owned>)")
    }
}

impl Deref for PooledClient {
    type Target = ClientWrapper;
    fn deref(&self) -> &Self::Target {
        self.lease().stock()
    }
}

impl PooledClient {
    fn lease(&self) -> &ClientLease {
        self.lease.as_ref().expect("unconsumed pooled client")
    }
    fn lease_mut(&mut self) -> &mut ClientLease {
        self.lease.as_mut().expect("unconsumed pooled client")
    }

    /// 只向已经登记的两个 infra 私有 GenericClient helper 借原 stock Object。
    pub(crate) fn as_generic(&self) -> &deadpool_postgres::Client {
        self.lease().stock()
    }

    /// 在这个原 client 上开始 legacy 事务；不提供原 mutable client loan。
    ///
    /// # Errors
    /// 返回该实际 driver 的原事务错误；此 legacy API 不授予 014 的关闭证明。
    pub async fn transaction(
        &mut self,
    ) -> Result<deadpool_postgres::Transaction<'_>, tokio_postgres::Error> {
        self.lease_mut().stock_mut().transaction().await
    }

    /// 原 client 的 opaque legacy transaction builder。
    pub fn build_transaction(&mut self) -> deadpool_postgres::TransactionBuilder<'_> {
        self.lease_mut().stock_mut().build_transaction()
    }

    /// 受信 bootstrap 的 opaque PG builder；没有 mutable PgClient/Wrapper/Object 出口。
    pub fn build_postgres_transaction(&mut self) -> tokio_postgres::TransactionBuilder<'_> {
        tokio_postgres::Client::build_transaction(self.lease_mut().stock_mut())
    }

    /// 消费并永久脱池，保留两个既有 legacy detach 调用；该 Wrapper 永远不能回原 Pool。
    pub fn take(mut this: Self) -> ClientWrapper {
        this.lease
            .take()
            .expect("unconsumed pooled client")
            .detach()
    }

    /// 仅原资源析构观察，不证明原事务成功、当前权限或远端关闭。
    pub fn observation(&self) -> ConnectionObservation {
        self.lease().observation()
    }
}

impl Drop for PooledClient {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            lease.release(true);
        }
    }
}

/// 单一原事务 owner 的封闭错误；不携带 PG 原文或自由 SQL。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TransactionOwnerError {
    #[error("database_transaction_already_started")]
    AlreadyStarted,
    #[error("database_transaction_deadline_exceeded")]
    DeadlineExceeded,
    #[error("database_transaction_begin_unavailable")]
    BeginUnavailable,
    #[error("database_transaction_commit_unknown")]
    CommitUnknown,
    #[error("database_transaction_rollback_unproven")]
    RollbackUnproven,
    #[error("database_transaction_commit_ack_after_deadline")]
    CommitAcknowledgedAfterDeadline,
    #[error("database_transaction_rollback_ack_after_deadline")]
    RollbackAcknowledgedAfterDeadline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionDisposition {
    Unstarted,
    BeginStarted,
    InTransaction,
    CommitStarted,
    RollbackStarted,
    CommitAcknowledged,
    RollbackAcknowledged,
    CommitAcknowledgedLate,
    RollbackAcknowledgedLate,
    CommitUnknown,
    RollbackUnproven,
}

/// 014 client：没有 stock Object、detach、替换或 mutable Wrapper loan；默认永久退役。
pub(crate) struct GuardedClient {
    lease: Option<ClientLease>,
    deadline: Instant,
    disposition: TransactionDisposition,
    always_retire: bool,
}

impl fmt::Debug for GuardedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuardedClient(<original-owner>)")
    }
}

impl GuardedClient {
    /// Retire this exact lease; the observation is not a closed acknowledgement.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn retire_original(mut self) -> ConnectionObservation {
        let lease = self.lease.take().expect("unconsumed guarded client");
        let observation = lease.observation();
        lease.release(false);
        observation
    }

    /// 只借这个原 client 的 immutable PG 查询面；不暴露 stock Object 或 mutable loan。
    pub(crate) fn as_client(&self) -> &tokio_postgres::Client {
        self.lease
            .as_ref()
            .expect("unconsumed guarded client")
            .stock()
    }

    /// BEGIN 也计入原预算；只有一个事务，真实 Read Committed，不接受 foreign Transaction。
    pub(crate) async fn begin_read_committed(
        &mut self,
    ) -> Result<GuardedTransaction<'_>, TransactionOwnerError> {
        self.begin_read_committed_mode(false).await
    }

    /// 原 reader 的固定只读 RC 事务，复用同一 owner、绝对期限及真实 ACK 路径。
    #[cfg(feature = "server-runtime")]
    pub(crate) async fn begin_read_committed_read_only(
        &mut self,
    ) -> Result<GuardedTransaction<'_>, TransactionOwnerError> {
        self.begin_read_committed_mode(true).await
    }

    async fn begin_read_committed_mode(
        &mut self,
        read_only: bool,
    ) -> Result<GuardedTransaction<'_>, TransactionOwnerError> {
        if self.disposition != TransactionDisposition::Unstarted {
            return Err(TransactionOwnerError::AlreadyStarted);
        }
        if Instant::now() >= self.deadline {
            return Err(TransactionOwnerError::DeadlineExceeded);
        }
        self.disposition = TransactionDisposition::BeginStarted;
        let deadline = self.deadline;
        let lease = self.lease.as_mut().expect("unconsumed guarded client");
        let builder = lease
            .stock_mut()
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted);
        let builder = if read_only {
            builder.read_only(true)
        } else {
            // 保留014原BEGIN的默认读写选项，不新增SET或READ WRITE语句。
            builder
        };
        let transaction =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), builder.start())
                .await;
        let transaction = match transaction {
            Ok(Ok(transaction)) => transaction,
            Ok(Err(_)) => return Err(TransactionOwnerError::BeginUnavailable),
            Err(_) => return Err(TransactionOwnerError::DeadlineExceeded),
        };
        if Instant::now() >= deadline {
            drop(transaction);
            return Err(TransactionOwnerError::DeadlineExceeded);
        }
        self.disposition = TransactionDisposition::InTransaction;
        Ok(GuardedTransaction {
            transaction: Some(transaction),
            disposition: &mut self.disposition,
            deadline,
        })
    }
}

impl Drop for GuardedClient {
    fn drop(&mut self) {
        let reusable = !self.always_retire
            && matches!(
                self.disposition,
                TransactionDisposition::CommitAcknowledged
                    | TransactionDisposition::RollbackAcknowledged
            )
            && Instant::now() < self.deadline;
        if let Some(lease) = self.lease.take() {
            lease.release(reusable);
        }
    }
}

/// 只由原 GuardedClient 的 BEGIN 构造。内部 ACK 路径是唯一可准许归池的路径。
pub(crate) struct GuardedTransaction<'a> {
    transaction: Option<deadpool_postgres::Transaction<'a>>,
    disposition: &'a mut TransactionDisposition,
    deadline: Instant,
}

impl fmt::Debug for GuardedTransaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuardedTransaction(<original-owner>)")
    }
}

impl<'a> GuardedTransaction<'a> {
    /// Only shorten the original owner cap, preserving its actual ACK classification.
    #[cfg(feature = "server-runtime")]
    pub(crate) async fn commit_before(mut self, cap: Instant) -> Result<(), TransactionOwnerError> {
        self.deadline = self.deadline.min(cap);
        self.commit().await
    }

    /// Only shorten the original owner cap; no external timeout replaces its ACK result.
    #[cfg(feature = "server-runtime")]
    pub(crate) async fn rollback_before(
        mut self,
        cap: Instant,
    ) -> Result<(), TransactionOwnerError> {
        self.deadline = self.deadline.min(cap);
        self.rollback().await
    }

    /// 不可变借用同一个原 PG 事务；所有外部 SQL await 必须继续使用原入口 deadline。
    pub(crate) fn as_transaction(&self) -> &tokio_postgres::Transaction<'a> {
        self.transaction
            .as_ref()
            .expect("unconsumed original transaction")
    }
    pub(crate) async fn commit(mut self) -> Result<(), TransactionOwnerError> {
        if Instant::now() >= self.deadline {
            return Err(TransactionOwnerError::DeadlineExceeded);
        }
        *self.disposition = TransactionDisposition::CommitStarted;
        let transaction = self
            .transaction
            .take()
            .expect("unconsumed original transaction");
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            transaction.commit(),
        )
        .await;
        match result {
            Ok(Ok(())) => {
                if Instant::now() >= self.deadline {
                    // 实际 ACK 已有，不能倒记 Unknown；耗尽预算仍禁止归池。
                    *self.disposition = TransactionDisposition::CommitAcknowledgedLate;
                    return Err(TransactionOwnerError::CommitAcknowledgedAfterDeadline);
                }
                *self.disposition = TransactionDisposition::CommitAcknowledged;
                Ok(())
            }
            _ => {
                *self.disposition = TransactionDisposition::CommitUnknown;
                Err(TransactionOwnerError::CommitUnknown)
            }
        }
    }

    pub(crate) async fn rollback(mut self) -> Result<(), TransactionOwnerError> {
        if Instant::now() >= self.deadline {
            return Err(TransactionOwnerError::DeadlineExceeded);
        }
        *self.disposition = TransactionDisposition::RollbackStarted;
        let transaction = self
            .transaction
            .take()
            .expect("unconsumed original transaction");
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            transaction.rollback(),
        )
        .await;
        match result {
            Ok(Ok(())) => {
                if Instant::now() >= self.deadline {
                    *self.disposition = TransactionDisposition::RollbackAcknowledgedLate;
                    return Err(TransactionOwnerError::RollbackAcknowledgedAfterDeadline);
                }
                *self.disposition = TransactionDisposition::RollbackAcknowledged;
                Ok(())
            }
            _ => {
                *self.disposition = TransactionDisposition::RollbackUnproven;
                Err(TransactionOwnerError::RollbackUnproven)
            }
        }
    }
}

impl Drop for GuardedTransaction<'_> {
    fn drop(&mut self) {
        match *self.disposition {
            TransactionDisposition::CommitStarted => {
                *self.disposition = TransactionDisposition::CommitUnknown
            }
            TransactionDisposition::InTransaction | TransactionDisposition::RollbackStarted => {
                *self.disposition = TransactionDisposition::RollbackUnproven;
            }
            _ => {}
        }
        // stock Transaction Drop 的 queued rollback 不提供 ACK；原 client 仍默认退役。
    }
}

/// 默认连接池上限。
pub const DEFAULT_MAX_POOL_SIZE: usize = 16;

/// 默认建连超时。
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// PostgreSQL 连接参数与池参数。
///
/// [`Debug`] 是**手写**的：派生实现会把 `password` 原样打印，而 repository contract §5 不变量 8 要求
/// secret 不进普通日志与 trace，配置结构体恰恰是最容易被顺手 `tracing::debug!` 掉的东西。
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// 主机名或 IP。
    pub host: String,
    /// 端口。
    pub port: u16,
    /// 登录用户。
    pub user: String,
    /// 口令；无口令认证（peer / trust）时为 `None`。
    pub password: Option<String>,
    /// 数据库名。
    pub dbname: String,
    /// 写进 `application_name` 的标识，便于在 `pg_stat_activity` 里认出是谁。
    pub application_name: Option<String>,
    /// 池里最多同时存在多少连接。
    pub max_pool_size: usize,
    /// 单次建连超时。
    pub connect_timeout: Duration,
}

/// `DATABASE_URL` / libpq keyword 串无法映射成本项目单一 TCP 数据库配置。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DatabaseConfigParseError {
    /// libpq/URL 语法错误。
    #[error("database_url_malformed")]
    Malformed,
    /// 缺 host/user/dbname，或给了多个/Unix host。
    #[error("database_url_shape_unsupported")]
    UnsupportedShape,
    /// 连接串要求了本实现不能兑现且绝不能静默降级的 TLS/拓扑/会话选项。
    #[error("database_url_option_unsupported")]
    UnsupportedOption,
    /// password 不是 UTF-8。
    #[error("database_url_password_not_utf8")]
    PasswordNotUtf8,
}

impl DatabaseConfig {
    /// 用必填四项建配置，池参数取默认值。
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        dbname: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            user: user.into(),
            password: None,
            dbname: dbname.into(),
            application_name: None,
            max_pool_size: DEFAULT_MAX_POOL_SIZE,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// 设置口令。
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// 设置 `application_name`。
    #[must_use]
    pub fn with_application_name(mut self, name: impl Into<String>) -> Self {
        self.application_name = Some(name.into());
        self
    }

    /// 设置池上限。
    #[must_use]
    pub fn with_max_pool_size(mut self, size: usize) -> Self {
        self.max_pool_size = size;
        self
    }

    /// 换一个库名，其余参数照抄。
    ///
    /// 建库 / 删库这类操作必须连到另一个库（通常是 `postgres`）上执行，这是那条路径的入口。
    #[must_use]
    pub fn with_dbname(mut self, dbname: impl Into<String>) -> Self {
        self.dbname = dbname.into();
        self
    }

    /// 翻译成 `tokio_postgres` 的连接配置。
    pub fn to_pg_config(&self) -> tokio_postgres::Config {
        let mut cfg = tokio_postgres::Config::new();
        cfg.host(&self.host)
            .port(self.port)
            .user(&self.user)
            .dbname(&self.dbname)
            .connect_timeout(self.connect_timeout);
        if let Some(password) = &self.password {
            cfg.password(password);
        }
        if let Some(name) = &self.application_name {
            cfg.application_name(name);
        }
        cfg
    }
}

impl FromStr for DatabaseConfig {
    type Err = DatabaseConfigParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = tokio_postgres::Config::from_str(value)
            .map_err(|_| DatabaseConfigParseError::Malformed)?;
        if parsed.get_hosts().len() != 1 {
            return Err(DatabaseConfigParseError::UnsupportedShape);
        }
        if !parsed.get_hostaddrs().is_empty() || parsed.get_ports().len() > 1 {
            return Err(DatabaseConfigParseError::UnsupportedShape);
        }
        let defaults = tokio_postgres::Config::new();
        if parsed.get_options().is_some()
            || matches!(
                parsed.get_ssl_mode(),
                tokio_postgres::config::SslMode::Require
            )
            || parsed.get_ssl_negotiation() != defaults.get_ssl_negotiation()
            || parsed.get_tcp_user_timeout().is_some()
            || parsed.get_keepalives() != defaults.get_keepalives()
            || parsed.get_keepalives_idle() != defaults.get_keepalives_idle()
            || parsed.get_keepalives_interval() != defaults.get_keepalives_interval()
            || parsed.get_keepalives_retries() != defaults.get_keepalives_retries()
            || parsed.get_target_session_attrs() != defaults.get_target_session_attrs()
            || matches!(
                parsed.get_channel_binding(),
                tokio_postgres::config::ChannelBinding::Require
            )
            || parsed.get_load_balance_hosts() != defaults.get_load_balance_hosts()
        {
            return Err(DatabaseConfigParseError::UnsupportedOption);
        }
        let host = match &parsed.get_hosts()[0] {
            tokio_postgres::config::Host::Tcp(host) if !host.is_empty() => host.clone(),
            _ => return Err(DatabaseConfigParseError::UnsupportedShape),
        };
        let user = parsed
            .get_user()
            .filter(|value| !value.is_empty())
            .ok_or(DatabaseConfigParseError::UnsupportedShape)?;
        let dbname = parsed
            .get_dbname()
            .filter(|value| !value.is_empty())
            .ok_or(DatabaseConfigParseError::UnsupportedShape)?;
        let port = parsed.get_ports().first().copied().unwrap_or(5432);
        let mut config = Self::new(host, port, user, dbname);
        if let Some(password) = parsed.get_password() {
            config = config.with_password(
                std::str::from_utf8(password)
                    .map_err(|_| DatabaseConfigParseError::PasswordNotUtf8)?,
            );
        }
        if let Some(application_name) = parsed.get_application_name() {
            config = config.with_application_name(application_name);
        }
        if let Some(connect_timeout) = parsed.get_connect_timeout() {
            config.connect_timeout = *connect_timeout;
        }
        Ok(config)
    }
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("dbname", &self.dbname)
            .field("application_name", &self.application_name)
            .field("max_pool_size", &self.max_pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

/// 建池，并立刻取一次连接把参数验穿。
///
/// 不做这次取用的话，错口令 / 库不存在这类问题会推迟到第一条业务查询才暴露 ——
/// 那时候的调用栈已经在业务里了，报出来的是"查询失败"而不是"根本没连上"。
///
/// # Errors
///
/// 建池或首次取连接失败返回 [`InfraError::Connect`]。
pub async fn connect(config: &DatabaseConfig) -> Result<DatabasePool, InfraError> {
    connect_config(
        config.to_pg_config(),
        config.max_pool_size,
        config.connect_timeout,
        format!("{} 数据库", config.dbname),
    )
    .await
}

/// Build and immediately probe one already-closed PostgreSQL driver configuration.
///
/// This is crate-private so callers cannot bypass [`DatabaseConfig`] for Server/network
/// connections. The Desktop Local adapter uses it with a fixed numeric-loopback topology and a
/// startup-only [`openbot_domain::vault::SecretBytes`] owner, avoiding a second public config path
/// that owns a password `String`.
pub(super) async fn connect_config(
    config: tokio_postgres::Config,
    max_pool_size: usize,
    connect_timeout: Duration,
    context: impl Into<String>,
) -> Result<DatabasePool, InfraError> {
    let context = context.into();
    let pool = DatabasePool::build_config(config, max_pool_size, connect_timeout)
        .map_err(|source| InfraError::connect(format!("建立{context}连接池"), source))?;
    let _probe = pool
        .get()
        .await
        .map_err(|source| InfraError::connect(format!("取{context}首个连接"), source))?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_password() {
        let config = DatabaseConfig::new("127.0.0.1", 5432, "postgres", "openbot")
            .with_password("hunter2-绝对不能出现在日志里")
            .with_application_name("openbot-test");
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("hunter2"),
            "口令泄漏进 Debug：{rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        // 正向对照：非敏感字段确实被打印了，说明上面不是在一个空串上判"不含"。
        assert!(rendered.contains("openbot-test"));
        assert!(rendered.contains("5432"));
    }

    #[test]
    fn debug_distinguishes_no_password_from_a_redacted_one() {
        let without = DatabaseConfig::new("127.0.0.1", 5432, "postgres", "openbot");
        assert!(format!("{without:?}").contains("password: None"));
    }

    #[test]
    fn builders_keep_the_other_fields_untouched() {
        let base = DatabaseConfig::new("db.internal", 6432, "openbot", "openbot")
            .with_password("s3cret")
            .with_application_name("openbot-server")
            .with_max_pool_size(4);
        let switched = base.clone().with_dbname("postgres");
        assert_eq!(switched.dbname, "postgres");
        assert_eq!(switched.host, base.host);
        assert_eq!(switched.port, base.port);
        assert_eq!(switched.user, base.user);
        assert_eq!(switched.password, base.password);
        assert_eq!(switched.application_name, base.application_name);
        assert_eq!(switched.max_pool_size, 4);
    }

    #[test]
    fn defaults_are_the_documented_constants() {
        let config = DatabaseConfig::new("127.0.0.1", 5432, "postgres", "openbot");
        assert_eq!(config.max_pool_size, DEFAULT_MAX_POOL_SIZE);
        assert_eq!(config.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(config.password, None);
        assert_eq!(config.application_name, None);
    }

    #[test]
    fn pg_config_carries_every_field_that_was_set() {
        let config = DatabaseConfig::new("db.internal", 6432, "openbot", "openbot_main")
            .with_password("s3cret")
            .with_application_name("openbot-server");
        let pg = config.to_pg_config();
        assert_eq!(pg.get_ports(), &[6432]);
        assert_eq!(pg.get_user(), Some("openbot"));
        assert_eq!(pg.get_dbname(), Some("openbot_main"));
        assert_eq!(pg.get_password(), Some(&b"s3cret"[..]));
        assert_eq!(pg.get_application_name(), Some("openbot-server"));
        assert_eq!(pg.get_connect_timeout(), Some(&DEFAULT_CONNECT_TIMEOUT));
    }

    #[test]
    fn database_url_and_keyword_forms_share_one_parser_and_redact_password() {
        for raw in [
            "postgresql://openbot:secret@127.0.0.1:5544/openbot",
            "host=127.0.0.1 port=5544 user=openbot password=secret dbname=openbot",
        ] {
            let config: DatabaseConfig = raw.parse().unwrap();
            assert_eq!(config.host, "127.0.0.1");
            assert_eq!(config.port, 5544);
            assert_eq!(config.user, "openbot");
            assert_eq!(config.dbname, "openbot");
            assert_eq!(config.password.as_deref(), Some("secret"));
            assert!(!format!("{config:?}").contains("secret"));
        }
    }

    #[test]
    fn malformed_or_ambiguous_database_shapes_are_refused_not_guessed() {
        assert_eq!(
            "not a database url".parse::<DatabaseConfig>(),
            Err(DatabaseConfigParseError::Malformed),
        );
        assert_eq!(
            "host=a,b user=u dbname=d".parse::<DatabaseConfig>(),
            Err(DatabaseConfigParseError::UnsupportedShape),
        );
        assert_eq!(
            "host=127.0.0.1 dbname=d".parse::<DatabaseConfig>(),
            Err(DatabaseConfigParseError::UnsupportedShape),
        );
    }

    #[test]
    fn security_or_topology_options_are_never_silently_downgraded() {
        for raw in [
            "host=127.0.0.1 user=u dbname=d sslmode=require",
            "host=127.0.0.1 user=u dbname=d target_session_attrs=read-write",
            "host=127.0.0.1 user=u dbname=d channel_binding=require",
            "host=127.0.0.1 user=u dbname=d options=-cstatement_timeout=10s",
            "host=127.0.0.1 hostaddr=127.0.0.2 user=u dbname=d",
        ] {
            assert!(
                matches!(
                    raw.parse::<DatabaseConfig>(),
                    Err(DatabaseConfigParseError::UnsupportedOption
                        | DatabaseConfigParseError::UnsupportedShape)
                ),
                "不可兑现的连接要求被静默接受：{raw}",
            );
        }

        // 正向对照：显式 NoTls 与默认 prefer 在本实现里都能如实兑现，不应被误拒。
        assert!(
            "host=127.0.0.1 user=u dbname=d sslmode=disable"
                .parse::<DatabaseConfig>()
                .is_ok()
        );
        assert!(
            "host=127.0.0.1 user=u dbname=d sslmode=prefer"
                .parse::<DatabaseConfig>()
                .is_ok()
        );
    }
}
