//! 测试固定身份 —— `cfg(test)` 或 `testkit` feature 下才存在，默认关。
//!
//! # 这里为什么**没有**认证
//!
//! G1 的 Desktop 不实现任何真实认证（见 crate 文档〈认证：G1 刻意没有〉）。本模块提供的
//! 是一组**写死的**测试身份，它们：
//!
//! - 走 `AuthContext::for_test`，而那个构造器本身也被 contracts 的 `testkit` feature 门着
//!   —— 于是"拿得到固定身份"这件事需要**两层 feature 同时打开**，生产 feature 图里一层
//!   都没有；
//! - **不是**"默认放行"的构造：它铸造的是一个具体的部署 / 租户 / actor / 代际，没有任何
//!   通配含义。测试要验跨租户、跨 actor、跨代际被挡住，靠的正是它能造出**不同**的身份。
//!
//! # G2 接在哪
//!
//! Desktop 的真实身份来源是本机 session。G2 落地时，本机 session 校验的结果经
//! `AuthContextBuilder::from_verified_session` 铸造 `AuthContext`，再交给
//! [`crate::transport::InProcessTransport::open_session`] —— 本 crate 的签名一行都不用改，
//! 本模块也不会被牵进生产路径（它不在默认 feature 图里）。

use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};

/// 测试部署 id。
pub const TEST_DEPLOYMENT: &str = "dep-g1";

/// 测试租户 id。
pub const TEST_TENANT: &str = "tenant-g1";

/// 测试身份的默认 auth generation。
///
/// 刻意不是 0：0 同时是"没设过"的自然值，用它做默认会让「代际比对确实跑了」与
/// 「两边都是默认值所以恰好相等」不可分辨。
pub const TEST_AUTH_GENERATION: u64 = 7;

/// 测试租户。
#[must_use]
pub fn tenant() -> TenantId {
    TenantId::new(TEST_TENANT)
}

/// 一个固定的已认证上下文，代际为 [`TEST_AUTH_GENERATION`]。
#[must_use]
pub fn auth_for(actor: &str) -> AuthContext {
    auth_with(actor, TEST_AUTH_GENERATION)
}

/// 指定代际的固定已认证上下文。
///
/// 角色集合刻意为空：transport 不做授权判定，给它角色只会诱导人在这一层写角色门。
#[must_use]
pub fn auth_with(actor: &str, auth_generation: u64) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new(TEST_DEPLOYMENT),
        TenantId::new(TEST_TENANT),
        ActorId::new(actor),
        [],
        AuthGeneration::new(auth_generation),
        false,
    )
}

/// 指定租户与代际的固定已认证上下文 —— 用于跨租户隔离的负向用例。
#[must_use]
pub fn auth_in_tenant(tenant_id: &str, actor: &str, auth_generation: u64) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new(TEST_DEPLOYMENT),
        TenantId::new(tenant_id),
        ActorId::new(actor),
        [],
        AuthGeneration::new(auth_generation),
        false,
    )
}

/// Runs a real-sidecar Desktop case on a 16 MiB thread over a two-worker runtime. The case body
/// and the Prepared Local setup poll on this thread; unoptimized, they overflow the default 2 MiB
/// test stack. Requests spawned from the body run on runtime workers with their default stack.
#[cfg(test)]
pub(crate) fn on_large_stack<F: std::future::Future<Output = ()> + 'static>(case: fn() -> F) {
    let polling = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(case())
        })
        .expect("test polling thread");
    if let Err(panic) = polling.join() {
        std::panic::resume_unwind(panic);
    }
}
