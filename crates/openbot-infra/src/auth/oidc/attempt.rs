//! 一次登录尝试：PKCE S256、`state`、`nonce`（v3 §6.2 条 3 的前三项）。
//!
//! # 三个值，一条命
//!
//! `state`、`nonce`、PKCE verifier 是**同一次**登录尝试的三个面，任何一个能被单独复用，
//! 这次尝试就不再是一次性的。所以它们装在同一个 [`LoginAttempt`] 里，由
//! [`LoginAttemptStore::consume`] 一次性取走 —— 取走用的是 `remove` 而不是 `get`，
//! 而且**先取走再校验**（见该函数文档里那条时序理由）。
//!
//! # PKCE 只有 S256
//!
//! [`S256Pkce`] 的构造入口只有 [`S256Pkce::generate`]（内部走
//! `PkceCodeChallenge::new_random_sha256`）与 [`S256Pkce::from_parts`]（对
//! `code_challenge_method` 逐字节判 `S256`）。`plain` 落进 [`OidcError::PkceMethodNotS256`]。
//!
//! 依赖图里还有一层刚好同向的构造性约束：`oauth2` 的
//! `PkceCodeChallenge::new_random_plain` / `from_code_verifier_plain` 都标了
//! `#[cfg(feature = "pkce-plain")]`，而 `openidconnect` 是以
//! `oauth2 = { default-features = false }` 引入的（`openidconnect-4.0.1/Cargo.toml`），
//! 本仓也没有别处打开这个 feature。所以在**这个依赖图里**根本造不出一个 `plain` challenge。
//! 那是一层不该依赖的巧合（换 feature 就没了），因此本模块仍然自己判一次 —— 由
//! `plain_is_refused_even_though_the_dependency_graph_already_makes_it_unbuildable` 钉住。
//!
//! # 时间由调用方传入
//!
//! 本模块没有时钟。每个涉及过期的函数都收一个 `now: OffsetDateTime`。这既是可测性要求，
//! 也是 repository contract「测试不得对不受控全机状态断言」的直接落实 —— 一个内部调
//! `OffsetDateTime::now_utc()` 的过期判定，其测试会在慢机器上间歇性翻。

use std::collections::HashMap;

use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::error::OidcError;
use super::provider::ProviderId;
use super::redirect::CanonicalRedirectUri;

/// `code_challenge_method` 的唯一合法取值。
///
/// RFC 7636 §4.2 定义了 `plain` 与 `S256` 两个方法，v3 §6.2 条 3 只允许后者。
pub const PKCE_METHOD_S256: &str = "S256";

/// 一次 PKCE 交换的两半，**保证**是 S256。
///
/// 刻意不实现 `Clone`：`oauth2` 对 `PkceCodeVerifier` 的注释写得很直白 ——「This type
/// intentionally does not implement Clone in order to make it difficult to reuse PKCE
/// challenges across multiple requests.」把 verifier 包进一个可 `Clone` 的结构体，等于把
/// 上游那条刻意的限制绕过去。
#[derive(Debug)]
pub struct S256Pkce {
    challenge: String,
    verifier: PkceCodeVerifier,
}

impl S256Pkce {
    /// 生成一对新的 challenge / verifier。
    #[must_use]
    pub fn generate() -> Self {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        debug_assert_eq!(challenge.method().as_str(), PKCE_METHOD_S256);
        Self {
            challenge: challenge.as_str().to_owned(),
            verifier,
        }
    }

    /// 从既有的一对值重建，并强制 method 必须是 `S256`。
    ///
    /// 用在「登录尝试从持久化状态里水合回来」的路径上：**水合是一次重新入口**，
    /// 落盘时是 S256 不代表读回来还是（表可能被别的版本写过、被人改过）。
    ///
    /// # Errors
    ///
    /// method 不是逐字节的 `S256` 时返回 [`OidcError::PkceMethodNotS256`]。大小写不宽容：
    /// RFC 7636 §4.3 把 `code_challenge_method` 定义成大小写敏感的字面量，宽容比对会让
    /// 我们接受一个授权服务器会拒绝的值。
    pub fn from_parts(
        challenge: String,
        method: &str,
        verifier: PkceCodeVerifier,
    ) -> Result<Self, OidcError> {
        if method != PKCE_METHOD_S256 {
            return Err(OidcError::PkceMethodNotS256);
        }
        Ok(Self {
            challenge,
            verifier,
        })
    }

    /// 放进授权请求的 `code_challenge`。
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// `code_challenge_method`，恒为 [`PKCE_METHOD_S256`]。
    #[must_use]
    pub const fn method(&self) -> &'static str {
        PKCE_METHOD_S256
    }

    /// 交出 verifier 去换 token。消耗 `self` —— 一次尝试只能换一次。
    #[must_use]
    pub fn into_verifier(self) -> PkceCodeVerifier {
        self.verifier
    }
}

// Configuration incarnation DATA only; never a fresh or Current authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ProviderIncarnationBinding {
    Configured {},
    Dynamic {
        #[serde(rename = "providerInternalId")]
        provider_internal_id: Uuid,
    },
}

impl ProviderIncarnationBinding {
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Configured {} => true,
            Self::Dynamic {
                provider_internal_id,
            } => !provider_internal_id.is_nil(),
        }
    }
}

/// 一次在飞的登录尝试。
///
/// 不实现 `Clone`（[`S256Pkce`] 不 `Clone`，这条约束就顺着结构传上来了），也不实现
/// `Serialize` —— 它带着 PKCE verifier 与 nonce，两者都是 secret（v3 §17.2 条 8）。
#[derive(Debug)]
pub struct LoginAttempt {
    provider: ProviderId,
    incarnation: ProviderIncarnationBinding,
    state: CsrfToken,
    nonce: Nonce,
    pkce: S256Pkce,
    redirect_uri: CanonicalRedirectUri,
    expires_at: OffsetDateTime,
}

/// 持久化 adapter 唯一能取出的内部形态；不实现 Debug/Clone/Serialize。
///
/// 字段只在 `openbot-infra` crate 内可见，避免把 PKCE verifier/nonce 变成通用 DTO。
pub(crate) struct LoginAttemptStorageRecord {
    pub(crate) state: String,
    pub(crate) provider: String,
    pub(crate) incarnation: ProviderIncarnationBinding,
    pub(crate) nonce: String,
    pub(crate) pkce_verifier: String,
    pub(crate) pkce_method: &'static str,
    pub(crate) redirect_uri: String,
    pub(crate) expires_at: OffsetDateTime,
}

/// callback 消耗一次 state 后得到的最小能力。
///
/// 不含 state/challenge，且不 Clone/Serialize；`into_nonce_and_verifier` 消耗自身，保证一次
/// callback 至多发起一次 token exchange。
pub struct CallbackLoginAttempt {
    provider: ProviderId,
    incarnation: ProviderIncarnationBinding,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    redirect_uri: CanonicalRedirectUri,
}

impl CallbackLoginAttempt {
    pub(crate) fn restore_bound(
        provider: ProviderId,
        nonce: Nonce,
        verifier: PkceCodeVerifier,
        redirect_uri: CanonicalRedirectUri,
        incarnation: ProviderIncarnationBinding,
    ) -> Self {
        Self {
            provider,
            incarnation,
            nonce,
            verifier,
            redirect_uri,
        }
    }

    pub(crate) const fn incarnation(&self) -> ProviderIncarnationBinding {
        self.incarnation
    }

    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    #[must_use]
    pub const fn redirect_uri(&self) -> &CanonicalRedirectUri {
        &self.redirect_uri
    }

    #[must_use]
    pub fn into_nonce_and_verifier(self) -> (Nonce, PkceCodeVerifier) {
        (self.nonce, self.verifier)
    }
}

impl core::fmt::Debug for CallbackLoginAttempt {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CallbackLoginAttempt")
            .field("provider", &self.provider)
            .field("nonce", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl LoginAttempt {
    /// 发起一次登录尝试。
    ///
    /// `state` 与 `nonce` 在这里随机生成（`CsrfToken::new_random` / `Nonce::new_random`，
    /// 各 16 字节 base64url），调用方拿不到「自己指定一个 state」的入口 —— 那个入口一旦
    /// 存在，就会有人把 session id 之类的东西塞进去。
    #[must_use]
    pub fn begin(
        provider: ProviderId,
        redirect_uri: CanonicalRedirectUri,
        now: OffsetDateTime,
        ttl: Duration,
    ) -> Self {
        Self::begin_bound(
            provider,
            redirect_uri,
            now,
            ttl,
            ProviderIncarnationBinding::Configured {},
        )
    }

    pub(crate) fn begin_bound(
        provider: ProviderId,
        redirect_uri: CanonicalRedirectUri,
        now: OffsetDateTime,
        ttl: Duration,
        incarnation: ProviderIncarnationBinding,
    ) -> Self {
        Self {
            provider,
            incarnation,
            state: CsrfToken::new_random(),
            nonce: Nonce::new_random(),
            pkce: S256Pkce::generate(),
            redirect_uri,
            expires_at: now + ttl,
        }
    }

    /// 这次尝试锁定的 provider。
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// `state`，放进授权请求的查询串。
    ///
    /// 这里没有 `#[must_use]`：`CsrfToken` 自己已经标了（`oauth2` 的 `new_secret_type!`
    /// 对它加了 `#[must_use]`），再标一次是 `clippy::double_must_use`。
    pub const fn state(&self) -> &CsrfToken {
        &self.state
    }

    /// `nonce`，放进授权请求，回来时由 ID token 校验。
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// PKCE 的两半。
    #[must_use]
    pub const fn pkce(&self) -> &S256Pkce {
        &self.pkce
    }

    /// 这次尝试登记的精确 redirect URI。
    #[must_use]
    pub const fn redirect_uri(&self) -> &CanonicalRedirectUri {
        &self.redirect_uri
    }

    /// 失效时刻。
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// 在 `now` 这一刻是否已过期。
    ///
    /// 判据是 `now >= expires_at`（闭区间的右端算过期）：边界上选「已失效」而不是
    /// 「还能用」，是因为两种误判的代价不对称 —— 早失效一毫秒是重新登录，晚失效一毫秒是
    /// 一个本该死掉的凭据还活着。
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// 拆出 nonce 与 PKCE verifier，用于换 token 与校验 ID token。消耗 `self`。
    #[must_use]
    pub fn into_nonce_and_verifier(self) -> (Nonce, PkceCodeVerifier) {
        (self.nonce, self.pkce.into_verifier())
    }

    /// 交给 PostgreSQL 一次性 store。显式方法而非 serde，避免整个类型获得通用序列化能力。
    pub(crate) fn into_storage_record(self) -> LoginAttemptStorageRecord {
        LoginAttemptStorageRecord {
            state: self.state.into_secret(),
            provider: self.provider.as_str().to_owned(),
            incarnation: self.incarnation,
            nonce: self.nonce.secret().clone(),
            pkce_verifier: self.pkce.into_verifier().into_secret(),
            pkce_method: PKCE_METHOD_S256,
            redirect_uri: self.redirect_uri.as_str().to_owned(),
            expires_at: self.expires_at,
        }
    }
}

/// 在飞登录尝试的一次性存储。
///
/// # 已知非目标：`state` 的查表不是常数时间
///
/// 索引是一张 [`HashMap`]，查表耗时与 key 有关。这里不做常数时间比对，理由是 `state`
/// 是 16 字节全熵、单次使用、短寿命的值，通过计时逐字节猜出它的收益低于直接重放。
/// **把它写下来是因为它是一条选择而不是遗漏** —— 真要改，正确做法是把索引换成对
/// `state` 摘要的比对（`openidconnect` 的 `impl NonceVerifier for &Nonce` 就是这么做的：
/// 比的是 `Sha256::digest` 而不是原串）。
#[derive(Debug)]
pub struct LoginAttemptStore {
    by_state: HashMap<String, LoginAttempt>,
    capacity: usize,
}

impl LoginAttemptStore {
    /// 建一个有容量上限的存储。
    ///
    /// 上限不是可选项：一张只增不减的在飞表就是 §6.2 点名的 callback flood 的落地形态。
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            by_state: HashMap::new(),
            capacity,
        }
    }

    /// 在飞尝试数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_state.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_state.is_empty()
    }

    /// 登记一次尝试。
    ///
    /// 满了先清一遍过期项再试；仍然满就拒。**先清后拒**的顺序是必要的：只拒不清会让
    /// 一批早就该死的条目把新登录永久挡在门外。
    ///
    /// # Errors
    ///
    /// [`OidcError::AttemptStoreFull`]：清完过期项后仍达容量上限。
    pub fn insert(&mut self, attempt: LoginAttempt, now: OffsetDateTime) -> Result<(), OidcError> {
        if self.by_state.len() >= self.capacity {
            self.sweep_expired(now);
        }
        if self.by_state.len() >= self.capacity {
            return Err(OidcError::AttemptStoreFull);
        }
        self.by_state
            .insert(attempt.state.secret().clone(), attempt);
        Ok(())
    }

    /// 按回调带来的 `state` 取走这次尝试。
    ///
    /// # 为什么是「先取走，再校验」
    ///
    /// `remove` 在任何一条校验之前执行，于是**只要 `state` 命中过一次，它就被烧掉了**，
    /// 无论后续的过期 / provider 校验过不过。反过来（先校验后 remove）会留下一个可重试的
    /// 口子：攻击者拿一个已知 `state` 反复试不同的 provider，直到猜中发起时锁定的那个。
    /// 由 `a_failed_consume_still_burns_the_state` 钉住。
    ///
    /// # Errors
    ///
    /// - [`OidcError::AttemptUnknown`]：没有这条 `state`（「不存在」与「已用掉」共用同一个
    ///   码，见该变体的文档）；
    /// - [`OidcError::AttemptExpired`]：已过期；
    /// - [`OidcError::AttemptProviderMismatch`]：回调声称的 provider 不是发起时锁定的那个。
    pub fn consume(
        &mut self,
        state: &str,
        provider: &ProviderId,
        now: OffsetDateTime,
    ) -> Result<LoginAttempt, OidcError> {
        let attempt = self
            .by_state
            .remove(state)
            .ok_or(OidcError::AttemptUnknown)?;

        if attempt.is_expired(now) {
            return Err(OidcError::AttemptExpired);
        }
        if attempt.provider() != provider {
            return Err(OidcError::AttemptProviderMismatch);
        }
        Ok(attempt)
    }

    /// 清掉已过期的条目，返回清掉的条数。
    ///
    /// 需要被周期性调用：一次尝试如果没人拿着 `state` 回来，它永远等不到
    /// [`Self::consume`]。
    pub fn sweep_expired(&mut self, now: OffsetDateTime) -> usize {
        let before = self.by_state.len();
        self.by_state.retain(|_, attempt| !attempt.is_expired(now));
        before - self.by_state.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{LoginAttempt, LoginAttemptStore, PKCE_METHOD_S256, S256Pkce};
    use crate::auth::oidc::error::OidcError;
    use crate::auth::oidc::provider::ProviderId;
    use crate::auth::oidc::redirect::{CanonicalRedirectUri, HTTPS_ONLY};
    use openidconnect::{PkceCodeChallenge, PkceCodeVerifier};
    use time::{Duration, OffsetDateTime};

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn okta() -> ProviderId {
        ProviderId::parse("okta").unwrap()
    }

    fn callback() -> CanonicalRedirectUri {
        CanonicalRedirectUri::parse("https://app.example.com/auth/callback", HTTPS_ONLY).unwrap()
    }

    fn attempt_at(now: OffsetDateTime) -> LoginAttempt {
        LoginAttempt::begin(okta(), callback(), now, Duration::minutes(10))
    }

    /// 生成的 PKCE 恒为 S256，且 challenge 是 base64url 无填充的 SHA-256 摘要（43 字符）。
    #[test]
    fn generated_pkce_is_always_s256() {
        let pkce = S256Pkce::generate();
        assert_eq!(pkce.method(), PKCE_METHOD_S256);
        assert_eq!(
            pkce.challenge().len(),
            43,
            "SHA-256 摘要经 base64url 无填充编码恒为 43 字符"
        );
        assert!(
            pkce.challenge()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );

        // 两次生成互不相同 —— 否则「随机」是假的。
        assert_ne!(
            S256Pkce::generate().challenge(),
            S256Pkce::generate().challenge()
        );
    }

    /// 水合路径：`plain` 被拒，`S256` 被接受。
    ///
    /// 负向断言（拒 `plain`）与正向断言（收 `S256`）成对出现；缺了后者，前者在
    /// 「`from_parts` 恒返回 Err」的世界里同样通过。
    #[test]
    fn plain_is_refused_even_though_the_dependency_graph_already_makes_it_unbuildable() {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();

        // 负向：`plain`、小写 `s256`、空串、别的方法名一律拒。
        for bad in ["plain", "s256", "", "S512", "S256 "] {
            let (_, v) = PkceCodeChallenge::new_random_sha256();
            assert_eq!(
                S256Pkce::from_parts(challenge.as_str().to_owned(), bad, v).map(|_| ()),
                Err(OidcError::PkceMethodNotS256),
                "{bad:?} 应当被拒"
            );
        }

        // 正向：`S256` 收得进，且原样带出 challenge 与 verifier。
        let secret = verifier.secret().clone();
        let rebuilt = S256Pkce::from_parts(
            challenge.as_str().to_owned(),
            PKCE_METHOD_S256,
            PkceCodeVerifier::new(secret.clone()),
        )
        .expect("S256 必须收得进");
        assert_eq!(rebuilt.challenge(), challenge.as_str());
        assert_eq!(rebuilt.into_verifier().secret(), &secret);

        // 依赖图事实的正向对照：库自己只提供 S256 的随机构造器（`new_random_plain`
        // 在 `pkce-plain` feature 之后），所以这里拿到的 method 恒为 S256。
        assert_eq!(challenge.method().as_str(), PKCE_METHOD_S256);
    }

    /// 一次尝试的三个值互不相同、每次都新生成。
    #[test]
    fn state_nonce_and_verifier_are_freshly_minted_per_attempt() {
        let a = attempt_at(t0());
        let b = attempt_at(t0());

        assert_ne!(a.state().secret(), b.state().secret());
        assert_ne!(a.nonce().secret(), b.nonce().secret());
        assert_ne!(a.pkce().challenge(), b.pkce().challenge());
        // 三个值在同一次尝试里也互不相同（不是同一个随机数被复用三遍）。
        assert_ne!(a.state().secret(), a.nonce().secret());
        assert_ne!(a.state().secret().as_str(), a.pkce().challenge());
    }

    /// `state` 一次性：第一次取得走，第二次拿到 `AttemptUnknown`。
    #[test]
    fn a_state_can_be_consumed_exactly_once() {
        let mut store = LoginAttemptStore::with_capacity(16);
        let attempt = attempt_at(t0());
        let state = attempt.state().secret().clone();
        store.insert(attempt, t0()).unwrap();
        assert_eq!(store.len(), 1);

        // 正向：第一次成功。
        let taken = store
            .consume(&state, &okta(), t0() + Duration::minutes(1))
            .expect("首次必须成功");
        assert_eq!(taken.provider(), &okta());
        assert!(store.is_empty());

        // 负向：第二次不认。
        assert_eq!(
            store
                .consume(&state, &okta(), t0() + Duration::minutes(1))
                .map(|_| ()),
            Err(OidcError::AttemptUnknown)
        );
    }

    /// 不存在的 `state` 与已用掉的 `state` 给出**同一个**码。
    #[test]
    fn an_unknown_state_is_indistinguishable_from_a_used_one() {
        let mut store = LoginAttemptStore::with_capacity(16);
        let attempt = attempt_at(t0());
        let state = attempt.state().secret().clone();
        store.insert(attempt, t0()).unwrap();
        store.consume(&state, &okta(), t0()).unwrap();

        let used = store.consume(&state, &okta(), t0()).map(|_| ());
        let never_existed = store
            .consume("this-state-never-existed", &okta(), t0())
            .map(|_| ());
        assert_eq!(used, never_existed);
        assert_eq!(used, Err(OidcError::AttemptUnknown));
    }

    /// 过期即失效，边界取「到点就算过期」。
    #[test]
    fn an_attempt_expires_at_the_instant_its_ttl_runs_out() {
        let mut store = LoginAttemptStore::with_capacity(16);
        let attempt = attempt_at(t0());
        let state = attempt.state().secret().clone();
        let expires_at = attempt.expires_at();
        assert_eq!(expires_at, t0() + Duration::minutes(10));
        store.insert(attempt, t0()).unwrap();

        // 负向：到点即失效。
        assert_eq!(
            store.consume(&state, &okta(), expires_at).map(|_| ()),
            Err(OidcError::AttemptExpired)
        );

        // 正向对照：差一纳秒还活着 —— 否则上一条在「恒判过期」的世界里同样通过。
        let mut store2 = LoginAttemptStore::with_capacity(16);
        let attempt2 = attempt_at(t0());
        let state2 = attempt2.state().secret().clone();
        let expires_at2 = attempt2.expires_at();
        store2.insert(attempt2, t0()).unwrap();
        assert!(
            store2
                .consume(&state2, &okta(), expires_at2 - Duration::nanoseconds(1))
                .is_ok()
        );
    }

    /// `state` 绑定到发起时锁定的 provider。
    #[test]
    fn an_attempt_is_bound_to_the_provider_it_started_with() {
        let mut store = LoginAttemptStore::with_capacity(16);
        let attempt = attempt_at(t0());
        let state = attempt.state().secret().clone();
        store.insert(attempt, t0()).unwrap();

        let other = ProviderId::parse("google").unwrap();
        assert_eq!(
            store.consume(&state, &other, t0()).map(|_| ()),
            Err(OidcError::AttemptProviderMismatch)
        );
    }

    /// 校验失败的 `consume` 依然把 `state` 烧掉。
    ///
    /// 这是「先取走再校验」那条时序的可判定形式：第二次拿同一个 `state`（哪怕带上正确的
    /// provider）也只能拿到 `AttemptUnknown`，攻击者没有重试窗口。
    #[test]
    fn a_failed_consume_still_burns_the_state() {
        let mut store = LoginAttemptStore::with_capacity(16);
        let attempt = attempt_at(t0());
        let state = attempt.state().secret().clone();
        store.insert(attempt, t0()).unwrap();

        let wrong = ProviderId::parse("google").unwrap();
        assert_eq!(
            store.consume(&state, &wrong, t0()).map(|_| ()),
            Err(OidcError::AttemptProviderMismatch)
        );
        // 用对 provider 重试也没用了。
        assert_eq!(
            store.consume(&state, &okta(), t0()).map(|_| ()),
            Err(OidcError::AttemptUnknown)
        );
        assert!(store.is_empty());
    }

    /// 容量上限：满了先清过期，清不出来才拒。
    #[test]
    fn the_store_sweeps_before_it_refuses() {
        let mut store = LoginAttemptStore::with_capacity(2);
        store.insert(attempt_at(t0()), t0()).unwrap();
        store.insert(attempt_at(t0()), t0()).unwrap();

        // 负向：同一时刻满了就拒。
        assert_eq!(
            store.insert(attempt_at(t0()), t0()),
            Err(OidcError::AttemptStoreFull)
        );

        // 正向对照：等前两条过期之后，同一次 insert 会先清再放行。
        let later = t0() + Duration::minutes(11);
        assert_eq!(store.insert(attempt_at(later), later), Ok(()));
        assert_eq!(store.len(), 1, "两条过期项应当被清掉");
    }

    /// `sweep_expired` 只清过期的，不误伤在飞的。
    #[test]
    fn sweeping_removes_only_expired_entries() {
        let mut store = LoginAttemptStore::with_capacity(8);
        store.insert(attempt_at(t0()), t0()).unwrap();
        let fresh = t0() + Duration::minutes(9);
        store.insert(attempt_at(fresh), fresh).unwrap();

        let swept = store.sweep_expired(t0() + Duration::minutes(10));
        assert_eq!(swept, 1);
        assert_eq!(store.len(), 1, "还没到期的那条必须留下");

        // 正向对照：再往后走，剩下那条也会被清 —— 证明它不是「清不掉」。
        assert_eq!(store.sweep_expired(t0() + Duration::minutes(20)), 1);
        assert!(store.is_empty());
    }
}
