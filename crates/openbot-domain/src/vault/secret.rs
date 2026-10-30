//! 明文本身的容器：[`SecretClass`]（v3 §6.4 那份"永不外泄"清单）、[`SecretBytes`]
//! （drop 时清除当前 allocation 的字节缓冲）、[`SealedSecret`]（打不出来、序列化不出去的包装）。
//!
//! # 为什么复用 `openbot_contracts::telemetry::Redacted` 而不是造第二个
//!
//! `Redacted` 已经把三件事做对了，而且是**刻意**不实现某些 trait 换来的：`Debug` / `Display`
//! 只输出 [`Redacted` 的固定占位][openbot_contracts::telemetry::REDACTED_PLACEHOLDER]；
//! 没有 `Serialize` / `Deserialize`（能序列化就能顺着任何 DTO 流出去，等于没包）；没有
//! `PartialEq`（会得到一个非常数时间的比较）；没有 `Deref`（自动解引用会让
//! `format!("{}", secret)` 在某些语境下悄悄绕过包装）。
//!
//! 再造一个同类型，收益是零、风险是两份实现哪天漂开 —— 而"同一判据两份实现 = 恒不等的门"
//! 是本仓反复撞过的形态。所以 [`SealedSecret`] 把 `Redacted` 装在肚子里，只补它缺的两样：
//!
//! 1. **类别标签**。`Redacted<T>` 不知道自己包的是模型密钥还是 updater key，而 §6.4 的清单
//!    是**按类别**列的；出了事要答"这个部署持有哪几类不可外泄的值"，标签是唯一答得出的东西。
//!    标签本身不敏感（知道"这是一把模型密钥"泄不出密钥），所以它可以进 `Debug`，而且**应该**
//!    进 —— 一个全是 `[redacted]` 的日志行等于没有日志。
//! 2. **落地擦除**。`Redacted<T>` 的 `Drop` 就是 `T` 的 `Drop`，一个 `Vec<u8>` 被回收时内容
//!    原样留在堆上。[`SecretBytes`] 补这一层，代价与局限见它自己的文档。
//!
//! `Redacted` 缺的第三样是**按值取出**：它只有 `expose(&self) -> &T`，没有 `into_inner`。
//! 本模块不绕过这一点 —— [`SealedSecret`] 同样只借出不交出。对 vault 的用法这不构成限制：
//! AEAD 接口收的是 `&[u8]`。

use core::fmt;

use openbot_contracts::telemetry::{REDACTED_PLACEHOLDER, Redacted};
use subtle::ConstantTimeEq;

/// v3 §6.4 那份"永不外泄"清单的封闭枚举。
///
/// 原文逐字：「以下值永不进入 Leptos state、Agent prompt、AG-UI、browser event、普通日志、
/// trace、metric、crash dump 或 screen URL：model key、MCP/OAuth refresh token、OIDC/SAML
/// secret、computer bootstrap secret、run signing key、updater key。」
///
/// # 为什么是封闭枚举而不是一个字符串标签
///
/// 清单的价值在于**穷尽**：它要能回答"这个部署持有哪几类不可外泄的值"。一个自由字符串
/// 回答不了这个问题 —— 它只能回答"某人在某处写了什么"。封闭枚举让新增一类值成为一次
/// 编译期事件：所有按类别分派的地方当场红，而不是安静地落进 `_ =>` 分支。
///
/// 八个变体与 §6.4 的八项**一一对应**，由 [`SecretClass::ALL`] 与
/// `secret_class_covers_exactly_the_plan_list` 双向钉住。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretClass {
    /// 模型供应商的 API key（§6.4「model key」）。
    ///
    /// 上游存在 `credentials` 表 `kind = 'model'` 的行里；它是唯一一类会被 Agent 主循环在
    /// **每次采样**时用到的密钥，所以它离模型 prompt 只有一层调用之隔 —— 清单把它排在第一位
    /// 不是巧合。
    ModelKey,

    /// MCP / OAuth 的 refresh token（§6.4「MCP/OAuth refresh token」）。
    ///
    /// §9.4 逐字要求「禁止 token passthrough 到模型、GUI、Electron 或另一个 MCP server」，
    /// 而 refresh token 比 access token 更重：它能换出新的 access token，撤销之前一直有效。
    McpOAuthRefreshToken,

    /// 企业 IdP 的 OIDC client secret 或 SAML 签名材料（§6.4「OIDC/SAML secret」）。
    ///
    /// 上游落在 `sso_providers.oidc_config` / `saml_config` 两列里，由
    /// `server/src/auth/encrypt-sso-config.ts` 用**同一个** v1 信封加密 —— 见
    /// [`super::envelope`] 关于两张表共用一种信封的说明。
    SsoProviderSecret,

    /// computer（浏览器 / 桌面控制引擎）的 bootstrap secret（§6.4「computer bootstrap secret」）。
    ///
    /// 它是 Rust 与 browser engine shim 之间那条控制通道的凭据。泄漏它等于把"封闭输入"这条
    /// 边界（§2 允许的非 Rust 例外里那条「无任何业务裁决权」）交给任意进程。
    ComputerBootstrapSecret,

    /// run assertion 的签名密钥（§6.4「run signing key」）。
    ///
    /// §7.1：remote Agent「只能使用运行时给出的工具，并以 per-agent token + signed run
    /// assertion 回调 Rust」。泄漏它等于让任何人伪造一次 run 的身份。
    RunSigningKey,

    /// 发行物更新签名密钥（§6.4「updater key」）。
    ///
    /// 泄漏面最大的一类：它签的是**下一次所有用户会执行的字节**。
    UpdaterKey,

    /// 下游渠道的 bot token、app secret 或 webhook 签名凭据。
    ExternalChannelCredential,

    /// 下游宿主驱动与外部宿主之间的会话或控制凭据。
    HostDriverToken,
}

impl SecretClass {
    /// 全部八个变体，顺序与 §6.4 原文的列举顺序一致。
    ///
    /// 用它遍历而不是各处手抄 —— 手抄件会漂。
    pub const ALL: [Self; 8] = [
        Self::ModelKey,
        Self::McpOAuthRefreshToken,
        Self::SsoProviderSecret,
        Self::ComputerBootstrapSecret,
        Self::RunSigningKey,
        Self::UpdaterKey,
        Self::ExternalChannelCredential,
        Self::HostDriverToken,
    ];

    /// 稳定标识符。进审计、metrics label 与 `Debug` 输出。
    ///
    /// 是**标识符**不是文案（repository contract §4a）。取值刻意用 snake_case 的英文短语而不是枚举名，
    /// 好让它与 §6.4 原文的词一一对得上。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelKey => "model_key",
            Self::McpOAuthRefreshToken => "mcp_oauth_refresh_token",
            Self::SsoProviderSecret => "sso_provider_secret",
            Self::ComputerBootstrapSecret => "computer_bootstrap_secret",
            Self::RunSigningKey => "run_signing_key",
            Self::UpdaterKey => "updater_key",
            Self::ExternalChannelCredential => "external_channel_credential",
            Self::HostDriverToken => "host_driver_token",
        }
    }
}

impl fmt::Display for SecretClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一段明文字节，drop 时由 `zeroize` 擦除当前 allocation。
///
/// # 它保证什么，不保证什么
///
/// **保证**：`Debug` 只打 `[redacted]`；没有 `Serialize` / `Display` / `PartialEq`；
/// 没有 `Clone`（复制一份密钥就是多一份需要擦除的副本，而"多出来的那份在哪"很快就没人答得出，
/// 所以复制这件事必须写出 `SecretBytes::new(bytes.expose().to_vec())` 那么长一句，在 review 里
/// 是看得见的）；[`zeroize::Zeroizing`] 在 `Drop` 时清除 `Vec` 当前长度与整个
/// capacity，并用稳定 Rust 优化屏障保证这些写不被优化掉。
///
/// **不保证**：两处类型边界外的副本仍无法追回：
///
/// 1. `Vec` 在交给本类型**之前**若经历扩容，旧 allocation 可能留下内容。所以构造时应当一次给足
///    （[`SecretBytes::new`] 收的就是一个已经成型的 `Vec`），不要先建空的再 `push`。
/// 2. 调用方在把 `Vec` 交出来**之前**的那些副本（例如它是从一个更大的读缓冲里 `to_vec()`
///    出来的），本类型同样够不着。
pub struct SecretBytes(zeroize::Zeroizing<Vec<u8>>);

impl zeroize::ZeroizeOnDrop for SecretBytes {}

impl SecretBytes {
    /// 接管一段明文字节。
    ///
    /// 收 `Vec<u8>` 而不是 `&[u8]`：收引用意味着我们再复制一份，而调用方手里那份仍然存在且
    /// 不会被擦 —— 接口形状本身就该逼调用方交出所有权。
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// **显式**借出明文。
    ///
    /// 名字是 `expose` 不是 `as_slice`：调用点读起来就是一句"我在此处暴露明文"，grep 得到。
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// 明文字节数。
    ///
    /// 长度**不是**秘密（密文长度已经泄漏了它，见 [`super::envelope`]），所以它可以公开。
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空。上游允许加密空字符串（实测：空明文的 v1 密文恰好 16 字节 = 只有 tag）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 常数时间相等比较。
    ///
    /// 刻意不实现 `PartialEq`：`==` 在明文上会被写得到处都是，而 `Vec<u8>` 的 `==` 一旦发现
    /// 第一个不同的字节就返回。迁移的"校验回读"（[`super::rotation`]）比的正是两段明文，
    /// 那是一条攻击者可以反复触发的路径。
    ///
    /// 长度不同时 `subtle` 会短路返回 `false` —— 长度本来就不是秘密，见 [`Self::len`]。
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.expose().ct_eq(other.expose()).into()
    }
}

impl fmt::Debug for SecretBytes {
    /// 只打占位。与 `Redacted` 用同一个常量 —— 两处各写各的字符串就是两份会漂的实现。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_PLACEHOLDER)
    }
}

/// 带类别标签的密封值：打不出来、序列化不出去、只能显式 `expose`。
///
/// 泄漏的常见形态不是有人存心 `println!` 了一把密钥，而是某个含密钥字段的结构体被
/// `#[derive(Debug)]` 之后随手 `tracing::debug!(?config)` 出去了。本类型把"不能打印"变成
/// **类型属性**：包在里面的 `T` 无论实现了什么 trait，都不会经由 [`SealedSecret`] 泄出去。
///
/// 类别标签**进** `Debug`，理由见模块文档：它不敏感，而且是排障时唯一有用的那一半。
pub struct SealedSecret<T> {
    class: SecretClass,
    value: Redacted<T>,
}

impl<T> SealedSecret<T> {
    /// 密封一个值，并给它一个 §6.4 的类别。
    #[must_use]
    pub const fn seal(class: SecretClass, value: T) -> Self {
        Self {
            class,
            value: Redacted::new(value),
        }
    }

    /// 它是哪一类不可外泄的值。标签本身不敏感。
    #[must_use]
    pub const fn class(&self) -> SecretClass {
        self.class
    }

    /// **显式**借出被密封的值。
    ///
    /// 只借不给：`Redacted` 没有按值取出的入口，本类型不绕过它（模块文档末段）。
    #[must_use]
    pub fn expose(&self) -> &T {
        self.value.expose()
    }
}

impl<T> fmt::Debug for SealedSecret<T> {
    /// 形如 `SealedSecret(model_key, [redacted])`。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SealedSecret({}, {REDACTED_PLACEHOLDER})",
            self.class.as_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 探测 `T: Serialize` 是否成立，不需要 `T` 真的实现它。
    ///
    /// 手法照抄 `openbot-contracts` 的 `auth.rs::SerializeProbe`：一个 inherent 方法（更优先）
    /// 与一个 blanket trait 方法（兜底）同名，重载解析选中哪一个就答出 trait 有没有实现。
    struct SerializeProbe<T>(core::marker::PhantomData<T>);

    impl<T> SerializeProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<T: serde::Serialize> SerializeProbe<T> {
        fn is_implemented(&self) -> bool {
            true
        }
    }

    trait SerializeProbeFallback {
        fn is_implemented(&self) -> bool {
            false
        }
    }

    impl<T> SerializeProbeFallback for SerializeProbe<T> {}

    /// 同上，探测 `Clone`。
    struct CloneProbe<T>(core::marker::PhantomData<T>);

    impl<T> CloneProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<T: Clone> CloneProbe<T> {
        fn is_implemented(&self) -> bool {
            true
        }
    }

    trait CloneProbeFallback {
        fn is_implemented(&self) -> bool {
            false
        }
    }

    impl<T> CloneProbeFallback for CloneProbe<T> {}

    /// 负向对照：明文类型两个方向都不可序列化，也不可复制。
    #[test]
    fn secret_types_implement_neither_serialize_nor_clone() {
        assert!(
            !SerializeProbe::<SecretBytes>::new().is_implemented(),
            "SecretBytes 一旦可序列化，就能顺着任何 DTO 流进 §6.4 点名的那六个去处"
        );
        assert!(
            !SerializeProbe::<SealedSecret<String>>::new().is_implemented(),
            "SealedSecret 可序列化 = 包装形同虚设"
        );
        assert!(
            !CloneProbe::<SecretBytes>::new().is_implemented(),
            "复制一份明文就是多一份没人负责擦除的副本"
        );
    }

    /// 类型层明示承诺 drop 清零；内层 `Zeroizing<Vec<u8>>` 承担实际 Drop。
    #[test]
    fn secret_bytes_is_marked_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretBytes>();
    }

    /// **正向对照**：同一对探测器在确实实现了这些 trait 的类型上返回 `true`。
    ///
    /// 没有这一条，上一条测试在"探测器恒返回 false"的世界里同样通过 —— 那是一个什么都
    /// 证明不了的断言。
    #[test]
    fn probes_are_not_constant_false_detectors() {
        assert!(
            SerializeProbe::<String>::new().is_implemented(),
            "String 确实可序列化；否则探测器本身是坏的"
        );
        assert!(
            SerializeProbe::<LocallyDerivedSerializable>::new().is_implemented(),
            "本地 derive 的类型确实可序列化；否则探测器本身是坏的"
        );
        assert!(CloneProbe::<String>::new().is_implemented());
        assert!(CloneProbe::<SecretClass>::new().is_implemented());
    }

    /// 只为上面那条正向对照存在：一个**本模块自己 derive** 出来的可序列化类型。
    ///
    /// 用它而不是只用 `String`，是为了证明探测器认的是"这个类型实现了 `Serialize`"，
    /// 而不是碰巧对标准库类型为真。
    #[derive(serde::Serialize)]
    struct LocallyDerivedSerializable {
        #[allow(dead_code)]
        marker: u8,
    }

    /// `Debug` 一个字节的明文都不打出来 —— 正向对照是同一段明文确实在 `expose()` 里。
    #[test]
    fn debug_does_not_render_the_plaintext() {
        let plaintext = "sk-test-model-key-0001";
        let secret = SecretBytes::new(plaintext.as_bytes().to_vec());

        let rendered = format!("{secret:?}");
        assert_eq!(rendered, REDACTED_PLACEHOLDER);
        assert!(
            !rendered.contains("sk-test"),
            "Debug 输出里出现了明文片段：{rendered}"
        );
        // 正向对照：明文确实还在里面。否则上一条断言在"这个容器根本是空的"的世界里也成立。
        assert_eq!(secret.expose(), plaintext.as_bytes());
    }

    /// [`SealedSecret`] 的 `Debug` 带类别、不带值。
    #[test]
    fn sealed_debug_shows_class_but_not_value() {
        let sealed = SealedSecret::seal(SecretClass::UpdaterKey, String::from("hunter2"));

        let rendered = format!("{sealed:?}");
        assert_eq!(rendered, "SealedSecret(updater_key, [redacted])");
        assert!(!rendered.contains("hunter2"));
        // 正向对照：值确实在里面。
        assert_eq!(sealed.expose(), "hunter2");
        assert_eq!(sealed.class(), SecretClass::UpdaterKey);
    }

    /// `Redacted` 的 `Debug` 里塞进 [`SealedSecret`] 也不会把值抖出来 —— 嵌套不破防。
    #[test]
    fn nesting_a_sealed_secret_in_a_derived_debug_struct_still_redacts() {
        #[derive(Debug)]
        struct Config {
            #[allow(dead_code)]
            endpoint: &'static str,
            #[allow(dead_code)]
            key: SealedSecret<&'static str>,
        }

        let config = Config {
            endpoint: "https://example.invalid",
            key: SealedSecret::seal(SecretClass::ModelKey, "sk-live-DO-NOT-LOG"),
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("sk-live"), "{rendered}");
        assert!(rendered.contains("model_key"), "{rendered}");
        // 正向对照：这条 Debug 确实渲染了别的字段，不是恒空字符串。
        assert!(rendered.contains("https://example.invalid"), "{rendered}");
    }

    /// 八个类别与 §6.4 原文一一对应，且标识符两两不同。
    #[test]
    fn secret_class_covers_exactly_the_plan_list() {
        assert_eq!(SecretClass::ALL.len(), 8);

        let mut codes: Vec<&'static str> = SecretClass::ALL
            .iter()
            .copied()
            .map(SecretClass::as_str)
            .collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 8, "类别标识符必须两两不同");

        // 穷举 match：新增变体不改这里就编译不过，于是 ALL 的长度断言不会悄悄过时。
        for class in SecretClass::ALL {
            let expected = match class {
                SecretClass::ModelKey => "model_key",
                SecretClass::McpOAuthRefreshToken => "mcp_oauth_refresh_token",
                SecretClass::SsoProviderSecret => "sso_provider_secret",
                SecretClass::ComputerBootstrapSecret => "computer_bootstrap_secret",
                SecretClass::RunSigningKey => "run_signing_key",
                SecretClass::UpdaterKey => "updater_key",
                SecretClass::ExternalChannelCredential => "external_channel_credential",
                SecretClass::HostDriverToken => "host_driver_token",
            };
            assert_eq!(class.as_str(), expected);
            assert_eq!(class.to_string(), expected);
        }
    }

    /// 常数时间比较在相等 / 不等 / 长度不同三种输入上给出正确答案。
    ///
    /// 这条是 [`SecretBytes::ct_eq`] 的正向对照：一个恒返回 `false` 的比较器会让迁移的
    /// "校验回读"永远失败，而一个恒返回 `true` 的比较器会让它永远通过 —— 后者更危险，
    /// 所以两个方向都要测。
    #[test]
    fn ct_eq_answers_both_directions() {
        let a = SecretBytes::new(b"same-bytes".to_vec());
        let b = SecretBytes::new(b"same-bytes".to_vec());
        let c = SecretBytes::new(b"same-byteS".to_vec());
        let d = SecretBytes::new(b"same-bytes-longer".to_vec());

        assert!(a.ct_eq(&b), "相同内容必须判等");
        assert!(!a.ct_eq(&c), "只差一个 bit 也必须判不等");
        assert!(!a.ct_eq(&d), "长度不同必须判不等");
        assert!(
            SecretBytes::new(Vec::new()).ct_eq(&SecretBytes::new(Vec::new())),
            "两段空明文相等"
        );
    }
}
