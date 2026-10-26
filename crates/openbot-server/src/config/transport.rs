//! Public URL metadata and the closed request-level trusted-transport policy (R394).
//!
//! A declared HTTPS URL controls cookie attributes; it does not prove how a request arrived.
//! Business routes additionally require a verified loopback single-user connection or an explicit
//! same-machine HTTPS proxy secret plus exact forwarded authority/protocol. Other configurations
//! retain diagnostics but cannot authenticate users, issue sessions or perform actions. Single-user
//! startup additionally rejects any configuration that cannot select the loopback single-user mode.

use crate::config::address::{DeploymentAddress, Scheme};
use crate::config::{ConfigProblem, EnvMap, Expectation, Secret};

/// Explicit transport authority supplied by the host. Neither headers nor a public URL alone
/// can construct an accepted request. The production builder defaults to [`Self::deny`].
#[derive(Clone, Debug)]
pub struct TrustedTransportPolicy {
    pub(crate) mode: TrustedTransportMode,
}

#[derive(Clone, Debug)]
pub(crate) enum TrustedTransportMode {
    Deny,
    LoopbackSingleUser,
    LoopbackHttpsProxy {
        authority: String,
        secret: Secret,
    },
    #[cfg(any(test, feature = "testkit"))]
    TestOnlyUnchecked,
}

/// Single-user startup requires a loopback HTTP configuration without a proxy secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SingleUserRemoteTransportRefused;

impl core::fmt::Display for SingleUserRemoteTransportRefused {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("single_user_remote_transport_refused")
    }
}

impl core::fmt::Debug for SingleUserRemoteTransportRefused {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for SingleUserRemoteTransportRefused {}

impl TrustedTransportPolicy {
    /// Disable business and authentication routes while retaining non-sensitive diagnostics.
    #[must_use]
    pub const fn deny() -> Self {
        Self {
            mode: TrustedTransportMode::Deny,
        }
    }

    pub(crate) fn from_configuration(
        public_url: Option<&DeploymentAddress>,
        secret: Option<Secret>,
        single_user: bool,
    ) -> Self {
        if single_user {
            return if secret.is_none()
                && public_url
                    .is_none_or(|address| address.scheme() == Scheme::Http && address.is_loopback())
            {
                Self {
                    mode: TrustedTransportMode::LoopbackSingleUser,
                }
            } else {
                Self::deny()
            };
        }
        if let (Some(address), Some(secret)) = (public_url, secret.as_ref()) {
            if valid_proxy_secret(secret.expose())
                && let Some(authority) = proxy_authority(address)
            {
                return Self {
                    mode: TrustedTransportMode::LoopbackHttpsProxy {
                        authority,
                        secret: secret.clone(),
                    },
                };
            }
            return Self::deny();
        }
        Self::deny()
    }

    pub(crate) const fn builder_default() -> Self {
        #[cfg(any(test, feature = "testkit"))]
        {
            // Existing in-memory transport fixtures have no socket. This variant is absent from
            // the default production feature graph; main always supplies a configuration-derived policy.
            Self {
                mode: TrustedTransportMode::TestOnlyUnchecked,
            }
        }
        #[cfg(not(any(test, feature = "testkit")))]
        {
            Self::deny()
        }
    }
}

fn valid_proxy_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Preserve the configured authority byte-for-byte, including an explicit default port, after
/// parsing with the already locked URL dependency. Userinfo and ambiguous forwarding values deny.
fn proxy_authority(address: &DeploymentAddress) -> Option<String> {
    let parsed = url::Url::parse(address.as_str()).ok()?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let (_, rest) = address.as_str().split_once("://")?;
    let authority = rest.split('/').next()?;
    if authority.is_empty()
        || authority.len() > 512
        || !authority.is_ascii()
        || authority.bytes().any(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'@' | b',' | b';' | b'\\' | b'?' | b'#')
        })
    {
        return None;
    }
    Some(authority.to_owned())
}

pub(crate) fn parse_tls_proxy_secret(
    env: &EnvMap,
    public_url: Option<&DeploymentAddress>,
    problems: &mut Vec<ConfigProblem>,
) -> Option<Secret> {
    let raw = env.get("OPENBOT_TLS_PROXY_SECRET")?;
    if !valid_proxy_secret(raw) {
        problems.push(ConfigProblem::Malformed {
            variable: "OPENBOT_TLS_PROXY_SECRET",
            expectation: Expectation::TlsProxySecret,
        });
        return None;
    }
    if public_url.and_then(proxy_authority).is_none() {
        problems.push(ConfigProblem::Malformed {
            variable: "OPENBOT_PUBLIC_URL",
            expectation: Expectation::HttpsProxyPublicUrl,
        });
        return None;
    }
    Some(Secret::new(raw.clone()))
}

/// 这个部署的公共传输长什么样。四态，理由见模块文档。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicTransport {
    /// `OPENBOT_PUBLIC_URL` 是 `https`。
    Https,
    /// `OPENBOT_PUBLIC_URL` 是 `http`，且 host 只能从本机到达。
    LoopbackHttp,
    /// `OPENBOT_PUBLIC_URL` 是 `http`，host 不是 loopback；业务请求必须拒绝。
    PublicHttp,
    /// 没有配 `OPENBOT_PUBLIC_URL`。
    Unconfigured,
}

impl PublicTransport {
    /// 由公共地址判定档位。**纯函数**，除入参外不看任何东西。
    #[must_use]
    pub fn classify(public_url: Option<&DeploymentAddress>) -> Self {
        match public_url {
            None => Self::Unconfigured,
            Some(address) => match address.scheme() {
                Scheme::Https => Self::Https,
                Scheme::Http if address.is_loopback() => Self::LoopbackHttp,
                Scheme::Http => Self::PublicHttp,
            },
        }
    }

    /// session cookie 要不要带 `Secure`。
    ///
    /// **只有 [`PublicTransport::Https`] 为真** —— 在别的档位上加 `Secure`，
    /// 得到的是一个浏览器不肯回传的 cookie，症状是登录后回到登录页。
    #[must_use]
    pub const fn cookie_secure(self) -> bool {
        matches!(self, Self::Https)
    }

    /// `/health` readiness 要不要附 `insecure_transport: true`（v3 §6.3）。
    #[must_use]
    pub const fn insecure_transport(self) -> bool {
        matches!(self, Self::PublicHttp)
    }

    /// 启动日志要不要说点什么，以及说什么。
    ///
    /// 返回 `&'static str` 而不是拼好的串：文案里不能出现任何配置值
    /// （理由同 [`crate::config::error`] 模块文档 —— 它会进日志）。
    #[must_use]
    pub const fn startup_warning(self) -> Option<&'static str> {
        match self {
            Self::Https | Self::LoopbackHttp => None,
            Self::PublicHttp => Some(
                "OPENBOT_PUBLIC_URL 是明文 http 且不是 loopback：session cookie 不会带 Secure，\
                 业务请求被可信传输入口拒绝。请配置受信 HTTPS 代理。",
            ),
            Self::Unconfigured => Some(
                "未配置 OPENBOT_PUBLIC_URL：本部署没有对外公共地址，OAuth 回调与连接器授权\
                 无法生成 redirect URI。若这是本机单用户部署，请确认绑定在 loopback 上。",
            ),
        }
    }

    /// 稳定的线上取值，供 readiness 响应体与日志使用。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::LoopbackHttp => "loopback_http",
            Self::PublicHttp => "public_http",
            Self::Unconfigured => "unconfigured",
        }
    }
}

#[cfg(test)]
#[path = "single_user_transport_tests.rs"]
mod single_user_transport_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn address(raw: &str) -> DeploymentAddress {
        DeploymentAddress::parse(raw).expect("测试地址必须合法")
    }

    #[test]
    fn proxy_configuration_requires_exact_secret_and_https_authority_without_leaking_values() {
        let secret = "a".repeat(64);
        let config = |url: Option<&str>, value: &str| {
            let mut env = EnvMap::new();
            if let Some(url) = url {
                env.insert("OPENBOT_PUBLIC_URL".into(), url.into());
            }
            env.insert("OPENBOT_TLS_PROXY_SECRET".into(), value.into());
            crate::config::ServerConfig::from_env_map(&env)
        };
        let valid = config(Some("https://example.test:443"), &secret).unwrap();
        assert!(
            matches!(valid.transport_policy(false).mode, TrustedTransportMode::LoopbackHttpsProxy { ref authority, .. } if authority == "example.test:443")
        );
        assert!(!format!("{valid:?}").contains(&secret));
        for bad in [
            "".to_owned(),
            "a".repeat(63),
            "A".repeat(64),
            "g".repeat(64),
            format!(" {secret}"),
        ] {
            assert!(config(Some("https://example.test"), &bad).is_err());
        }
        for bad in [
            None,
            Some("http://example.test"),
            Some("https://user:password@example.test"),
            Some("https://example.test?x=1"),
            Some("https://example.test#x"),
            Some("https://example.test:70000"),
            Some("https://example.test\\other"),
        ] {
            let error = config(bad, &secret).unwrap_err();
            assert!(!format!("{error:?} {error}").contains(&secret));
        }
    }

    #[test]
    fn missing_proxy_proof_never_falls_back_to_remote_plaintext() {
        for url in [
            None,
            Some(address("https://example.test")),
            Some(address("http://example.test")),
        ] {
            assert!(matches!(
                TrustedTransportPolicy::from_configuration(url.as_ref(), None, false).mode,
                TrustedTransportMode::Deny
            ));
        }
        assert!(matches!(
            TrustedTransportPolicy::from_configuration(None, None, true).mode,
            TrustedTransportMode::LoopbackSingleUser
        ));
        assert!(matches!(
            TrustedTransportPolicy::from_configuration(
                Some(&address("http://localhost:3001")),
                None,
                true
            )
            .mode,
            TrustedTransportMode::LoopbackSingleUser
        ));
        assert!(matches!(
            TrustedTransportPolicy::from_configuration(
                Some(&address("https://example.test")),
                None,
                true
            )
            .mode,
            TrustedTransportMode::Deny
        ));
        assert!(matches!(
            TrustedTransportPolicy::from_configuration(
                Some(&address("http://example.test")),
                None,
                true
            )
            .mode,
            TrustedTransportMode::Deny
        ));
    }

    /// 任务点名的三种情形：https / loopback http / 非 loopback http。
    ///
    /// 三条一起断言，因为它们互为对照：任何一个"恒返回同一档"的实现都会在这里红。
    #[test]
    fn the_three_shapes_land_in_three_different_places() {
        assert_eq!(
            PublicTransport::classify(Some(&address("https://openbot.example.com"))),
            PublicTransport::Https
        );
        assert_eq!(
            PublicTransport::classify(Some(&address("http://localhost:3001"))),
            PublicTransport::LoopbackHttp
        );
        assert_eq!(
            PublicTransport::classify(Some(&address("http://openbot.example.com"))),
            PublicTransport::PublicHttp
        );
        // 第四档：没配。
        assert_eq!(
            PublicTransport::classify(None),
            PublicTransport::Unconfigured
        );
    }

    /// `Secure` 当且仅当 https。
    #[test]
    fn secure_is_set_exactly_when_the_scheme_is_https() {
        assert!(PublicTransport::Https.cookie_secure());
        // 负向：其余三档都不加 —— 加了就是一个浏览器不肯回传的 cookie。
        assert!(!PublicTransport::LoopbackHttp.cookie_secure());
        assert!(!PublicTransport::PublicHttp.cookie_secure());
        assert!(!PublicTransport::Unconfigured.cookie_secure());
    }

    /// `insecure_transport` 只在"真实暴露的明文"那一档点亮。
    #[test]
    fn only_a_genuinely_exposed_plaintext_deployment_raises_the_flag() {
        assert!(PublicTransport::PublicHttp.insecure_transport());
        // 负向对照三条。loopback 那条是本组的重点：把它也点亮，
        // 这盏灯就会在每台开发机上常亮，从而在真出事那天没人看。
        assert!(!PublicTransport::Https.insecure_transport());
        assert!(!PublicTransport::LoopbackHttp.insecure_transport());
        assert!(!PublicTransport::Unconfigured.insecure_transport());
    }

    /// 两档有话说，两档没有 —— 且说的话里不含任何配置值。
    #[test]
    fn warnings_exist_exactly_where_they_are_earned() {
        assert!(PublicTransport::Https.startup_warning().is_none());
        assert!(PublicTransport::LoopbackHttp.startup_warning().is_none());

        let exposed = PublicTransport::PublicHttp
            .startup_warning()
            .expect("暴露的明文部署必须被点名");
        assert!(exposed.contains("Secure"), "{exposed}");

        let unconfigured = PublicTransport::Unconfigured
            .startup_warning()
            .expect("没配公共地址也要说出来");
        assert!(
            unconfigured.contains("OPENBOT_PUBLIC_URL"),
            "{unconfigured}"
        );
    }

    /// 四个线上取值两两不同 —— 折叠掉任何一档，这里当场红。
    #[test]
    fn four_states_are_pairwise_distinct_on_the_wire() {
        let all = [
            PublicTransport::Https,
            PublicTransport::LoopbackHttp,
            PublicTransport::PublicHttp,
            PublicTransport::Unconfigured,
        ];
        for (index, left) in all.iter().enumerate() {
            for right in &all[index + 1..] {
                assert_ne!(left.as_str(), right.as_str(), "线上取值撞了");
            }
        }
    }

    /// 两个问题确实是两个问题：存在一档 `Secure` 与 `insecure_transport` **同时为假**。
    ///
    /// 这条把"能不能压成布尔"钉死：如果能，那么 `insecure = !secure` 恒成立，
    /// 而 loopback 明文这一档正是反例。
    #[test]
    fn the_two_questions_cannot_be_collapsed_into_one_boolean() {
        let loopback = PublicTransport::LoopbackHttp;
        assert!(!loopback.cookie_secure());
        assert!(!loopback.insecure_transport());
        // 正向对照：确实存在一档两者相反，否则上一条在"两个函数恒返回 false"
        // 的世界里同样通过。
        assert!(PublicTransport::Https.cookie_secure());
        assert!(PublicTransport::PublicHttp.insecure_transport());
    }
}
