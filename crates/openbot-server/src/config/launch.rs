//! Wrok Bot 启动入口。品牌变量只在此翻译一次，业务解析器继续共享原有契约。
//!
//! `--local` 显式选择独立本机实例，不改写既有部署的默认租户或权限。

use core::fmt;

use super::env::{self, EnvMap};
use super::server::DEFAULT_PORT;

/// 新本机实例使用的第一方租户包；不包含必须预置凭据的 managed Agent。
pub const LOCAL_PACKAGE_DIRECTORY: &str = "examples/wrok-bot";

/// 新品牌配置与兼容解析器字段的唯一映射。厂商自己的 OPENAI/BOT 变量保持原协议。
const VARIABLES: &[(&str, &str)] = &[
    ("WROK_BOT_ARTIFACT_ROOT", "OPENBOT_ARTIFACT_ROOT"),
    ("WROK_BOT_APP_DIST_DIR", "APP_DIST_DIR"),
    ("WROK_BOT_APP_URL", "OPENBOT_APP_URL"),
    ("WROK_BOT_DATABASE_URL", "DATABASE_URL"),
    ("WROK_BOT_DEPLOYMENT_ID", "DEPLOYMENT_ID"),
    ("WROK_BOT_ENV", "OPENBOT_ENV"),
    ("WROK_BOT_KEY_ENCRYPTION_KEY", "KEY_ENCRYPTION_KEY"),
    ("WROK_BOT_PORT", "PORT"),
    (
        "WROK_BOT_PROVIDER_ALLOW_HTTP",
        "OPENBOT_PROVIDER_ALLOW_HTTP",
    ),
    (
        "WROK_BOT_PROVIDER_EGRESS_ALLOW_CIDRS",
        "OPENBOT_PROVIDER_EGRESS_ALLOW_CIDRS",
    ),
    (
        "WROK_BOT_PROVIDER_MAX_OUTPUT_TOKENS",
        "OPENBOT_PROVIDER_MAX_OUTPUT_TOKENS",
    ),
    ("WROK_BOT_PUBLIC_URL", "OPENBOT_PUBLIC_URL"),
    ("WROK_BOT_RUN_DEADLINE_MS", "OPENBOT_RUN_DEADLINE_MS"),
    ("WROK_BOT_SESSION_SECRET", "OPENBOT_SESSION_SECRET"),
    ("WROK_BOT_SINGLE_USER", "OPENBOT_SINGLE_USER"),
    ("WROK_BOT_TLS_PROXY_SECRET", "OPENBOT_TLS_PROXY_SECRET"),
    ("WROK_BOT_TENANT_PACKAGE_DIR", "TENANT_PACKAGE_DIR"),
    ("WROK_BOT_TRUSTED_ORIGINS", "TRUSTED_ORIGINS"),
];

/// 无动态载荷的启动失败；输入值、密钥与路径不会进入错误文本。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchError {
    /// 新旧配置同时存在，拒绝任选一份。
    VariableCollision,
    /// 未知品牌配置，避免安全选项拼错后静默失效。
    UnknownVariable,
    /// 显式本机模式与禁用单用户的配置冲突。
    LocalModeConflict,
    /// 本机自动 Origin 需要一个实际、非零端口。
    LocalPortInvalid,
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::VariableCollision => "wrok_bot_env_collision",
            Self::UnknownVariable => "wrok_bot_env_unknown",
            Self::LocalModeConflict => "wrok_bot_local_mode_conflict",
            Self::LocalPortInvalid => "wrok_bot_local_port_invalid",
        })
    }
}

impl std::error::Error for LaunchError {}

/// 消费唯一环境快照，将新品牌字段移动到兼容解析器；不读取/修改进程环境。
///
/// 本机模式仅填充未配置项，仍需要真实 PG 与持久 Vault key，仍执行原安全校验。
pub fn prepare_environment(mut input: EnvMap, local: bool) -> Result<EnvMap, LaunchError> {
    for name in input.keys().filter(|name| name.starts_with("WROK_BOT_")) {
        if name == "WROK_BOT_RECOVERY_CONFIG" {
            continue;
        }
        let Some((_, legacy)) = VARIABLES.iter().find(|(brand, _)| *brand == name) else {
            return Err(LaunchError::UnknownVariable);
        };
        if input.contains_key(*legacy) {
            return Err(LaunchError::VariableCollision);
        }
    }
    for &(brand, legacy) in VARIABLES {
        if let Some(value) = input.remove(brand) {
            input.insert(legacy.to_owned(), value);
        }
    }
    if !local {
        return Ok(input);
    }
    if input.contains_key("OPENBOT_SINGLE_USER")
        && env::optional(&input, "OPENBOT_SINGLE_USER") != Some("true")
    {
        return Err(LaunchError::LocalModeConflict);
    }
    let port = match env::optional(&input, "PORT") {
        Some(raw) => raw
            .parse::<u16>()
            .map_err(|_| LaunchError::LocalPortInvalid)?,
        None => DEFAULT_PORT,
    };
    if port == 0 {
        return Err(LaunchError::LocalPortInvalid);
    }
    input.insert("OPENBOT_SINGLE_USER".to_owned(), "true".to_owned());
    if env::optional(&input, "TENANT_PACKAGE_DIR").is_none() {
        input.insert(
            "TENANT_PACKAGE_DIR".to_owned(),
            LOCAL_PACKAGE_DIRECTORY.to_owned(),
        );
    }
    if env::optional(&input, "TRUSTED_ORIGINS").is_none() {
        input.insert(
            "TRUSTED_ORIGINS".to_owned(),
            format!("http://127.0.0.1:{port},http://localhost:{port}"),
        );
    }
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, &str)]) -> EnvMap {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    #[test]
    fn fresh_local_start_needs_no_managed_provider_or_implicit_allow_policy() {
        let env = prepare_environment(EnvMap::new(), true).unwrap();
        assert_eq!(
            env.get("TENANT_PACKAGE_DIR").unwrap(),
            LOCAL_PACKAGE_DIRECTORY
        );
        assert_eq!(env.get("OPENBOT_SINGLE_USER").unwrap(), "true");
        assert_eq!(
            env.get("TRUSTED_ORIGINS").unwrap(),
            "http://127.0.0.1:3001,http://localhost:3001"
        );
        let config = super::super::ServerConfig::from_env_map(&env).unwrap();
        assert!(config.computer.is_none());
        assert!(config.managed_provider.is_none());
        assert!(config.package_openai_provider.environment_api_key.is_none());
        assert!(!env.contains_key("KEY_ENCRYPTION_KEY"));
        assert!(!env.contains_key("DATABASE_URL"));
    }

    #[test]
    fn local_package_loads_without_environment_credentials_or_remote_slots() {
        use openbot_application::tenant::package::{
            BuiltInProviderSource, TenantAgentConfiguration, TenantPackageEnvironment,
        };
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(LOCAL_PACKAGE_DIRECTORY);
        let loaded =
            openbot_infra::tenant::load_tenant_package(&root, &TenantPackageEnvironment::default())
                .unwrap();
        assert_eq!(loaded.package.tenant_id, "wrok-bot-local");
        assert_eq!(loaded.package.agents.len(), 1);
        assert!(matches!(
            loaded.package.agents[0].configuration,
            TenantAgentConfiguration::BuiltIn {
                provider_source: BuiltInProviderSource::Package,
                ..
            }
        ));
        assert_eq!(loaded.package.channels.len(), 1);
        assert!(loaded.package.knowledge_sources.is_empty());
    }

    #[test]
    fn existing_deployment_is_unchanged_unless_local_was_explicitly_selected() {
        let original = values(&[
            ("DEPLOYMENT_ID", "existing"),
            ("TENANT_PACKAGE_DIR", "/mounted/tenant"),
        ]);
        assert_eq!(
            prepare_environment(original.clone(), false).unwrap(),
            original
        );
        let local = prepare_environment(original, true).unwrap();
        assert_eq!(local.get("DEPLOYMENT_ID").unwrap(), "existing");
        assert_eq!(local.get("TENANT_PACKAGE_DIR").unwrap(), "/mounted/tenant");
    }

    #[test]
    fn blank_local_defaults_do_not_fall_back_to_the_legacy_package_or_origin() {
        let input = values(&[
            ("WROK_BOT_TENANT_PACKAGE_DIR", " \u{feff}"),
            ("WROK_BOT_TRUSTED_ORIGINS", " "),
        ]);
        assert_eq!(
            prepare_environment(input, true).unwrap(),
            prepare_environment(EnvMap::new(), true).unwrap()
        );
    }

    #[test]
    fn each_brand_variable_moves_its_value_once_and_retains_legacy_migration_rejections() {
        for &(brand, legacy) in VARIABLES {
            let expected = values(&[(legacy, "exact-value"), ("UNRELATED", "retained")]);
            let actual = prepare_environment(
                values(&[(brand, "exact-value"), ("UNRELATED", "retained")]),
                false,
            )
            .unwrap();
            assert_eq!(actual, expected, "{brand}");
        }
        let retired = prepare_environment(
            values(&[("WROK_BOT_ENV", "production"), ("AGENT_TOOL_TOKEN", "")]),
            false,
        )
        .unwrap();
        assert!(super::super::ServerConfig::from_env_map(&retired).is_err());
    }

    #[test]
    fn brand_fields_reach_the_existing_validators_and_collisions_never_choose_a_value() {
        let input = values(&[
            ("WROK_BOT_PORT", "3210"),
            ("WROK_BOT_RUN_DEADLINE_MS", "9000"),
        ]);
        let mapped = prepare_environment(input, true).unwrap();
        let config = super::super::ServerConfig::from_env_map(&mapped).unwrap();
        assert_eq!(config.port, 3210);
        assert_eq!(
            config.agent_budgets.run_deadline,
            Some(std::time::Duration::from_secs(9))
        );
        assert_eq!(
            mapped.get("TRUSTED_ORIGINS").unwrap(),
            "http://127.0.0.1:3210,http://localhost:3210"
        );
        for (brand, legacy) in VARIABLES {
            let collision = values(&[(brand, "secret-canary"), (legacy, "secret-canary")]);
            let err = prepare_environment(collision, false).unwrap_err();
            assert_eq!(err, LaunchError::VariableCollision);
            assert!(!format!("{err:?} {err}").contains("secret-canary"));
        }
        let malformed =
            prepare_environment(values(&[("WROK_BOT_RUN_DEADLINE_MS", "invalid")]), false).unwrap();
        assert!(super::super::ServerConfig::from_env_map(&malformed).is_err());
    }

    #[test]
    fn typo_disabled_single_user_and_ephemeral_local_port_fail_closed() {
        assert_eq!(
            prepare_environment(values(&[("WROK_BOT_SINGEL_USER", "true")]), false),
            Err(LaunchError::UnknownVariable)
        );
        for value in ["false", "", "TRUE"] {
            assert_eq!(
                prepare_environment(values(&[("WROK_BOT_SINGLE_USER", value)]), true),
                Err(LaunchError::LocalModeConflict)
            );
        }
        for port in ["0", "65536", "3001extra"] {
            assert_eq!(
                prepare_environment(values(&[("WROK_BOT_PORT", port)]), true),
                Err(LaunchError::LocalPortInvalid)
            );
        }
    }
}
