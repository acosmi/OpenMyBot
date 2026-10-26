use super::*;
use openbot_server::config::transport::SingleUserRemoteTransportRefused;
use openbot_server::config::{
    EnvMap,
    launch::{LaunchError, prepare_environment},
};

fn environment(pairs: &[(&str, &str)]) -> EnvMap {
    pairs
        .iter()
        .map(|(key, value)| ((*key).into(), (*value).into()))
        .collect()
}

fn main_source() -> &'static str {
    // A source-level wiring audit, not an execution of the production startup or its PG prefix.
    include_str!("main.rs")
        .split_once("async fn main()")
        .unwrap()
        .1
        .split("#[cfg(test)]")
        .next()
        .unwrap()
}

#[test]
fn actual_provider_presence_keeps_existing_multi_user_selection() {
    let mut env = environment(&[
        ("OPENBOT_SINGLE_USER", "true"),
        ("OPENBOT_PUBLIC_URL", "https://public.example:443"),
        (
            "OPENBOT_TLS_PROXY_SECRET",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        (
            "OPENBOT_SESSION_SECRET",
            "owned-session-key-for-current-provider-configuration-only",
        ),
        ("INITIAL_ADMIN_EMAILS", "owner@example.test"),
    ]);
    let server = ServerConfig::from_env_map(&env).unwrap();
    // The bool is the existing dynamic-provider fact input; no database query is claimed here.
    let configured = auth_config_with_dynamic_provider(
        &env,
        server.public_url.as_ref().map(|url| url.as_str()),
        default_session_lifetime(),
        true,
    )
    .unwrap();
    assert!(configured.is_some());
    let actual = single_user_enabled(&env, configured.is_some()).unwrap();
    assert!(!actual);
    assert!(server.startup_transport_policy(actual).is_ok());

    env.remove("OPENBOT_SESSION_SECRET");
    let configured = auth_config_with_dynamic_provider(
        &env,
        server.public_url.as_ref().map(|url| url.as_str()),
        default_session_lifetime(),
        false,
    )
    .unwrap();
    assert!(configured.is_none());
    let actual = single_user_enabled(&env, configured.is_some()).unwrap();
    assert!(actual);
    assert_eq!(
        server.startup_transport_policy(actual).unwrap_err(),
        SingleUserRemoteTransportRefused
    );
    let error = single_user_enabled(&EnvMap::new(), false).unwrap_err();
    assert_eq!(error.problems()[0].code(), "single_user_not_requested");
}

#[test]
fn local_and_branded_aliases_feed_the_same_checked_transport_guard() {
    for public_url in [
        None,
        Some("http://localhost:3001"),
        Some("https://public.example"),
    ] {
        let mut branded = environment(&[("WROK_BOT_SINGLE_USER", "true")]);
        let mut legacy = environment(&[("OPENBOT_SINGLE_USER", "true")]);
        if let Some(url) = public_url {
            branded.insert("WROK_BOT_PUBLIC_URL".into(), url.into());
            legacy.insert("OPENBOT_PUBLIC_URL".into(), url.into());
        }
        let branded = prepare_environment(branded, false).unwrap();
        let legacy = prepare_environment(legacy, false).unwrap();
        assert_eq!(branded, legacy);
        let actual = single_user_enabled(&branded, false).unwrap();
        let one = ServerConfig::from_env_map(&branded)
            .unwrap()
            .startup_transport_policy(actual);
        let two = ServerConfig::from_env_map(&legacy)
            .unwrap()
            .startup_transport_policy(actual);
        assert_eq!(one.is_ok(), two.is_ok());
        assert_eq!(
            one.is_ok(),
            public_url.is_none_or(|url| url.starts_with("http://"))
        );
        if let Err(error) = one {
            assert_eq!(error.to_string(), "single_user_remote_transport_refused");
        }
    }
    for prefix in ["OPENBOT", "WROK_BOT"] {
        let mut env = EnvMap::new();
        env.insert(format!("{prefix}_SINGLE_USER"), "true".into());
        env.insert(
            format!("{prefix}_PUBLIC_URL"),
            "https://public.example:443".into(),
        );
        env.insert(
            format!("{prefix}_TLS_PROXY_SECRET"),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        );
        let env = prepare_environment(env, false).unwrap();
        assert!(
            ServerConfig::from_env_map(&env)
                .unwrap()
                .startup_transport_policy(single_user_enabled(&env, false).unwrap())
                .is_err()
        );
    }
    let local = prepare_environment(EnvMap::new(), true).unwrap();
    assert!(single_user_enabled(&local, false).unwrap());
    assert!(
        ServerConfig::from_env_map(&local)
            .unwrap()
            .startup_transport_policy(true)
            .is_ok()
    );
    let collision = prepare_environment(
        environment(&[
            ("WROK_BOT_TLS_PROXY_SECRET", "synthetic-canary"),
            ("OPENBOT_TLS_PROXY_SECRET", "synthetic-canary"),
        ]),
        false,
    )
    .unwrap_err();
    assert_eq!(collision, LaunchError::VariableCollision);
    assert!(!format!("{collision:?} {collision}").contains("synthetic-canary"));
}

#[test]
fn real_main_checks_actual_mode_before_single_user_auth_and_listener() {
    let source = main_source();
    let guard = "let transport_policy = server.startup_transport_policy(single_user)?;";
    assert_eq!(source.matches(guard).count(), 1);
    let guard_at = source.find(guard).unwrap();
    for earlier in [
        "let single_user = single_user_enabled(&env, has_provider)?;",
        "if local && !single_user",
    ] {
        assert!(source.find(earlier).unwrap() < guard_at);
    }
    for later in [
        "let environment_provider_ids",
        "initialize_single_user(&pool, single_user).await?;",
        "let (auth, sensitive, floor, oidc_login): AuthAssembly",
        "TcpListener::bind(&address).await?",
    ] {
        assert!(source.find(later).unwrap() > guard_at);
    }
    assert_eq!(
        source
            .matches(".with_transport_policy(transport_policy)")
            .count(),
        1
    );
    assert!(!source.contains(".with_transport_policy(server.transport_policy("));
    assert!(source.contains("let address = format!(\"127.0.0.1:{}\", server.port);"));
}

#[test]
fn startup_parse_auth_and_local_conflict_priorities_remain_unchanged() {
    let collision = prepare_environment(
        environment(&[
            ("WROK_BOT_SINGLE_USER", "true"),
            ("OPENBOT_SINGLE_USER", "true"),
        ]),
        false,
    )
    .unwrap_err();
    assert_eq!(collision, LaunchError::VariableCollision);
    assert_eq!(
        prepare_environment(environment(&[("OPENBOT_SINGLE_USER", "false")]), true).unwrap_err(),
        LaunchError::LocalModeConflict
    );
    let malformed = ServerConfig::from_env_map(&environment(&[
        ("OPENBOT_SINGLE_USER", "true"),
        ("PORT", "bad"),
        ("OPENBOT_PUBLIC_URL", "https://public.example"),
    ]))
    .unwrap_err();
    assert_eq!(malformed.problems()[0].code(), "malformed_env_var");
    assert_eq!(malformed.problems()[0].variable(), "PORT");
    let auth = auth_config_with_dynamic_provider(
        &environment(&[
            ("OPENBOT_SINGLE_USER", "true"),
            ("OPENBOT_SESSION_SECRET", "synthetic-canary"),
        ]),
        Some("https://public.example"),
        default_session_lifetime(),
        false,
    )
    .unwrap_err();
    assert_eq!(auth.problems()[0].code(), "session_secret_without_provider");
    assert!(!format!("{auth} {auth:?}").contains("synthetic-canary"));

    let source = main_source();
    let markers = [
        "prepare_environment(env_map_from_process(), local)?",
        "ServerConfig::from_env_map(&env)?",
        "pool::connect(&database).await?",
        "openbot_server::database::initialize(&pool).await?",
        "PolicyListener::start(",
        "KeyEncryptionKey::from_env_map(&env, key_policy)?",
        "database_has_dynamic_provider(&pool).await?",
        "auth_config_with_dynamic_provider(",
        "single_user_enabled(&env, has_provider)?",
        "if local && !single_user",
        "server.startup_transport_policy(single_user)?",
    ];
    let positions: Vec<_> = markers
        .iter()
        .map(|marker| source.find(marker).unwrap())
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    let local_conflict = source
        .find("return Err(openbot_server::config::launch::LaunchError::LocalModeConflict.into());")
        .unwrap();
    assert!(local_conflict < *positions.last().unwrap());
}
