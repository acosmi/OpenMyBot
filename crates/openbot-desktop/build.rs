//! The product context is opt-in and only exists on the first supported Desktop host.

fn main() {
    println!("cargo:rerun-if-env-changed=WROK_BOT_DESKTOP_RELEASE_SHA256");
    println!("cargo:rerun-if-env-changed=WROK_BOT_PG_MAINTENANCE_BUNDLE_SHA256");
    #[cfg(feature = "postgres-maintenance")]
    if let Some(value) = std::env::var_os("WROK_BOT_PG_MAINTENANCE_BUNDLE_SHA256") {
        assert!(
            value.to_str().is_some_and(|s| s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "maintenance_bundle_binding_invalid"
        );
    }
    #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        build_macos_launcher();
    }
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
fn build_macos_launcher() {
    // Neither the Tauri CLI nor a parent's environment may add capabilities or a dev server.
    println!("cargo:rerun-if-env-changed=TAURI_CONFIG");
    assert!(
        std::env::var_os("TAURI_CONFIG").is_none(),
        "wrok_bot_tauri_override_denied"
    );
    for name in [
        "tauri.macos.conf.json",
        "tauri.macos.conf.json5",
        "Tauri.macos.toml",
    ] {
        println!("cargo:rerun-if-changed={name}");
        assert!(
            !std::path::Path::new(name).exists(),
            "wrok_bot_tauri_overlay_denied"
        );
    }
    if let Some(digest) = std::env::var_os("WROK_BOT_DESKTOP_RELEASE_SHA256") {
        let valid = digest.to_str().is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        assert!(valid, "wrok_bot_release_trust_invalid");
    }
    let app = tauri_build::AppManifest::new()
        .commands(&[
            "openbot_structured_events_open",
            "openbot_structured_events_close",
            "wrok_bot_window_chrome",
        ])
        // The generated command permissions above are the entire app permission surface.
        .permissions_path_pattern("permissions/no-additional-permissions/*.toml");
    let attributes = tauri_build::Attributes::new()
        .app_manifest(app)
        .capabilities_path_pattern("capabilities/desktop-main.json");
    assert!(
        tauri_build::try_build(attributes).is_ok(),
        "wrok_bot_tauri_context_build_failed"
    );
}
