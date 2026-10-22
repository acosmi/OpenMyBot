//! Brand-independent native Webview lifecycle assembly.
//!
//! This module deliberately does not define a product name, bundle identifier, deep-link scheme,
//! capability file, or release binary. It closes the reusable host edge that can be implemented
//! before those reviewed release inputs exist: bind verified Rust authority before local content
//! can load, create one locked-down Webview, roll authority back when creation fails, and unbind
//! only after Tauri reports [`WindowEvent::Destroyed`].

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openbot_contracts::auth::AuthContext;
use tauri::webview::NewWindowResponse;
use tauri::{
    Builder, Manager, Runtime, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent,
};

use crate::tauri_host::{DesktopTauriProtocol, TauriHostError, valid_scheme};

/// Authority already derived by Rust from a verified local/remote session.
///
/// The renderer cannot construct or send this type. The constructor name is intentionally an
/// assertion at the host call site, matching [`openbot_contracts::auth::AuthContextBuilder`].
pub struct VerifiedDesktopWindowAuthority {
    auth: AuthContext,
    fresh_for: Option<Duration>,
    self_owned_capture_fixture: bool,
}

impl VerifiedDesktopWindowAuthority {
    /// Wrap an [`AuthContext`] that the host obtained from its verified session source.
    #[must_use]
    pub const fn from_verified_session(auth: AuthContext, fresh_for: Option<Duration>) -> Self {
        Self {
            auth,
            fresh_for,
            self_owned_capture_fixture: false,
        }
    }

    // The opaque witness can only originate in the fixed original fixture factory.
    // This flag changes the WebKit datastore policy; it is not capture/Ready authority.
    #[cfg(all(
        target_os = "macos",
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        debug_assertions
    ))]
    pub(crate) fn from_self_owned_fixture(
        auth: AuthContext,
        fixture: &crate::tauri_background::SelfOwnedCaptureFixtureBinding,
    ) -> Result<Self, DesktopWindowLifecycleError> {
        fixture.require_window_witness().map_err(|_| DesktopWindowLifecycleError::RegistryUnavailable)?;
        Ok(Self {
            auth,
            fresh_for: None,
            self_owned_capture_fixture: true,
        })
    }
}

/// Stable native-window assembly failure without leaking platform paths or WebView diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum DesktopWindowLifecycleError {
    /// Existing protocol authority/binding operation failed.
    #[error(transparent)]
    Host(#[from] TauriHostError),
    /// The validated custom scheme could not form its local start URL.
    #[error("desktop_window_start_url_invalid")]
    InvalidStartUrl,
    /// Tauri/Wry rejected actual window creation; authority was rolled back first.
    #[error("desktop_window_build_failed")]
    WindowBuildFailed,
    /// The host's own active-window registry became unavailable.
    #[error("desktop_window_registry_unavailable")]
    RegistryUnavailable,
}

impl DesktopWindowLifecycleError {
    fn stable_code(&self) -> &'static str {
        match self {
            Self::Host(_) => "desktop_window_host_failed",
            Self::InvalidStartUrl => "desktop_window_start_url_invalid",
            Self::WindowBuildFailed => "desktop_window_build_failed",
            Self::RegistryUnavailable => "desktop_window_registry_unavailable",
        }
    }
}

/// One protocol plus the actual native windows created through its verified host path.
pub struct DesktopWindowLifecycle {
    protocol: Arc<DesktopTauriProtocol>,
    scheme: Arc<str>,
    active: Mutex<BTreeSet<String>>,
}

impl DesktopWindowLifecycle {
    /// Construct the lifecycle for an already selected internal custom protocol.
    pub fn new(
        scheme: &str,
        protocol: Arc<DesktopTauriProtocol>,
    ) -> Result<Self, DesktopWindowLifecycleError> {
        if !valid_scheme(scheme) {
            return Err(TauriHostError::InvalidScheme.into());
        }
        Ok(Self {
            protocol,
            scheme: Arc::from(scheme),
            active: Mutex::new(BTreeSet::new()),
        })
    }

    /// Create one actual Tauri Webview after binding host-verified authority.
    ///
    /// Security defaults are closed here rather than left to a future `tauri.conf`: production
    /// devtools are disabled, top-level navigation accepts only this exact custom scheme on the
    /// `localhost` authority, `window.open` is denied, and downloads are denied until a typed host
    /// journey exists. If Tauri rejects the label/window, the prior authority binding is removed
    /// before this method returns an error.
    pub fn create_verified_window<R, M>(
        &self,
        manager: &M,
        label: impl Into<String>,
        authority: VerifiedDesktopWindowAuthority,
    ) -> Result<WebviewWindow<R>, DesktopWindowLifecycleError>
    where
        R: Runtime,
        M: Manager<R>,
    {
        let label = label.into();
        let start_url = Url::parse(&format!("{}://localhost/", self.scheme))
            .map_err(|_| DesktopWindowLifecycleError::InvalidStartUrl)?;
        let navigation_scheme = Arc::clone(&self.scheme);

        let self_owned_capture_fixture = authority.self_owned_capture_fixture;
        self.protocol
            .bind_window(label.clone(), authority.auth, authority.fresh_for)?;
        let builder = WebviewWindowBuilder::new(
            manager,
            label.clone(),
            WebviewUrl::CustomProtocol(start_url),
        )
        .title(manager.package_info().name.clone())
        .devtools(false)
        .on_navigation(move |url| allows_local_navigation(&navigation_scheme, url))
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .on_download(|_, _| false);
        #[cfg(target_os = "macos")]
        let builder = builder
            .title_bar_style(tauri::TitleBarStyle::Overlay)
            .hidden_title(true);
        let builder = if self_owned_capture_fixture {
            builder.incognito(true)
        } else {
            builder
        };
        let built = builder.build();

        let window = match built {
            Ok(window) => window,
            Err(_) => {
                self.protocol.unbind_window(&label)?;
                return Err(DesktopWindowLifecycleError::WindowBuildFailed);
            }
        };

        let inserted = self
            .active
            .lock()
            .map(|mut active| active.insert(label.clone()));
        match inserted {
            Ok(true) => Ok(window),
            Ok(false) | Err(_) => {
                let _ = window.destroy();
                self.protocol.unbind_window(&label)?;
                Err(DesktopWindowLifecycleError::RegistryUnavailable)
            }
        }
    }

    /// Consume a Tauri window event. Only `Destroyed` removes authority: `CloseRequested` can be
    /// prevented by another handler and therefore is not proof that the Webview is gone.
    pub fn handle_window_event(
        &self,
        label: &str,
        event: &WindowEvent,
    ) -> Result<bool, DesktopWindowLifecycleError> {
        if matches!(event, WindowEvent::Destroyed) {
            return self.unbind_destroyed(label);
        }
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        if matches!(event, WindowEvent::Focused(false)) {
            // Native NSWindow focus loss clears existing grants, including all old authority
            // clones. A system authentication dialog may itself cause blur, so this does not
            // cancel the in-progress native confirmation or replace its binding.
            self.protocol.clear_window_confirmation(label)?;
        }
        Ok(false)
    }

    /// Remove one destroyed window's authority and every structured subscription it owned.
    pub fn unbind_destroyed(&self, label: &str) -> Result<bool, DesktopWindowLifecycleError> {
        let unbound = self.protocol.unbind_window(label)?;
        self.active
            .lock()
            .map_err(|_| DesktopWindowLifecycleError::RegistryUnavailable)?
            .remove(label);
        Ok(unbound)
    }

    /// Revoke authority for every native window before app shutdown.
    pub fn shutdown_authority(&self) -> Result<usize, DesktopWindowLifecycleError> {
        self.protocol.close_request_bindings();
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        self.protocol.shutdown_local_confirmation();
        let labels = self
            .active
            .lock()
            .map_err(|_| DesktopWindowLifecycleError::RegistryUnavailable)?
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut unbound = 0;
        for label in labels {
            if self.unbind_destroyed(&label)? {
                unbound += 1;
            }
        }
        Ok(unbound)
    }

    #[cfg(feature = "desktop-local-runtime")]
    pub(crate) async fn wait_local_confirmation_stopped(&self) {
        #[cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]
        self.protocol.wait_local_confirmation_stopped().await;
    }

    /// Number of actual windows still owned by this lifecycle.
    #[must_use]
    pub fn active_window_count(&self) -> usize {
        self.active
            .lock()
            .expect("desktop window lifecycle registry must not be poisoned")
            .len()
    }
}

/// Manage one lifecycle in Tauri and exact-unbind on the real `Destroyed` event.
pub fn register_tauri_window_lifecycle<R: Runtime>(
    builder: Builder<R>,
    lifecycle: Arc<DesktopWindowLifecycle>,
) -> Builder<R> {
    let event_lifecycle = Arc::clone(&lifecycle);
    builder
        .manage(lifecycle)
        .on_window_event(move |window, event| {
            if let Err(error) = event_lifecycle.handle_window_event(window.label(), event) {
                tracing::error!(
                    code = error.stable_code(),
                    "native window authority cleanup failed"
                );
            }
        })
}

const WINDOWS_HTTP_WORKAROUND: bool = cfg!(target_os = "windows");

fn allows_local_navigation(scheme: &str, url: &Url) -> bool {
    allows_local_navigation_for(WINDOWS_HTTP_WORKAROUND, scheme, url)
}

fn allows_local_navigation_for(
    windows_http_workaround: bool,
    custom_scheme: &str,
    url: &Url,
) -> bool {
    let authority_is_closed =
        url.username().is_empty() && url.password().is_none() && url.port().is_none();
    let native = url.scheme() == custom_scheme && url.host_str() == Some("localhost");
    let windows_host = format!("{custom_scheme}.localhost");
    let windows_workaround = windows_http_workaround
        && url.scheme() == "http"
        && url.host_str() == Some(windows_host.as_str());
    authority_is_closed && (native || windows_workaround)
}

#[cfg(test)]
mod tests {
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use async_trait::async_trait;
    use openbot_application::{AppEventStream, ApplicationService};
    use openbot_contracts::auth::AuthContext;
    use openbot_contracts::command::{
        AppCommand, AppEvent, AppReply, HealthReport, SubscriptionRequest,
    };
    use openbot_contracts::error::AppError;
    use tauri::Manager;

    use super::*;
    use crate::InProcessTransport;
    use crate::testing::auth_for;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct EmptyStream(VecDeque<AppEvent>);

    impl futures_core::Stream for EmptyStream {
        type Item = AppEvent;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    struct NoopService;

    #[async_trait]
    impl ApplicationService for NoopService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(HealthReport { ok: true }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Ok(Box::pin(EmptyStream(VecDeque::new())))
        }
    }

    fn protocol_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "openbot-tauri-lifecycle-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("index.html"),
            "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>",
        )
        .unwrap();
        fs::write(root.join("openbot-bootstrap.mjs"), "export {};").unwrap();
        root
    }

    fn lifecycle() -> (
        Arc<DesktopWindowLifecycle>,
        Arc<DesktopTauriProtocol>,
        PathBuf,
    ) {
        let root = protocol_root();
        let transport = Arc::new(InProcessTransport::new(Arc::new(NoopService)));
        let protocol = Arc::new(DesktopTauriProtocol::open(&root, transport).unwrap());
        (
            Arc::new(DesktopWindowLifecycle::new("openbot", Arc::clone(&protocol)).unwrap()),
            protocol,
            root,
        )
    }

    #[test]
    fn navigation_is_exactly_the_platform_internal_custom_origin() {
        for allowed in [
            "openbot://localhost/",
            "openbot://localhost/channel/id?x=1#message",
        ] {
            assert!(allows_local_navigation(
                "openbot",
                &Url::parse(allowed).unwrap()
            ));
        }
        for rejected in [
            "https://localhost/",
            "openbot://remote.invalid/",
            "openbot://user@localhost/",
            "openbot://localhost:444/",
            "other://localhost/",
            "file:///tmp/secret",
        ] {
            assert!(
                !allows_local_navigation("openbot", &Url::parse(rejected).unwrap()),
                "navigation unexpectedly allowed: {rejected}"
            );
        }
        assert!(allows_local_navigation_for(
            true,
            "openbot",
            &Url::parse("http://openbot.localhost/channel/id").unwrap(),
        ));
        for rejected in [
            "https://openbot.localhost/",
            "http://openbot.localhost:81/",
            "http://user@openbot.localhost/",
            "http://other.localhost/",
        ] {
            assert!(
                !allows_local_navigation_for(true, "openbot", &Url::parse(rejected).unwrap(),),
                "Windows workaround unexpectedly allowed: {rejected}"
            );
        }
        assert!(!allows_local_navigation_for(
            false,
            "openbot",
            &Url::parse("http://openbot.localhost/").unwrap(),
        ));
    }

    #[test]
    fn mock_runtime_creates_bound_local_window_and_destroyed_event_unbinds_it() {
        let (lifecycle, protocol, root) = lifecycle();
        let app =
            register_tauri_window_lifecycle(tauri::test::mock_builder(), Arc::clone(&lifecycle))
                .build(tauri::test::mock_context(tauri::test::noop_assets()))
                .unwrap();
        assert!(app.try_state::<Arc<DesktopWindowLifecycle>>().is_some());

        let window = lifecycle
            .create_verified_window(
                &app,
                "main",
                VerifiedDesktopWindowAuthority::from_verified_session(auth_for("actor-1"), None),
            )
            .unwrap();
        assert_eq!(window.label(), "main");
        assert_eq!(window.url().unwrap().as_str(), "openbot://localhost/");
        assert_eq!(lifecycle.active_window_count(), 1);
        assert!(protocol.is_window_bound("main").unwrap());

        assert!(
            !lifecycle
                .handle_window_event("main", &WindowEvent::Focused(false))
                .unwrap()
        );
        assert!(protocol.is_window_bound("main").unwrap());

        assert!(
            lifecycle
                .handle_window_event("main", &WindowEvent::Destroyed)
                .unwrap()
        );
        assert_eq!(lifecycle.active_window_count(), 0);
        assert!(!protocol.is_window_bound("main").unwrap());
        assert!(
            !lifecycle
                .handle_window_event("main", &WindowEvent::Destroyed)
                .unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_tauri_label_rolls_back_authority_and_shutdown_unbinds_every_window() {
        let (lifecycle, protocol, root) = lifecycle();
        let app = tauri::test::mock_app();
        assert!(matches!(
            lifecycle.create_verified_window(
                &app,
                "bad label",
                VerifiedDesktopWindowAuthority::from_verified_session(auth_for("actor-1"), None),
            ),
            Err(DesktopWindowLifecycleError::WindowBuildFailed)
        ));
        assert_eq!(lifecycle.active_window_count(), 0);
        assert!(!protocol.is_window_bound("bad label").unwrap());

        for label in ["main", "auxiliary"] {
            lifecycle
                .create_verified_window(
                    &app,
                    label,
                    VerifiedDesktopWindowAuthority::from_verified_session(
                        auth_for("actor-1"),
                        None,
                    ),
                )
                .unwrap();
        }
        assert_eq!(protocol.bound_window_count().unwrap(), 2);
        assert_eq!(lifecycle.shutdown_authority().unwrap(), 2);
        assert_eq!(lifecycle.active_window_count(), 0);
        assert_eq!(protocol.bound_window_count().unwrap(), 0);
        fs::remove_dir_all(root).unwrap();
    }
}
