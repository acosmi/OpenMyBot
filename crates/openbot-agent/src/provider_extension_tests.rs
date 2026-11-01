use super::*;
use openbot_application::{
    ProviderEvent, ProviderExtensionKey, ProviderExtensions, ProviderMessage, ProviderMessageRole,
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
#[derive(Default)]
struct Adapter {
    calls: AtomicUsize,
    requests: Mutex<Vec<ProviderRequest>>,
}
#[async_trait]
impl ProviderAdapter for Adapter {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().unwrap().push(request);
        Ok(Box::new(Session))
    }
}
struct Session;
#[async_trait]
impl ProviderSession for Session {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        Ok(Some(ProviderEvent::Completed))
    }
}
fn request(route: ProviderRoute) -> ProviderRequest {
    ProviderRequest {
        route,
        messages: vec![ProviderMessage {
            role: ProviderMessageRole::User,
            content: "bounded external text".into(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        }],
        tools: Vec::new(),
        max_output_tokens: Some(16),
        rate_card: None,
        cost_cap: None,
    }
}
#[tokio::test]
async fn registered_extension_selects_only_its_adapter() {
    let package = Arc::new(Adapter::default());
    let managed = Arc::new(Adapter::default());
    let extension = Arc::new(Adapter::default());
    let other = Arc::new(Adapter::default());
    let key = ProviderExtensionKey::new("fake_host").unwrap();
    let registry = ProviderExtensions::try_new(vec![
        (key.clone(), extension.clone()),
        (ProviderExtensionKey::new("other").unwrap(), other.clone()),
    ])
    .unwrap();
    let router =
        ProviderRouter::new(package.clone(), Some(managed.clone())).with_extensions(registry);
    let _ = router
        .start(request(ProviderRoute::Extension(key.clone())))
        .await
        .unwrap();
    assert_eq!(extension.calls.load(Ordering::SeqCst), 1);
    for unused in [package, managed, other] {
        assert_eq!(unused.calls.load(Ordering::SeqCst), 0);
    }
    let requests = extension.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let captured = &requests[0];
    assert_eq!(captured.route, ProviderRoute::Extension(key));
    assert!(captured.rate_card.is_none());
    assert!(captured.cost_cap.is_none());
    assert!(captured.tools.is_empty());
    assert_eq!(captured.messages.len(), 1);
    assert_eq!(captured.messages[0].content, "bounded external text");
    for secret in [
        "package-api-key",
        "managed-api-key",
        "custom-api-key",
        "environment-secret",
    ] {
        assert!(!format!("{captured:?}").contains(secret));
    }
}
#[tokio::test]
async fn unregistered_extension_never_falls_back() {
    let package = Arc::new(Adapter::default());
    let managed = Arc::new(Adapter::default());
    let custom = Arc::new(Adapter::default());
    let remote = Arc::new(Adapter::default());
    let router = ProviderRouter::new(package.clone(), Some(managed.clone()))
        .with_custom(custom.clone())
        .with_remote_agui(remote.clone());
    assert!(matches!(
        router
            .start(request(ProviderRoute::Extension(
                ProviderExtensionKey::new("missing").unwrap()
            )))
            .await,
        Err(ProviderPortError::Unavailable)
    ));
    for adapter in [package, managed, custom, remote] {
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn empty_extensions_preserve_original_routes() {
    let package = Arc::new(Adapter::default());
    let managed = Arc::new(Adapter::default());
    let legacy = ProviderRouter::new(package.clone(), Some(managed.clone()));
    let defaults = ProviderRouter::new(package.clone(), Some(managed.clone()))
        .with_extensions(ProviderExtensions::default());
    for route in [ProviderRoute::PackageOpenAi, ProviderRoute::Managed] {
        assert!(legacy.start(request(route.clone())).await.is_ok());
        assert!(defaults.start(request(route)).await.is_ok());
    }
    assert_eq!(package.calls.load(Ordering::SeqCst), 2);
    assert_eq!(managed.calls.load(Ordering::SeqCst), 2);
    assert!(matches!(
        ProviderRouter::new(package.clone(), None)
            .with_extensions(ProviderExtensions::default())
            .start(request(ProviderRoute::Managed))
            .await,
        Err(ProviderPortError::Unavailable)
    ));
    assert_eq!(package.calls.load(Ordering::SeqCst), 2);
}
