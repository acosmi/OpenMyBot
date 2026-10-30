//! Route only validated PostgreSQL context: Bot configuration or a frozen personal selection.

use std::sync::Arc;

use async_trait::async_trait;
use openbot_application::{
    ProviderAdapter, ProviderPortError, ProviderRequest, ProviderRoute, ProviderSession,
};

/// One Agent runtime dispatches an explicit authoritative route without implicit fallback.
pub struct ProviderRouter {
    extensions: openbot_application::ProviderExtensions,
    package_openai: Arc<dyn ProviderAdapter>,
    managed: Option<Arc<dyn ProviderAdapter>>,
    remote_agui: Option<Arc<dyn ProviderAdapter>>,
    custom: Option<Arc<dyn ProviderAdapter>>,
}

impl ProviderRouter {
    /// Construct with mandatory package OpenAI and optional deployment-managed adapter。
    #[must_use]
    pub fn new(
        package_openai: Arc<dyn ProviderAdapter>,
        managed: Option<Arc<dyn ProviderAdapter>>,
    ) -> Self {
        Self {
            extensions: Default::default(),
            package_openai,
            managed,
            remote_agui: None,
            custom: None,
        }
    }

    /// Use the immutable registry returned by this application's assembly.
    #[must_use]
    pub fn with_extensions(mut self, extensions: openbot_application::ProviderExtensions) -> Self {
        self.extensions = extensions;
        self
    }

    /// Attach the remote AG-UI semantic adapter. Missing means remote routes fail closed.
    #[must_use]
    pub fn with_remote_agui(mut self, remote: Arc<dyn ProviderAdapter>) -> Self {
        self.remote_agui = Some(remote);
        self
    }

    /// Attach the shared PostgreSQL/Vault adapter; absence never falls back or retries.
    #[must_use]
    pub fn with_custom(mut self, custom: Arc<dyn ProviderAdapter>) -> Self {
        self.custom = Some(custom);
        self
    }
}

impl core::fmt::Debug for ProviderRouter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderRouter")
            .field("package_openai", &"configured/[redacted]")
            .field("extensions", &self.extensions.len())
            .field("managed", &self.managed.is_some())
            .field("remote_agui", &self.remote_agui.is_some())
            .field("custom", &self.custom.is_some())
            .finish()
    }
}

#[async_trait]
impl ProviderAdapter for ProviderRouter {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        match &request.route {
            ProviderRoute::Extension(key) => match self.extensions.get(key) {
                Some(provider) => provider.start(request).await,
                None => Err(ProviderPortError::Unavailable),
            },
            ProviderRoute::CustomModel(_) => match &self.custom {
                Some(provider) => provider.start(request).await,
                None => Err(ProviderPortError::InvalidRequest {
                    field: "custom_model_unavailable",
                }),
            },
            ProviderRoute::PackageOpenAi => self.package_openai.start(request).await,
            ProviderRoute::Managed => match &self.managed {
                Some(provider) => provider.start(request).await,
                None => Err(ProviderPortError::Unavailable),
            },
            ProviderRoute::RemoteAgUi(_) => match &self.remote_agui {
                Some(provider) => provider.start(request).await,
                None => Err(ProviderPortError::Unavailable),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use openbot_application::{ProviderEvent, ProviderMessage, ProviderMessageRole};

    use super::*;

    struct CountingProvider {
        id: &'static str,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ProviderAdapter for CountingProvider {
        async fn start(
            &self,
            _request: ProviderRequest,
        ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(OneEvent(Some(ProviderEvent::ResponseStarted {
                response_id: self.id.to_owned(),
            }))))
        }
    }

    struct OneEvent(Option<ProviderEvent>);

    #[async_trait]
    impl ProviderSession for OneEvent {
        async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
            Ok(self.0.take())
        }
    }

    fn request(route: ProviderRoute) -> ProviderRequest {
        ProviderRequest {
            route,
            messages: vec![ProviderMessage {
                role: ProviderMessageRole::User,
                content: "hello".to_owned(),
                tool_call_id: None,
                tool_name: None,
                tool_calls: Vec::new(),
            }],
            tools: Vec::new(),
            max_output_tokens: None,
            rate_card: None,
            cost_cap: None,
        }
    }

    #[tokio::test]
    async fn authoritative_route_selects_exactly_one_adapter() {
        let package = Arc::new(CountingProvider {
            id: "package",
            calls: AtomicUsize::new(0),
        });
        let managed = Arc::new(CountingProvider {
            id: "managed",
            calls: AtomicUsize::new(0),
        });
        let router = ProviderRouter::new(package.clone(), Some(managed.clone()));
        let mut package_session = router
            .start(request(ProviderRoute::PackageOpenAi))
            .await
            .unwrap();
        let mut managed_session = router.start(request(ProviderRoute::Managed)).await.unwrap();
        assert!(matches!(
            package_session.next_event().await.unwrap(),
            Some(ProviderEvent::ResponseStarted { response_id }) if response_id == "package"
        ));
        assert!(matches!(
            managed_session.next_event().await.unwrap(),
            Some(ProviderEvent::ResponseStarted { response_id }) if response_id == "managed"
        ));
        assert_eq!(package.calls.load(Ordering::SeqCst), 1);
        assert_eq!(managed.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn missing_managed_adapter_never_falls_back_to_package_openai() {
        let package = Arc::new(CountingProvider {
            id: "package",
            calls: AtomicUsize::new(0),
        });
        let router = ProviderRouter::new(package.clone(), None);
        assert!(matches!(
            router.start(request(ProviderRoute::Managed)).await,
            Err(ProviderPortError::Unavailable)
        ));
        assert_eq!(package.calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
#[path = "provider_extension_tests.rs"]
mod provider_extension_tests;
