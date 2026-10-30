//! Validated provider extension keys and one immutable assembly registration.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ProviderAdapter;

/// A provider extension key in the exact ASCII language `[a-z][a-z0-9_-]{0,31}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderExtensionKey(String);

impl ProviderExtensionKey {
    /// Validate without trimming or changing case.
    pub fn new(value: &str) -> Result<Self, ProviderExtensionKeyError> {
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 32
            || !bytes[0].is_ascii_lowercase()
            || !bytes[1..].iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        {
            return Err(ProviderExtensionKeyError);
        }
        Ok(Self(value.to_owned()))
    }

    /// Borrow the exact validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A key failed the fixed provider extension language.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("provider_extension_key_invalid")]
pub struct ProviderExtensionKeyError;

/// Invalid provider extension registration; no adapter configuration is retained in errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProviderExtensionsError {
    /// More than one adapter was registered under the same key.
    #[error("provider_extension_duplicate_key")]
    DuplicateKey,
    /// The assembly registration exceeded eight adapters.
    #[error("provider_extension_too_many_adapters")]
    TooManyAdapters,
}

/// Immutable adapters shared by the context loader and provider router of one assembly.
#[derive(Clone, Default)]
pub struct ProviderExtensions(Arc<BTreeMap<ProviderExtensionKey, Arc<dyn ProviderAdapter>>>);

impl ProviderExtensions {
    /// Build a unique registration containing at most eight adapters.
    #[doc(hidden)]
    pub fn try_new(
        entries: Vec<(ProviderExtensionKey, Arc<dyn ProviderAdapter>)>,
    ) -> Result<Self, ProviderExtensionsError> {
        if entries.len() > 8 {
            return Err(ProviderExtensionsError::TooManyAdapters);
        }
        let mut registered = BTreeMap::new();
        for (key, adapter) in entries {
            if registered.insert(key, adapter).is_some() {
                return Err(ProviderExtensionsError::DuplicateKey);
            }
        }
        Ok(Self(Arc::new(registered)))
    }

    /// Clone the adapter registered under this exact key, without any fallback.
    #[must_use]
    pub fn get(&self, key: &ProviderExtensionKey) -> Option<Arc<dyn ProviderAdapter>> {
        self.0.get(key).cloned()
    }

    /// Number of registered extension adapters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the assembly registered no extensions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for ProviderExtensions {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProviderExtensions")
            .field("count", &self.len())
            .finish()
    }
}
