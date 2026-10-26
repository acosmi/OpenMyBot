use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    ProviderAdapter, ProviderExtensionKey, ProviderExtensionKeyError, ProviderExtensions,
    ProviderExtensionsError, ProviderPortError, ProviderRequest, ProviderSession,
};

#[derive(Debug)]
struct FakeAdapter {
    configuration: &'static str,
}

#[async_trait]
impl ProviderAdapter for FakeAdapter {
    async fn start(
        &self,
        _request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        panic!("registration must not start an adapter")
    }
}

fn adapter() -> Arc<dyn ProviderAdapter> {
    Arc::new(FakeAdapter {
        configuration: "private-adapter-configuration",
    })
}

fn key(value: &str) -> ProviderExtensionKey {
    ProviderExtensionKey::new(value).unwrap()
}

#[test]
fn key_language_and_boundaries_are_exact() {
    for value in ["a", "z", "a0", "a-b_c9", &"a".repeat(32)] {
        assert_eq!(key(value).as_str(), value);
    }
    for value in ["", "A", "0a", "_a", "-a", " a", "a ", "aé", "é"] {
        assert_eq!(
            ProviderExtensionKey::new(value),
            Err(ProviderExtensionKeyError)
        );
    }
    assert_eq!(
        ProviderExtensionKey::new(&"a".repeat(33)),
        Err(ProviderExtensionKeyError)
    );
    for byte in 0_u8..=127 {
        let first = String::from(char::from(byte));
        assert_eq!(
            ProviderExtensionKey::new(&first).is_ok(),
            byte.is_ascii_lowercase(),
            "first byte {byte}"
        );
        let tail = format!("a{}", char::from(byte));
        assert_eq!(
            ProviderExtensionKey::new(&tail).is_ok(),
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-'),
            "tail byte {byte}"
        );
    }
    assert_eq!(
        ProviderExtensionKeyError.to_string(),
        "provider_extension_key_invalid"
    );
    assert_eq!(key("a-b_c9").clone(), key("a-b_c9"));
    assert!(format!("{:?}", key("a-b_c9")).contains("a-b_c9"));
}

#[test]
fn registry_rejects_duplicate_and_ninth_key() {
    let empty = ProviderExtensions::try_new(Vec::new()).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert!(empty.get(&key("missing")).is_none());
    let single = ProviderExtensions::try_new(vec![(key("one"), adapter())]).unwrap();
    assert_eq!(single.len(), 1);
    assert!(single.get(&key("one")).is_some());
    assert!(single.get(&key("missing")).is_none());
    let entries = || {
        (0..8)
            .map(|index| (key(&format!("key_{index}")), adapter()))
            .collect::<Vec<_>>()
    };
    let full = ProviderExtensions::try_new(entries()).unwrap();
    assert_eq!(full.len(), 8);
    for index in 0..8 {
        assert!(full.get(&key(&format!("key_{index}"))).is_some());
    }
    assert!(matches!(
        ProviderExtensions::try_new(vec![(key("same"), adapter()), (key("same"), adapter())]),
        Err(ProviderExtensionsError::DuplicateKey)
    ));
    let mut ninth = entries();
    ninth.push((key("ninth"), adapter()));
    assert!(matches!(
        ProviderExtensions::try_new(ninth),
        Err(ProviderExtensionsError::TooManyAdapters)
    ));
}

#[test]
fn registry_debug_and_clones_are_immutable() {
    let fake = FakeAdapter {
        configuration: "private-adapter-configuration",
    };
    assert!(format!("{fake:?}").contains(fake.configuration));
    let original: Arc<dyn ProviderAdapter> = Arc::new(fake);
    let mut input = vec![(key("private_key"), original.clone())];
    let registry = ProviderExtensions::try_new(input.clone()).unwrap();
    let cloned = registry.clone();
    input.clear();
    input.push((key("replacement"), adapter()));
    assert_eq!(registry.len(), 1);
    assert_eq!(cloned.len(), 1);
    assert!(!registry.is_empty());
    assert!(Arc::ptr_eq(
        &registry.get(&key("private_key")).unwrap(),
        &original
    ));
    assert!(Arc::ptr_eq(
        &cloned.get(&key("private_key")).unwrap(),
        &original
    ));
    assert!(registry.get(&key("replacement")).is_none());
    assert!(cloned.get(&key("replacement")).is_none());
    let rendered = format!("{registry:?}");
    assert_eq!(rendered, "ProviderExtensions { count: 1 }");
    assert_eq!(format!("{cloned:?}"), rendered);
    assert!(!rendered.contains("private_key"));
    assert!(!rendered.contains("FakeAdapter"));
    assert!(!rendered.contains("private-adapter-configuration"));
    assert!(ProviderExtensions::default().is_empty());
}
