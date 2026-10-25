use super::*;
use std::time::{Duration, UNIX_EPOCH};

fn source(external: bool, id: &str) -> DelegationSource {
    if external {
        DelegationSource::ExternalBinding {
            binding_id: id.into(),
        }
    } else {
        DelegationSource::AutomationDefinition {
            definition_id: id.into(),
        }
    }
}

fn grant() -> VerifiedDelegation {
    VerifiedDelegation::from_verified_grant(
        source(false, "definition"),
        7,
        "trigger".into(),
        AuthGeneration::new(9),
        None,
    )
    .unwrap()
}

fn carrier(delegation: VerifiedDelegation) -> AuthContext {
    AuthContextBuilder::from_verified_delegation(
        DeploymentId::new("deployment"),
        TenantId::new("tenant"),
        ActorId::new("owner"),
        AuthGeneration::new(9),
        false,
        delegation,
    )
    .with_role(Role::User)
    .build()
}

#[test]
fn delegation_identifier_shapes_accept_exact_ascii_boundaries() {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-";
    for external in [false, true] {
        for id in ["a".into(), "z".repeat(128), alphabet.into()] {
            assert!(
                VerifiedDelegation::from_verified_grant(
                    source(external, &id),
                    0,
                    id,
                    AuthGeneration::new(0),
                    None
                )
                .is_ok()
            );
        }
        for bad in [
            String::new(),
            "a".repeat(129),
            "é".into(),
            " ".into(),
            "\t".into(),
            "\n".into(),
            "\0".into(),
            "/".into(),
        ] {
            let source_error = VerifiedDelegation::from_verified_grant(
                source(external, &bad),
                0,
                "trigger".into(),
                AuthGeneration::new(0),
                None,
            )
            .unwrap_err();
            let trigger_error = VerifiedDelegation::from_verified_grant(
                source(external, "source"),
                0,
                bad,
                AuthGeneration::new(0),
                None,
            )
            .unwrap_err();
            assert_eq!(source_error, DelegationShapeError::InvalidSourceIdentifier);
            assert_eq!(
                trigger_error,
                DelegationShapeError::InvalidTriggerIdentifier
            );
            assert_eq!(
                source_error.to_string(),
                "invalid_delegation_source_identifier"
            );
            assert_eq!(
                trigger_error.to_string(),
                "invalid_delegation_trigger_identifier"
            );
            assert_eq!(format!("{source_error:?}"), "InvalidSourceIdentifier");
            assert_eq!(format!("{trigger_error:?}"), "InvalidTriggerIdentifier");
        }
    }
}

#[test]
fn verified_grant_getters_preserve_all_five_facts_without_validity_inference() {
    for external in [false, true] {
        for revision in [0, u64::MAX] {
            for generation in [0, u64::MAX] {
                for expiry in [
                    None,
                    Some(UNIX_EPOCH),
                    Some(UNIX_EPOCH + Duration::from_secs(10_000_000_000)),
                ] {
                    let origin = source(external, "source");
                    let value = VerifiedDelegation::from_verified_grant(
                        origin.clone(),
                        revision,
                        "trigger".into(),
                        AuthGeneration::new(generation),
                        expiry,
                    )
                    .unwrap();
                    assert_eq!(value.source(), &origin);
                    assert_eq!(value.revision(), revision);
                    assert_eq!(value.trigger_id(), "trigger");
                    assert_eq!(value.granted_generation(), AuthGeneration::new(generation));
                    assert_eq!(value.expires_at(), expiry);
                }
            }
        }
    }
}

struct SerializeProbe<T>(core::marker::PhantomData<T>);
impl<T: Serialize> SerializeProbe<T> {
    fn implemented(&self) -> bool {
        true
    }
}
trait SerializeFallback {
    fn implemented(&self) -> bool {
        false
    }
}
impl<T> SerializeFallback for SerializeProbe<T> {}
struct DeserializeProbe<T>(core::marker::PhantomData<T>);
impl<T: serde::de::DeserializeOwned> DeserializeProbe<T> {
    fn implemented(&self) -> bool {
        true
    }
}
trait DeserializeFallback {
    fn implemented(&self) -> bool {
        false
    }
}
impl<T> DeserializeFallback for DeserializeProbe<T> {}

#[test]
fn delegation_and_auth_carriers_remain_nonserde() {
    assert!(SerializeProbe::<String>(core::marker::PhantomData).implemented());
    assert!(DeserializeProbe::<String>(core::marker::PhantomData).implemented());
    assert!(!SerializeProbe::<VerifiedDelegation>(core::marker::PhantomData).implemented());
    assert!(!DeserializeProbe::<VerifiedDelegation>(core::marker::PhantomData).implemented());
    assert!(!SerializeProbe::<DelegationSource>(core::marker::PhantomData).implemented());
    assert!(!DeserializeProbe::<DelegationSource>(core::marker::PhantomData).implemented());
    assert!(!SerializeProbe::<AuthContext>(core::marker::PhantomData).implemented());
    assert!(!DeserializeProbe::<AuthContext>(core::marker::PhantomData).implemented());
}

#[test]
fn delegation_debug_exposes_only_kind_revision_and_presence() {
    for external in [false, true] {
        let delegation = VerifiedDelegation::from_verified_grant(
            source(external, "source_canary"),
            23,
            "trigger_canary".into(),
            AuthGeneration::new(987654321),
            Some(UNIX_EPOCH + Duration::from_secs(123456789)),
        )
        .unwrap();
        let kind = if external {
            "ExternalBinding"
        } else {
            "AutomationDefinition"
        };
        assert_eq!(format!("{:?}", delegation.source()), kind);
        assert_eq!(
            format!("{delegation:?}"),
            format!("VerifiedDelegation {{ source: {kind}, revision: 23 }}")
        );
        let debug = format!("{:?}", carrier(delegation));
        assert!(debug.contains("delegation_present: true"));
        for forbidden in [
            "source_canary",
            "trigger_canary",
            "987654321",
            "123456789",
            "VerifiedDelegation",
            kind,
            "expires_at",
            "granted_generation",
        ] {
            assert!(!debug.contains(forbidden), "{forbidden}");
        }
    }
}

#[test]
fn auth_equality_distinguishes_every_delegation_fact() {
    let value = grant();
    let base = carrier(value.clone());
    assert_eq!(base, base.clone());
    let ordinary = AuthContextBuilder::from_verified_session(
        DeploymentId::new("deployment"),
        TenantId::new("tenant"),
        ActorId::new("owner"),
        AuthGeneration::new(9),
        false,
    )
    .with_role(Role::User)
    .build();
    assert_ne!(base, ordinary);
    for changed in [
        VerifiedDelegation {
            source: source(false, "other"),
            ..value.clone()
        },
        VerifiedDelegation {
            source: source(true, "definition"),
            ..value.clone()
        },
        VerifiedDelegation {
            revision: 8,
            ..value.clone()
        },
        VerifiedDelegation {
            trigger_id: "other".into(),
            ..value.clone()
        },
        VerifiedDelegation {
            granted_generation: AuthGeneration::new(10),
            ..value.clone()
        },
        VerifiedDelegation {
            expires_at: Some(UNIX_EPOCH),
            ..value.clone()
        },
    ] {
        assert_ne!(value, changed);
        assert_ne!(base, carrier(changed));
    }
}

#[test]
fn ordinary_and_test_constructors_keep_delegation_absent() {
    for single_user in [false, true] {
        let ordinary = AuthContextBuilder::from_verified_session(
            DeploymentId::new("d"),
            TenantId::new("t"),
            ActorId::new("a"),
            AuthGeneration::new(0),
            single_user,
        )
        .with_role(Role::User)
        .with_roles([Role::Admin, Role::User])
        .build();
        let test = AuthContext::for_test(
            DeploymentId::new("d"),
            TenantId::new("t"),
            ActorId::new("a"),
            [Role::User, Role::Admin],
            AuthGeneration::new(0),
            single_user,
        );
        assert!(ordinary.delegation().is_none());
        assert!(test.delegation().is_none());
        assert_eq!(ordinary, test);
        assert_eq!(ordinary.roles().len(), 2);
        assert_eq!(ordinary.is_single_user(), single_user);
    }
}

#[test]
fn delegated_builder_and_test_constructor_preserve_roles_and_identity() {
    for single_user in [false, true] {
        let builder = AuthContextBuilder::from_verified_delegation(
            DeploymentId::new("d"),
            TenantId::new("t"),
            ActorId::new("owner"),
            AuthGeneration::new(9),
            single_user,
            grant(),
        );
        assert!(builder.context.roles().is_empty());
        assert!(builder.context.request_binding().is_none());
        let auth = builder
            .with_role(Role::User)
            .with_roles([Role::Admin, Role::User])
            .build();
        let test = AuthContext::for_test_delegated(
            DeploymentId::new("d"),
            TenantId::new("t"),
            ActorId::new("owner"),
            [Role::Admin, Role::User],
            AuthGeneration::new(9),
            single_user,
            grant(),
        );
        assert_eq!(auth, test);
        assert_eq!(auth.deployment(), &DeploymentId::new("d"));
        assert_eq!(auth.tenant(), &TenantId::new("t"));
        assert_eq!(auth.actor(), &ActorId::new("owner"));
        assert_eq!(auth.auth_generation(), AuthGeneration::new(9));
        assert_eq!(auth.is_single_user(), single_user);
        assert_eq!(auth.roles(), &BTreeSet::from([Role::Admin, Role::User]));
        assert_eq!(auth.delegation(), Some(&grant()));
        assert!(test.request_binding().is_none());
    }
}
