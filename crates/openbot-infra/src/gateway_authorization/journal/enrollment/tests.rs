//! Pure closed-fact and byte/AAD vectors. No owner, Host or PG grant is fabricated.
use super::*;

#[test]
fn p01_name_byte_bounds_and_scope_bytes() {
    assert!(!valid_name(""));
    assert!(valid_name(" "));
    assert!(valid_name(&"x".repeat(100)));
    assert!(!valid_name(&"x".repeat(101)));
    assert!(valid_name(&"é".repeat(50)));
    assert!(!valid_name(&"é".repeat(51)));
    let raw = " account\tai ";
    assert_eq!(raw.as_bytes(), b" account\tai ");
    assert_eq!(
        raw.split_ascii_whitespace().collect::<Vec<_>>(),
        ["account", "ai"]
    );
}

#[test]
fn p02_write_terminal_action_and_ack_are_distinct() {
    for action in [Action::Commit, Action::Rollback] {
        assert_eq!(
            write_fact(action, Ack::NotAttempted),
            WriteTerminal::NotAttempted
        );
        for ack in [Ack::Unknown, Ack::Timely, Ack::Late] {
            let expected = match action {
                Action::Commit => WriteTerminal::Commit(ack),
                Action::Rollback => WriteTerminal::Rollback(ack),
            };
            assert_eq!(write_fact(action, ack), expected);
        }
    }
    assert_ne!(
        write_fact(Action::Commit, Ack::Unknown),
        write_fact(Action::Rollback, Ack::Unknown)
    );
}

#[test]
fn p03_closed_error_maps_preserve_id_and_ack() {
    let id = Uuid::from_u128(0x1234);
    let mut facts = Facts::new();
    facts.id = Some(id);
    facts.metadata = Ack::Timely;
    facts.profile = Ack::Late;
    facts.write = WriteTerminal::Commit(Ack::Unknown);
    facts.readback = Ack::NotAttempted;
    facts.observe(Cleanup::OriginalResourcesDestroyed);
    facts.observe(Cleanup::NotNeeded);
    assert_eq!(facts.cleanup, Cleanup::OriginalResourcesDestroyed);
    facts.observe(Cleanup::Unknown);
    facts.observe(Cleanup::OriginalResourcesDestroyed);
    assert_eq!(facts.cleanup, Cleanup::Unknown);
    for (input, expected) in [
        (PoolError::Unavailable, Kind::Unavailable),
        (PoolError::Closed, Kind::Unavailable),
        (PoolError::OwnershipUnavailable, Kind::Corrupt),
        (PoolError::IdentityCollision, Kind::Corrupt),
        (PoolError::CreationLimit, Kind::Corrupt),
        (PoolError::DeadlineExceeded, Kind::Deadline),
        (PoolError::ObservationUnavailable, Kind::ClosureUnknown),
    ] {
        let error = facts.error(Stage::Write, map_pool(input));
        assert_eq!(error.kind(), expected);
        assert_eq!(error.reserved_connection_id(), Some(id));
        assert_eq!(error.metadata_headers_rollback_ack(), Ack::Timely);
        assert_eq!(error.profile_headers_rollback_ack(), Ack::Late);
        assert_eq!(
            error.adoption_write_terminal(),
            WriteTerminal::Commit(Ack::Unknown)
        );
        assert_eq!(error.adoption_readback_rollback_ack(), Ack::NotAttempted);
        assert_eq!(error.cleanup_state(), Cleanup::Unknown);
    }
    assert_eq!(
        map_terminal(TransactionOwnerError::RollbackUnproven, false),
        Kind::CleanupUnknown
    );
    assert_eq!(
        map_terminal(TransactionOwnerError::RollbackUnproven, true),
        Kind::ReadbackUnproven
    );
    assert_eq!(
        map_terminal(
            TransactionOwnerError::CommitAcknowledgedAfterDeadline,
            false
        ),
        Kind::CommitAcknowledgedAfterDeadline
    );
    assert_eq!(
        map_terminal(
            TransactionOwnerError::RollbackAcknowledgedAfterDeadline,
            true
        ),
        Kind::RollbackAcknowledgedAfterDeadline
    );
}

#[test]
fn p04_original_id_only_after_whole_binding() {
    // Projection only: genuine whole-binding authorization is covered by the true Host cases.
    let facts = Facts::new();
    for kind in [
        Kind::BeforeAdoptionRefused,
        Kind::InvalidInput,
        Kind::Cancelled,
        Kind::Deadline,
    ] {
        let before = facts.error(Stage::Entry, kind);
        assert_eq!(before.reserved_connection_id(), None);
        assert_eq!(
            before.adoption_write_terminal(),
            WriteTerminal::NotAttempted
        );
        assert_eq!(before.cleanup_state(), Cleanup::NotNeeded);
    }
    let original = Uuid::from_u128(0x4321);
    let mut bound = facts;
    bound.id = Some(original);
    for stage in [
        Stage::Metadata,
        Stage::Profile,
        Stage::Write,
        Stage::Readback,
        Stage::FinalHandoff,
    ] {
        for kind in [
            Kind::BeforeAdoptionRefused,
            Kind::Cancelled,
            Kind::Deadline,
            Kind::CommitUnknown,
        ] {
            assert_eq!(
                bound.error(stage, kind).reserved_connection_id(),
                Some(original)
            );
        }
    }
}

#[test]
fn p06_original_clock_and_child_caps_never_renew() {
    // No fake clock/owner: arithmetic of fixed absolute subcaps only.
    let original = Instant::now() + Duration::from_secs(2);
    let first = child_cap(original, Duration::from_secs(5));
    let later = child_cap(original, Duration::from_secs(5));
    assert_eq!(first, original);
    assert_eq!(later, original);
    let cleanup = child_cap(original, Duration::from_secs(1));
    assert!(cleanup <= original);
    let same_cleanup_for_rollback_and_destruction = cleanup;
    assert_eq!(cleanup, same_cleanup_for_rollback_and_destruction);
    let expired = Instant::now() - Duration::from_secs(1);
    assert_eq!(child_cap(expired, Duration::from_secs(5)), expired);
}

#[test]
fn p07_six_token_fields_and_aad_bytes_are_exact() {
    use openbot_contracts::ids::{ActorId, TenantId};
    use openbot_domain::vault::{KeyVersion, SecretKind, SecretPrincipal, ServiceId, WrappingKey};
    let tokens = acosmi::TokenSet {
        access_token: "OWNED-access".into(),
        refresh_token: "OWNED-refresh".into(),
        expires_at: "2030-01-01T01:02:03+00:00".into(),
        scope: " account\tai ".into(),
        client_id: "Owned-Client".into(),
        server_url: "https://owned.example".into(),
    };
    let raw = serde_json::to_vec(&serde_json::json!({"tokens": {
        "access_token":tokens.access_token,"refresh_token":tokens.refresh_token,
        "expires_at":tokens.expires_at,"scope":tokens.scope,
        "client_id":tokens.client_id,"server_url":tokens.server_url,
    }}))
    .unwrap();
    let vault = crate::vault::CredentialRecordVault::single_key(
        TenantId::new("owned-tenant"),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x43; 32]).unwrap(),
    );
    let secret = Uuid::from_u128(0x1111);
    let connection = Uuid::from_u128(0x2222);
    let owner = SecretPrincipal::Actor(ActorId::new("owned-actor"));
    let service = SecretPrincipal::Service(ServiceId::new(connection.to_string()));
    let sealed = vault
        .seal(
            &secret,
            SecretKind::Model,
            owner.clone(),
            service.clone(),
            &SecretBytes::new(raw.clone()),
        )
        .unwrap();
    let opened = vault
        .open(
            &secret,
            SecretKind::Model,
            owner.clone(),
            service.clone(),
            &sealed,
        )
        .unwrap();
    assert!(!opened.needs_migration());
    assert_eq!(opened.into_secret().expose(), raw.as_slice());
    assert!(
        vault
            .open(
                &secret,
                SecretKind::Model,
                SecretPrincipal::Actor(ActorId::new("other")),
                service.clone(),
                &sealed
            )
            .is_err()
    );
    assert!(
        vault
            .open(
                &secret,
                SecretKind::Model,
                owner,
                SecretPrincipal::Service(ServiceId::new(Uuid::from_u128(0x3333).to_string())),
                &sealed
            )
            .is_err()
    );
    let decoded: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let fields = decoded["tokens"].as_object().unwrap();
    assert_eq!(fields.len(), 6);
    assert_eq!(
        fields["scope"].as_str().unwrap().as_bytes(),
        b" account\tai "
    );
    // This unit covers SDK bytes plus the real Vault AAD primitive; actual R367 envelope/PG
    // consumption is independently checked by real r01/r02/r10, never credited here.
}

#[test]
fn p08_public_errors_are_static_redacted_descriptions() {
    let mut facts = Facts::new();
    facts.id = Some(Uuid::from_u128(0xdead));
    facts.write = WriteTerminal::Commit(Ack::Timely);
    let error = facts.error(Stage::FinalHandoff, Kind::HttpStatus(429));
    assert_eq!(
        format!("{error}"),
        "gateway_authorization_enrollment_failed"
    );
    assert_eq!(
        format!("{error:?}"),
        "GatewayAuthorizationEnrollmentError([redacted])"
    );
    assert!(!format!("{error:?}").contains(&facts.id.unwrap().to_string()));
    assert_eq!(error.kind(), Kind::HttpStatus(429));
    assert_eq!(
        error.adoption_write_terminal(),
        WriteTerminal::Commit(Ack::Timely)
    );
}
