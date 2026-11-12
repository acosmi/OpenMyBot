//! GK-05 公开入口：事实组合出五态投影，不把填入的枚举原样当结果。

use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::ActorId;
use openbot_domain::identity::generation::GenerationMismatch;
use openbot_domain::runtime_capabilities::{
    ActionAuthorization, BindingClaim, BindingField, BridgeSourceFact, CapabilityId,
    CapabilityState, ConfigFact, Evidence, HostMode, ImplementationSet, LocalConfirmationFact,
    MAX_REVISION_BYTES, MAX_WINDOW_LABEL_BYTES, ModelKeyFact, PermissionFact, PolicyFact, Presence,
    ProjectionFault, ProviderFact, ReasonCode, RuntimeCapabilityFacts, RuntimeCapabilityProjection,
    RuntimeCapabilityRequest, SCHEMA_VERSION, SessionLiveness, SourceFact, WindowBindingClaim,
    project_runtime_capabilities, reject_remote_prose,
};

const EXPECTED_IDS: [&str; 13] = [
    "workspace",
    "agent_tools",
    "model_custom_v1",
    "model_selection_v2",
    "model_sdk_gateway",
    "model_account_bridge",
    "browser_control",
    "native_control",
    "pixel_egress",
    "local_confirmation",
    "backup_restore",
    "dynamic_sso",
    "device_pairing",
];

const EXPECTED_STATES: [&str; 5] = [
    "unsupported",
    "unconfigured",
    "permission_required",
    "ready",
    "unavailable",
];

const REVISION: &str = "proj-rev-1";

fn implemented() -> Presence {
    Presence::Present {
        independent_api: Evidence::Present,
        release_dependency: Evidence::Present,
    }
}

fn unimplemented_all() -> ImplementationSet {
    ImplementationSet {
        workspace: Presence::Absent,
        agent_tools: Presence::Absent,
        model_custom_v1: Presence::Absent,
        model_selection_v2: Presence::Absent,
        model_sdk_gateway: Presence::Absent,
        model_account_bridge: Presence::Absent,
        browser_control: Presence::Absent,
        native_control: Presence::Absent,
        pixel_egress: Presence::Absent,
        local_confirmation: Presence::Absent,
        backup_restore: Presence::Absent,
        dynamic_sso: Presence::Absent,
        device_pairing: Presence::Absent,
    }
}

fn implemented_all() -> ImplementationSet {
    ImplementationSet {
        workspace: implemented(),
        agent_tools: implemented(),
        model_custom_v1: implemented(),
        model_selection_v2: implemented(),
        model_sdk_gateway: implemented(),
        model_account_bridge: implemented(),
        browser_control: implemented(),
        native_control: implemented(),
        pixel_egress: implemented(),
        local_confirmation: implemented(),
        backup_restore: implemented(),
        dynamic_sso: implemented(),
        device_pairing: implemented(),
    }
}

fn facts_all_ready() -> RuntimeCapabilityFacts {
    RuntimeCapabilityFacts {
        implementations: implemented_all(),
        product_permissions: [PermissionFact::Granted; 13],
        custom_model: openbot_domain::runtime_capabilities::ModelSourceFacts {
            key: ModelKeyFact::Present,
            provider: ProviderFact::Available,
        },
        sdk_model: openbot_domain::runtime_capabilities::ModelSourceFacts {
            key: ModelKeyFact::Present,
            provider: ProviderFact::Available,
        },
        bridge_model: openbot_domain::runtime_capabilities::ModelSourceFacts {
            key: ModelKeyFact::Present,
            provider: ProviderFact::Available,
        },
        acting_policy: PolicyFact::Configured,
        model_key: ModelKeyFact::Present,
        custom_model_config: ConfigFact::Present,
        selection_v2_config: ConfigFact::Present,
        sdk_gateway_config: ConfigFact::Present,
        account_bridge_config: ConfigFact::Present,
        account_bridge_source: BridgeSourceFact::Available,
        backup_config: ConfigFact::Present,
        sso_config: ConfigFact::Present,
        sso_provider: ProviderFact::Available,
        pairing_config: ConfigFact::Present,
        model_provider: ProviderFact::Available,
        computer_source: SourceFact::Present,
        native_source: SourceFact::Present,
        screen_source: SourceFact::Present,
        os_capture: PermissionFact::Granted,
        os_accessibility: PermissionFact::Granted,
        os_input: PermissionFact::Granted,
        pixel_model_consent: PermissionFact::Granted,
        local_confirmation: LocalConfirmationFact::Fresh,
    }
}

fn actor(name: &str) -> ActorId {
    ActorId::new(name)
}

fn window(label: &str, nonce: u64) -> WindowBindingClaim {
    WindowBindingClaim::declare(label, nonce).expect("synthetic window")
}

fn binding(
    actor_name: &str,
    generation: u64,
    host: HostMode,
    session: SessionLiveness,
    window_label: &str,
    nonce: u64,
) -> BindingClaim {
    let window = if host == HostMode::DesktopLocal || host == HostMode::DesktopRemote {
        Some(window(window_label, nonce))
    } else {
        None
    };
    BindingClaim::declare(
        actor(actor_name),
        AuthGeneration::new(generation),
        host,
        session,
        window,
    )
    .expect("synthetic binding")
}

fn desktop_binding() -> BindingClaim {
    binding(
        "actor-1",
        3,
        HostMode::DesktopLocal,
        SessionLiveness::Active,
        "main",
        7,
    )
}

fn project(
    current: &BindingClaim,
    observed: &BindingClaim,
    facts: &RuntimeCapabilityFacts,
) -> Result<RuntimeCapabilityProjection, ProjectionFault> {
    project_runtime_capabilities(RuntimeCapabilityRequest {
        current_runtime: std::num::NonZeroU64::new(1).unwrap(),
        observed_runtime: std::num::NonZeroU64::new(1).unwrap(),
        current_binding: current,
        observed_binding: observed,
        revision: REVISION,
        facts,
    })
}

fn project_current(
    facts: &RuntimeCapabilityFacts,
) -> Result<RuntimeCapabilityProjection, ProjectionFault> {
    let binding = desktop_binding();
    project(&binding, &binding, facts)
}

#[test]
fn closed_id_set_matches_handwritten_literals_in_fixed_order() {
    let projected = project_current(&facts_all_ready()).expect("synthetic all-ready");
    let ids: Vec<&str> = projected
        .capabilities()
        .iter()
        .map(|item| item.id().as_str())
        .collect();
    assert_eq!(ids.as_slice(), EXPECTED_IDS.as_slice());
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), 13);
}

#[test]
fn five_states_have_handwritten_literals() {
    assert_eq!(CapabilityState::Unsupported.as_str(), EXPECTED_STATES[0]);
    assert_eq!(CapabilityState::Unconfigured.as_str(), EXPECTED_STATES[1]);
    assert_eq!(
        CapabilityState::PermissionRequired.as_str(),
        EXPECTED_STATES[2]
    );
    assert_eq!(CapabilityState::Ready.as_str(), EXPECTED_STATES[3]);
    assert_eq!(CapabilityState::Unavailable.as_str(), EXPECTED_STATES[4]);
}

#[test]
fn each_state_is_reachable_on_a_real_capability() {
    let ready = project_current(&facts_all_ready()).expect("ready sample");
    assert_eq!(
        ready.status(CapabilityId::Workspace).state(),
        CapabilityState::Ready
    );
    assert_eq!(
        ready.status(CapabilityId::NativeControl).state(),
        CapabilityState::Ready
    );

    let mut unsupported = facts_all_ready();
    unsupported.implementations.native_control = Presence::Absent;
    let projected = project_current(&unsupported).expect("unsupported sample");
    assert_eq!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::Unsupported
    );
    assert_eq!(
        projected.status(CapabilityId::NativeControl).reason_code(),
        ReasonCode::PlatformUnimplemented
    );

    let mut unconfigured = facts_all_ready();
    unconfigured.acting_policy = PolicyFact::Empty;
    let projected = project_current(&unconfigured).expect("unconfigured sample");
    assert_eq!(
        projected.status(CapabilityId::AgentTools).state(),
        CapabilityState::Unconfigured
    );
    assert_eq!(
        projected.status(CapabilityId::AgentTools).reason_code(),
        ReasonCode::PolicyEmpty
    );

    let mut permission = facts_all_ready();
    permission.os_accessibility = PermissionFact::Denied;
    let projected = project_current(&permission).expect("permission sample");
    assert_eq!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::PermissionRequired
    );
    assert_eq!(
        projected.status(CapabilityId::NativeControl).reason_code(),
        ReasonCode::OsPermissionAccessibilityRequired
    );

    let mut unavailable = facts_all_ready();
    unavailable.native_source = SourceFact::Absent;
    let projected = project_current(&unavailable).expect("unavailable sample");
    assert_eq!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::Unavailable
    );
    assert_eq!(
        projected.status(CapabilityId::NativeControl).reason_code(),
        ReasonCode::NativeSourceMissing
    );
}

#[test]
fn workspace_is_ready_without_model_key_and_does_not_lift_acting() {
    let mut facts = facts_all_ready();
    facts.model_key = ModelKeyFact::Absent;
    facts.custom_model.key = ModelKeyFact::Absent;
    facts.sdk_model.key = ModelKeyFact::Absent;
    facts.bridge_model.key = ModelKeyFact::Absent;
    let projected = project_current(&facts).expect("workspace independent");
    assert_eq!(
        projected.status(CapabilityId::Workspace).state(),
        CapabilityState::Ready
    );
    assert_eq!(
        projected.status(CapabilityId::AgentTools).state(),
        CapabilityState::Unconfigured
    );
    assert_eq!(
        projected.status(CapabilityId::AgentTools).reason_code(),
        ReasonCode::ModelKeyMissing
    );
    assert_eq!(
        projected.status(CapabilityId::ModelCustomV1).state(),
        CapabilityState::Unconfigured
    );
    assert_eq!(
        projected.status(CapabilityId::ModelSdkGateway).state(),
        CapabilityState::Unconfigured
    );
    assert_ne!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::Unconfigured
    );
    assert_eq!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::Ready
    );
}

#[test]
fn host_mode_alone_does_not_make_control_capabilities_ready() {
    let mut facts = facts_all_ready();
    facts.implementations = unimplemented_all();
    facts.implementations.workspace = implemented();
    let current = desktop_binding();
    let projected = project(&current, &current, &facts).expect("workspace-only");
    assert_eq!(projected.host_mode(), HostMode::DesktopLocal);
    assert_eq!(
        projected.status(CapabilityId::Workspace).state(),
        CapabilityState::Ready
    );
    for id in [
        CapabilityId::BrowserControl,
        CapabilityId::NativeControl,
        CapabilityId::PixelEgress,
        CapabilityId::LocalConfirmation,
        CapabilityId::AgentTools,
    ] {
        assert_eq!(
            projected.status(id).state(),
            CapabilityState::Unsupported,
            "{}",
            id.as_str()
        );
        assert_ne!(projected.status(id).state(), CapabilityState::Ready);
    }
}

#[test]
fn missing_independent_api_or_release_dependency_blocks_ready() {
    let mut api = facts_all_ready();
    api.implementations.browser_control = Presence::Present {
        independent_api: Evidence::Missing,
        release_dependency: Evidence::Present,
    };
    let projected = project_current(&api).expect("api missing");
    assert_eq!(
        projected.status(CapabilityId::BrowserControl).state(),
        CapabilityState::Unsupported
    );
    assert_eq!(
        projected.status(CapabilityId::BrowserControl).reason_code(),
        ReasonCode::IndependentApiMissing
    );

    let mut release = facts_all_ready();
    release.implementations.backup_restore = Presence::Present {
        independent_api: Evidence::Present,
        release_dependency: Evidence::Missing,
    };
    let projected = project_current(&release).expect("release missing");
    assert_eq!(
        projected.status(CapabilityId::BackupRestore).state(),
        CapabilityState::Unavailable
    );
    assert_eq!(
        projected.status(CapabilityId::BackupRestore).reason_code(),
        ReasonCode::ReleaseDependencyMissing
    );
}

#[test]
fn unconfigured_empty_and_invalid_policy_block_acting_not_workspace() {
    for (policy, reason) in [
        (PolicyFact::Unconfigured, ReasonCode::PolicyUnconfigured),
        (PolicyFact::Empty, ReasonCode::PolicyEmpty),
        (PolicyFact::Invalid, ReasonCode::PolicyInvalid),
    ] {
        let mut facts = facts_all_ready();
        facts.acting_policy = policy;
        let projected = project_current(&facts).expect("policy sample");
        assert_eq!(
            projected.status(CapabilityId::Workspace).state(),
            CapabilityState::Ready
        );
        assert_eq!(
            projected.status(CapabilityId::AgentTools).state(),
            CapabilityState::Unconfigured
        );
        assert_eq!(
            projected.status(CapabilityId::AgentTools).reason_code(),
            reason
        );
        assert_eq!(
            projected.status(CapabilityId::BrowserControl).state(),
            CapabilityState::Unconfigured
        );
    }
}

#[test]
fn missing_model_connection_config_is_unconfigured() {
    let mut facts = facts_all_ready();
    facts.custom_model_config = ConfigFact::Missing;
    let projected = project_current(&facts).expect("custom config");
    assert_eq!(
        projected.status(CapabilityId::ModelCustomV1).state(),
        CapabilityState::Unconfigured
    );
    assert_eq!(
        projected.status(CapabilityId::Workspace).state(),
        CapabilityState::Ready
    );
}

#[test]
fn no_tcc_local_confirmation_source_or_provider_each_block_ready() {
    let mut tcc = facts_all_ready();
    tcc.os_capture = PermissionFact::Denied;
    tcc.os_accessibility = PermissionFact::Denied;
    tcc.os_input = PermissionFact::Denied;
    let projected = project_current(&tcc).expect("no tcc");
    assert_eq!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::PermissionRequired
    );
    assert_eq!(
        projected.status(CapabilityId::PixelEgress).state(),
        CapabilityState::PermissionRequired
    );
    assert_ne!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::Ready
    );

    let mut confirmation = facts_all_ready();
    confirmation.local_confirmation = LocalConfirmationFact::Required;
    let projected = project_current(&confirmation).expect("no confirmation");
    assert_eq!(
        projected.status(CapabilityId::LocalConfirmation).state(),
        CapabilityState::PermissionRequired
    );
    assert_eq!(
        projected
            .status(CapabilityId::LocalConfirmation)
            .reason_code(),
        ReasonCode::LocalConfirmationRequired
    );

    let mut screen = facts_all_ready();
    screen.screen_source = SourceFact::Absent;
    let projected = project_current(&screen).expect("no screen");
    assert_eq!(
        projected.status(CapabilityId::PixelEgress).state(),
        CapabilityState::Unavailable
    );

    let mut native = facts_all_ready();
    native.native_source = SourceFact::Absent;
    let projected = project_current(&native).expect("no native source");
    assert_eq!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::Unavailable
    );

    let mut computer = facts_all_ready();
    computer.computer_source = SourceFact::Absent;
    let projected = project_current(&computer).expect("no computer");
    assert_eq!(
        projected.status(CapabilityId::BrowserControl).state(),
        CapabilityState::Unavailable
    );
    assert_eq!(
        projected.status(CapabilityId::BrowserControl).reason_code(),
        ReasonCode::ComputerSourceMissing
    );

    let mut provider = facts_all_ready();
    provider.model_provider = ProviderFact::Disconnected;
    provider.custom_model.provider = ProviderFact::Disconnected;
    let projected = project_current(&provider).expect("provider down");
    assert_eq!(
        projected.status(CapabilityId::ModelCustomV1).state(),
        CapabilityState::Unavailable
    );
    assert_eq!(
        projected.status(CapabilityId::AgentTools).state(),
        CapabilityState::Unavailable
    );
    assert_eq!(
        projected.status(CapabilityId::ModelCustomV1).reason_code(),
        ReasonCode::ProviderDisconnected
    );
}

#[test]
fn unknown_and_expired_observations_cannot_become_ready() {
    let mut unknown_impl = facts_all_ready();
    unknown_impl.implementations.dynamic_sso = Presence::Unknown;
    let projected = project_current(&unknown_impl).expect("unknown impl");
    assert_eq!(
        projected.status(CapabilityId::DynamicSso).state(),
        CapabilityState::Unavailable
    );
    assert_ne!(
        projected.status(CapabilityId::DynamicSso).state(),
        CapabilityState::Ready
    );

    let mut expired = facts_all_ready();
    expired.os_input = PermissionFact::Expired;
    let projected = project_current(&expired).expect("expired tcc");
    assert_eq!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::Unavailable
    );
    assert_eq!(
        projected.status(CapabilityId::NativeControl).reason_code(),
        ReasonCode::OsPermissionExpired
    );

    let mut unknown_config = facts_all_ready();
    unknown_config.sso_config = ConfigFact::Unknown;
    let projected = project_current(&unknown_config).expect("unknown config");
    assert_eq!(
        projected.status(CapabilityId::DynamicSso).state(),
        CapabilityState::Unavailable
    );
}

#[test]
fn stale_bindings_exit_and_revocation_refuse_the_whole_projection() {
    let facts = facts_all_ready();
    let current = desktop_binding();

    let old_actor = binding(
        "actor-2",
        3,
        HostMode::DesktopLocal,
        SessionLiveness::Active,
        "main",
        7,
    );
    assert_eq!(
        project(&current, &old_actor, &facts).unwrap_err(),
        ProjectionFault::BindingMismatch {
            field: BindingField::Actor
        }
    );

    let old_host = binding(
        "actor-1",
        3,
        HostMode::DesktopRemote,
        SessionLiveness::Active,
        "main",
        7,
    );
    assert_eq!(
        project(&current, &old_host, &facts).unwrap_err(),
        ProjectionFault::BindingMismatch {
            field: BindingField::Host
        }
    );

    let replaced = binding(
        "actor-1",
        3,
        HostMode::DesktopLocal,
        SessionLiveness::Active,
        "main",
        8,
    );
    assert_eq!(
        project(&current, &replaced, &facts).unwrap_err(),
        ProjectionFault::WindowReplaced
    );

    let relabeled = binding(
        "actor-1",
        3,
        HostMode::DesktopLocal,
        SessionLiveness::Active,
        "other",
        7,
    );
    assert_eq!(
        project(&current, &relabeled, &facts).unwrap_err(),
        ProjectionFault::WindowReplaced
    );

    let exited = binding(
        "actor-1",
        3,
        HostMode::DesktopLocal,
        SessionLiveness::Exited,
        "main",
        7,
    );
    assert_eq!(
        project(&current, &exited, &facts).unwrap_err(),
        ProjectionFault::SessionExited
    );
    assert_eq!(
        project(&exited, &current, &facts).unwrap_err(),
        ProjectionFault::SessionExited
    );

    let revoked = binding(
        "actor-1",
        3,
        HostMode::DesktopLocal,
        SessionLiveness::Revoked,
        "main",
        7,
    );
    assert_eq!(
        project(&current, &revoked, &facts).unwrap_err(),
        ProjectionFault::SessionRevoked
    );

    let stale = binding(
        "actor-1",
        2,
        HostMode::DesktopLocal,
        SessionLiveness::Active,
        "main",
        7,
    );
    assert_eq!(
        project(&current, &stale, &facts).unwrap_err(),
        ProjectionFault::Generation(GenerationMismatch::Stale)
    );

    let future = binding(
        "actor-1",
        4,
        HostMode::DesktopLocal,
        SessionLiveness::Active,
        "main",
        7,
    );
    assert_eq!(
        project(&current, &future, &facts).unwrap_err(),
        ProjectionFault::Generation(GenerationMismatch::FromTheFuture)
    );
}

#[test]
fn identical_current_input_is_deterministic() {
    let facts = facts_all_ready();
    let first = project_current(&facts).expect("first");
    let second = project_current(&facts).expect("second");
    assert_eq!(first, second);
    assert_eq!(first.schema_version(), SCHEMA_VERSION);
    assert_eq!(first.revision().as_str(), REVISION);
}

#[test]
fn revision_empty_too_long_and_secret_like_values_are_rejected() {
    let facts = facts_all_ready();
    let binding = desktop_binding();
    let err = project_runtime_capabilities(RuntimeCapabilityRequest {
        current_runtime: std::num::NonZeroU64::new(1).unwrap(),
        observed_runtime: std::num::NonZeroU64::new(1).unwrap(),
        current_binding: &binding,
        observed_binding: &binding,
        revision: "",
        facts: &facts,
    })
    .unwrap_err();
    assert_eq!(err.code(), "runtime_capabilities_revision_empty");

    let too_long = "a".repeat(MAX_REVISION_BYTES + 1);
    let err = project_runtime_capabilities(RuntimeCapabilityRequest {
        current_runtime: std::num::NonZeroU64::new(1).unwrap(),
        observed_runtime: std::num::NonZeroU64::new(1).unwrap(),
        current_binding: &binding,
        observed_binding: &binding,
        revision: &too_long,
        facts: &facts,
    })
    .unwrap_err();
    assert_eq!(err.code(), "runtime_capabilities_revision_too_long");

    let err = project_runtime_capabilities(RuntimeCapabilityRequest {
        current_runtime: std::num::NonZeroU64::new(1).unwrap(),
        observed_runtime: std::num::NonZeroU64::new(1).unwrap(),
        current_binding: &binding,
        observed_binding: &binding,
        revision: "sk-live/not-a-revision",
        facts: &facts,
    })
    .unwrap_err();
    assert_eq!(err.code(), "runtime_capabilities_revision_invalid_charset");
}

#[test]
fn remote_error_strings_are_not_reason_codes_and_do_not_appear_in_output() {
    assert_eq!(
        reject_remote_prose("dial tcp 10.8.0.4:443: i/o timeout").to_string(),
        "runtime_capabilities_remote_prose_rejected"
    );
    let current = BindingClaim::declare(
        actor("actor-1"),
        AuthGeneration::new(3),
        HostMode::DesktopLocal,
        SessionLiveness::Active,
        Some(window("postgres://robot:secret@127.0.0.1:5432/openbot", 7)),
    )
    .expect("dirty window stays in input only");
    let projected = project(&current, &current, &facts_all_ready()).expect("projection");
    let rendered = format!("{projected:?}");
    assert!(!rendered.contains("postgres://"));
    assert!(!rendered.contains("127.0.0.1"));
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains("5432"));
    for item in projected.capabilities() {
        assert!(!item.reason_code().as_str().contains("tcp"));
        assert!(!item.reason_code().as_str().contains("timeout"));
    }
}

#[test]
fn projection_does_not_grant_action_capability() {
    let projected = project_current(&facts_all_ready()).expect("ready");
    assert_eq!(
        projected.action_authorization(),
        ActionAuthorization::NotGranted
    );
    assert_eq!(projected.action_authorization().as_str(), "not_granted");
}

#[test]
fn configuration_blocker_hides_a_later_os_permission_blocker() {
    let mut facts = facts_all_ready();
    facts.acting_policy = PolicyFact::Unconfigured;
    facts.os_accessibility = PermissionFact::Denied;
    let status = project_current(&facts)
        .expect("different levels do not conflict")
        .status(CapabilityId::NativeControl);
    assert_eq!(status.state(), CapabilityState::Unconfigured);
    assert_eq!(status.reason_code(), ReasonCode::PolicyUnconfigured);
}

#[test]
fn each_adjacent_level_boundary_reports_only_the_earlier_level() {
    // Level 1 release dependency over level 2 product permission.
    let mut facts = facts_all_ready();
    facts.implementations.backup_restore = Presence::Present {
        independent_api: Evidence::Present,
        release_dependency: Evidence::Missing,
    };
    facts.product_permissions[10] = PermissionFact::Denied;
    let status = project_current(&facts)
        .expect("level 1 over level 2")
        .status(CapabilityId::BackupRestore);
    assert_eq!(status.state(), CapabilityState::Unavailable);
    assert_eq!(status.reason_code(), ReasonCode::ReleaseDependencyMissing);

    // Level 2 product permission over level 3 acting policy.
    let mut facts = facts_all_ready();
    facts.product_permissions[6] = PermissionFact::Denied;
    facts.acting_policy = PolicyFact::Unconfigured;
    let status = project_current(&facts)
        .expect("level 2 over level 3")
        .status(CapabilityId::BrowserControl);
    assert_eq!(status.state(), CapabilityState::PermissionRequired);
    assert_eq!(status.reason_code(), ReasonCode::ProductPermissionRequired);

    // Level 3 acting policy over level 4 computer source.
    let mut facts = facts_all_ready();
    facts.acting_policy = PolicyFact::Unconfigured;
    facts.computer_source = SourceFact::Absent;
    let status = project_current(&facts)
        .expect("level 3 over level 4")
        .status(CapabilityId::BrowserControl);
    assert_eq!(status.state(), CapabilityState::Unconfigured);
    assert_eq!(status.reason_code(), ReasonCode::PolicyUnconfigured);

    // Level 4 native source over level 5 OS permission.
    let mut facts = facts_all_ready();
    facts.native_source = SourceFact::Absent;
    facts.os_accessibility = PermissionFact::Denied;
    let status = project_current(&facts)
        .expect("level 4 over level 5")
        .status(CapabilityId::NativeControl);
    assert_eq!(status.state(), CapabilityState::Unavailable);
    assert_eq!(status.reason_code(), ReasonCode::NativeSourceMissing);
}

#[test]
fn two_states_inside_one_level_still_refuse_the_whole_projection() {
    let mut facts = facts_all_ready();
    facts.acting_policy = PolicyFact::Unconfigured;
    facts.model_key = ModelKeyFact::Unknown;
    match project_current(&facts).unwrap_err() {
        ProjectionFault::UnresolvedBlockers(conflict) => {
            assert_eq!(conflict.capability(), CapabilityId::AgentTools);
            assert!(conflict.unconfigured());
            assert!(!conflict.permission_required());
            assert!(conflict.unavailable());
        }
        other => panic!("expected unresolved blockers, got {other:?}"),
    }
}

#[test]
fn permission_and_unavailable_inside_the_os_level_refuse_the_whole_projection() {
    let mut facts = facts_all_ready();
    facts.os_accessibility = PermissionFact::Denied;
    facts.os_input = PermissionFact::Unknown;
    match project_current(&facts).unwrap_err() {
        ProjectionFault::UnresolvedBlockers(conflict) => {
            assert_eq!(conflict.capability(), CapabilityId::NativeControl);
            assert!(!conflict.unconfigured());
            assert!(conflict.permission_required());
            assert!(conflict.unavailable());
        }
        other => panic!("expected unresolved blockers, got {other:?}"),
    }
}

#[test]
fn one_state_inside_one_level_reports_the_first_collected_reason() {
    let mut facts = facts_all_ready();
    facts.os_accessibility = PermissionFact::Denied;
    facts.os_input = PermissionFact::Denied;
    let status = project_current(&facts)
        .expect("same state")
        .status(CapabilityId::NativeControl);
    assert_eq!(status.state(), CapabilityState::PermissionRequired);
    assert_eq!(
        status.reason_code(),
        ReasonCode::OsPermissionAccessibilityRequired
    );
}

#[test]
fn pixel_model_key_is_a_configuration_blocker_ahead_of_the_screen_source() {
    let mut facts = facts_all_ready();
    facts.model_key = ModelKeyFact::Absent;
    facts.screen_source = SourceFact::Absent;
    let status = project_current(&facts)
        .expect("level 3 over level 4")
        .status(CapabilityId::PixelEgress);
    assert_eq!(status.state(), CapabilityState::Unconfigured);
    assert_eq!(status.reason_code(), ReasonCode::ModelKeyMissing);
}

#[test]
fn local_confirmation_is_evaluated_directly_after_product_permission() {
    let mut facts = facts_all_ready();
    facts.acting_policy = PolicyFact::Unconfigured;
    facts.local_confirmation = LocalConfirmationFact::Pending;
    let status = project_current(&facts)
        .expect("policy does not apply")
        .status(CapabilityId::LocalConfirmation);
    assert_eq!(status.state(), CapabilityState::PermissionRequired);
    assert_eq!(status.reason_code(), ReasonCode::LocalConfirmationPending);

    let mut facts = facts_all_ready();
    facts.product_permissions[9] = PermissionFact::Denied;
    facts.local_confirmation = LocalConfirmationFact::Unavailable;
    let status = project_current(&facts)
        .expect("level 2 over level 5")
        .status(CapabilityId::LocalConfirmation);
    assert_eq!(status.state(), CapabilityState::PermissionRequired);
    assert_eq!(status.reason_code(), ReasonCode::ProductPermissionRequired);
}

#[test]
fn account_bridge_source_blocked_is_unconfigured() {
    let mut facts = facts_all_ready();
    facts.account_bridge_source = BridgeSourceFact::Blocked;
    let projected = project_current(&facts).expect("bridge blocked");
    assert_eq!(
        projected.status(CapabilityId::ModelAccountBridge).state(),
        CapabilityState::Unconfigured
    );
    assert_eq!(
        projected
            .status(CapabilityId::ModelAccountBridge)
            .reason_code(),
        ReasonCode::AccountBridgeSourceBlocked
    );
}

#[test]
fn server_and_mobile_hosts_project_without_window_and_without_inferring_ready() {
    let mut facts = facts_all_ready();
    facts.implementations = unimplemented_all();
    facts.implementations.workspace = implemented();
    let server = binding(
        "actor-1",
        3,
        HostMode::Server,
        SessionLiveness::Active,
        "unused",
        1,
    );
    let projected = project(&server, &server, &facts).expect("server workspace");
    assert_eq!(projected.host_mode(), HostMode::Server);
    assert_eq!(
        projected.status(CapabilityId::Workspace).state(),
        CapabilityState::Ready
    );
    assert_eq!(
        projected.status(CapabilityId::NativeControl).state(),
        CapabilityState::Unsupported
    );

    let mobile = binding(
        "actor-1",
        3,
        HostMode::MobileRemote,
        SessionLiveness::Active,
        "unused",
        1,
    );
    let projected = project(&mobile, &mobile, &facts).expect("mobile workspace");
    assert_eq!(projected.host_mode(), HostMode::MobileRemote);
    assert_eq!(
        projected.status(CapabilityId::LocalConfirmation).state(),
        CapabilityState::Unsupported
    );
}

#[test]
fn window_shape_and_nonce_are_validated() {
    assert_eq!(
        WindowBindingClaim::declare("main", 0).unwrap_err(),
        ProjectionFault::WindowNonce
    );
    assert_eq!(
        WindowBindingClaim::declare("", 1).unwrap_err(),
        ProjectionFault::WindowLabel
    );
    let too_long = "w".repeat(MAX_WINDOW_LABEL_BYTES + 1);
    assert_eq!(
        WindowBindingClaim::declare(&too_long, 1).unwrap_err(),
        ProjectionFault::WindowLabel
    );
    assert_eq!(
        BindingClaim::declare(
            actor("actor-1"),
            AuthGeneration::new(1),
            HostMode::Server,
            SessionLiveness::Active,
            Some(window("main", 1)),
        )
        .unwrap_err(),
        ProjectionFault::WindowShape
    );
    assert_eq!(
        BindingClaim::declare(
            actor("actor-1"),
            AuthGeneration::new(1),
            HostMode::DesktopLocal,
            SessionLiveness::Active,
            None,
        )
        .unwrap_err(),
        ProjectionFault::WindowShape
    );
}

#[test]
fn bad_policy_does_not_create_implicit_allow_all() {
    let mut facts = facts_all_ready();
    facts.acting_policy = PolicyFact::Unconfigured;
    let projected = project_current(&facts).expect("no implicit allow");
    assert_ne!(
        projected.status(CapabilityId::AgentTools).state(),
        CapabilityState::Ready
    );
    assert_ne!(
        projected.status(CapabilityId::BrowserControl).state(),
        CapabilityState::Ready
    );
}

#[test]
fn controller_pixel_send_requires_current_provider() {
    let mut facts = facts_all_ready();
    facts.model_provider = ProviderFact::Disconnected;
    let projection = project_current(&facts).unwrap();
    assert_ne!(
        projection.status(CapabilityId::PixelEgress).state(),
        CapabilityState::Ready
    );
}

#[test]
fn controller_product_permission_is_independent_of_os_permission() {
    for permission in [
        PermissionFact::Denied,
        PermissionFact::Unknown,
        PermissionFact::Expired,
    ] {
        let mut facts = facts_all_ready();
        facts.product_permissions[7] = permission;
        assert_ne!(
            project_current(&facts)
                .unwrap()
                .status(CapabilityId::NativeControl)
                .state(),
            CapabilityState::Ready
        );
    }
}
#[test]
fn controller_replaced_server_runtime_rejects_old_snapshot() {
    let b = binding(
        "actor-1",
        3,
        HostMode::Server,
        SessionLiveness::Active,
        "",
        0,
    );
    let facts = facts_all_ready();
    assert!(
        project_runtime_capabilities(RuntimeCapabilityRequest {
            current_runtime: std::num::NonZeroU64::new(2).unwrap(),
            observed_runtime: std::num::NonZeroU64::new(1).unwrap(),
            current_binding: &b,
            observed_binding: &b,
            revision: "revision",
            facts: &facts,
        })
        .is_err()
    );
}

#[test]
fn controller_model_sources_do_not_share_readiness() {
    let mut facts = facts_all_ready();
    facts.sdk_model.provider = ProviderFact::Disconnected;
    facts.bridge_model.key = ModelKeyFact::Absent;
    let projection = project_current(&facts).unwrap();
    assert_eq!(
        projection.status(CapabilityId::ModelCustomV1).state(),
        CapabilityState::Ready
    );
    assert_eq!(
        projection.status(CapabilityId::ModelSdkGateway).state(),
        CapabilityState::Unavailable
    );
    assert_eq!(
        projection.status(CapabilityId::ModelAccountBridge).state(),
        CapabilityState::Unconfigured
    );
}

#[test]
fn sso_protocol_unproven_or_lost_does_not_become_ready_from_configuration() {
    for (provider, reason) in [
        (ProviderFact::Unknown, ReasonCode::ProviderUnproven),
        (ProviderFact::Disconnected, ReasonCode::ProviderDisconnected),
        (ProviderFact::Expired, ReasonCode::ProviderExpired),
    ] {
        let mut facts = facts_all_ready();
        facts.sso_provider = provider;
        let status = project_current(&facts)
            .unwrap()
            .status(CapabilityId::DynamicSso);
        assert_eq!(status.state(), CapabilityState::Unavailable);
        assert_eq!(status.reason_code(), reason);
    }
}
#[test]
fn missing_sso_configuration_does_not_add_an_unrelated_provider_blocker() {
    let mut facts = facts_all_ready();
    facts.sso_config = ConfigFact::Missing;
    facts.sso_provider = ProviderFact::Unknown;
    let status = project_current(&facts)
        .unwrap()
        .status(CapabilityId::DynamicSso);
    assert_eq!(status.state(), CapabilityState::Unconfigured);
    assert_eq!(status.reason_code(), ReasonCode::ConfigurationMissing);
}
#[test]
fn present_sso_product_permission_hides_the_provider_blocker() {
    let mut facts = facts_all_ready();
    facts.sso_provider = ProviderFact::Unknown;
    facts.product_permissions[11] = PermissionFact::Denied;
    let status = project_current(&facts)
        .expect("different levels do not conflict")
        .status(CapabilityId::DynamicSso);
    assert_eq!(status.state(), CapabilityState::PermissionRequired);
    assert_eq!(status.reason_code(), ReasonCode::ProductPermissionRequired);
}
