use openbot_contracts::{
    auth::{AuthContextBuilder, AuthGeneration, Role},
    ids::{ActorId, DeploymentId, TenantId},
};

#[test]
fn pending_constructor_preserves_scope_without_delegation() {
    let deployment = DeploymentId::new("pending-deployment");
    let tenant = TenantId::new("pending-tenant");
    let actor = ActorId::new("pending-user");
    let auth = AuthContextBuilder::from_verified_pending_input(
        actor.clone(),
        deployment.clone(),
        tenant.clone(),
        AuthGeneration::new(17),
    )
    .with_roles([Role::User])
    .build();
    assert_eq!(auth.deployment(), &deployment);
    assert_eq!(auth.tenant(), &tenant);
    assert_eq!(auth.actor(), &actor);
    assert_eq!(auth.auth_generation(), AuthGeneration::new(17));
    assert!(auth.has_role(Role::User));
    assert!(!auth.has_role(Role::Admin));
    assert!(!auth.is_single_user());
    assert!(auth.delegation().is_none());
    assert!(auth.request_binding().is_none());
}
