//! Production sign-in route and fail-closed authenticated application boundary.

use leptos::prelude::*;
use leptos_router::hooks::use_location;
use leptos_router::location::Location;
use openbot_contracts::auth::{
    AuthProviderId, AuthenticationCapabilities, MAX_SSO_ROUTING_EMAIL_BYTES,
};

#[cfg(any(target_arch = "wasm32", test))]
use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::{
    load_authentication_capabilities, load_current_user, start_enterprise_sign_in,
    start_environment_sign_in,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Field, Input, InputType, Notice, NoticeTone,
};

#[cfg(any(target_arch = "wasm32", test))]
const SIGN_PATH: &str = "/sign";
#[cfg(target_arch = "wasm32")]
const APP_PATH: &str = "/";
#[cfg(any(target_arch = "wasm32", test))]
const ENTERPRISE_CONTINUE_PATH: &str = "/api/auth/sso/continue";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthGateState {
    Checking,
    Authenticated,
    #[cfg(target_arch = "wasm32")]
    SignedOut,
    #[cfg(target_arch = "wasm32")]
    Redirecting,
    Failed,
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthGateDecision {
    MountAuthenticated,
    ShowSignIn,
    RedirectToSignIn,
    RedirectToApplication,
    ShowFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapabilityState {
    Loading,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignInAttempt {
    Provider(AuthProviderId),
    Enterprise,
}

/// Probe the authoritative current-session endpoint before constructing any protected child.
#[component]
pub fn AuthenticatedBoundary(children: ChildrenFn) -> impl IntoView {
    let i18n = use_i18n();
    let gate = RwSignal::new(AuthGateState::Checking);
    let retry_generation = RwSignal::new(0_u64);
    let children = StoredValue::new(children);
    let location = use_location();

    install_auth_probe(gate, retry_generation);
    install_authenticated_sign_redirect(gate, location);

    view! {
        <Show
            when=move || gate.get() == AuthGateState::Authenticated
            fallback=move || auth_gate_fallback(i18n, gate.get(), retry_generation)
        >
            {move || children.get_value()()}
        </Show>
    }
}

fn install_authenticated_sign_redirect(gate: RwSignal<AuthGateState>, location: Location) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let pathname = location.pathname.get();
        if authenticated_path_requires_root(gate.get(), &pathname) {
            gate.set(AuthGateState::Redirecting);
            if replace_location(APP_PATH).is_err() {
                gate.set(AuthGateState::Failed);
            }
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (gate, location);
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn authenticated_path_requires_root(state: AuthGateState, pathname: &str) -> bool {
    state == AuthGateState::Authenticated && pathname == SIGN_PATH
}

fn install_auth_probe(gate: RwSignal<AuthGateState>, retry_generation: RwSignal<u64>) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let attempt = retry_generation.get();
        gate.set(AuthGateState::Checking);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = load_current_user().await.map(|_| ());
            if retry_generation.get_untracked() != attempt {
                return;
            }
            let pathname = current_pathname().unwrap_or_default();
            match auth_gate_decision(&pathname, result) {
                AuthGateDecision::MountAuthenticated => gate.set(AuthGateState::Authenticated),
                AuthGateDecision::ShowSignIn => gate.set(AuthGateState::SignedOut),
                AuthGateDecision::RedirectToSignIn => {
                    gate.set(AuthGateState::Redirecting);
                    if replace_location(SIGN_PATH).is_err() {
                        gate.set(AuthGateState::Failed);
                    }
                }
                AuthGateDecision::RedirectToApplication => {
                    gate.set(AuthGateState::Redirecting);
                    if replace_location(APP_PATH).is_err() {
                        gate.set(AuthGateState::Failed);
                    }
                }
                AuthGateDecision::ShowFailure => gate.set(AuthGateState::Failed),
            }
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = retry_generation;
        gate.set(AuthGateState::Failed);
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn auth_gate_decision(pathname: &str, result: Result<(), ApiError>) -> AuthGateDecision {
    match result {
        Ok(()) if pathname == SIGN_PATH => AuthGateDecision::RedirectToApplication,
        Ok(()) => AuthGateDecision::MountAuthenticated,
        Err(ApiError::Unauthorized) if pathname == SIGN_PATH => AuthGateDecision::ShowSignIn,
        Err(ApiError::Unauthorized) => AuthGateDecision::RedirectToSignIn,
        Err(_) => AuthGateDecision::ShowFailure,
    }
}

fn auth_gate_fallback(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    state: AuthGateState,
    retry_generation: RwSignal<u64>,
) -> AnyView {
    match state {
        #[cfg(target_arch = "wasm32")]
        AuthGateState::SignedOut => view! { <SignInPage /> }.into_any(),
        AuthGateState::Failed => {
            let retry = move |_| {
                retry_generation.update(|generation| *generation = generation.saturating_add(1));
            };
            view! {
                <AuthStateCard
                    title=move || t_string!(i18n, auth.unavailable_title).to_owned()
                    body=move || t_string!(i18n, auth.unavailable_body).to_owned()
                >
                    <Button
                        variant=ButtonVariant::Primary
                        size=ButtonSize::Large
                        on_activate=retry
                    >
                        {move || t!(i18n, common.retry)}
                    </Button>
                </AuthStateCard>
            }
            .into_any()
        }
        AuthGateState::Checking | AuthGateState::Authenticated => auth_loading_view(i18n),
        #[cfg(target_arch = "wasm32")]
        AuthGateState::Redirecting => auth_loading_view(i18n),
    }
}

fn auth_loading_view(i18n: leptos_i18n::I18nContext<crate::i18n::Locale>) -> AnyView {
    view! {
        <main class="ob-auth-state" id="main-content" tabindex="-1">
            <div class="ob-loading" role="status">
                {move || t!(i18n, auth.checking_session)}
            </div>
        </main>
    }
    .into_any()
}

#[component]
fn SignInPage() -> impl IntoView {
    let i18n = use_i18n();
    let state = RwSignal::new(CapabilityState::Loading);
    let capabilities = RwSignal::new(None::<AuthenticationCapabilities>);
    let retry_generation = RwSignal::new(0_u64);
    let opening = RwSignal::new(None::<SignInAttempt>);
    let start_error = RwSignal::new(None::<SignInAttempt>);
    let email = RwSignal::new(String::new());

    install_capabilities_loader(state, capabilities, retry_generation);

    view! {
        <Show
            when=move || state.get() == CapabilityState::Ready
            fallback=move || capabilities_fallback(i18n, state.get(), retry_generation)
        >
            <main class="ob-auth-state" id="main-content" tabindex="-1">
                <section class="ob-sign-card" aria-labelledby="sign-in-title">
                    <header class="ob-sign-header">
                <crate::primitives::BrandMark sign_in=true/>
                        <h1 class="ob-page-title" id="sign-in-title">
                            {move || t!(i18n, auth.sign_in_title)}
                        </h1>
                        <p class="ob-page-intro">{move || t!(i18n, auth.sign_in_subtitle)}</p>
                    </header>

                    <div class="ob-sign-actions">
                        <For
                            each=move || {
                                capabilities
                                    .get()
                                    .map(|value| value.auth_providers)
                                    .unwrap_or_default()
                            }
                            key=|provider| provider.as_str()
                            children=move |provider| {
                                view! {
                                    <ProviderSignInButton
                                        provider
                                        opening
                                        start_error
                                    />
                                }
                            }
                        />
                    </div>

                    <Show when=move || {
                        capabilities
                            .get()
                            .is_some_and(|value| value.sso_configured)
                    }>
                        <Show when=move || {
                            capabilities
                                .get()
                                .is_some_and(|value| !value.auth_providers.is_empty())
                        }>
                            <div class="ob-sign-divider" aria-hidden="true">
                                <span></span>
                                <span>{move || t!(i18n, auth.or_separator)}</span>
                                <span></span>
                            </div>
                        </Show>
                        <div class="ob-sign-enterprise">
                            <Field
                                control_id="enterprise-email"
                                label=move || t_string!(i18n, auth.enterprise_email_label).to_owned()
                                disabled=Signal::derive(move || opening.get().is_some())
                            >
                                <Input
                                    value=email
                                    input_type=InputType::Email
                                    placeholder=move || t_string!(i18n, auth.enterprise_email_placeholder).to_owned()
                                    on_submit=UnsyncCallback::new(move |_| {
                                        begin_enterprise_sign_in(email, opening, start_error);
                                    })
                                />
                            </Field>
                            <Button
                                variant=ButtonVariant::Chip
                                size=ButtonSize::Large
                                disabled=Signal::derive(move || {
                                    opening.get().is_some() || !enterprise_email_ready(&email.get())
                                })
                                loading=Signal::derive(move || {
                                    opening.get() == Some(SignInAttempt::Enterprise)
                                })
                                on_activate=move |_| {
                                    begin_enterprise_sign_in(email, opening, start_error);
                                }
                            >
                                {move || if opening.get() == Some(SignInAttempt::Enterprise) {
                                    t!(i18n, auth.opening).into_any()
                                } else {
                                    t!(i18n, auth.continue_with_company).into_any()
                                }}
                            </Button>
                        </div>
                    </Show>

                    <Show when=move || {
                        capabilities.get().is_some_and(|value| {
                            value.auth_providers.is_empty() && !value.sso_configured
                        })
                    }>
                        <div class="ob-sign-empty" role="status">
                            <h2>{move || t!(i18n, auth.no_providers_title)}</h2>
                            <p>{move || t!(i18n, auth.no_providers_body)}</p>
                        </div>
                    </Show>

                    <Show when=move || start_error.get().is_some()>
                        <Notice tone=NoticeTone::Error>
                            {move || sign_in_error(i18n, start_error.get())}
                        </Notice>
                    </Show>
                </section>
            </main>
        </Show>
    }
}

fn install_capabilities_loader(
    state: RwSignal<CapabilityState>,
    capabilities: RwSignal<Option<AuthenticationCapabilities>>,
    retry_generation: RwSignal<u64>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let attempt = retry_generation.get();
        state.set(CapabilityState::Loading);
        capabilities.set(None);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = load_authentication_capabilities().await;
            if retry_generation.get_untracked() != attempt {
                return;
            }
            match result {
                Ok(loaded) => {
                    capabilities.set(Some(loaded));
                    state.set(CapabilityState::Ready);
                }
                Err(_) => state.set(CapabilityState::Failed),
            }
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (capabilities, retry_generation);
        state.set(CapabilityState::Failed);
    }
}

fn capabilities_fallback(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    state: CapabilityState,
    retry_generation: RwSignal<u64>,
) -> AnyView {
    match state {
        CapabilityState::Loading | CapabilityState::Ready => view! {
            <main class="ob-auth-state" id="main-content" tabindex="-1">
                <div class="ob-loading" role="status">
                    {move || t!(i18n, common.loading)}
                </div>
            </main>
        }
        .into_any(),
        CapabilityState::Failed => {
            let retry = move |_| {
                retry_generation.update(|generation| *generation = generation.saturating_add(1));
            };
            view! {
                <AuthStateCard
                    title=move || t_string!(i18n, auth.providers_load_error_title).to_owned()
                    body=move || t_string!(i18n, auth.providers_load_error_body).to_owned()
                >
                    <Button
                        variant=ButtonVariant::Primary
                        size=ButtonSize::Large
                        on_activate=retry
                    >
                        {move || t!(i18n, common.retry)}
                    </Button>
                </AuthStateCard>
            }
            .into_any()
        }
    }
}

#[component]
fn ProviderSignInButton(
    provider: AuthProviderId,
    opening: RwSignal<Option<SignInAttempt>>,
    start_error: RwSignal<Option<SignInAttempt>>,
) -> impl IntoView {
    let i18n = use_i18n();
    let activate = move |_| begin_provider_sign_in(provider, opening, start_error);
    view! {
        <div class="ob-sign-provider" data-auth-provider=provider.as_str()>
            <Button
                variant=ButtonVariant::Chip
                size=ButtonSize::Large
                disabled=Signal::derive(move || opening.get().is_some())
                loading=Signal::derive(move || {
                    opening.get() == Some(SignInAttempt::Provider(provider))
                })
                on_activate=activate
            >
                {move || if opening.get() == Some(SignInAttempt::Provider(provider)) {
                    t!(i18n, auth.opening).into_any()
                } else {
                    provider_label(i18n, provider)
                }}
            </Button>
        </div>
    }
}

fn provider_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    provider: AuthProviderId,
) -> AnyView {
    match provider {
        AuthProviderId::Google => t!(i18n, auth.continue_with_google).into_any(),
        AuthProviderId::Microsoft => t!(i18n, auth.continue_with_microsoft).into_any(),
        AuthProviderId::Okta => t!(i18n, auth.continue_with_okta).into_any(),
    }
}

fn provider_name(provider: AuthProviderId) -> &'static str {
    match provider {
        AuthProviderId::Google => "Google",
        AuthProviderId::Microsoft => "Microsoft",
        AuthProviderId::Okta => "Okta",
    }
}

fn sign_in_error(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    attempt: Option<SignInAttempt>,
) -> AnyView {
    match attempt {
        Some(SignInAttempt::Provider(provider)) => t!(
            i18n,
            auth.provider_start_error,
            provider = provider_name(provider)
        )
        .into_any(),
        Some(SignInAttempt::Enterprise) => t!(i18n, auth.enterprise_start_error).into_any(),
        None => ().into_any(),
    }
}

fn begin_provider_sign_in(
    provider: AuthProviderId,
    opening: RwSignal<Option<SignInAttempt>>,
    start_error: RwSignal<Option<SignInAttempt>>,
) {
    if opening.get_untracked().is_some() {
        return;
    }
    start_error.set(None);
    opening.set(Some(SignInAttempt::Provider(provider)));
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        match start_environment_sign_in(provider).await {
            Ok(target) if assign_location(&target).is_ok() => {}
            Ok(_) | Err(_) => {
                opening.set(None);
                start_error.set(Some(SignInAttempt::Provider(provider)));
            }
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        opening.set(None);
        start_error.set(Some(SignInAttempt::Provider(provider)));
    }
}

fn begin_enterprise_sign_in(
    email: RwSignal<String>,
    opening: RwSignal<Option<SignInAttempt>>,
    start_error: RwSignal<Option<SignInAttempt>>,
) {
    let email = email.get_untracked();
    if opening.get_untracked().is_some() || !enterprise_email_ready(&email) {
        return;
    }
    start_error.set(None);
    opening.set(Some(SignInAttempt::Enterprise));
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        match start_enterprise_sign_in(email).await {
            Ok(()) if assign_location(ENTERPRISE_CONTINUE_PATH).is_ok() => {}
            Ok(()) | Err(_) => {
                opening.set(None);
                start_error.set(Some(SignInAttempt::Enterprise));
            }
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        opening.set(None);
        start_error.set(Some(SignInAttempt::Enterprise));
    }
}

fn enterprise_email_ready(email: &str) -> bool {
    !email.trim().is_empty() && email.len() <= MAX_SSO_ROUTING_EMAIL_BYTES
}

#[component]
fn AuthStateCard(
    #[prop(into)] title: TextProp,
    #[prop(into)] body: TextProp,
    children: Children,
) -> impl IntoView {
    view! {
        <main class="ob-auth-state" id="main-content" tabindex="-1">
            <section class="ob-sign-card" aria-labelledby="auth-state-title">
                <header class="ob-sign-header">
                <crate::primitives::BrandMark sign_in=true/>
                    <h1 class="ob-page-title" id="auth-state-title">{move || title.get()}</h1>
                    <p class="ob-page-intro">{move || body.get()}</p>
                </header>
                <div class="ob-sign-actions">{children()}</div>
            </section>
        </main>
    }
}

#[cfg(target_arch = "wasm32")]
fn current_pathname() -> Result<String, ()> {
    web_sys::window()
        .ok_or(())?
        .location()
        .pathname()
        .map_err(|_| ())
}

#[cfg(target_arch = "wasm32")]
fn replace_location(target: &str) -> Result<(), ()> {
    web_sys::window()
        .ok_or(())?
        .location()
        .replace(target)
        .map_err(|_| ())
}

#[cfg(target_arch = "wasm32")]
fn assign_location(target: &str) -> Result<(), ()> {
    web_sys::window()
        .ok_or(())?
        .location()
        .assign(target)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unauthorized_is_a_signed_out_answer_and_sign_redirects_are_exact() {
        assert_eq!(
            auth_gate_decision(SIGN_PATH, Ok(())),
            AuthGateDecision::RedirectToApplication
        );
        assert_eq!(
            auth_gate_decision("/channel/channel-1", Ok(())),
            AuthGateDecision::MountAuthenticated
        );
        assert_eq!(
            auth_gate_decision(SIGN_PATH, Err(ApiError::Unauthorized)),
            AuthGateDecision::ShowSignIn
        );
        assert_eq!(
            auth_gate_decision("/", Err(ApiError::Unauthorized)),
            AuthGateDecision::RedirectToSignIn
        );
        for error in [
            ApiError::Network,
            ApiError::Forbidden,
            ApiError::NotFound,
            ApiError::Conflict,
            ApiError::InvalidResponse,
            ApiError::Server,
            ApiError::Unavailable,
        ] {
            assert_eq!(
                auth_gate_decision(SIGN_PATH, Err(error)),
                AuthGateDecision::ShowFailure
            );
            assert_eq!(
                auth_gate_decision("/", Err(error)),
                AuthGateDecision::ShowFailure
            );
        }
        assert!(authenticated_path_requires_root(
            AuthGateState::Authenticated,
            SIGN_PATH
        ));
        assert!(!authenticated_path_requires_root(
            AuthGateState::Authenticated,
            "/sign/"
        ));
        assert!(!authenticated_path_requires_root(
            AuthGateState::Checking,
            SIGN_PATH
        ));
    }

    #[test]
    fn provider_labels_and_enterprise_input_share_closed_limits() {
        assert_eq!(SIGN_PATH, "/sign");
        assert_eq!(ENTERPRISE_CONTINUE_PATH, "/api/auth/sso/continue");
        assert!(enterprise_email_ready("person@example.com"));
        assert!(!enterprise_email_ready("   "));
        assert!(!enterprise_email_ready(
            &"a".repeat(MAX_SSO_ROUTING_EMAIL_BYTES + 1)
        ));
        assert_eq!(provider_name(AuthProviderId::Google), "Google");
        assert_eq!(provider_name(AuthProviderId::Microsoft), "Microsoft");
        assert_eq!(provider_name(AuthProviderId::Okta), "Okta");
    }
}
