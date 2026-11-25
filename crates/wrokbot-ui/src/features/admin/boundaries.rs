//! Administrator action-policy editor backed by the existing production policy boundary.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use openbot_contracts::policy::{
    ActionPolicyDocument, ActionPolicyMode, MAX_ACTION_POLICY_EXPRESSION_BYTES,
};
use openbot_contracts::text::trim_ecmascript;

#[cfg(target_arch = "wasm32")]
use crate::api::{load_action_policy, save_action_policy};
use crate::features::layout::{PageEmpty, PageHeader, PageSection, PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, IconSize, IconView, Input, InputType, Notice,
    NoticePresentation, NoticeTone,
};

const ALLOW_EVERYTHING_RULE: &str = "true";
const NEVER_SUBMIT_RULE: &str = "(intent == \"activate\" && contains(element.name, \"submit\")) || ((tool.name == \"computer_key\" || tool.name == \"computer_type\") && key == \"Enter\")";
const NEVER_PASSWORD_RULE: &str = "intent == \"type\" && contains(element.name, \"password\")";
const STAY_OFF_SOCIAL_RULE: &str = "intent == \"navigate\" && (contains(page.host, \"facebook.com\") || contains(page.host, \"x.com\"))";

#[derive(Clone)]
struct PolicySaveIntent {
    document: ActionPolicyDocument,
    clear_draft: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleDraftError {
    Empty,
    TooLong,
    Duplicate,
    Unconfigured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BaselineShape {
    DefaultDeny,
    AllowUnmatched,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FirstSetupPreset {
    DefaultDeny,
    AllowUnmatched,
}

#[derive(Clone, Copy)]
struct BoundaryPreset {
    kind: BoundaryPresetKind,
    rule: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BoundaryPresetKind {
    NeverSubmit,
    NeverPassword,
    StayOffSocial,
}

const BOUNDARY_PRESETS: [BoundaryPreset; 3] = [
    BoundaryPreset {
        kind: BoundaryPresetKind::NeverSubmit,
        rule: NEVER_SUBMIT_RULE,
    },
    BoundaryPreset {
        kind: BoundaryPresetKind::NeverPassword,
        rule: NEVER_PASSWORD_RULE,
    },
    BoundaryPreset {
        kind: BoundaryPresetKind::StayOffSocial,
        rule: STAY_OFF_SOCIAL_RULE,
    },
];

/// First-setup wizard and ordered CEL boundary editor.
#[component]
pub fn AdminBoundariesPage() -> impl IntoView {
    let i18n = use_i18n();
    let policy = RwSignal::new(None::<ActionPolicyDocument>);
    let loading = RwSignal::new(false);
    let load_error = RwSignal::new(false);
    let save_pending = RwSignal::new(false);
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::Boundaries,
        move || "$policy".into(),
    );
    let save_error = RwSignal::new(false);
    let saved = RwSignal::new(false);
    let draft = RwSignal::new(String::new());
    let draft_error = RwSignal::new(None::<RuleDraftError>);
    let page_owner = StoredValue::new(Owner::current());

    request_action_policy(policy, loading, load_error, page_owner);
    let save = UnsyncCallback::new(move |intent: PolicySaveIntent| {
        dispatch_policy_save(
            intent,
            policy,
            draft,
            draft_error,
            save_pending,
            save_error,
            saved,
            page_owner,
        );
    });
    let retry = move |_| request_action_policy(policy, loading, load_error, page_owner);

    let choose_default_deny = UnsyncCallback::new(move |_| {
        save.run(PolicySaveIntent {
            document: first_setup_policy(FirstSetupPreset::DefaultDeny),
            clear_draft: false,
        });
    });
    let choose_allow_unmatched = UnsyncCallback::new(move |_| {
        save.run(PolicySaveIntent {
            document: first_setup_policy(FirstSetupPreset::AllowUnmatched),
            clear_draft: false,
        });
    });
    let enforce = move |_| save_mode(policy, save, ActionPolicyMode::Enforce);
    let dry_run = move |_| save_mode(policy, save, ActionPolicyMode::DryRun);
    let add_rule = UnsyncCallback::new(move |_| {
        draft_error.set(None);
        match add_deny_rule(policy.get_untracked(), &draft.get_untracked()) {
            Ok(document) => save.run(PolicySaveIntent {
                document,
                clear_draft: true,
            }),
            Err(error) => draft_error.set(Some(error)),
        }
    });
    let submit_rule = move |event: SubmitEvent| {
        event.prevent_default();
        add_rule.run(());
    };
    let allow_unmatched = move |_| {
        save_baseline(policy, save, BaselineShape::AllowUnmatched);
    };
    let deny_unmatched = move |_| {
        save_baseline(policy, save, BaselineShape::DefaultDeny);
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="admin-boundaries-title"
                title=move || t_string!(i18n, boundaries.title).to_owned()
                description=move || t_string!(i18n, boundaries.intro).to_owned()
            />
            <p class="ob-boundaries-audit-link">
                <a href="/admin/audit">{move || t!(i18n, boundaries.open_audit)}</a>
            </p>
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">
                    <IconView icon=Icon::LoaderCircle size=IconSize::Navigation />
                    <span>{move || t!(i18n, common.loading)}</span>
                </div>
            </Show>
            <Show when=move || load_error.get()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, boundaries.load_error)}</span>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        on_activate=retry
                    >
                        {move || t!(i18n, common.retry)}
                    </Button>
                </Notice>
            </Show>
            <Show when=move || save_error.get()>
                <Notice tone=NoticeTone::Error>{move || t!(i18n, boundaries.save_error)}</Notice>
            </Show>
            <Show when=move || saved.get()>
                <Notice tone=NoticeTone::Success>{move || t!(i18n, boundaries.saved)}</Notice>
            </Show>
            <Show when=move || {
                !loading.get() && !load_error.get() && policy.get().is_none()
            }>
                <FirstSetup
                    save_pending
                    choose_default_deny
                    choose_allow_unmatched
                />
            </Show>
            <Show when=move || policy.get().is_some()>
                <PageSection
                    heading_id="boundary-mode-title"
                    title=move || t_string!(i18n, boundaries.mode_title).to_owned()
                    description=move || t_string!(i18n, boundaries.mode_intro).to_owned()
                >
                    <div class="ob-boundary-mode-actions">
                        <Button
                            variant=ButtonVariant::Chip
                            size=ButtonSize::Small
                            selected=Signal::derive(move || {
                                policy.get().is_some_and(|policy| {
                                    policy.mode == ActionPolicyMode::Enforce
                                })
                            })
                            disabled=Signal::derive(move || save_pending.get() || write_lock.get())
                            on_activate=enforce
                        >
                            {move || t!(i18n, boundaries.mode_enforce)}
                        </Button>
                        <Button
                            variant=ButtonVariant::Chip
                            size=ButtonSize::Small
                            selected=Signal::derive(move || {
                                policy.get().is_some_and(|policy| {
                                    policy.mode == ActionPolicyMode::DryRun
                                })
                            })
                            disabled=Signal::derive(move || save_pending.get() || write_lock.get())
                            on_activate=dry_run
                        >
                            {move || t!(i18n, boundaries.mode_dry_run)}
                        </Button>
                    </div>
                    <p class="ob-boundary-mode-help">
                        {move || match policy.get().map(|policy| policy.mode) {
                            Some(ActionPolicyMode::Enforce) => {
                                t_string!(i18n, boundaries.mode_enforce_help).to_owned()
                            }
                            Some(ActionPolicyMode::DryRun) => {
                                t_string!(i18n, boundaries.mode_dry_run_help).to_owned()
                            }
                            None => String::new(),
                        }}
                    </p>
                </PageSection>

                <PageSection
                    heading_id="boundary-deny-title"
                    title=move || t_string!(i18n, boundaries.deny_title).to_owned()
                    description=move || t_string!(i18n, boundaries.deny_intro).to_owned()
                >
                    <Show
                        when=move || policy.get().is_some_and(|policy| !policy.deny.is_empty())
                        fallback=move || view! {
                            <PageEmpty>{move || t!(i18n, boundaries.deny_empty)}</PageEmpty>
                        }
                    >
                        <ul class="ob-boundary-rule-list">
                            <For
                                each=move || policy.get().map_or_else(Vec::new, |policy| {
                                    policy.deny.into_iter().enumerate().collect::<Vec<_>>()
                                })
                                key=|(index, rule)| (*index, rule.clone())
                                children=move |(index, rule)| {
                                    let displayed = if rule.is_empty() {
                                        t_string!(i18n, boundaries.empty_rule).to_owned()
                                    } else {
                                        rule
                                    };
                                    let remove = move |_| {
                                        if let Some(document) = policy.get_untracked() {
                                            save.run(PolicySaveIntent {
                                                document: remove_deny_rule(document, index),
                                                clear_draft: false,
                                            });
                                        }
                                    };
                                    view! {
                                        <li>
                                            <code>{displayed}</code>
                                            <Button
                                                aria_label=move || t_string!(
                                                    i18n,
                                                    boundaries.remove_rule_label,
                                                    number = index + 1,
                                                ).to_owned()
                                                variant=ButtonVariant::Ghost
                                                size=ButtonSize::Small
                                                disabled=Signal::derive(move || save_pending.get() || write_lock.get())
                                                on_activate=remove
                                            >
                                                {move || t!(i18n, boundaries.remove_rule)}
                                            </Button>
                                        </li>
                                    }
                                }
                            />
                        </ul>
                    </Show>

                    <form class="ob-boundary-rule-form" on:submit=submit_rule>
                        <Input
                            value=draft
                            input_type=InputType::Text
                            aria_label=move || t_string!(i18n, boundaries.rule_label).to_owned()
                            placeholder=move || t_string!(i18n, boundaries.rule_placeholder).to_owned()
                            invalid=Signal::derive(move || draft_error.get().is_some())
                            disabled=Signal::derive(move || save_pending.get() || write_lock.get())
                        />
                        <Button
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Small
                            disabled=Signal::derive(move || {
                                save_pending.get() || write_lock.get() || trim_ecmascript(&draft.get()).is_empty()
                            })
                            on_activate=move |_| add_rule.run(())
                        >
                            {move || t!(i18n, boundaries.add_rule)}
                        </Button>
                    </form>
                    <Show when=move || draft_error.get().is_some()>
                        <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                            {move || draft_error_text(i18n, draft_error.get())}
                        </Notice>
                    </Show>

                    <ul class="ob-boundary-presets">
                        <For
                            each=move || BOUNDARY_PRESETS
                            key=|preset| preset.kind
                            children=move |preset| {
                                let add = move |_| {
                                    draft_error.set(None);
                                    match add_deny_rule(
                                        policy.get_untracked(),
                                        preset.rule,
                                    ) {
                                        Ok(document) => save.run(PolicySaveIntent {
                                            document,
                                            clear_draft: false,
                                        }),
                                        Err(error) => draft_error.set(Some(error)),
                                    }
                                };
                                view! {
                                    <li>
                                        <Button
                                            variant=ButtonVariant::Chip
                                            size=ButtonSize::Small
                                            disabled=Signal::derive(move || {
                                                save_pending.get() || write_lock.get()
                                                    || policy.get().is_none_or(|policy| {
                                                        policy.deny.iter().any(|rule| rule == preset.rule)
                                                    })
                                            })
                                            on_activate=add
                                        >
                                            {move || preset_label(i18n, preset.kind)}
                                        </Button>
                                        <span>{move || preset_cost(i18n, preset.kind)}</span>
                                    </li>
                                }
                            }
                        />
                    </ul>
                </PageSection>

                <PageSection
                    heading_id="boundary-allow-title"
                    title=move || t_string!(i18n, boundaries.allow_title).to_owned()
                    description=move || t_string!(i18n, boundaries.allow_intro).to_owned()
                >
                    {move || policy.get().map(|document| {
                        let shape = baseline_shape(&document);
                        view! {
                            <ul class="ob-boundary-allow-list">
                                {document.allow.into_iter().map(|rule| view! {
                                    <li><code>{if rule == ALLOW_EVERYTHING_RULE {
                                        t_string!(i18n, boundaries.allow_true).to_owned()
                                    } else if rule.is_empty() {
                                        t_string!(i18n, boundaries.empty_rule).to_owned()
                                    } else {
                                        rule
                                    }}</code></li>
                                }).collect_view()}
                            </ul>
                            <Show when=move || shape == BaselineShape::DefaultDeny>
                                <p class="ob-page-empty">{move || t!(i18n, boundaries.allow_none)}</p>
                                <Button
                                    variant=ButtonVariant::Chip
                                    size=ButtonSize::Small
                                    disabled=Signal::derive(move || save_pending.get() || write_lock.get())
                                    on_activate=allow_unmatched
                                >
                                    {move || t!(i18n, boundaries.allow_unmatched)}
                                </Button>
                            </Show>
                            <Show when=move || shape == BaselineShape::AllowUnmatched>
                                <Button
                                    variant=ButtonVariant::DangerText
                                    size=ButtonSize::Small
                                    disabled=Signal::derive(move || save_pending.get() || write_lock.get())
                                    on_activate=deny_unmatched
                                >
                                    {move || t!(i18n, boundaries.deny_unmatched)}
                                </Button>
                            </Show>
                            <Show when=move || shape == BaselineShape::Custom>
                                <p class="ob-boundary-custom-allow">
                                    {move || t!(i18n, boundaries.custom_allow_read_only)}
                                </p>
                            </Show>
                        }
                    })}
                </PageSection>
            </Show>
        </PageShell>
    }
}

#[component]
fn FirstSetup(
    save_pending: RwSignal<bool>,
    choose_default_deny: UnsyncCallback<()>,
    choose_allow_unmatched: UnsyncCallback<()>,
) -> impl IntoView {
    let i18n = use_i18n();
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::Boundaries,
        move || "$policy".into(),
    );
    view! {
        <PageSection
            heading_id="boundary-first-setup-title"
            title=move || t_string!(i18n, boundaries.first_setup_title).to_owned()
            description=move || t_string!(i18n, boundaries.first_setup_intro).to_owned()
        >
            <div class="ob-boundary-first-setup">
                <article>
                    <h3>{move || t!(i18n, boundaries.first_setup_strict)}</h3>
                    <p>{move || t!(i18n, boundaries.first_setup_strict_help)}</p>
                    <Button
                        variant=ButtonVariant::Primary
                        size=ButtonSize::Medium
                        disabled=Signal::derive(move || save_pending.get() || write_lock.get())
                        on_activate=choose_default_deny
                    >
                        {move || t!(i18n, boundaries.choose_strict)}
                    </Button>
                </article>
                <article>
                    <h3>{move || t!(i18n, boundaries.first_setup_compatible)}</h3>
                    <p>{move || t!(i18n, boundaries.first_setup_compatible_help)}</p>
                    <Button
                        variant=ButtonVariant::Chip
                        size=ButtonSize::Medium
                        disabled=Signal::derive(move || save_pending.get() || write_lock.get())
                        on_activate=choose_allow_unmatched
                    >
                        {move || t!(i18n, boundaries.choose_compatible)}
                    </Button>
                </article>
            </div>
        </PageSection>
    }
}

fn request_action_policy(
    policy: RwSignal<Option<ActionPolicyDocument>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
    page_owner: StoredValue<Option<Owner>>,
) {
    if loading.get_untracked() {
        return;
    }
    loading.set(true);
    load_error.set(false);
    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match load_action_policy().await {
                    Ok(stored) => policy.set(stored),
                    Err(_) => load_error.set(true),
                }
                loading.set(false);
            });
        };
        match page_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (policy, page_owner);
        loading.set(false);
        load_error.set(true);
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_policy_save(
    intent: PolicySaveIntent,
    policy: RwSignal<Option<ActionPolicyDocument>>,
    draft: RwSignal<String>,
    draft_error: RwSignal<Option<RuleDraftError>>,
    pending: RwSignal<bool>,
    error: RwSignal<bool>,
    saved: RwSignal<bool>,
    page_owner: StoredValue<Option<Owner>>,
) {
    if pending.get_untracked() {
        return;
    }
    pending.set(true);
    error.set(false);
    saved.set(false);
    #[cfg(target_arch = "wasm32")]
    {
        let writes = expect_context::<crate::configuration_writes::ConfigurationWrites>();
        let start_worker = move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match save_action_policy(&intent.document).await {
                    Ok(stored) => {
                        policy.set(Some(stored));
                        if intent.clear_draft {
                            draft.set(String::new());
                        }
                        draft_error.set(None);
                        saved.set(true);
                    }
                    Err(_) => error.set(!writes.locked(
                        crate::configuration_writes::ConfigurationKind::Boundaries,
                        "$policy",
                    )),
                }
                pending.set(false);
            });
        };
        match page_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let PolicySaveIntent {
            document,
            clear_draft,
        } = intent;
        let _ = (
            document,
            clear_draft,
            policy,
            draft,
            draft_error,
            page_owner,
        );
        error.set(true);
        pending.set(false);
    }
}

fn save_mode(
    policy: RwSignal<Option<ActionPolicyDocument>>,
    save: UnsyncCallback<PolicySaveIntent>,
    mode: ActionPolicyMode,
) {
    let Some(mut document) = policy.get_untracked() else {
        return;
    };
    if document.mode == mode {
        return;
    }
    document.mode = mode;
    save.run(PolicySaveIntent {
        document,
        clear_draft: false,
    });
}

fn save_baseline(
    policy: RwSignal<Option<ActionPolicyDocument>>,
    save: UnsyncCallback<PolicySaveIntent>,
    baseline: BaselineShape,
) {
    let Some(mut document) = policy.get_untracked() else {
        return;
    };
    document.allow = match baseline {
        BaselineShape::DefaultDeny => Vec::new(),
        BaselineShape::AllowUnmatched => vec![ALLOW_EVERYTHING_RULE.to_owned()],
        BaselineShape::Custom => return,
    };
    save.run(PolicySaveIntent {
        document,
        clear_draft: false,
    });
}

fn first_setup_policy(preset: FirstSetupPreset) -> ActionPolicyDocument {
    ActionPolicyDocument {
        mode: ActionPolicyMode::Enforce,
        deny: Vec::new(),
        allow: match preset {
            FirstSetupPreset::DefaultDeny => Vec::new(),
            FirstSetupPreset::AllowUnmatched => vec![ALLOW_EVERYTHING_RULE.to_owned()],
        },
    }
}

fn add_deny_rule(
    policy: Option<ActionPolicyDocument>,
    draft: &str,
) -> Result<ActionPolicyDocument, RuleDraftError> {
    let mut document = policy.ok_or(RuleDraftError::Unconfigured)?;
    let rule = trim_ecmascript(draft);
    if rule.is_empty() {
        return Err(RuleDraftError::Empty);
    }
    if rule.len() > MAX_ACTION_POLICY_EXPRESSION_BYTES {
        return Err(RuleDraftError::TooLong);
    }
    if document.deny.iter().any(|stored| stored == rule) {
        return Err(RuleDraftError::Duplicate);
    }
    document.deny.push(rule.to_owned());
    Ok(document)
}

fn remove_deny_rule(mut policy: ActionPolicyDocument, index: usize) -> ActionPolicyDocument {
    if index < policy.deny.len() {
        policy.deny.remove(index);
    }
    policy
}

fn baseline_shape(policy: &ActionPolicyDocument) -> BaselineShape {
    match policy.allow.as_slice() {
        [] => BaselineShape::DefaultDeny,
        [rule] if rule == ALLOW_EVERYTHING_RULE => BaselineShape::AllowUnmatched,
        _ => BaselineShape::Custom,
    }
}

fn draft_error_text(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    error: Option<RuleDraftError>,
) -> String {
    match error {
        Some(RuleDraftError::Empty) => t_string!(i18n, boundaries.rule_empty).to_owned(),
        Some(RuleDraftError::TooLong) => t_string!(
            i18n,
            boundaries.rule_too_long,
            max = MAX_ACTION_POLICY_EXPRESSION_BYTES,
        )
        .to_owned(),
        Some(RuleDraftError::Duplicate) => t_string!(i18n, boundaries.rule_duplicate).to_owned(),
        Some(RuleDraftError::Unconfigured) => {
            t_string!(i18n, boundaries.rule_unconfigured).to_owned()
        }
        None => String::new(),
    }
}

fn preset_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    kind: BoundaryPresetKind,
) -> String {
    match kind {
        BoundaryPresetKind::NeverSubmit => {
            t_string!(i18n, boundaries.preset_never_submit).to_owned()
        }
        BoundaryPresetKind::NeverPassword => {
            t_string!(i18n, boundaries.preset_never_password).to_owned()
        }
        BoundaryPresetKind::StayOffSocial => {
            t_string!(i18n, boundaries.preset_stay_off_social).to_owned()
        }
    }
}

fn preset_cost(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    kind: BoundaryPresetKind,
) -> String {
    match kind {
        BoundaryPresetKind::NeverSubmit => {
            t_string!(i18n, boundaries.preset_never_submit_cost).to_owned()
        }
        BoundaryPresetKind::NeverPassword => {
            t_string!(i18n, boundaries.preset_never_password_cost).to_owned()
        }
        BoundaryPresetKind::StayOffSocial => {
            t_string!(i18n, boundaries.preset_stay_off_social_cost).to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ActionPolicyDocument {
        ActionPolicyDocument {
            mode: ActionPolicyMode::Enforce,
            deny: vec!["first".to_owned(), "second".to_owned()],
            allow: vec![ALLOW_EVERYTHING_RULE.to_owned()],
        }
    }

    #[test]
    fn first_setup_has_no_implicit_choice_and_baselines_are_reversible() {
        let strict = first_setup_policy(FirstSetupPreset::DefaultDeny);
        assert_eq!(strict.mode, ActionPolicyMode::Enforce);
        assert!(strict.deny.is_empty());
        assert!(strict.allow.is_empty());
        assert_eq!(baseline_shape(&strict), BaselineShape::DefaultDeny);

        let compatible = first_setup_policy(FirstSetupPreset::AllowUnmatched);
        assert_eq!(compatible.allow, [ALLOW_EVERYTHING_RULE]);
        assert_eq!(baseline_shape(&compatible), BaselineShape::AllowUnmatched);
        let custom = ActionPolicyDocument {
            allow: vec!["actor.id == \"owner\"".to_owned()],
            ..compatible
        };
        assert_eq!(baseline_shape(&custom), BaselineShape::Custom);
    }

    #[test]
    fn deny_add_remove_uses_ecmascript_trim_limit_order_and_exact_duplicate_rules() {
        let added = add_deny_rule(Some(policy()), "\u{feff} third \u{feff}").unwrap();
        assert_eq!(added.deny, ["first", "second", "third"]);
        assert_eq!(
            add_deny_rule(Some(added.clone()), "third").unwrap_err(),
            RuleDraftError::Duplicate,
        );
        assert_eq!(
            add_deny_rule(Some(added.clone()), &"x".repeat(4097)).unwrap_err(),
            RuleDraftError::TooLong,
        );
        assert_eq!(
            add_deny_rule(Some(added.clone()), " \t\n ").unwrap_err(),
            RuleDraftError::Empty,
        );
        assert_eq!(
            add_deny_rule(None, "true").unwrap_err(),
            RuleDraftError::Unconfigured,
        );
        assert_eq!(remove_deny_rule(added, 1).deny, ["first", "third"]);
    }

    #[test]
    fn fixed_upstream_presets_are_unique_and_inside_the_shared_parser_limit() {
        let mut rules = BOUNDARY_PRESETS.map(|preset| preset.rule).to_vec();
        assert!(
            rules
                .iter()
                .all(|rule| rule.len() <= MAX_ACTION_POLICY_EXPRESSION_BYTES)
        );
        rules.sort_unstable();
        rules.dedup();
        assert_eq!(rules.len(), BOUNDARY_PRESETS.len());
        assert_eq!(NEVER_SUBMIT_RULE.len(), 143);
    }
}
