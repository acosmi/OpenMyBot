//! Personal and deployment skill management backed by the existing authenticated plugin contracts.

mod forms;
mod state;

use leptos::prelude::*;

use crate::features::admin::plugins::PluginActions;
use crate::features::layout::{
    DetailPanelLayout, DetailPanelMain, PageEmpty, PageHeader, PageRows, PageSection, PageShell,
    editor_location::EditorLocation,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{Button, ButtonVariant, IconSize, IconView, Input, Notice, NoticeTone};
use forms::{SkillDialog, SkillDialogs};
use state::SkillPageState;

/// Manage only the current actor’s own skills, including when the actor is an administrator.
#[component]
pub fn PersonalSkillsPage() -> impl IntoView {
    view! { <SkillsPage /> }
}

/// Manage deployment-owned skills behind the existing AdminShell authorization boundary.
#[component]
pub fn DeploymentSkillsPage() -> impl IntoView {
    view! { <SkillsPage deployment=true /> }
}

#[component]
fn SkillsPage(#[prop(optional)] deployment: bool) -> impl IntoView {
    let i18n = use_i18n();
    let state = SkillPageState::new();
    let actions = expect_context::<PluginActions>();
    let search = RwSignal::new(String::new());
    let dialog = RwSignal::new(None::<SkillDialog>);
    let editor = EditorLocation::new(&["skill-new", "skill-edit", "skill-grants", "skill-delete"]);
    Effect::new(move |_| {
        let selected = editor
            .selection
            .get()
            .and_then(|selected| match selected.kind {
                "skill-new" => Some(SkillDialog::Create),
                "skill-edit" => selected
                    .target
                    .filter(|s| crate::api::skills::valid_slug(s))
                    .map(SkillDialog::Edit),
                "skill-grants" => selected
                    .target
                    .filter(|s| crate::api::skills::valid_slug(s))
                    .map(SkillDialog::Grants),
                "skill-delete" => selected
                    .target
                    .filter(|s| crate::api::skills::valid_slug(s))
                    .map(SkillDialog::Delete),
                _ => None,
            });
        dialog.set(selected);
    });
    let page_open = Signal::derive(move || {
        dialog
            .get()
            .is_some_and(|dialog| !matches!(dialog, SkillDialog::Delete(_)))
    });
    Effect::new(move |_| {
        actions.revision.track();
        state.reload(deployment);
    });
    let disabled =
        Signal::derive(move || actions.busy.get() || state.loading.get() || state.error.get());
    let rows = Memo::new(move |_| {
        let query = search.get().trim().to_lowercase();
        state
            .data
            .get()
            .map(|data| data.scoped(deployment))
            .unwrap_or_default()
            .into_iter()
            .filter(|row| {
                query.is_empty()
                    || format!("{} {} {}", row.slug, row.title, row.summary)
                        .to_lowercase()
                        .contains(&query)
            })
            .collect::<Vec<_>>()
    });
    view! {
        <DetailPanelLayout open=page_open>
        <DetailPanelMain>
        <PageShell>
            <div class="ob-agent-roster-toolbar">
                <PageHeader heading_id="skills-title" title=move || if deployment { t_string!(i18n,skills.deployment_title).to_owned() } else { t_string!(i18n,skills.personal_title).to_owned() }
                    description=move || if deployment { t_string!(i18n,skills.deployment_intro).to_owned() } else { t_string!(i18n,skills.personal_intro).to_owned() } />
                <Button id="skill-create" variant=ButtonVariant::Primary disabled=disabled on_activate=move |_| editor.open("skill-new", None)>
                    <IconView icon=Icon::Plus size=IconSize::Inline />{move || t!(i18n,skills.create)}
                </Button>
            </div>
            <Input value=search input_type=crate::primitives::InputType::Search aria_label=move || t_string!(i18n,skills.search).to_owned() placeholder=move || t_string!(i18n,skills.search).to_owned() />
            <Show when=move || state.loading.get()><p role="status" class="ob-loading">{move || t!(i18n,common.loading)}</p></Show>
            <Show when=move || state.error.get()><Notice tone=NoticeTone::Error><span>{move || t!(i18n,skills.load_error)}</span><Button on_activate=move |_| state.reload(deployment)>{move || t!(i18n,common.retry)}</Button></Notice></Show>
            <PageSection heading_id="skills-list-title" title=move || t_string!(i18n,skills.saved).to_owned()>
                <Show when=move || !state.loading.get() && !state.error.get() && rows.get().is_empty()>
                    <PageEmpty>{move || if search.get().trim().is_empty(){t_string!(i18n,skills.empty).to_owned()}else{t_string!(i18n,skills.no_match).to_owned()}}</PageEmpty>
                </Show>
                <Show when=move || !rows.get().is_empty()>
                    <PageRows>
                        <For each=move || rows.get() key=|skill| (skill.id.clone(), skill.title.clone(), skill.summary.clone(), skill.granted_to.clone()) children=move |skill| {
                            let edit=skill.slug.clone();let remove=skill.slug.clone();let grants=skill.slug.clone();
                            view! { <div class="ob-plugin-grant">
                                <div class="ob-plugin-copy"><strong>{skill.title}</strong><code>{format!("/{}",skill.slug)}</code><p class="text-fg-secondary">{skill.summary}</p>
                                    <span class="text-fg-muted">{move || t_string!(i18n,skills.grant_count,count=skill.granted_to.len()).to_owned()}</span>
                                </div>
                                <div class="ob-plugin-controls">
                                    <Button id=format!("skill-edit-{edit}") disabled=disabled on_activate=move |_|editor.open("skill-edit", Some(edit.clone()))>{move || t!(i18n,skills.edit)}</Button>
                                    <Button id=format!("skill-grants-{grants}") disabled=disabled on_activate=move |_|editor.open("skill-grants", Some(grants.clone()))>{move || t!(i18n,skills.grants)}</Button>
                                    <Button id=format!("skill-delete-{remove}") disabled=disabled variant=ButtonVariant::DangerText on_activate=move |_|editor.open("skill-delete", Some(remove.clone()))>{move || t!(i18n,skills.delete)}</Button>
                                </div>
                            </div> }
                        } />
                    </PageRows>
                </Show>
            </PageSection>
            <p class="ob-page-empty">{move || t!(i18n,skills.runtime_pending)}</p>
        </PageShell>
        </DetailPanelMain>
        <SkillDialogs dialog state deployment editor />
        </DetailPanelLayout>
    }
}
