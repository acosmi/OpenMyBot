//! The direct-Bot entry's explicit model choice.
//!
//! `SubmitThreadInput` accepts only a v2 body whose selection is `custom`, and the Server compares
//! all four frozen values against the durable connection and catalog rows. The owner's custom
//! model catalog is therefore the only authoritative source: no revision is guessed, no value is
//! repaired, a disabled entry never becomes a selection, and nothing falls back to another model.

use leptos::prelude::*;
use openbot_contracts::custom_model_catalog::CustomModelCatalogEntry;
use openbot_contracts::versioned_model_selection::{
    ModelSelectionIntentSource, RunModelSelectionV2,
};

#[cfg(target_arch = "wasm32")]
use crate::api::list_custom_model_catalog;
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{Select, SelectContent, SelectItem, SelectTrigger};

/// Closed status of the catalog the picker reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CatalogStatus {
    /// The catalog has not been read yet.
    Idle,
    /// A read is in flight.
    Loading,
    /// The catalog is loaded and usable.
    Ready,
    /// The catalog could not be read.
    Failed,
}

/// One catalog row the picker shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CatalogChoice {
    /// Stable connection identity.
    pub(crate) connection_id: String,
    /// User-visible name.
    pub(crate) name: String,
    /// Provider model name.
    pub(crate) model: String,
    /// The exact v2 selection this entry produces; `None` exactly for a disabled entry, which is
    /// shown but can never be chosen.
    pub(crate) selection: Option<RunModelSelectionV2>,
}

/// Build the versioned selection one catalog entry stands for; a disabled entry has none.
pub(crate) fn selection_v2(entry: &CustomModelCatalogEntry) -> Option<RunModelSelectionV2> {
    if !entry.enabled {
        return None;
    }
    RunModelSelectionV2::new(
        ModelSelectionIntentSource::Custom,
        entry.connection_id.clone(),
        entry.connection_revision,
        entry.model_id.clone(),
        entry.catalog_revision,
    )
    .ok()
}

/// The direct-Bot entry's frozen model choice.
///
/// The composer owns signals, not values, so it is copied rather than cloned: every closure that
/// needs the choice works on the same choice. The choice lives as long as the conversation mount:
/// it is kept across sends and is only dropped by a new conversation or a catalog that no longer
/// offers it unchanged.
#[derive(Clone, Copy)]
pub(crate) struct ModelComposerV2 {
    /// The chosen catalog entry's frozen selection, when one is chosen.
    pub(crate) selected: RwSignal<Option<RunModelSelectionV2>>,
    /// The catalog dropped or changed the chosen entry, so it must be chosen again.
    repick: RwSignal<bool>,
    /// The catalog rows the picker shows.
    choices: RwSignal<Vec<CatalogChoice>>,
    /// The catalog read status.
    status: RwSignal<CatalogStatus>,
    /// Whether the picker popup is open.
    open: RwSignal<bool>,
    /// The remote assistant cannot carry an explicit local model selection.
    pub(crate) supports_explicit: Signal<bool>,
    request_epoch: RwSignal<u64>,
}

impl ModelComposerV2 {
    /// Build the composer for one conversation.
    ///
    /// The catalog is read when the picker is mounted, not here: a conversation that never shows
    /// the picker must not issue a catalog request.
    pub(crate) fn new(supports_explicit: Signal<bool>) -> Self {
        Self {
            selected: RwSignal::new(None),
            repick: RwSignal::new(false),
            choices: RwSignal::new(Vec::new()),
            status: RwSignal::new(CatalogStatus::Idle),
            open: RwSignal::new(false),
            supports_explicit,
            request_epoch: RwSignal::new(0),
        }
    }

    /// Read the owner's catalog again.
    pub(crate) fn reload(self) {
        let epoch = self.request_epoch.get_untracked().saturating_add(1);
        self.request_epoch.set(epoch);
        self.status.set(CatalogStatus::Loading);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local(async move {
            let result = list_custom_model_catalog().await;
            // A newer read, or the end of this conversation, makes this reply irrelevant.
            if self.request_epoch.try_get_untracked() != Some(epoch) {
                return;
            }
            match result {
                Ok(page) => self.install(
                    page.models
                        .iter()
                        .map(|entry| CatalogChoice {
                            connection_id: entry.connection_id.clone(),
                            name: entry.name.clone(),
                            model: entry.model.clone(),
                            selection: selection_v2(entry),
                        })
                        .collect(),
                ),
                Err(_) => self.status.set(CatalogStatus::Failed),
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        self.status.set(CatalogStatus::Failed);
    }

    /// Show a freshly read catalog. A chosen selection the catalog no longer offers unchanged is
    /// dropped, and the user is told to choose again instead of being moved to another entry.
    fn install(self, choices: Vec<CatalogChoice>) {
        if let Some(selected) = self.selected.get_untracked()
            && !choices
                .iter()
                .any(|choice| choice.selection.as_ref() == Some(&selected))
        {
            self.selected.set(None);
            self.repick.set(true);
        }
        self.choices.set(choices);
        self.status.set(CatalogStatus::Ready);
    }

    /// The frozen selection the next direct-Bot submission must carry.
    ///
    /// A submission without a selection is refused by the Server, so a missing choice is a
    /// visible refusal rather than a silently downgraded request. A remote assistant cannot carry
    /// an explicit local model selection at all, so it never freezes one.
    pub(crate) fn freeze(self) -> Option<RunModelSelectionV2> {
        if !self.supports_explicit.get_untracked() {
            return None;
        }
        self.selected.get_untracked()
    }

    /// Apply the value emitted by a catalog option without rebuilding its frozen selection.
    fn choose(self, value: &str) {
        let chosen = self.choices.get_untracked().into_iter().find_map(|choice| {
            choice
                .selection
                .filter(|selection| selection_key(selection) == value)
        });
        if let Some(chosen) = chosen {
            self.selected.set(Some(chosen));
            self.repick.set(false);
        }
    }
}

/// The direct-Bot entry's model picker.
#[component]
pub fn ModelPickerV2(state: ModelComposerV2, disabled: Signal<bool>) -> impl IntoView {
    let i18n = use_i18n();
    if state.status.get_untracked() == CatalogStatus::Idle {
        state.reload();
    }
    let picker_value = RwSignal::new(
        state
            .selected
            .get_untracked()
            .map(|selection| selection_key(&selection)),
    );
    Effect::new(move |_| {
        if disabled.get() {
            state.open.set(false);
        }
        picker_value.set(
            state
                .selected
                .get()
                .map(|selection| selection_key(&selection)),
        );
    });
    let choose = UnsyncCallback::new(move |value: Option<String>| {
        if let Some(value) = value
            && !disabled.get_untracked()
        {
            state.choose(&value);
        }
    });

    view! {
        <div class="ob-skill-picker">
            <Select
                id="bot-model-picker"
                open=state.open
                value=picker_value
                disabled=disabled
                on_value_change=choose
            >
                <SelectTrigger
                    aria_label=move || t_string!(i18n, models.choose_for_next).to_owned()
                    placeholder=move || match state.status.get() {
                        CatalogStatus::Idle | CatalogStatus::Loading => {
                            t_string!(i18n, common.loading).to_owned()
                        }
                        CatalogStatus::Ready if state.selected.get().is_some() => {
                            t_string!(i18n, models.custom_source).to_owned()
                        }
                        CatalogStatus::Ready if state.repick.get() => {
                            t_string!(i18n, bot_work.model_repick).to_owned()
                        }
                        CatalogStatus::Ready => t_string!(i18n, bot_work.model_choose).to_owned(),
                        CatalogStatus::Failed => {
                            t_string!(i18n, models.selection_unavailable_label).to_owned()
                        }
                    }
                />
                <SelectContent>
                    <For
                        each=move || state.choices.get()
                        // A re-read catalog may change an entry's revisions or enablement under
                        // the same connection, so the option is rebuilt from the whole row.
                        key=|choice| format!("{choice:?}")
                        children=move |choice| {
                            let value = choice
                                .selection
                                .as_ref()
                                .map_or_else(|| choice.connection_id.clone(), selection_key);
                            let disabled = choice.selection.is_none();
                            let supports = state.supports_explicit;
                            let label = format!("{} · {}", choice.name, choice.model);
                            view! {
                                <SelectItem
                                    id=format!("bot-model-{}", choice.connection_id)
                                    value=value
                                    label=label
                                    disabled=Signal::derive(move || disabled || !supports.get())
                                >
                                    <strong>{choice.name}</strong>
                                    <small>{choice.model}</small>
                                </SelectItem>
                            }
                        }
                    />
                    <Show when=move || state.status.get()==CatalogStatus::Loading>
                        <p role="status">{move || t!(i18n, common.loading)}</p>
                    </Show>
                    <Show when=move || state.status.get()==CatalogStatus::Failed>
                        <p class="ob-alert" role="alert">{move || t!(i18n, models.load_failed)}</p>
                    </Show>
                    <Show when=move || state.status.get()==CatalogStatus::Ready && state.choices.get().is_empty()>
                        <p>{move || t!(i18n, models.none_available)}</p>
                    </Show>
                </SelectContent>
            </Select>
            <Show when=move || !state.supports_explicit.get()>
                <span class="ob-page-empty" role="status">
                    {move || t!(i18n, bot_work.remote_assistant_unsupported)}
                </span>
            </Show>
        </div>
    }
}

/// The stable picker value of one selection.
fn selection_key(selection: &RunModelSelectionV2) -> String {
    format!(
        "{}:{}",
        selection.connection_id(),
        selection.expected_catalog_revision()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> CustomModelCatalogEntry {
        CustomModelCatalogEntry {
            source: openbot_contracts::model_connections::ModelConnectionSource::Custom,
            connection_id: "01991389-7380-7000-8000-000000000004".to_owned(),
            connection_revision: 3,
            model_id: "custom:01991389-7380-7000-8000-000000000004".to_owned(),
            catalog_revision: 7,
            name: "Local".to_owned(),
            protocol: openbot_contracts::model_connections::CustomModelProtocol::OpenaiResponses,
            model: "model".to_owned(),
            enabled: true,
        }
    }

    fn choice(entry: &CustomModelCatalogEntry) -> CatalogChoice {
        CatalogChoice {
            connection_id: entry.connection_id.clone(),
            name: entry.name.clone(),
            model: entry.model.clone(),
            selection: selection_v2(entry),
        }
    }

    #[test]
    fn a_catalog_entry_assembles_the_exact_v2_selection_and_disabled_rows_cannot() {
        let entry = entry();
        let selection = selection_v2(&entry).expect("enabled catalog entry assembles");
        assert_eq!(selection.source(), ModelSelectionIntentSource::Custom);
        assert_eq!(selection.connection_id(), entry.connection_id);
        assert_eq!(selection.expected_connection_revision(), 3);
        assert_eq!(selection.model_id(), entry.model_id);
        assert_eq!(selection.expected_catalog_revision(), 7);

        let mut disabled = entry;
        disabled.enabled = false;
        assert!(selection_v2(&disabled).is_none());
    }

    #[test]
    fn a_broken_catalog_entry_never_produces_a_selection() {
        let mut broken = entry();
        broken.catalog_revision = 0;
        assert!(selection_v2(&broken).is_none());
        let mut broken = entry();
        broken.connection_revision = 0;
        assert!(selection_v2(&broken).is_none());
    }

    #[test]
    fn picker_option_value_selects_the_frozen_catalog_entry() {
        Owner::new().with(|| {
            let composer = ModelComposerV2::new(Signal::derive(|| true));
            let entry = entry();
            let expected = selection_v2(&entry).expect("enabled catalog entry assembles");
            composer.install(vec![choice(&entry)]);
            // Use the production option value and selection handler, rather than assigning
            // `selected` directly and bypassing the menu's value contract.
            composer.choose(&selection_key(&expected));
            let frozen = composer
                .freeze()
                .expect("choosing the menu option selects a model");
            assert_eq!(frozen, expected);
            let body = super::super::submit::v2_body(
                &openbot_contracts::ids::RunId::new("run"),
                &openbot_contracts::ids::BotId::new("bot"),
                "hello",
                &[],
                &frozen,
            );
            assert_eq!(body.model_selection, expected);
        });
    }

    #[test]
    fn a_remote_assistant_can_never_freeze_a_local_selection() {
        Owner::new().with(|| {
            let composer = ModelComposerV2::new(Signal::derive(|| false));
            composer.selected.set(selection_v2(&entry()));
            assert!(composer.freeze().is_none());
        });
    }

    #[test]
    fn a_builtin_assistant_without_a_choice_has_no_selection_to_send() {
        Owner::new().with(|| {
            let composer = ModelComposerV2::new(Signal::derive(|| true));
            assert!(composer.freeze().is_none());
        });
    }

    #[test]
    fn the_choice_is_kept_across_sends_until_the_catalog_stops_offering_it_unchanged() {
        Owner::new().with(|| {
            let composer = ModelComposerV2::new(Signal::derive(|| true));
            let entry = entry();
            composer.install(vec![choice(&entry)]);
            composer.choose(&selection_key(&selection_v2(&entry).expect("enabled")));
            let chosen = composer.freeze();
            assert!(chosen.is_some());
            // Every send freezes the same choice; nothing clears it after a send.
            assert_eq!(composer.freeze(), chosen);
            // The same entry read again keeps the choice.
            composer.install(vec![choice(&entry)]);
            assert_eq!(composer.freeze(), chosen);
            assert!(!composer.repick.get_untracked());
            // A new catalog revision is a different selection: it must be chosen again.
            let mut revised = entry;
            revised.catalog_revision = 8;
            composer.install(vec![choice(&revised)]);
            assert!(composer.freeze().is_none());
            assert!(composer.repick.get_untracked());
            composer.choose(&selection_key(&selection_v2(&revised).expect("enabled")));
            assert_eq!(composer.freeze(), selection_v2(&revised));
            assert!(!composer.repick.get_untracked());
        });
    }
}
