//! Shared custom-model inventory and explicit per-composer selection.

use leptos::prelude::*;
use openbot_contracts::ids::BotId;
use openbot_contracts::model_connections::{
    ModelConnection, ModelConnectionSource, RunModelSelection,
};

use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::model_connections;
use crate::features::settings::models::ModelActions;
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Notice, NoticePresentation, NoticeTone, Select, SelectContent, SelectItem, SelectTrigger,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectoryStatus {
    Idle,
    Loading,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ModelSelectionStatus {
    AgentDefault,
    Ready,
    Loading,
    DirectoryFailed,
    Unavailable,
    AgentConflict,
}

#[derive(Clone, Copy)]
pub(crate) struct ModelDirectory {
    pub(crate) rows: RwSignal<Vec<ModelConnection>>,
    pub(crate) status: RwSignal<DirectoryStatus>,
    request_epoch: RwSignal<u64>,
}

impl ModelDirectory {
    pub(crate) fn new(actions: ModelActions) -> Self {
        let directory = Self {
            rows: RwSignal::new(Vec::new()),
            status: RwSignal::new(DirectoryStatus::Idle),
            request_epoch: RwSignal::new(0),
        };
        Effect::new(move |_| {
            if actions.revision.get() > 0 {
                directory.reload();
            }
        });
        directory
    }

    pub(crate) fn reload(self) {
        let Some(epoch) = self.request_epoch.get_untracked().checked_add(1) else {
            self.status.set(DirectoryStatus::Failed);
            return;
        };
        self.request_epoch.set(epoch);
        self.status.set(DirectoryStatus::Loading);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local(async move {
            let result = model_connections::list_all().await;
            self.complete(epoch, result);
        });
        #[cfg(not(target_arch = "wasm32"))]
        self.complete(epoch, Err(ApiError::Unavailable));
    }

    fn complete(self, epoch: u64, result: Result<Vec<ModelConnection>, ApiError>) -> bool {
        if self.request_epoch.try_get_untracked() != Some(epoch) {
            return false;
        }
        match result {
            Ok(rows) => {
                _ = self.rows.try_set(rows);
                _ = self.status.try_set(DirectoryStatus::Ready);
            }
            Err(_) => {
                _ = self.status.try_set(DirectoryStatus::Failed);
            }
        }
        true
    }

    pub(crate) fn current(
        self,
        selection: &RunModelSelection,
    ) -> Result<ModelConnection, ApiError> {
        validate_ready_selection(
            self.status.get_untracked(),
            &self.rows.get_untracked(),
            selection,
        )
    }
}

fn validate_ready_selection(
    status: DirectoryStatus,
    rows: &[ModelConnection],
    selection: &RunModelSelection,
) -> Result<ModelConnection, ApiError> {
    if !selection.is_valid() {
        return Err(ApiError::InvalidResponse);
    }
    if status != DirectoryStatus::Ready {
        return Err(ApiError::Conflict);
    }
    rows.iter()
        .find(|row| {
            row.id == selection.connection_id
                && row.revision == selection.expected_revision
                && row.enabled
                && row.has_credential
        })
        .cloned()
        .ok_or(ApiError::Conflict)
}

fn classify_selection(
    directory_status: DirectoryStatus,
    rows: &[ModelConnection],
    selection: Option<&RunModelSelection>,
    supports_explicit: bool,
    selected_agent: Option<&BotId>,
    current_agent: Option<&BotId>,
) -> ModelSelectionStatus {
    let Some(selection) = selection else {
        return ModelSelectionStatus::AgentDefault;
    };
    if !supports_explicit || selected_agent != current_agent {
        return ModelSelectionStatus::AgentConflict;
    }
    match directory_status {
        DirectoryStatus::Idle | DirectoryStatus::Loading => ModelSelectionStatus::Loading,
        DirectoryStatus::Failed => ModelSelectionStatus::DirectoryFailed,
        DirectoryStatus::Ready => {
            if selection.is_valid()
                && rows.iter().any(|row| {
                    row.id == selection.connection_id
                        && row.revision == selection.expected_revision
                        && row.enabled
                        && row.has_credential
                })
            {
                ModelSelectionStatus::Ready
            } else {
                ModelSelectionStatus::Unavailable
            }
        }
    }
}

fn can_choose_explicit(status: DirectoryStatus, supports_explicit: bool) -> bool {
    status == DirectoryStatus::Ready && supports_explicit
}

#[derive(Clone, Copy)]
pub(crate) struct ModelComposer {
    pub(crate) selected: RwSignal<Option<RunModelSelection>>,
    pub(crate) open: RwSignal<bool>,
    pub(crate) supports_explicit: Signal<bool>,
    agent: Signal<Option<BotId>>,
    selected_agent: RwSignal<Option<BotId>>,
    directory: ModelDirectory,
}

impl ModelComposer {
    pub(crate) fn new(supports_explicit: Signal<bool>, agent: Signal<Option<BotId>>) -> Self {
        Self {
            selected: RwSignal::new(None),
            open: RwSignal::new(false),
            supports_explicit,
            agent,
            selected_agent: RwSignal::new(None),
            directory: expect_context::<ModelDirectory>(),
        }
    }

    pub(crate) fn freeze(self) -> Result<Option<RunModelSelection>, ApiError> {
        let selection = self.selected.get_untracked();
        if selection.is_some() && !self.supports_explicit.get_untracked() {
            return Err(ApiError::Conflict);
        }
        if selection.is_some() && self.selected_agent.get_untracked() != self.agent.get_untracked()
        {
            return Err(ApiError::Conflict);
        }
        if let Some(value) = &selection {
            self.directory.current(value)?;
        }
        Ok(selection)
    }

    pub(crate) fn selection_status(self) -> ModelSelectionStatus {
        let selection = self.selected.get();
        let directory_status = self.directory.status.get();
        let supports_explicit = self.supports_explicit.get();
        let selected_agent = self.selected_agent.get();
        let current_agent = self.agent.get();
        self.directory.rows.with(|rows| {
            classify_selection(
                directory_status,
                rows,
                selection.as_ref(),
                supports_explicit,
                selected_agent.as_ref(),
                current_agent.as_ref(),
            )
        })
    }

    fn selection_status_untracked(self) -> ModelSelectionStatus {
        let selection = self.selected.get_untracked();
        let directory_status = self.directory.status.get_untracked();
        let supports_explicit = self.supports_explicit.get_untracked();
        let selected_agent = self.selected_agent.get_untracked();
        let current_agent = self.agent.get_untracked();
        self.directory.rows.with_untracked(|rows| {
            classify_selection(
                directory_status,
                rows,
                selection.as_ref(),
                supports_explicit,
                selected_agent.as_ref(),
                current_agent.as_ref(),
            )
        })
    }

    pub(crate) fn restore_selection(
        self,
        selection: Option<RunModelSelection>,
        agent: Option<BotId>,
    ) {
        let selected_agent = selection.as_ref().and(agent);
        self.selected.set(selection);
        self.selected_agent.set(selected_agent);
        self.open.set(false);
    }

    pub(crate) fn clear(self) {
        self.selected.set(None);
        self.selected_agent.set(None);
        self.open.set(false);
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn directory_reload(self) {
        self.directory.reload();
    }
}

#[component]
pub(crate) fn ModelPicker(state: ModelComposer, disabled: Signal<bool>) -> impl IntoView {
    let i18n = use_i18n();
    if state.directory.status.get_untracked() == DirectoryStatus::Idle {
        state.directory.reload();
    }
    let rows = Signal::derive(move || state.directory.rows.get());
    let selection_status = Signal::derive(move || state.selection_status());
    let picker_value = RwSignal::new(displayed_selection_key(
        state.selection_status_untracked(),
        state.selected.get_untracked().as_ref(),
    ));
    Effect::new(move |_| {
        let status = selection_status.get();
        let selection = state.selected.get();
        if disabled.get() || (selection.is_some() && status != ModelSelectionStatus::Ready) {
            state.open.set(false);
        }
        picker_value.set(displayed_selection_key(status, selection.as_ref()));
    });
    let choose = UnsyncCallback::new(move |value: Option<String>| {
        if disabled.get_untracked() {
            return;
        }
        let Some(value) = value else {
            return;
        };
        if value == "agent-default" {
            picker_value.set(None);
            state.clear();
            return;
        }
        if !can_choose_explicit(
            state.directory.status.get_untracked(),
            state.supports_explicit.get_untracked(),
        ) {
            picker_value.set(displayed_selection_key(
                state.selection_status_untracked(),
                state.selected.get_untracked().as_ref(),
            ));
            return;
        }
        let selected = state
            .directory
            .rows
            .get_untracked()
            .into_iter()
            .find_map(|row| {
                let selection = RunModelSelection {
                    connection_id: row.id.clone(),
                    expected_revision: row.revision,
                };
                (row.enabled
                    && row.has_credential
                    && selection_key(Some(&selection)).as_deref() == Some(value.as_str()))
                .then_some(selection)
            });
        if let Some(selected) = selected {
            state.selected.set(Some(selected));
            state.selected_agent.set(state.agent.get_untracked());
        } else {
            picker_value.set(displayed_selection_key(
                state.selection_status_untracked(),
                state.selected.get_untracked().as_ref(),
            ));
        }
    });
    view! {
        <div class="ob-skill-picker">
            <Select
                id="run-model-picker"
                open=state.open
                value=picker_value
                disabled=disabled
                on_value_change=choose
            >
                <SelectTrigger
                    aria_label=move || t_string!(i18n, models.choose_for_next).to_owned()
                    placeholder=move || {
                        match selection_status.get() {
                            ModelSelectionStatus::AgentDefault | ModelSelectionStatus::Ready =>
                                t_string!(i18n, models.use_agent_default).to_owned(),
                            ModelSelectionStatus::Loading =>
                                t_string!(i18n, common.loading).to_owned(),
                            ModelSelectionStatus::DirectoryFailed
                            | ModelSelectionStatus::Unavailable
                            | ModelSelectionStatus::AgentConflict =>
                                t_string!(i18n, models.selection_unavailable_label).to_owned(),
                        }
                    }
                />
                <SelectContent>
                    <SelectItem
                        id="run-model-agent-default"
                        value="agent-default"
                        label=move || t_string!(i18n, models.use_agent_default).to_owned()
                    >
                        {move || t!(i18n, models.use_agent_default)}
                    </SelectItem>
                    <For each=move || rows.get() key=|row| (row.id.clone(), row.revision) children=move |row| {
                        let selection = RunModelSelection {
                            connection_id: row.id.clone(),
                            expected_revision: row.revision,
                        };
                        let value = selection_key(Some(&selection)).expect("selection key");
                        let option_id = format!("run-model-{}-{}", row.id, row.revision);
                        let presentation = StoredValue::new((row.source, row.model, row.name.clone()));
                        let enabled = row.enabled;
                        let has_credential = row.has_credential;
                        let summary = move || presentation.with_value(|(source, model, _)| {
                            let source_label = match source {
                                ModelConnectionSource::Custom => t_string!(i18n, models.custom_source).to_owned(),
                            };
                            let availability = if !enabled {
                                t_string!(i18n, models.disabled).to_owned()
                            } else if !has_credential {
                                t_string!(i18n, models.key_missing).to_owned()
                            } else {
                                t_string!(i18n, models.key_stored).to_owned()
                            };
                            format!("{model} · {source_label} · {availability}")
                        });
                        let label = move || {
                            let summary = summary();
                            presentation.with_value(|(_, _, name)| format!("{name} · {summary}"))
                        };
                        view! {
                            <SelectItem
                                id=option_id
                                value=value
                                label=label
                                disabled=Signal::derive(move || {
                                    !row.enabled || !row.has_credential || !can_choose_explicit(
                                        state.directory.status.get(),
                                        state.supports_explicit.get(),
                                    )
                                })
                            >
                                <strong>{row.name}</strong><small>{move || summary()}</small>
                            </SelectItem>
                        }
                    }/>
                    <Show when=move || state.directory.status.get()==DirectoryStatus::Loading><p role="status">{move || t!(i18n, common.loading)}</p></Show>
                    <Show when=move || state.directory.status.get()==DirectoryStatus::Failed><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, models.load_failed)}</Notice></Show>
                    <Show when=move || state.directory.status.get()==DirectoryStatus::Ready && rows.get().is_empty()><p>{move || t!(i18n, models.none_available)}</p></Show>
                </SelectContent>
            </Select>
            <Show when=move || selection_status.get()==ModelSelectionStatus::Loading>
                <span class="ob-page-empty" role="status">{move || t!(i18n, common.loading)}</span>
            </Show>
            <Show when=move || selection_status.get()==ModelSelectionStatus::DirectoryFailed>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, models.load_failed)}</Notice>
            </Show>
            <Show when=move || selection_status.get()==ModelSelectionStatus::Unavailable>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || if disabled.get() {t_string!(i18n, models.selection_unavailable_locked).to_owned()} else {t_string!(i18n, models.selection_unavailable).to_owned()}}</Notice>
            </Show>
            <Show when=move || selection_status.get()==ModelSelectionStatus::AgentConflict>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || if disabled.get() {t_string!(i18n, models.selection_unavailable_locked).to_owned()} else {t_string!(i18n, models.selection_agent_conflict).to_owned()}}</Notice>
            </Show>
            <Show when=move || !state.supports_explicit.get() && selection_status.get()==ModelSelectionStatus::AgentDefault>
                <span class="ob-page-empty">{move || t!(i18n, models.managed_by_agent)}</span>
            </Show>
        </div>
        <Show when=move || state.directory.status.get()==DirectoryStatus::Ready && !state.directory.rows.get().iter().any(|row| row.enabled && row.has_credential)>
            <aside class="ob-model-setup" role="note">
                <span>{move || t!(i18n, models.custom_setup_note)}</span>
                <a href="/settings/models">{move || t!(i18n, models.custom_setup_action)}</a>
            </aside>
        </Show>
    }
}

fn selection_key(selection: Option<&RunModelSelection>) -> Option<String> {
    selection.map(|value| format!("{}:{}", value.connection_id, value.expected_revision))
}

fn displayed_selection_key(
    status: ModelSelectionStatus,
    selection: Option<&RunModelSelection>,
) -> Option<String> {
    (status == ModelSelectionStatus::Ready)
        .then(|| selection_key(selection))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::model_connections::{CustomModelProtocol, ModelConnectionSource};

    fn row() -> ModelConnection {
        ModelConnection {
            id: "01991389-7380-7000-8000-000000000001".into(),
            source: ModelConnectionSource::Custom,
            name: "Test".into(),
            protocol: CustomModelProtocol::OpenaiResponses,
            endpoint: "https://example.test/v1/responses".into(),
            model: "model".into(),
            enabled: true,
            revision: 7,
            has_credential: true,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn directory() -> ModelDirectory {
        ModelDirectory {
            rows: RwSignal::new(Vec::new()),
            status: RwSignal::new(DirectoryStatus::Idle),
            request_epoch: RwSignal::new(0),
        }
    }

    #[test]
    fn only_a_ready_exact_usable_revision_can_start_a_new_run() {
        let row = row();
        let selection = RunModelSelection {
            connection_id: row.id.clone(),
            expected_revision: row.revision,
        };
        assert_eq!(
            validate_ready_selection(
                DirectoryStatus::Ready,
                std::slice::from_ref(&row),
                &selection
            ),
            Ok(row.clone())
        );
        for status in [
            DirectoryStatus::Idle,
            DirectoryStatus::Loading,
            DirectoryStatus::Failed,
        ] {
            assert_eq!(
                validate_ready_selection(status, std::slice::from_ref(&row), &selection),
                Err(ApiError::Conflict)
            );
        }

        let mut stale = selection.clone();
        stale.expected_revision += 1;
        assert_eq!(
            validate_ready_selection(DirectoryStatus::Ready, std::slice::from_ref(&row), &stale),
            Err(ApiError::Conflict)
        );
        let mut unavailable = row;
        unavailable.enabled = false;
        assert_eq!(
            validate_ready_selection(DirectoryStatus::Ready, &[unavailable], &selection),
            Err(ApiError::Conflict)
        );
    }

    #[test]
    fn composer_rejects_agent_drift_and_remote_agents_without_clearing_the_selection() {
        Owner::new().with(|| {
            let directory = directory();
            let row = row();
            directory.rows.set(vec![row.clone()]);
            directory.status.set(DirectoryStatus::Ready);
            provide_context(directory);

            let supports = RwSignal::new(true);
            let agent = RwSignal::new(Some(BotId::new("builtin")));
            let composer = ModelComposer::new(
                Signal::derive(move || supports.get()),
                Signal::derive(move || agent.get()),
            );
            let selection = RunModelSelection {
                connection_id: row.id,
                expected_revision: row.revision,
            };
            composer.restore_selection(Some(selection.clone()), agent.get_untracked());
            assert_eq!(composer.freeze(), Ok(Some(selection.clone())));

            agent.set(Some(BotId::new("other-builtin")));
            assert_eq!(composer.freeze(), Err(ApiError::Conflict));
            assert_eq!(composer.selected.get_untracked(), Some(selection.clone()));

            agent.set(Some(BotId::new("builtin")));
            supports.set(false);
            assert_eq!(composer.freeze(), Err(ApiError::Conflict));
            assert_eq!(composer.selected.get_untracked(), Some(selection));
        });
    }

    #[test]
    fn display_status_reacts_to_revision_agent_and_directory_without_rebinding_selection() {
        Owner::new().with(|| {
            let directory = directory();
            let original_row = row();
            directory.rows.set(vec![original_row.clone()]);
            directory.status.set(DirectoryStatus::Ready);
            provide_context(directory);

            let supports = RwSignal::new(true);
            let agent = RwSignal::new(Some(BotId::new("builtin")));
            let composer = ModelComposer::new(
                Signal::derive(move || supports.get()),
                Signal::derive(move || agent.get()),
            );
            let original = RunModelSelection {
                connection_id: original_row.id.clone(),
                expected_revision: original_row.revision,
            };
            composer.restore_selection(Some(original.clone()), agent.get_untracked());
            let display_value = Signal::derive(move || {
                displayed_selection_key(
                    composer.selection_status(),
                    composer.selected.get().as_ref(),
                )
            });

            assert_eq!(composer.selection_status(), ModelSelectionStatus::Ready);
            assert_eq!(
                display_value.get_untracked(),
                selection_key(Some(&original))
            );
            assert!(can_choose_explicit(DirectoryStatus::Ready, true));

            directory.status.set(DirectoryStatus::Loading);
            assert_eq!(composer.selection_status(), ModelSelectionStatus::Loading);
            assert_eq!(display_value.get_untracked(), None);
            assert!(!can_choose_explicit(DirectoryStatus::Loading, true));
            assert_eq!(composer.selected.get_untracked(), Some(original.clone()));

            directory.status.set(DirectoryStatus::Failed);
            assert_eq!(
                composer.selection_status(),
                ModelSelectionStatus::DirectoryFailed
            );
            assert_eq!(display_value.get_untracked(), None);
            assert!(!can_choose_explicit(DirectoryStatus::Failed, true));
            assert_eq!(composer.selected.get_untracked(), Some(original.clone()));

            let mut refreshed_row = original_row;
            refreshed_row.revision += 1;
            directory.rows.set(vec![refreshed_row.clone()]);
            directory.status.set(DirectoryStatus::Ready);
            assert_eq!(
                composer.selection_status(),
                ModelSelectionStatus::Unavailable
            );
            assert_eq!(display_value.get_untracked(), None);
            assert_eq!(composer.selected.get_untracked(), Some(original));

            agent.set(Some(BotId::new("other-builtin")));
            assert_eq!(
                composer.selection_status(),
                ModelSelectionStatus::AgentConflict
            );
            assert_eq!(display_value.get_untracked(), None);

            let refreshed = RunModelSelection {
                connection_id: refreshed_row.id,
                expected_revision: refreshed_row.revision,
            };
            composer.restore_selection(Some(refreshed.clone()), agent.get_untracked());
            assert_eq!(composer.selection_status(), ModelSelectionStatus::Ready);
            assert_eq!(
                display_value.get_untracked(),
                selection_key(Some(&refreshed))
            );

            supports.set(false);
            assert_eq!(
                composer.selection_status(),
                ModelSelectionStatus::AgentConflict
            );
            assert_eq!(display_value.get_untracked(), None);
            assert_eq!(composer.selected.get_untracked(), Some(refreshed));
            assert!(!can_choose_explicit(DirectoryStatus::Ready, false));

            composer.restore_selection(None, Some(BotId::new("ignored")));
            assert_eq!(
                composer.selection_status(),
                ModelSelectionStatus::AgentDefault
            );
            assert_eq!(composer.selected_agent.get_untracked(), None);
            assert_eq!(display_value.get_untracked(), None);
        });
    }

    #[test]
    fn stale_directory_completion_cannot_replace_the_current_request() {
        Owner::new().with(|| {
            let directory = directory();
            let old = row();
            let mut fresh = row();
            fresh.revision += 1;
            directory.rows.set(vec![old.clone()]);
            directory.status.set(DirectoryStatus::Loading);
            directory.request_epoch.set(2);

            assert!(!directory.complete(1, Ok(vec![fresh.clone()])));
            assert_eq!(directory.status.get_untracked(), DirectoryStatus::Loading);
            assert_eq!(directory.rows.get_untracked(), vec![old]);

            assert!(directory.complete(2, Ok(vec![fresh.clone()])));
            assert_eq!(directory.status.get_untracked(), DirectoryStatus::Ready);
            assert_eq!(directory.rows.get_untracked(), vec![fresh.clone()]);
            assert!(!directory.complete(1, Err(ApiError::Network)));
            assert_eq!(directory.status.get_untracked(), DirectoryStatus::Ready);
            assert_eq!(directory.rows.get_untracked(), vec![fresh]);
        });
    }
}
