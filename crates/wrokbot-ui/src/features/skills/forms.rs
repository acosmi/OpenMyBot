//! Skill editor and separately acknowledged grant changes; instruction text is data, never code.

use super::state::SkillPageState;
use crate::api::skills as api;
use crate::editor_notice::EditorNotice;
use crate::editor_runtime::{after, now_ms};
use crate::features::admin::plugins::PluginActions;
use crate::features::layout::{
    editor_location::EditorLocation, library_editor::LibraryEditorFrame,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonVariant, Field, Input, Notice, NoticePresentation, NoticeTone, Textarea,
};
use crate::revision_editor::{Apply, AttemptToken, EditorCore, FailureClass, Phase};
use leptos::prelude::*;
use openbot_contracts::mcp::{McpAdminSkill, PluginSkillMutation};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkillDialog {
    Create,
    Edit(String),
    Grants(String),
    Delete(String),
}

#[derive(Clone, PartialEq, Eq)]
struct SkillDraft {
    title: String,
    summary: String,
    instructions: String,
}

impl SkillDraft {
    fn of(row: &McpAdminSkill) -> Self {
        Self {
            title: row.title.clone(),
            summary: row.summary.clone(),
            instructions: row.instructions.clone(),
        }
    }
    fn mutation(&self, row: &McpAdminSkill, revision: Option<i64>) -> PluginSkillMutation {
        PluginSkillMutation {
            slug: row.slug.clone(),
            title: self.title.clone(),
            summary: self.summary.clone(),
            instructions: self.instructions.clone(),
            deployment_wide: row.owner_user_id.is_none(),
            expected_revision: revision,
        }
    }
}

#[derive(Clone)]
struct FrozenSkillSave {
    token: AttemptToken,
    known: McpAdminSkill,
    draft: SkillDraft,
    mutation: PluginSkillMutation,
    close_on_ack: bool,
}

#[derive(Clone, Copy)]
enum SkillRecovery {
    Compare,
    Load,
    Retry,
    Reapply,
}

fn instruction_lines(text: String) -> impl IntoView {
    view! { <p class="ob-library-detail-body">{text.split('\n').map(|line| view! { <span>{line.to_owned()}</span><br /> }).collect_view()}</p> }
}

/// Bodies live only with this editor; the authenticated owner retains payload-free holds.
#[derive(Clone, Copy)]
struct SkillEditor {
    core: RwSignal<EditorCore>,
    known: RwSignal<Option<McpAdminSkill>>,
    latest: RwSignal<Option<McpAdminSkill>>,
    remote_hint: RwSignal<Option<openbot_contracts::revision::RevisionSnapshot>>,
    original: RwSignal<Option<FrozenSkillSave>>,
    title: RwSignal<String>,
    summary: RwSignal<String>,
    instructions: RwSignal<String>,
    read_busy: RwSignal<bool>,
    read_failed: RwSignal<bool>,
    comparison: RwSignal<bool>,
    composition_mask: RwSignal<u8>,
    invalid: RwSignal<bool>,
    dialog: RwSignal<Option<SkillDialog>>,
    state: SkillPageState,
    deployment: bool,
    actions: PluginActions,
    location: EditorLocation,
    owner: StoredValue<Option<Owner>>,
}

impl SkillEditor {
    fn draft(self) -> Option<SkillDraft> {
        Some(SkillDraft {
            title: self.title.try_get_untracked()?,
            summary: self.summary.try_get_untracked()?,
            instructions: self.instructions.try_get_untracked()?,
        })
    }

    fn hydrate(self, row: &McpAdminSkill) {
        self.title.try_set(row.title.clone());
        self.summary.try_set(row.summary.clone());
        self.instructions.try_set(row.instructions.clone());
    }

    fn reset(self) {
        self.core.try_update(|core| {
            let _ = core.invalidate();
        });
        self.known.try_set(None);
        self.latest.try_set(None);
        self.remote_hint.try_set(None);
        self.original.try_set(None);
        self.read_busy.try_set(false);
        self.read_failed.try_set(false);
        self.comparison.try_set(false);
        self.composition_mask.try_set(0);
    }

    fn initialize(self, row: McpAdminSkill) {
        self.core.try_update(|core| {
            if core.bind_existing(row.revision).is_ok()
                && let Some((phase, uncertain)) =
                    self.actions.skill_hold(&api::SkillBinding::of(&row))
            {
                core.restore_pause(phase, uncertain);
            }
        });
        self.known.try_set(Some(row));
    }

    fn eligible(self, row: &McpAdminSkill) -> bool {
        if self.state.loading.try_get_untracked() != Some(false)
            || self.state.error.try_get_untracked() != Some(false)
            || self.read_busy.try_get_untracked() != Some(false)
            || self.dialog.try_get_untracked().flatten()
                != Some(SkillDialog::Edit(row.slug.clone()))
        {
            return false;
        }
        self.state
            .data
            .try_get_untracked()
            .flatten()
            .is_some_and(|data| {
                (!self.deployment || data.actor_is_admin)
                    && data
                        .selected(&row.slug, self.deployment)
                        .is_some_and(|current| {
                            api::SkillBinding::of(&current) == api::SkillBinding::of(row)
                        })
            })
    }

    fn edited(self) {
        let Some(row) = self.known.try_get_untracked().flatten() else {
            return;
        };
        let Some(draft) = self.draft() else {
            return;
        };
        self.invalid.try_set(false);
        self.core.try_update(|core| {
            let _ = core.edit(now_ms());
            core.set_local_matches_known(draft == SkillDraft::of(&row));
        });
        self.schedule();
    }

    fn composing(self, field: u8, active: bool) {
        let Some(mut mask) = self.composition_mask.try_get_untracked() else {
            return;
        };
        if active {
            mask |= 1 << field;
        } else {
            mask &= !(1 << field);
        }
        self.composition_mask.try_set(mask);
        self.core.try_update(|core| {
            let _ = core.set_composing(mask != 0, now_ms());
        });
        if mask == 0 {
            self.schedule();
        }
    }

    fn schedule(self) {
        let Some(core) = self.core.try_get_untracked() else {
            return;
        };
        let Some(deadline) = core.next_auto_deadline() else {
            return;
        };
        let ticket = core.debounce_token();
        after(
            deadline.saturating_sub(now_ms()).min(800) as i32,
            move || {
                let Some(mut core) = self.core.try_get_untracked() else {
                    return;
                };
                if core.debounce_token() != ticket {
                    return;
                }
                if core
                    .next_auto_deadline()
                    .is_some_and(|deadline| deadline > now_ms())
                {
                    self.schedule();
                    return;
                }
                let Some(row) = self.known.try_get_untracked().flatten() else {
                    return;
                };
                let Some(draft) = self.draft() else {
                    return;
                };
                let mutation = draft.mutation(&row, core.known_revision());
                if api::validate_mutation(&mutation).is_err() {
                    self.invalid.try_set(true);
                    return;
                }
                let Ok(token) = core.begin_auto(ticket, now_ms(), self.eligible(&row)) else {
                    return;
                };
                let Some(serial) = self.actions.begin_skill(api::SkillBinding::of(&row), false)
                else {
                    return;
                };
                self.core.try_set(core);
                self.send(
                    FrozenSkillSave {
                        token,
                        known: row,
                        draft,
                        mutation,
                        close_on_ack: false,
                    },
                    serial,
                );
            },
        );
    }

    fn save_explicit(self) {
        let Some(row) = self.known.try_get_untracked().flatten() else {
            return;
        };
        let Some(draft) = self.draft() else {
            return;
        };
        let Some(mut core) = self.core.try_get_untracked() else {
            return;
        };
        let mutation = draft.mutation(&row, core.known_revision());
        if api::validate_mutation(&mutation).is_err() {
            self.invalid.try_set(true);
            return;
        }
        let Ok(token) = core.begin_explicit(now_ms(), self.eligible(&row)) else {
            return;
        };
        let Some(serial) = self.actions.begin_skill(api::SkillBinding::of(&row), false) else {
            return;
        };
        self.core.try_set(core);
        self.send(
            FrozenSkillSave {
                token,
                known: row,
                draft,
                mutation,
                close_on_ack: true,
            },
            serial,
        );
    }

    fn send(self, frozen: FrozenSkillSave, serial: u64) {
        self.original.try_set(Some(frozen.clone()));
        let token = frozen.token;
        let binding = api::SkillBinding::of(&frozen.known);
        let timeout_binding = binding.clone();
        after(10_000, move || {
            // Auth-owned effect tracking survives closing this editor; its physical slot stays live.
            self.actions.timeout_skill(&timeout_binding, serial);
            self.core.try_update(|core| {
                let _ = core.mark_timeout(token, now_ms());
            });
        });
        leptos::task::spawn_local(async move {
            let result = api::save_existing(frozen.mutation.clone(), frozen.known.clone()).await;
            let unknown = matches!(result, Err(api::SkillWriteError::Unknown(_)));
            let conflict = matches!(result, Err(api::SkillWriteError::Conflict(_)));
            if !self
                .actions
                .finish_skill(&binding, serial, result.is_ok(), unknown, conflict)
            {
                return;
            }
            let Some(mut core) = self.core.try_get_untracked() else {
                return;
            };
            if core.generation() != token.generation() {
                return;
            }
            let mut close_after_ack = false;
            match result {
                Ok(row) => {
                    let matches = self
                        .draft()
                        .is_some_and(|draft| draft == SkillDraft::of(&row));
                    if core.finish_ack(token, row.revision, matches) == Apply::Applied {
                        // Hydration never writes over an input made since the captured attempt.
                        if core.edit_serial() == token.edit_serial()
                            && self.draft().as_ref() == Some(&frozen.draft)
                        {
                            self.hydrate(&row);
                            close_after_ack = frozen.close_on_ack && core.phase() == Phase::Saved;
                        }
                        self.known.try_set(Some(row));
                    }
                }
                Err(api::SkillWriteError::Conflict(snapshot)) => {
                    self.remote_hint.try_set(Some(snapshot));
                    core.finish_closed_conflict(token, snapshot.current_revision());
                }
                Err(api::SkillWriteError::Rejected(error)) => {
                    core.finish_failure(token, FailureClass::Definite);
                    if matches!(
                        error,
                        crate::api::ApiError::Unauthorized
                            | crate::api::ApiError::Forbidden
                            | crate::api::ApiError::NotFound
                    ) {
                        self.read_failed.try_set(true);
                    }
                }
                Err(api::SkillWriteError::Unknown(error)) => {
                    let _ = error;
                    core.finish_failure(token, FailureClass::Unknown);
                }
            }
            self.core.try_set(core);
            if close_after_ack {
                self.location.close();
            }
            self.schedule();
        });
    }

    fn recover(self, choice: SkillRecovery) {
        if self.read_busy.try_get_untracked() != Some(false) {
            return;
        }
        let Some(known) = self.known.try_get_untracked().flatten() else {
            return;
        };
        let Some(mut core) = self.core.try_get_untracked() else {
            return;
        };
        if core.current_attempt().is_some() {
            return;
        }
        let Ok(read) = core.begin_read() else {
            return;
        };
        let generation = core.generation();
        let compared = self.latest.try_get_untracked().flatten();
        let confirmed_draft = self.draft();
        let confirmed_edit_serial = core.edit_serial();
        self.core.try_set(core);
        self.read_busy.try_set(true);
        self.read_failed.try_set(false);
        let Some(owner) = self.owner.try_get_value().flatten() else {
            return;
        };
        owner.with(|| {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let result = api::read_existing(&known).await;
                let Some(mut core) = self.core.try_get_untracked() else {
                    return;
                };
                if core.generation() != generation {
                    return;
                }
                self.read_busy.try_set(false);
                let Ok(remote) = result else {
                    self.read_failed.try_set(true);
                    return;
                };
                // Grant membership is independent; editing metadata at the same revision is not.
                if remote.revision == known.revision
                    && remote.revision_snapshot().ok() != known.revision_snapshot().ok()
                {
                    core.restore_pause(Phase::Error, core.historical_uncertainty());
                    self.actions
                        .hold_skill(&api::SkillBinding::of(&known), Phase::Error);
                    self.core.try_set(core);
                    self.read_failed.try_set(true);
                    return;
                }
                if let Some(hint) = self.remote_hint.try_get_untracked().flatten()
                    && (remote.revision < hint.current_revision()
                        || (remote.revision == hint.current_revision()
                            && remote.revision_snapshot().ok() != Some(hint)))
                {
                    core.restore_pause(Phase::Error, core.historical_uncertainty());
                    self.actions
                        .hold_skill(&api::SkillBinding::of(&known), Phase::Error);
                    self.core.try_set(core);
                    self.read_failed.try_set(true);
                    return;
                }
                let Ok(recovery) = core.accept_recovery_read(read, remote.revision) else {
                    self.core.try_set(core);
                    self.read_failed.try_set(true);
                    return;
                };
                self.latest.try_set(Some(remote.clone()));
                self.remote_hint.try_set(remote.revision_snapshot().ok());
                self.comparison.try_set(true);
                match choice {
                    SkillRecovery::Compare => {}
                    SkillRecovery::Load => {
                        if core.edit_serial() == confirmed_edit_serial
                            && self.draft() == confirmed_draft
                            && core.choose_load(recovery, true) == Apply::Applied
                        {
                            self.hydrate(&remote);
                            self.known.try_set(Some(remote.clone()));
                            self.original.try_set(None);
                            self.comparison.try_set(false);
                            if !core.auto_paused() {
                                self.actions.loaded_skill(&api::SkillBinding::of(&remote));
                            }
                        }
                    }
                    SkillRecovery::Retry | SkillRecovery::Reapply => {
                        let frozen = if matches!(choice, SkillRecovery::Retry) {
                            self.original
                                .try_get_untracked()
                                .flatten()
                                .and_then(|original| {
                                    let eligible = self.dialog.try_get_untracked().flatten()
                                        == Some(SkillDialog::Edit(remote.slug.clone()))
                                        && api::SkillBinding::of(&known)
                                            == api::SkillBinding::of(&remote);
                                    core.begin_retry_original(
                                        recovery,
                                        original.token,
                                        now_ms(),
                                        eligible,
                                    )
                                    .ok()
                                    .map(|token| FrozenSkillSave { token, ..original })
                                })
                        } else if core.edit_serial() == confirmed_edit_serial
                            && self.draft() == confirmed_draft
                            && compared.as_ref().is_some_and(|previous| {
                                previous.revision_snapshot().ok() == remote.revision_snapshot().ok()
                            })
                        {
                            confirmed_draft.and_then(|draft| {
                                let mutation = draft.mutation(&remote, Some(remote.revision));
                                if api::validate_mutation(&mutation).is_err() {
                                    self.invalid.try_set(true);
                                    return None;
                                }
                                let eligible = self.dialog.try_get_untracked().flatten()
                                    == Some(SkillDialog::Edit(remote.slug.clone()))
                                    && api::SkillBinding::of(&known)
                                        == api::SkillBinding::of(&remote);
                                core.begin_reapply(recovery, true, now_ms(), eligible)
                                    .ok()
                                    .map(|token| FrozenSkillSave {
                                        token,
                                        known: remote.clone(),
                                        draft,
                                        mutation,
                                        close_on_ack: false,
                                    })
                            })
                        } else {
                            None
                        };
                        if let Some(frozen) = frozen {
                            let binding = api::SkillBinding::of(&remote);
                            if let Some(serial) = self.actions.begin_skill(binding, true) {
                                self.core.try_set(core);
                                self.send(frozen, serial);
                                return;
                            }
                            // A family barrier prevented submission; the local attempt never ran.
                            core.finish_failure(frozen.token, FailureClass::Definite);
                        }
                    }
                }
                self.core.try_set(core);
            })
        });
    }
}

impl SkillDialog {
    fn slug(&self) -> Option<&str> {
        match self {
            Self::Create => None,
            Self::Edit(s) | Self::Grants(s) | Self::Delete(s) => Some(s),
        }
    }
    fn return_id(&self) -> String {
        match self {
            Self::Create => "skill-create".into(),
            Self::Edit(s) => format!("skill-edit-{s}"),
            Self::Grants(s) => format!("skill-grants-{s}"),
            Self::Delete(s) => format!("skill-delete-{s}"),
        }
    }
}

#[component]
pub fn SkillDialogs(
    dialog: RwSignal<Option<SkillDialog>>,
    state: SkillPageState,
    deployment: bool,
    editor: EditorLocation,
) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<PluginActions>();
    let data = state.data;
    let open = RwSignal::new(false);
    let slug = RwSignal::new(String::new());
    let title = RwSignal::new(String::new());
    let summary = RwSignal::new(String::new());
    let instructions = RwSignal::new(String::new());
    let invalid = RwSignal::new(false);
    let collision = RwSignal::new(false);
    let attempted = RwSignal::new(false);
    let skill_editor = SkillEditor {
        core: RwSignal::new(EditorCore::new()),
        known: RwSignal::new(None),
        latest: RwSignal::new(None),
        remote_hint: RwSignal::new(None),
        original: RwSignal::new(None),
        title,
        summary,
        instructions,
        read_busy: RwSignal::new(false),
        read_failed: RwSignal::new(false),
        comparison: RwSignal::new(false),
        composition_mask: RwSignal::new(0),
        invalid,
        dialog,
        state,
        deployment,
        actions,
        owner: StoredValue::new(Owner::current()),
        location: editor,
    };
    // Capture the first readable version opened by this editor; reloads cannot rebase its draft.
    let opened_revision = RwSignal::new(None::<(String, i64)>);
    let generation = RwSignal::new(0_u64);
    let initialized = RwSignal::new(false);
    let readable = Memo::new(move |_| {
        if state.loading.get() || state.error.get() {
            return false;
        }
        let Some(current) = data.get() else {
            return false;
        };
        dialog.get().is_some_and(|selected| {
            selected
                .slug()
                .is_none_or(|slug| current.selected(slug, deployment).is_some())
        })
    });
    let return_focus = RwSignal::new("skill-create".to_owned());
    Effect::new(move |_| {
        let selected = dialog.get();
        skill_editor.reset();
        let Some(next) = generation.get_untracked().checked_add(1) else {
            initialized.set(false);
            opened_revision.set(None);
            open.set(false);
            invalid.set(true);
            return;
        };
        generation.set(next);
        opened_revision.set(None);
        if selected.is_some() {
            return_focus.set("skill-create".to_owned());
        }
        initialized.set(matches!(selected, Some(SkillDialog::Create)));
        open.set(selected.is_some());
        invalid.set(false);
        collision.set(false);
        attempted.set(false);
        slug.set(String::new());
        title.set(String::new());
        summary.set(String::new());
        instructions.set(String::new());
        if let Some(selected) = selected
            && let Some(selected_slug) = selected.slug()
        {
            slug.set(selected_slug.to_owned());
        }
    });
    Effect::new(move |_| {
        generation.track();
        let selected = dialog.get();
        let current = data.get();
        if !readable.get() || initialized.get_untracked() {
            return;
        }
        if let Some(selected) = selected
            && let Some(row) = current.and_then(|d| d.selected(selected.slug()?, deployment))
        {
            opened_revision.set(Some((row.slug.clone(), row.revision)));
            skill_editor.hydrate(&row);
            if matches!(selected, SkillDialog::Edit(_)) {
                skill_editor.initialize(row);
            }
            return_focus.set(selected.return_id());
            initialized.set(true);
        }
    });
    Effect::new(move |_| {
        let current = data.get();
        let is_readable = readable.get();
        if !is_readable {
            return;
        }
        let Some(known) = skill_editor.known.get_untracked() else {
            return;
        };
        let Some(row) = current.and_then(|data| data.selected(&known.slug, deployment)) else {
            return;
        };
        if api::SkillBinding::of(&row) != api::SkillBinding::of(&known) {
            return;
        }
        let Some(mut core) = skill_editor.core.try_get_untracked() else {
            return;
        };
        if row.revision > known.revision {
            core.observe_remote(row.revision);
            skill_editor.latest.set(Some(row.clone()));
            skill_editor.remote_hint.set(row.revision_snapshot().ok());
            actions.hold_skill(&api::SkillBinding::of(&known), Phase::Conflict);
            skill_editor.core.set(core);
        } else if row.revision < known.revision
            || row.revision_snapshot().ok() != known.revision_snapshot().ok()
        {
            core.restore_pause(Phase::Error, false);
            actions.hold_skill(&api::SkillBinding::of(&known), Phase::Error);
            skill_editor.read_failed.set(true);
            skill_editor.core.set(core);
        }
    });
    Effect::new(move |_| {
        let busy = actions.busy.get();
        state.loading.track();
        state.error.track();
        if !busy {
            skill_editor.schedule();
        }
    });
    let user_edit = UnsyncCallback::new(move |_| skill_editor.edited());
    let title_composition = UnsyncCallback::new(move |active| skill_editor.composing(0, active));
    let summary_composition = UnsyncCallback::new(move |active| skill_editor.composing(1, active));
    let instructions_composition =
        UnsyncCallback::new(move |active| skill_editor.composing(2, active));
    let edit_fields_disabled = Signal::derive(move || {
        !matches!(dialog.get(), Some(SkillDialog::Edit(_))) && actions.busy.get()
    });
    let compare = UnsyncCallback::new(move |_| skill_editor.recover(SkillRecovery::Compare));
    let load = UnsyncCallback::new(move |_| skill_editor.recover(SkillRecovery::Load));
    let retry = UnsyncCallback::new(move |_| skill_editor.recover(SkillRecovery::Retry));
    let reapply = UnsyncCallback::new(move |_| skill_editor.recover(SkillRecovery::Reapply));
    let editor_phase = Signal::derive(move || skill_editor.core.get().phase());
    let recovery_busy = Signal::derive(move || {
        skill_editor.read_busy.get() || skill_editor.core.get().current_attempt().is_some()
    });
    let save_disabled = Signal::derive(move || {
        actions.busy.get()
            || !readable.get()
            || (matches!(dialog.get(), Some(SkillDialog::Edit(_)))
                && (skill_editor.core.get().auto_paused()
                    || skill_editor.composition_mask.get() != 0))
    });
    let close = UnsyncCallback::new(move |_| {
        editor.close();
    });
    let save = move |_| {
        if matches!(
            dialog.try_get_untracked().flatten(),
            Some(SkillDialog::Edit(_))
        ) {
            skill_editor.save_explicit();
            return;
        }
        if actions.busy.get_untracked() || !initialized.get_untracked() || !readable.get_untracked()
        {
            return;
        }
        let Some(selected) = dialog.get_untracked() else {
            return;
        };
        let Some(current) = data.get_untracked() else {
            invalid.set(true);
            return;
        };
        invalid.set(false);
        collision.set(false);
        let submitted_generation = generation.get_untracked();
        let submitted_dialog = selected.clone();
        let finish = move |ok| {
            if ok {
                close_saved_dialog(
                    dialog,
                    generation,
                    submitted_generation,
                    &submitted_dialog,
                    move || editor.close(),
                );
            }
        };
        match selected {
            SkillDialog::Create => {
                let mutation = PluginSkillMutation {
                    slug: slug.get_untracked().trim().to_owned(),
                    title: title.get_untracked(),
                    summary: summary.get_untracked(),
                    instructions: instructions.get_untracked(),
                    deployment_wide: deployment,
                    expected_revision: None,
                };
                if api::validate_mutation(&mutation).is_err() {
                    invalid.set(true);
                    return;
                }
                if current.all.iter().any(|row| row.slug == mutation.slug) {
                    collision.set(true);
                    return;
                }
                let expected_owner = (!deployment).then_some(current.actor_id);
                attempted.set(true);
                actions.launch(
                    format!("skill:{}", mutation.slug),
                    async move { api::save(mutation, expected_owner).await },
                    finish,
                );
            }
            SkillDialog::Delete(target) => {
                if current.selected(&target, deployment).is_none() {
                    invalid.set(true);
                    return;
                }
                let Some((opened_slug, expected_revision)) = opened_revision.get_untracked() else {
                    invalid.set(true);
                    return;
                };
                if opened_slug != target || expected_revision <= 0 {
                    invalid.set(true);
                    return;
                }
                attempted.set(true);
                actions.launch(
                    format!("skill:{target}"),
                    async move { api::remove(&target, expected_revision).await },
                    finish,
                );
            }
            SkillDialog::Grants(_) | SkillDialog::Edit(_) => {}
        }
    };
    view! {
        <LibraryEditorFrame id="skills-dialog" open=Signal::derive(move || open.get())
            confirm=Signal::derive(move || matches!(dialog.get(),Some(SkillDialog::Delete(_))))
            return_focus_id=move || return_focus.get() on_close=close
            title=move || match dialog.get(){Some(SkillDialog::Create)=>t_string!(i18n,skills.create).to_owned(),Some(SkillDialog::Edit(_))=>t_string!(i18n,skills.edit).to_owned(),Some(SkillDialog::Delete(_))=>t_string!(i18n,skills.delete).to_owned(),Some(SkillDialog::Grants(_))=>t_string!(i18n,skills.grants).to_owned(),None=>t_string!(i18n,skills.saved).to_owned()}>
                <Show when=move || initialized.get() && (readable.get() || matches!(dialog.get(), Some(SkillDialog::Edit(_)))) fallback=move || view! {
                    <p class="ob-page-empty" role="status">{move || if state.loading.get() {t_string!(i18n,common.loading).to_owned()} else {t_string!(i18n,skills.no_longer_available).to_owned()}}</p>
                    <Button disabled=state.loading on_activate=move |_| state.reload(deployment)>{move ||t!(i18n,common.retry)}</Button>
                }>
                <div class="ob-library-form">
                    <Show when=move || invalid.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n,skills.invalid)}</Notice></Show>
                    <Show when=move || collision.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n,skills.collision)}</Notice></Show>
                    <Show when=move || attempted.get() && actions.failed.get() && !actions.unknown.get() && !matches!(dialog.get(), Some(SkillDialog::Edit(_)))><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n,skills.write_error)}</Notice></Show>
                    <Show when=move || matches!(dialog.get(), Some(SkillDialog::Edit(_)))>
                        <EditorNotice id_prefix="skill-editor" phase=editor_phase busy=recovery_busy
                            can_retry=Signal::derive(move ||skill_editor.original.get().is_some())
                            on_compare=compare on_load=load on_retry=retry on_reapply=reapply />
                        <Show when=move || skill_editor.read_failed.get() || (!state.loading.get() && !readable.get())>
                            <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n,revision_editor.read_failed)}</Notice>
                        </Show>
                        <Show when=move || skill_editor.comparison.get()>
                            <section class="ob-library-form" data-skill-comparison="local">
                                <h3>{move || t!(i18n,revision_editor.local_draft)}</h3>
                                <strong>{move || title.get()}</strong><p>{move || summary.get()}</p>{move || instruction_lines(instructions.get())}
                            </section>
                            {move || skill_editor.latest.get().map(|row| view! {
                                <section class="ob-library-form" data-skill-comparison="remote">
                                    <h3>{move || t!(i18n,revision_editor.server_version)}</h3>
                                    <strong>{row.title}</strong><p>{row.summary}</p>{instruction_lines(row.instructions)}
                                </section>
                            })}
                        </Show>
                    </Show>
                    <Show when=move || matches!(dialog.get(),Some(SkillDialog::Create|SkillDialog::Edit(_)))>
                        <Field control_id="skill-slug" label=move ||t_string!(i18n,skills.slug).to_owned() description=move ||t_string!(i18n,skills.slug_help).to_owned()>
                            <Input value=slug disabled=Signal::derive(move ||actions.busy.get()||!matches!(dialog.get(),Some(SkillDialog::Create))) />
                        </Field>
                        <Field control_id="skill-title-input" label=move ||t_string!(i18n,skills.title_label).to_owned() disabled=edit_fields_disabled><Input value=title on_edit=user_edit on_composition=title_composition /></Field>
                        <Field control_id="skill-summary" label=move ||t_string!(i18n,skills.summary).to_owned() disabled=edit_fields_disabled><Input value=summary on_edit=user_edit on_composition=summary_composition /></Field>
                        <Field control_id="skill-instructions" label=move ||t_string!(i18n,skills.instructions).to_owned() description=move ||t_string!(i18n,skills.instructions_help).to_owned() disabled=edit_fields_disabled><Textarea value=instructions on_edit=user_edit on_composition=instructions_composition /></Field>
                    </Show>
                    <Show when=move ||matches!(dialog.get(),Some(SkillDialog::Delete(_)))>
                        <p>{move ||t_string!(i18n,skills.delete_confirm,slug=slug.get()).to_owned()}</p>
                        <p class="text-fg-secondary">{move ||t!(i18n,skills.delete_help)}</p>
                    </Show>
                    <Show when=move ||matches!(dialog.get(),Some(SkillDialog::Grants(_)))>
                        <p>{move ||t!(i18n,skills.grants_intro)}</p>
                        {move || {
                            let Some(d)=data.get() else{return view!{<p role="status">{move ||t!(i18n,common.loading)}</p>}.into_any();};
                            if !d.agents_available{return view!{<Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n,skills.agents_error)}</Notice>}.into_any();}
                            let Some(skill)=d.selected(&slug.get(),deployment) else{return view!{<p role="status">{move ||t!(i18n,skills.no_longer_available)}</p>}.into_any();};
                            let grant_set=skill.granted_to.into_iter().collect::<std::collections::BTreeSet<_>>();
                            let unavailable_count=grant_set.iter().filter(|id|!d.agents.iter().any(|a|a.id.as_str()==id.as_str())).count();
                            view!{
                                <div class="ob-page-rows">
                                    {d.agents.into_iter().map(|agent|{
                                        let allowed = super::state::may_grant_to_agent(d.actor_is_admin, agent.mine);
                                        let granted=grant_set.contains(agent.id.as_str());
                                        let current_slug=skill.slug.clone();let agent_id=agent.id.as_str().to_owned();

                                        view!{<div class="ob-plugin-grant"><div class="ob-plugin-copy"><strong>{agent.name}</strong><Show when=move ||!allowed><span class="text-fg-secondary">{move ||t!(i18n,skills.agent_read_only)}</span></Show></div>
                                            <Button selected=granted disabled=Signal::derive(move || actions.busy.get() || !allowed) on_activate=move |_|{
                                                let target=current_slug.clone();let id=agent_id.clone();attempted.set(true);
                                                actions.launch(format!("skill-grant:{target}:{id}"),async move{api::set_grant(&target,&id,!granted).await},move |_|{});
                                            }>{move ||if granted{t_string!(i18n,skills.revoke).to_owned()}else{t_string!(i18n,skills.grant).to_owned()}}</Button>
                                        </div>}
                                    }).collect_view()}
                                </div>
                                <Show when=move || { unavailable_count > 0 }><p class="text-fg-muted">{move ||t_string!(i18n,skills.unavailable_grants,count=unavailable_count).to_owned()}</p></Show>
                            }.into_any()
                        }}
                    </Show>
                </div>
                <div class="ob-library-form-actions">
                    <Button on_activate=move |_|close.run(())>{move ||t!(i18n,common.close)}</Button>
                    <Show when=move ||matches!(dialog.get(),Some(SkillDialog::Create|SkillDialog::Edit(_)))>
                        <Button id="skill-save" variant=ButtonVariant::Primary disabled=save_disabled on_activate=save>{move ||t!(i18n,common.save)}</Button>
                    </Show>
                    <Show when=move ||matches!(dialog.get(),Some(SkillDialog::Delete(_)))>
                        <Button id="skill-confirm-delete" variant=ButtonVariant::DangerText disabled=actions.busy on_activate=save>{move ||t!(i18n,skills.confirm_delete)}</Button>
                    </Show>
                </div>
                </Show>
        </LibraryEditorFrame>
    }
}

fn close_saved_dialog(
    dialog: RwSignal<Option<SkillDialog>>,
    generation: RwSignal<u64>,
    submitted_generation: u64,
    submitted_dialog: &SkillDialog,
    close: impl FnOnce(),
) {
    if generation.try_get_untracked() == Some(submitted_generation)
        && dialog.try_get_untracked().flatten().as_ref() == Some(submitted_dialog)
    {
        close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_reply_cannot_close_another_or_reopened_skill_editor() {
        Owner::new().with(|| {
            let first = SkillDialog::Edit("review".into());
            let dialog = RwSignal::new(Some(first.clone()));
            let generation = RwSignal::new(1);
            dialog.set(Some(SkillDialog::Edit("other".into())));
            close_saved_dialog(dialog, generation, 1, &first, || dialog.set(None));
            assert!(dialog.get_untracked().is_some());
            dialog.set(Some(first.clone()));
            generation.set(3);
            close_saved_dialog(dialog, generation, 1, &first, || dialog.set(None));
            assert!(dialog.get_untracked().is_some());
            close_saved_dialog(dialog, generation, 3, &first, || dialog.set(None));
            assert!(dialog.get_untracked().is_none());
        });
    }
}
