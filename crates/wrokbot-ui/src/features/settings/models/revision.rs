//! Revision editing of public model metadata. Credentials exist only in the explicit form.

use super::{ModelActions, form::ModelForm};
use crate::{
    api::model_connections::{self as api, MetadataChange, MetadataError},
    editor_notice::EditorNotice,
    editor_runtime::{after, now_ms},
    features::channels::composer::models::ModelDirectory,
    i18n::{t, t_string, use_i18n},
    primitives::{Button, Field, Input, Notice, NoticePresentation, NoticeTone},
    revision_editor::{Apply, AttemptToken, EditorCore, FailureClass, Phase},
};
use leptos::prelude::*;
use openbot_contracts::model_connections::ModelConnection;

#[derive(Clone, Copy)]
enum ReadChoice {
    Compare,
    Load,
    Retry,
    Reapply,
}

#[derive(Clone, Copy)]
struct ModelDriver {
    core: RwSignal<EditorCore>,
    known: RwSignal<ModelConnection>,
    name: RwSignal<String>,
    model: RwSignal<String>,
    latest: RwSignal<Option<ModelConnection>>,
    hint: RwSignal<Option<openbot_contracts::revision::RevisionSnapshot>>,
    retained: StoredValue<Option<(AttemptToken, MetadataChange)>>,
    reading: RwSignal<bool>,
    read_failed: RwSignal<bool>,
    owner: StoredValue<Option<Owner>>,
    actions: ModelActions,
    close: UnsyncCallback<()>,
}

impl ModelDriver {
    fn snapshot(self) -> Option<MetadataChange> {
        let change = MetadataChange {
            base: self.known.try_get_untracked()?,
            name: self.name.try_get_untracked()?.trim().to_owned(),
            model: self.model.try_get_untracked()?.trim().to_owned(),
        };
        change.valid().then_some(change)
    }
    fn matches(self, row: &ModelConnection) -> bool {
        self.name
            .try_get_untracked()
            .is_some_and(|value| value.trim() == row.name)
            && self
                .model
                .try_get_untracked()
                .is_some_and(|value| value.trim() == row.model)
    }
    fn edited(self) {
        let Some(mut core) = self.core.try_get_untracked() else {
            return;
        };
        if core.edit(now_ms()).is_err() {
            self.core.try_set(core);
            return;
        }
        if let Some(known) = self.known.try_get_untracked() {
            core.set_local_matches_known(self.matches(&known));
        }
        self.core.try_set(core);
        self.schedule();
    }
    fn composing(self, active: bool) {
        let Some(mut core) = self.core.try_get_untracked() else {
            return;
        };
        let _ = core.set_composing(active, now_ms());
        self.core.try_set(core);
        if !active {
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
                let Some(change) = self.snapshot() else {
                    return;
                };
                let Some(mut current) = self.core.try_get_untracked() else {
                    return;
                };
                let eligible = self.actions.metadata_hold(&change.base.id).is_none()
                    && self
                        .actions
                        .status
                        .try_get_untracked()
                        .is_some_and(|status| !status.locked());
                let attempt = current.begin_auto(ticket, now_ms(), eligible);
                self.core.try_set(current);
                if let Ok(attempt) = attempt {
                    self.dispatch(attempt, change, false, false);
                }
            },
        );
    }
    fn save_explicit(self) {
        let Some(change) = self.snapshot() else {
            return;
        };
        let Some(mut core) = self.core.try_get_untracked() else {
            return;
        };
        let eligible = self.actions.metadata_hold(&change.base.id).is_none()
            && self
                .actions
                .status
                .try_get_untracked()
                .is_some_and(|status| !status.locked());
        let attempt = core.begin_explicit(now_ms(), eligible);
        self.core.try_set(core);
        if let Ok(token) = attempt {
            self.dispatch(token, change, false, true);
        }
    }
    fn dispatch(
        self,
        token: AttemptToken,
        change: MetadataChange,
        recovery: bool,
        close_on_ack: bool,
    ) {
        if token.expected_revision() != Some(change.base.revision) || !change.valid() {
            self.core.try_update(|core| {
                core.finish_failure(token, FailureClass::Definite);
            });
            return;
        }
        let Some(lease) = self.actions.claim_metadata(&change.base.id, recovery) else {
            self.core.try_update(|core| {
                core.finish_failure(token, FailureClass::Definite);
            });
            return;
        };
        self.retained.try_set_value(Some((token, change.clone())));
        let id = change.base.id.clone();
        after(10_000, move || {
            self.actions.timeout_metadata(&id, lease);
            self.core.try_update(|core| {
                core.mark_timeout(token, now_ms());
            });
        });
        self.actions.launch_metadata(change, lease, move |result| {
            let Some(mut core) = self.core.try_get_untracked() else {
                return;
            };
            if core.generation() != token.generation() {
                return;
            }
            match result {
                Ok(row) => {
                    if core.finish_ack(token, row.revision, self.matches(&row)) == Apply::Applied {
                        self.known.try_set(row);
                        if !core.auto_paused() {
                            self.retained.try_set_value(None);
                        }
                    }
                }
                Err(MetadataError::Conflict(snapshot)) => {
                    if core.finish_closed_conflict(token, snapshot.current_revision())
                        == Apply::Applied
                    {
                        self.hint.try_set(Some(snapshot));
                    }
                }
                Err(error) => {
                    core.finish_failure(
                        token,
                        if error == MetadataError::Unknown {
                            FailureClass::Unknown
                        } else {
                            FailureClass::Definite
                        },
                    );
                }
            }
            let close_now = close_on_ack && core.phase() == Phase::Saved && !core.auto_paused();
            self.core.try_set(core);
            if close_now {
                let _ = self.close.try_run(());
            } else {
                self.schedule();
            }
        });
    }
    fn read(self, choice: ReadChoice) {
        if self.reading.try_get_untracked() != Some(false) {
            return;
        }
        let Some(mut core) = self.core.try_get_untracked() else {
            return;
        };
        let Some(known) = self.known.try_get_untracked() else {
            return;
        };
        if core.current_attempt().is_some()
            || self
                .actions
                .metadata_hold(&known.id)
                .is_some_and(|hold| hold.pending)
        {
            return;
        }
        let Ok(read_token) = core.begin_read() else {
            self.core.try_set(core);
            return;
        };
        let confirmed_edit_serial = core.edit_serial();
        let compared = self.latest.try_get_untracked().flatten();
        let confirmed_draft = self.snapshot();
        self.core.try_set(core);
        let Some(Some(owner)) = self.owner.try_get_value() else {
            return;
        };
        self.reading.try_set(true);
        self.read_failed.try_set(false);
        owner.with(|| {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let result = api::get(&known.id).await;
                let Some(mut core) = self.core.try_get_untracked() else {
                    return;
                };
                self.reading.try_set(false);
                let Ok(row) = result else {
                    self.read_failed.try_set(true);
                    return;
                };
                // A same-revision response cannot substitute a different public object snapshot.
                if row.revision == known.revision && row != known {
                    self.read_failed.try_set(true);
                    return;
                }
                if let Some(Some(hint)) = self.hint.try_get_untracked()
                    && (row.revision < hint.current_revision()
                        || row.revision == hint.current_revision()
                            && openbot_contracts::revision::RevisionSnapshot::from_public(
                                row.revision,
                                row.updated_at,
                                &row,
                            )
                            .ok()
                                != Some(hint))
                {
                    self.read_failed.try_set(true);
                    return;
                }
                let Ok(recovery) = core.accept_recovery_read(read_token, row.revision) else {
                    self.core.try_set(core);
                    self.read_failed.try_set(true);
                    return;
                };
                self.latest.try_set(Some(row.clone()));
                let mut dispatch = None;
                match choice {
                    ReadChoice::Compare => {}
                    ReadChoice::Load => {
                        if core.edit_serial() == confirmed_edit_serial
                            && self.snapshot() == confirmed_draft
                            && !self
                                .actions
                                .metadata_hold(&known.id)
                                .is_some_and(|hold| hold.pending)
                            && core.choose_load(recovery, true) == Apply::Applied
                        {
                            self.name.try_set(row.name.clone());
                            self.model.try_set(row.model.clone());
                            self.known.try_set(row.clone());
                            if !core.auto_paused() {
                                self.actions.release_metadata_after_read(&row.id);
                                self.retained.try_set_value(None);
                            }
                        }
                    }
                    ReadChoice::Retry => {
                        if let Some(Some((original, change))) = self.retained.try_get_value()
                            && !self
                                .actions
                                .metadata_hold(&known.id)
                                .is_some_and(|hold| hold.pending)
                            && let Ok(token) = core.begin_retry_original(
                                recovery,
                                original,
                                now_ms(),
                                change.valid(),
                            )
                        {
                            dispatch = Some((token, change));
                        }
                    }
                    ReadChoice::Reapply => {
                        if compared.as_ref() == Some(&row)
                            && core.edit_serial() == confirmed_edit_serial
                            && let Some(mut change) = confirmed_draft
                        {
                            change.base = row;
                            let eligible = change.valid()
                                && !self
                                    .actions
                                    .metadata_hold(&known.id)
                                    .is_some_and(|hold| hold.pending);
                            if let Ok(token) =
                                core.begin_reapply(recovery, true, now_ms(), eligible)
                            {
                                dispatch = Some((token, change));
                            }
                        }
                    }
                }
                self.core.try_set(core);
                if let Some((token, change)) = dispatch {
                    self.dispatch(token, change, true, false);
                }
            })
        });
    }
}

#[component]
pub(super) fn ModelRevisionEditor(
    base: ModelConnection,
    close: UnsyncCallback<()>,
) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<ModelActions>();
    let directory = expect_context::<ModelDirectory>();
    let mut initial = EditorCore::new();
    let _ = initial.bind_existing(base.revision);
    if let Some(hold) = actions.metadata_hold(&base.id) {
        initial.restore_pause(
            if hold.phase == Phase::Conflict {
                Phase::Conflict
            } else {
                Phase::Error
            },
            hold.uncertain,
        );
    }
    let driver = ModelDriver {
        core: RwSignal::new(initial),
        name: RwSignal::new(base.name.clone()),
        model: RwSignal::new(base.model.clone()),
        known: RwSignal::new(base),
        latest: RwSignal::new(None),
        hint: RwSignal::new(None),
        retained: StoredValue::new(None),
        reading: RwSignal::new(false),
        read_failed: RwSignal::new(false),
        owner: StoredValue::new(Owner::current()),
        actions,
        close,
    };
    let sensitive = RwSignal::new(false);
    let edit = UnsyncCallback::new(move |_| driver.edited());
    let composition = UnsyncCallback::new(move |active| driver.composing(active));
    let phase = Signal::derive(move || driver.core.get().phase());
    let busy = Signal::derive(move || {
        driver.reading.get()
            || driver.core.get().current_attempt().is_some()
            || actions
                .metadata_hold(&driver.known.get().id)
                .is_some_and(|hold| hold.pending)
    });
    let invalid = Signal::derive(move || {
        driver.name.track();
        driver.model.track();
        driver.known.track();
        driver.snapshot().is_none()
    });
    let explicit_disabled = Signal::derive(move || {
        phase.get() != Phase::Saved
            || driver.reading.get()
            || actions.status.get().locked()
            || actions.metadata_hold(&driver.known.get().id).is_some()
    });
    Effect::new(move |_| {
        let rows = directory.rows.get();
        let Some(known) = driver.known.try_get_untracked() else {
            return;
        };
        if let Some(remote) = rows
            .into_iter()
            .find(|row| row.id == known.id && row.revision > known.revision)
        {
            driver.latest.try_set(Some(remote.clone()));
            driver.core.try_update(|core| {
                core.observe_remote(remote.revision);
            });
        }
    });
    on_cleanup(move || {
        driver.core.try_update_untracked(|core| {
            let _ = core.invalidate();
        });
        driver.retained.try_set_value(None);
    });
    view! {
        <Show when=move ||sensitive.get() fallback=move ||view! {
            <div class="ob-library-form">
                <p class="ob-page-intro">{move ||t!(i18n,revision_editor.metadata_boundary)}</p>
                <Field control_id="model-name" label=move ||t_string!(i18n,models.name).to_owned() invalid disabled=Signal::derive(move ||actions.status.get().locked())><Input value=driver.name on_edit=edit on_composition=composition/></Field>
                <Field control_id="model-identifier" label=move ||t_string!(i18n,models.identifier).to_owned() invalid disabled=Signal::derive(move ||actions.status.get().locked())><Input value=driver.model on_edit=edit on_composition=composition/></Field>
                <Show when=move ||invalid.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n,models.invalid)}</Notice></Show>
                <Show when=move ||driver.read_failed.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n,revision_editor.read_failed)}</Notice></Show>
                <EditorNotice phase busy id_prefix="model-editor"
                    can_retry=Signal::derive(move ||{driver.core.track();driver.retained.get_value().is_some()})
                    on_compare=UnsyncCallback::new(move |_|driver.read(ReadChoice::Compare))
                    on_load=UnsyncCallback::new(move |_|driver.read(ReadChoice::Load))
                    on_retry=UnsyncCallback::new(move |_|driver.read(ReadChoice::Retry))
                    on_reapply=UnsyncCallback::new(move |_|driver.read(ReadChoice::Reapply))/>
                <Show when=move ||driver.latest.get().is_some()>
                    <div class="ob-library-form ob-library-detail-body">
                        <h3>{move ||t!(i18n,revision_editor.local_draft)}</h3><p>{move ||driver.name.get()}</p><p>{move ||driver.model.get()}</p>
                        <h3>{move ||t!(i18n,revision_editor.server_version)}</h3><p>{move ||driver.latest.get().map(|row|row.name)}</p><p>{move ||driver.latest.get().map(|row|row.model)}</p>
                    </div>
                </Show>
                <div class="ob-library-form-actions">
                    <Button id="model-confirm" disabled=Signal::derive(move ||phase.get()!=Phase::Dirty || invalid.get() || actions.status.get().locked()) on_activate=move |_|driver.save_explicit()>{move ||t!(i18n,common.save)}</Button>
                    <Button id="model-sensitive-mode" disabled=explicit_disabled on_activate=move |_|sensitive.set(true)>{move ||t!(i18n,revision_editor.sensitive_mode)}</Button><Button on_activate=move |_|close.run(())>{move ||t!(i18n,common.close)}</Button>
                </div>
            </div>
        }>
            <p class="ob-page-intro">{move ||t!(i18n,revision_editor.sensitive_boundary)}</p>
            <ModelForm base=Some(driver.known.get_untracked()) deleting=false close/>
        </Show>
    }
}
