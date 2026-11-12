//! Browser-authored sandbox component editor using the production Web renderer.

use core::fmt::Write as _;
use std::collections::BTreeMap;

use leptos::prelude::*;
use openbot_contracts::sandboxed::SaveSandboxedComponentRequest;
use openbot_contracts::sandboxed::{
    PublishedSandboxedComponent, SandboxedComponentRecord, is_sandboxed_component_name,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::{
    delete_sandboxed_component, load_sandboxed_components, publish_sandboxed_component,
    save_sandboxed_component_draft, save_sandboxed_component_draft_cas,
};
#[cfg(target_arch = "wasm32")]
use crate::configuration_writes::CasWriteError;
use crate::configuration_writes::{ConfigurationWrites, SandboxCasMode};
use crate::editor_notice::EditorNotice;
use crate::features::gallery::SandboxedComponentFrame;
use crate::features::layout::{PageHeader, PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Dialog, DialogBody, DialogContent, DialogFooter, Field,
    Input, Notice, NoticeTone, Textarea,
};
#[cfg(target_arch = "wasm32")]
use crate::revision_editor::{Apply, Phase};
use crate::revision_editor::{AttemptToken, EditorCore, FailureClass};

const STARTER_HTML: &str = concat!(
    "<div cl",
    "ass=\"card\">\n  <h3 id=\"title\">Untitled</h3>\n  <p id=\"body\"></p>\n</div>"
);
const STARTER_CSS: &str = ".card { font: 14px system-ui; border: 1px solid #e5e5e5; border-radius: 8px; padding: 12px; }\n.card h3 { margin: 0 0 4px; font-size: 15px; }";
const STARTER_JS: &str = "// The arguments are on window.__args by the time this runs.\nconst args = window.__args || {};\ndocument.getElementById(\"title\").textContent = args.title || \"Untitled\";\ndocument.getElementById(\"body\").textContent = args.body || \"\";";
const STARTER_SCHEMA: &str = "{\n  \"type\": \"object\",\n  \"properties\": {\n    \"title\": { \"type\": \"string\" },\n    \"body\": { \"type\": \"string\" }\n  }\n}";
const STARTER_SAMPLE: &str = "{\n  \"title\": \"A worked example\",\n  \"body\": \"Edit the panels on the left and this redraws.\"\n}";

#[derive(Clone, Copy)]
struct DraftSignals {
    known_revision: RwSignal<Option<(String, i64)>>,
    slug: RwSignal<String>,
    title: RwSignal<String>,
    description: RwSignal<String>,
    html: RwSignal<String>,
    css: RwSignal<String>,
    js_functions: RwSignal<String>,
    argument_schema: RwSignal<String>,
    sample_arguments: RwSignal<String>,
}

impl DraftSignals {
    fn starter() -> Self {
        Self {
            known_revision: RwSignal::new(None),
            slug: RwSignal::new(String::new()),
            title: RwSignal::new(String::new()),
            description: RwSignal::new(String::new()),
            html: RwSignal::new(STARTER_HTML.to_owned()),
            css: RwSignal::new(STARTER_CSS.to_owned()),
            js_functions: RwSignal::new(STARTER_JS.to_owned()),
            argument_schema: RwSignal::new(STARTER_SCHEMA.to_owned()),
            sample_arguments: RwSignal::new(STARTER_SAMPLE.to_owned()),
        }
    }

    fn request(self) -> Option<SaveSandboxedComponentRequest> {
        if !is_sandboxed_component_name(&format!("custom_{}", self.slug.get_untracked()))
            || self.title.get_untracked().is_empty()
        {
            return None;
        }
        Some(SaveSandboxedComponentRequest {
            expected_revision: self
                .known_revision
                .get_untracked()
                .filter(|(name, _)| *name == format!("custom_{}", self.slug.get_untracked()))
                .map(|(_, revision)| revision),
            slug: self.slug.get_untracked(),
            title: self.title.get_untracked(),
            description: self.description.get_untracked(),
            html: self.html.get_untracked(),
            css: self.css.get_untracked(),
            js_functions: self.js_functions.get_untracked(),
            argument_schema: parse_object(&self.argument_schema.get_untracked())?,
            sample_arguments: parse_object(&self.sample_arguments.get_untracked())?,
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn snapshot(self) -> [String; 8] {
        [
            self.slug,
            self.title,
            self.description,
            self.html,
            self.css,
            self.js_functions,
            self.argument_schema,
            self.sample_arguments,
        ]
        .map(|field| field.get_untracked())
    }

    fn load(self, component: &SandboxedComponentRecord) {
        self.known_revision
            .set(Some((component.name.clone(), component.editing_revision)));
        self.load_fields(component);
    }

    #[cfg(target_arch = "wasm32")]
    fn confirm_revision(self, component: &SandboxedComponentRecord) {
        if self.slug.try_get_untracked().as_deref() != component.name.strip_prefix("custom_") {
            return;
        }
        self.known_revision.try_update(|known| {
            if known.as_ref().is_some_and(|(name, revision)| {
                name == &component.name && *revision > component.editing_revision
            }) {
                return;
            }
            *known = Some((component.name.clone(), component.editing_revision));
        });
    }

    fn load_fields(self, component: &SandboxedComponentRecord) {
        self.slug.set(
            component
                .name
                .strip_prefix("custom_")
                .unwrap_or_default()
                .to_owned(),
        );
        self.title.set(component.title.clone());
        self.description.set(component.draft_description.clone());
        self.html.set(component.draft_html.clone());
        self.css.set(component.draft_css.clone());
        self.js_functions.set(component.draft_js_functions.clone());
        self.argument_schema.set(
            serde_json::to_string_pretty(&component.draft_argument_schema)
                .unwrap_or_else(|_| "{}".to_owned()),
        );
        self.sample_arguments.set(
            serde_json::to_string_pretty(&component.sample_arguments)
                .unwrap_or_else(|_| "{}".to_owned()),
        );
    }
}

#[derive(Clone, PartialEq)]
struct PreviewItem {
    key: String,
    component: PublishedSandboxedComponent,
    arguments: Value,
}

#[derive(Clone, Copy)]
struct MutationState {
    pending: RwSignal<bool>,
    error: RwSignal<bool>,
    reload: RwSignal<u64>,
    write_lock: Signal<bool>,
}

#[derive(Clone)]
struct FrozenDraft {
    token: AttemptToken,
    request: SaveSandboxedComponentRequest,
}

#[derive(Clone, Copy)]
struct SandboxEditing {
    core: RwSignal<EditorCore>,
    known: RwSignal<Option<SandboxedComponentRecord>>,
    latest: RwSignal<Option<SandboxedComponentRecord>>,
    hint: RwSignal<Option<openbot_contracts::revision::RevisionSnapshot>>,
    frozen: RwSignal<Option<FrozenDraft>>,
    reading: RwSignal<bool>,
    read_error: RwSignal<Option<ApiError>>,
    comparing: RwSignal<bool>,
    writes: ConfigurationWrites,
}

impl SandboxEditing {
    fn new() -> Self {
        Self {
            core: RwSignal::new(EditorCore::new()),
            known: RwSignal::new(None),
            latest: RwSignal::new(None),
            hint: RwSignal::new(None),
            frozen: RwSignal::new(None),
            reading: RwSignal::new(false),
            read_error: RwSignal::new(None),
            comparing: RwSignal::new(false),
            writes: expect_context::<ConfigurationWrites>(),
        }
    }

    fn bind(self, draft: DraftSignals, record: &SandboxedComponentRecord) {
        let mut core = self.core.get_untracked();
        if core.bind_existing(record.editing_revision).is_err() {
            return;
        }
        if let Some((phase, uncertain)) = self.writes.sandbox_pause(&record.name) {
            core.restore_pause(phase, uncertain);
        }
        draft.load(record);
        self.core.set(core);
        self.known.set(Some(record.clone()));
        self.latest.set(None);
        self.hint.set(None);
        self.frozen.set(None);
        self.comparing.set(false);
        self.reading.set(false);
        self.read_error.set(None);
    }

    fn edited(self, draft: DraftSignals, state: MutationState) {
        if self
            .known
            .get_untracked()
            .as_ref()
            .is_some_and(|known| known.name != format!("custom_{}", draft.slug.get_untracked()))
        {
            self.core.update(|core| {
                let _ = core.invalidate();
            });
            self.known.set(None);
            self.latest.set(None);
            self.hint.set(None);
            self.frozen.set(None);
            self.comparing.set(false);
        }
        self.core.update(|core| {
            let _ = core.edit(crate::editor_runtime::now_ms());
            if let (Some(request), Some(known)) = (draft.request(), self.known.get_untracked()) {
                core.set_local_matches_known(draft_matches(&request, &known));
            }
        });
        self.schedule(draft, state);
    }

    fn composition(self, draft: DraftSignals, state: MutationState, active: bool) {
        self.core.update(|core| {
            let _ = core.set_composing(active, crate::editor_runtime::now_ms());
        });
        if !active {
            self.schedule(draft, state);
        }
    }

    fn schedule(self, draft: DraftSignals, state: MutationState) {
        let Some(core) = self.core.try_get_untracked() else {
            return;
        };
        let Some(deadline) = core.next_auto_deadline() else {
            return;
        };
        let ticket = core.debounce_token();
        let wait = deadline
            .saturating_sub(crate::editor_runtime::now_ms())
            .min(i32::MAX as u64) as i32;
        crate::editor_runtime::after(wait, move || {
            let Some(mut core) = self.core.try_get_untracked() else {
                return;
            };
            if core.debounce_token() != ticket {
                return;
            }
            let Some(mut request) = draft.request() else {
                return;
            };
            let eligible = self.known.get_untracked().is_some()
                && !state.pending.get_untracked()
                && !state.write_lock.get_untracked();
            match core.begin_auto(ticket, crate::editor_runtime::now_ms(), eligible) {
                Ok(token) => {
                    request.expected_revision = token.expected_revision();
                    self.core.set(core);
                    dispatch_cas(
                        draft,
                        state,
                        self,
                        token,
                        request,
                        SandboxCasMode::Automatic,
                    );
                }
                Err(crate::revision_editor::Blocked::NotDue) => self.schedule(draft, state),
                Err(_) => {}
            }
        });
    }

    fn explicit_save(self, draft: DraftSignals, state: MutationState) {
        let Some(mut request) = draft.request() else {
            return;
        };
        let mut core = self.core.get_untracked();
        let eligible = !state.pending.get_untracked() && !state.write_lock.get_untracked();
        let Ok(token) = core.begin_explicit(crate::editor_runtime::now_ms(), eligible) else {
            return;
        };
        request.expected_revision = token.expected_revision();
        self.core.set(core);
        dispatch_cas(
            draft,
            state,
            self,
            token,
            request,
            SandboxCasMode::Automatic,
        );
    }
}

fn draft_matches(
    request: &SaveSandboxedComponentRequest,
    record: &SandboxedComponentRecord,
) -> bool {
    record.name == format!("custom_{}", request.slug)
        && record.title == request.title
        && record.draft_description == request.description
        && record.draft_html == request.html
        && record.draft_css == request.css
        && record.draft_js_functions == request.js_functions
        && record.draft_argument_schema == request.argument_schema
        && record.sample_arguments == request.sample_arguments
}

#[derive(Clone, Copy)]
enum RecoveryChoice {
    Compare,
    Load,
    Retry,
    Reapply,
}

fn dispatch_cas(
    _draft: DraftSignals,
    state: MutationState,
    editing: SandboxEditing,
    token: AttemptToken,
    request: SaveSandboxedComponentRequest,
    mode: SandboxCasMode,
) {
    let frozen = FrozenDraft { token, request };
    editing.frozen.set(Some(frozen.clone()));
    state.error.set(false);
    #[cfg(target_arch = "wasm32")]
    {
        let draft = _draft;
        crate::editor_runtime::after(10_000, move || {
            let Some(mut core) = editing.core.try_get_untracked() else {
                return;
            };
            if core.mark_timeout(token, crate::editor_runtime::now_ms()) == Apply::Applied {
                editing.core.try_set(core);
            }
        });
        let Some(owner) = editing.writes.owner() else {
            editing.core.update(|core| {
                core.finish_failure(token, FailureClass::Unknown);
            });
            return;
        };
        owner.with(move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let result = save_sandboxed_component_draft_cas(&frozen.request, mode).await;
                let Some(mut core) = editing
                    .core
                    .try_get_untracked()
                    .filter(|core| core.generation() == token.generation())
                else {
                    return;
                };
                match result {
                    Ok(saved) => {
                        let matches = draft
                            .request()
                            .is_some_and(|request| draft_matches(&request, &saved.component));
                        if core.finish_ack(token, saved.component.editing_revision, matches)
                            == Apply::Applied
                        {
                            draft.confirm_revision(&saved.component);
                            editing.known.try_set(Some(saved.component));
                            state.reload.try_update(|generation| {
                                if let Some(next) = generation.checked_add(1) {
                                    *generation = next;
                                }
                            });
                        }
                    }
                    Err(CasWriteError::Conflict(snapshot)) => {
                        if core.finish_closed_conflict(token, snapshot.current_revision())
                            == Apply::Applied
                        {
                            editing.hint.try_set(Some(snapshot));
                        }
                    }
                    Err(CasWriteError::Rejected(_)) => {
                        core.finish_failure(token, FailureClass::Definite);
                    }
                    Err(CasWriteError::Unknown(_)) => {
                        core.finish_failure(token, FailureClass::Unknown);
                    }
                }
                editing.core.try_set(core);
                editing.schedule(draft, state);
            })
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (frozen.token, frozen.request, mode);
        editing.core.update(|core| {
            core.finish_failure(token, FailureClass::Unknown);
        });
    }
}

fn recover_draft(
    draft: DraftSignals,
    state: MutationState,
    editing: SandboxEditing,
    choice: RecoveryChoice,
) {
    if editing.reading.get_untracked()
        || state.pending.get_untracked()
        || editing.core.get_untracked().current_attempt().is_some()
    {
        return;
    }
    let Some(known) = editing.known.get_untracked() else {
        return;
    };
    #[cfg(target_arch = "wasm32")]
    let compared = editing
        .comparing
        .get_untracked()
        .then(|| editing.latest.get_untracked())
        .flatten();
    let mut core = editing.core.get_untracked();
    #[cfg(target_arch = "wasm32")]
    let load_confirmed =
        matches!(choice, RecoveryChoice::Load).then(|| (draft.snapshot(), core.edit_serial()));
    #[cfg(target_arch = "wasm32")]
    let confirmed = matches!(choice, RecoveryChoice::Reapply)
        .then(|| {
            draft
                .request()
                .map(|request| (request, draft.snapshot(), core.edit_serial()))
        })
        .flatten();
    let Ok(read) = core.begin_read() else {
        return;
    };
    editing.core.set(core);
    editing.reading.set(true);
    editing.read_error.set(None);
    #[cfg(target_arch = "wasm32")]
    if let Some(owner) = editing.writes.owner() {
        owner.with(move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let result = load_sandboxed_components().await;
                let Some(mut core) = editing
                    .core
                    .try_get_untracked()
                    .filter(|current| current.generation() == core.generation())
                else {
                    return;
                };
                editing.reading.try_set(false);
                let record = match result {
                    Ok(loaded) => loaded
                        .components
                        .into_iter()
                        .find(|record| record.name == known.name),
                    Err(error) => {
                        editing.read_error.try_set(Some(error));
                        core.restore_pause(Phase::Error, core.historical_uncertainty());
                        editing.core.try_set(core);
                        return;
                    }
                };
                let Some(record) = record else {
                    editing.read_error.try_set(Some(ApiError::NotFound));
                    return;
                };
                if record.editing_revision == known.editing_revision && record != known {
                    editing.read_error.try_set(Some(ApiError::InvalidResponse));
                    core.restore_pause(Phase::Error, core.historical_uncertainty());
                    editing.core.try_set(core);
                    return;
                }
                if let Some(hint) = editing.hint.get_untracked() {
                    let current = openbot_contracts::revision::RevisionSnapshot::from_public(
                        record.editing_revision,
                        record.updated_at,
                        &record,
                    )
                    .ok();
                    if record.editing_revision < hint.current_revision()
                        || (record.editing_revision == hint.current_revision()
                            && current != Some(hint))
                    {
                        editing.read_error.try_set(Some(ApiError::InvalidResponse));
                        core.restore_pause(Phase::Error, core.historical_uncertainty());
                        editing.core.try_set(core);
                        return;
                    }
                }
                let Ok(recovered) = core.accept_recovery_read(read, record.editing_revision) else {
                    editing.read_error.try_set(Some(ApiError::InvalidResponse));
                    editing.core.try_set(core);
                    return;
                };
                editing.latest.try_set(Some(record.clone()));
                match choice {
                    RecoveryChoice::Compare => {
                        editing.comparing.try_set(true);
                        editing.core.try_set(core);
                    }
                    RecoveryChoice::Load => {
                        if load_confirmed.as_ref().is_none_or(|(raw, serial)| {
                            core.edit_serial() != *serial || draft.snapshot() != *raw
                        }) {
                            editing.comparing.try_set(true);
                            editing.core.try_set(core);
                            return;
                        }
                        if core.choose_load(recovered, true) == Apply::Applied {
                            draft.load(&record);
                            editing.known.try_set(Some(record.clone()));
                            editing.hint.try_set(None);
                            editing.frozen.try_set(None);
                            editing.comparing.try_set(false);
                            editing.writes.sandbox_loaded(&record.name);
                        }
                        editing.core.try_set(core);
                    }
                    RecoveryChoice::Retry | RecoveryChoice::Reapply => {
                        let (request, attempt, mode) = if matches!(choice, RecoveryChoice::Retry) {
                            let Some(frozen) = editing.frozen.get_untracked() else {
                                editing.comparing.try_set(true);
                                editing.core.try_set(core);
                                return;
                            };
                            let attempt = core.begin_retry_original(
                                recovered,
                                frozen.token,
                                crate::editor_runtime::now_ms(),
                                true,
                            );
                            (frozen.request, attempt, SandboxCasMode::RetryOriginal)
                        } else {
                            // Confirmation applies to the complete remote version already
                            // displayed. A new or changed read first needs comparison again.
                            if compared.as_ref() != Some(&record) {
                                editing.comparing.try_set(true);
                                editing.core.try_set(core);
                                return;
                            }
                            let Some((request, raw, confirmed_serial)) = confirmed else {
                                editing.core.try_set(core);
                                return;
                            };
                            if core.edit_serial() != confirmed_serial || draft.snapshot() != raw {
                                editing.comparing.try_set(true);
                                editing.core.try_set(core);
                                return;
                            }
                            let attempt = core.begin_reapply(
                                recovered,
                                true,
                                crate::editor_runtime::now_ms(),
                                true,
                            );
                            (request, attempt, SandboxCasMode::Reapply)
                        };
                        match attempt {
                            Ok(token) => {
                                let mut request = request;
                                request.expected_revision = token.expected_revision();
                                editing.core.try_set(core);
                                dispatch_cas(draft, state, editing, token, request, mode);
                            }
                            Err(_) => {
                                editing.comparing.try_set(true);
                                editing.core.try_set(core);
                            }
                        }
                    }
                }
            })
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (known, read, draft, choice);
        editing.reading.set(false);
        editing.read_error.set(Some(ApiError::Unavailable));
    }
}

/// Fresh-admin draft/save/publish/delete journey with the same renderer used by conversations.
#[component]
pub fn SandboxPlaygroundPage() -> impl IntoView {
    let i18n = use_i18n();
    let draft = DraftSignals::starter();
    let components = RwSignal::new(Vec::<SandboxedComponentRecord>::new());
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(None::<ApiError>);
    let action_error = RwSignal::new(false);
    let pending = RwSignal::new(false);
    let write_lock = crate::configuration_writes::family_lock(
        crate::configuration_writes::ConfigurationKind::Sandbox,
    );
    let reload_generation = RwSignal::new(0_u64);
    let delete_open = RwSignal::new(false);
    let deleting = RwSignal::new(None::<String>);
    let worker_owner = StoredValue::new(Owner::current());
    let state = MutationState {
        pending,
        error: action_error,
        reload: reload_generation,
        write_lock,
    };
    let editing = SandboxEditing::new();
    on_cleanup(move || {
        editing.core.try_update(|core| {
            let _ = core.invalidate();
        });
    });
    let on_edit = UnsyncCallback::new(move |_| editing.edited(draft, state));
    let on_composition =
        UnsyncCallback::new(move |active| editing.composition(draft, state, active));
    Effect::new(move |_| {
        let locked = write_lock.get();
        let core = editing.core.get();
        if !locked && core.next_auto_deadline().is_some() {
            editing.schedule(draft, state);
        }
    });
    install_loader(
        reload_generation,
        components,
        loading,
        load_error,
        worker_owner,
        editing,
    );

    let schema_valid = Memo::new(move |_| parse_object(&draft.argument_schema.get()).is_some());
    let sample = Memo::new(move |_| parse_object(&draft.sample_arguments.get()));
    let identity_valid = Memo::new(move |_| {
        is_sandboxed_component_name(&format!("custom_{}", draft.slug.get()))
            && !draft.title.get().is_empty()
    });
    let draft_valid =
        Memo::new(move |_| identity_valid.get() && schema_valid.get() && sample.get().is_some());
    let preview = Memo::new(move |_| {
        let arguments = Value::Object(sample.get()?.into_iter().collect());
        let html = draft.html.get();
        let css = draft.css.get();
        let js_functions = draft.js_functions.get();
        let sample_text = draft.sample_arguments.get();
        Some(PreviewItem {
            key: format!("{html}\u{0}{css}\u{0}{js_functions}\u{0}{sample_text}"),
            component: PublishedSandboxedComponent {
                name: "custom_preview".to_owned(),
                html,
                css,
                js_functions,
                argument_schema: BTreeMap::new(),
            },
            arguments,
        })
    });

    let submit = move |publish: bool| {
        if draft_valid.get_untracked() {
            if !publish && editing.known.get_untracked().is_some() {
                editing.explicit_save(draft, state);
            } else {
                dispatch_draft(draft, state, editing, publish);
            }
        }
    };
    let confirm_delete = move || {
        let Some(_name) = deleting.get_untracked() else {
            return;
        };
        if pending.get_untracked()
            || write_lock.get_untracked()
            || editing.core.get_untracked().current_attempt().is_some()
        {
            return;
        }
        pending.set(true);
        action_error.set(false);
        #[cfg(target_arch = "wasm32")]
        if let Some(owner) = editing.writes.owner() {
            owner.with(move || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let Some(revision) = components
                        .get_untracked()
                        .iter()
                        .find(|component| component.name == _name)
                        .map(|component| component.editing_revision)
                    else {
                        pending.try_set(false);
                        action_error.try_set(true);
                        return;
                    };
                    match delete_sandboxed_component(&_name, revision).await {
                        Ok(()) => {
                            if editing
                                .known
                                .try_get_untracked()
                                .flatten()
                                .is_some_and(|known| known.name == _name)
                            {
                                editing.core.try_update(|core| {
                                    let _ = core.invalidate();
                                });
                                editing.known.try_set(None);
                                editing.latest.try_set(None);
                                editing.frozen.try_set(None);
                            }
                            if deleting.try_get_untracked().flatten().as_deref() == Some(&_name) {
                                delete_open.try_set(false);
                                deleting.try_set(None);
                            }
                            reload_generation.try_update(|generation| {
                                *generation = generation.saturating_add(1)
                            });
                        }
                        Err(_) => {
                            action_error.try_set(!write_lock.get_untracked());
                        }
                    }
                    pending.try_set(false);
                })
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        pending.set(false);
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="sandbox-playground-title"
                title=move || t_string!(i18n, admin.playground_title).to_owned()
                description=move || t_string!(i18n, admin.playground_intro).to_owned()
            />
            <div class="ob-playground-actions">
                <Button
                    variant=ButtonVariant::Chip
                    size=ButtonSize::Small
                    disabled=Signal::derive(move || !draft_valid.get() || pending.get() || write_lock.get() || editing.core.get().auto_paused())
                    loading=pending
                    on_activate=move || submit(false)
                >{move || t!(i18n, admin.playground_save)}</Button>
                <Button
                    variant=ButtonVariant::Primary
                    size=ButtonSize::Small
                    disabled=Signal::derive(move || !draft_valid.get() || pending.get() || write_lock.get() || editing.core.get().auto_paused())
                    loading=pending
                    on_activate=move || submit(true)
                >{move || t!(i18n, admin.playground_publish)}</Button>
            </div>
            <Show when=move || editing.core.get().is_bound()>
                <EditorNotice
                    id_prefix="sandbox-editor"
                    phase=Signal::derive(move || editing.core.get().phase())
                    busy=Signal::derive(move || pending.get() || editing.reading.get() || editing.core.get().current_attempt().is_some())
                    can_retry=Signal::derive(move || editing.frozen.get().is_some())
                    on_compare=UnsyncCallback::new(move |_| recover_draft(draft, state, editing, RecoveryChoice::Compare))
                    on_load=UnsyncCallback::new(move |_| recover_draft(draft, state, editing, RecoveryChoice::Load))
                    on_retry=UnsyncCallback::new(move |_| recover_draft(draft, state, editing, RecoveryChoice::Retry))
                    on_reapply=UnsyncCallback::new(move |_| recover_draft(draft, state, editing, RecoveryChoice::Reapply))
                />
            </Show>
            <Show when=move || editing.comparing.get() && editing.latest.get().is_some()>
                <div class="ob-library-form" id="sandbox-editor-remote">
                    <p>{move || t!(i18n, revision_editor.compare)}</p>
                    <pre>{move || editing.latest.get().and_then(|record| serde_json::to_string_pretty(&record).ok()).unwrap_or_default()}</pre>
                </div>
            </Show>
            <Show when=move || action_error.get()>
                <Notice tone=NoticeTone::Error>{move || t!(i18n, admin.playground_action_error)}</Notice>
            </Show>
            <Show when=move || editing.read_error.get().is_some()>
                <Notice tone=NoticeTone::Error>{move || if editing.read_error.get() == Some(ApiError::Forbidden) {
                    t_string!(i18n, admin.playground_forbidden).to_owned()
                } else { t_string!(i18n, admin.playground_load_error).to_owned() }}</Notice>
            </Show>
            <Show when=move || load_error.get().is_some()>
                <Notice tone=NoticeTone::Error>{move || if load_error.get() == Some(ApiError::Forbidden) {
                    t_string!(i18n, admin.playground_forbidden).to_owned()
                } else {
                    t_string!(i18n, admin.playground_load_error).to_owned()
                }}</Notice>
            </Show>
            <div class="ob-playground-grid">
                <section class="ob-playground-editor" aria-labelledby="sandbox-editor-title">
                    <h2 id="sandbox-editor-title">{move || t!(i18n, admin.playground_editor)}</h2>
                    <div class="ob-playground-identity">
                        <EditorField
                            id="sandbox-name"
                            label=move || t_string!(i18n, admin.playground_name).to_owned()
                            placeholder=move || t_string!(i18n, admin.playground_name_placeholder).to_owned()
                            value=draft.slug
                            on_edit on_composition
                        />
                        <EditorField
                            id="sandbox-title"
                            label=move || t_string!(i18n, admin.playground_component_title).to_owned()
                            placeholder=move || t_string!(i18n, admin.playground_title_placeholder).to_owned()
                            value=draft.title
                            on_edit on_composition
                        />
                    </div>
                    <EditorField
                        id="sandbox-description"
                        label=move || t_string!(i18n, admin.playground_description).to_owned()
                        placeholder=move || t_string!(i18n, admin.playground_description_placeholder).to_owned()
                        value=draft.description
                        on_edit on_composition
                    />
                    <CodeField id="sandbox-html" label="HTML".to_owned() value=draft.html on_edit on_composition />
                    <CodeField id="sandbox-css" label="CSS".to_owned() value=draft.css on_edit on_composition />
                    <CodeField id="sandbox-js" label="JavaScript".to_owned() value=draft.js_functions on_edit on_composition />
                    <CodeField
                        id="sandbox-schema"
                        label=move || t_string!(i18n, admin.playground_schema).to_owned()
                        value=draft.argument_schema
                        invalid=Signal::derive(move || !schema_valid.get())
                        on_edit on_composition
                    />
                    <CodeField
                        id="sandbox-sample"
                        label=move || t_string!(i18n, admin.playground_sample).to_owned()
                        value=draft.sample_arguments
                        invalid=Signal::derive(move || sample.get().is_none())
                        on_edit on_composition
                    />
                </section>
                <section class="ob-playground-preview" aria-labelledby="sandbox-preview-title">
                    <h2 id="sandbox-preview-title">{move || t!(i18n, admin.playground_preview)}</h2>
                    <Show when=move || sample.get().is_none()>
                        <Notice tone=NoticeTone::Error>
                            {move || t!(i18n, admin.playground_sample_invalid)}
                        </Notice>
                    </Show>
                    <For
                        each=move || preview.get()
                        key=|item| item.key.clone()
                        children=move |item| view! {
                            <SandboxedComponentFrame
                                component=item.component
                                arguments=item.arguments
                                title=move || t_string!(i18n, admin.playground_preview).to_owned()
                            />
                        }
                    />
                    <div class="ob-playground-saved">
                        <h2>{move || t!(i18n, admin.playground_saved)}</h2>
                        <Show when=move || loading.get()>
                            <p class="ob-loading" role="status">{move || t!(i18n, common.loading)}</p>
                        </Show>
                        <Show when=move || !loading.get() && components.get().is_empty()>
                            <p class="ob-empty-body">{move || t!(i18n, admin.playground_empty)}</p>
                        </Show>
                        <ul class="ob-playground-list">
                            <For
                                each=move || components.get()
                                key=sandboxed_component_row_key
                                children=move |component| {
                                    let open_component = component.clone();
                                    let delete_name = component.name.clone();
                                    let published = component.published;
                                    let revision = component.revision;
                                    let has_unpublished_changes = component.has_unpublished_changes;
                                    let status = move || {
                                        let status = if published {
                                            t_string!(i18n, admin.playground_published, revision = revision).to_owned()
                                        } else {
                                            t_string!(i18n, admin.playground_draft_only).to_owned()
                                        };
                                        if has_unpublished_changes {
                                            format!("{status} · {}", t_string!(i18n, admin.playground_edited))
                                        } else {
                                            status
                                        }
                                    };
                                    view! {
                                        <li>
                                            <div>
                                                <code>{component.name}</code>
                                                <p>{status}</p>
                                            </div>
                                            <div class="ob-playground-row-actions">
                                                <Button
                                                    size=ButtonSize::Small
                                                    variant=ButtonVariant::Chip
                                                    disabled=pending
                                                    on_activate=move || editing.bind(draft, &open_component)
                                                >{t!(i18n, admin.playground_open)}</Button>
                                                <Button
                                                    size=ButtonSize::Small
                                                    variant=ButtonVariant::DangerText
                                                    on_activate=move || {
                                                        deleting.set(Some(delete_name.clone()));
                                                        delete_open.set(true);
                                                    }
                                                >{t!(i18n, common.delete)}</Button>
                                            </div>
                                        </li>
                                    }
                                }
                            />
                        </ul>
                    </div>
                </section>
            </div>
        </PageShell>
        <Dialog
            id="sandbox-delete-dialog"
            open=delete_open
            on_close=UnsyncCallback::new(move |_| deleting.set(None))
        >
            <DialogContent
                title=move || t_string!(i18n, admin.playground_delete_title).to_owned()
                description=move || t_string!(i18n, admin.playground_delete_description).to_owned()
            >
                <DialogBody>
                    <code>{move || deleting.get().unwrap_or_default()}</code>
                </DialogBody>
                <DialogFooter>
                    <Button
                        variant=ButtonVariant::Ghost
                        on_activate=move || {
                            delete_open.set(false);
                            deleting.set(None);
                        }
                    >{move || t!(i18n, common.cancel)}</Button>
                    <Button
                        variant=ButtonVariant::DangerText
                        loading=pending disabled=write_lock
                        on_activate=confirm_delete
                    >{move || t!(i18n, common.delete)}</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    }
}

fn dispatch_draft(
    draft: DraftSignals,
    state: MutationState,
    editing: SandboxEditing,
    publish: bool,
) {
    if state.pending.get_untracked()
        || state.write_lock.get_untracked()
        || editing.core.get_untracked().current_attempt().is_some()
        || editing.core.get_untracked().auto_paused()
    {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let Some(request) = draft.request() else {
            return;
        };
        let snapshot = draft.snapshot();
        let observed_core = editing.core.get_untracked();
        let observed = observed_core.generation();
        let creating = !observed_core.is_bound();
        state.pending.set(true);
        state.error.set(false);
        if let Some(owner) = editing.writes.owner() {
            owner.with(move || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    // Explicit creation has no existing revision to recover. Revalidate the
                    // actual fresh-admin read before each attempt, including a prior denial.
                    let authorized = if creating {
                        load_sandboxed_components().await.map(|_| ())
                    } else {
                        Ok(())
                    };
                    let result = match authorized {
                        Err(error) => Err(error),
                        Ok(()) if publish => publish_sandboxed_component(&request).await,
                        Ok(()) => save_sandboxed_component_draft(&request).await,
                    };
                    // The authenticated write has settled even if the user changed the draft target.
                    state.pending.try_set(false);
                    if editing
                        .core
                        .try_get_untracked()
                        .is_none_or(|core| core.generation() != observed)
                    {
                        return;
                    }
                    match result {
                        Ok(saved) => {
                            draft.confirm_revision(&saved.component);
                            if format!("custom_{}", draft.slug.get_untracked())
                                != saved.component.name
                            {
                                state.reload.try_update(|generation| {
                                    if let Some(next) = generation.checked_add(1) {
                                        *generation = next;
                                    }
                                });
                                return;
                            }
                            if draft.snapshot() == snapshot {
                                draft.load_fields(&saved.component);
                            }
                            let mut core = editing.core.get_untracked();
                            if core
                                .bind_existing(saved.component.editing_revision)
                                .is_err()
                            {
                                return;
                            }
                            editing.known.try_set(Some(saved.component.clone()));
                            editing.latest.try_set(None);
                            editing.hint.try_set(None);
                            editing.frozen.try_set(None);
                            if !draft
                                .request()
                                .is_some_and(|request| draft_matches(&request, &saved.component))
                            {
                                let _ = core.edit(crate::editor_runtime::now_ms());
                            }
                            editing.core.try_set(core);
                            state.reload.try_update(|generation| {
                                *generation = generation.saturating_add(1)
                            });
                        }
                        Err(_) => {
                            state.error.try_set(!state.write_lock.get_untracked());
                            if observed_core.is_bound() {
                                editing.core.try_update(|core| {
                                    core.restore_pause(
                                        Phase::Error,
                                        state.write_lock.get_untracked(),
                                    )
                                });
                            }
                        }
                    }
                    state.pending.try_set(false);
                    editing.schedule(draft, state);
                });
            });
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (draft, publish, state.error, state.reload, editing);
}

#[component]
fn EditorField(
    #[prop(into)] id: String,
    #[prop(into)] label: TextProp,
    #[prop(into)] placeholder: TextProp,
    value: RwSignal<String>,
    on_edit: UnsyncCallback<()>,
    on_composition: UnsyncCallback<bool>,
) -> impl IntoView {
    view! {
        <Field control_id=id label>
            <Input value placeholder on_edit on_composition />
        </Field>
    }
}

#[component]
fn CodeField(
    #[prop(into)] id: String,
    #[prop(into)] label: TextProp,
    value: RwSignal<String>,
    #[prop(optional, into)] invalid: MaybeProp<bool>,
    on_edit: UnsyncCallback<()>,
    on_composition: UnsyncCallback<bool>,
) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <div class="ob-playground-code">
            <Field
                control_id=id
                label
                invalid
                error=move || t_string!(i18n, admin.playground_json_invalid).to_owned()
            >
                <Textarea value on_edit on_composition />
            </Field>
        </div>
    }
}

fn parse_object(raw: &str) -> Option<BTreeMap<String, Value>> {
    serde_json::from_str(raw).ok()
}

fn sandboxed_component_row_key(component: &SandboxedComponentRecord) -> String {
    let encoded = serde_json::to_vec(component).unwrap_or_default();
    let mut key = String::from("sandboxed-row-");
    for byte in Sha256::digest(encoded) {
        write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
    }
    key
}

fn install_loader(
    generation: RwSignal<u64>,
    components: RwSignal<Vec<SandboxedComponentRecord>>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<ApiError>>,
    worker_owner: StoredValue<Option<Owner>>,
    editing: SandboxEditing,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let observed = generation.get();
        let editor_generation = editing.core.get_untracked().generation();
        loading.set(true);
        error.set(None);
        if let Some(owner) = worker_owner.get_value() {
            owner.with(move || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    match load_sandboxed_components().await {
                        Ok(loaded) if generation.try_get_untracked() == Some(observed) => {
                            if editing
                                .core
                                .try_get_untracked()
                                .is_some_and(|core| core.generation() == editor_generation)
                                && let Some(known) = editing.known.get_untracked()
                                && let Some(remote) = loaded
                                    .components
                                    .iter()
                                    .find(|record| record.name == known.name)
                                && remote.editing_revision > known.editing_revision
                            {
                                editing.latest.try_set(Some(remote.clone()));
                                editing.core.try_update(|core| {
                                    core.observe_remote(remote.editing_revision);
                                });
                            }
                            components.try_set(loaded.components);
                        }
                        Err(failure) if generation.try_get_untracked() == Some(observed) => {
                            error.try_set(Some(failure));
                        }
                        Ok(_) | Err(_) => {}
                    }
                    if generation.try_get_untracked() == Some(observed) {
                        loading.try_set(false);
                    }
                })
            });
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (generation, components, worker_owner, editing);
        loading.set(false);
        error.set(Some(ApiError::Unavailable));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_json_requires_an_object_and_starter_contract_is_valid() {
        assert!(parse_object(STARTER_SCHEMA).is_some());
        assert!(parse_object(STARTER_SAMPLE).is_some());
        for invalid in ["", "[]", "null", "true", "{"] {
            assert!(parse_object(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn saved_row_identity_changes_with_draft_and_publication_state() {
        let mut component = SandboxedComponentRecord {
            editing_revision: 1,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            name: "custom_card".to_owned(),
            title: "Card".to_owned(),
            draft_description: "draft".to_owned(),
            draft_html: "<p>draft</p>".to_owned(),
            draft_css: "p{}".to_owned(),
            draft_js_functions: "document.body.dataset.ready='1';".to_owned(),
            draft_argument_schema: BTreeMap::new(),
            published_html: None,
            published_css: None,
            published_js_functions: None,
            published_argument_schema: None,
            sample_arguments: BTreeMap::new(),
            revision: 0,
            published: false,
            published_at: None,
            authored_by: Some("admin".to_owned()),
            has_unpublished_changes: false,
        };
        let draft_key = sandboxed_component_row_key(&component);
        component.published = true;
        component.revision = 1;
        component.published_html = Some(component.draft_html.clone());
        component.published_css = Some(component.draft_css.clone());
        component.published_js_functions = Some(component.draft_js_functions.clone());
        component.published_argument_schema = Some(BTreeMap::new());
        assert_ne!(sandboxed_component_row_key(&component), draft_key);
    }
}
