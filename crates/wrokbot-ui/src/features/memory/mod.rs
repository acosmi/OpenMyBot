//! Owner-scoped native memory controls and `/settings/memory` route.

#![cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]

pub(crate) mod remember;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemoryReadIssue {
    None,
    Failed,
    ReconciliationRequired,
}

use std::collections::BTreeSet;

use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::memory::CorrectMemory;
use openbot_contracts::memory::{
    MemoryKind, MemoryMutation, MemoryOrigin, MemoryPage, MemoryRecord, MemoryScope,
    MemorySensitivity, MemoryStatus,
};
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
use crate::api::{
    correct_memory_record, list_memories, load_memory_control, mutate_memory_record,
    save_memory_control,
};
use crate::features::layout::{PageEmpty, PageHeader, PageRows, PageSection, PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Badge, BadgeTone, Button, ButtonSize, ButtonVariant, Dialog, DialogBody, DialogClose,
    DialogContent, DialogFooter, Field, Input, InputType, Notice, NoticeTone, Switch, Textarea,
    Timestamp,
};

/// Native memory list and control destination required by v3 §3.1 item 7.
#[component]
pub fn MemoryPage() -> impl IntoView {
    let i18n = use_i18n();
    let memories = RwSignal::new(Vec::<MemoryRecord>::new());
    let next_cursor = RwSignal::new(None::<String>);
    let writes_enabled = RwSignal::new(true);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(MemoryReadIssue::None);
    let control_pending = RwSignal::new(false);
    let control_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::Memory,
        move || "$control".into(),
    );
    let control_error = RwSignal::new(false);
    let action_error = RwSignal::new(false);
    let pending_ids = RwSignal::new(BTreeSet::<String>::new());
    let loading_more = RwSignal::new(false);
    let page_owner = StoredValue::new(Owner::current());
    let reload_generation = RwSignal::new(0_u64);
    let reload_focus = RwSignal::new(None::<String>);
    let correct_open = RwSignal::new(false);
    let correcting = RwSignal::new(None::<MemoryRecord>);
    let correction = RwSignal::new(String::new());
    let correction_invalid = RwSignal::new(false);
    let correction_return_focus = RwSignal::new(None::<String>);
    let correction_generation = RwSignal::new(0_u64);

    install_memory_loader(
        reload_generation,
        memories,
        next_cursor,
        writes_enabled,
        (loading, loading_more),
        load_error,
        reload_focus,
    );

    let retry = move |_| {
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
    };
    let save_control = UnsyncCallback::new(move |next: bool| {
        if control_pending.get_untracked() {
            writes_enabled.set(!next);
            return;
        }
        control_pending.set(true);
        control_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            match save_memory_control(next).await {
                Ok(control) => writes_enabled.set(control.writes_enabled),
                Err(
                    crate::api::ApiError::ReconciliationRequired
                    | crate::api::ApiError::Network
                    | crate::api::ApiError::InvalidResponse
                    | crate::api::ApiError::Server,
                ) => {
                    load_error.set(MemoryReadIssue::ReconciliationRequired);
                }
                Err(_) => {
                    writes_enabled.set(!next);
                    control_error.set(true);
                }
            }
            control_pending.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            writes_enabled.set(!next);
            control_error.set(true);
            control_pending.set(false);
        }
    });
    let load_more = move |_| {
        let Some(cursor) = next_cursor.get_untracked() else {
            return;
        };
        if loading_more.get_untracked() {
            return;
        }
        loading_more.set(true);
        action_error.set(false);
        let generation = reload_generation.get_untracked();
        #[cfg(target_arch = "wasm32")]
        if let Some(owner) = page_owner.get_value() {
            owner.with(|| {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let result = list_memories(Some(&cursor)).await;
                    if reload_generation.try_get_untracked() != Some(generation) {
                        return;
                    }
                    match result {
                        Ok(page) => match append_page(&memories.get_untracked(), page) {
                            Ok((rows, cursor)) => {
                                memories.set(rows);
                                next_cursor.set(cursor);
                            }
                            Err(()) => reload_generation
                                .update(|generation| *generation = generation.saturating_add(1)),
                        },
                        Err(_) => action_error.set(true),
                    }
                    loading_more.set(false);
                })
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (cursor, generation, page_owner);
            loading_more.set(false);
            action_error.set(true);
        }
    };
    let open_correction = UnsyncCallback::new(move |record: MemoryRecord| {
        correction_generation.update(|generation| *generation = generation.saturating_add(1));
        correction_return_focus.set(Some(correct_trigger_id(&record.memory_id)));
        correction.set(record.content.clone().unwrap_or_default());
        correction_invalid.set(false);
        correcting.set(Some(record));
        correct_open.set(true);
    });
    let close_correction = UnsyncCallback::new(move |_| {
        correction_generation.update(|generation| *generation = generation.saturating_add(1));
        dismiss_correction(
            correct_open,
            correcting,
            correction,
            correction_invalid,
            correction_return_focus,
            true,
        );
    });
    let save_correction = move |_| {
        let text = correction.get_untracked();
        if text.is_empty() {
            correction_invalid.set(true);
            return;
        }
        let Some(record) = correcting.get_untracked() else {
            return;
        };
        let memory_id = record.memory_id.clone();
        let editor_generation = correction_generation.get_untracked();
        if pending_ids.get_untracked().contains(&memory_id) {
            return;
        }
        pending_ids.update(|ids| {
            ids.insert(memory_id.clone());
        });
        action_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = correct_memory_record(
                &memory_id,
                CorrectMemory {
                    content: text,
                    tags: record.tags,
                    sensitivity: record.sensitivity,
                    expires_at: record.expires_at,
                },
            )
            .await;
            pending_ids.update(|ids| {
                ids.remove(&memory_id);
            });
            let same_editor = correction_generation.get_untracked() == editor_generation
                && correcting.with_untracked(|selected| {
                    selected
                        .as_ref()
                        .is_some_and(|record| record.memory_id == memory_id)
                });
            match result {
                Ok(replacement) => {
                    if same_editor {
                        dismiss_correction(
                            correct_open,
                            correcting,
                            correction,
                            correction_invalid,
                            correction_return_focus,
                            false,
                        );
                        reload_focus.set(Some(memory_dom_id(&replacement.memory_id)));
                    }
                    reload_generation
                        .update(|generation| *generation = generation.saturating_add(1));
                }
                Err(
                    crate::api::ApiError::ReconciliationRequired
                    | crate::api::ApiError::Network
                    | crate::api::ApiError::InvalidResponse
                    | crate::api::ApiError::Server,
                ) => {
                    if same_editor {
                        dismiss_correction(
                            correct_open,
                            correcting,
                            correction,
                            correction_invalid,
                            correction_return_focus,
                            false,
                        );
                    }
                    load_error.set(MemoryReadIssue::ReconciliationRequired);
                }
                Err(_) => action_error.set(true),
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = editor_generation;
            pending_ids.update(|ids| {
                ids.remove(&memory_id);
            });
            action_error.set(true);
        }
    };
    let mutate = UnsyncCallback::new(move |(memory_id, mutation): (String, MemoryMutation)| {
        if pending_ids.get_untracked().contains(&memory_id) {
            return;
        }
        pending_ids.update(|ids| {
            ids.insert(memory_id.clone());
        });
        action_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = mutate_memory_record(&memory_id, mutation).await;
            pending_ids.update(|ids| {
                ids.remove(&memory_id);
            });
            match result {
                Ok(record) => {
                    reload_focus.set(Some(memory_dom_id(&record.memory_id)));
                    reload_generation
                        .update(|generation| *generation = generation.saturating_add(1));
                }
                Err(
                    crate::api::ApiError::ReconciliationRequired
                    | crate::api::ApiError::Network
                    | crate::api::ApiError::InvalidResponse
                    | crate::api::ApiError::Server,
                ) => {
                    load_error.set(MemoryReadIssue::ReconciliationRequired);
                }
                Err(_) => action_error.set(true),
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = mutation;
            pending_ids.update(|ids| {
                ids.remove(&memory_id);
            });
            action_error.set(true);
        }
    });

    // Deleting erases the content, so it is confirmed first; forbidding is not.
    let delete_open = RwSignal::new(false);
    let delete_target = RwSignal::new(None::<String>);
    let delete_excerpt = RwSignal::new(None::<String>);
    let request_mutation =
        UnsyncCallback::new(move |(memory_id, mutation): (String, MemoryMutation)| {
            if matches!(mutation, MemoryMutation::Delete) {
                delete_excerpt.set(memories.with_untracked(|rows| {
                    rows.iter()
                        .find(|row| row.memory_id == memory_id)
                        .and_then(|row| row.content.as_deref().map(memory_excerpt))
                }));
                delete_target.set(Some(memory_id));
                delete_open.set(true);
            } else {
                mutate.run((memory_id, mutation));
            }
        });
    let close_delete = UnsyncCallback::new(move |_| delete_target.set(None));
    let confirm_delete = move |_| {
        if let Some(memory_id) = delete_target.get_untracked() {
            mutate.run((memory_id, MemoryMutation::Delete));
        }
        delete_target.set(None);
        delete_open.set(false);
    };

    view! {
        <PageShell width=PageWidth::Content>
            <div class="ob-memory-page">
                <PageHeader
                    heading_id="memory-page-title"
                    title=move || t_string!(i18n, memory.title).to_owned()
                    description=move || t_string!(i18n, memory.description).to_owned()
                />
                <MemorySearch
                    reload_generation
                    pending_ids
                    on_correct=open_correction
                    on_mutate=request_mutation
                />
                <Show when=move || loading.get()>
                    <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
                </Show>
                <Show when=move || load_error.get() != MemoryReadIssue::None>
                    <Notice tone=NoticeTone::Error>
                        <span>{move || if load_error.get() == MemoryReadIssue::ReconciliationRequired { t_string!(i18n, memory.reconciliation_required).to_owned() } else { t_string!(i18n, memory.load_error).to_owned() }}</span>
                        <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry>
                            {move || t!(i18n, models.refresh)}
                        </Button>
                    </Notice>
                </Show>
                <Show when=move || !loading.get() && load_error.get() == MemoryReadIssue::None>
                    <PageSection
                        heading_id="memory-control-title"
                        title=move || t_string!(i18n, memory.control_title).to_owned()
                    >
                        <div class="ob-memory-control">
                            <Field
                                control_id="memory-writes-enabled"
                                label=move || t_string!(i18n, memory.control_label).to_owned()
                                description=move || t_string!(i18n, memory.control_description).to_owned()
                                disabled=Signal::derive(move || control_pending.get() || control_lock.get())
                            >
                                <Switch
                                    checked=writes_enabled
                                    on_change=save_control
                                />
                            </Field>
                        </div>
                        <Show when=move || control_error.get()>
                            <Notice tone=NoticeTone::Error>{move || t!(i18n, memory.control_error)}</Notice>
                        </Show>
                    </PageSection>
                    <PageSection
                        heading_id="memory-entries-title"
                        title=move || t_string!(i18n, memory.entry).to_owned()
                    >
                        <Show
                            when=move || !memories.get().is_empty()
                            fallback=move || view! {
                                <PageEmpty>{move || t!(i18n, memory.empty_body)}</PageEmpty>
                            }
                        >
                            <PageRows>
                                <For
                                    each=move || memories.get()
                                    key=|record| record.memory_id.clone()
                                    children=move |record| view! {
                                        <MemoryRow
                                            record
                                            writes_enabled=Signal::derive(move || writes_enabled.get())
                                            pending_ids
                                            on_correct=open_correction
                                            on_mutate=request_mutation
                                        />
                                    }
                                />
                            </PageRows>
                        </Show>
                        <Show when=move || next_cursor.get().is_some()>
                            <Button
                                variant=ButtonVariant::Ghost
                                size=ButtonSize::Medium
                                loading=loading_more
                                on_activate=load_more
                            >
                                {move || t!(i18n, memory.load_more)}
                            </Button>
                        </Show>
                    </PageSection>
                    <Show when=move || action_error.get()>
                        <Notice tone=NoticeTone::Error>{move || t!(i18n, memory.action_error)}</Notice>
                    </Show>
                </Show>
            </div>
        </PageShell>
        <Dialog id="memory-delete-dialog" open=delete_open on_close=close_delete>
            <DialogContent
                title=move || t_string!(i18n, memory.delete_title).to_owned()
                description=move || t_string!(i18n, memory.delete_description).to_owned()
            >
                <Show when=move || delete_excerpt.with(Option::is_some)>
                    <DialogBody>
                        <p class="ob-memory-content">{move || delete_excerpt.get()}</p>
                    </DialogBody>
                </Show>
                <DialogFooter>
                    <DialogClose id="memory-delete-cancel">
                        {move || t!(i18n, common.cancel)}
                    </DialogClose>
                    <Button
                        id="memory-delete-confirm"
                        variant=ButtonVariant::DangerText
                        size=ButtonSize::Medium
                        on_activate=confirm_delete
                    >
                        {move || t!(i18n, memory.delete_entry)}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
        <Dialog id="memory-correct-dialog" open=correct_open on_close=close_correction>
            <DialogContent
                title=move || t_string!(i18n, memory.correct_title).to_owned()
                description=move || t_string!(i18n, memory.correct_description).to_owned()
            >
                <DialogBody>
                    <Field
                        control_id="memory-correction-content"
                        label=move || t_string!(i18n, memory.correct_content_label).to_owned()
                        error=move || t_string!(i18n, memory.correct_empty).to_owned()
                        invalid=Signal::derive(move || correction_invalid.get())
                    >
                        <Textarea value=correction />
                    </Field>
                </DialogBody>
                <DialogFooter>
                    <DialogClose id="memory-correction-cancel">
                        {move || t!(i18n, common.cancel)}
                    </DialogClose>
                    <Button
                        id="memory-correction-save"
                        disabled=crate::configuration_writes::resource_lock(crate::configuration_writes::ConfigurationKind::Memory, move || correcting.get().map(|record| record.memory_id).unwrap_or_default())
                        variant=ButtonVariant::Primary
                        size=ButtonSize::Medium
                        loading=Signal::derive(move || {
                            correcting.get().is_some_and(|record| {
                                pending_ids.get().contains(&record.memory_id)
                            })
                        })
                        on_activate=save_correction
                    >
                        {move || t!(i18n, memory.correct_save)}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    }
}

/// This destination has no authoritative Bot/Thread context. Recall uses only the current
/// actor's User scope; the complete owner list and its management actions remain separate.
#[component]
fn MemorySearch(
    reload_generation: RwSignal<u64>,
    pending_ids: RwSignal<BTreeSet<String>>,
    on_correct: UnsyncCallback<MemoryRecord>,
    on_mutate: UnsyncCallback<(String, MemoryMutation)>,
) -> impl IntoView {
    let i18n = use_i18n();
    let query = RwSignal::new(String::new());
    let generation = RwSignal::new(0_u64);
    let pending = RwSignal::new(false);
    let failed = RwSignal::new(false);
    let invalid = RwSignal::new(false);
    let results = RwSignal::new(None::<Vec<MemoryRecord>>);
    let read_owner = StoredValue::new(Owner::current());

    // Typing, a known mutation or explicit list reload invalidates the old read projection.
    // It never reissues recall and never clears the existing configuration write barrier.
    Effect::new(move |_| {
        let _ = query.get();
        let _ = reload_generation.get();
        generation.update(|value| *value = value.saturating_add(1));
        pending.set(false);
        failed.set(false);
        invalid.set(false);
        results.set(None);
    });
    let search = UnsyncCallback::new(move |()| {
        if pending.get_untracked() {
            return;
        }
        let submitted = query.get_untracked();
        if submitted.trim().is_empty() || submitted.len() > 4096 || submitted.contains('\0') {
            invalid.set(true);
            return;
        }
        generation.update(|value| *value = value.saturating_add(1));
        let expected_generation = generation.get_untracked();
        pending.set(true);
        failed.set(false);
        invalid.set(false);
        results.set(None);
        #[cfg(target_arch = "wasm32")]
        if let Some(owner) = read_owner.get_value() {
            owner.with(|| {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let outcome = crate::api::recall_user_memories(&submitted).await;
                    if generation.try_get_untracked() != Some(expected_generation) {
                        return;
                    }
                    match outcome {
                        Ok(recalled) => results.set(Some(recalled.memories)),
                        Err(_) => failed.set(true),
                    }
                    pending.set(false);
                })
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (submitted, expected_generation, read_owner);
            failed.set(true);
            pending.set(false);
        }
    });

    view! {
        <PageSection
            heading_id="memory-search-title"
            title=move || t_string!(i18n, memory.search_placeholder).to_owned()
        >
            <Field
                control_id="memory-search-query"
                label=move || t_string!(i18n, memory.search_placeholder).to_owned()
                description=move || t_string!(i18n, memory.search_scope_help).to_owned()
                invalid=Signal::derive(move || invalid.get())
                error=move || t_string!(i18n, memory.search_invalid).to_owned()
            >
                <Input value=query input_type=InputType::Search on_submit=search />
            </Field>
            <div class="ob-memory-actions">
                <Button id="memory-search-submit" size=ButtonSize::Small loading=pending
                    on_activate=move |_| search.run(())>
                    {move || if failed.get() { t_string!(i18n, common.retry).to_owned() } else { t_string!(i18n, memory.search_placeholder).to_owned() }}
                </Button>
                <Button id="memory-search-clear" size=ButtonSize::Small variant=ButtonVariant::Ghost
                    on_activate=move |_| query.set(String::new())>
                    {move || t!(i18n, common.clear)}
                </Button>
            </div>
            <Show when=move || failed.get()>
                <Notice tone=NoticeTone::Error>{move || t!(i18n, memory.load_error)}</Notice>
            </Show>
            <Show when=move || results.get().is_some_and(|records| records.is_empty())>
                <PageEmpty>{move || t!(i18n, common.no_results)}</PageEmpty>
            </Show>
            <div id="memory-search-results" aria-live="polite" aria-busy=move || if pending.get() { "true" } else { "false" }>
                <PageRows>
                    <For each=move || results.get().unwrap_or_default()
                        key=|record| record.memory_id.clone()
                        children=move |record| view! {
                            <MemoryRow record read_only=true
                                writes_enabled=Signal::derive(|| false)
                                pending_ids on_correct on_mutate />
                        }
                    />
                </PageRows>
            </div>
        </PageSection>
    }
}

#[component]
fn MemoryRow(
    record: MemoryRecord,
    writes_enabled: Signal<bool>,
    pending_ids: RwSignal<BTreeSet<String>>,
    on_correct: UnsyncCallback<MemoryRecord>,
    on_mutate: UnsyncCallback<(String, MemoryMutation)>,
    #[prop(optional)] read_only: bool,
) -> impl IntoView {
    let i18n = use_i18n();
    let memory_id = record.memory_id.clone();
    let correct_record = StoredValue::new(record.clone());
    let forbid_id = StoredValue::new(memory_id.clone());
    let delete_id = StoredValue::new(memory_id.clone());
    let busy_id = memory_id.clone();
    let lock_id = StoredValue::new(memory_id.clone());
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::Memory,
        move || lock_id.get_value(),
    );
    let busy = Signal::derive(move || pending_ids.get().contains(&busy_id) || write_lock.get());
    let excerpt = StoredValue::new(record.content.as_deref().map(memory_excerpt));
    let excerpt_label = move || {
        excerpt
            .get_value()
            .unwrap_or_else(|| t_string!(i18n, memory.content_erased).to_owned())
    };
    let correct_label =
        move || t_string!(i18n, memory.correct_label, memory = excerpt_label()).to_owned();
    let forbid_label =
        move || t_string!(i18n, memory.forbid_label, memory = excerpt_label()).to_owned();
    let delete_label =
        move || t_string!(i18n, memory.delete_label, memory = excerpt_label()).to_owned();
    let show_correct = record.status == MemoryStatus::Active && record.content.is_some();
    let show_forbid = !matches!(
        record.status,
        MemoryStatus::Forbidden | MemoryStatus::Deleted
    );
    let show_delete = record.status != MemoryStatus::Deleted;
    let content = record.content.clone();
    let scope = record.scope.clone();
    let tags = StoredValue::new(record.tags.clone());
    let source = StoredValue::new(record.source.clone());
    let created_at = record.created_at;
    let status = record.status;
    let kind = record.memory_kind;
    let sensitivity = record.sensitivity;
    let origin = record.origin;
    let dom_id = if read_only {
        format!("recall-{}", memory_dom_id(&memory_id))
    } else {
        memory_dom_id(&memory_id)
    };
    let correct_id = correct_trigger_id(&memory_id);
    view! {
        <article id=dom_id class="ob-memory-row" data-memory-status=status_name(status)
            data-memory-readonly=read_only.then_some("true") tabindex="-1">
            <div class="ob-memory-row-header">
                <Badge tone=status_tone(status)>{move || status_label(i18n, status)}</Badge>
                <span>{move || kind_label(i18n, kind)}</span>
                <span>{move || sensitivity_label(i18n, sensitivity)}</span>
            </div>
            <p class="ob-memory-content">
                {move || content.clone().unwrap_or_else(|| t_string!(i18n, memory.content_erased).to_owned())}
            </p>
            <p class="ob-memory-scope">{move || scope_label(i18n, &scope)}</p>
            <div class="ob-memory-provenance">
                <span>{move || t!(i18n, memory.created)} " " <Timestamp at=created_at /></span>
                <span>{move || t_string!(i18n, memory.origin, value = origin_label(i18n, origin)).to_owned()}</span>
                <Show when=move || source.get_value().is_some()>
                    {move || source.get_value().map(|source| t_string!(
                        i18n,
                        memory.source_detail,
                        thread = source.thread_id.as_str(),
                        message = source.message_id.as_str(),
                    ).to_owned())}
                </Show>
            </div>
            <Show when=move || !tags.get_value().is_empty()>
                <ul class="ob-memory-tags" aria-label=move || t_string!(i18n, common.optional).to_owned()>
                    <For
                        each=move || tags.get_value()
                        key=|tag| tag.clone()
                        children=move |tag| view! { <li>{tag}</li> }
                    />
                </ul>
            </Show>
            <div class="ob-memory-actions">
                <Show when=move || !read_only && show_correct>
                    <Button
                        id=correct_id.clone()
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        aria_label=correct_label
                        disabled=Signal::derive(move || busy.get() || !writes_enabled.get())
                        on_activate=move |_| on_correct.run(correct_record.get_value())
                    >{move || t!(i18n, memory.correct_entry)}</Button>
                </Show>
                <Show when=move || !read_only && show_forbid>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        aria_label=forbid_label
                        disabled=busy
                        on_activate=move |_| on_mutate.run((forbid_id.get_value(), MemoryMutation::Forbid))
                    >{move || t!(i18n, memory.forbid_entry)}</Button>
                </Show>
                <Show when=move || !read_only && show_delete>
                    <Button
                        variant=ButtonVariant::DangerText
                        size=ButtonSize::Small
                        aria_label=delete_label
                        disabled=busy
                        on_activate=move |_| on_mutate.run((delete_id.get_value(), MemoryMutation::Delete))
                    >{move || t!(i18n, memory.delete_entry)}</Button>
                </Show>
            </div>
        </article>
    }
}

fn install_memory_loader(
    reload_generation: RwSignal<u64>,
    memories: RwSignal<Vec<MemoryRecord>>,
    next_cursor: RwSignal<Option<String>>,
    writes_enabled: RwSignal<bool>,
    loading: (RwSignal<bool>, RwSignal<bool>),
    load_error: RwSignal<MemoryReadIssue>,
    reload_focus: RwSignal<Option<String>>,
) {
    let (loading, loading_more) = loading;
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let generation = reload_generation.get();
        loading_more.set(false);
        loading.set(true);
        load_error.set(MemoryReadIssue::None);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let control = load_memory_control().await;
            let page = list_memories(None).await;
            if reload_generation.get_untracked() != generation {
                return;
            }
            match (control, page) {
                (Ok(control), Ok(page)) => {
                    writes_enabled.set(control.writes_enabled);
                    memories.set(page.memories);
                    next_cursor.set(page.next_cursor);
                    restore_focus(reload_focus.get_untracked());
                    reload_focus.set(None);
                }
                _ => {
                    memories.set(Vec::new());
                    next_cursor.set(None);
                    load_error.set(MemoryReadIssue::Failed);
                }
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        loading.set(false);
        load_error.set(MemoryReadIssue::Failed);
        let _ = (
            reload_generation,
            memories,
            next_cursor,
            writes_enabled,
            reload_focus,
            loading_more,
        );
    }
}

fn append_page(
    existing: &[MemoryRecord],
    page: MemoryPage,
) -> Result<(Vec<MemoryRecord>, Option<String>), ()> {
    let mut ids = BTreeSet::new();
    let mut rows = Vec::with_capacity(existing.len() + page.memories.len());
    for record in existing.iter().chain(&page.memories) {
        if !ids.insert(record.memory_id.clone()) {
            return Err(());
        }
        rows.push(record.clone());
    }
    Ok((rows, page.next_cursor))
}

fn memory_excerpt(raw: &str) -> String {
    let mut excerpt = raw.chars().take(80).collect::<String>();
    if raw.chars().count() > 80 {
        excerpt.push('…');
    }
    excerpt
}

fn correct_trigger_id(memory_id: &str) -> String {
    format!("{}-correct", memory_dom_id(memory_id))
}

fn dismiss_correction(
    correct_open: RwSignal<bool>,
    correcting: RwSignal<Option<MemoryRecord>>,
    correction: RwSignal<String>,
    correction_invalid: RwSignal<bool>,
    correction_return_focus: RwSignal<Option<String>>,
    return_to_trigger: bool,
) {
    correct_open.set(false);
    correcting.set(None);
    correction.set(String::new());
    correction_invalid.set(false);
    if return_to_trigger {
        restore_focus(correction_return_focus.get_untracked());
    }
    correction_return_focus.set(None);
}

fn restore_focus(id: Option<String>) {
    #[cfg(target_arch = "wasm32")]
    if let Some(id) = id {
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            use wasm_bindgen::JsCast;

            leptos::task::tick().await;
            if let Some(element) = web_sys::window()
                .and_then(|window| window.document())
                .and_then(|document| document.get_element_by_id(&id))
                .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
            {
                _ = element.focus();
            }
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = id;
}

fn memory_dom_id(memory_id: &str) -> String {
    let digest = Sha256::digest(memory_id.as_bytes());
    let mut encoded = String::with_capacity(23);
    encoded.push_str("memory-");
    for byte in digest.iter().take(8) {
        use core::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String formatting is infallible");
    }
    encoded
}

const fn status_name(status: MemoryStatus) -> &'static str {
    match status {
        MemoryStatus::Active => "active",
        MemoryStatus::Superseded => "superseded",
        MemoryStatus::Forbidden => "forbidden",
        MemoryStatus::Deleted => "deleted",
    }
}

const fn status_tone(status: MemoryStatus) -> BadgeTone {
    match status {
        MemoryStatus::Active => BadgeTone::Success,
        MemoryStatus::Superseded => BadgeTone::Info,
        MemoryStatus::Forbidden => BadgeTone::Caution,
        MemoryStatus::Deleted => BadgeTone::Danger,
    }
}

fn status_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    status: MemoryStatus,
) -> String {
    match status {
        MemoryStatus::Active => t_string!(i18n, memory.status_active).to_owned(),
        MemoryStatus::Superseded => t_string!(i18n, memory.status_superseded).to_owned(),
        MemoryStatus::Forbidden => t_string!(i18n, memory.status_forbidden).to_owned(),
        MemoryStatus::Deleted => t_string!(i18n, memory.status_deleted).to_owned(),
    }
}

fn kind_label(i18n: leptos_i18n::I18nContext<crate::i18n::Locale>, kind: MemoryKind) -> String {
    match kind {
        MemoryKind::Preference => t_string!(i18n, memory.kind_preference).to_owned(),
        MemoryKind::Fact => t_string!(i18n, memory.kind_fact).to_owned(),
    }
}

fn sensitivity_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    sensitivity: MemorySensitivity,
) -> String {
    match sensitivity {
        MemorySensitivity::Normal => t_string!(i18n, memory.sensitivity_normal).to_owned(),
        MemorySensitivity::Sensitive => t_string!(i18n, memory.sensitivity_sensitive).to_owned(),
    }
}

fn origin_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    origin: MemoryOrigin,
) -> String {
    match origin {
        MemoryOrigin::UserAction => t_string!(i18n, memory.origin_user_action).to_owned(),
        MemoryOrigin::RememberTool => t_string!(i18n, memory.origin_remember_tool).to_owned(),
        MemoryOrigin::VerifiedImport => t_string!(i18n, memory.origin_verified_import).to_owned(),
    }
}

fn scope_label(i18n: leptos_i18n::I18nContext<crate::i18n::Locale>, scope: &MemoryScope) -> String {
    match scope {
        MemoryScope::User => t_string!(i18n, memory.scope_user).to_owned(),
        MemoryScope::Bot { bot_id } => {
            t_string!(i18n, memory.scope_bot, id = bot_id.as_str()).to_owned()
        }
        MemoryScope::Thread { thread_id } => {
            t_string!(i18n, memory.scope_thread, id = thread_id.as_str()).to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use openbot_contracts::memory::MemorySensitivity;
    use time::OffsetDateTime;

    use super::*;

    fn record(id: &str, content: Option<&str>, status: MemoryStatus) -> MemoryRecord {
        MemoryRecord {
            memory_id: id.to_owned(),
            owner_user_id: "actor".to_owned(),
            scope: MemoryScope::User,
            memory_kind: MemoryKind::Preference,
            content: content.map(str::to_owned),
            tags: Vec::new(),
            sensitivity: MemorySensitivity::Normal,
            source: None,
            source_run_id: None,
            source_authorization_snapshot: None,
            origin: MemoryOrigin::UserAction,
            created_by: "actor".to_owned(),
            supersedes_id: None,
            status,
            expires_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn append_rejects_duplicate_ids_and_preserves_keyset_order() {
        let existing = [record("m-2", Some("two"), MemoryStatus::Active)];
        let page = MemoryPage {
            memories: vec![record("m-1", Some("one"), MemoryStatus::Active)],
            next_cursor: Some("m-1".to_owned()),
        };
        let (rows, cursor) = append_page(&existing, page).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.memory_id.as_str())
                .collect::<Vec<_>>(),
            ["m-2", "m-1"]
        );
        assert_eq!(cursor.as_deref(), Some("m-1"));
        assert!(
            append_page(
                &existing,
                MemoryPage {
                    memories: existing.to_vec(),
                    next_cursor: None,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn dom_identity_excerpt_and_status_domains_are_bounded() {
        assert_eq!(memory_dom_id("memory-1").len(), 23);
        assert_eq!(memory_dom_id("memory-1"), memory_dom_id("memory-1"));
        assert_ne!(memory_dom_id("memory-1"), memory_dom_id("memory-2"));
        let long = "x".repeat(90);
        assert_eq!(memory_excerpt(&long).chars().count(), 81);
        assert_eq!(correct_trigger_id("memory-1").len(), 31);
        assert_eq!(status_name(MemoryStatus::Forbidden), "forbidden");
        assert_eq!(status_tone(MemoryStatus::Deleted), BadgeTone::Danger);
    }
}
