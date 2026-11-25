//! Explicit, source-bound message memory review. Writes outlive page unmount and are never retried automatically.
use crate::{
    api::ApiError,
    i18n::{t, t_string, use_i18n},
    primitives::{
        Button, ButtonVariant, Dialog, DialogBody, DialogClose, DialogContent, DialogFooter, Field,
        Notice, NoticePresentation, NoticeTone, Switch, Textarea,
    },
};
use leptos::prelude::*;
use openbot_contracts::{
    ids::ThreadId,
    memory::{MemoryKind, MemoryScope, MemorySensitivity, MemorySource, RememberMemory},
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RememberStatus {
    Pending,
    Saved,
    Unknown,
}
#[derive(Clone, Copy)]
pub(crate) struct RememberActions {
    pub entries: RwSignal<BTreeMap<(String, String), RememberStatus>>,
}
impl RememberActions {
    pub fn new() -> Self {
        Self {
            entries: RwSignal::new(BTreeMap::new()),
        }
    }
    fn launch(self, input: RememberMemory, finished: impl FnOnce(Result<(), ApiError>) + 'static) {
        let Some(source) = &input.source else {
            return;
        };
        let key = (
            source.thread_id.as_str().to_owned(),
            source.message_id.clone(),
        );
        if self
            .entries
            .with_untracked(|entries| entries.contains_key(&key))
        {
            return;
        }
        self.entries.update(|entries| {
            entries.insert(key.clone(), RememberStatus::Pending);
        });
        leptos::task::spawn_local(async move {
            let result = crate::api::remember_memory_record(input).await.map(|_| ());
            self.complete(key, result, finished);
        });
    }
    fn complete(
        self,
        key: (String, String),
        result: Result<(), ApiError>,
        finished: impl FnOnce(Result<(), ApiError>),
    ) {
        if self.entries.try_get_untracked().is_none() {
            return;
        }
        self.entries.try_update(|entries| match result {
            Ok(()) => {
                entries.insert(key, RememberStatus::Saved);
            }
            Err(ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound) => {
                entries.remove(&key);
            }
            Err(_) => {
                entries.insert(key, RememberStatus::Unknown);
            }
        });
        finished(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn late_remember_completion_cannot_mark_the_next_accounts_message() {
        for result in [Ok(()), Err(ApiError::ReconciliationRequired)] {
            let owner = Owner::new();
            let old = owner.with(RememberActions::new);
            let key = ("same-thread".into(), "same-message".into());
            old.entries.update(|entries| {
                entries.insert(key.clone(), RememberStatus::Pending);
            });
            owner.cleanup();
            Owner::new().with(|| {
                let new = RememberActions::new();
                let invoked = std::cell::Cell::new(false);
                old.complete(key, result, |_| invoked.set(true));
                assert!(!invoked.get());
                assert!(new.entries.get_untracked().is_empty());
            });
        }
    }
}

#[derive(Clone)]
pub(crate) struct RememberTarget {
    pub thread: ThreadId,
    pub message_id: String,
    pub content: String,
}
#[derive(Clone, Copy)]
pub(crate) struct RememberReview {
    target: RwSignal<Option<RememberTarget>>,
    open: RwSignal<bool>,
    content: RwSignal<String>,
    preference: RwSignal<bool>,
    everywhere: RwSignal<bool>,
    sensitive: RwSignal<bool>,
    loading: RwSignal<bool>,
    enabled: RwSignal<bool>,
    failed: RwSignal<bool>,
    serial: RwSignal<u64>,
}
impl RememberReview {
    pub fn new() -> Self {
        Self {
            target: RwSignal::new(None),
            open: RwSignal::new(false),
            content: RwSignal::new(String::new()),
            preference: RwSignal::new(false),
            everywhere: RwSignal::new(false),
            sensitive: RwSignal::new(false),
            loading: RwSignal::new(false),
            enabled: RwSignal::new(false),
            failed: RwSignal::new(false),
            serial: RwSignal::new(0),
        }
    }
    pub fn review(self, target: RememberTarget) {
        self.content.set(target.content.clone());
        self.target.set(Some(target));
        self.preference.set(false);
        self.everywhere.set(false);
        self.sensitive.set(false);
        self.failed.set(false);
        self.enabled.set(false);
        self.loading.set(true);
        self.open.set(true);
        let serial = self.serial.get_untracked().saturating_add(1);
        self.serial.set(serial);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = crate::api::load_memory_control().await;
            if self.serial.try_get_untracked() != Some(serial) {
                return;
            }
            match result {
                Ok(control) => self.enabled.set(control.writes_enabled),
                Err(_) => self.failed.set(true),
            }
            self.loading.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.loading.set(false);
            self.failed.set(true);
        }
    }
}

#[component]
pub(crate) fn RememberDialog(review: RememberReview) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<RememberActions>();
    let status = Signal::derive(move || {
        review.target.get().and_then(|target| {
            actions
                .entries
                .get()
                .get(&(target.thread.as_str().to_owned(), target.message_id))
                .copied()
        })
    });
    let disabled = Signal::derive(move || {
        review.loading.get() || !review.enabled.get() || status.get().is_some()
    });
    let invalid = Signal::derive(move || {
        review.content.get().trim().is_empty()
            || review.content.get().len() > 64 * 1024
            || review.content.get().as_bytes().contains(&0)
    });
    let save = move |_| {
        if disabled.get_untracked() || invalid.get_untracked() {
            return;
        }
        let Some(target) = review.target.get_untracked() else {
            return;
        };
        let input = RememberMemory {
            memory_kind: if review.preference.get_untracked() {
                MemoryKind::Preference
            } else {
                MemoryKind::Fact
            },
            scope: if review.everywhere.get_untracked() {
                MemoryScope::User
            } else {
                MemoryScope::Thread {
                    thread_id: target.thread.clone(),
                }
            },
            content: review.content.get_untracked(),
            tags: Vec::new(),
            sensitivity: if review.sensitive.get_untracked() {
                MemorySensitivity::Sensitive
            } else {
                MemorySensitivity::Normal
            },
            source: Some(MemorySource {
                thread_id: target.thread,
                message_id: target.message_id,
            }),
            expires_at: None,
        };
        review.failed.set(false);
        let serial = review.serial.get_untracked();
        actions.launch(input, move |result| {
            if review.serial.try_get_untracked() == Some(serial) && result.is_err() {
                review.failed.try_set(true);
            }
        });
    };
    view! {
        <Dialog id="remember-message" open=review.open on_close=UnsyncCallback::new(move |_| { review.content.set(String::new()); review.target.set(None); review.serial.update(|n| *n = n.saturating_add(1)); })>
            <DialogContent title=move || t_string!(i18n, memory.remember_title).to_owned() description=move || t_string!(i18n, memory.remember_description).to_owned()>
                <DialogBody>
                    <Field control_id="remember-content" label=move || t_string!(i18n, memory.remember_content).to_owned()
                        invalid=invalid error=move || t_string!(i18n, memory.remember_invalid).to_owned()>
                        <Textarea value=review.content disabled=disabled/>
                    </Field>
                    <Field control_id="remember-preference" label=move || t_string!(i18n, memory.remember_preference).to_owned()>
                        <Switch checked=review.preference disabled=disabled/>
                    </Field>
                    <Field control_id="remember-everywhere" label=move || t_string!(i18n, memory.remember_everywhere).to_owned()>
                        <Switch checked=review.everywhere disabled=disabled/>
                    </Field>
                    <Field control_id="remember-sensitive" label=move || t_string!(i18n, memory.remember_sensitive).to_owned()>
                        <Switch checked=review.sensitive disabled=disabled/>
                    </Field>
                    <Show when=move || review.loading.get()><p role="status">{move || t!(i18n, common.loading)}</p></Show>
                    <Show when=move || !review.loading.get() && !review.enabled.get() && !review.failed.get()><Notice tone=NoticeTone::Caution presentation=NoticePresentation::Inline>{move || t!(i18n, memory.remember_disabled)}</Notice></Show>
                    <Show when=move || review.failed.get() || status.get() == Some(RememberStatus::Unknown)><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, memory.remember_error)}</Notice></Show>
                    <Show when=move || status.get() == Some(RememberStatus::Saved)><p role="status">{move || t!(i18n, memory.remember_saved)}</p></Show>
                    <a class="ob-plugin-link" href="/settings/memory">{move || t!(i18n, memory.remember_manage)}</a>
                </DialogBody>
                <DialogFooter>
                    <DialogClose>{move || t!(i18n, common.close)}</DialogClose>
                    <Button variant=ButtonVariant::Primary disabled=Signal::derive(move || disabled.get() || invalid.get()) loading=Signal::derive(move || status.get() == Some(RememberStatus::Pending)) on_activate=save>{move || t!(i18n, memory.remember_action)}</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    }
}
