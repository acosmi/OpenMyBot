//! Authenticated preference editing. Immediate appearance is separate from revision persistence.

use crate::{
    api::preference_cas::{self as api, CasError},
    editor_notice::EditorNotice,
    editor_runtime::{after, now_ms},
    i18n::{Locale, t, use_i18n},
    revision_editor::{Apply, AttemptToken, EditorCore, FailureClass, Phase},
};
use leptos::prelude::*;
use leptos_i18n::I18nContext;
use openbot_contracts::{
    revision::RevisionSnapshot,
    ui::{UiLocale, UiPreferences, UiTheme, UpdateUiPreferences},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PreferenceDraft {
    theme: Option<UiTheme>,
    locale: Option<UiLocale>,
}
impl PreferenceDraft {
    fn is_empty(self) -> bool {
        self.theme.is_none() && self.locale.is_none()
    }
    fn merge(&mut self, newer: Self) {
        self.theme = newer.theme.or(self.theme);
        self.locale = newer.locale.or(self.locale);
    }
    fn matches(self, row: UiPreferences) -> bool {
        self.theme.is_none_or(|theme| Some(theme) == row.theme)
            && self.locale.is_none_or(|locale| Some(locale) == row.locale)
    }
    fn request(self, known: UiPreferences) -> UpdateUiPreferences {
        UpdateUiPreferences {
            theme: self.theme.filter(|theme| Some(*theme) != known.theme),
            locale: self.locale.filter(|locale| Some(*locale) != known.locale),
            expected_revision: known.revision,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PreferenceIntent {
    token: AttemptToken,
    base: UiPreferences,
    request: UpdateUiPreferences,
    theme_serial: u64,
    locale_serial: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct PreferenceWrites {
    core: EditorCore,
    known: Option<UiPreferences>,
    draft: PreferenceDraft,
    latest: Option<UiPreferences>,
    hint: Option<RevisionSnapshot>,
    retained: Option<PreferenceIntent>,
    last_edit_ms: u64,
    theme_serial: u64,
    locale_serial: u64,
}

impl PreferenceWrites {
    fn retire_acknowledged_fields(&mut self, intent: PreferenceIntent, stored: UiPreferences) {
        if intent.request.theme.is_some()
            && self.theme_serial == intent.theme_serial
            && self.draft.theme == intent.request.theme
            && self.draft.theme == stored.theme
        {
            self.draft.theme = None;
        }
        if intent.request.locale.is_some()
            && self.locale_serial == intent.locale_serial
            && self.draft.locale == intent.request.locale
            && self.draft.locale == stored.locale
        {
            self.draft.locale = None;
        }
    }
}

#[derive(Clone, Copy)]
enum ReadChoice {
    Compare,
    Load,
    Retry,
    Reapply,
}

/// Shared authenticated editor; child locale/theme reconstruction cannot cancel its receipt owner.
#[derive(Clone, Copy)]
pub struct UiPreferenceContext {
    theme: RwSignal<UiTheme>,
    fallback_locale: UiLocale,
    writes: RwSignal<PreferenceWrites>,
    reading: RwSignal<bool>,
    read_failed: RwSignal<bool>,
    interaction_revision: RwSignal<u64>,
    read_serial: RwSignal<u64>,
    worker_owner: StoredValue<Option<Owner>>,
}

/// Install the single authenticated context and read actual stored preference presence.
pub fn provide_ui_preferences(i18n: I18nContext<Locale>) -> UiPreferenceContext {
    let context = UiPreferenceContext {
        theme: RwSignal::new(current_theme()),
        fallback_locale: use_context::<crate::locale_policy::SystemLocale>()
            .map_or(UiLocale::En, |locale| locale.0),
        writes: RwSignal::new(PreferenceWrites::default()),
        reading: RwSignal::new(false),
        read_failed: RwSignal::new(false),
        interaction_revision: RwSignal::new(0),
        read_serial: RwSignal::new(0),
        worker_owner: StoredValue::new(Owner::current()),
    };
    provide_context(context);
    on_cleanup(move || {
        context.writes.try_update(|writes| {
            let _ = writes.core.invalidate();
        });
    });
    context.read(i18n, ReadChoice::Compare);
    context
}

/// Get the context owned by the authenticated app shell.
pub fn use_ui_preferences() -> UiPreferenceContext {
    use_context().expect("AppShell provides UiPreferenceContext")
}

impl UiPreferenceContext {
    /// Effective local appearance, independent of persistence acknowledgment.
    #[must_use]
    pub fn theme(self) -> UiTheme {
        self.theme.get()
    }
    /// Whether edits or a current request still await a confirmed result.
    #[must_use]
    pub fn is_saving(self) -> bool {
        matches!(self.writes.get().core.phase(), Phase::Dirty | Phase::Saving)
    }
    /// Apply a deliberate theme choice immediately and merge its persistence input for800ms.
    pub fn select_theme(self, theme: UiTheme) {
        apply_theme(theme);
        self.theme.set(theme);
        self.enqueue(PreferenceDraft {
            theme: Some(theme),
            locale: None,
        });
    }
    /// Apply a deliberate language choice immediately, without persisting a host fallback.
    pub fn select_locale(self, i18n: I18nContext<Locale>, locale: UiLocale) {
        i18n.set_locale(contract_locale(locale));
        self.enqueue(PreferenceDraft {
            theme: None,
            locale: Some(locale),
        });
    }
    fn enqueue(self, draft: PreferenceDraft) {
        let Some(next) = self
            .interaction_revision
            .try_get_untracked()
            .and_then(|value| value.checked_add(1))
        else {
            self.writes
                .try_update(|writes| writes.core.restore_pause(Phase::Error, false));
            return;
        };
        self.interaction_revision.try_set(next);
        self.writes.try_update(|writes| {
            writes.draft.merge(draft);
            if draft.theme.is_some() {
                writes.theme_serial = next;
            }
            if draft.locale.is_some() {
                writes.locale_serial = next;
            }
            writes.last_edit_ms = now_ms();
            let _ = writes.core.edit(writes.last_edit_ms);
            if let Some(known) = writes.known {
                writes
                    .core
                    .set_local_matches_known(writes.draft.matches(known));
            }
        });
        self.schedule();
    }
    fn schedule(self) {
        let Some(writes) = self.writes.try_get_untracked() else {
            return;
        };
        let Some(deadline) = writes.core.next_auto_deadline() else {
            return;
        };
        let ticket = writes.core.debounce_token();
        after(
            deadline.saturating_sub(now_ms()).min(800) as i32,
            move || {
                let Some(mut writes) = self.writes.try_get_untracked() else {
                    return;
                };
                let Some(known) = writes.known else {
                    return;
                };
                let request = writes.draft.request(known);
                let token = writes
                    .core
                    .begin_auto(ticket, now_ms(), !request.is_empty());
                self.writes.try_set(writes);
                if let Ok(token) = token {
                    self.dispatch(token, known, request);
                }
            },
        );
    }
    fn dispatch(self, token: AttemptToken, base: UiPreferences, request: UpdateUiPreferences) {
        if token.expected_revision() != request.expected_revision
            || request.expected_revision != base.revision
        {
            self.writes.try_update(|writes| {
                writes.core.finish_failure(token, FailureClass::Definite);
            });
            return;
        }
        let Some(Some(owner)) = self.worker_owner.try_get_value() else {
            return;
        };
        let Some(writes) = self.writes.try_get_untracked() else {
            return;
        };
        let intent = PreferenceIntent {
            token,
            base,
            request,
            theme_serial: writes.theme_serial,
            locale_serial: writes.locale_serial,
        };
        self.writes
            .try_update(|writes| writes.retained = Some(intent));
        after(10_000, move || {
            self.writes.try_update(|writes| {
                writes.core.mark_timeout(token, now_ms());
            });
        });
        owner.with(|| {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let result = api::save(base, request).await;
                let Some(mut writes) = self.writes.try_get_untracked() else {
                    return;
                };
                if writes.core.generation() != token.generation() {
                    return;
                }
                match result {
                    Ok(stored) => {
                        if writes.core.finish_ack(
                            token,
                            stored.revision.unwrap_or(0),
                            writes.draft.matches(stored),
                        ) == Apply::Applied
                        {
                            writes.known = Some(stored);
                            writes.retire_acknowledged_fields(intent, stored);
                            if !writes.core.auto_paused() {
                                writes.retained = None;
                            }
                        }
                    }
                    Err(CasError::Conflict(snapshot)) => {
                        if writes
                            .core
                            .finish_closed_conflict(token, snapshot.current_revision())
                            == Apply::Applied
                        {
                            writes.hint = Some(snapshot);
                        }
                    }
                    Err(error) => {
                        writes.core.finish_failure(
                            token,
                            if error == CasError::Unknown {
                                FailureClass::Unknown
                            } else {
                                FailureClass::Definite
                            },
                        );
                    }
                }
                self.writes.try_set(writes);
                self.schedule();
            })
        });
    }
    fn apply_stored(
        self,
        i18n: I18nContext<Locale>,
        stored: UiPreferences,
        theme_unedited: bool,
        locale_unedited: bool,
    ) {
        if self.writes.try_get_untracked().is_none() {
            return;
        }
        if theme_unedited && let Some(theme) = stored.theme {
            apply_theme(theme);
            self.theme.try_set(theme);
        }
        if let Some(locale) = crate::locale_policy::locale_after_read(
            stored.locale,
            self.fallback_locale,
            locale_unedited,
        ) {
            i18n.set_locale(contract_locale(locale));
        }
    }
    fn read(self, i18n: I18nContext<Locale>, choice: ReadChoice) {
        if self.reading.try_get_untracked() != Some(false) {
            return;
        }
        let Some(mut initial) = self.writes.try_get_untracked() else {
            return;
        };
        let cold = initial.known.is_none();
        let compared = initial.latest;
        let confirmed_draft = initial.draft;
        let confirmed_edit_serial = initial.core.edit_serial();
        let read_token = if cold {
            None
        } else {
            match initial.core.begin_read() {
                Ok(token) => Some(token),
                Err(_) => {
                    self.writes.try_set(initial);
                    return;
                }
            }
        };
        self.writes.try_set(initial);
        let Some(serial) = self
            .read_serial
            .try_get_untracked()
            .and_then(|value| value.checked_add(1))
        else {
            return;
        };
        let Some(Some(owner)) = self.worker_owner.try_get_value() else {
            return;
        };
        self.read_serial.try_set(serial);
        self.reading.try_set(true);
        self.read_failed.try_set(false);
        owner.with(|| {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let result = api::read().await;
                if self.read_serial.try_get_untracked() != Some(serial) {
                    return;
                }
                let Some(mut writes) = self.writes.try_get_untracked() else {
                    return;
                };
                self.reading.try_set(false);
                let Ok(stored) = result else {
                    if cold {
                        writes.core.restore_pause(Phase::Error, false);
                        self.writes.try_set(writes);
                    }
                    self.read_failed.try_set(true);
                    return;
                };
                if cold {
                    let bind = match stored.revision {
                        Some(revision) => writes.core.bind_existing(revision),
                        None => writes.core.bind_absent(),
                    };
                    if bind.is_err() {
                        self.writes.try_set(writes);
                        self.read_failed.try_set(true);
                        return;
                    }
                    writes.known = Some(stored);
                    let theme_unedited = writes.draft.theme.is_none();
                    let locale_unedited = writes.draft.locale.is_none();
                    if !writes.draft.is_empty() {
                        let _ = writes.core.edit(writes.last_edit_ms);
                        writes
                            .core
                            .set_local_matches_known(writes.draft.matches(stored));
                    }
                    self.writes.try_set(writes);
                    self.apply_stored(i18n, stored, theme_unedited, locale_unedited);
                    self.schedule();
                    return;
                }
                if !consistent_read(&writes, stored) {
                    self.read_failed.try_set(true);
                    return;
                }
                let Some(read_token) = read_token else {
                    return;
                };
                let recovery = match stored.revision {
                    Some(revision) => writes.core.accept_recovery_read(read_token, revision),
                    None => writes.core.accept_recovery_absent(read_token),
                };
                let Ok(recovery) = recovery else {
                    self.writes.try_set(writes);
                    self.read_failed.try_set(true);
                    return;
                };
                writes.latest = Some(stored);
                let mut send = None;
                let mut apply = false;
                match choice {
                    ReadChoice::Compare => {}
                    ReadChoice::Load => {
                        if writes.core.edit_serial() == confirmed_edit_serial
                            && writes.draft == confirmed_draft
                            && writes.core.choose_load(recovery, true) == Apply::Applied
                        {
                            writes.known = Some(stored);
                            writes.draft = PreferenceDraft::default();
                            apply = true;
                            if !writes.core.auto_paused() {
                                writes.retained = None;
                            }
                        }
                    }
                    ReadChoice::Retry => {
                        if let Some(intent) = writes.retained
                            && let Ok(token) = writes.core.begin_retry_original(
                                recovery,
                                intent.token,
                                now_ms(),
                                !intent.request.is_empty(),
                            )
                        {
                            send = Some((token, intent.base, intent.request));
                        }
                    }
                    ReadChoice::Reapply => {
                        let request = confirmed_draft.request(stored);
                        if compared == Some(stored)
                            && writes.core.edit_serial() == confirmed_edit_serial
                            && let Ok(token) = writes.core.begin_reapply(
                                recovery,
                                true,
                                now_ms(),
                                !request.is_empty(),
                            )
                        {
                            send = Some((token, stored, request));
                        }
                    }
                }
                self.writes.try_set(writes);
                if apply {
                    self.apply_stored(i18n, stored, true, true);
                }
                if let Some((token, base, request)) = send {
                    self.dispatch(token, base, request);
                }
            })
        });
    }
}

fn consistent_read(writes: &PreferenceWrites, stored: UiPreferences) -> bool {
    if let Some(known) = writes.known
        && stored.revision == known.revision
        && stored != known
    {
        return false;
    }
    if let Some(hint) = writes.hint {
        let Some(revision) = stored.revision else {
            return false;
        };
        if revision < hint.current_revision()
            || revision == hint.current_revision() && stored.revision_snapshot().ok() != Some(hint)
        {
            return false;
        }
    }
    true
}

/// Shared status and explicit version choices; IDs distinguish sidebar and settings mounts.
#[component]
pub fn PreferenceSaveStatus(
    /// Stable prefix that distinguishes the sidebar and settings recovery controls.
    #[prop(default = "preferences-editor")]
    id_prefix: &'static str,
) -> impl IntoView {
    let i18n = use_i18n();
    let preferences = use_ui_preferences();
    let phase = Signal::derive(move || preferences.writes.get().core.phase());
    let busy = Signal::derive(move || preferences.reading.get());
    view! {
        <Show when=move ||preferences.read_failed.get()><p class="ob-preference-error" role="alert">{move ||t!(i18n,revision_editor.read_failed)}</p></Show>
        <Show when=move ||preferences.writes.get().known.is_some() fallback=move ||view! {
            <Show when=move ||preferences.read_failed.get() fallback=move ||view! {<p role="status">{move ||t!(i18n,common.loading)}</p>}>
                <crate::primitives::Button id=format!("{id_prefix}-retry-read") disabled=busy on_activate=move |_|preferences.read(i18n,ReadChoice::Compare)>{move ||t!(i18n,common.retry)}</crate::primitives::Button>
            </Show>
        }>
            <EditorNotice phase busy id_prefix
                can_retry=Signal::derive(move ||preferences.writes.get().retained.is_some())
                on_compare=UnsyncCallback::new(move |_|preferences.read(i18n,ReadChoice::Compare))
                on_load=UnsyncCallback::new(move |_|preferences.read(i18n,ReadChoice::Load))
                on_retry=UnsyncCallback::new(move |_|preferences.read(i18n,ReadChoice::Retry))
                on_reapply=UnsyncCallback::new(move |_|preferences.read(i18n,ReadChoice::Reapply))/>
        </Show>
        <Show when=move ||preferences.writes.get().latest.is_some()>
            <div class="ob-library-form ob-library-detail-body">
                <h3>{move ||t!(i18n,revision_editor.local_draft)}</h3>
                <p>{move ||preferences.writes.get().draft.theme.map(|value|value.as_str())}</p><p>{move ||preferences.writes.get().draft.locale.map(|value|value.as_str())}</p>
                <h3>{move ||t!(i18n,revision_editor.server_version)}</h3>
                <p>{move ||preferences.writes.get().latest.and_then(|row|row.theme).map(|value|value.as_str())}</p><p>{move ||preferences.writes.get().latest.and_then(|row|row.locale).map(|value|value.as_str())}</p>
            </div>
        </Show>
    }
}

const fn contract_locale(locale: UiLocale) -> Locale {
    match locale {
        UiLocale::En => Locale::en,
        UiLocale::ZhCn => Locale::zh_CN,
    }
}

#[cfg(target_arch = "wasm32")]
fn current_theme() -> UiTheme {
    let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    else {
        return UiTheme::System;
    };
    let classes = root.class_list();
    if classes.contains("dark") {
        UiTheme::Dark
    } else if classes.contains("light") {
        UiTheme::Light
    } else {
        UiTheme::System
    }
}
#[cfg(not(target_arch = "wasm32"))]
const fn current_theme() -> UiTheme {
    UiTheme::System
}

#[cfg(target_arch = "wasm32")]
fn apply_theme(theme: UiTheme) {
    let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    else {
        return;
    };
    let classes = root.class_list();
    _ = classes.remove_2("light", "dark");
    match theme {
        UiTheme::System => {}
        UiTheme::Light => {
            _ = classes.add_1("light");
        }
        UiTheme::Dark => {
            _ = classes.add_1("dark");
        }
    }
}
#[cfg(not(target_arch = "wasm32"))]
const fn apply_theme(_theme: UiTheme) {}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    #[test]
    fn preference_patch_retains_newer_edits_and_does_not_invent_unspecified_fields() {
        let mut draft = PreferenceDraft {
            theme: Some(UiTheme::Dark),
            locale: None,
        };
        let frozen = draft.request(UiPreferences::default());
        draft.merge(PreferenceDraft {
            theme: Some(UiTheme::Light),
            locale: Some(UiLocale::ZhCn),
        });
        assert_eq!(frozen.theme, Some(UiTheme::Dark));
        assert_eq!(frozen.locale, None);
        assert_eq!(frozen.expected_revision, None);
        let row = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            revision: Some(1),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        };
        assert!(!draft.matches(row));
        assert_eq!(draft.request(row).expected_revision, Some(1));
    }
    #[test]
    fn a_destroyed_authenticated_context_cannot_write_into_a_new_account() {
        let owner = Owner::new();
        let old = owner.with(|| RwSignal::new(PreferenceWrites::default()));
        owner.cleanup();
        Owner::new().with(|| {
            let new = RwSignal::new(PreferenceWrites::default());
            assert!(old.try_get_untracked().is_none());
            assert!(new.get_untracked().known.is_none());
        });
    }
    #[test]
    fn full_closed_conflict_snapshot_binds_same_revision_recovery_read() {
        let row = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: None,
            revision: Some(3),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        };
        let writes = PreferenceWrites {
            hint: Some(row.revision_snapshot().unwrap()),
            ..PreferenceWrites::default()
        };
        assert!(consistent_read(&writes, row));
        assert!(!consistent_read(
            &writes,
            UiPreferences {
                theme: Some(UiTheme::Light),
                ..row
            }
        ));
        assert!(!consistent_read(
            &writes,
            UiPreferences {
                updated_at: Some(time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1)),
                ..row
            }
        ));
        assert!(!consistent_read(&writes, UiPreferences::default()));
    }

    #[test]
    fn acknowledged_field_retires_without_absorbing_a_newer_other_field_or_draft() {
        let base = UiPreferences {
            theme: Some(UiTheme::Dark),
            locale: Some(UiLocale::En),
            revision: Some(2),
            updated_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        };
        let mut core = EditorCore::new();
        core.bind_existing(2).unwrap();
        let ticket = core.edit(0).unwrap();
        let token = core.begin_auto(ticket, 800, true).unwrap();
        let request = UpdateUiPreferences {
            theme: Some(UiTheme::Light),
            locale: None,
            expected_revision: Some(2),
        };
        let intent = PreferenceIntent {
            token,
            base,
            request,
            theme_serial: 1,
            locale_serial: 0,
        };
        let stored = UiPreferences {
            theme: Some(UiTheme::Light),
            revision: Some(3),
            ..base
        };
        let mut writes = PreferenceWrites {
            draft: PreferenceDraft {
                theme: Some(UiTheme::Light),
                locale: Some(UiLocale::ZhCn),
            },
            theme_serial: 1,
            locale_serial: 2,
            ..PreferenceWrites::default()
        };
        writes.retire_acknowledged_fields(intent, stored);
        assert_eq!(writes.draft.theme, None);
        assert_eq!(writes.draft.locale, Some(UiLocale::ZhCn));
        let next = writes.draft.request(stored);
        assert_eq!(next.theme, None);
        assert_eq!(next.locale, Some(UiLocale::ZhCn));
        assert_eq!(next.expected_revision, Some(3));
        writes.draft.theme = Some(UiTheme::Dark);
        writes.theme_serial = 3;
        writes.retire_acknowledged_fields(intent, stored);
        assert_eq!(writes.draft.theme, Some(UiTheme::Dark));
        assert_eq!(writes.draft.request(stored).theme, Some(UiTheme::Dark));
    }
}
