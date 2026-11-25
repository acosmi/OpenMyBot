//! Existing original-run facts, observed page by page. No command, unlock or effect retry.
#[cfg(any(target_arch = "wasm32", test))]
use crate::api::ApiError;
use crate::api::reconciliation;
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Notice, NoticeTone, TechnicalDetails, Timestamp,
};
use leptos::prelude::*;
use openbot_contracts::ids::{RunId, ThreadId};
use openbot_contracts::reconciliation::{
    RunEffectReceiptsSnapshot, RunReconciliationCursor, RunReconciliationSnapshot,
};

#[derive(Clone)]
struct PageState<P> {
    page: Option<P>,
    busy: bool,
    error: bool,
    generation: u64,
}
impl<P> Default for PageState<P> {
    fn default() -> Self {
        Self {
            page: None,
            busy: false,
            error: false,
            generation: 0,
        }
    }
}

#[component]
pub(crate) fn UnknownFacts(
    thread: ThreadId,
    run: RunId,
    #[prop(default=Signal::derive(||None))] expected_terminal: Signal<Option<u64>>,
) -> impl IntoView {
    let i18n = use_i18n();
    #[cfg(target_arch = "wasm32")]
    let read_owner = StoredValue::new(Owner::current());
    let identity = StoredValue::new((thread.clone(), run.clone()));
    let terminal = RwSignal::new(expected_terminal.get_untracked());
    let attempts = RwSignal::new(PageState::<RunReconciliationSnapshot>::default());
    let receipts = RwSignal::new(PageState::<RunEffectReceiptsSnapshot>::default());
    let read_attempts = UnsyncCallback::new(move |after: Option<RunReconciliationCursor>| {
        if attempts.get_untracked().busy {
            return;
        }
        let Some(generation) = attempts.get_untracked().generation.checked_add(1) else {
            return;
        };
        attempts.set(PageState {
            generation,
            busy: true,
            ..Default::default()
        });
        let (thread, run) = identity.get_value();
        #[cfg(target_arch = "wasm32")]
        spawn_read(read_owner, async move {
            let result = reconciliation::attempts(&thread, &run, after).await;
            if attempts
                .try_get_untracked()
                .is_none_or(|state| state.generation != generation)
            {
                return;
            }
            match result.and_then(|page| {
                if let Some(expected) = expected_terminal.get_untracked() {
                    bind_terminal(terminal, expected)?;
                }
                bind_terminal(terminal, page.terminal_event_sequence).map(|()| page)
            }) {
                Ok(page) => attempts.set(PageState {
                    page: Some(page),
                    busy: false,
                    error: false,
                    generation,
                }),
                Err(_) => attempts.set(PageState {
                    error: true,
                    generation,
                    ..Default::default()
                }),
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (thread, run, after, reconciliation::attempts);
            attempts.set(PageState {
                error: true,
                generation,
                ..Default::default()
            });
        }
    });
    let read_receipts = UnsyncCallback::new(move |after: Option<RunReconciliationCursor>| {
        if receipts.get_untracked().busy {
            return;
        }
        let Some(generation) = receipts.get_untracked().generation.checked_add(1) else {
            return;
        };
        receipts.set(PageState {
            generation,
            busy: true,
            ..Default::default()
        });
        let (thread, run) = identity.get_value();
        #[cfg(target_arch = "wasm32")]
        spawn_read(read_owner, async move {
            let result = reconciliation::receipts(&thread, &run, after).await;
            if receipts
                .try_get_untracked()
                .is_none_or(|state| state.generation != generation)
            {
                return;
            }
            match result.and_then(|page| {
                if let Some(expected) = expected_terminal.get_untracked() {
                    bind_terminal(terminal, expected)?;
                }
                bind_terminal(terminal, page.terminal_event_sequence).map(|()| page)
            }) {
                Ok(page) => receipts.set(PageState {
                    page: Some(page),
                    busy: false,
                    error: false,
                    generation,
                }),
                Err(_) => receipts.set(PageState {
                    error: true,
                    generation,
                    ..Default::default()
                }),
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (thread, run, after, reconciliation::receipts, terminal);
            receipts.set(PageState {
                error: true,
                generation,
                ..Default::default()
            });
        }
    });
    let run_attribute = run.as_str().to_owned();
    view! { <section class="ob-unknown-facts" data-unknown-run=run_attribute>
        <h3>{move || t!(i18n, admin.unknown_title)}</h3>
        <TechnicalDetails copy=format!("{}\n{}", thread.as_str(), run.as_str())><code>{thread.as_str().to_owned()}</code><code>{run.as_str().to_owned()}</code></TechnicalDetails>
        <p>{move || t!(i18n, admin.unknown_boundary)}</p>
        <section><h4>{move || t!(i18n, admin.unknown_attempts)}</h4>
            <Button variant=ButtonVariant::Ghost size=ButtonSize::Small disabled=Signal::derive(move || attempts.get().busy) on_activate=move |_| read_attempts.run(None)>{move || t!(i18n, channels.reread)}</Button>
            <Show when=move || attempts.get().error><Notice tone=NoticeTone::Error>{move || t!(i18n, admin.unknown_read_error)}</Notice></Show>
            {move || attempts.get().page.map(|page| { let next=page.next; let empty=page.attempts.is_empty(); let rows=page.attempts; view! {
                <FactObservation observed=page.observed_at blocked=page.foreground_blocked terminal=page.terminal_event_sequence/>
                <Show when=move || empty><p>{move || t!(i18n, admin.unknown_empty)}</p></Show>
                <ul>{rows.into_iter().map(|row| view! { <li>
                    <p>{move || format!("{:?} · {}", row.status, row.recorded_commit_state.map_or_else(|| t_string!(i18n, admin.unknown_not_recorded).to_owned(), |state| format!("{state:?}")))}</p>
                    <Timestamp at=row.created_at />
                    <TechnicalDetails copy=format!("{}\n{}", row.tool_call_id, row.attempt_id)><code>{row.tool_call_id}</code><code>{row.attempt_id}</code></TechnicalDetails>
                </li> }).collect_view()}</ul>
                {next.map(|next| view! { <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| read_attempts.run(Some(next))>{move || t!(i18n, common.next)}</Button> })}
            } })}
        </section>
        <section><h4>{move || t!(i18n, admin.unknown_receipts)}</h4>
            <Button variant=ButtonVariant::Ghost size=ButtonSize::Small disabled=Signal::derive(move || receipts.get().busy) on_activate=move |_| read_receipts.run(None)>{move || t!(i18n, channels.reread)}</Button>
            <Show when=move || receipts.get().error><Notice tone=NoticeTone::Error>{move || t!(i18n, admin.unknown_read_error)}</Notice></Show>
            {move || receipts.get().page.map(|page| { let next=page.next; let empty=page.receipts.is_empty(); let rows=page.receipts; view! {
                <FactObservation observed=page.observed_at blocked=page.foreground_blocked terminal=page.terminal_event_sequence/>
                <Show when=move || empty><p>{move || t!(i18n, admin.unknown_empty)}</p></Show>
                <ul>{rows.into_iter().map(|row| view! { <li>
                    <p>{move || t!(i18n, admin.unknown_memory_fact)}</p><Timestamp at=row.recorded_at />
                    <TechnicalDetails copy=format!("{}\n{}\n{}", row.receipt_id, row.tool_call_id, row.attempt_id)><code>{row.receipt_id}</code><code>{row.tool_call_id}</code><code>{row.attempt_id}</code></TechnicalDetails>
                </li> }).collect_view()}</ul>
                {next.map(|next| view! { <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| read_receipts.run(Some(next))>{move || t!(i18n, common.next)}</Button> })}
            } })}
        </section>
    </section> }
}

#[cfg(target_arch = "wasm32")]
fn spawn_read(
    owner: StoredValue<Option<Owner>>,
    future: impl core::future::Future<Output = ()> + 'static,
) {
    // The next-page button is removed when loading begins. Its owner cannot own the read.
    if let Some(owner) = owner.get_value() {
        owner.with(|| leptos::task::spawn_local_scoped_with_cancellation(future));
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn bind_terminal(terminal: RwSignal<Option<u64>>, sequence: u64) -> Result<(), ApiError> {
    let Some(known) = terminal.try_get_untracked() else {
        return Err(ApiError::Unavailable);
    };
    if known.is_some_and(|known| known != sequence) {
        return Err(ApiError::InvalidResponse);
    }
    terminal.set(Some(sequence));
    Ok(())
}
#[component]
fn FactObservation(observed: time::OffsetDateTime, blocked: bool, terminal: u64) -> impl IntoView {
    let i18n = use_i18n();
    view! { <p class="ob-page-intro"><Timestamp at=observed /> " · " {move || if blocked { t_string!(i18n, admin.unknown_blocked).to_owned() } else { t_string!(i18n, admin.unknown_unblocked_fact).to_owned() }}</p>
    <TechnicalDetails copy=terminal.to_string()><code>{terminal}</code></TechnicalDetails> }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pages_share_original_terminal_identity_but_not_a_clock_or_occupancy_snapshot() {
        let owner = Owner::new();
        let terminal = owner.with(|| RwSignal::new(None));
        assert!(bind_terminal(terminal, 74).is_ok());
        assert!(bind_terminal(terminal, 74).is_ok());
        assert_eq!(bind_terminal(terminal, 75), Err(ApiError::InvalidResponse));
        owner.cleanup();
        assert_eq!(bind_terminal(terminal, 74), Err(ApiError::Unavailable));
    }
}
