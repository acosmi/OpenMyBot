//! Distinct authenticated decision owners shared by the current-actor and inline views.
use crate::api::ApiError;
use crate::features::gallery::HumanDecisionCard;
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Notice, NoticePresentation, NoticeTone, TechnicalDetails,
    Textarea, Timestamp,
};
use leptos::prelude::*;
use openbot_contracts::components::{
    ComponentHumanDecisionAnswer, ComponentHumanDecisionResolved, PendingComponentHumanDecision,
    validate_component_human_decision_answer,
};
use openbot_contracts::ids::RunId;
use openbot_contracts::remote_interrupt::{
    PendingRemoteInterrupt, RemoteInterruptAnswer, RemoteInterruptAnswerStatus,
    RemoteInterruptResolved,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Submitting,
    Confirmed,
    Unknown,
}

/// Retain source identity and time, never expired authorization or presentation payload.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceReference {
    id: String,
    run: String,
    bot: String,
    call: Option<String>,
    requested: i64,
    expires: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ComponentObservation {
    source: SourceReference,
    binding: [u8; 32],
    answer: ComponentHumanDecisionAnswer,
    phase: Phase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteObservation {
    source: SourceReference,
    binding: [u8; 32],
    status: RemoteInterruptAnswerStatus,
    phase: Phase,
}

#[derive(Clone, Copy)]
pub(crate) struct ComponentDecisionActions {
    pending: RwSignal<Vec<PendingComponentHumanDecision>>,
    observations: RwSignal<BTreeMap<String, ComponentObservation>>,
    error: RwSignal<Option<ApiError>>,
    now: RwSignal<i64>,
    epoch: RwSignal<u64>,
    #[cfg(target_arch = "wasm32")]
    owner: StoredValue<Option<Owner>>,
}

impl ComponentDecisionActions {
    pub(crate) fn has_for_run(self, run: Option<RunId>) -> bool {
        run.is_some_and(|run| {
            !inaccessible(self.error.get())
                && (self
                    .pending
                    .with(|rows| rows.iter().any(|row| row.run_id == run))
                    || self
                        .observations
                        .with(|rows| rows.values().any(|row| row.source.run == run.as_str())))
        })
    }
    pub(crate) fn new() -> Self {
        let actions = Self {
            pending: RwSignal::new(Vec::new()),
            observations: RwSignal::new(BTreeMap::new()),
            error: RwSignal::new(None),
            now: RwSignal::new(now_ms()),
            epoch: RwSignal::new(0),
            #[cfg(target_arch = "wasm32")]
            owner: StoredValue::new(Owner::current()),
        };
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            loop {
                let epoch = actions.epoch.get_untracked();
                let result = crate::api::list_pending_component_human_decisions().await;
                actions.install(epoch, result.map(|page| page.decisions));
                delay().await;
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        actions.install(0, Err(ApiError::Unavailable));
        start_clock(actions.now);
        actions
    }

    fn install(
        self,
        epoch: u64,
        result: Result<Vec<PendingComponentHumanDecision>, ApiError>,
    ) -> bool {
        if self.epoch.try_get_untracked() != Some(epoch) {
            return false;
        }
        match result {
            Ok(rows) => {
                self.pending.set(rows);
                self.error.set(None);
            }
            Err(error) => {
                self.error.set(Some(error));
                if inaccessible(Some(error)) {
                    self.pending.set(Vec::new());
                }
            }
        }
        true
    }

    fn begin(
        self,
        card: &PendingComponentHumanDecision,
        answer: &ComponentHumanDecisionAnswer,
    ) -> bool {
        if self.observations.try_get_untracked().is_none()
            || self.error.get_untracked().is_some()
            || now_ms() >= milliseconds(card.expires_at)
            || self
                .observations
                .with_untracked(|rows| rows.contains_key(&card.decision_id))
            || !self.pending.with_untracked(|rows| rows.contains(card))
            || validate_component_human_decision_answer(
                &card.component_name,
                &card.arguments,
                answer,
            )
            .is_err()
        {
            return false;
        }
        self.observations.update(|rows| {
            rows.insert(
                card.decision_id.clone(),
                ComponentObservation {
                    binding: binding(card),
                    source: SourceReference {
                        id: card.decision_id.clone(),
                        run: card.run_id.as_str().to_owned(),
                        bot: card.agent_id.as_str().to_owned(),
                        call: Some(card.provider_call_id.clone()),
                        requested: milliseconds(card.requested_at),
                        expires: milliseconds(card.expires_at),
                    },
                    answer: answer.clone(),
                    phase: Phase::Submitting,
                },
            );
        });
        true
    }

    fn complete(
        self,
        id: &str,
        answer: &ComponentHumanDecisionAnswer,
        result: Result<ComponentHumanDecisionResolved, ApiError>,
    ) {
        let Some(rows) = self.observations.try_get_untracked() else {
            return;
        };
        if !rows
            .get(id)
            .is_some_and(|row| row.phase == Phase::Submitting && &row.answer == answer)
        {
            return;
        }
        let confirmed = matches!(result, Ok(ref receipt) if receipt.decision_id == id && &receipt.answer == answer);
        if let Err(error @ (ApiError::Unauthorized | ApiError::Forbidden)) = result {
            self.epoch.update(|epoch| *epoch = epoch.saturating_add(1));
            self.error.set(Some(error));
            self.pending.set(Vec::new());
        }
        self.observations.update(|rows| {
            if let Some(row) = rows.get_mut(id) {
                row.phase = if confirmed {
                    Phase::Confirmed
                } else {
                    Phase::Unknown
                };
            }
        });
    }

    fn answer(self, card: PendingComponentHumanDecision, answer: ComponentHumanDecisionAnswer) {
        if !self.begin(&card, &answer) {
            return;
        }
        #[cfg(target_arch = "wasm32")]
        {
            let start = || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let result =
                        crate::api::answer_component_human_decision(&card.decision_id, &answer)
                            .await;
                    self.complete(&card.decision_id, &answer, result);
                })
            };
            if let Some(owner) = self.owner.get_value() {
                owner.with(start);
            } else {
                start();
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        self.complete(&card.decision_id, &answer, Err(ApiError::Unavailable));
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RemoteInterruptActions {
    pending: RwSignal<Vec<PendingRemoteInterrupt>>,
    observations: RwSignal<BTreeMap<String, RemoteObservation>>,
    error: RwSignal<Option<ApiError>>,
    now: RwSignal<i64>,
    epoch: RwSignal<u64>,
    #[cfg(target_arch = "wasm32")]
    owner: StoredValue<Option<Owner>>,
}

impl RemoteInterruptActions {
    pub(crate) fn has_for_run(self, run: Option<RunId>) -> bool {
        run.is_some_and(|run| {
            !inaccessible(self.error.get())
                && (self
                    .pending
                    .with(|rows| rows.iter().any(|row| row.run_id == run.as_str()))
                    || self
                        .observations
                        .with(|rows| rows.values().any(|row| row.source.run == run.as_str())))
        })
    }
    pub(crate) fn new() -> Self {
        let actions = Self {
            pending: RwSignal::new(Vec::new()),
            observations: RwSignal::new(BTreeMap::new()),
            error: RwSignal::new(None),
            now: RwSignal::new(now_ms()),
            epoch: RwSignal::new(0),
            #[cfg(target_arch = "wasm32")]
            owner: StoredValue::new(Owner::current()),
        };
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            loop {
                let epoch = actions.epoch.get_untracked();
                let result = crate::api::list_pending_remote_interrupts().await;
                actions.install(epoch, result.map(|page| page.interrupts));
                delay().await;
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        actions.install(0, Err(ApiError::Unavailable));
        start_clock(actions.now);
        actions
    }

    fn install(self, epoch: u64, result: Result<Vec<PendingRemoteInterrupt>, ApiError>) -> bool {
        if self.epoch.try_get_untracked() != Some(epoch) {
            return false;
        }
        match result {
            Ok(rows) => {
                self.pending.set(rows);
                self.error.set(None);
            }
            Err(error) => {
                self.error.set(Some(error));
                if inaccessible(Some(error)) {
                    self.pending.set(Vec::new());
                }
            }
        }
        true
    }

    fn begin(self, card: &PendingRemoteInterrupt, answer: &RemoteInterruptAnswer) -> bool {
        if self.observations.try_get_untracked().is_none()
            || self.error.get_untracked().is_some()
            || now_ms() >= card.expires_at_ms
            || self
                .observations
                .with_untracked(|rows| rows.contains_key(&card.request_id))
            || !self.pending.with_untracked(|rows| rows.contains(card))
        {
            return false;
        }
        self.observations.update(|rows| {
            rows.insert(
                card.request_id.clone(),
                RemoteObservation {
                    binding: binding(card),
                    source: SourceReference {
                        id: card.request_id.clone(),
                        run: card.run_id.clone(),
                        bot: card.agent_id.clone(),
                        call: None,
                        requested: card.requested_at_ms,
                        expires: card.expires_at_ms,
                    },
                    status: answer.status,
                    phase: Phase::Submitting,
                },
            );
        });
        true
    }

    fn complete(
        self,
        id: &str,
        status: RemoteInterruptAnswerStatus,
        result: Result<RemoteInterruptResolved, ApiError>,
    ) {
        let Some(rows) = self.observations.try_get_untracked() else {
            return;
        };
        if !rows
            .get(id)
            .is_some_and(|row| row.phase == Phase::Submitting && row.status == status)
        {
            return;
        }
        let confirmed = matches!(result, Ok(ref receipt) if receipt.request_id == id && receipt.status == status);
        if let Err(error @ (ApiError::Unauthorized | ApiError::Forbidden)) = result {
            self.epoch.update(|epoch| *epoch = epoch.saturating_add(1));
            self.error.set(Some(error));
            self.pending.set(Vec::new());
        }
        self.observations.update(|rows| {
            if let Some(row) = rows.get_mut(id) {
                row.phase = if confirmed {
                    Phase::Confirmed
                } else {
                    Phase::Unknown
                };
            }
        });
    }

    fn answer(self, card: PendingRemoteInterrupt, answer: RemoteInterruptAnswer) {
        if !self.begin(&card, &answer) {
            return;
        }
        #[cfg(target_arch = "wasm32")]
        {
            let start = || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let result =
                        crate::api::answer_remote_interrupt(&card.request_id, &answer).await;
                    self.complete(&card.request_id, answer.status, result);
                })
            };
            if let Some(owner) = self.owner.get_value() {
                owner.with(start);
            } else {
                start();
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        self.complete(&card.request_id, answer.status, Err(ApiError::Unavailable));
    }
}

fn inaccessible(error: Option<ApiError>) -> bool {
    matches!(
        error,
        Some(ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound)
    )
}
fn matches_run(filter: Option<RunId>, run: &str) -> bool {
    filter.is_none_or(|filter| filter.as_str() == run)
}

/// The three DTO families are displayed separately; no incomplete aggregate count is synthesized.
#[component]
pub(crate) fn DecisionAttention(
    #[prop(default=Signal::derive(|| None))] run: Signal<Option<RunId>>,
    #[prop(default = false)] inline: bool,
) -> impl IntoView {
    let i18n = use_i18n();
    let component = expect_context::<ComponentDecisionActions>();
    let remote = expect_context::<RemoteInterruptActions>();
    view! {
        <section class="ob-attention-family" data-attention-family="component">
            <Show when=move || component.error.get().is_some()><Notice tone=NoticeTone::Caution>{move || t!(i18n, gallery.decision_load_error)}</Notice></Show>
            <For each=move || if inaccessible(component.error.get()) || (inline && run.get().is_none()) { Vec::new() } else { component.pending.get().into_iter().filter(|card| matches_run(run.get(), card.run_id.as_str())).collect() }
                key=|card| (card.decision_id.clone(), binding(card))
                children=move |card| view! { <ComponentAttentionCard card actions=component/> }/>
            <For each=move || if inaccessible(component.error.get()) || (inline && run.get().is_none()) { Vec::new() } else { component.observations.get().into_values().filter(|row| matches_run(run.get(), &row.source.run) && !component.pending.with(|cards| cards.iter().any(|card| card.decision_id == row.source.id))).collect() }
                key=|row| row.source.id.clone() children=move |row| { let id = row.source.id.clone(); view! { <DecisionReference source=row.source phase=Signal::derive(move || component.observations.get().get(&id).map(|row| row.phase))/> } }/>
        </section>
        <section class="ob-attention-family" data-attention-family="remote">
            <Show when=move || remote.error.get().is_some()><Notice tone=NoticeTone::Caution>{move || t!(i18n, channels.remote_interrupt_load_error)}</Notice></Show>
            <For each=move || if inaccessible(remote.error.get()) || (inline && run.get().is_none()) { Vec::new() } else { remote.pending.get().into_iter().filter(|card| matches_run(run.get(), &card.run_id)).collect() }
                key=|card| (card.request_id.clone(), binding(card))
                children=move |card| view! { <RemoteAttentionCard card actions=remote/> }/>
            <For each=move || if inaccessible(remote.error.get()) || (inline && run.get().is_none()) { Vec::new() } else { remote.observations.get().into_values().filter(|row| matches_run(run.get(), &row.source.run) && !remote.pending.with(|cards| cards.iter().any(|card| card.request_id == row.source.id))).collect() }
                key=|row| row.source.id.clone() children=move |row| { let id = row.source.id.clone(); view! { <DecisionReference source=row.source phase=Signal::derive(move || remote.observations.get().get(&id).map(|row| row.phase))/> } }/>
        </section>
    }
}

#[component]
fn ComponentAttentionCard(
    card: PendingComponentHumanDecision,
    actions: ComponentDecisionActions,
) -> impl IntoView {
    let current_binding = binding(&card);
    let id = card.decision_id.clone();
    let answer_id = id.clone();
    let phase_id = id.clone();
    let blocked_id = id.clone();
    let phase = Signal::derive(move || {
        actions.observations.get().get(&phase_id).map(|row| {
            if row.binding == current_binding {
                row.phase
            } else {
                Phase::Unknown
            }
        })
    });
    let answer = Signal::derive(move || {
        actions
            .observations
            .get()
            .get(&answer_id)
            .filter(|row| row.phase == Phase::Confirmed && row.binding == current_binding)
            .map(|row| row.answer.clone())
    });
    let expires = milliseconds(card.expires_at);
    let blocked = Signal::derive(move || {
        actions.now.get() >= expires
            || actions.error.get().is_some()
            || actions.observations.get().contains_key(&blocked_id)
    });
    let callback_card = card.clone();
    view! { <article class="ob-review-card" data-component-decision=id>
        <div class="ob-approval-source"><TechnicalDetails copy=format!("{}\n{}\n{}", card.agent_id.as_str(), card.run_id.as_str(), card.provider_call_id)><code>{card.agent_id.as_str().to_owned()}</code><code>{card.run_id.as_str().to_owned()}</code><code>{card.provider_call_id.clone()}</code></TechnicalDetails></div>
        <DecisionExpiry requested=milliseconds(card.requested_at) expires now=actions.now/>
        <DecisionStatus phase/>
        <HumanDecisionCard name=card.component_name arguments=card.arguments answer blocked
            submitting=Signal::derive(move || phase.get() == Some(Phase::Submitting))
            error=Signal::derive(move || phase.get() == Some(Phase::Unknown))
            on_answer=UnsyncCallback::new(move |answer| actions.answer(callback_card.clone(), answer))/>
    </article> }
}

#[component]
fn RemoteAttentionCard(
    card: PendingRemoteInterrupt,
    actions: RemoteInterruptActions,
) -> impl IntoView {
    let i18n = use_i18n();
    let current_binding = binding(&card);
    let id = card.request_id.clone();
    let phase_id = id.clone();
    let blocked_id = id.clone();
    let phase = Signal::derive(move || {
        actions.observations.get().get(&phase_id).map(|row| {
            if row.binding == current_binding {
                row.phase
            } else {
                Phase::Unknown
            }
        })
    });
    let expires = card.expires_at_ms;
    let blocked = Signal::derive(move || {
        actions.now.get() >= expires
            || actions.error.get().is_some()
            || actions.observations.get().contains_key(&blocked_id)
    });
    let payload = RwSignal::new("{}".to_owned());
    let invalid = RwSignal::new(false);
    let resolve_card = card.clone();
    let cancel_card = card.clone();
    view! { <article class="ob-review-card" data-remote-interrupt=id>
        <div class="ob-approval-source"><TechnicalDetails copy=format!("{}\n{}", card.agent_id, card.run_id)><code>{card.agent_id}</code><code>{card.run_id}</code></TechnicalDetails></div>
        <DecisionExpiry requested=card.requested_at_ms expires now=actions.now/>
        <DecisionStatus phase/>
        <div data-untrusted-remote-content=""><h3>{card.untrusted_reason}</h3><p>{card.untrusted_message.unwrap_or_default()}</p>
            <p class="ob-page-intro">{move || t!(i18n, channels.remote_interrupt_caption)}</p></div>
        <Textarea value=payload aria_label=move || t_string!(i18n, channels.remote_interrupt_payload_label).to_owned() disabled=blocked invalid/>
        <Show when=move || invalid.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, channels.remote_interrupt_payload_invalid)}</Notice></Show>
        <footer class="ob-approval-actions">
            <Button variant=ButtonVariant::Primary size=ButtonSize::Small disabled=blocked on_activate=move |_| {
                if blocked.get_untracked() { return; }
                let raw = payload.get_untracked(); let raw = openbot_contracts::text::trim_ecmascript(&raw);
                match if raw.is_empty() { Ok(None) } else { serde_json::from_str(raw).map(Some) } {
                    Ok(value) => { invalid.set(false); actions.answer(resolve_card.clone(), RemoteInterruptAnswer { status: RemoteInterruptAnswerStatus::Resolved, payload: value }); }
                    Err(_) => invalid.set(true),
                }
            }>{move || t!(i18n, channels.remote_interrupt_submit)}</Button>
            <Button variant=ButtonVariant::Ghost size=ButtonSize::Small disabled=blocked on_activate=move |_| actions.answer(cancel_card.clone(), RemoteInterruptAnswer { status: RemoteInterruptAnswerStatus::Cancelled, payload: None })>{move || t!(i18n, channels.remote_interrupt_cancel)}</Button>
        </footer>
    </article> }
}

#[component]
fn DecisionReference(source: SourceReference, phase: Signal<Option<Phase>>) -> impl IntoView {
    view! { <article class="ob-review-card" data-decision-reference=source.id>
        <div class="ob-approval-source"><TechnicalDetails copy={[Some(source.bot.as_str()), Some(source.run.as_str()), source.call.as_deref()].into_iter().flatten().collect::<Vec<_>>().join("\n")}><code>{source.bot}</code><code>{source.run}</code>{source.call.map(|call| view! { <code>{call}</code> })}</TechnicalDetails></div>
        <DecisionStatus phase/>
    </article> }
}

#[component]
fn DecisionStatus(phase: Signal<Option<Phase>>) -> impl IntoView {
    let i18n = use_i18n();
    view! { <Show when=move || phase.get().is_some()><p class="ob-approval-observation" role="status">{move || match phase.get() {
        Some(Phase::Submitting) => t_string!(i18n, common.loading).to_owned(),
        Some(Phase::Confirmed) => t_string!(i18n, admin.attention_answer_recorded).to_owned(),
        Some(Phase::Unknown) => t_string!(i18n, admin.approval_decision_error).to_owned(), None => String::new(),
    }}</p></Show> }
}

#[component]
fn DecisionExpiry(requested: i64, expires: i64, now: RwSignal<i64>) -> impl IntoView {
    let i18n = use_i18n();
    view! { <p class="ob-page-intro">{time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(requested) * 1_000_000).ok().map(|at| view! { <Timestamp at /> " · " })}{move || if now.get() >= expires { t_string!(i18n, admin.approval_expired).to_owned() } else { t_string!(i18n, admin.approval_expires, seconds=(expires.saturating_sub(now.get())/1000)).to_owned() }}</p> }
}
fn milliseconds(time: time::OffsetDateTime) -> i64 {
    i64::try_from(time.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}
fn now_ms() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now().floor() as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        milliseconds(time::OffsetDateTime::now_utc())
    }
}
fn start_clock(now: RwSignal<i64>) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        loop {
            delay().await;
            if now.try_get_untracked().is_none() {
                return;
            }
            now.set(now_ms());
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = now;
}
#[cfg(target_arch = "wasm32")]
async fn delay() {
    let _ = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
        if let Some(window) = web_sys::window() {
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 1000);
        }
    }))
    .await;
}

pub(super) fn binding(value: &impl serde::Serialize) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(serde_json::to_vec(value).expect("closed DTO serializes")).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::components::{ComponentApprovalAnswer, ComponentApprovalDecision};
    use openbot_contracts::ids::BotId;
    fn component() -> PendingComponentHumanDecision {
        let now = time::OffsetDateTime::now_utc();
        PendingComponentHumanDecision {
            decision_id: "component-1".into(),
            run_id: RunId::new("run-1"),
            provider_call_id: "provider-1".into(),
            agent_id: BotId::new("bot-1"),
            component_name: "askApproval".into(),
            arguments: serde_json::json!({"title":"Synthetic approval","summary":"Review original request"}),
            requested_at: now,
            expires_at: now + time::Duration::minutes(5),
        }
    }
    fn answer() -> ComponentHumanDecisionAnswer {
        ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
            decision: ComponentApprovalDecision::Approved,
            note: None,
        })
    }
    fn remote() -> PendingRemoteInterrupt {
        PendingRemoteInterrupt {
            request_id: "018f6f8a-5f4b-7c2d-8a31-111111111111".into(),
            run_id: "run-1".into(),
            agent_id: "bot-1".into(),
            untrusted_reason: "human_input".into(),
            untrusted_message: None,
            untrusted_response_schema: None,
            requested_at_ms: now_ms(),
            expires_at_ms: now_ms() + 300_000,
        }
    }
    #[test]
    fn component_unknown_survives_navigation_and_pending_absence_and_rejects_changed_answer() {
        Owner::new().with(|| {
            let actions = ComponentDecisionActions::new();
            let card = component();
            let answer = answer();
            assert!(actions.install(0, Ok(vec![card.clone()])));
            assert!(actions.begin(&card, &answer));
            assert!(!actions.begin(&card, &answer));
            actions.complete(&card.decision_id, &answer, Err(ApiError::Network));
            assert!(actions.install(0, Ok(Vec::new())));
            assert!(actions.has_for_run(Some(card.run_id.clone())));
            assert!(actions.install(0, Ok(vec![card.clone()])));
            let changed = ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                decision: ComponentApprovalDecision::Declined,
                note: None,
            });
            assert!(!actions.begin(&card, &changed));
            assert_eq!(
                actions.observations.get_untracked()[&card.decision_id].phase,
                Phase::Unknown
            );
            let mut fresh = card.clone();
            fresh.arguments["summary"] = serde_json::json!("changed original body");
            assert_ne!(
                binding(&fresh),
                actions.observations.get_untracked()[&card.decision_id].binding
            );
        });
    }
    #[test]
    fn both_families_hide_on_denial_and_reject_pre_denial_reads_without_unlocking() {
        Owner::new().with(|| {
            let component = component();
            let answer = answer();
            let actions = ComponentDecisionActions::new();
            actions.install(0, Ok(vec![component.clone()]));
            assert!(actions.begin(&component, &answer));
            actions.complete(&component.decision_id, &answer, Err(ApiError::Forbidden));
            assert!(actions.pending.get_untracked().is_empty());
            assert!(!actions.install(0, Ok(vec![component.clone()])));
            assert_eq!(actions.error.get_untracked(), Some(ApiError::Forbidden));
            assert!(actions.install(1, Ok(vec![component.clone()])));
            assert!(!actions.begin(&component, &answer));
            let card = remote();
            let actions = RemoteInterruptActions::new();
            let answer = RemoteInterruptAnswer {
                status: RemoteInterruptAnswerStatus::Resolved,
                payload: None,
            };
            actions.install(0, Ok(vec![card.clone()]));
            assert!(actions.begin(&card, &answer));
            actions.complete(&card.request_id, answer.status, Err(ApiError::Unauthorized));
            assert!(actions.pending.get_untracked().is_empty());
            assert!(!actions.install(0, Ok(vec![card.clone()])));
            assert!(actions.install(1, Ok(vec![card.clone()])));
            assert!(!actions.begin(&card, &answer));
        });
    }
    #[test]
    fn expired_cards_cannot_use_a_stalled_network_clock() {
        Owner::new().with(|| {
            let actions = ComponentDecisionActions::new();
            let mut card = component();
            card.requested_at -= time::Duration::hours(1);
            card.expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
            actions.now.set(0);
            actions.install(0, Ok(vec![card.clone()]));
            assert!(!actions.begin(&card, &answer()));
            let actions = RemoteInterruptActions::new();
            let mut card = remote();
            card.requested_at_ms -= 3_600_000;
            card.expires_at_ms = now_ms() - 1000;
            actions.now.set(0);
            actions.install(0, Ok(vec![card.clone()]));
            assert!(!actions.begin(
                &card,
                &RemoteInterruptAnswer {
                    status: RemoteInterruptAnswerStatus::Resolved,
                    payload: None
                }
            ));
        });
    }
    #[test]
    fn disposed_actor_cannot_complete_into_a_new_actor_with_the_same_ids() {
        let actor_a = Owner::new();
        let component = component();
        let remote = remote();
        let answer = answer();
        let (a_component, a_remote) = actor_a.with(|| {
            let c = ComponentDecisionActions::new();
            c.install(0, Ok(vec![component.clone()]));
            assert!(c.begin(&component, &answer));
            let r = RemoteInterruptActions::new();
            r.install(0, Ok(vec![remote.clone()]));
            assert!(r.begin(
                &remote,
                &RemoteInterruptAnswer {
                    status: RemoteInterruptAnswerStatus::Resolved,
                    payload: None
                }
            ));
            (c, r)
        });
        actor_a.cleanup();
        let actor_b = Owner::new();
        actor_b.with(|| {
            let b_component = ComponentDecisionActions::new();
            let b_remote = RemoteInterruptActions::new();
            a_component.complete(
                &component.decision_id,
                &answer,
                Ok(ComponentHumanDecisionResolved {
                    decision_id: component.decision_id.clone(),
                    answer: answer.clone(),
                    replayed: false,
                }),
            );
            a_remote.complete(
                &remote.request_id,
                RemoteInterruptAnswerStatus::Resolved,
                Ok(RemoteInterruptResolved {
                    request_id: remote.request_id.clone(),
                    status: RemoteInterruptAnswerStatus::Resolved,
                    replayed: false,
                }),
            );
            assert!(b_component.observations.get_untracked().is_empty());
            assert!(b_remote.observations.get_untracked().is_empty());
        });
    }
}
