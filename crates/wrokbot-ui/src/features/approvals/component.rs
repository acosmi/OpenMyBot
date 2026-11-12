//! Interactive current-actor approval page.

use std::collections::BTreeMap;

use crate::shell::layout::set_shell_title;
use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::command::{AppEvent, SubscriptionRequest};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::tool::MAX_PENDING_TOOL_APPROVALS;
use openbot_contracts::tool::{
    ToolApprovalClass, ToolApprovalDecision, ToolApprovalEffect, ToolApprovalResolved,
};
use time::format_description::well_known::Rfc3339;

use super::ApprovalCardView;
use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::decide_tool_approval;
#[cfg(target_arch = "wasm32")]
use crate::api::desktop_transport::{
    DesktopStructuredHandlers, is_tauri_host, open_desktop_structured,
};
#[cfg(target_arch = "wasm32")]
use crate::api::list_pending_tool_approvals;
use crate::features::layout::{PageActions, PageHeader, PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Badge, BadgeTone, Button, ButtonSize, ButtonVariant, EmptyState, IconSize, IconView, Notice,
    NoticePresentation, NoticeTone, TechnicalDetails, Timestamp,
};

#[cfg(target_arch = "wasm32")]
const APPROVAL_ACTIVITY_PROTOCOL: &str = "openbot.tool-approvals.v1";
#[cfg(any(target_arch = "wasm32", test))]
const FIRST_RETRY_MS: u32 = 500;
#[cfg(any(target_arch = "wasm32", test))]
const MAX_RETRY_MS: u32 = 5_000;
#[cfg(target_arch = "wasm32")]
const FALLBACK_REFRESH_SECONDS: u32 = 30;

#[derive(Clone, Copy)]
struct ApprovalRefresh {
    approvals: RwSignal<Vec<ApprovalCardView>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<Option<ApiError>>,
    epoch: RwSignal<u64>,
    #[cfg(target_arch = "wasm32")]
    worker_owner: StoredValue<Option<Owner>>,
}

impl ApprovalRefresh {
    fn request(self) {
        request_refresh(self);
    }

    fn install(self, epoch: u64, result: Result<Vec<ApprovalCardView>, ApiError>) -> bool {
        if self.epoch.try_get_untracked() != Some(epoch) {
            return false;
        }
        match result {
            Ok(cards) => {
                self.approvals.set(cards);
                self.load_error.set(None);
            }
            Err(error) => {
                if matches!(
                    error,
                    ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound
                ) {
                    self.approvals.set(Vec::new());
                }
                self.load_error.set(Some(error));
            }
        }
        self.loading.set(false);
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecisionPhase {
    Submitting,
    Confirmed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecisionObservation {
    decision: ToolApprovalDecision,
    binding: [u8; 32],
    phase: DecisionPhase,
    // Presentation only: a closed notice cannot change or release the decision observation.
    dismissed_binding: Option<[u8; 32]>,
}

/// One authentication owner supplies both current-actor and inline approval surfaces.
#[derive(Clone, Copy)]
pub(crate) struct ToolApprovalActions {
    refresh: ApprovalRefresh,
    now: RwSignal<i64>,
    decisions: RwSignal<BTreeMap<String, DecisionObservation>>,
    retained: RwSignal<BTreeMap<String, ApprovalCardView>>,
}

impl ToolApprovalActions {
    pub(crate) fn has_for_run(self, run: Option<openbot_contracts::ids::RunId>) -> bool {
        run.is_some_and(|run| self.cards().iter().any(|card| card.run_id == run))
    }
    pub(crate) fn new() -> Self {
        let refresh = ApprovalRefresh {
            approvals: RwSignal::new(Vec::new()),
            loading: RwSignal::new(true),
            load_error: RwSignal::new(None),
            epoch: RwSignal::new(0),
            #[cfg(target_arch = "wasm32")]
            worker_owner: StoredValue::new(Owner::current()),
        };
        let actions = Self {
            refresh,
            now: RwSignal::new(now_epoch_seconds()),
            decisions: RwSignal::new(BTreeMap::new()),
            retained: RwSignal::new(BTreeMap::new()),
        };
        start_realtime(refresh, actions.now);
        actions
    }

    fn cards(self) -> Vec<ApprovalCardView> {
        if matches!(
            self.refresh.load_error.get(),
            Some(ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound)
        ) {
            return Vec::new();
        }
        let mut cards = self.retained.get();
        for card in self.refresh.approvals.get() {
            cards.insert(card.approval_id.clone(), card);
        }
        cards.into_values().collect()
    }

    fn begin(self, card: &ApprovalCardView, decision: ToolApprovalDecision) -> bool {
        if self.decisions.try_get_untracked().is_none()
            || self.refresh.loading.get_untracked()
            || self.refresh.load_error.get_untracked().is_some()
            || self
                .decisions
                .with_untracked(|entries| entries.contains_key(&card.approval_id))
            || remaining_seconds(card.expires_at.unix_timestamp(), now_epoch_seconds()) == 0
            || !self
                .refresh
                .approvals
                .with_untracked(|cards| cards.contains(card))
        {
            return false;
        }
        // Only minimal historical source identity is retained when current pending visibility ends.
        let mut reference = card.clone();
        reference.target_kind.clear();
        reference.target_id.clear();
        reference.arguments.clear();
        reference.change = None;
        self.retained.update(|cards| {
            cards.insert(card.approval_id.clone(), reference);
        });
        self.decisions.update(|entries| {
            entries.insert(
                card.approval_id.clone(),
                DecisionObservation {
                    decision,
                    binding: super::attention::binding(card),
                    phase: DecisionPhase::Submitting,
                    dismissed_binding: None,
                },
            );
        });
        true
    }

    fn complete(
        self,
        id: &str,
        decision: ToolApprovalDecision,
        result: Result<ToolApprovalResolved, ApiError>,
    ) {
        let Some(entries) = self.decisions.try_get_untracked() else {
            return;
        };
        if !entries.get(id).is_some_and(|entry| {
            entry.decision == decision && entry.phase == DecisionPhase::Submitting
        }) {
            return;
        }
        let confirmed = matches!(result, Ok(ref receipt) if receipt.approval_id == id && receipt.decision == decision);
        if let Err(error @ (ApiError::Unauthorized | ApiError::Forbidden)) = result {
            self.refresh.load_error.set(Some(error));
            self.refresh.approvals.set(Vec::new());
        }
        self.decisions.update(|entries| {
            if let Some(entry) = entries.get_mut(id) {
                entry.phase = if confirmed {
                    DecisionPhase::Confirmed
                } else {
                    DecisionPhase::Unknown
                };
            }
        });
        // A pending-list refresh is an observation, never permission to clear Unknown and resend.
        self.refresh.request();
    }

    fn dismiss_notice(self, id: &str, binding: [u8; 32]) -> bool {
        let Some(error) = self.refresh.load_error.try_get_untracked() else {
            return false;
        };
        if matches!(
            error,
            Some(ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound)
        ) {
            return false;
        }
        let Some(pending) = self.refresh.approvals.try_get_untracked() else {
            return false;
        };
        let card = pending
            .into_iter()
            .find(|card| card.approval_id == id)
            .or_else(|| self.retained.try_get_untracked()?.remove(id));
        let Some(card) = card else {
            return false;
        };
        // An old surface must not close a notice for a refreshed object with the same id.
        if super::attention::binding(&card) != binding {
            return false;
        }
        self.decisions
            .try_update(|entries| {
                let Some(entry) = entries.get_mut(id) else {
                    return false;
                };
                if entry.phase != DecisionPhase::Unknown
                    && (card.arguments.is_empty() || entry.binding == binding)
                {
                    return false;
                }
                entry.dismissed_binding = Some(binding);
                true
            })
            .unwrap_or(false)
    }

    fn decide(self, card: ApprovalCardView, decision: ToolApprovalDecision) {
        if !self.begin(&card, decision) {
            return;
        }
        #[cfg(target_arch = "wasm32")]
        {
            let start_worker = || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let result = decide_tool_approval(&card.approval_id, decision).await;
                    self.complete(&card.approval_id, decision, result);
                })
            };
            match self.refresh.worker_owner.get_value() {
                Some(owner) => owner.with(start_worker),
                None => start_worker(),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        self.complete(&card.approval_id, decision, Err(ApiError::Unavailable));
    }
}

/// Current-actor list page for pending durable tool approvals.
#[component]
pub fn ApprovalPage() -> impl IntoView {
    let i18n = use_i18n();
    set_shell_title(move || vec![t_string!(i18n, admin.nav_approvals).to_owned()]);
    let actions = expect_context::<ToolApprovalActions>();
    let refresh = actions.refresh;
    let loading = refresh.loading;
    let load_error = refresh.load_error;

    let refresh_page = move |_| {
        refresh.request();
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageActions>
                <Button
                    variant=ButtonVariant::Chip
                    size=ButtonSize::Medium
                    disabled=loading
                    loading=loading
                    on_activate=refresh_page
                >
                    <IconView icon=Icon::RefreshCw size=IconSize::Inline />
                    {move || t!(i18n, common.refresh)}
                </Button>
            </PageActions>
            <PageHeader
                heading_id="approvals-title"
                title=move || t_string!(i18n, admin.nav_approvals).to_owned()
                title_in_top_bar=true
                description=move || t_string!(i18n, admin.approvals_intro).to_owned()
            />

            <super::attention::DecisionAttention/>

            <Show when=move || load_error.get().is_some()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, admin.approval_load_error)}</span>
                </Notice>
            </Show>

            {move || {
                if loading.get() && actions.cards().is_empty() {
                    view! {
                        <div class="ob-loading" role="status">
                            <IconView icon=Icon::LoaderCircle size=IconSize::Navigation />
                            <span>{t!(i18n, common.loading)}</span>
                        </div>
                    }
                    .into_any()
                } else if load_error.get().is_some() && actions.cards().is_empty() {
                    ().into_any()
                } else if actions.cards().is_empty() {
                    view! {
                        <EmptyState
                            heading_id="approval-empty-title"
                            title=move || t_string!(i18n, admin.approval_empty_title)
                            body=move || t_string!(i18n, admin.approval_empty_body)
                        />
                    }
                    .into_any()
                } else {
                    view! {
                        <div class="ob-approval-list">
                            <For
                                each=move || actions.cards()
                                key=|card| (card.approval_id.clone(), super::attention::binding(card))
                                children=move |card| {
                                    view! {
                                        <ApprovalCard
                                            card
                                            actions
                                        />
                                    }
                                }
                            />
                        </div>
                    }
                    .into_any()
                }
            }}
        </PageShell>
    }
}

/// The conversation uses precisely the same objects and operation observations as the list page.
#[component]
pub(crate) fn InlineToolApprovals(
    run: Signal<Option<openbot_contracts::ids::RunId>>,
) -> impl IntoView {
    let actions = expect_context::<ToolApprovalActions>();
    view! {
        <div class="ob-inline-approvals">
            <For
                each={move || actions.cards().into_iter().filter(|card| run.get().as_ref() == Some(&card.run_id)).collect::<Vec<_>>()}
                key=|card| (card.approval_id.clone(), super::attention::binding(card))
                children=move |card| view! { <ApprovalCard card actions /> }
            />
        </div>
    }
}

#[component]
fn ApprovalCard(card: ApprovalCardView, actions: ToolApprovalActions) -> impl IntoView {
    let i18n = use_i18n();
    let current_binding = super::attention::binding(&card);
    let current_details = !card.arguments.is_empty();
    let heading_id = approval_heading_id(&card.approval_id);
    let arguments_id = format!("{heading_id}-arguments");
    let article_heading_id = heading_id.clone();
    let payload_heading_id = arguments_id.clone();
    let approval_id = card.approval_id.clone();
    let grant_card = card.clone();
    let deny_card = card.clone();
    let dismiss_id = StoredValue::new(approval_id.clone());
    let expires_at = card.expires_at;
    let expires_datetime = card
        .expires_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| card.expires_at.unix_timestamp().to_string());
    let pending_id = approval_id.clone();
    let observation = Signal::derive(move || {
        actions.decisions.with(|entries| {
            entries.get(&pending_id).copied().map(|mut row| {
                if current_details && row.binding != current_binding {
                    row.phase = DecisionPhase::Unknown;
                }
                row
            })
        })
    });
    let is_loading = Signal::derive(move || {
        observation
            .get()
            .is_some_and(|value| value.phase == DecisionPhase::Submitting)
    });
    let is_expired = Signal::derive(move || {
        remaining_seconds(expires_at.unix_timestamp(), actions.now.get()) == 0
    });
    let unavailable = Signal::derive(move || {
        observation.get().is_some()
            || is_expired.get()
            || actions.refresh.loading.get()
            || actions.refresh.load_error.get().is_some()
    });

    let grant = move |_| {
        actions.decide(grant_card.clone(), ToolApprovalDecision::Grant);
    };
    let deny = move |_| {
        actions.decide(deny_card.clone(), ToolApprovalDecision::Deny);
    };
    let dismiss_notice = move |_| {
        if let Some(id) = dismiss_id.try_get_value() {
            actions.dismiss_notice(&id, current_binding);
        }
    };
    let effect = card.effect;
    let approval_class = card.approval_class;
    let server = card.server.clone();
    let change = card.change.clone();
    view! {
        <article class="ob-approval-card" aria-labelledby=article_heading_id data-approval-id=approval_id>
            <header class="ob-approval-card-header">
                <div class="ob-approval-title-group">
                    <IconView icon=Icon::ShieldCheck size=IconSize::Navigation />
                    <div>
                        <h2 id=heading_id class="ob-approval-title">{card.tool_title}</h2>
                        {server.map(|server| view! { <p class="ob-approval-server">{server}</p> })}
                    </div>
                </div>
                <Badge tone=BadgeTone::Caution>
                    {move || effect_label(i18n, effect)}
                </Badge>
            </header>

            <div class="ob-approval-source">
                <Timestamp at=card.requested_at />
                <TechnicalDetails copy=format!("{}\n{}\n{}", card.bot_id.as_str(), card.run_id.as_str(), card.call_id.as_str())>
                    <code>{card.bot_id.as_str().to_owned()}</code>
                    <code>{card.run_id.as_str().to_owned()}</code>
                    <code>{card.call_id.as_str().to_owned()}</code>
                </TechnicalDetails>
            </div>
            <Show when=move || observation.get().is_some()>
                <p class="ob-approval-observation" role="status">{move || match observation.get() {
                    Some(DecisionObservation { phase: DecisionPhase::Submitting, .. }) => t_string!(i18n, common.loading).to_owned(),
                    Some(DecisionObservation { phase: DecisionPhase::Unknown, .. }) => t_string!(i18n, common.unknown).to_owned(),
                    Some(DecisionObservation { decision: ToolApprovalDecision::Grant, phase: DecisionPhase::Confirmed, .. }) => t_string!(i18n, admin.approval_granted).to_owned(),
                    Some(DecisionObservation { decision: ToolApprovalDecision::Deny, phase: DecisionPhase::Confirmed, .. }) => t_string!(i18n, admin.approval_denied).to_owned(),
                    None => String::new(),
                }}</p>
            </Show>
            <Show when=move || observation.get().is_some_and(|value| value.phase == DecisionPhase::Unknown && value.dismissed_binding != Some(current_binding))>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                    <span>{move || t!(i18n, admin.approval_decision_error)}</span>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        on_activate=dismiss_notice
                    >
                        {move || t!(i18n, common.close)}
                    </Button>
                </Notice>
            </Show>

            {current_details.then(|| view! {
            <dl class="ob-approval-facts">
                <div class="ob-approval-fact">
                    <dt>{move || t!(i18n, admin.approval_effect)}</dt>
                    <dd>{move || effect_label(i18n, effect)}</dd>
                </div>
                <div class="ob-approval-fact">
                    <dt>{move || t!(i18n, admin.approval_target)}</dt>
                    <dd>
                        <span class="ob-target-kind">{card.target_kind}</span>
                        <code class="ob-target-id">{card.target_id}</code>
                    </dd>
                </div>
                <div class="ob-approval-fact">
                    <dt>{move || t!(i18n, admin.approval_reuse)}</dt>
                    <dd>{move || approval_class_label(i18n, approval_class)}</dd>
                </div>
                <div class="ob-approval-fact">
                    <dt>
                        <IconView icon=Icon::Clock size=IconSize::Inline />
                        <span class="ob-visually-hidden">{move || t!(i18n, admin.approval_expiry)}</span>
                    </dt>
                    <dd>
                        <time datetime=expires_datetime>
                            {move || {
                                let seconds = remaining_seconds(expires_at.unix_timestamp(), actions.now.get());
                                if seconds == 0 {
                                    t_string!(i18n, admin.approval_expired).to_owned()
                                } else {
                                    t_string!(i18n, admin.approval_expires, seconds = seconds)
                                }
                            }}
                        </time>
                    </dd>
                </div>
            </dl>

            <section class="ob-approval-payload" aria-labelledby=payload_heading_id>
                <h3 id=arguments_id>
                    {move || t!(i18n, admin.approval_arguments)}
                </h3>
                <pre><code>{card.arguments}</code></pre>
            </section>
            {change.map(|change| view! {
                <section class="ob-approval-payload">
                    <h3>{move || t!(i18n, admin.approval_change)}</h3>
                    <pre><code>{change}</code></pre>
                </section>
            })}
            })}

            <footer class="ob-approval-actions">
                <Button
                    variant=ButtonVariant::DangerText
                    size=ButtonSize::Medium
                    disabled=unavailable
                    loading=is_loading
                    on_activate=deny
                >
                    <IconView icon=Icon::X size=IconSize::Inline />
                    {move || t!(i18n, admin.approval_reject)}
                </Button>
                <Button
                    variant=ButtonVariant::Primary
                    size=ButtonSize::Medium
                    disabled=unavailable
                    loading=is_loading
                    on_activate=grant
                >
                    <IconView icon=Icon::Check size=IconSize::Inline />
                    {move || t!(i18n, admin.approval_approve)}
                </Button>
            </footer>
        </article>
    }
}

fn request_refresh(refresh: ApprovalRefresh) {
    let Some(epoch) = refresh.epoch.try_get_untracked() else {
        return;
    };
    let Some(request_epoch) = next_refresh_epoch(epoch) else {
        refresh.loading.set(false);
        if refresh.load_error.get_untracked().is_none() {
            refresh.load_error.set(Some(ApiError::Unavailable));
        }
        return;
    };
    refresh.epoch.set(request_epoch);
    refresh.loading.set(true);
    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                refresh_page(refresh, request_epoch).await;
            });
        };
        match refresh.worker_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let error = refresh
            .load_error
            .get_untracked()
            .unwrap_or(ApiError::Unavailable);
        refresh.install(request_epoch, Err(error));
    }
}

fn start_realtime(refresh: ApprovalRefresh, now: RwSignal<i64>) {
    refresh.request();
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        let mut elapsed_seconds = 0_u32;
        loop {
            delay_ms(1_000).await;
            now.set(now_epoch_seconds());
            elapsed_seconds = elapsed_seconds.saturating_add(1);
            if elapsed_seconds >= FALLBACK_REFRESH_SECONDS {
                elapsed_seconds = 0;
                refresh.request();
            }
        }
    });
    #[cfg(target_arch = "wasm32")]
    install_approval_socket(refresh);
    #[cfg(not(target_arch = "wasm32"))]
    {
        refresh.loading.set(false);
        refresh.load_error.set(Some(ApiError::Unavailable));
        let _ = (refresh.approvals, now, refresh.epoch);
    }
}

#[cfg(target_arch = "wasm32")]
async fn delay_ms(milliseconds: u32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        web_sys::window()
            .expect("CSR approval realtime requires Window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                &resolve,
                i32::try_from(milliseconds).unwrap_or(i32::MAX),
            )
            .expect("browser rejected approval realtime timer");
    });
    _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[cfg(target_arch = "wasm32")]
fn install_approval_socket(refresh: ApprovalRefresh) {
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        use futures_util::StreamExt as _;
        use gloo_net::websocket::{Message, futures::WebSocket};
        use openbot_contracts::tool::ToolApprovalActivityEvent;

        let mut retry = FIRST_RETRY_MS;
        loop {
            // The socket has no replay cursor. Refetch before every connection/reconnection.
            refresh.request();
            if is_tauri_host() {
                let handlers = DesktopStructuredHandlers::new(
                    move |event| match event {
                        AppEvent::ToolApprovalActivity(event)
                            if event.pending_count <= MAX_PENDING_TOOL_APPROVALS =>
                        {
                            refresh.request();
                            true
                        }
                        AppEvent::ToolApprovalActivity(_)
                        | AppEvent::ToolApprovalStreamError { .. } => {
                            refresh.request();
                            false
                        }
                        AppEvent::Heartbeat { .. }
                        | AppEvent::ThreadRunEvent(_)
                        | AppEvent::ThreadStreamError { .. }
                        | AppEvent::ChannelActivity(_)
                        | AppEvent::ChannelStreamError { .. } => false,
                    },
                    move |_| refresh.request(),
                    move || refresh.request(),
                );
                match open_desktop_structured(SubscriptionRequest::ToolApprovalActivity, handlers) {
                    Ok(connection) => {
                        retry = FIRST_RETRY_MS;
                        connection.finished().await;
                    }
                    Err(()) => {
                        delay_ms(retry).await;
                        retry = next_retry(retry);
                        continue;
                    }
                }
                delay_ms(retry).await;
                retry = next_retry(retry);
                continue;
            }
            let Some(url) = approval_socket_url() else {
                delay_ms(retry).await;
                retry = next_retry(retry);
                continue;
            };
            let Ok(mut socket) = WebSocket::open_with_protocol(&url, APPROVAL_ACTIVITY_PROTOCOL)
            else {
                delay_ms(retry).await;
                retry = next_retry(retry);
                continue;
            };
            while let Some(message) = socket.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        let event = serde_json::from_str::<ToolApprovalActivityEvent>(&text);
                        if !matches!(event, Ok(event) if event.pending_count <= MAX_PENDING_TOOL_APPROVALS)
                        {
                            refresh.request();
                            break;
                        }
                        retry = FIRST_RETRY_MS;
                        refresh.request();
                    }
                    Ok(Message::Bytes(_)) | Err(_) => {
                        refresh.request();
                        break;
                    }
                }
            }
            delay_ms(retry).await;
            retry = next_retry(retry);
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn approval_socket_url() -> Option<String> {
    let location = web_sys::window()?.location();
    let protocol = match location.protocol().ok()?.as_str() {
        "https:" => "wss:",
        "http:" => "ws:",
        _ => return None,
    };
    Some(format!(
        "{protocol}//{}/api/tool-approvals/events",
        location.host().ok()?
    ))
}

#[cfg(any(target_arch = "wasm32", test))]
fn next_retry(current: u32) -> u32 {
    current.saturating_mul(2).min(MAX_RETRY_MS)
}

fn next_refresh_epoch(current: u64) -> Option<u64> {
    current.checked_add(1)
}

#[cfg(target_arch = "wasm32")]
async fn refresh_page(refresh: ApprovalRefresh, request_epoch: u64) {
    let result = list_pending_tool_approvals().await;
    refresh.install(
        request_epoch,
        result.map(|page| {
            page.approvals
                .iter()
                .map(ApprovalCardView::from_pending)
                .collect()
        }),
    );
}

fn effect_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    effect: ToolApprovalEffect,
) -> String {
    match effect {
        ToolApprovalEffect::Write => t_string!(i18n, admin.approval_effect_write).to_owned(),
        ToolApprovalEffect::Execute => t_string!(i18n, admin.approval_effect_execute).to_owned(),
        ToolApprovalEffect::Network => t_string!(i18n, admin.approval_effect_network).to_owned(),
        ToolApprovalEffect::Credential => {
            t_string!(i18n, admin.approval_effect_credential).to_owned()
        }
    }
}

fn approval_class_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    class: ToolApprovalClass,
) -> String {
    match class {
        ToolApprovalClass::OncePerRun => t_string!(i18n, admin.approval_once_per_run).to_owned(),
        ToolApprovalClass::EveryCall => t_string!(i18n, admin.approval_every_call).to_owned(),
    }
}

fn remaining_seconds(expires_at: i64, now: i64) -> i64 {
    expires_at.saturating_sub(now).max(0)
}

fn approval_heading_id(approval_id: &str) -> String {
    use core::fmt::Write as _;

    let mut id = String::from("approval-");
    for byte in approval_id.bytes() {
        write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
    }
    id
}

#[cfg(target_arch = "wasm32")]
fn now_epoch_seconds() -> i64 {
    (js_sys::Date::now() / 1_000.0).floor() as i64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_epoch_seconds() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> ApprovalCardView {
        ApprovalCardView::from_pending(&openbot_contracts::tool::PendingToolApproval {
            approval_id: "approval-1".into(),
            call_id: openbot_contracts::ids::ToolCallId::new("call-1"),
            run_id: openbot_contracts::ids::RunId::new("run-1"),
            bot_id: openbot_contracts::ids::BotId::new("bot-1"),
            tool_name: "mcp__files__write_file".into(),
            target_kind: "mcp_tool".into(),
            target_id: "files/write_file".into(),
            effect: ToolApprovalEffect::Write,
            approval_class: ToolApprovalClass::EveryCall,
            arguments_summary: serde_json::json!({"target":"original"}),
            change_summary: None,
            requested_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
        })
    }

    #[test]
    fn tool_unknown_never_unlocks_on_absence_changed_target_or_failed_read() {
        let owner = Owner::new();
        owner.with(|| {
            let actions = ToolApprovalActions::new();
            let card = card();
            actions.refresh.install(
                actions.refresh.epoch.get_untracked(),
                Ok(vec![card.clone()]),
            );
            assert!(actions.begin(&card, ToolApprovalDecision::Grant));
            assert!(!actions.begin(&card, ToolApprovalDecision::Deny));
            actions.complete(
                &card.approval_id,
                ToolApprovalDecision::Grant,
                Err(ApiError::Unavailable),
            );
            let epoch = actions.refresh.epoch.get_untracked();
            actions.refresh.install(epoch, Ok(Vec::new()));
            assert_eq!(actions.cards().len(), 1);
            assert!(actions.cards()[0].arguments.is_empty());
            assert_eq!(
                actions.decisions.get_untracked()[&card.approval_id].phase,
                DecisionPhase::Unknown
            );
            assert!(!actions.begin(&card, ToolApprovalDecision::Grant));
            let mut changed = card.clone();
            changed.target_id = "files/new_target".into();
            actions.refresh.install(epoch, Ok(vec![changed.clone()]));
            assert_ne!(
                actions.decisions.get_untracked()[&card.approval_id].binding,
                super::super::attention::binding(&changed)
            );
            assert!(!actions.begin(&changed, ToolApprovalDecision::Grant));
            actions.refresh.install(epoch, Err(ApiError::Forbidden));
            assert!(actions.cards().is_empty());
            assert_eq!(
                actions.decisions.get_untracked()[&card.approval_id].phase,
                DecisionPhase::Unknown
            );
        });
    }

    #[test]
    fn closing_one_unknown_notice_keeps_both_locks_and_rejects_stale_bindings() {
        let owner = Owner::new();
        owner.with(|| {
            let actions = ToolApprovalActions::new();
            let first = card();
            let mut second = first.clone();
            second.approval_id = "approval-2".into();
            actions.refresh.install(
                actions.refresh.epoch.get_untracked(),
                Ok(vec![first.clone(), second.clone()]),
            );
            assert!(actions.begin(&first, ToolApprovalDecision::Grant));
            assert!(actions.begin(&second, ToolApprovalDecision::Deny));
            for (card, decision) in [
                (&first, ToolApprovalDecision::Grant),
                (&second, ToolApprovalDecision::Deny),
            ] {
                actions.complete(&card.approval_id, decision, Err(ApiError::Unavailable));
            }
            let epoch = actions.refresh.epoch.get_untracked();
            actions
                .refresh
                .install(epoch, Ok(vec![first.clone(), second.clone()]));
            let binding = super::super::attention::binding(&first);
            let before = actions.decisions.get_untracked();
            assert!(actions.dismiss_notice(&first.approval_id, binding));
            let after = actions.decisions.get_untracked();
            assert_eq!(after[&second.approval_id], before[&second.approval_id]);
            let first_before = before[&first.approval_id];
            let first_after = after[&first.approval_id];
            assert_eq!(
                (first_after.decision, first_after.binding, first_after.phase),
                (
                    first_before.decision,
                    first_before.binding,
                    first_before.phase
                )
            );
            assert_eq!(first_after.dismissed_binding, Some(binding));
            assert_eq!(actions.refresh.epoch.get_untracked(), epoch);
            for card in [&first, &second] {
                assert!(!actions.begin(card, ToolApprovalDecision::Grant));
                assert!(!actions.begin(card, ToolApprovalDecision::Deny));
            }

            let mut changed = first.clone();
            changed.arguments = "{\"target\":\"refreshed\"}".into();
            let changed_binding = super::super::attention::binding(&changed);
            assert_ne!(binding, changed_binding);
            actions
                .refresh
                .install(epoch, Ok(vec![changed.clone(), second]));
            assert!(!actions.dismiss_notice(&first.approval_id, binding));
            assert_ne!(
                actions.decisions.get_untracked()[&first.approval_id].dismissed_binding,
                Some(changed_binding)
            );
            assert!(actions.dismiss_notice(&changed.approval_id, changed_binding));
            assert!(!actions.begin(&changed, ToolApprovalDecision::Grant));
            assert!(!actions.begin(&changed, ToolApprovalDecision::Deny));
        });
    }

    #[test]
    fn notice_close_does_not_affect_submitting_confirmed_or_another_actor() {
        for decision in [ToolApprovalDecision::Grant, ToolApprovalDecision::Deny] {
            let owner = Owner::new();
            let (actions, card, binding) = owner.with(|| {
                let actions = ToolApprovalActions::new();
                let card = card();
                let binding = super::super::attention::binding(&card);
                actions.refresh.install(
                    actions.refresh.epoch.get_untracked(),
                    Ok(vec![card.clone()]),
                );
                assert!(actions.begin(&card, decision));
                assert!(!actions.dismiss_notice(&card.approval_id, binding));
                actions.complete(
                    &card.approval_id,
                    decision,
                    Ok(ToolApprovalResolved {
                        approval_id: card.approval_id.clone(),
                        decision,
                    }),
                );
                actions.refresh.install(
                    actions.refresh.epoch.get_untracked(),
                    Ok(vec![card.clone()]),
                );
                assert!(!actions.dismiss_notice(&card.approval_id, binding));
                assert_eq!(
                    actions.decisions.get_untracked()[&card.approval_id].phase,
                    DecisionPhase::Confirmed
                );
                assert_eq!(
                    actions.decisions.get_untracked()[&card.approval_id].dismissed_binding,
                    None
                );
                (actions, card, binding)
            });
            owner.cleanup();
            assert!(!actions.dismiss_notice(&card.approval_id, binding));
        }
        let owner = Owner::new();
        owner.with(|| {
            let actions = ToolApprovalActions::new();
            let card = card();
            actions.refresh.install(
                actions.refresh.epoch.get_untracked(),
                Ok(vec![card.clone()]),
            );
            assert!(actions.begin(&card, ToolApprovalDecision::Grant));
            actions.complete(
                &card.approval_id,
                ToolApprovalDecision::Grant,
                Err(ApiError::Forbidden),
            );
            assert!(
                !actions.dismiss_notice(&card.approval_id, super::super::attention::binding(&card))
            );
            assert_eq!(
                actions.decisions.get_untracked()[&card.approval_id].dismissed_binding,
                None
            );
        });
    }

    #[test]
    fn tool_write_denial_invalidates_pre_denial_pending_and_disposed_actor() {
        for error in [ApiError::Unauthorized, ApiError::Forbidden] {
            let owner = Owner::new();
            let (actions, card, old_epoch) = owner.with(|| {
                let actions = ToolApprovalActions::new();
                let card = card();
                let old_epoch = actions.refresh.epoch.get_untracked();
                actions.refresh.install(old_epoch, Ok(vec![card.clone()]));
                assert!(actions.begin(&card, ToolApprovalDecision::Grant));
                actions.complete(&card.approval_id, ToolApprovalDecision::Grant, Err(error));
                assert!(!actions.refresh.install(old_epoch, Ok(vec![card.clone()])));
                assert!(actions.cards().is_empty());
                assert!(!actions.begin(&card, ToolApprovalDecision::Deny));
                (actions, card, old_epoch)
            });
            owner.cleanup();
            assert!(!actions.refresh.install(old_epoch, Ok(vec![card.clone()])));
            actions.complete(
                &card.approval_id,
                ToolApprovalDecision::Grant,
                Ok(ToolApprovalResolved {
                    approval_id: card.approval_id.clone(),
                    decision: ToolApprovalDecision::Grant,
                }),
            );
        }
    }

    #[test]
    fn expiry_is_inclusive_and_dom_ids_are_closed() {
        assert_eq!(remaining_seconds(101, 100), 1);
        assert_eq!(remaining_seconds(100, 100), 0);
        assert_eq!(remaining_seconds(99, 100), 0);
        let id = approval_heading_id("a / b");
        assert_eq!(id, "approval-61202f2062");
        assert!(
            id.chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
        );
        assert_eq!(next_retry(FIRST_RETRY_MS), 1_000);
        assert_eq!(next_retry(MAX_RETRY_MS), MAX_RETRY_MS);
        assert_eq!(next_refresh_epoch(0), Some(1));
        assert_eq!(next_refresh_epoch(u64::MAX), None);
    }
}
