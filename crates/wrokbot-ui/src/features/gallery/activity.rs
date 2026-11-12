//! Policy-governed Activity report renderer backed by build-owned deployment reads.

#![cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]

use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::components::SHOW_ACTIVITY_REPORT_COMPONENT_NAME;
use openbot_contracts::components::{
    BOT_ACTIVITY_FUNCTION_NAME, BotActivityReport, ComponentDecisionRefusal, ComponentFunctionCall,
    ComponentFunctionData, RECENT_REFUSALS_FUNCTION_NAME, RecentRefusalsReport,
};
use openbot_contracts::ids::BotId;

#[cfg(target_arch = "wasm32")]
use crate::api::call_component_function;
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Notice, NoticePresentation, NoticeTone, Timestamp,
};

use super::GalleryFrame;

/// Closed report choice from the `showActivityReport` schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityReportKind {
    /// Count Bot actions over a bounded day window.
    Activity,
    /// Show bounded recent refusal facts.
    Refusals,
}

impl ActivityReportKind {
    /// Build-owned function selected by this report; the model cannot choose an arbitrary name.
    #[must_use]
    pub const fn function(self) -> &'static str {
        match self {
            Self::Activity => BOT_ACTIVITY_FUNCTION_NAME,
            Self::Refusals => RECENT_REFUSALS_FUNCTION_NAME,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ActivityState {
    Reading,
    Refused(ComponentDecisionRefusal),
    Failed,
    Activity(BotActivityReport),
    Refusals(RecentRefusalsReport),
}

/// Runtime Activity component. It never appears in Settings preview because mounting performs a read.
#[component]
pub fn ActivityReportCard(
    agent_id: BotId,
    report: ActivityReportKind,
    title: Option<String>,
    days: Option<f64>,
    on_ask: UnsyncCallback<String>,
    ask_disabled: Signal<bool>,
) -> impl IntoView {
    let i18n = use_i18n();
    let state = RwSignal::new(ActivityState::Reading);
    let title = StoredValue::new(title.unwrap_or_default());

    #[cfg(target_arch = "wasm32")]
    {
        let agent_id = StoredValue::new(agent_id);
        Effect::new(move |_| {
            state.set(ActivityState::Reading);
            let args = match (report, days) {
                (ActivityReportKind::Activity, Some(days)) => serde_json::json!({"days": days}),
                _ => serde_json::json!({}),
            };
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let result = call_component_function(
                    SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
                    &agent_id.get_value(),
                    report.function(),
                    args,
                )
                .await;
                state.set(match result {
                    Ok(result) => project_result(report, result),
                    Err(_) => ActivityState::Failed,
                });
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (agent_id, days);

    view! {
        {move || match state.get() {
            ActivityState::Reading => view! {
                <GalleryFrame
                    title=runtime_title(i18n, title.get_value(), report)
                    caption=t_string!(i18n, gallery.activity_reading_caption).to_owned()
                >
                    <p class="ob-gallery-activity-state" role="status">{t!(i18n, gallery.activity_reading)}</p>
                </GalleryFrame>
            }.into_any(),
            ActivityState::Refused(refusal) => view! {
                <GalleryFrame title=runtime_title(i18n, title.get_value(), report)>
                    <div class="ob-gallery-activity-refused" role="status">
                        <p>{t!(i18n, gallery.activity_not_shown)}</p>
                        <span>{refusal_label(i18n, &refusal)}</span>
                    </div>
                </GalleryFrame>
            }.into_any(),
            ActivityState::Failed => view! {
                <GalleryFrame title=runtime_title(i18n, title.get_value(), report)>
                    <Notice tone=NoticeTone::Caution presentation=NoticePresentation::Inline>{t!(i18n, gallery.activity_read_failed)}</Notice>
                </GalleryFrame>
            }.into_any(),
            ActivityState::Activity(data) => view! {
                <BotActivityView
                    title=runtime_title(i18n, title.get_value(), report)
                    data
                    on_ask
                    ask_disabled
                />
            }.into_any(),
            ActivityState::Refusals(data) => view! {
                <RecentRefusalsView
                    title=runtime_title(i18n, title.get_value(), report)
                    data
                    on_ask
                    ask_disabled
                />
            }.into_any(),
        }}
    }
}

fn project_result(report: ActivityReportKind, result: ComponentFunctionCall) -> ActivityState {
    if let Some(refusal) = result.refusal {
        return ActivityState::Refused(refusal);
    }
    if result.error.is_some() {
        return ActivityState::Failed;
    }
    match (report, result.data) {
        (ActivityReportKind::Activity, Some(ComponentFunctionData::BotActivity(data))) => {
            ActivityState::Activity(data)
        }
        (ActivityReportKind::Refusals, Some(ComponentFunctionData::RecentRefusals(data))) => {
            ActivityState::Refusals(data)
        }
        _ => ActivityState::Failed,
    }
}

#[component]
fn BotActivityView(
    title: String,
    data: BotActivityReport,
    on_ask: UnsyncCallback<String>,
    ask_disabled: Signal<bool>,
) -> impl IntoView {
    let i18n = use_i18n();
    let most = data.rows.first().map_or(0, |row| row.actions);
    let busiest = StoredValue::new(data.rows.first().map(|row| row.bot.clone()));
    let action = view! {
        <Show when=move || busiest.get_value().is_some()>
            <Button
                variant=ButtonVariant::Chip
                size=ButtonSize::Small
                disabled=ask_disabled
                on_activate=move |_| {
                    if let Some(bot) = busiest.get_value() {
                        on_ask.run(busiest_follow_up(&bot));
                    }
                }
            >{t!(i18n, gallery.activity_ask_busiest)}</Button>
        </Show>
    }
    .into_any();
    let days = data.days;
    let rows = RwSignal::new(data.rows);
    view! {
        <GalleryFrame
            title
            caption=move || t_string!(i18n, gallery.activity_bot_caption, days = days).to_owned()
            action
        >
            <Show
                when=move || !rows.get().is_empty()
                fallback=move || view! {
                    <p class="ob-gallery-empty-copy">
                        {move || t_string!(i18n, gallery.activity_bot_empty, days = days).to_owned()}
                    </p>
                }
            >
                <ul class="ob-gallery-activity-bars">
                    <For
                        each=move || rows.get().into_iter().enumerate()
                        key=|(index, _)| *index
                        children=move |(index, row)| {
                            let width = activity_width(row.actions, most);
                            view! {
                                <li>
                                    <span>{row.bot}</span>
                                    <span class="ob-gallery-activity-track" aria-hidden="true">
                                        <span
                                            data-series=(index % 5).to_string()
                                            style:width=format!("{width}%")
                                        ></span>
                                    </span>
                                    <strong>{row.actions}</strong>
                                </li>
                            }
                        }
                    />
                </ul>
            </Show>
        </GalleryFrame>
    }
}

#[component]
fn RecentRefusalsView(
    title: String,
    data: RecentRefusalsReport,
    on_ask: UnsyncCallback<String>,
    ask_disabled: Signal<bool>,
) -> impl IntoView {
    let i18n = use_i18n();
    let has_rows = !data.rows.is_empty();
    let action = view! {
        <Show when=move || has_rows>
            <Button
                variant=ButtonVariant::Chip
                size=ButtonSize::Small
                disabled=ask_disabled
                on_activate=move |_| on_ask.run(REFUSAL_FOLLOW_UP.to_owned())
            >{t!(i18n, gallery.activity_explain_latest)}</Button>
        </Show>
    }
    .into_any();
    let rows = RwSignal::new(data.rows);
    view! {
        <GalleryFrame
            title
            caption=move || t_string!(i18n, gallery.activity_refusals_caption).to_owned()
            action
        >
            <Show
                when=move || !rows.get().is_empty()
                fallback=move || view! {
                    <p class="ob-gallery-empty-copy">{t!(i18n, gallery.activity_refusals_empty)}</p>
                }
            >
                <ul class="ob-gallery-refusal-list">
                    <For
                        each=move || rows.get().into_iter().enumerate()
                        key=|(index, _)| *index
                        children=move |(_, row)| {
                            let when = row.at;
                            let has_bot = row.bot.is_some();
                            let bot = StoredValue::new(row.bot.unwrap_or_default());
                            let has_reason = row.reason.is_some();
                            let reason = StoredValue::new(row.reason.unwrap_or_default());
                            view! {
                                <li>
                                    <div>
                                        <code>{row.what}</code>
                                        <Show when=move || has_bot>
                                            <span>{move || bot.get_value()}</span>
                                        </Show>
                                        <Timestamp at=when />
                                    </div>
                                    <Show when=move || has_reason>
                                        <p>{move || reason.get_value()}</p>
                                    </Show>
                                </li>
                            }
                        }
                    />
                </ul>
            </Show>
        </GalleryFrame>
    }
}

fn runtime_title(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    title: String,
    report: ActivityReportKind,
) -> String {
    if !title.is_empty() {
        return title;
    }
    match report {
        ActivityReportKind::Activity => t_string!(i18n, gallery.activity_bot_title).to_owned(),
        ActivityReportKind::Refusals => t_string!(i18n, gallery.activity_refusals_title).to_owned(),
    }
}

fn refusal_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    refusal: &ComponentDecisionRefusal,
) -> String {
    match refusal {
        ComponentDecisionRefusal::FunctionActorNotAuthorized { .. } => {
            t_string!(i18n, gallery.activity_refused_actor).to_owned()
        }
        ComponentDecisionRefusal::FunctionPolicyRefused { .. } => {
            t_string!(i18n, gallery.activity_refused_policy).to_owned()
        }
        ComponentDecisionRefusal::FunctionNotGranted { .. } => {
            t_string!(i18n, gallery.activity_refused_grant).to_owned()
        }
        ComponentDecisionRefusal::FunctionUnavailable { .. } => {
            t_string!(i18n, gallery.activity_refused_unavailable).to_owned()
        }
        ComponentDecisionRefusal::UnknownComponent
        | ComponentDecisionRefusal::Unpublished
        | ComponentDecisionRefusal::WithheldFromAgent => {
            t_string!(i18n, gallery.activity_refused_component).to_owned()
        }
    }
}

fn activity_width(actions: u64, most: u64) -> f64 {
    if most == 0 {
        0.0
    } else {
        ((actions as f64 / most as f64) * 100.0).clamp(0.0, 100.0)
    }
}

fn busiest_follow_up(bot: &str) -> String {
    format!("What has {bot} actually been doing? Look at the audit trail and summarise it.")
}

const REFUSAL_FOLLOW_UP: &str = "Explain the most recent refusal in that list, and what would have to change for it to be allowed.";

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::components::{ComponentFunctionError, RecentRefusalRow};
    use time::OffsetDateTime;

    #[test]
    fn report_function_mapping_widths_and_results_are_closed() {
        assert_eq!(
            ActivityReportKind::Activity.function(),
            BOT_ACTIVITY_FUNCTION_NAME
        );
        assert_eq!(
            ActivityReportKind::Refusals.function(),
            RECENT_REFUSALS_FUNCTION_NAME
        );
        assert_eq!(activity_width(5, 10), 50.0);
        assert_eq!(activity_width(0, 0), 0.0);
        assert_eq!(
            busiest_follow_up("bot-finance"),
            "What has bot-finance actually been doing? Look at the audit trail and summarise it."
        );
        assert_eq!(
            REFUSAL_FOLLOW_UP,
            "Explain the most recent refusal in that list, and what would have to change for it to be allowed."
        );
        assert!(matches!(
            project_result(
                ActivityReportKind::Refusals,
                ComponentFunctionCall::succeeded(ComponentFunctionData::RecentRefusals(
                    RecentRefusalsReport {
                        rows: vec![RecentRefusalRow {
                            at: OffsetDateTime::UNIX_EPOCH,
                            bot: None,
                            what: "component.refused".to_owned(),
                            reason: Some("component_withheld".to_owned()),
                        }],
                    },
                )),
            ),
            ActivityState::Refusals(_)
        ));
        assert_eq!(
            project_result(
                ActivityReportKind::Activity,
                ComponentFunctionCall::failed(ComponentFunctionError::ReadFailed),
            ),
            ActivityState::Failed
        );
    }
}
