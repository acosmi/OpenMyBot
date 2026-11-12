//! Inert preview registry for the compiled renderers actually present in this Rust build.

use leptos::prelude::*;
#[cfg(test)]
use openbot_contracts::components::compiled_component_manifest;
use openbot_contracts::components::{
    ASK_APPROVAL_COMPONENT_NAME, ASK_CHOICE_COMPONENT_NAME, ComponentApprovalAnswer,
    ComponentApprovalDecision, ComponentChoiceAnswer, ComponentHumanDecisionAnswer,
    SHOW_ACTIVITY_REPORT_COMPONENT_NAME, SHOW_AREA_CHART_COMPONENT_NAME,
    SHOW_BAR_CHART_COMPONENT_NAME, SHOW_CHECKLIST_COMPONENT_NAME, SHOW_LINE_CHART_COMPONENT_NAME,
    SHOW_METRICS_COMPONENT_NAME, SHOW_NOTICE_COMPONENT_NAME, SHOW_PIE_CHART_COMPONENT_NAME,
    SHOW_PROGRESS_COMPONENT_NAME, SHOW_QUOTE_COMPONENT_NAME, SHOW_RECORD_COMPONENT_NAME,
};

use crate::i18n::{t, t_string, use_i18n};

use super::{
    AreaChartCard, BarChartCard, ChartPoint, ChartSeries, ChecklistCard, ChecklistItem,
    GalleryTone, HeadlineMetric, HumanDecisionCard, LineChartCard, MetricsCard, NoticeCard,
    PieChartCard, ProgressChartCard, ProgressPoint, QuoteCard, RecordCard, RecordField,
};

const RENDERER_NAMES: [&str; 13] = [
    ASK_APPROVAL_COMPONENT_NAME,
    ASK_CHOICE_COMPONENT_NAME,
    SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
    SHOW_AREA_CHART_COMPONENT_NAME,
    SHOW_BAR_CHART_COMPONENT_NAME,
    SHOW_CHECKLIST_COMPONENT_NAME,
    SHOW_LINE_CHART_COMPONENT_NAME,
    SHOW_METRICS_COMPONENT_NAME,
    SHOW_NOTICE_COMPONENT_NAME,
    SHOW_PIE_CHART_COMPONENT_NAME,
    SHOW_PROGRESS_COMPONENT_NAME,
    SHOW_QUOTE_COMPONENT_NAME,
    SHOW_RECORD_COMPONENT_NAME,
];

/// Stable names this build can actually draw.
#[must_use]
pub const fn renderer_names() -> &'static [&'static str] {
    &RENDERER_NAMES
}

/// Whether one durable catalogue row has a renderer in this exact build.
#[must_use]
pub fn component_has_renderer(name: &str) -> bool {
    renderer_names().contains(&name)
}

/// Draw one inert component sample or an honest stale-row fallback.
#[component]
pub fn ComponentPreview(name: String) -> AnyView {
    let i18n = use_i18n();
    let content = match name.as_str() {
        ASK_APPROVAL_COMPONENT_NAME => view! {
            <HumanDecisionCard
                name=ASK_APPROVAL_COMPONENT_NAME.to_owned()
                arguments=serde_json::json!({
                    "title": t_string!(i18n, gallery.sample_refund_title),
                    "summary": t_string!(i18n, gallery.sample_refund_summary),
                    "details":[
                        {"label": t_string!(i18n, gallery.sample_amount), "value":"$128.40"},
                        {"label": t_string!(i18n, gallery.sample_order), "value":"2043"}
                    ],
                    "approveLabel": t_string!(i18n, gallery.sample_refund)
                })
                answer=Signal::derive(|| Some(ComponentHumanDecisionAnswer::Approval(
                    ComponentApprovalAnswer {
                        decision: ComponentApprovalDecision::Approved,
                        note: None,
                    }
                )))
                submitting=Signal::derive(|| false)
                error=Signal::derive(|| false)
            />
        }.into_any(),
        ASK_CHOICE_COMPONENT_NAME => {
            let staging = t_string!(i18n, gallery.sample_staging).to_owned();
            view! {
                <HumanDecisionCard
                    name=ASK_CHOICE_COMPONENT_NAME.to_owned()
                    arguments=serde_json::json!({
                        "title": t_string!(i18n, gallery.sample_destination_title),
                        "summary": t_string!(i18n, gallery.sample_destination_summary),
                        "options":[
                            {"id":"staging","label": staging},
                            {"id":"production","label": t_string!(i18n, gallery.sample_production),"description": t_string!(i18n, gallery.sample_live_customers)}
                        ]
                    })
                    answer=Signal::derive(move || Some(ComponentHumanDecisionAnswer::Choice(
                        ComponentChoiceAnswer {
                            choice: "staging".to_owned(),
                            label: staging.clone(),
                        }
                    )))
                    submitting=Signal::derive(|| false)
                    error=Signal::derive(|| false)
                />
            }.into_any()
        }
        SHOW_ACTIVITY_REPORT_COMPONENT_NAME => view! {
            <p class="ob-gallery-preview-unavailable">
                {move || t!(i18n, gallery.preview_unavailable)}
            </p>
        }
        .into_any(),
        SHOW_AREA_CHART_COMPONENT_NAME => view! {
            <AreaChartCard
                title=t_string!(i18n, gallery.sample_storage_title).to_owned()
                caption=Some(t_string!(i18n, gallery.sample_storage_caption).to_owned())
                labels=vec![
                    t_string!(i18n, gallery.sample_jan).to_owned(),
                    t_string!(i18n, gallery.sample_feb).to_owned(),
                    t_string!(i18n, gallery.sample_mar).to_owned(),
                    t_string!(i18n, gallery.sample_apr).to_owned(),
                    t_string!(i18n, gallery.sample_may).to_owned(),
                ]
                series=vec![ChartSeries { name: "TB".to_owned(), values: vec![12.0, 19.0, 26.0, 31.0, 44.0] }]
            />
        }.into_any(),
        SHOW_BAR_CHART_COMPONENT_NAME => view! {
            <BarChartCard
                title=t_string!(i18n, gallery.sample_revenue_title).to_owned()
                caption=Some(t_string!(i18n, gallery.sample_revenue_caption).to_owned())
                points=vec![
                    ChartPoint { label: t_string!(i18n, gallery.sample_sales).to_owned(), value: 120.0 },
                    ChartPoint { label: t_string!(i18n, gallery.sample_engineering).to_owned(), value: 80.0 },
                    ChartPoint { label: t_string!(i18n, gallery.sample_support).to_owned(), value: 45.0 },
                ]
            />
        }.into_any(),
        SHOW_CHECKLIST_COMPONENT_NAME => view! {
            <ChecklistCard
                title=t_string!(i18n, gallery.sample_release_title).to_owned()
                caption=None
                items=vec![
                    ChecklistItem { text: t_string!(i18n, gallery.sample_migrations).to_owned(), done: true, note: None },
                    ChecklistItem { text: t_string!(i18n, gallery.sample_changelog).to_owned(), done: true, note: None },
                    ChecklistItem { text: t_string!(i18n, gallery.sample_load_test).to_owned(), done: false, note: Some(t_string!(i18n, gallery.sample_waiting_staging).to_owned()) },
                ]
            />
        }
        .into_any(),
        SHOW_LINE_CHART_COMPONENT_NAME => view! {
            <LineChartCard
                title=t_string!(i18n, gallery.sample_signups).to_owned()
                caption=Some(t_string!(i18n, gallery.sample_signups_caption).to_owned())
                labels=(1..=6).map(|week| t_string!(i18n, gallery.sample_week, week = week).to_owned()).collect::<Vec<_>>()
                series=vec![ChartSeries { name: t_string!(i18n, gallery.sample_signups).to_owned(), values: vec![120.0, 180.0, 160.0, 240.0, 300.0, 420.0] }]
            />
        }.into_any(),
        SHOW_METRICS_COMPONENT_NAME => view! {
            <MetricsCard
                title=t_string!(i18n, gallery.sample_this_month).to_owned()
                caption=None
                metrics=vec![
                    HeadlineMetric { label: t_string!(i18n, gallery.sample_revenue).to_owned(), value: "$412k".to_owned(), change: Some(t_string!(i18n, gallery.sample_revenue_change).to_owned()), change_tone: GalleryTone::Positive },
                    HeadlineMetric { label: t_string!(i18n, gallery.sample_open_deals).to_owned(), value: "38".to_owned(), change: None, change_tone: GalleryTone::Neutral },
                    HeadlineMetric { label: t_string!(i18n, gallery.sample_churn).to_owned(), value: "1.4%".to_owned(), change: Some("+0.3pt".to_owned()), change_tone: GalleryTone::Caution },
                ]
            />
        }
        .into_any(),
        SHOW_NOTICE_COMPONENT_NAME => view! {
            <NoticeCard
                title=t_string!(i18n, gallery.sample_certificate_title).to_owned()
                body=t_string!(i18n, gallery.sample_certificate_body).to_owned()
                tone=GalleryTone::Caution
                points=vec![
                    t_string!(i18n, gallery.sample_certificate_owner).to_owned(),
                    t_string!(i18n, gallery.sample_certificate_renews).to_owned(),
                ]
            />
        }
        .into_any(),
        SHOW_PIE_CHART_COMPONENT_NAME => view! {
            <PieChartCard
                title=t_string!(i18n, gallery.sample_month_title).to_owned()
                caption=None
                points=vec![
                    ChartPoint { label: t_string!(i18n, gallery.sample_build).to_owned(), value: 48.0 },
                    ChartPoint { label: t_string!(i18n, gallery.sample_support).to_owned(), value: 26.0 },
                    ChartPoint { label: t_string!(i18n, gallery.sample_meetings).to_owned(), value: 26.0 },
                ]
            />
        }.into_any(),
        SHOW_PROGRESS_COMPONENT_NAME => view! {
            <ProgressChartCard
                title=t_string!(i18n, gallery.sample_runtime_title).to_owned()
                caption=Some(t_string!(i18n, gallery.sample_runtime_caption).to_owned())
                points=vec![
                    ProgressPoint { label: t_string!(i18n, gallery.sample_services_moved).to_owned(), value: 18.0, target: 20.0 },
                    ProgressPoint { label: t_string!(i18n, gallery.sample_tests_ported).to_owned(), value: 240.0, target: 240.0 },
                ]
            />
        }.into_any(),
        SHOW_QUOTE_COMPONENT_NAME => view! {
            <QuoteCard
                quote=t_string!(i18n, gallery.sample_quote).to_owned()
                attribution=t_string!(i18n, gallery.sample_quote_attribution).to_owned()
                context=t_string!(i18n, gallery.sample_quote_context).to_owned()
            />
        }
        .into_any(),
        SHOW_RECORD_COMPONENT_NAME => view! {
            <RecordCard
                title=t_string!(i18n, gallery.sample_invoice_title).to_owned()
                subtitle=Some("Northwind Traders".to_owned())
                status=Some(t_string!(i18n, gallery.decision_approved).to_owned())
                status_tone=GalleryTone::Neutral
                fields=vec![
                    RecordField { label: t_string!(i18n, gallery.sample_amount).to_owned(), value: "$4,280.00".to_owned() },
                    RecordField { label: t_string!(i18n, gallery.sample_raised).to_owned(), value: t_string!(i18n, gallery.sample_raised_date).to_owned() },
                    RecordField { label: t_string!(i18n, gallery.sample_owner).to_owned(), value: "Priya Raman".to_owned() },
                ]
            />
        }
        .into_any(),
        _ => view! {
            <p class="ob-gallery-preview-unavailable">
                {move || t!(i18n, gallery.renderer_unavailable)}
            </p>
        }
        .into_any(),
    };
    view! {
        <div class="ob-gallery-preview" aria-hidden="true">
            {content}
        </div>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_registry_is_unique_and_exactly_matches_the_current_manifest() {
        let manifest = compiled_component_manifest();
        assert_eq!(
            renderer_names(),
            [
                ASK_APPROVAL_COMPONENT_NAME,
                ASK_CHOICE_COMPONENT_NAME,
                SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
                SHOW_AREA_CHART_COMPONENT_NAME,
                SHOW_BAR_CHART_COMPONENT_NAME,
                SHOW_CHECKLIST_COMPONENT_NAME,
                SHOW_LINE_CHART_COMPONENT_NAME,
                SHOW_METRICS_COMPONENT_NAME,
                SHOW_NOTICE_COMPONENT_NAME,
                SHOW_PIE_CHART_COMPONENT_NAME,
                SHOW_PROGRESS_COMPONENT_NAME,
                SHOW_QUOTE_COMPONENT_NAME,
                SHOW_RECORD_COMPONENT_NAME,
            ]
        );
        assert_eq!(
            manifest
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            renderer_names()
        );
        assert!(component_has_renderer(SHOW_QUOTE_COMPONENT_NAME));
        assert!(!component_has_renderer("showLegacyWidget"));
    }
}
