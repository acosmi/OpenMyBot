//! Administrator audit keyset page backed by the existing typed production API.

use leptos::prelude::*;
use openbot_contracts::audit::AuditEventView;
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::audit::AuditPage;

#[cfg(any(target_arch = "wasm32", test))]
use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::load_audit_page;
use crate::features::layout::{PageActions, PageHeader, PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, IconSize, IconView, Notice, NoticeTone, Timestamp,
};

/// Time-ordered, paginated administrator audit page.
#[component]
pub fn AdminAuditPage() -> impl IntoView {
    let i18n = use_i18n();
    let events = RwSignal::new(Vec::<AuditEventView>::new());
    let next_cursor = RwSignal::new(None::<String>);
    let loading = RwSignal::new(false);
    let load_error = RwSignal::new(false);
    let page_owner = StoredValue::new(Owner::current());

    request_audit_page(events, next_cursor, loading, load_error, page_owner, None);
    let load_more = move |_| {
        let cursor = next_cursor.get_untracked();
        request_audit_page(events, next_cursor, loading, load_error, page_owner, cursor);
    };

    view! {
        <PageShell width=PageWidth::Table>
            <PageActions>
                <Show when=move || next_cursor.get().is_some()>
                    <Button
                        variant=ButtonVariant::Chip
                        size=ButtonSize::Medium
                        disabled=loading
                        loading=loading
                        on_activate=load_more
                    >
                        {move || t!(i18n, admin.audit_load_more)}
                    </Button>
                </Show>
            </PageActions>
            <PageHeader
                heading_id="admin-audit-title"
                title=move || t_string!(i18n, admin.audit_title).to_owned()
                description=move || t_string!(i18n, admin.audit_intro).to_owned()
            />
            <Show when=move || load_error.get()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, admin.audit_load_error)}</span>
                    <Button disabled=loading on_activate=load_more>
                        {move || t!(i18n, common.retry)}
                    </Button>
                </Notice>
            </Show>
            <Show when=move || loading.get() && events.with(Vec::is_empty)>
                <div class="ob-loading" role="status">
                    <IconView icon=Icon::LoaderCircle size=IconSize::Navigation />
                    <span>{move || t!(i18n, common.loading)}</span>
                </div>
            </Show>
            <Show when=move || !loading.get() && !load_error.get() && events.with(Vec::is_empty)>
                <p class="ob-page-empty">{move || t!(i18n, admin.audit_empty)}</p>
            </Show>
            <Show when=move || !events.with(Vec::is_empty)>
                <ol class="ob-audit-list">
                    <For
                        each=move || events.get()
                        key=|event| event.id.clone()
                        children=move |event| view! { <AuditRow event /> }
                    />
                </ol>
            </Show>
        </PageShell>
    }
}

fn request_audit_page(
    events: RwSignal<Vec<AuditEventView>>,
    next_cursor: RwSignal<Option<String>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
    page_owner: StoredValue<Option<Owner>>,
    cursor: Option<String>,
) {
    if loading.get_untracked() {
        return;
    }
    loading.set(true);
    load_error.set(false);
    #[cfg(target_arch = "wasm32")]
    if let Some(owner) = page_owner.try_get_value().flatten() {
        owner.with(|| {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match load_audit_page(cursor.as_deref()).await {
                    Ok(page) => {
                        if append_audit_page(&mut events.write(), &page).is_err() {
                            load_error.set(true);
                        } else {
                            next_cursor.set(page.next_cursor);
                        }
                    }
                    Err(_) => load_error.set(true),
                }
                loading.set(false);
            })
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (events, next_cursor, page_owner, cursor);
        loading.set(false);
        load_error.set(true);
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn append_audit_page(current: &mut Vec<AuditEventView>, page: &AuditPage) -> Result<(), ApiError> {
    let mut ids = current
        .iter()
        .map(|event| event.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if page
        .events
        .iter()
        .any(|event| !ids.insert(event.id.as_str()))
    {
        return Err(ApiError::InvalidResponse);
    }
    current.extend(page.events.iter().cloned());
    Ok(())
}

#[component]
fn AuditRow(event: AuditEventView) -> impl IntoView {
    let i18n = use_i18n();
    let actor = event
        .actor_user_id
        .as_ref()
        .map(|actor| actor.as_str().to_owned());
    let target = event.target_id.as_ref().map_or_else(
        || event.target_type.clone(),
        |target| format!("{} / {target}", event.target_type),
    );
    let payload = serde_json::to_string_pretty(&event.payload).unwrap_or_else(|_| "{}".to_owned());
    view! {
        <li class="ob-audit-row">
            <div class="ob-audit-row-header">
                <strong>{event.event_type}</strong>
                <Timestamp at=event.created_at />
            </div>
            <dl class="ob-audit-facts">
                <div><dt>{move || t!(i18n, admin.audit_actor)}</dt><dd>{move || actor.clone().unwrap_or_else(|| t_string!(i18n, admin.audit_system).to_owned())}</dd></div>
                <div><dt>{move || t!(i18n, admin.audit_target)}</dt><dd>{target}</dd></div>
            </dl>
            <details>
                <summary>{move || t!(i18n, admin.audit_payload)}</summary>
                <pre><code>{payload}</code></pre>
            </details>
        </li>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::ids::AuditEventId;

    fn event(id: &str) -> AuditEventView {
        AuditEventView {
            id: AuditEventId::new(id),
            actor_user_id: None,
            event_type: "agent.invoked".to_owned(),
            target_type: "run".to_owned(),
            target_id: Some("run-1".to_owned()),
            payload: serde_json::json!({}),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn page_append_is_ordered_and_rejects_cross_page_duplicates() {
        let mut current = vec![event("event-1")];
        assert!(
            append_audit_page(
                &mut current,
                &AuditPage {
                    events: vec![event("event-2")],
                    next_cursor: None,
                },
            )
            .is_ok()
        );
        assert_eq!(current.len(), 2);
        assert_eq!(
            append_audit_page(
                &mut current,
                &AuditPage {
                    events: vec![event("event-2")],
                    next_cursor: None,
                },
            )
            .unwrap_err(),
            ApiError::InvalidResponse
        );
    }
}
