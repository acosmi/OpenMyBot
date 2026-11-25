//! Read-only account projection shared with the existing authenticated Server/Desktop host.
use crate::{
    api::load_current_user,
    features::layout::PageSection,
    i18n::{t, t_string, use_i18n},
    primitives::{Button, ButtonSize, ButtonVariant, Notice, NoticeTone},
};
use leptos::prelude::*;
use openbot_contracts::auth::Role;

#[component]
pub(super) fn AccountSummary() -> impl IntoView {
    let i18n = use_i18n();
    let user = LocalResource::new(load_current_user);
    view! {
        <PageSection heading_id="settings-account-title" title=move || t_string!(i18n, account.title).to_owned()>
            <Suspense fallback=move || view! { <p class="ob-page-intro" role="status">{move || t!(i18n, account.loading)}</p> }>
                {move || user.get().map(|result| match result {
                    Ok(identity) => {
                        let name = identity.name.filter(|name| !name.trim().is_empty()).unwrap_or_else(|| identity.email.clone());
                        let administrator = identity.role == Role::Admin;
                        view! {
                            <div class="ob-settings-preference-row">
                                <div class="ob-settings-preference-copy"><h3>{name}</h3><p>{identity.email}</p></div>
                                <span>{move || if administrator { t_string!(i18n, account.role_admin).to_owned() } else { t_string!(i18n, account.role_member).to_owned() }}</span>
                            </div>
                            <p class="ob-page-intro">{move || t!(i18n, account.profile_source)}</p>
                        }.into_any()
                    }
                    Err(_) => view! {
                        <Notice tone=NoticeTone::Error>
                            <span>{move || t!(i18n, account.load_failed)}</span>
                            <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| user.refetch()>{move || t!(i18n, common.retry)}</Button>
                        </Notice>
                    }.into_any()
                })}
            </Suspense>
        </PageSection>
        <PageSection heading_id="settings-account-usage" title=move || t_string!(i18n, account.usage_title).to_owned()>
            <p class="ob-page-intro">{move || t!(i18n, account.usage_pending)}</p>
            <p class="ob-page-intro">{move || t!(i18n, account.cap_boundary)}</p>
        </PageSection>
    }
}
