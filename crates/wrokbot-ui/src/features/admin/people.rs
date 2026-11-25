//! Administrator people journey backed by the existing typed production API.

use leptos::prelude::*;
use openbot_contracts::auth::Role;
use openbot_contracts::ids::ActorId;
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::people::PeoplePage;
use openbot_contracts::people::Person;

#[cfg(any(target_arch = "wasm32", test))]
use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::{change_person_access, change_person_role, load_current_user, load_people_page};
use crate::features::layout::{PageHeader, PageSection, PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, IconSize, IconView, Input, InputType, Notice, NoticeTone,
    Switch,
};

const PEOPLE_SEARCH_DEBOUNCE_MS: i32 = 250;

#[derive(Clone, Copy)]
enum PersonMutation {
    Role {
        person: RwSignal<Person>,
        checked: RwSignal<bool>,
        desired: Role,
    },
    Access {
        person: RwSignal<Person>,
        revoked: bool,
    },
}

/// Searchable, keyset-paged administrator people management page.
#[component]
pub fn AdminPeoplePage() -> impl IntoView {
    let i18n = use_i18n();
    let people = RwSignal::new(Vec::<RwSignal<Person>>::new());
    let current_actor = RwSignal::new(None::<ActorId>);
    let next_cursor = RwSignal::new(None::<String>);
    let search = RwSignal::new(String::new());
    let query = RwSignal::new(String::new());
    let search_generation = RwSignal::new(0_u64);
    let request_epoch = RwSignal::new(0_u64);
    let loading = RwSignal::new(false);
    let load_error = RwSignal::new(false);
    let mutation_pending = RwSignal::new(false);
    let mutation_error = RwSignal::new(false);
    let page_owner = StoredValue::new(Owner::current());

    request_people_page(
        people,
        current_actor,
        next_cursor,
        request_epoch,
        page_owner,
        loading,
        load_error,
        String::new(),
        None,
        true,
        true,
    );

    Effect::new(move |_| {
        let requested = search.get();
        schedule_people_search(
            requested,
            query,
            search_generation,
            people,
            current_actor,
            next_cursor,
            request_epoch,
            page_owner,
            loading,
            load_error,
        );
    });

    let refresh = UnsyncCallback::new(move |_| {
        request_people_page(
            people,
            current_actor,
            next_cursor,
            request_epoch,
            page_owner,
            loading,
            load_error,
            query.get_untracked(),
            None,
            true,
            current_actor.get_untracked().is_none(),
        );
    });
    let mutate = UnsyncCallback::new(move |mutation: PersonMutation| {
        dispatch_person_mutation(
            mutation,
            mutation_pending,
            mutation_error,
            page_owner,
            request_epoch,
            refresh,
        );
    });
    let load_more = move |_| {
        let Some(cursor) = next_cursor.get_untracked() else {
            return;
        };
        request_people_page(
            people,
            current_actor,
            next_cursor,
            request_epoch,
            page_owner,
            loading,
            load_error,
            query.get_untracked(),
            Some(cursor),
            false,
            false,
        );
    };
    let retry = move |_| {
        retry_people_page(
            people,
            current_actor,
            next_cursor,
            request_epoch,
            page_owner,
            loading,
            load_error,
            query,
        );
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="admin-people-title"
                title=move || t_string!(i18n, admin.people_title).to_owned()
                description=move || t_string!(i18n, admin.people_intro).to_owned()
            />
            <PageSection
                heading_id="admin-people-list-title"
                title=move || t_string!(i18n, admin.people_section).to_owned()
                description=move || t_string!(i18n, admin.people_section_intro).to_owned()
            >
                <Show when=move || mutation_error.get()>
                    <Notice tone=NoticeTone::Error>
                        {move || t!(i18n, admin.people_mutation_error)}
                    </Notice>
                </Show>
                <div class="ob-people-search">
                    <Input
                        value=search
                        input_type=InputType::Search
                        aria_label=move || t_string!(i18n, admin.people_search_label).to_owned()
                        placeholder=move || t_string!(i18n, admin.people_search_placeholder).to_owned()
                    />
                </div>
                <Show when=move || load_error.get()>
                    <Notice tone=NoticeTone::Error>
                        <span>{move || t!(i18n, admin.people_load_error)}</span>
                        <Button
                            variant=ButtonVariant::Ghost
                            size=ButtonSize::Small
                            disabled=mutation_pending
                            loading=loading
                            on_activate=retry
                        >
                            {move || t!(i18n, common.retry)}
                        </Button>
                    </Notice>
                </Show>
                <Show when=move || loading.get() && people.with(Vec::is_empty)>
                    <div class="ob-loading" role="status">
                        <IconView icon=Icon::LoaderCircle size=IconSize::Navigation />
                        <span>{move || t!(i18n, common.loading)}</span>
                    </div>
                </Show>
                <Show when=move || {
                    !loading.get() && !load_error.get() && people.with(Vec::is_empty)
                }>
                    <p class="ob-page-empty">
                        {move || {
                            let active = query.get();
                            if active.is_empty() {
                                t_string!(i18n, admin.people_empty).to_owned()
                            } else {
                                t_string!(i18n, admin.people_no_match, query = active).to_owned()
                            }
                        }}
                    </p>
                </Show>
                <Show when=move || !people.with(Vec::is_empty)>
                    <div class="ob-page-rows ob-people-list" role="list">
                        <For
                            each=move || people.get()
                            key=|person| person.with(|person| person.id.clone())
                            children=move |person| view! {
                                <PersonRow
                                    person
                                    current_actor
                                    mutation_pending
                                    on_mutation=mutate
                                />
                            }
                        />
                    </div>
                </Show>
                <Show when=move || next_cursor.get().is_some()>
                    <div class="ob-people-load-more">
                        <Button
                            variant=ButtonVariant::Chip
                            size=ButtonSize::Small
                            disabled=mutation_pending
                            loading=loading
                            on_activate=load_more
                        >
                            {move || t!(i18n, admin.people_load_more)}
                        </Button>
                    </div>
                </Show>
            </PageSection>
        </PageShell>
    }
}

#[component]
fn PersonRow(
    person: RwSignal<Person>,
    current_actor: RwSignal<Option<ActorId>>,
    mutation_pending: RwSignal<bool>,
    on_mutation: UnsyncCallback<PersonMutation>,
) -> impl IntoView {
    let i18n = use_i18n();
    let role_checked = RwSignal::new(person.with_untracked(|person| person.role == Role::Admin));
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::People,
        move || person.with(|person| person.id.as_str().to_owned()),
    );
    Effect::new(move |_| {
        role_checked.set(person.with(|person| person.role == Role::Admin));
    });
    let controls_disabled = Signal::derive(move || {
        mutation_pending.get()
            || write_lock.get()
            || current_actor.get().is_none_or(|actor| {
                person.with(|person| actor == person.id || person.configured_admin)
            })
    });
    let access = move |_| {
        let revoked = person.with_untracked(|person| !person.revoked);
        on_mutation.run(PersonMutation::Access { person, revoked });
    };
    let role = UnsyncCallback::new(move |checked: bool| {
        on_mutation.run(PersonMutation::Role {
            person,
            checked: role_checked,
            desired: if checked { Role::Admin } else { Role::User },
        });
    });

    view! {
        <div
            class="ob-person-row"
            role="listitem"
            data-person-id=move || person.with(|person| person.id.as_str().to_owned())
            data-revoked=move || person.with(|person| person.revoked.then_some("true"))
            data-configured-admin=move || {
                person.with(|person| person.configured_admin.then_some("true"))
            }
        >
            <span class="ob-person-media">
                {move || {
                    let icon = person.with(person_icon);
                    view! { <IconView icon size=IconSize::Navigation /> }
                }}
            </span>
            <span class="ob-person-content">
                <strong>{move || person.with(person_title)}</strong>
                <span>{move || person.with(|person| person_description(i18n, person))}</span>
            </span>
            <span class="ob-person-actions">
                <Show
                    when=move || person.with(|person| person.revoked)
                    fallback=move || view! {
                        <Button
                            aria_label=move || t_string!(
                                i18n,
                                admin.people_remove_label,
                                email = person.with(|person| person.email.clone()),
                            ).to_owned()
                            variant=ButtonVariant::DangerText
                            size=ButtonSize::Small
                            disabled=controls_disabled
                            on_activate=access
                        >
                            {move || t!(i18n, admin.people_remove)}
                        </Button>
                    }
                >
                    <Button
                        aria_label=move || t_string!(
                            i18n,
                            admin.people_restore_label,
                            email = person.with(|person| person.email.clone()),
                        ).to_owned()
                        variant=ButtonVariant::Chip
                        size=ButtonSize::Small
                        disabled=controls_disabled
                        on_activate=access
                    >
                        {move || t!(i18n, admin.people_restore)}
                    </Button>
                </Show>
                <Switch
                    checked=role_checked
                    aria_label=move || t_string!(
                        i18n,
                        admin.people_administrator_label,
                        email = person.with(|person| person.email.clone()),
                    ).to_owned()
                    disabled=controls_disabled
                    on_change=role
                />
            </span>
        </div>
    }
}

#[allow(clippy::too_many_arguments)]
fn schedule_people_search(
    requested: String,
    query: RwSignal<String>,
    search_generation: RwSignal<u64>,
    people: RwSignal<Vec<RwSignal<Person>>>,
    current_actor: RwSignal<Option<ActorId>>,
    next_cursor: RwSignal<Option<String>>,
    request_epoch: RwSignal<u64>,
    page_owner: StoredValue<Option<Owner>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
) {
    let Some(generation) = advance_counter(search_generation) else {
        load_error.set(true);
        return;
    };
    if requested == query.get_untracked() {
        return;
    }
    schedule_people_timeout(move || {
        if search_generation.try_get_untracked() != Some(generation)
            || query
                .try_get_untracked()
                .is_none_or(|query| requested == query)
        {
            return;
        }
        let Some(owner) = page_owner.try_get_value().flatten() else {
            return;
        };
        owner.with(|| {
            query.set(requested.clone());
            request_people_page(
                people,
                current_actor,
                next_cursor,
                request_epoch,
                page_owner,
                loading,
                load_error,
                requested,
                None,
                true,
                false,
            );
        });
    });
}

fn schedule_people_timeout(callback: impl FnOnce() + 'static) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        let callback = Closure::once_into_js(callback);
        if let Some(window) = web_sys::window() {
            _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.unchecked_ref(),
                PEOPLE_SEARCH_DEBOUNCE_MS,
            );
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (callback, PEOPLE_SEARCH_DEBOUNCE_MS);
}

#[allow(clippy::too_many_arguments)]
fn retry_people_page(
    people: RwSignal<Vec<RwSignal<Person>>>,
    current_actor: RwSignal<Option<ActorId>>,
    next_cursor: RwSignal<Option<String>>,
    request_epoch: RwSignal<u64>,
    page_owner: StoredValue<Option<Owner>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
    query: RwSignal<String>,
) {
    if loading.get_untracked() {
        return;
    }
    // Only a successful page advances this cursor; a query reset clears it before its read.
    let cursor = next_cursor.get_untracked();
    let reset = cursor.is_none();
    request_people_page(
        people,
        current_actor,
        next_cursor,
        request_epoch,
        page_owner,
        loading,
        load_error,
        query.get_untracked(),
        cursor,
        reset,
        current_actor.get_untracked().is_none(),
    );
}

#[allow(clippy::too_many_arguments)]
fn request_people_page(
    people: RwSignal<Vec<RwSignal<Person>>>,
    current_actor: RwSignal<Option<ActorId>>,
    next_cursor: RwSignal<Option<String>>,
    request_epoch: RwSignal<u64>,
    page_owner: StoredValue<Option<Owner>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
    query: String,
    cursor: Option<String>,
    reset: bool,
    include_actor: bool,
) {
    if loading.get_untracked() && !reset {
        return;
    }
    let Some(epoch) = advance_counter(request_epoch) else {
        load_error.set(true);
        return;
    };
    if reset {
        people.set(Vec::new());
        next_cursor.set(None);
    }
    loading.set(true);
    load_error.set(false);
    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let page = load_people_page(&query, cursor.as_deref()).await;
                let actor = if include_actor {
                    Some(load_current_user().await.map(|user| user.id))
                } else {
                    None
                };
                if request_epoch.get_untracked() != epoch {
                    return;
                }
                let actor_failed = actor.as_ref().is_some_and(Result::is_err);
                match page {
                    Ok(page) if !actor_failed => {
                        let mut current = if reset {
                            Vec::new()
                        } else {
                            people
                                .get_untracked()
                                .into_iter()
                                .map(|person| person.get_untracked())
                                .collect()
                        };
                        if append_people_page(&mut current, &page).is_err() {
                            load_error.set(true);
                        } else {
                            people.set(current.into_iter().map(RwSignal::new).collect());
                            next_cursor.set(page.next_cursor);
                            if let Some(Ok(actor)) = actor {
                                current_actor.set(Some(actor));
                            }
                        }
                    }
                    _ => load_error.set(true),
                }
                loading.set(false);
            });
        };
        match page_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (
            people,
            current_actor,
            query,
            cursor,
            include_actor,
            epoch,
            page_owner,
        );
        loading.set(false);
        load_error.set(true);
    }
}

fn dispatch_person_mutation(
    mutation: PersonMutation,
    pending: RwSignal<bool>,
    error: RwSignal<bool>,
    worker_owner: StoredValue<Option<Owner>>,
    request_epoch: RwSignal<u64>,
    refresh: UnsyncCallback<()>,
) {
    if pending.get_untracked() {
        if let PersonMutation::Role {
            checked, desired, ..
        } = mutation
        {
            checked.try_set(desired != Role::Admin);
        }
        return;
    }
    pending.set(true);
    error.set(false);
    let epoch = request_epoch.get_untracked();
    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let outcome = match mutation {
                    PersonMutation::Role {
                        person, desired, ..
                    } => {
                        let id = person.with_untracked(|person| person.id.as_str().to_owned());
                        change_person_role(&id, desired).await
                    }
                    PersonMutation::Access { person, revoked } => {
                        let id = person.with_untracked(|person| person.id.as_str().to_owned());
                        change_person_access(&id, revoked).await
                    }
                };
                let same_page = request_epoch.get_untracked() == epoch;
                match outcome {
                    Ok(replacement) => match mutation {
                        PersonMutation::Role {
                            person, checked, ..
                        } => {
                            if same_page {
                                checked.try_set(replacement.role == Role::Admin);
                                person.try_set(replacement);
                            }
                        }
                        PersonMutation::Access { person, .. } => {
                            if same_page {
                                person.try_set(replacement);
                            }
                        }
                    },
                    Err(_) => {
                        if let PersonMutation::Role {
                            checked, desired, ..
                        } = mutation
                        {
                            checked.try_set(desired != Role::Admin);
                        }
                        error.set(true);
                    }
                }
                pending.set(false);
                if !same_page {
                    refresh.run(());
                }
            });
        };
        match worker_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (epoch, refresh);
        match mutation {
            PersonMutation::Role {
                person,
                checked,
                desired,
            } => {
                let _ = person;
                checked.set(desired != Role::Admin);
            }
            PersonMutation::Access { person, revoked } => {
                let _ = (person, revoked);
            }
        }
        let _ = worker_owner;
        pending.set(false);
        error.set(true);
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn append_people_page(current: &mut Vec<Person>, page: &PeoplePage) -> Result<(), ApiError> {
    let mut ids = current
        .iter()
        .map(|person| person.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if page
        .people
        .iter()
        .any(|person| !ids.insert(person.id.as_str()))
    {
        return Err(ApiError::InvalidResponse);
    }
    current.extend(page.people.iter().cloned());
    Ok(())
}

fn advance_counter(counter: RwSignal<u64>) -> Option<u64> {
    let next = counter.get_untracked().checked_add(1)?;
    counter.set(next);
    Some(next)
}

fn person_icon(person: &Person) -> Icon {
    if person.revoked {
        Icon::Lock
    } else if person.role == Role::Admin {
        Icon::ShieldCheck
    } else {
        Icon::User
    }
}

fn person_title(person: &Person) -> String {
    person
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&person.email)
        .to_owned()
}

fn person_description(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    person: &Person,
) -> String {
    let providers = if person.providers.is_empty() {
        t_string!(i18n, admin.people_no_provider).to_owned()
    } else {
        person
            .providers
            .iter()
            .map(|provider| provider_name(provider))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let when = person.last_signed_in_at.map_or_else(
        || t_string!(i18n, admin.people_never_signed_in).to_owned(),
        |signed_in| {
            t_string!(
                i18n,
                admin.people_last_signed_in,
                date = signed_in.date().to_string(),
            )
            .to_owned()
        },
    );
    let summary = if person.revoked {
        t_string!(i18n, admin.people_access_removed, providers = providers,).to_owned()
    } else if person.configured_admin {
        t_string!(i18n, admin.people_configured_admin, when = when).to_owned()
    } else {
        t_string!(
            i18n,
            admin.people_provider_and_time,
            providers = providers,
            when = when,
        )
        .to_owned()
    };
    if person.name.as_deref().is_some_and(|name| !name.is_empty()) {
        format!("{} · {summary}", person.email)
    } else {
        summary
    }
}

fn provider_name(provider: &str) -> String {
    match provider {
        "google" => "Google".to_owned(),
        "microsoft" => "Microsoft".to_owned(),
        "okta" => "Okta".to_owned(),
        other => other.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(id: &str) -> Person {
        Person {
            id: ActorId::new(id),
            email: format!("{id}@example.test"),
            name: Some(id.to_owned()),
            image: None,
            role: Role::User,
            providers: vec!["google".to_owned()],
            last_signed_in_at: None,
            revoked: false,
            configured_admin: false,
        }
    }

    #[test]
    fn page_append_rejects_duplicates_and_counter_exhaustion_fails_closed() {
        let mut current = vec![person("person-1")];
        assert!(
            append_people_page(
                &mut current,
                &PeoplePage {
                    people: vec![person("person-2")],
                    next_cursor: None,
                },
            )
            .is_ok()
        );
        assert_eq!(current.len(), 2);
        assert_eq!(
            append_people_page(
                &mut current,
                &PeoplePage {
                    people: vec![person("person-2")],
                    next_cursor: None,
                },
            )
            .unwrap_err(),
            ApiError::InvalidResponse,
        );

        let owner = Owner::new();
        owner.with(|| {
            let counter = RwSignal::new(u64::MAX - 1);
            assert_eq!(advance_counter(counter), Some(u64::MAX));
            assert_eq!(advance_counter(counter), None);
            assert_eq!(counter.get_untracked(), u64::MAX);
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn paged_read_retry_failure_preserves_loaded_people_and_opaque_cursor() {
        let owner = Owner::new();
        owner.with(|| {
            let first = RwSignal::new(person("person-1"));
            let people = RwSignal::new(vec![first]);
            let current_actor = RwSignal::new(None::<ActorId>);
            let cursor = "opaque+/=?".to_owned();
            let next_cursor = RwSignal::new(Some(cursor.clone()));
            let request_epoch = RwSignal::new(3_u64);
            let page_owner = StoredValue::new(Owner::current());
            let loading = RwSignal::new(false);
            let load_error = RwSignal::new(true);
            let query = RwSignal::new("member + one".to_owned());

            // Exercise the request's native unavailable branch without HTTP.
            retry_people_page(
                people,
                current_actor,
                next_cursor,
                request_epoch,
                page_owner,
                loading,
                load_error,
                query,
            );

            assert_eq!(people.with_untracked(Vec::len), 1);
            assert_eq!(
                people.get_untracked()[0].get_untracked(),
                person("person-1")
            );
            assert_eq!(next_cursor.get_untracked(), Some(cursor));
            assert_eq!(query.get_untracked(), "member + one");
            assert_eq!(request_epoch.get_untracked(), 4);
            assert!(!loading.get_untracked());
            assert!(load_error.get_untracked());
        });
    }

    #[test]
    fn icons_and_provider_names_follow_the_fixed_upstream_states() {
        assert_eq!(PEOPLE_SEARCH_DEBOUNCE_MS, 250);
        let mut row = person("person-1");
        assert_eq!(person_icon(&row), Icon::User);
        row.role = Role::Admin;
        assert_eq!(person_icon(&row), Icon::ShieldCheck);
        row.revoked = true;
        assert_eq!(person_icon(&row), Icon::Lock);
        assert_eq!(provider_name("google"), "Google");
        assert_eq!(provider_name("private-oidc"), "private-oidc");
    }
}
