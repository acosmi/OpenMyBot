//! Read-only published compiled component gallery index and detail routes.

#![cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use openbot_contracts::components::{CompiledComponentKind, ComponentRecord, ComponentRecords};

use crate::api::component_gallery_href;
#[cfg(target_arch = "wasm32")]
use crate::api::{announce_component_catalogue, load_components};
use crate::features::gallery::ComponentPreview;
use crate::features::layout::{
    PageBackLink, PageEmpty, PageHeader, PageSection, PageShell, PageTopbar, PageWidth,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, IconSize, IconView, Notice, NoticeTone,
};

/// Published compiled components this deployment can currently offer.
#[component]
pub fn ComponentsGalleryPage() -> impl IntoView {
    let i18n = use_i18n();
    let records = RwSignal::new(None::<ComponentRecords>);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);
    install_component_loader(reload_generation, records, loading, load_error);
    let published = Memo::new(move |_| {
        records
            .get()
            .as_ref()
            .map(published_components)
            .unwrap_or_default()
    });
    let retry = move |_| {
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="components-gallery-title"
                title=move || t_string!(i18n, gallery.components_title).to_owned()
                description=move || t_string!(i18n, gallery.components_description).to_owned()
            />
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || load_error.get()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, gallery.components_load_error)}</span>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        on_activate=retry
                    >
                        {move || t!(i18n, common.retry)}
                    </Button>
                </Notice>
            </Show>
            <Show when=move || !loading.get() && !load_error.get()>
                <Show
                    when=move || !published.get().is_empty()
                    fallback=move || view! {
                        <section class="ob-gallery-page-empty" aria-labelledby="components-gallery-empty-title">
                            <h2 id="components-gallery-empty-title">
                                {move || t!(i18n, gallery.nothing_published)}
                            </h2>
                            <PageEmpty>{move || t!(i18n, gallery.nothing_published_description)}</PageEmpty>
                        </section>
                    }
                >
                    <div class="ob-gallery-grid">
                        <For
                            each=move || published.get()
                            key=|component| component.name.clone()
                            children=move |component| {
                                let href = component_gallery_href(&component.name)
                                    .expect("validated component record owns a bounded route name");
                                let name = component.name.clone();
                                let title = component.title;
                                let description = component.published_description.unwrap_or_default();
                                view! {
                                    <a class="ob-gallery-tile" href=href>
                                        <div class="ob-gallery-tile-copy">
                                            <h2>{title}</h2>
                                            <p>{description}</p>
                                        </div>
                                        <div class="ob-gallery-tile-preview">
                                            <ComponentPreview name />
                                        </div>
                                    </a>
                                }
                            }
                        />
                    </div>
                </Show>
            </Show>
        </PageShell>
    }
}

/// One published compiled component preview and read-only identity facts.
#[component]
pub fn ComponentGalleryDetailPage() -> impl IntoView {
    let i18n = use_i18n();
    let params = use_params_map();
    let records = RwSignal::new(None::<ComponentRecords>);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);
    install_component_loader(reload_generation, records, loading, load_error);
    let component = Memo::new(move |_| {
        let name = params.read().get("name")?;
        records
            .get()
            .as_ref()?
            .components
            .iter()
            .find(|record| record.name == name && record.published)
            .cloned()
    });
    let retry = move |_| {
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageTopbar>
                <PageBackLink
                    href="/settings/components-gallery".to_owned()
                    label=move || t_string!(i18n, gallery.components_title).to_owned()
                />
            </PageTopbar>
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || load_error.get()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, gallery.components_load_error)}</span>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        on_activate=retry
                    >
                        {move || t!(i18n, common.retry)}
                    </Button>
                </Notice>
            </Show>
            <Show when=move || !loading.get() && !load_error.get() && component.get().is_none()>
                <PageHeader
                    heading_id="component-gallery-not-found"
                    title=move || t_string!(i18n, gallery.no_such_component).to_owned()
                    description=move || t_string!(i18n, gallery.no_such_component_description).to_owned()
                />
                <div class="ob-gallery-not-found">
                    <IconView icon=Icon::LayoutGrid size=IconSize::Navigation />
                    <a href="/settings/components-gallery">
                        {move || t!(i18n, gallery.back_to_gallery)}
                    </a>
                </div>
            </Show>
            <Show when=move || component.get().is_some()>
                {move || component.get().map(|component| {
                    let name = component.name.clone();
                    let called_as = component.name;
                    let title = component.title;
                    let description = component.published_description.unwrap_or_default();
                    let kind = component.kind;
                    view! {
                        <PageHeader
                            heading_id="component-gallery-title"
                            title=title
                            description=description
                        />
                        <div class="ob-gallery-detail-preview">
                            <ComponentPreview name />
                        </div>
                        <PageSection
                            heading_id="component-gallery-details"
                            title=move || t_string!(i18n, gallery.details).to_owned()
                        >
                            <dl class="ob-gallery-facts">
                                <div>
                                    <dt>{move || t!(i18n, gallery.kind)}</dt>
                                    <dd>{move || component_kind_label(i18n, kind)}</dd>
                                </div>
                                <div>
                                    <dt>{move || t!(i18n, gallery.called_as)}</dt>
                                    <dd><code>{called_as}</code></dd>
                                </div>
                            </dl>
                        </PageSection>
                    }
                })}
            </Show>
        </PageShell>
    }
}

fn install_component_loader(
    reload_generation: RwSignal<u64>,
    records: RwSignal<Option<ComponentRecords>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let generation = reload_generation.get();
        loading.set(true);
        load_error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let _ = announce_component_catalogue().await;
            let outcome = load_components().await;
            if reload_generation.get_untracked() != generation {
                return;
            }
            match outcome {
                Ok(loaded) => records.set(Some(loaded)),
                Err(_) => {
                    records.set(None);
                    load_error.set(true);
                }
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (reload_generation, records, loading, load_error);
}

fn published_components(records: &ComponentRecords) -> Vec<ComponentRecord> {
    records
        .components
        .iter()
        .filter(|component| component.published && component.published_description.is_some())
        .cloned()
        .collect()
}

fn component_kind_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    kind: CompiledComponentKind,
) -> String {
    match kind {
        CompiledComponentKind::Chart => t_string!(i18n, gallery.kind_chart).to_owned(),
        CompiledComponentKind::Card => t_string!(i18n, gallery.kind_card).to_owned(),
        CompiledComponentKind::Decision => t_string!(i18n, gallery.kind_decision).to_owned(),
        CompiledComponentKind::Sandboxed => t_string!(i18n, gallery.kind_sandboxed).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;

    fn record(name: &str, published: bool) -> ComponentRecord {
        ComponentRecord {
            name: name.to_owned(),
            title: name.to_owned(),
            kind: CompiledComponentKind::Card,
            draft_description: "draft".to_owned(),
            published_description: published.then(|| "published".to_owned()),
            published,
            published_at: published.then_some(OffsetDateTime::UNIX_EPOCH),
            updated_by: None,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            has_unpublished_changes: !published,
            withheld_from: Vec::new(),
            functions: Vec::new(),
        }
    }

    #[test]
    fn settings_gallery_exposes_only_published_rows_but_keeps_stale_renderer_rows() {
        let records = ComponentRecords {
            components: vec![
                record("showLegacyWidget", true),
                record("showNotice", false),
            ],
        };
        let published = published_components(&records);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].name, "showLegacyWidget");
    }
}
