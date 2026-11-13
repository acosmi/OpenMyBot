//! Consistent configuration-page frame and section anatomy.

use leptos::prelude::*;

/// Closed content measure from the GUI first source, never an arbitrary pixel width.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PageWidth {
    /// Library and configuration pages, 1040px maximum including their source padding.
    #[default]
    Content,
    /// Dense tables, 1200px maximum.
    Table,
    /// Transcript-like reading columns, 850px maximum.
    Chat,
}

impl PageWidth {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Table => "table",
            Self::Chat => "chat",
        }
    }
}

/// Centered page frame with one closed content measure.
#[component]
pub fn PageShell(
    /// One first-source content measure.
    #[prop(optional)]
    width: PageWidth,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="ob-page-shell" data-width=width.as_str()>
            {children()}
        </div>
    }
}

/// Row of page-level actions (refresh, load more) above the page content.
#[component]
pub fn PageActions(children: Children) -> impl IntoView {
    view! { <div class="ob-page-actions">{children()}</div> }
}

/// The page's unique h1 and optional explanatory sentence.
#[component]
pub fn PageHeader(
    /// Stable h1 DOM token.
    #[prop(into)]
    heading_id: String,
    /// Localized h1 text.
    #[prop(into)]
    title: TextProp,
    /// The top bar already shows this same title, so the h1 is kept for assistive technology
    /// only instead of stacking a second visible title (UI spec v5.2 §5.4).
    #[prop(optional)]
    title_in_top_bar: bool,
    /// Optional localized explanatory sentence.
    #[prop(optional, into)]
    description: TextProp,
) -> impl IntoView {
    assert_dom_id(&heading_id);
    assert!(
        !title.get().trim().is_empty(),
        "page title must be nonempty"
    );
    let visible_description = description.clone();
    view! {
        <header class="ob-page-header">
            <h1
                id=heading_id
                class="ob-page-title"
                class:ob-visually-hidden=title_in_top_bar
            >{move || title.get()}</h1>
            <p
                class="ob-page-intro"
                hidden=move || visible_description.get().trim().is_empty()
            >
                {move || description.get()}
            </p>
        </header>
    }
}

/// A named h2 section with an optional explanatory sentence.
#[component]
pub fn PageSection(
    /// Stable h2 DOM token used to name the section.
    #[prop(into)]
    heading_id: String,
    /// Visible localized h2 text.
    #[prop(into)]
    title: TextProp,
    /// Optional localized explanatory sentence.
    #[prop(optional, into)]
    description: TextProp,
    children: Children,
) -> impl IntoView {
    assert_dom_id(&heading_id);
    assert!(
        !title.get().trim().is_empty(),
        "section title must be nonempty"
    );
    let labelled_by = heading_id.clone();
    let visible_description = description.clone();
    view! {
        <section class="ob-page-section" aria-labelledby=labelled_by>
            <h2 id=heading_id>{move || title.get()}</h2>
            <p
                class="ob-page-section-description"
                hidden=move || visible_description.get().trim().is_empty()
            >
                {move || description.get()}
            </p>
            {children()}
        </section>
    }
}

/// Thinly divided library rows; callers omit this component for empty collections.
#[component]
pub fn PageRows(children: Children) -> impl IntoView {
    view! { <div class="ob-page-rows">{children()}</div> }
}

/// Sentence-level empty fact for an already named configuration section.
#[component]
pub fn PageEmpty(children: Children) -> impl IntoView {
    view! { <p class="ob-page-empty">{children()}</p> }
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "layout id must be one bounded DOM token"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_and_ids_are_closed() {
        assert_eq!(PageWidth::Content.as_str(), "content");
        assert_eq!(PageWidth::Table.as_str(), "table");
        assert_eq!(PageWidth::Chat.as_str(), "chat");
        assert_dom_id("settings-connected-accounts");
    }
}
