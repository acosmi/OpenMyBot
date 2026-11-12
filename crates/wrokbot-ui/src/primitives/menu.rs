//! APG menu button with one-level submenu and bounded typeahead.

use leptos::context::Provider;
use leptos::ev::KeyboardEvent;
use leptos::html;
use leptos::prelude::*;

use super::timing::schedule_timeout;

const TYPEAHEAD_RESET_MS: i32 = 500;

/// Which edge of the trigger the root popup lines up with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MenuAlign {
    /// The popup starts at the trigger's inline-start edge.
    #[default]
    Start,
    /// The popup ends at the trigger's inline-end edge, for triggers at the end of a row.
    End,
}

#[derive(Clone)]
struct RootMenu {
    open: RwSignal<bool>,
    trigger_ref: NodeRef<html::Button>,
    on_close: Option<UnsyncCallback<()>>,
    align: MenuAlign,
}

#[derive(Clone)]
struct MenuContext {
    id: String,
    open: RwSignal<bool>,
    trigger_ref: NodeRef<html::Button>,
    content_ref: NodeRef<html::Div>,
    root: RootMenu,
    parent_trigger: Option<NodeRef<html::Button>>,
    pending_focus_last: RwSignal<Option<bool>>,
    typeahead: RwSignal<String>,
    typeahead_generation: RwSignal<u64>,
}

/// Root menu state/provider.
#[component]
pub fn Menu(
    #[prop(into)] id: String,
    open: RwSignal<bool>,
    #[prop(optional)] on_close: Option<UnsyncCallback<()>>,
    #[prop(optional)] align: MenuAlign,
    children: Children,
) -> impl IntoView {
    assert_dom_id(&id);
    let trigger_ref = NodeRef::new();
    let root = RootMenu {
        open,
        trigger_ref,
        on_close,
        align,
    };
    let context = MenuContext {
        id,
        open,
        trigger_ref,
        content_ref: NodeRef::new(),
        root,
        parent_trigger: None,
        pending_focus_last: RwSignal::new(None),
        typeahead: RwSignal::new(String::new()),
        typeahead_generation: RwSignal::new(0),
    };
    install_open_focus(context.clone());
    view! {
        <Provider value=context>
            <span class="ob-menu-root">{children()}</span>
        </Provider>
    }
}

/// Root menu button.
#[component]
pub fn MenuTrigger(
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    children: Children,
) -> impl IntoView {
    let context = menu_context();
    let trigger_id = format!("{}-trigger", context.id);
    let content_id = format!("{}-content", context.id);
    let click_context = context.clone();
    let key_context = context.clone();
    view! {
        <button
            id=trigger_id
            type="button"
            class="ob-menu-trigger"
            node_ref=context.trigger_ref
            data-state=move || menu_state_tokens(
                context.open.get(),
                disabled.get().unwrap_or(false),
            )
            aria-haspopup="menu"
            aria-expanded=move || explicit_bool(context.open.get())
            aria-controls=content_id
            aria-disabled=move || explicit_bool(disabled.get().unwrap_or(false))
            disabled=move || disabled.get().unwrap_or(false)
            on:click=move |_| {
                if disabled.get().unwrap_or(false) {
                    return;
                }
                if click_context.open.get_untracked() {
                    close_root(click_context.root.clone(), true);
                } else {
                    open_menu(click_context.clone(), false);
                }
            }
            on:keydown=move |event: KeyboardEvent| {
                if disabled.get().unwrap_or(false) {
                    return;
                }
                match event.key().as_str() {
                    "ArrowDown" | "Enter" | " " => {
                        event.prevent_default();
                        open_menu(key_context.clone(), false);
                    }
                    "ArrowUp" => {
                        event.prevent_default();
                        open_menu(key_context.clone(), true);
                    }
                    "Escape" if key_context.open.get_untracked() => {
                        event.prevent_default();
                        close_root(key_context.root.clone(), true);
                    }
                    _ => {}
                }
            }
        >{children()}</button>
    }
}

/// Root or submenu popup.
#[component]
pub fn MenuContent(children: Children) -> impl IntoView {
    let context = menu_context();
    let content_id = format!("{}-content", context.id);
    let trigger_id = format!("{}-trigger", context.id);
    let is_root = context.parent_trigger.is_none();
    let align_end = is_root && context.root.align == MenuAlign::End;
    let dismiss_root = context.root.clone();
    let key_context = context.clone();
    view! {
        {is_root.then(|| view! {
            <div
                class="ob-menu-dismiss"
                hidden=move || !context.open.get()
                on:click=move |_| close_root(dismiss_root.clone(), true)
            ></div>
        })}
        <div
            id=content_id
            class="ob-menu-content"
            role="menu"
            aria-labelledby=trigger_id
            hidden=move || !context.open.get()
            tabindex="-1"
            node_ref=context.content_ref
            data-level=if is_root { "root" } else { "sub" }
            data-align=align_end.then_some("end")
            data-state=move || menu_state_tokens(context.open.get(), false)
            on:keydown=move |event| handle_menu_key(event, key_context.clone())
        >
            {children()}
        </div>
    }
}

/// Action item. Disabled items are skipped by keyboard focus and cannot activate.
#[component]
pub fn MenuItem(
    #[prop(optional, into)] id: Option<String>,
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    #[prop(into)] on_select: UnsyncCallback<()>,
    children: Children,
) -> impl IntoView {
    if let Some(id) = &id {
        assert_dom_id(id);
    }
    let context = menu_context();
    let click_root = context.root.clone();
    let key_root = context.root;
    view! {
        <button
            id=id
            type="button"
            class="ob-menu-item"
            role="menuitem"
            tabindex="-1"
            data-state=move || menu_state_tokens(false, disabled.get().unwrap_or(false))
            aria-disabled=move || explicit_bool(disabled.get().unwrap_or(false))
            disabled=move || disabled.get().unwrap_or(false)
            on:click=move |_| {
                if !disabled.get().unwrap_or(false) {
                    on_select.run(());
                    close_root(click_root.clone(), true);
                }
            }
            on:keydown=move |event: KeyboardEvent| {
                if matches!(event.key().as_str(), "Enter" | " ")
                    && !disabled.get().unwrap_or(false)
                {
                    event.prevent_default();
                    on_select.run(());
                    close_root(key_root.clone(), true);
                }
            }
        >{children()}</button>
    }
}

/// Decorative separator inside a menu.
#[component]
pub fn MenuSeparator() -> impl IntoView {
    view! { <div class="ob-menu-separator" role="separator"></div> }
}

/// One nested submenu provider. Nested submenus beyond one level are intentionally unsupported.
#[component]
pub fn MenuSub(#[prop(into)] id: String, children: Children) -> impl IntoView {
    assert_dom_id(&id);
    let parent = menu_context();
    assert!(
        parent.parent_trigger.is_none(),
        "Menu supports one submenu level only"
    );
    let trigger_ref = NodeRef::new();
    let context = MenuContext {
        id,
        open: RwSignal::new(false),
        trigger_ref,
        content_ref: NodeRef::new(),
        root: parent.root.clone(),
        parent_trigger: Some(trigger_ref),
        pending_focus_last: RwSignal::new(None),
        typeahead: RwSignal::new(String::new()),
        typeahead_generation: RwSignal::new(0),
    };
    install_open_focus(context.clone());
    let root_open = context.root.open;
    let sub_open = context.open;
    Effect::new(move |_| {
        if !root_open.get() {
            sub_open.set(false);
        }
    });
    view! {
        <Provider value=context>
            <span
                class="ob-menu-sub"
                data-state=move || menu_state_tokens(sub_open.get(), false)
            >{children()}</span>
        </Provider>
    }
}

/// Parent menuitem that opens its submenu with Right/Enter/Space.
#[component]
pub fn MenuSubTrigger(
    #[prop(optional, into)] disabled: MaybeProp<bool>,
    children: Children,
) -> impl IntoView {
    let context = menu_context();
    assert!(
        context.parent_trigger.is_some(),
        "MenuSubTrigger requires MenuSub"
    );
    let trigger_id = format!("{}-trigger", context.id);
    let content_id = format!("{}-content", context.id);
    let click_context = context.clone();
    let key_context = context.clone();
    view! {
        <button
            id=trigger_id
            type="button"
            class="ob-menu-item ob-menu-sub-trigger"
            role="menuitem"
            tabindex="-1"
            data-state=move || menu_state_tokens(
                context.open.get(),
                disabled.get().unwrap_or(false),
            )
            aria-haspopup="menu"
            aria-expanded=move || explicit_bool(context.open.get())
            aria-controls=content_id
            aria-disabled=move || explicit_bool(disabled.get().unwrap_or(false))
            disabled=move || disabled.get().unwrap_or(false)
            node_ref=context.trigger_ref
            on:click=move |_| {
                if !disabled.get().unwrap_or(false) {
                    open_menu(click_context.clone(), false);
                }
            }
            on:keydown=move |event: KeyboardEvent| {
                if disabled.get().unwrap_or(false) {
                    return;
                }
                match event.key().as_str() {
                    "ArrowRight" | "Enter" | " " => {
                        event.prevent_default();
                        event.stop_propagation();
                        open_menu(key_context.clone(), false);
                    }
                    "ArrowLeft" | "Escape" if key_context.open.get_untracked() => {
                        event.prevent_default();
                        event.stop_propagation();
                        close_current(key_context.clone(), true);
                    }
                    _ => {}
                }
            }
        >
            <span>{children()}</span>
            <span aria-hidden="true">"›"</span>
        </button>
    }
}

fn menu_context() -> MenuContext {
    use_context::<MenuContext>().expect("Menu compound component must be nested in Menu/MenuSub")
}

fn install_open_focus(context: MenuContext) {
    let was_open = StoredValue::new(false);
    Effect::new(move |_| {
        let open = context.open.get();
        if open && !was_open.get_value() {
            let focus_last = context.pending_focus_last.get_untracked().unwrap_or(false);
            context.pending_focus_last.set(None);
            let focus_context = context.clone();
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                leptos::task::tick().await;
                focus_edge(focus_context.content_ref, focus_last);
            });
        }
        was_open.set_value(open);
    });
}

fn open_menu(context: MenuContext, focus_last: bool) {
    context.pending_focus_last.set(Some(focus_last));
    if context.open.get_untracked() {
        focus_edge(context.content_ref, focus_last);
    } else {
        context.open.set(true);
    }
}

fn close_current(context: MenuContext, return_focus: bool) {
    context.open.set(false);
    context.typeahead.set(String::new());
    if return_focus {
        let trigger = context.trigger_ref;
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            leptos::task::tick().await;
            focus_trigger(trigger);
        });
    }
}

fn close_root(root: RootMenu, return_focus: bool) {
    if root.open.get_untracked() {
        root.open.set(false);
        if let Some(callback) = root.on_close {
            callback.run(());
        }
    }
    if return_focus {
        let trigger = root.trigger_ref;
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            leptos::task::tick().await;
            focus_trigger(trigger);
        });
    }
}

fn handle_menu_key(event: KeyboardEvent, context: MenuContext) {
    let key = event.key();
    let handled_by_sub = matches!(
        key.as_str(),
        "ArrowDown" | "ArrowUp" | "Home" | "End" | "Escape" | "ArrowLeft" | "Tab"
    ) || is_typeahead_key(&event, &key);
    if context.parent_trigger.is_some() && handled_by_sub {
        event.stop_propagation();
    }
    match key.as_str() {
        "ArrowDown" => {
            event.prevent_default();
            focus_relative(context.content_ref, 1);
        }
        "ArrowUp" => {
            event.prevent_default();
            focus_relative(context.content_ref, -1);
        }
        "Home" => {
            event.prevent_default();
            focus_edge(context.content_ref, false);
        }
        "End" => {
            event.prevent_default();
            focus_edge(context.content_ref, true);
        }
        "Escape" => {
            event.prevent_default();
            if context.parent_trigger.is_some() {
                close_current(context, true);
            } else {
                close_root(context.root, true);
            }
        }
        "ArrowLeft" if context.parent_trigger.is_some() => {
            event.prevent_default();
            close_current(context, true);
        }
        "Tab" => {
            let backwards = event.shift_key();
            let root = context.root;
            schedule_timeout(0, move || close_root_after_tab(root, backwards));
        }
        key if is_typeahead_key(&event, key) => {
            event.prevent_default();
            push_typeahead(context, key);
        }
        _ => {}
    }
}

fn is_typeahead_key(event: &KeyboardEvent, key: &str) -> bool {
    key.chars().count() == 1
        && key != " "
        && !event.alt_key()
        && !event.ctrl_key()
        && !event.meta_key()
}

fn push_typeahead(context: MenuContext, key: &str) {
    context
        .typeahead
        .update(|buffer| buffer.extend(key.chars().flat_map(char::to_lowercase)));
    focus_prefix(context.content_ref, &context.typeahead.get_untracked());
    let generation = context
        .typeahead_generation
        .get_untracked()
        .saturating_add(1);
    context.typeahead_generation.set(generation);
    schedule_timeout(TYPEAHEAD_RESET_MS, move || {
        if context.typeahead_generation.get_untracked() == generation {
            context.typeahead.set(String::new());
        }
    });
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "Menu id must be one bounded DOM token"
    );
}

const fn explicit_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

const fn menu_state_tokens(open: bool, disabled: bool) -> Option<&'static str> {
    match (open, disabled) {
        (false, false) => None,
        (true, false) => Some("open"),
        (false, true) => Some("disabled"),
        (true, true) => Some("open disabled"),
    }
}

#[cfg(target_arch = "wasm32")]
fn menu_items(content_ref: NodeRef<html::Div>) -> Vec<web_sys::HtmlElement> {
    use wasm_bindgen::JsCast;

    let Some(content) = content_ref.get() else {
        return Vec::new();
    };
    let Ok(nodes) = web_sys::Element::query_selector_all(
        &content,
        "[role='menuitem']:not([aria-disabled='true'])",
    ) else {
        return Vec::new();
    };
    (0..nodes.length())
        .filter_map(|index| nodes.item(index))
        .filter_map(|node| node.dyn_into::<web_sys::HtmlElement>().ok())
        .filter(|item| {
            item.closest("[role='menu']")
                .ok()
                .flatten()
                .is_some_and(|owner| js_sys::Object::is(owner.as_ref(), content.as_ref()))
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn current_index(items: &[web_sys::HtmlElement]) -> Option<usize> {
    let active = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.active_element())?;
    items
        .iter()
        .position(|item| js_sys::Object::is(active.as_ref(), item.as_ref()))
}

#[cfg(target_arch = "wasm32")]
fn focus_edge(content_ref: NodeRef<html::Div>, last: bool) {
    let items = menu_items(content_ref);
    let target = if last { items.last() } else { items.first() };
    if let Some(target) = target {
        _ = target.focus();
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn focus_edge(_content_ref: NodeRef<html::Div>, _last: bool) {}

fn focus_relative(content_ref: NodeRef<html::Div>, delta: i32) {
    #[cfg(target_arch = "wasm32")]
    {
        let items = menu_items(content_ref);
        if items.is_empty() {
            return;
        }
        let current = current_index(&items).unwrap_or(if delta > 0 { items.len() - 1 } else { 0 });
        let next = (i32::try_from(current).expect("index fits i32") + delta)
            .rem_euclid(i32::try_from(items.len()).expect("menu length fits i32"));
        _ = items[usize::try_from(next).expect("nonnegative")].focus();
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (content_ref, delta);
}

fn focus_prefix(content_ref: NodeRef<html::Div>, prefix: &str) {
    #[cfg(target_arch = "wasm32")]
    if let Some(target) = menu_items(content_ref).into_iter().find(|item| {
        item.text_content()
            .unwrap_or_default()
            .trim()
            .to_lowercase()
            .starts_with(prefix)
    }) {
        _ = target.focus();
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (content_ref, prefix);
}

#[cfg(target_arch = "wasm32")]
fn focus_trigger(trigger_ref: NodeRef<html::Button>) {
    if let Some(trigger) = trigger_ref.get() {
        _ = web_sys::HtmlElement::focus(&trigger);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn focus_trigger(_trigger_ref: NodeRef<html::Button>) {}

fn close_root_after_tab(root: RootMenu, backwards: bool) {
    #[cfg(target_arch = "wasm32")]
    {
        let needs_fallback = tab_focus_needs_fallback();
        let trigger = root.trigger_ref;
        close_root(root, false);
        if needs_fallback {
            if backwards {
                focus_trigger(trigger);
            } else {
                focus_next_after_trigger(trigger);
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = backwards;
        close_root(root, false);
    }
}

#[cfg(target_arch = "wasm32")]
fn tab_focus_needs_fallback() -> bool {
    let Some(active) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.active_element())
    else {
        return true;
    };
    matches!(active.tag_name().as_str(), "BODY" | "HTML")
        || active.closest("[role='menu']").ok().flatten().is_some()
}

#[cfg(target_arch = "wasm32")]
fn focus_next_after_trigger(trigger_ref: NodeRef<html::Button>) {
    use wasm_bindgen::JsCast;

    let Some(trigger) = trigger_ref.get() else {
        return;
    };
    let Some(document) = web_sys::window().and_then(|window| window.document()) else {
        return;
    };
    let selector = "a[href]:not([tabindex='-1']),button:not([disabled]):not([tabindex='-1']),input:not([disabled]):not([tabindex='-1']),textarea:not([disabled]):not([tabindex='-1']),select:not([disabled]):not([tabindex='-1']),[tabindex]:not([tabindex='-1'])";
    let Ok(nodes) = document.query_selector_all(selector) else {
        return;
    };
    let focusables = (0..nodes.length())
        .filter_map(|index| nodes.item(index))
        .filter_map(|node| node.dyn_into::<web_sys::HtmlElement>().ok())
        .filter(|element| element.closest("[hidden],[inert]").ok().flatten().is_none())
        .collect::<Vec<_>>();
    let Some(index) = focusables
        .iter()
        .position(|element| js_sys::Object::is(element.as_ref(), trigger.as_ref()))
    else {
        return;
    };
    if let Some(target) = focusables.get(index + 1).or_else(|| focusables.first()) {
        _ = target.focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_constants_and_ids_are_closed() {
        assert_eq!(TYPEAHEAD_RESET_MS, 500);
        assert_dom_id("actions-menu");
        assert_eq!(explicit_bool(false), "false");
        assert_eq!(menu_state_tokens(false, false), None);
        assert_eq!(menu_state_tokens(true, true), Some("open disabled"));
    }

    #[test]
    #[should_panic(expected = "Menu id")]
    fn menu_id_cannot_split_aria_tokens() {
        assert_dom_id("bad menu");
    }
}
