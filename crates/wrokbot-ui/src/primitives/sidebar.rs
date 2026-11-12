//! Responsive application sidebar with large, rail, and mobile-Sheet presentations.

use leptos::context::Provider;
use leptos::html;
use leptos::prelude::*;
use time::OffsetDateTime;

use crate::icons::Icon;

use super::modal::{ModalPresentation, modal_root_with_inline};
use super::{
    Avatar, AvatarSize, Badge, BadgeTone, DialogContent, IconSize, IconView, SheetSide, Timestamp,
};

/// First-source breakpoint where the full desktop layout begins.
pub const SIDEBAR_LARGE_BREAKPOINT_PX: u32 = 1101;
/// First-source breakpoint above the narrow Web navigation Sheet.
pub const SIDEBAR_MEDIUM_BREAKPOINT_PX: u32 = 701;

/// Responsive presentation selected from the real viewport width.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SidebarViewport {
    /// Above 1100px: user-controlled content sidebar beside the separate 48px rail.
    #[default]
    Large,
    /// 701–1100px: the same user-controlled sidebar; no automatic collapse.
    Medium,
    /// At most 700px: navigation moves into the shared Sheet modal.
    Compact,
}

impl SidebarViewport {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Large => "large",
            Self::Medium => "medium",
            Self::Compact => "compact",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SidebarState {
    Expanded,
    Rail,
    MobileOpen,
    MobileClosed,
}

impl SidebarState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Expanded => "expanded",
            Self::Rail => "rail",
            Self::MobileOpen => "mobile-open",
            Self::MobileClosed => "mobile-closed",
        }
    }
}

#[derive(Clone)]
struct SidebarContext {
    id: String,
    collapsed: RwSignal<bool>,
    mobile_open: RwSignal<bool>,
    viewport: RwSignal<SidebarViewport>,
    aria_label: TextProp,
    mobile_title: TextProp,
    mobile_description: TextProp,
    on_collapsed_change: Option<UnsyncCallback<bool>>,
    trigger_ref: NodeRef<html::Button>,
    rail_trigger_ref: NodeRef<html::Button>,
}

/// Read-only/control handle for shell composition below [`SidebarProvider`].
#[derive(Clone)]
pub struct SidebarController {
    context: SidebarContext,
}

impl SidebarController {
    /// The separately mounted desktop rail toggle is a visible return-focus target.
    pub fn rail_trigger_ref(&self) -> NodeRef<html::Button> {
        self.context.rail_trigger_ref
    }
    /// Current responsive presentation.
    pub fn viewport(&self) -> SidebarViewport {
        self.context.viewport.get()
    }

    /// Current semantic state after responsive rules are applied.
    pub fn state(&self) -> &'static str {
        effective_state(&self.context).as_str()
    }

    /// Toggle the allowed state for the current viewport.
    pub fn toggle(&self) {
        toggle_sidebar(self.context.clone());
    }

    /// Open the navigation and focus its actual loaded-channel history region.
    pub fn show_history(&self) {
        if self.context.viewport.get_untracked() == SidebarViewport::Compact {
            self.context.mobile_open.set(true);
        } else {
            self.context.collapsed.set(false);
            if let Some(callback) = self.context.on_collapsed_change {
                callback.run(false);
            }
        }
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            use wasm_bindgen::JsCast as _;
            leptos::task::tick().await;
            if let Some(history) = web_sys::window()
                .and_then(|window| window.document())
                .and_then(|document| document.get_element_by_id("sidebar-history"))
                .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
            {
                _ = history.focus();
            }
        });
    }
}

/// Read the nearest sidebar controller.
pub fn use_sidebar() -> SidebarController {
    SidebarController {
        context: sidebar_context(),
    }
}

/// Provide one responsive/collapse/mobile/shortcut state to Sidebar and its shell trigger.
#[component]
pub fn SidebarProvider(
    #[prop(into)] id: String,
    collapsed: RwSignal<bool>,
    #[prop(into)] aria_label: TextProp,
    #[prop(into)] mobile_title: TextProp,
    #[prop(into)] mobile_description: TextProp,
    #[prop(optional)] on_collapsed_change: Option<UnsyncCallback<bool>>,
    children: Children,
) -> impl IntoView {
    assert_dom_id(&id);
    assert!(
        !aria_label.get().is_empty(),
        "Sidebar label must be nonempty"
    );
    assert!(
        !mobile_title.get().is_empty(),
        "Sidebar mobile title must be nonempty"
    );
    let context = SidebarContext {
        id,
        collapsed,
        mobile_open: RwSignal::new(false),
        viewport: RwSignal::new(SidebarViewport::Large),
        aria_label,
        mobile_title,
        mobile_description,
        on_collapsed_change,
        trigger_ref: NodeRef::new(),
        rail_trigger_ref: NodeRef::new(),
    };
    install_viewport_observer(context.clone());
    install_shortcut(context.clone());
    let state_context = context.clone();
    view! {
        <Provider value=context>
            <div
                class="ob-sidebar-provider"
                data-viewport=move || state_context.viewport.get().as_str()
                data-state=move || effective_state(&state_context).as_str()
            >
                {children()}
            </div>
        </Provider>
    }
}

/// Render one nav tree as an aside on desktop/rail or inside the shared Sheet on compact widths.
#[component]
pub fn Sidebar(children: Children) -> impl IntoView {
    let context = sidebar_context();
    let state_context = context.clone();
    let viewport = context.viewport;
    let inline = Signal::derive(move || viewport.get() != SidebarViewport::Compact);
    let close_context = context.clone();
    let sheet_id = context.id;
    let mobile_open = context.mobile_open;
    let title = context.mobile_title;
    let description = context.mobile_description;
    let aria_label = context.aria_label;
    let content: Children = Box::new(move || {
        view! {
                <DialogContent
                    title=move || title.get()
                    description=move || description.get()
                >
                    <nav
                        class="ob-sidebar-nav"
                        data-mobile=move || (!inline.get()).then_some("true")
                        on:click=move |event| close_mobile_on_navigation(event, mobile_open)
                        aria-label=move || aria_label.get()
                    >
                        {children()}
                    </nav>
                </DialogContent>
        }
        .into_any()
    });
    let modal = modal_root_with_inline(
        mobile_open,
        ModalPresentation::Sheet(SheetSide::Left),
        Some(UnsyncCallback::new(move |_| {
            focus_sidebar_trigger_later(close_context.clone())
        })),
        sheet_id,
        inline,
        content,
    );
    view! {
        <aside class="ob-sidebar"
            data-inline=move || inline.get().to_string()
            data-state=move || effective_state(&state_context).as_str()>
            {modal}
        </aside>
    }
}

// Handle every real link in the mobile nav, including custom account and history links.
fn close_mobile_on_navigation(event: leptos::ev::MouseEvent, open: RwSignal<bool>) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast as _;
        if event.button() != 0
            || event.ctrl_key()
            || event.meta_key()
            || event.shift_key()
            || event.alt_key()
        {
            return;
        }
        let navigates = event
            .target()
            .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
            .and_then(|element| element.closest("a[href]").ok().flatten())
            .is_some();
        if navigates {
            open.set(false);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (event, open);
}

/// Toggle button for the shell, also the mobile Sheet's return-focus target.
#[component]
pub fn SidebarTrigger(
    #[prop(optional, into)] id: Option<String>,
    #[prop(into)] aria_label: TextProp,
) -> impl IntoView {
    if let Some(id) = &id {
        assert_dom_id(id);
    }
    assert!(
        !aria_label.get().is_empty(),
        "SidebarTrigger label must be nonempty"
    );
    let context = sidebar_context();
    let controls_context = context.clone();
    let expanded_context = context.clone();
    let click_context = context.clone();
    let trigger_node = context.trigger_ref;
    view! {
        <button
            id=id
            type="button"
            class="ob-sidebar-trigger"
            data-state=move || effective_state(&context).as_str()
            aria-label=move || aria_label.get()
            aria-controls=move || controls_id(&controls_context)
            aria-expanded=move || explicit_bool(sidebar_expanded(&expanded_context))
            node_ref=trigger_node
            on:click=move |_| toggle_sidebar(click_context.clone())
        >
            <IconView icon=Icon::PanelLeft size=IconSize::Navigation />
        </button>
    }
}

/// Brand/top controls slot.
#[component]
pub fn SidebarHeader(children: Children) -> impl IntoView {
    view! { <header class="ob-sidebar-header" on:mousedown=crate::api::desktop_chrome::start_drag>{children()}</header> }
}

/// Scrollable primary groups slot.
#[component]
pub fn SidebarContent(children: Children) -> impl IntoView {
    view! { <div class="ob-sidebar-content">{children()}</div> }
}

/// Bottom-pinned user/settings slot.
#[component]
pub fn SidebarFooter(children: Children) -> impl IntoView {
    view! { <footer class="ob-sidebar-footer">{children()}</footer> }
}

/// Navigation group.
#[component]
pub fn SidebarGroup(children: Children) -> impl IntoView {
    view! { <div class="ob-sidebar-group">{children()}</div> }
}

/// Group heading hidden visually in rail state.
#[component]
pub fn SidebarGroupLabel(children: Children) -> impl IntoView {
    view! { <div class="ob-sidebar-group-label">{children()}</div> }
}

/// Semantic navigation list.
#[component]
pub fn SidebarNavList(children: Children) -> impl IntoView {
    view! { <ul class="ob-sidebar-list">{children()}</ul> }
}

/// The one sidebar navigation row: a same-origin link, or a button when the destination is not a
/// URL (a direct-assistant conversation). It shows an optional icon or avatar, a one-line label
/// with its full text as the tooltip, an optional secondary line, an optional time and count, and
/// marks the current destination with `aria-current="page"`. Row-end controls (`actions`) and
/// content beneath the row (`below`) sit outside the activating element.
#[component]
pub fn SidebarRow(
    /// Same-origin destination; without it the row is a button running `on_activate`.
    #[prop(optional, into)]
    href: Option<String>,
    /// Activation of a button row.
    #[prop(optional)]
    on_activate: Option<UnsyncCallback<()>>,
    /// Leading icon.
    #[prop(optional)]
    icon: Option<Icon>,
    /// Leading avatar seed; the avatar is named after the label.
    #[prop(optional, into)]
    avatar: Option<String>,
    /// Visible label.
    #[prop(into)]
    label: TextProp,
    /// Optional second line.
    #[prop(optional, into)]
    secondary: MaybeProp<String>,
    /// Optional trailing time.
    #[prop(optional_no_strip)]
    time: Option<OffsetDateTime>,
    /// Optional trailing count or short status.
    #[prop(optional, into)]
    badge: MaybeProp<String>,
    /// Whether this row is the current destination.
    #[prop(optional, into)]
    current: MaybeProp<bool>,
    /// Row-end controls.
    #[prop(optional, into)]
    actions: Option<ViewFn>,
    /// Content shown beneath the row.
    #[prop(optional, into)]
    below: Option<ViewFn>,
) -> impl IntoView {
    assert!(
        href.is_some() != on_activate.is_some(),
        "SidebarRow is either a link or a button"
    );
    if let Some(href) = &href {
        assert_same_origin_href(href);
    }
    let lead = (icon, avatar.map(|seed| (seed, label.get().to_string())));
    let title = label.clone();
    let content = move || {
        view! {
            {lead.0.map(|icon| view! { <IconView icon size=IconSize::Navigation /> })}
            {lead.1.clone().map(|(seed, name)| view! {
                <span class="ob-sidebar-row-avatar" aria-hidden="true">
                    <Avatar principal_id=seed name size=AvatarSize::Medium />
                </span>
            })}
            <span class="ob-sidebar-row-text">
                <span class="ob-sidebar-row-label">{move || label.get()}</span>
                {move || secondary.get().map(|text| view! {
                    <span class="ob-sidebar-row-secondary">{text}</span>
                })}
            </span>
            {time.map(|at| view! { <span class="ob-sidebar-row-time"><Timestamp at /></span> })}
            {move || badge.get().map(|text| view! { <Badge tone=BadgeTone::Caution>{text}</Badge> })}
        }
    };
    let aria_current = move || current.get().unwrap_or(false).then_some("page");
    let main = match (href, on_activate) {
        (Some(href), _) => view! {
            <a class="ob-sidebar-row-main" href=href title=move || title.get() aria-current=aria_current>
                {content()}
            </a>
        }
        .into_any(),
        (None, Some(on_activate)) => {
            let context = sidebar_context();
            view! {
                <button
                    type="button"
                    class="ob-sidebar-row-main"
                    title=move || title.get()
                    aria-current=aria_current
                    on:click=move |_| {
                        on_activate.run(());
                        if context.viewport.get_untracked() == SidebarViewport::Compact {
                            context.mobile_open.set(false);
                        }
                    }
                >
                    {content()}
                </button>
            }
            .into_any()
        }
        (None, None) => unreachable!("checked above"),
    };
    view! {
        <li class="ob-sidebar-row">
            <div class="ob-sidebar-row-line">
                {main}
                {actions.map(|actions| view! { <span class="ob-sidebar-row-actions">{actions.run()}</span> })}
            </div>
            {below.map(|below| below.run())}
        </li>
    }
}

fn sidebar_context() -> SidebarContext {
    use_context::<SidebarContext>()
        .expect("Sidebar compound component must be nested in SidebarProvider")
}

fn effective_state(context: &SidebarContext) -> SidebarState {
    match context.viewport.get() {
        SidebarViewport::Large | SidebarViewport::Medium if context.collapsed.get() => {
            SidebarState::Rail
        }
        SidebarViewport::Large | SidebarViewport::Medium => SidebarState::Expanded,
        SidebarViewport::Compact if context.mobile_open.get() => SidebarState::MobileOpen,
        SidebarViewport::Compact => SidebarState::MobileClosed,
    }
}

fn sidebar_expanded(context: &SidebarContext) -> bool {
    matches!(
        effective_state(context),
        SidebarState::Expanded | SidebarState::MobileOpen
    )
}

fn controls_id(context: &SidebarContext) -> String {
    format!("{}-panel", context.id)
}

fn toggle_sidebar(context: SidebarContext) {
    match context.viewport.get_untracked() {
        SidebarViewport::Large | SidebarViewport::Medium => {
            let collapsed = !context.collapsed.get_untracked();
            context.collapsed.set(collapsed);
            if let Some(callback) = context.on_collapsed_change {
                callback.run(collapsed);
            }
        }
        SidebarViewport::Compact => {
            let closing = context.mobile_open.get_untracked();
            context.mobile_open.set(!closing);
            if closing {
                focus_sidebar_trigger_later(context);
            }
        }
    }
}

fn install_viewport_observer(context: SidebarContext) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        struct ObserverState {
            observer: web_sys::ResizeObserver,
            _callback:
                wasm_bindgen::closure::Closure<dyn FnMut(js_sys::Array, web_sys::ResizeObserver)>,
        }

        let observer_state = StoredValue::new_local(None::<ObserverState>);
        let effect_context = context.clone();
        Effect::new(move |_| {
            if observer_state.with_value(Option::is_some) {
                return;
            }
            update_viewport(effect_context.clone());
            let callback_context = effect_context.clone();
            let callback =
                Closure::<dyn FnMut(js_sys::Array, web_sys::ResizeObserver)>::new(move |_, _| {
                    update_viewport(callback_context.clone());
                });
            let Some(root) = web_sys::window()
                .and_then(|window| window.document())
                .and_then(|document| document.document_element())
            else {
                return;
            };
            if let Ok(observer) = web_sys::ResizeObserver::new(callback.as_ref().unchecked_ref()) {
                observer.observe(&root);
                observer_state.set_value(Some(ObserverState {
                    observer,
                    _callback: callback,
                }));
            }
        });
        on_cleanup(move || {
            observer_state.update_value(|state| {
                if let Some(state) = state.take() {
                    state.observer.disconnect();
                }
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = context;
}

#[cfg(target_arch = "wasm32")]
fn update_viewport(context: SidebarContext) {
    let Some(width) = web_sys::window()
        .and_then(|window| window.inner_width().ok())
        .and_then(|width| width.as_f64())
    else {
        return;
    };
    let viewport = viewport_for_width(width);
    context.viewport.set(viewport);
    if viewport != SidebarViewport::Compact {
        let was_open = context.mobile_open.get_untracked();
        context.mobile_open.set(false);
        if was_open {
            focus_sidebar_trigger_later(context);
        }
    }
}

fn focus_sidebar_trigger_later(context: SidebarContext) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        leptos::task::tick().await;
        let target = if context.viewport.get_untracked() == SidebarViewport::Compact {
            context.trigger_ref
        } else {
            context.rail_trigger_ref
        };
        if let Some(trigger) = target.get() {
            _ = web_sys::HtmlElement::focus(&trigger);
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = context;
}

#[cfg(target_arch = "wasm32")]
struct ShortcutState {
    window: web_sys::Window,
    callback: wasm_bindgen::closure::Closure<dyn FnMut(web_sys::KeyboardEvent)>,
}

fn install_shortcut(context: SidebarContext) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        let shortcut_state = StoredValue::new_local(None::<ShortcutState>);
        let shortcut_context = context.clone();
        if let Some(window) = web_sys::window() {
            let callback = Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(
                move |event: web_sys::KeyboardEvent| {
                    let shortcut = event.key().eq_ignore_ascii_case("b")
                        && (event.meta_key() || event.ctrl_key())
                        && !event.alt_key();
                    if shortcut {
                        event.prevent_default();
                        toggle_sidebar(shortcut_context.clone());
                    }
                },
            );
            if window
                .add_event_listener_with_callback("keydown", callback.as_ref().unchecked_ref())
                .is_ok()
            {
                shortcut_state.set_value(Some(ShortcutState { window, callback }));
            }
        }
        on_cleanup(move || {
            shortcut_state.update_value(|state| {
                if let Some(state) = state.take() {
                    _ = state.window.remove_event_listener_with_callback(
                        "keydown",
                        state.callback.as_ref().unchecked_ref(),
                    );
                }
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = context;
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn viewport_for_width(width: f64) -> SidebarViewport {
    if width >= f64::from(SIDEBAR_LARGE_BREAKPOINT_PX) {
        SidebarViewport::Large
    } else if width >= f64::from(SIDEBAR_MEDIUM_BREAKPOINT_PX) {
        SidebarViewport::Medium
    } else {
        SidebarViewport::Compact
    }
}

fn assert_dom_id(id: &str) {
    assert!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "Sidebar id must be one bounded DOM token"
    );
}

fn assert_same_origin_href(href: &str) {
    assert!(
        href.starts_with('/')
            && !href.starts_with("//")
            && href.len() <= 2048
            && !href.chars().any(char::is_control),
        "SidebarRow href must be one bounded same-origin absolute path"
    );
}

const fn explicit_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidebar_breakpoints_states_and_links_are_closed() {
        assert_eq!(viewport_for_width(1440.0), SidebarViewport::Large);
        assert_eq!(viewport_for_width(1101.0), SidebarViewport::Large);
        assert_eq!(viewport_for_width(1100.0), SidebarViewport::Medium);
        assert_eq!(viewport_for_width(701.0), SidebarViewport::Medium);
        assert_eq!(viewport_for_width(700.0), SidebarViewport::Compact);
        assert_eq!(SidebarViewport::Large.as_str(), "large");
        assert_eq!(SidebarState::Expanded.as_str(), "expanded");
        assert_dom_id("app-sidebar");
        assert_same_origin_href("/settings/profile");
    }

    #[test]
    #[should_panic(expected = "same-origin")]
    fn sidebar_rejects_external_links() {
        assert_same_origin_href("https://example.com/settings");
    }
}
