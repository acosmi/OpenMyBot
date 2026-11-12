#![cfg(feature = "design-gallery")]
//! Compile-time-only primitive gallery; never part of a production bundle.

use leptos::prelude::*;

use crate::features::agents::{AgentPresence, AgentPresenceState};
use crate::features::computer::ComputerPlaceholder;
use crate::features::gallery::{GalleryBadge, GalleryFrame, GalleryTone, QuoteCard, RefusedCard};
use crate::features::layout::{
    DetailPanel, DetailPanelLayout, DetailPanelMain, PageActions, PageEmpty, PageRows, PageSection,
    PageShell, PageWidth, RowMark, SectionTab, SectionTabs, StaggerItem,
};
use crate::features::settings::ComputerPlaceholderArt;
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Avatar, AvatarSize, Bubble, BubbleKind, Button, ButtonPreviewState, ButtonSize, ButtonVariant,
    Combobox, ComboboxContent, ComboboxEmpty, ComboboxInput, ComboboxItem, ComboboxList, Dialog,
    DialogBody, DialogClose, DialogContent, DialogFooter, DialogTrigger, Field, IconSize, IconView,
    Input, InputGroup, InputGroupAffix, InputGroupAffixPosition, InputPreviewState, InputType,
    Item, ItemAction, ItemActions, ItemDescription, ItemMedia, ItemTitle, Kbd, KbdKey, KbdModifier,
    Menu, MenuContent, MenuItem, MenuSeparator, MenuSub, MenuSubTrigger, MenuTrigger, Message,
    MessageAlign, MessageAvatar, MessageContent, MessageFooter, MessageGroup, MessageHeader,
    MessageScroller, MessageScrollerButton, MessageScrollerContent, MessageScrollerItem,
    MessageScrollerViewport, Notice, NoticePresentation, NoticeTone, Select, SelectContent,
    SelectGroup, SelectItem, SelectTrigger, Separator, SeparatorOrientation, Sheet, SheetSide,
    Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupLabel, SidebarHeader,
    SidebarNavList, SidebarProvider, SidebarRow, SidebarTrigger, Skeleton, SkeletonShape, Switch,
    TechnicalDetails, Textarea, TextareaPreviewState, Timestamp, Toast, ToastPreviewState, Tooltip,
    TooltipTrigger, TooltipTriggerAction,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct ScrollerGalleryItem {
    id: i32,
    anchor: bool,
}

/// Render the first Batch 17 primitive states for golden, keyboard and AX inspection.
#[component]
pub fn DesignGallery() -> impl IntoView {
    let i18n = use_i18n();
    crate::shell::layout::set_shell_title(move || {
        vec![t_string!(i18n, design_gallery.title).to_owned()]
    });
    let button_count = RwSignal::new(0_u32);
    let item_count = RwSignal::new(0_u32);
    let name = RwSignal::new(String::new());
    let search = RwSignal::new(String::new());
    let notes = RwSignal::new(String::new());
    let enabled = RwSignal::new(false);
    let disabled_checked = RwSignal::new(true);
    let toast_preview_visible = RwSignal::new(true);
    let toast_auto_visible = RwSignal::new(true);
    let toast_dismiss_count = RwSignal::new(0_u32);
    let tooltip_activation_count = RwSignal::new(0_u32);
    let dialog_open = RwSignal::new(false);
    let dialog_close_count = RwSignal::new(0_u32);
    let sheet_open = RwSignal::new(false);
    let sheet_close_count = RwSignal::new(0_u32);
    let menu_open = RwSignal::new(false);
    let menu_select_count = RwSignal::new(0_u32);
    let menu_close_count = RwSignal::new(0_u32);
    let combobox_open = RwSignal::new(false);
    let combobox_value = RwSignal::new(None::<String>);
    let combobox_change_count = RwSignal::new(0_u32);
    let invalid_combobox_open = RwSignal::new(false);
    let invalid_combobox_value = RwSignal::new(None::<String>);
    let select_open = RwSignal::new(false);
    let select_value = RwSignal::new(Some("private".to_owned()));
    let select_change_count = RwSignal::new(0_u32);
    let disabled_select_open = RwSignal::new(false);
    let disabled_select_value = RwSignal::new(None::<String>);
    let sidebar_collapsed = RwSignal::new(false);
    let sidebar_change_count = RwSignal::new(0_u32);
    let detail_open = RwSignal::new(true);
    let detail_close_count = RwSignal::new(0_u32);
    let scroller_items = RwSignal::new(
        (1..=10)
            .map(|id| ScrollerGalleryItem {
                id,
                anchor: id % 2 == 1,
            })
            .collect::<Vec<_>>(),
    );
    let scroller_next_id = RwSignal::new(11_i32);
    let scroller_previous_id = RwSignal::new(-1_i32);
    let scroller_expanded_id = RwSignal::new(None::<i32>);
    let sample_time = time::macros::datetime!(2026-11-12 09:41 UTC);

    view! {
        <section class="ob-page ob-design-gallery" aria-labelledby="design-gallery-title">
            <header class="ob-page-header">
                <div>
                    <p class="ob-eyebrow">{move || t!(i18n, design_gallery.eyebrow)}</p>
                    <h1 id="design-gallery-title" class="ob-page-title">
                        {move || t!(i18n, design_gallery.title)}
                    </h1>
                    <p class="ob-page-intro">{move || t!(i18n, design_gallery.intro)}</p>
                </div>
            </header>

            <crate::features::computer::viewer::ScreenFixturePreview/>
            <crate::features::channels::markdown::MarkdownPreview/>
            <div class="ob-design-grid">
                <section class="ob-design-section" aria-labelledby="design-buttons-title">
                    <h2 id="design-buttons-title">{move || t!(i18n, design_gallery.buttons)}</h2>
                    <div class="ob-design-row" id="design-buttons">
                        <Button
                            variant=ButtonVariant::Chip
                            size=ButtonSize::Small
                            on_activate=move |_| button_count.update(|count| *count += 1)
                        >
                            {move || t!(i18n, design_gallery.activate)}
                        </Button>
                        <Button
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Medium
                            selected=true
                            on_activate=move |_| button_count.update(|count| *count += 1)
                        >
                            {move || t!(i18n, common.confirm)}
                        </Button>
                        <Button
                            variant=ButtonVariant::Ghost
                            size=ButtonSize::Large
                            open=true
                            preview_state=ButtonPreviewState::FocusVisible
                            on_activate=move |_| button_count.update(|count| *count += 1)
                        >
                            {move || t!(i18n, common.open)}
                        </Button>
                        <Button
                            variant=ButtonVariant::DangerText
                            size=ButtonSize::Medium
                            invalid=true
                            on_activate=move |_| button_count.update(|count| *count += 1)
                        >
                            {move || t!(i18n, common.delete)}
                        </Button>
                        <Button
                            loading=true
                            preview_state=ButtonPreviewState::Hover
                            on_activate=move |_| button_count.update(|count| *count += 1)
                        >
                            {move || t!(i18n, common.loading)}
                        </Button>
                        <Button
                            disabled=true
                            preview_state=ButtonPreviewState::Active
                            on_activate=move |_| button_count.update(|count| *count += 1)
                        >
                            {move || t!(i18n, common.disabled)}
                        </Button>
                    </div>
                    <output id="design-button-count" aria-live="polite">{button_count}</output>
                </section>

                <section class="ob-design-section" aria-labelledby="design-fields-title">
                    <h2 id="design-fields-title">{move || t!(i18n, design_gallery.fields)}</h2>
                    <div class="ob-design-stack" id="design-fields">
                        <Field
                            control_id="design-name"
                            label=move || t_string!(i18n, design_gallery.name_label).to_owned()
                            description=move || t_string!(i18n, design_gallery.name_description).to_owned()
                        >
                            <Input value=name input_type=InputType::Text />
                        </Field>
                        <Field
                            control_id="design-notes"
                            label=move || t_string!(i18n, design_gallery.notes_label).to_owned()
                            error=move || t_string!(i18n, errors.validation_invalid).to_owned()
                            invalid=true
                        >
                            <Textarea
                                value=notes
                                preview_state=TextareaPreviewState::Focus
                            />
                        </Field>
                        <Field
                            control_id="design-disabled-input"
                            label=move || t_string!(i18n, common.disabled).to_owned()
                            disabled=true
                        >
                            <Input value=name input_type=InputType::Text />
                        </Field>
                        <InputGroup preview_focus_within=true>
                            <InputGroupAffix position=InputGroupAffixPosition::Prefix>
                                <IconView icon=Icon::Search size=IconSize::Inline />
                            </InputGroupAffix>
                            <Input
                                value=search
                                input_type=InputType::Search
                                id="design-search"
                                aria_label=move || t_string!(i18n, shell.search).to_owned()
                                preview_state=InputPreviewState::Focus
                            />
                            <InputGroupAffix position=InputGroupAffixPosition::Suffix>
                                <Kbd modifier=KbdModifier::Primary key=KbdKey::Character('K') />
                            </InputGroupAffix>
                        </InputGroup>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-listboxes-title">
                    <h2 id="design-listboxes-title">{move || t!(i18n, design_gallery.listboxes)}</h2>
                    <div class="ob-design-stack" id="design-listboxes">
                        <Combobox
                            id="design-combobox"
                            open=combobox_open
                            value=combobox_value
                            on_value_change=UnsyncCallback::new(move |_| {
                                combobox_change_count.update(|count| *count += 1);
                            })
                        >
                            <ComboboxInput
                                aria_label=move || t_string!(i18n, design_gallery.combobox_label).to_owned()
                                placeholder=move || t_string!(i18n, design_gallery.combobox_placeholder).to_owned()
                            />
                            <ComboboxContent>
                                <ComboboxEmpty>
                                    {move || t!(i18n, design_gallery.combobox_empty)}
                                </ComboboxEmpty>
                                <ComboboxList>
                                    <ComboboxItem
                                        id="design-combobox-ada"
                                        value="ada"
                                        label=move || t_string!(i18n, design_gallery.combobox_ada).to_owned()
                                    >
                                        {move || t!(i18n, design_gallery.combobox_ada)}
                                    </ComboboxItem>
                                    <ComboboxItem
                                        id="design-combobox-grace"
                                        value="grace"
                                        label=move || t_string!(i18n, design_gallery.combobox_grace).to_owned()
                                        disabled=true
                                    >
                                        {move || t!(i18n, design_gallery.combobox_grace)}
                                    </ComboboxItem>
                                    <ComboboxItem
                                        id="design-combobox-zhang"
                                        value="zhang"
                                        label=move || t_string!(i18n, design_gallery.combobox_zhang).to_owned()
                                    >
                                        {move || t!(i18n, design_gallery.combobox_zhang)}
                                    </ComboboxItem>
                                </ComboboxList>
                            </ComboboxContent>
                        </Combobox>
                        <div class="ob-design-row">
                            <output id="design-combobox-value" aria-live="polite">
                                {move || combobox_value.get().unwrap_or_else(|| "—".to_owned())}
                            </output>
                            <output id="design-combobox-change-count" aria-live="polite">
                                {combobox_change_count}
                            </output>
                        </div>
                        <Field
                            control_id="design-combobox-invalid"
                            label=move || t_string!(i18n, design_gallery.combobox_invalid).to_owned()
                            error=move || t_string!(i18n, errors.validation_invalid).to_owned()
                            invalid=true
                        >
                            <Combobox
                                id="design-combobox-invalid"
                                open=invalid_combobox_open
                                value=invalid_combobox_value
                                preview_focus=true
                            >
                                <ComboboxInput
                                    aria_label=move || t_string!(i18n, design_gallery.combobox_invalid).to_owned()
                                    placeholder=move || t_string!(i18n, design_gallery.combobox_invalid).to_owned()
                                />
                                <ComboboxContent>
                                    <ComboboxList>
                                        <ComboboxItem
                                            id="design-combobox-invalid-option"
                                            value="invalid"
                                            label=move || t_string!(i18n, design_gallery.combobox_invalid).to_owned()
                                        >
                                            {move || t!(i18n, design_gallery.combobox_invalid)}
                                        </ComboboxItem>
                                    </ComboboxList>
                                </ComboboxContent>
                            </Combobox>
                        </Field>
                        <Select
                            id="design-select"
                            open=select_open
                            value=select_value
                            on_value_change=UnsyncCallback::new(move |_| {
                                select_change_count.update(|count| *count += 1);
                            })
                        >
                            <SelectTrigger
                                aria_label=move || t_string!(i18n, design_gallery.select_label).to_owned()
                                placeholder=move || t_string!(i18n, design_gallery.select_placeholder).to_owned()
                            />
                            <SelectContent>
                                <SelectGroup>
                                    <SelectItem
                                        id="design-select-private"
                                        value="private"
                                        label=move || t_string!(i18n, design_gallery.select_private).to_owned()
                                    >
                                        {move || t!(i18n, design_gallery.select_private)}
                                    </SelectItem>
                                    <SelectItem
                                        id="design-select-team"
                                        value="team"
                                        label=move || t_string!(i18n, design_gallery.select_team).to_owned()
                                        disabled=true
                                    >
                                        {move || t!(i18n, design_gallery.select_team)}
                                    </SelectItem>
                                    <SelectItem
                                        id="design-select-public"
                                        value="public"
                                        label=move || t_string!(i18n, design_gallery.select_public).to_owned()
                                    >
                                        {move || t!(i18n, design_gallery.select_public)}
                                    </SelectItem>
                                </SelectGroup>
                            </SelectContent>
                        </Select>
                        <div class="ob-design-row">
                            <output id="design-select-value" aria-live="polite">
                                {move || select_value.get().unwrap_or_else(|| "—".to_owned())}
                            </output>
                            <output id="design-select-change-count" aria-live="polite">
                                {select_change_count}
                            </output>
                        </div>
                        <Field
                            control_id="design-select-disabled"
                            label=move || t_string!(i18n, design_gallery.select_disabled).to_owned()
                            disabled=true
                        >
                            <Select
                                id="design-select-disabled"
                                open=disabled_select_open
                                value=disabled_select_value
                            >
                                <SelectTrigger
                                    aria_label=move || t_string!(i18n, design_gallery.select_disabled).to_owned()
                                    placeholder=move || t_string!(i18n, design_gallery.select_disabled).to_owned()
                                />
                                <SelectContent>
                                    <SelectItem
                                        id="design-select-disabled-option"
                                        value="disabled"
                                        label=move || t_string!(i18n, design_gallery.select_disabled).to_owned()
                                    >
                                        {move || t!(i18n, design_gallery.select_disabled)}
                                    </SelectItem>
                                </SelectContent>
                            </Select>
                        </Field>
                        <button
                            id="design-listbox-after"
                            type="button"
                            class="ob-button"
                            data-variant="chip"
                            data-size="md"
                        >
                            {move || t!(i18n, design_gallery.listbox_after)}
                        </button>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-sidebar-title">
                    <h2 id="design-sidebar-title">{move || t!(i18n, design_gallery.sidebar)}</h2>
                    <SidebarProvider
                        id="design-sidebar"
                        collapsed=sidebar_collapsed
                        aria_label=move || t_string!(i18n, design_gallery.sidebar_label).to_owned()
                        mobile_title=move || t_string!(i18n, design_gallery.sidebar_mobile_title).to_owned()
                        mobile_description=move || t_string!(i18n, design_gallery.sidebar_mobile_description).to_owned()
                        on_collapsed_change=UnsyncCallback::new(move |_| {
                            sidebar_change_count.update(|count| *count += 1);
                        })
                    >
                        <div class="ob-design-sidebar-shell" id="design-sidebar-shell">
                            <Sidebar>
                                <SidebarHeader>
                                    <IconView icon=Icon::Bot size=IconSize::Navigation />
                                    <span class="ob-account-name">{move || t!(i18n, common.app_name)}</span>
                                </SidebarHeader>
                                <SidebarContent>
                                    <SidebarGroup>
                                        <SidebarGroupLabel>
                                            {move || t!(i18n, design_gallery.sidebar_group)}
                                        </SidebarGroupLabel>
                                        <SidebarNavList>
                                            <SidebarRow
                                                href="/approvals"
                                                icon=Icon::ListChecks
                                                label=move || t_string!(i18n, admin.nav_approvals).to_owned()
                                                badge="2"
                                                current=true
                                            />
                                            <SidebarRow
                                                href="/agents"
                                                avatar="design-sidebar-assistant"
                                                label=move || t_string!(i18n, design_gallery.avatar_ada).to_owned()
                                                secondary=Signal::derive(move || t_string!(i18n, design_gallery.sidebar_row_secondary).to_owned())
                                                time=Some(sample_time)
                                            />
                                            <SidebarRow
                                                on_activate=UnsyncCallback::new(move |_| item_count.update(|count| *count += 1))
                                                icon=Icon::Settings
                                                label=move || t_string!(i18n, shell.nav_settings).to_owned()
                                                actions=move || view! {
                                                    <span class="ob-sidebar-row-marker"><IconView icon=Icon::Globe size=IconSize::Inline /></span>
                                                }
                                            />
                                        </SidebarNavList>
                                    </SidebarGroup>
                                </SidebarContent>
                                <SidebarFooter>
                                    <IconView icon=Icon::User size=IconSize::Navigation />
                                    <span class="ob-account-name">
                                        {move || t!(i18n, design_gallery.sidebar_user)}
                                    </span>
                                </SidebarFooter>
                            </Sidebar>
                            <div class="ob-design-sidebar-main">
                                <SidebarTrigger
                                    id="design-sidebar-trigger"
                                    aria_label=move || t_string!(i18n, design_gallery.sidebar_toggle).to_owned()
                                />
                                <p>{move || t!(i18n, design_gallery.sidebar_content)}</p>
                                <output id="design-sidebar-change-count" aria-live="polite">
                                    {sidebar_change_count}
                                </output>
                            </div>
                        </div>
                    </SidebarProvider>
                </section>

                <section class="ob-design-section" aria-labelledby="design-items-title">
                    <h2 id="design-items-title">{move || t!(i18n, design_gallery.items)}</h2>
                    <div class="ob-design-stack" id="design-items">
                        <Item
                            action=ItemAction::Link("/approvals".to_owned())
                            selected=true
                            preview_hover=true
                        >
                            <ItemMedia><IconView icon=Icon::ListChecks size=IconSize::Navigation /></ItemMedia>
                            <ItemTitle>{move || t!(i18n, admin.nav_approvals)}</ItemTitle>
                            <ItemDescription>{move || t!(i18n, design_gallery.item_description)}</ItemDescription>
                        </Item>
                        <Item
                            action=ItemAction::Button(UnsyncCallback::new(move |_| item_count.update(|count| *count += 1)))
                        >
                            <ItemMedia><IconView icon=Icon::Settings size=IconSize::Navigation /></ItemMedia>
                            <ItemTitle>{move || t!(i18n, shell.nav_settings)}</ItemTitle>
                            <ItemActions>
                                <IconView icon=Icon::ChevronRight size=IconSize::Inline />
                            </ItemActions>
                        </Item>
                        <Item
                            action=ItemAction::Button(UnsyncCallback::new(move |_| item_count.update(|count| *count += 1)))
                            disabled=true
                        >
                            <ItemTitle>{move || t!(i18n, common.disabled)}</ItemTitle>
                        </Item>
                        <output id="design-item-count" aria-live="polite">{item_count}</output>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-feedback-title">
                    <h2 id="design-feedback-title">{move || t!(i18n, design_gallery.feedback)}</h2>
                    <div class="ob-design-stack" id="design-feedback">
                        <Field
                            control_id="design-switch"
                            label=move || t_string!(i18n, design_gallery.switch_label).to_owned()
                        >
                            <Switch checked=enabled />
                        </Field>
                        <Switch
                            checked=disabled_checked
                            aria_label=move || t_string!(i18n, common.disabled).to_owned()
                            disabled=true
                        />
                        <Separator decorative=true />
                        <div class="ob-design-row">
                            <Skeleton shape=SkeletonShape::Circle />
                            <Skeleton shape=SkeletonShape::Line />
                        </div>
                        <Skeleton shape=SkeletonShape::Block />
                        <Separator orientation=SeparatorOrientation::Horizontal />
                        <Separator orientation=SeparatorOrientation::Vertical />
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-messages-title">
                    <h2 id="design-messages-title">{move || t!(i18n, design_gallery.messages)}</h2>
                    <div class="ob-design-stack" id="design-messages">
                        <MessageGroup>
                            <Message
                                align=MessageAlign::Start
                                aria_label=move || t_string!(i18n, design_gallery.avatar_ada).to_owned()
                            >
                                <MessageAvatar>
                                    <Avatar
                                        principal_id="principal-ada"
                                        name=move || t_string!(i18n, design_gallery.avatar_ada).to_owned()
                                        size=AvatarSize::Medium
                                    />
                                </MessageAvatar>
                                <MessageContent>
                                    <MessageHeader>{move || t!(i18n, design_gallery.avatar_ada)}</MessageHeader>
                                    <Bubble kind=BubbleKind::Assistant preview_hover=true>
                                        {move || t!(i18n, design_gallery.assistant_message)}
                                    </Bubble>
                                    <MessageFooter><Kbd key=KbdKey::Enter /></MessageFooter>
                                </MessageContent>
                            </Message>
                            <Message
                                align=MessageAlign::End
                                aria_label=move || t_string!(i18n, design_gallery.avatar_zhang).to_owned()
                            >
                                <MessageAvatar>
                                    <Avatar
                                        principal_id="principal-zhang"
                                        name=move || t_string!(i18n, design_gallery.avatar_zhang).to_owned()
                                        size=AvatarSize::Small
                                    />
                                </MessageAvatar>
                                <MessageContent>
                                    <MessageHeader>{move || t!(i18n, design_gallery.avatar_zhang)}</MessageHeader>
                                    <Bubble kind=BubbleKind::User>
                                        {move || t!(i18n, design_gallery.user_message)}
                                    </Bubble>
                                    <MessageFooter>
                                        <Kbd modifier=KbdModifier::Shift key=KbdKey::Enter />
                                    </MessageFooter>
                                </MessageContent>
                            </Message>
                        </MessageGroup>
                        <div class="ob-design-row" id="design-avatar-repeat">
                            <Avatar
                                principal_id="principal-ada"
                                name=move || t_string!(i18n, design_gallery.avatar_ada).to_owned()
                                size=AvatarSize::Large
                            />
                            <Kbd key=KbdKey::Escape />
                            <Kbd key=KbdKey::Slash />
                        </div>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-message-scroller-title">
                    <h2 id="design-message-scroller-title">
                        {move || t!(i18n, design_gallery.message_scroller)}
                    </h2>
                    <div class="ob-design-stack">
                        <div class="ob-design-message-scroller" id="design-message-scroller-example">
                            <MessageScroller
                                id="design-message-scroller"
                                aria_label=move || t_string!(i18n, design_gallery.message_scroller_label).to_owned()
                            >
                                <MessageScrollerViewport>
                                    <MessageScrollerContent>
                                        <For
                                            each=move || scroller_items.get()
                                            key=|item| item.id
                                            children=move |item| {
                                                let id = item.id;
                                                let anchor = item.anchor;
                                                view! {
                                                    <MessageScrollerItem
                                                        message_id=format!("design-scroller-message-{id}")
                                                        scroll_anchor=anchor
                                                    >
                                                        <div
                                                            class="ob-design-scroller-row"
                                                            data-anchor=if anchor { "true" } else { "false" }
                                                        >
                                                            <strong>
                                                                {move || if anchor {
                                                                    t_string!(i18n, design_gallery.scroller_user).to_owned()
                                                                } else {
                                                                    t_string!(i18n, design_gallery.scroller_reply).to_owned()
                                                                }}
                                                            </strong>
                                                            " · "
                                                            {move || format!(
                                                                "{} {id}",
                                                                t_string!(i18n, design_gallery.scroller_item),
                                                            )}
                                                            <Show when=move || scroller_expanded_id.get() == Some(id)>
                                                                <p>{move || t!(i18n, design_gallery.scroller_stream_line)}</p>
                                                                <p>{move || t!(i18n, design_gallery.scroller_stream_line)}</p>
                                                                <p>{move || t!(i18n, design_gallery.scroller_stream_line)}</p>
                                                                <p>{move || t!(i18n, design_gallery.scroller_stream_line)}</p>
                                                            </Show>
                                                        </div>
                                                    </MessageScrollerItem>
                                                }
                                            }
                                        />
                                    </MessageScrollerContent>
                                </MessageScrollerViewport>
                                <MessageScrollerButton
                                    aria_label=move || t_string!(i18n, design_gallery.scroll_to_end).to_owned()
                                />
                            </MessageScroller>
                        </div>
                        <div class="ob-design-row" id="design-message-scroller-controls">
                            <Button
                                id="design-scroller-append"
                                on_activate=move |_| {
                                    let id = scroller_next_id.get_untracked();
                                    scroller_next_id.set(id + 1);
                                    scroller_expanded_id.set(None);
                                    scroller_items.update(|items| items.push(ScrollerGalleryItem {
                                        id,
                                        anchor: false,
                                    }));
                                }
                            >
                                {move || t!(i18n, design_gallery.scroller_append)}
                            </Button>
                            <Button
                                id="design-scroller-anchor"
                                on_activate=move |_| {
                                    let id = scroller_next_id.get_untracked();
                                    scroller_next_id.set(id + 1);
                                    scroller_expanded_id.set(None);
                                    scroller_items.update(|items| items.push(ScrollerGalleryItem {
                                        id,
                                        anchor: true,
                                    }));
                                }
                            >
                                {move || t!(i18n, design_gallery.scroller_anchor)}
                            </Button>
                            <Button
                                id="design-scroller-prepend"
                                on_activate=move |_| {
                                    let id = scroller_previous_id.get_untracked();
                                    scroller_previous_id.set(id - 1);
                                    scroller_items.update(|items| items.insert(0, ScrollerGalleryItem {
                                        id,
                                        anchor: true,
                                    }));
                                }
                            >
                                {move || t!(i18n, design_gallery.scroller_prepend)}
                            </Button>
                            <Button
                                id="design-scroller-grow"
                                on_activate=move |_| {
                                    let last = scroller_items.with(|items| items.last().map(|item| item.id));
                                    scroller_expanded_id.set(
                                        if scroller_expanded_id.get_untracked() == last {
                                            None
                                        } else {
                                            last
                                        },
                                    );
                                }
                            >
                                {move || t!(i18n, design_gallery.scroller_grow)}
                            </Button>
                            <Button
                                id="design-scroller-replace"
                                on_activate=move |_| {
                                    let id = scroller_next_id.get_untracked();
                                    scroller_next_id.set(id + 1);
                                    scroller_expanded_id.set(None);
                                    scroller_items.update(|items| {
                                        if let Some(last) = items.last_mut() {
                                            *last = ScrollerGalleryItem { id, anchor: false };
                                        }
                                    });
                                }
                            >
                                {move || t!(i18n, design_gallery.scroller_replace)}
                            </Button>
                            <output id="design-scroller-count" aria-live="polite">
                                {move || scroller_items.with(Vec::len)}
                            </output>
                        </div>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-notices-title">
                    <h2 id="design-notices-title">{move || t!(i18n, design_gallery.notices)}</h2>
                    <div class="ob-design-stack" id="design-notices">
                        <Notice tone=NoticeTone::Error>
                            <span>{move || t!(i18n, design_gallery.notice_error)}</span>
                            <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| button_count.update(|count| *count += 1)>
                                {move || t!(i18n, common.retry)}
                            </Button>
                        </Notice>
                        <Notice tone=NoticeTone::Caution>{move || t!(i18n, design_gallery.notice_caution)}</Notice>
                        <Notice tone=NoticeTone::Status>{move || t!(i18n, design_gallery.notice_status)}</Notice>
                        <Notice tone=NoticeTone::Success>{move || t!(i18n, design_gallery.notice_success)}</Notice>
                        <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                            <span>{move || t!(i18n, design_gallery.notice_error)}</span>
                            <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| button_count.update(|count| *count += 1)>
                                {move || t!(i18n, common.retry)}
                            </Button>
                        </Notice>
                        <Notice tone=NoticeTone::Caution presentation=NoticePresentation::Inline>{move || t!(i18n, design_gallery.notice_caution)}</Notice>
                        <Notice tone=NoticeTone::Status presentation=NoticePresentation::Inline>{move || t!(i18n, design_gallery.notice_status)}</Notice>
                        <Separator decorative=true />
                        <Timestamp at=sample_time />
                        <TechnicalDetails copy="run_01JC0000000000000000000000\ncall_7f3a">
                            <code>"run_01JC0000000000000000000000"</code>
                            <code>"call_7f3a"</code>
                        </TechnicalDetails>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-feedback-primitives-title">
                    <h2 id="design-feedback-primitives-title">
                        {move || t!(i18n, design_gallery.feedback_primitives)}
                    </h2>
                    <div class="ob-design-stack" id="design-feedback-primitives">
                        <Toast
                            id="design-toast-preview"
                            visible=toast_preview_visible
                            message=move || t_string!(i18n, design_gallery.toast_preview).to_owned()
                            preview_state=ToastPreviewState::Open
                        />
                        <Toast
                            id="design-toast-auto"
                            visible=toast_auto_visible
                            message=move || t_string!(i18n, design_gallery.toast_auto).to_owned()
                            on_dismiss=UnsyncCallback::new(move |_| toast_dismiss_count.update(|count| *count += 1))
                        />
                        <Button
                            variant=ButtonVariant::Chip
                            on_activate=move |_| toast_auto_visible.set(true)
                        >
                            {move || t!(i18n, design_gallery.show_toast)}
                        </Button>
                        <output id="design-toast-dismiss-count" aria-live="polite">
                            {toast_dismiss_count}
                        </output>
                        <div class="ob-design-row">
                            <Tooltip
                                id="design-tooltip-preview"
                                content=move || t_string!(i18n, design_gallery.tooltip_preview).to_owned()
                                preview_open=true
                            >
                                <TooltipTrigger
                                    id="design-tooltip-preview-trigger"
                                    action=TooltipTriggerAction::Button(UnsyncCallback::new(move |_| {}))
                                >
                                    {move || t!(i18n, design_gallery.tooltip_preview)}
                                </TooltipTrigger>
                            </Tooltip>
                            <Tooltip
                                id="design-tooltip-live"
                                content=move || t_string!(i18n, design_gallery.tooltip_content).to_owned()
                            >
                                <TooltipTrigger
                                    id="design-tooltip-live-trigger"
                                    action=TooltipTriggerAction::Button(UnsyncCallback::new(move |_| tooltip_activation_count.update(|count| *count += 1)))
                                >
                                    {move || t!(i18n, design_gallery.tooltip_trigger)}
                                </TooltipTrigger>
                            </Tooltip>
                        </div>
                        <output id="design-tooltip-count" aria-live="polite">
                            {tooltip_activation_count}
                        </output>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-modals-title">
                    <h2 id="design-modals-title">{move || t!(i18n, design_gallery.modals)}</h2>
                    <div class="ob-design-row" id="design-modals">
                        <Dialog
                            id="design-dialog"
                            open=dialog_open
                            on_close=UnsyncCallback::new(move |_| dialog_close_count.update(|count| *count += 1))
                        >
                            <DialogTrigger id="design-dialog-trigger">
                                {move || t!(i18n, design_gallery.dialog_trigger)}
                            </DialogTrigger>
                            <DialogContent
                                title=move || t_string!(i18n, design_gallery.dialog_title).to_owned()
                                description=move || t_string!(i18n, design_gallery.dialog_description).to_owned()
                            >
                                <DialogBody>
                                    <p>{move || t!(i18n, design_gallery.dialog_body)}</p>
                                </DialogBody>
                                <DialogFooter>
                                    <DialogClose id="design-dialog-cancel">
                                        {move || t!(i18n, common.cancel)}
                                    </DialogClose>
                                    <DialogClose id="design-dialog-save">
                                        {move || t!(i18n, common.save)}
                                    </DialogClose>
                                </DialogFooter>
                            </DialogContent>
                        </Dialog>
                        <output id="design-dialog-close-count" aria-live="polite">
                            {dialog_close_count}
                        </output>

                        <Sheet
                            id="design-sheet"
                            open=sheet_open
                            side=SheetSide::Right
                            on_close=UnsyncCallback::new(move |_| sheet_close_count.update(|count| *count += 1))
                        >
                            <DialogTrigger id="design-sheet-trigger">
                                {move || t!(i18n, design_gallery.sheet_trigger)}
                            </DialogTrigger>
                            <DialogContent
                                title=move || t_string!(i18n, design_gallery.sheet_title).to_owned()
                                description=move || t_string!(i18n, design_gallery.sheet_description).to_owned()
                            >
                                <DialogBody>
                                    <p>{move || t!(i18n, design_gallery.dialog_body)}</p>
                                </DialogBody>
                                <DialogFooter>
                                    <DialogClose id="design-sheet-done">
                                        {move || t!(i18n, design_gallery.done)}
                                    </DialogClose>
                                </DialogFooter>
                            </DialogContent>
                        </Sheet>
                        <output id="design-sheet-close-count" aria-live="polite">
                            {sheet_close_count}
                        </output>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-menu-title">
                    <h2 id="design-menu-title">{move || t!(i18n, design_gallery.menu)}</h2>
                    <div class="ob-design-row" id="design-menu-example">
                        <Menu
                            id="design-menu"
                            open=menu_open
                            on_close=UnsyncCallback::new(move |_| menu_close_count.update(|count| *count += 1))
                        >
                            <MenuTrigger>{move || t!(i18n, design_gallery.menu_trigger)}</MenuTrigger>
                            <MenuContent>
                                <MenuItem
                                    id="design-menu-new"
                                    on_select=move |_| menu_select_count.update(|count| *count += 1)
                                >
                                    {move || t!(i18n, design_gallery.menu_new)}
                                </MenuItem>
                                <MenuItem
                                    id="design-menu-disabled"
                                    disabled=true
                                    on_select=move |_| menu_select_count.update(|count| *count += 100)
                                >
                                    {move || t!(i18n, design_gallery.menu_disabled)}
                                </MenuItem>
                                <MenuSeparator />
                                <MenuSub id="design-menu-more">
                                    <MenuSubTrigger>
                                        {move || t!(i18n, design_gallery.menu_more)}
                                    </MenuSubTrigger>
                                    <MenuContent>
                                        <MenuItem
                                            id="design-menu-copy"
                                            on_select=move |_| menu_select_count.update(|count| *count += 1)
                                        >
                                            {move || t!(i18n, design_gallery.menu_copy)}
                                        </MenuItem>
                                        <MenuItem
                                            id="design-menu-delete"
                                            on_select=move |_| menu_select_count.update(|count| *count += 1)
                                        >
                                            {move || t!(i18n, design_gallery.menu_delete)}
                                        </MenuItem>
                                    </MenuContent>
                                </MenuSub>
                                <MenuItem
                                    id="design-menu-settings"
                                    on_select=move |_| menu_select_count.update(|count| *count += 1)
                                >
                                    {move || t!(i18n, design_gallery.menu_settings)}
                                </MenuItem>
                            </MenuContent>
                        </Menu>
                        <button id="design-menu-after" type="button" class="ob-button" data-variant="chip" data-size="md">
                            {move || t!(i18n, design_gallery.menu_after)}
                        </button>
                        <output id="design-menu-select-count" aria-live="polite">{menu_select_count}</output>
                        <output id="design-menu-close-count" aria-live="polite">{menu_close_count}</output>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-layout-title">
                    <h2 id="design-layout-title">{move || t!(i18n, design_gallery.layout)}</h2>
                    <div class="ob-design-layout-preview" id="design-layout-example">
                        <DetailPanelLayout open=detail_open>
                            <DetailPanelMain>
                                <SectionTabs label=move || t_string!(i18n, design_gallery.section_tabs).to_owned()>
                                    <SectionTab href="/_design" icon=Icon::LayoutGrid
                                        label=move || t_string!(i18n, design_gallery.title).to_owned() />
                                    <SectionTab href="/settings" icon=Icon::Settings nested=true
                                        label=move || t_string!(i18n, shell.nav_settings).to_owned() />
                                </SectionTabs>
                                <PageShell width=PageWidth::Content>
                                    <PageActions>
                                        <span>{move || t!(i18n, design_gallery.layout_topbar)}</span>
                                        <div class="ob-design-row">
                                            <Button
                                                id="design-detail-open"
                                                open=detail_open
                                                on_activate=move |_| detail_open.set(true)
                                            >
                                                {move || t!(i18n, design_gallery.layout_open_detail)}
                                            </Button>
                                            <output id="design-detail-close-count" aria-live="polite">
                                                {detail_close_count}
                                            </output>
                                        </div>
                                    </PageActions>
                                    <PageSection
                                        heading_id="design-layout-section"
                                        title=move || t_string!(i18n, design_gallery.layout_section).to_owned()
                                        description=move || t_string!(i18n, design_gallery.layout_section_description).to_owned()
                                    >
                                        <PageRows>
                                            <StaggerItem index=0>
                                                <Item action=ItemAction::Link("/settings".to_owned())>
                                                    <ItemMedia>
                                                        <RowMark>
                                                            <IconView icon=Icon::Plug size=IconSize::Navigation />
                                                        </RowMark>
                                                    </ItemMedia>
                                                    <ItemTitle>
                                                        {move || t!(i18n, design_gallery.layout_row)}
                                                    </ItemTitle>
                                                    <ItemDescription>
                                                        {move || t!(i18n, design_gallery.layout_row_description)}
                                                    </ItemDescription>
                                                </Item>
                                            </StaggerItem>
                                        </PageRows>
                                        <PageEmpty>
                                            {move || t!(i18n, design_gallery.layout_empty)}
                                        </PageEmpty>
                                    </PageSection>
                                </PageShell>
                            </DetailPanelMain>
                            <DetailPanel
                                id="design-detail-panel"
                                title=move || t_string!(i18n, design_gallery.layout_detail).to_owned()
                                open=detail_open
                                return_focus_id="design-detail-open"
                                on_close=move |_| {
                                    detail_open.set(false);
                                    detail_close_count.update(|count| *count += 1);
                                }
                            >
                                <p>{move || t!(i18n, design_gallery.layout_detail_body)}</p>
                            </DetailPanel>
                        </DetailPanelLayout>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-agent-presence-title">
                    <h2 id="design-agent-presence-title">
                        {move || t!(i18n, design_gallery.agent_presence)}
                    </h2>
                    <div class="ob-design-row" id="design-agent-presence">
                        <div class="ob-design-presence-state">
                            <AgentPresence state=AgentPresenceState::Idle />
                            <span>{move || t!(i18n, agents.presence_idle)}</span>
                        </div>
                        <div class="ob-design-presence-state">
                            <AgentPresence state=AgentPresenceState::Thinking />
                            <span>{move || t!(i18n, agents.presence_thinking)}</span>
                        </div>
                        <div class="ob-design-presence-state">
                            <AgentPresence state=AgentPresenceState::Speaking />
                            <span>{move || t!(i18n, agents.presence_speaking)}</span>
                        </div>
                        <div class="ob-design-presence-state">
                            <AgentPresence state=AgentPresenceState::Error />
                            <span>{move || t!(i18n, agents.presence_error)}</span>
                        </div>
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-computer-art-title">
                    <h2 id="design-computer-art-title">
                        {move || t!(i18n, design_gallery.computer_placeholder_art)}
                    </h2>
                    <div class="ob-design-computer-examples" id="design-computer-art">
                        <div class="ob-design-computer-art">
                            <ComputerPlaceholderArt />
                        </div>
                        <ComputerPlaceholder />
                    </div>
                </section>

                <section class="ob-design-section" aria-labelledby="design-compiled-gallery-title">
                    <h2 id="design-compiled-gallery-title">
                        {move || t!(i18n, gallery.frame)}
                    </h2>
                    <div class="ob-design-stack" id="design-compiled-gallery">
                        <GalleryFrame
                            title=move || t_string!(i18n, gallery.cards).to_owned()
                            caption=move || t_string!(i18n, gallery.preview).to_owned()
                            action=view! {
                                <GalleryBadge tone=GalleryTone::Positive>
                                    {move || t!(i18n, common.enabled)}
                                </GalleryBadge>
                            }.into_any()
                        >
                            <div class="ob-design-row">
                                <GalleryBadge tone=GalleryTone::Neutral>"Neutral"</GalleryBadge>
                                <GalleryBadge tone=GalleryTone::Caution>"Caution"</GalleryBadge>
                                <GalleryBadge tone=GalleryTone::Negative>"Negative"</GalleryBadge>
                            </div>
                        </GalleryFrame>
                        <QuoteCard
                            quote="The exact words remain attached to their source.".to_owned()
                            attribution="the fixture".to_owned()
                            context="Compiled Rust renderer".to_owned()
                        />
                        <RefusedCard
                            title="Quotation".to_owned()
                            reason="This component is not available to this coworker.".to_owned()
                        />
                    </div>
                </section>
            </div>
        </section>
    }
}
