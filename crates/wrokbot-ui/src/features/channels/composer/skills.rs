//! Explicit skill selection. Grants are current facts; selected slugs are frozen with each send.
use super::draft::ComposerDraft;
use crate::api::skills::SkillChoice;
use crate::features::admin::plugins::PluginActions;
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Notice, NoticePresentation, NoticeTone,
};
use leptos::{ev::KeyboardEvent, prelude::*};
use openbot_contracts::command::{MAX_SELECTED_SKILLS, valid_selected_skill_slugs};
use openbot_contracts::ids::BotId;

/// A trailing slash token must start at a word boundary; URLs and paths remain ordinary text.
fn slash_query(text: &str) -> Option<(usize, &str)> {
    let start = text
        .rfind(char::is_whitespace)
        .map_or(0, |i| i + text[i..].chars().next().unwrap().len_utf8());
    let query = text[start..].strip_prefix('/')?;
    (query.len() <= 40
        && query
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    .then_some((start, query))
}

pub(crate) fn selected_draft(text: String, slugs: Vec<String>) -> ComposerDraft {
    let is_empty = openbot_contracts::text::trim_ecmascript(&text).is_empty() && slugs.is_empty();
    ComposerDraft {
        text,
        agent_id: None,
        command_ids: slugs,
        is_empty,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SkillComposer {
    pub selected: RwSignal<Vec<String>>,
    choices: RwSignal<Vec<SkillChoice>>,
    pub loading: RwSignal<bool>,
    error: RwSignal<bool>,
    manual_open: RwSignal<bool>,
    dismissed: RwSignal<Option<String>>,
    active: RwSignal<usize>,
    pub open: Signal<bool>,
    pub matches: Signal<Vec<SkillChoice>>,
    pub invalid: Signal<bool>,
    pub active_descendant: Signal<Option<String>>,
    draft: RwSignal<String>,
    agent: Signal<Option<BotId>>,
    serial: RwSignal<u64>,
    editor_id: &'static str,
}
impl SkillComposer {
    pub fn new(
        draft: RwSignal<String>,
        agent: Signal<Option<BotId>>,
        editor_id: &'static str,
    ) -> Self {
        let selected = RwSignal::new(Vec::<String>::new());
        let choices = RwSignal::new(Vec::<SkillChoice>::new());
        let loading = RwSignal::new(false);
        let error = RwSignal::new(false);
        let manual_open = RwSignal::new(false);
        let dismissed = RwSignal::new(None::<String>);
        let active = RwSignal::new(0_usize);
        let open = Signal::derive(move || {
            manual_open.get()
                || (slash_query(&draft.get()).is_some()
                    && dismissed.get().as_ref() != Some(&draft.get()))
        });
        let matches = Signal::derive(move || {
            let text = draft.get();
            let query = slash_query(&text).map_or("", |(_, q)| q);
            choices
                .get()
                .into_iter()
                .filter(|s| {
                    !selected.get().contains(&s.slug)
                        && (s.slug.contains(query) || s.title.to_lowercase().contains(query))
                })
                .take(32)
                .collect::<Vec<_>>()
        });
        let invalid = Signal::derive(move || {
            let chosen = selected.get();
            !valid_selected_skill_slugs(&chosen)
                || (!chosen.is_empty()
                    && (loading.get()
                        || error.get()
                        || chosen
                            .iter()
                            .any(|s| !choices.get().iter().any(|c| c.slug == *s))))
        });
        let active_descendant = Signal::derive(move || {
            (open.get() && !matches.get().is_empty()).then(|| {
                format!(
                    "skill-choice-{}",
                    active.get().min(matches.get().len().saturating_sub(1))
                )
            })
        });
        let state = Self {
            selected,
            choices,
            loading,
            error,
            manual_open,
            dismissed,
            active,
            open,
            matches,
            invalid,
            active_descendant,
            draft,
            agent,
            serial: RwSignal::new(0),
            editor_id,
        };
        let actions = expect_context::<PluginActions>();
        Effect::new(move |_| {
            actions.revision.track();
            agent.track();
            state.reload();
        });
        state
    }
    pub fn reload(self) {
        let serial = self.serial.get_untracked().saturating_add(1);
        self.serial.set(serial);
        self.error.set(false);
        self.choices.set(Vec::new());
        let Some(agent) = self.agent.get_untracked() else {
            self.loading.set(false);
            return;
        };
        self.loading.set(true);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = crate::api::skills::granted_choices(agent.as_str()).await;
            if self.serial.try_get_untracked() != Some(serial) {
                return;
            }
            match result {
                Ok(choices) => self.choices.set(choices),
                Err(_) => self.error.set(true),
            }
            self.loading.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = agent;
            self.loading.set(false);
            self.error.set(true);
        }
    }
    pub fn compose(self) -> ComposerDraft {
        selected_draft(self.draft.get_untracked(), self.selected.get_untracked())
    }
    pub fn clear(self) {
        self.draft.set(String::new());
        self.selected.set(Vec::new());
        self.close();
    }
    pub fn close(self) {
        self.manual_open.set(false);
        self.dismissed.set(Some(self.draft.get_untracked()));
    }
    pub fn choose(self, slug: String) {
        if self.loading.get_untracked()
            || self.selected.get_untracked().len() >= MAX_SELECTED_SKILLS
            || !self.choices.get_untracked().iter().any(|s| s.slug == slug)
        {
            return;
        }
        self.selected.update(|chosen| {
            if !chosen.contains(&slug) {
                chosen.push(slug);
            }
        });
        self.draft.update(|text| {
            if let Some((start, _)) = slash_query(text) {
                text.truncate(start);
            }
        });
        self.close();
        self.active.set(0);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            use wasm_bindgen::JsCast as _;
            leptos::task::tick().await;
            if let Some(element) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.get_element_by_id(self.editor_id))
                .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
            {
                _ = element.focus();
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        let _ = self.editor_id;
    }
    pub fn keyboard(self, event: KeyboardEvent) {
        if !self.open.get_untracked()
            || event.shift_key()
            || event.ctrl_key()
            || event.meta_key()
            || event.alt_key()
        {
            return;
        }
        let choices = self.matches.get_untracked();
        let index = self
            .active
            .get_untracked()
            .min(choices.len().saturating_sub(1));
        match event.key().as_str() {
            "Escape" => {
                event.prevent_default();
                self.close();
            }
            "ArrowDown" if !choices.is_empty() => {
                event.prevent_default();
                self.active.set((index + 1) % choices.len());
            }
            "ArrowUp" if !choices.is_empty() => {
                event.prevent_default();
                self.active.set((index + choices.len() - 1) % choices.len());
            }
            "Enter" if !choices.is_empty() => {
                event.prevent_default();
                self.choose(choices[index].slug.clone());
            }
            _ => {}
        }
    }
}

#[component]
pub(crate) fn SkillPicker(state: SkillComposer, disabled: Signal<bool>) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <div class="ob-skill-picker">
            <div class="ob-skill-chips">
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small disabled=disabled
                    on_activate=move |_| { if state.open.get_untracked() { state.close(); } else { state.manual_open.set(true); state.active.set(0); state.reload(); } }>
                    {move || t!(i18n, skills.choose)}
                </Button>
                <For each=move || state.selected.get() key=Clone::clone children=move |slug| {
                    let remove = slug.clone();
                    let label = slug.clone();
                    view! { <Button variant=ButtonVariant::Chip size=ButtonSize::Small disabled=disabled
                        aria_label=move || format!("{} /{}", t_string!(i18n, skills.remove_selection), label)
                        on_activate=move |_| state.selected.update(|chosen| chosen.retain(|s| s != &remove))>
                        {format!("/{slug} ×")}
                    </Button> }
                }/>
            </div>
            <Show when=move || state.open.get() && !disabled.get()>
                <div class="ob-home-mention-results" id="channel-skill-results" role="listbox" aria-label=move || t_string!(i18n, skills.choose).to_owned()>
                    <For each=move || { state.matches.get().into_iter().enumerate().collect::<Vec<_>>() } key=|(index, s)| (*index, s.slug.clone(), s.title.clone()) children=move |(index, skill)| {
                        let slug = skill.slug.clone();
                        view! { <button type="button" role="option" id=format!("skill-choice-{index}")
                            aria-selected=move || state.active.get().min(state.matches.get().len().saturating_sub(1)) == index
                            disabled=move || { state.loading.get() || state.selected.get().len() >= MAX_SELECTED_SKILLS }
                            on:click=move |_| state.choose(slug.clone())>
                            <span>{format!("/{}", skill.slug)}</span><span><strong>{skill.title}</strong><small>{skill.summary}</small></span>
                        </button> }
                    }/>
                </div>
                <Show when=move || state.loading.get()><p class="ob-page-empty" role="status">{move || t!(i18n, common.loading)}</p></Show>
                <Show when=move || state.error.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, skills.choices_error)}</Notice></Show>
                <Show when=move || state.agent.get().is_some() && !state.loading.get() && !state.error.get() && state.matches.get().is_empty()><p class="ob-page-empty">{move || t!(i18n, skills.choices_empty)}</p></Show>
                <Show when=move || state.agent.get().is_none()><p class="ob-page-empty">{move || t!(i18n, skills.choose_agent_first)}</p></Show>
                <a class="ob-plugin-link" href="/skills">{move || t!(i18n, skills.manage)}</a>
            </Show>
            <Show when=move || state.invalid.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, skills.selection_invalid)}</Notice></Show>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slash_picker_never_interprets_urls_paths_or_embedded_slashes() {
        for text in [
            "https://example.test/a",
            "path/to/file",
            "ask/foo",
            "/foo bar",
            "/大纲",
        ] {
            assert!(slash_query(text).is_none(), "{text}");
        }
        assert_eq!(slash_query("问题　/review"), Some((9, "review")));
        assert_eq!(slash_query("/"), Some((0, "")));
    }
    #[test]
    fn skill_selection_never_expands_into_user_text_and_keeps_order() {
        let draft = selected_draft(
            "  保留我的原话\n".into(),
            vec!["review".into(), "check".into()],
        );
        assert_eq!(draft.text, "  保留我的原话\n");
        assert_eq!(draft.command_ids, ["review", "check"]);
        assert!(!draft.is_empty);
        assert!(!selected_draft(String::new(), vec!["review".into()]).is_empty);
    }
}
