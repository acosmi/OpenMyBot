//! The one notice above a composer: of all conditions that are true, only the most important one
//! is shown (UI spec v5.2 §7.1, §7.4, §13.4). Each caller keeps its own conditions and wording.

use leptos::prelude::*;

use crate::primitives::{Button, ButtonSize, ButtonVariant, Notice, NoticeTone};

/// An optional action shown after the notice text.
#[derive(Clone)]
pub(crate) enum SlotAction {
    /// Navigate to a page.
    Link { href: String, label: String },
    /// Run a local action such as a retry.
    Button {
        label: String,
        run: UnsyncCallback<()>,
    },
}

impl PartialEq for SlotAction {
    // A callback has no identity worth comparing; the slot only re-renders when what the user
    // sees changes.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Link { href, label },
                Self::Link {
                    href: other_href,
                    label: other_label,
                },
            ) => href == other_href && label == other_label,
            (Self::Button { label, .. }, Self::Button { label: other, .. }) => label == other,
            _ => false,
        }
    }
}

/// One true condition the slot may show.
#[derive(Clone, PartialEq)]
pub(crate) struct SlotNotice {
    tone: NoticeTone,
    blocks_send: bool,
    text: String,
    /// The whole text is a link to this page.
    href: Option<String>,
    action: Option<SlotAction>,
}

impl SlotNotice {
    pub(crate) fn new(tone: NoticeTone, text: impl Into<String>) -> Self {
        Self {
            tone,
            blocks_send: false,
            text: text.into(),
            href: None,
            action: None,
        }
    }

    /// A caution that keeps the composer from sending ranks above other cautions.
    pub(crate) fn blocking(mut self) -> Self {
        self.blocks_send = true;
        self
    }

    /// Make the whole text a link.
    pub(crate) fn linked(mut self, href: String) -> Self {
        self.href = Some(href);
        self
    }

    pub(crate) fn with_link(mut self, href: impl Into<String>, label: impl Into<String>) -> Self {
        self.action = Some(SlotAction::Link {
            href: href.into(),
            label: label.into(),
        });
        self
    }

    pub(crate) fn with_button(mut self, label: impl Into<String>, run: UnsyncCallback<()>) -> Self {
        self.action = Some(SlotAction::Button {
            label: label.into(),
            run,
        });
        self
    }

    /// Error > caution that blocks sending > caution > status > success.
    const fn rank(&self) -> u8 {
        match (self.tone, self.blocks_send) {
            (NoticeTone::Error, _) => 4,
            (NoticeTone::Caution, true) => 3,
            (NoticeTone::Caution, false) => 2,
            (NoticeTone::Status, _) => 1,
            (NoticeTone::Success, _) => 0,
        }
    }
}

/// The highest-ranked notice; among equals, the one listed first.
fn pick(candidates: Vec<SlotNotice>) -> Option<SlotNotice> {
    candidates
        .into_iter()
        .fold(None, |best: Option<SlotNotice>, next| match best {
            Some(best) if best.rank() >= next.rank() => Some(best),
            _ => Some(next),
        })
}

/// Render the most important of the caller's currently true notices, or nothing.
#[component]
pub(crate) fn StatusSlot(
    /// Every condition that is true right now, in the caller's order.
    notices: Signal<Vec<SlotNotice>>,
) -> impl IntoView {
    // Only a change of the shown notice re-renders it, so a live region is not re-announced on
    // every unrelated update of the page state.
    let shown = Memo::new(move |_| pick(notices.get()));
    move || {
        shown.get().map(|notice| {
            let text = match notice.href {
                Some(href) => view! { <a href=href>{notice.text}</a> }.into_any(),
                None => view! { <span>{notice.text}</span> }.into_any(),
            };
            let action = notice.action.map(|action| match action {
                SlotAction::Link { href, label } => view! { <a href=href>{label}</a> }.into_any(),
                SlotAction::Button { label, run } => view! {
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=run>{label}</Button>
                }
                .into_any(),
            });
            view! { <Notice tone=notice.tone>{text}{action}</Notice> }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(candidates: &[(NoticeTone, bool, &str)]) -> Option<String> {
        pick(
            candidates
                .iter()
                .map(|&(tone, blocks, text)| {
                    let notice = SlotNotice::new(tone, text);
                    if blocks { notice.blocking() } else { notice }
                })
                .collect(),
        )
        .map(|notice| notice.text)
    }

    #[test]
    fn the_slot_shows_only_the_most_important_true_condition() {
        use NoticeTone::{Caution, Error, Status, Success};
        assert_eq!(shown(&[]), None);
        assert_eq!(
            shown(&[(Success, false, "saved")]).as_deref(),
            Some("saved")
        );
        assert_eq!(
            shown(&[(Success, false, "saved"), (Status, false, "status")]).as_deref(),
            Some("status")
        );
        assert_eq!(
            shown(&[(Status, false, "status"), (Caution, false, "caution")]).as_deref(),
            Some("caution")
        );
        assert_eq!(
            shown(&[
                (Caution, false, "caution"),
                (Caution, true, "blocking"),
                (Status, false, "status"),
            ])
            .as_deref(),
            Some("blocking")
        );
        // Among equals the first listed wins, so a later error never hides an earlier one.
        assert_eq!(
            shown(&[
                (Caution, true, "blocking"),
                (Success, false, "saved"),
                (Error, false, "error"),
                (Error, false, "later error"),
            ])
            .as_deref(),
            Some("error")
        );
        // A one-time receipt listed before an equal-rank caution, such as the stop receipt
        // before the hold notice, stays visible.
        assert_eq!(
            shown(&[(Caution, false, "stop receipt"), (Caution, false, "hold")]).as_deref(),
            Some("stop receipt")
        );
        // The blocking flag only orders cautions; it never lifts a status above a caution.
        assert_eq!(
            shown(&[(Status, true, "status"), (Caution, false, "caution")]).as_deref(),
            Some("caution")
        );
    }
}
