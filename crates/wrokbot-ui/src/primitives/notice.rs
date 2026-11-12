//! Notice primitive: the one way a page, pane, row or form tells the user about an error,
//! a condition that needs care, or a neutral status change.

use leptos::prelude::*;

use super::{IconSize, IconView};
use crate::icons::Icon;

/// What the notice reports. The tone decides the live-region role, the icon and the color;
/// the text always carries the meaning on its own (UI spec v5.2 §13.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeTone {
    /// Something failed; announced assertively.
    Error,
    /// Not failed, but the user should look before going on.
    Caution,
    /// Neutral progress or outcome.
    Status,
}

/// Where the notice sits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NoticePresentation {
    /// Framed block at page or pane level.
    #[default]
    Banner,
    /// Unframed line inside a row, the sidebar, a dialog or a form.
    Inline,
}

impl NoticeTone {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Caution => "caution",
            Self::Status => "status",
        }
    }

    const fn role(self) -> &'static str {
        match self {
            Self::Error => "alert",
            Self::Caution | Self::Status => "status",
        }
    }

    const fn icon(self) -> Icon {
        match self {
            Self::Error => Icon::CircleAlert,
            Self::Caution => Icon::TriangleAlert,
            Self::Status => Icon::Info,
        }
    }
}

impl NoticePresentation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Banner => "banner",
            Self::Inline => "inline",
        }
    }
}

/// Render one notice. Children are the message, optionally followed by one action
/// (a retry or dismiss button, or a link); the action wraps below the message when narrow.
#[component]
pub fn Notice(
    /// Semantic tone.
    tone: NoticeTone,
    /// Banner or inline placement.
    #[prop(optional)]
    presentation: NoticePresentation,
    /// Message and optional action.
    children: Children,
) -> impl IntoView {
    view! {
        <div
            class="ob-notice"
            data-tone=tone.as_str()
            data-presentation=presentation.as_str()
            role=tone.role()
        >
            <IconView icon=tone.icon() size=IconSize::Inline />
            <div class="ob-notice-body">{children()}</div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::{NoticePresentation, NoticeTone};

    #[test]
    fn only_errors_interrupt_and_every_tone_has_a_closed_css_value() {
        assert_eq!(
            [
                NoticeTone::Error.role(),
                NoticeTone::Caution.role(),
                NoticeTone::Status.role(),
            ],
            ["alert", "status", "status"]
        );
        assert_eq!(
            [
                NoticeTone::Error.as_str(),
                NoticeTone::Caution.as_str(),
                NoticeTone::Status.as_str(),
                NoticePresentation::Banner.as_str(),
                NoticePresentation::Inline.as_str(),
            ],
            ["error", "caution", "status", "banner", "inline"]
        );
    }
}
