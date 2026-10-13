//! Startup-only locale fallback. Explicit authenticated preferences remain authoritative.

use crate::i18n::Locale;
use leptos::prelude::*;
use openbot_contracts::ui::UiLocale;

/// One host/system fallback captured for this application mount; never a preference write.
#[derive(Clone, Copy)]
pub(crate) struct SystemLocale(pub UiLocale);

/// Freeze the initial locale so browser language-list changes cannot undo a manual choice.
pub(crate) fn provide_startup_locale() {
    let (initial, fallback) = host_locales();
    provide_context(SystemLocale(fallback));
    let initial = contract_locale(initial);
    let i18n = leptos_i18n::context::init_i18n_subcontext(Some(Signal::derive(move || initial)));
    provide_context(i18n);
}

/// An unedited read may apply the explicit value or fallback; a local draft is never replaced.
pub(crate) const fn locale_after_read(
    stored: Option<UiLocale>,
    fallback: UiLocale,
    locale_unedited: bool,
) -> Option<UiLocale> {
    if !locale_unedited {
        return None;
    }
    Some(match stored {
        Some(locale) => locale,
        None => fallback,
    })
}

/// The primary system language alone selects the fallback, rather than a secondary match.
#[cfg(any(test, target_arch = "wasm32"))]
fn locale_from_system_tag(tag: &str) -> UiLocale {
    let primary = tag.trim().split(['-', '_']).next().unwrap_or_default();
    if primary.eq_ignore_ascii_case("zh") {
        UiLocale::ZhCn
    } else {
        UiLocale::En
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn projected_locale(tag: Option<&str>) -> Option<UiLocale> {
    match tag {
        Some("en") => Some(UiLocale::En),
        Some("zh-CN") => Some(UiLocale::ZhCn),
        _ => None,
    }
}

const fn contract_locale(locale: UiLocale) -> Locale {
    match locale {
        UiLocale::En => Locale::en,
        UiLocale::ZhCn => Locale::zh_CN,
    }
}

#[cfg(target_arch = "wasm32")]
fn host_locales() -> (UiLocale, UiLocale) {
    let Some(window) = web_sys::window() else {
        return (UiLocale::En, UiLocale::En);
    };
    let tag = window
        .document()
        .and_then(|document| document.document_element())
        .and_then(|root| root.get_attribute("lang"));
    let projected = projected_locale(tag.as_deref());
    let fallback = if crate::api::desktop_transport::is_tauri_host() {
        // Desktop already projects its OS locale or explicit first-frame preference. No IPC.
        projected.unwrap_or(UiLocale::En)
    } else {
        window
            .navigator()
            .language()
            .as_deref()
            .map_or(UiLocale::En, locale_from_system_tag)
    };
    // Preserve the existing host-authored first frame until the authenticated row is read.
    (projected.unwrap_or(fallback), fallback)
}

#[cfg(not(target_arch = "wasm32"))]
fn host_locales() -> (UiLocale, UiLocale) {
    (UiLocale::En, UiLocale::En)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_chinese_variants_use_simplified_chinese() {
        for tag in ["zh", "zh-CN", "zh-TW", "zh-Hant-HK", "ZH-cn", "zh_CN.UTF-8"] {
            assert_eq!(locale_from_system_tag(tag), UiLocale::ZhCn, "{tag}");
        }
    }

    #[test]
    fn other_primary_languages_do_not_negotiate_a_secondary_chinese_match() {
        for tag in [
            "en",
            "en-US",
            "fr-FR",
            "ja-JP",
            "de-DE",
            "",
            "*",
            "zho",
            "fr-FR,zh-CN",
        ] {
            assert_eq!(locale_from_system_tag(tag), UiLocale::En, "{tag}");
        }
    }

    #[test]
    fn explicit_preference_wins_over_a_different_system_default() {
        assert_eq!(
            locale_after_read(Some(UiLocale::En), UiLocale::ZhCn, true),
            Some(UiLocale::En)
        );
        assert_eq!(
            locale_after_read(Some(UiLocale::ZhCn), UiLocale::En, true),
            Some(UiLocale::ZhCn)
        );
        assert_eq!(
            locale_after_read(None, UiLocale::ZhCn, true),
            Some(UiLocale::ZhCn)
        );
        assert_eq!(
            locale_after_read(None, UiLocale::En, true),
            Some(UiLocale::En)
        );
    }

    #[test]
    fn late_read_cannot_replace_an_inflight_manual_locale_draft() {
        for stored in [None, Some(UiLocale::En), Some(UiLocale::ZhCn)] {
            for fallback in [UiLocale::En, UiLocale::ZhCn] {
                assert_eq!(locale_after_read(stored, fallback, false), None);
            }
        }
    }

    #[test]
    fn first_frame_projection_accepts_only_existing_closed_wire_values() {
        assert_eq!(projected_locale(Some("en")), Some(UiLocale::En));
        assert_eq!(projected_locale(Some("zh-CN")), Some(UiLocale::ZhCn));
        for tag in [None, Some("zh"), Some("fr-FR"), Some("zh-CN, en"), Some("")] {
            assert_eq!(projected_locale(tag), None);
        }
    }
}
