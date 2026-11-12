//! Timestamp primitive: user-facing times follow the interface language (UI spec v5.2 §13.4)
//! while the machine value stays in `<time datetime>`.

use leptos::prelude::*;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::i18n::{Locale, t_string, use_i18n};

/// Render a short relative time with the full localized date and time as its title.
#[component]
pub fn Timestamp(
    /// The instant to show.
    at: OffsetDateTime,
) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <time
            class="ob-timestamp"
            datetime=at.format(&Rfc3339).ok()
            title=move || localized_date_time(at, i18n.get_locale())
        >
            {move || localized_relative_time(i18n, current_time(), at)}
        </time>
    }
}

/// Full date and time in the interface language, including the time zone.
pub(crate) fn localized_date_time(at: OffsetDateTime, locale: Locale) -> String {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsValue;
        // OffsetDateTime's year range lies well inside JS Date's, so the value is always finite.
        let date = js_sys::Date::new(&JsValue::from_f64(
            (at.unix_timestamp_nanos() / 1_000_000) as f64,
        ));
        let options = js_sys::Object::new();
        for (key, value) in [
            ("year", "numeric"),
            ("month", "2-digit"),
            ("day", "2-digit"),
            ("hour", "2-digit"),
            ("minute", "2-digit"),
            ("second", "2-digit"),
            ("timeZoneName", "short"),
        ] {
            _ = js_sys::Reflect::set(&options, &JsValue::from_str(key), &JsValue::from_str(value));
        }
        let locale = match locale {
            Locale::en => "en",
            Locale::zh_CN => "zh-CN",
        };
        date.to_locale_string(locale, options.as_ref()).into()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let at = at.to_offset(time::UtcOffset::UTC);
        let (year, month, day) = (at.year(), u8::from(at.month()), at.day());
        let (hour, minute, second) = (at.hour(), at.minute(), at.second());
        match locale {
            Locale::en => {
                format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
            }
            Locale::zh_CN => {
                format!("{year:04}年{month:02}月{day:02}日 {hour:02}:{minute:02}:{second:02} UTC")
            }
        }
    }
}

fn current_time() -> OffsetDateTime {
    #[cfg(target_arch = "wasm32")]
    {
        let nanos = (js_sys::Date::now() * 1_000_000.0) as i128;
        OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        OffsetDateTime::now_utc()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelativeAge {
    JustNow,
    Minutes(i64),
    Hours(i64),
    Days(i64),
    Weeks(i64),
}

fn relative_age(now: OffsetDateTime, at: OffsetDateTime) -> RelativeAge {
    let elapsed = (now - at).whole_seconds().max(0);
    match elapsed {
        0..=59 => RelativeAge::JustNow,
        60..=3_599 => RelativeAge::Minutes((elapsed + 30) / 60),
        3_600..=86_399 => RelativeAge::Hours((elapsed + 1_800) / 3_600),
        86_400..=604_799 => RelativeAge::Days((elapsed + 43_200) / 86_400),
        _ => RelativeAge::Weeks((elapsed + 302_400) / 604_800),
    }
}

fn localized_relative_time(
    i18n: leptos_i18n::I18nContext<Locale>,
    now: OffsetDateTime,
    at: OffsetDateTime,
) -> String {
    match relative_age(now, at) {
        RelativeAge::JustNow => t_string!(i18n, common.just_now).to_owned(),
        RelativeAge::Minutes(count) => {
            t_string!(i18n, common.time_minutes_ago, count = count).to_owned()
        }
        RelativeAge::Hours(count) => {
            t_string!(i18n, common.time_hours_ago, count = count).to_owned()
        }
        RelativeAge::Days(count) => t_string!(i18n, common.time_days_ago, count = count).to_owned(),
        RelativeAge::Weeks(count) => {
            t_string!(i18n, common.time_weeks_ago, count = count).to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn relative_age_uses_closed_nonnegative_units() {
        let now = datetime!(2026-08-26 12:00 UTC);
        assert_eq!(relative_age(now, now), RelativeAge::JustNow);
        assert_eq!(
            relative_age(now, datetime!(2026-08-26 11:58 UTC)),
            RelativeAge::Minutes(2)
        );
        assert_eq!(
            relative_age(now, datetime!(2026-08-26 09:00 UTC)),
            RelativeAge::Hours(3)
        );
        assert_eq!(
            relative_age(now, datetime!(2026-08-24 12:00 UTC)),
            RelativeAge::Days(2)
        );
        assert_eq!(
            relative_age(now, datetime!(2026-08-12 12:00 UTC)),
            RelativeAge::Weeks(2)
        );
        assert_eq!(
            relative_age(now, datetime!(2026-08-27 12:00 UTC)),
            RelativeAge::JustNow
        );
    }

    #[test]
    fn full_time_follows_the_interface_language_in_utc() {
        let at = datetime!(2026-11-12 09:41:05 +08:00);
        assert_eq!(
            localized_date_time(at, Locale::en),
            "2026-11-12 01:41:05 UTC"
        );
        assert_eq!(
            localized_date_time(at, Locale::zh_CN),
            "2026年11月12日 01:41:05 UTC"
        );
    }
}
