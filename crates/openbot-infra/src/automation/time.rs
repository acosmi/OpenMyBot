//! Fixed bundled time-zone and five-field grammar checks for paused draft admission.

use jiff::tz::TimeZone;
use openbot_contracts::{automation::AutomationTrigger, error::AppError};
use openbot_domain::automation::AutomationConfig;

/// Check a newly admitted draft without creating progress, slots or scheduler state.
pub(crate) fn validate_draft(config: &AutomationConfig) -> Result<(), AppError> {
    if let AutomationTrigger::Cron {
        expression,
        timezone,
        ..
    } = &config.wire().trigger
    {
        fields(expression)?;
        if timezone.is_empty() || timezone.len() > 128 || !timezone.is_ascii() {
            return Err(malformed());
        }
        let (name, bytes) = jiff_tzdb::get(timezone).ok_or_else(malformed)?;
        TimeZone::tzif(name, bytes).map_err(|_| malformed())?;
    }
    Ok(())
}

fn malformed() -> AppError {
    AppError::MalformedPayload { field: "trigger" }
}

fn fields(expression: &str) -> Result<[u64; 5], AppError> {
    if expression.is_empty() || expression.len() > 128 || !expression.is_ascii() {
        return Err(malformed());
    }
    let mut parts = expression.split_ascii_whitespace();
    let mut fields = [0; 5];
    let bounds = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)];
    for (index, (minimum, maximum)) in bounds.into_iter().enumerate() {
        let part = parts.next().ok_or_else(malformed)?;
        for item in part.split(',') {
            let (range, step) = match item.split_once('/') {
                Some((range, step)) => {
                    if range != "*" && !range.contains('-') {
                        return Err(malformed());
                    }
                    (range, number(step)?)
                }
                None => (item, 1),
            };
            if step == 0 || step > maximum - minimum + 1 {
                return Err(malformed());
            }
            let (first, last) = if range == "*" {
                (minimum, maximum)
            } else if let Some((first, last)) = range.split_once('-') {
                (number(first)?, number(last)?)
            } else {
                let value = number(range)?;
                (value, value)
            };
            if first < minimum || last > maximum || first > last {
                return Err(malformed());
            }
            for value in (first..=last).step_by(usize::from(step)) {
                fields[index] |= 1_u64 << value;
            }
        }
    }
    let all_dom = (1_u64 << 32) - 2;
    let all_dow = (1_u64 << 7) - 1;
    if parts.next().is_some() || (fields[2] != all_dom && fields[4] != all_dow) {
        return Err(malformed());
    }
    Ok(fields)
}

fn number(value: &str) -> Result<u8, AppError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed());
    }
    value.parse().map_err(|_| malformed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::automation::AutomationConfigV1;
    use serde_json::json;

    #[test]
    fn draft_cron_uses_only_registered_grammar_and_bundled_iana_zones() {
        let input = |expression: &str, timezone: &str| {
            let wire: AutomationConfigV1 = serde_json::from_value(json!({
                "schemaVersion":1,"title":"Draft","botId":"bot","promptTemplate":"Check",
                "trigger":{"kind":"cron","expression":expression,"timezone":timezone,"catchUpLatest":false},
                "modelPolicy":"bot_current","permissionCeiling":{"toolIds":[],"dataScopes":[]},
                "budget":[{"metric":"sampling_calls","totalLimit":"2"}],"runDeadlineSeconds":60
            })).unwrap();
            AutomationConfig::try_from(wire).unwrap()
        };
        for (expression, timezone) in [
            ("*/5 0-23/2 * 1,6,12 0-6", "America/New_York"),
            ("0 9 1-31 * 1-5", "Asia/Shanghai"),
            ("0 9 1 * *", "Etc/UTC"),
        ] {
            validate_draft(&input(expression, timezone)).unwrap();
        }
        for expression in [
            "0 0 * * 7",
            "0 0 1 * 1",
            "1/2 * * * *",
            "*/0 * * * *",
            "*/61 * * * *",
            "0 0 * JAN *",
            "@daily",
            "0 0 0 * * *",
            "0 0 L * *",
            "0 0 * * ?",
            "0,,1 * * * *",
            "60 * * * *",
            "0 24 * * *",
            "0 0 0 * *",
            "0 0 * 13 *",
            "0 0 * * 6-1",
        ] {
            assert_eq!(
                validate_draft(&input(expression, "America/New_York")),
                Err(malformed()),
                "{expression}"
            );
        }
        for timezone in [
            "",
            "Mars/Olympus",
            "/etc/localtime",
            ":/usr/share/zoneinfo/UTC",
            "时区",
        ] {
            assert_eq!(
                validate_draft(&input("0 0 * * *", timezone)),
                Err(malformed()),
                "{timezone}"
            );
        }
        assert!(validate_draft(&input(&"*".repeat(129), "Etc/UTC")).is_err());
        assert_eq!(
            fields("0-10/5 * * * *").unwrap()[0],
            1 | (1 << 5) | (1 << 10)
        );
        assert!(
            jiff_tzdb::VERSION.is_some(),
            "the pinned bundle exposes its actual IANA version"
        );
    }
}
