//! Deployment-scoped user preferences at `/settings`.

use leptos::prelude::*;
use openbot_contracts::budget::{RunCostBudgetPreference, RunCostCapInput};

#[cfg(target_arch = "wasm32")]
use crate::api::{load_run_cost_budget, replace_run_cost_budget};
use crate::features::layout::{PageHeader, PageSection, PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::preferences::PreferenceSaveStatus;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Field, Input, LocaleSwitch, Notice, NoticePresentation,
    NoticeTone, Switch, ThemeToggle,
};

const MICRO_UNITS_PER_UNIT: u128 = 1_000_000;
const MAX_COST_MICRO_UNITS: u128 = i64::MAX as u128;

#[derive(Clone, Debug, PartialEq, Eq)]
struct BudgetFormSnapshot {
    enabled: bool,
    currency: String,
    amount: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AmountInputError {
    InvalidDecimal,
    NotPositive,
    TooPrecise,
    TooLarge,
}

/// User-owned appearance, language and per-run provider-cost upper-bound settings.
#[component]
pub fn SettingsPage() -> impl IntoView {
    let i18n = use_i18n();
    let cap_enabled = RwSignal::new(false);
    let currency = RwSignal::new("USD".to_owned());
    let amount = RwSignal::new(String::new());
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let saving = RwSignal::new(false);
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::Preferences,
        move || "$budget".into(),
    );
    let attempted = RwSignal::new(false);
    let saved_form = RwSignal::new(None::<BudgetFormSnapshot>);
    let save_error_form = RwSignal::new(None::<BudgetFormSnapshot>);
    let reload_generation = RwSignal::new(0_u64);
    let worker_owner = StoredValue::new(Owner::current());

    install_run_cost_budget_loader(
        reload_generation,
        cap_enabled,
        currency,
        amount,
        loading,
        load_error,
    );

    let retry = move |_| {
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
    };
    let toggle_cap = UnsyncCallback::new(move |_| {
        attempted.set(false);
    });
    let save = move |_| {
        if loading.get_untracked() || saving.get_untracked() {
            return;
        }
        attempted.set(true);
        let snapshot = budget_form_snapshot(cap_enabled, currency, amount);
        save_error_form.set(None);
        saved_form.set(None);
        let Ok(preference) = build_run_cost_budget_preference(
            snapshot.enabled,
            &snapshot.currency,
            &snapshot.amount,
        ) else {
            return;
        };
        saving.set(true);
        #[cfg(target_arch = "wasm32")]
        {
            let writes = expect_context::<crate::configuration_writes::ConfigurationWrites>();
            let start_worker = || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    match replace_run_cost_budget(preference).await {
                        Ok(stored) => {
                            if apply_run_cost_budget_preference(
                                stored,
                                cap_enabled,
                                currency,
                                amount,
                            )
                            .is_ok()
                            {
                                attempted.set(false);
                                saved_form.set(Some(budget_form_snapshot(
                                    cap_enabled,
                                    currency,
                                    amount,
                                )));
                            } else {
                                save_error_form.set(Some(snapshot));
                            }
                        }
                        Err(_) => {
                            if !writes.locked(
                                crate::configuration_writes::ConfigurationKind::Preferences,
                                "$budget",
                            ) {
                                save_error_form.set(Some(snapshot));
                            }
                        }
                    }
                    saving.set(false);
                });
            };
            match worker_owner.get_value() {
                Some(owner) => owner.with(start_worker),
                None => start_worker(),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (preference, worker_owner);
            save_error_form.set(Some(snapshot));
            saving.set(false);
        }
    };

    let currency_invalid = Signal::derive(move || {
        attempted.get() && cap_enabled.get() && !valid_currency(&currency.get())
    });
    let amount_invalid = Signal::derive(move || {
        attempted.get() && cap_enabled.get() && parse_main_currency_amount(&amount.get()).is_err()
    });
    let current_form = move || budget_form_snapshot(cap_enabled, currency, amount);

    view! {
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="settings-page-title"
                title=move || t_string!(i18n, settings.preferences_title).to_owned()
                description=move || t_string!(i18n, settings.preferences_description).to_owned()
            />
            <super::account::AccountSummary/>
            <PageSection
                heading_id="settings-general-title"
                title=move || t_string!(i18n, settings.nav_general).to_owned()
            >
                <div class="ob-settings-preference-list">
                    <div class="ob-settings-preference-row">
                        <div class="ob-settings-preference-copy">
                            <h3>{move || t!(i18n, settings.appearance_theme_label)}</h3>
                            <p>{move || t!(i18n, settings.appearance_theme_help)}</p>
                        </div>
                        <div class="ob-settings-preference-actions">
                            <ThemeToggle />
                        </div>
                    </div>
                    <div class="ob-settings-preference-row">
                        <div class="ob-settings-preference-copy">
                            <h3>{move || t!(i18n, settings.nav_language)}</h3>
                            <p>{move || t!(i18n, settings.language_help)}</p>
                        </div>
                        <div class="ob-settings-preference-actions">
                            <LocaleSwitch id="settings-locale-switch" />
                        </div>
                    </div>
                    <div class="ob-settings-preference-row">
                        <div class="ob-settings-preference-copy">
                            <h3>{move || t!(i18n, settings.run_cost_budget_label)}</h3>
                            <p>{move || t!(i18n, settings.run_cost_budget_help)}</p>
                        </div>
                        <div class="ob-settings-preference-actions ob-run-cost-budget">
                            <Show when=move || loading.get()>
                                <p class="ob-preference-saving" role="status">
                                    {move || t!(i18n, settings.run_cost_budget_loading)}
                                </p>
                            </Show>
                            <Show when=move || load_error.get()>
                                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                                    <span>{move || t!(i18n, settings.run_cost_budget_load_error)}</span>
                                    <Button
                                        variant=ButtonVariant::Ghost
                                        size=ButtonSize::Small
                                        on_activate=retry
                                    >
                                        {move || t!(i18n, common.retry)}
                                    </Button>
                                </Notice>
                            </Show>
                            <Show when=move || !loading.get() && !load_error.get()>
                                <Field
                                    control_id="run-cost-cap-enabled"
                                    label=move || t_string!(i18n, settings.run_cost_budget_enable_label).to_owned()
                                    description=move || t_string!(i18n, settings.run_cost_budget_enable_help).to_owned()
                                    disabled=Signal::derive(move || saving.get() || write_lock.get())
                                >
                                    <Switch checked=cap_enabled on_change=toggle_cap />
                                </Field>
                                <Show when=move || cap_enabled.get()>
                                    <div class="ob-run-cost-budget-fields">
                                        <Field
                                            control_id="run-cost-cap-currency"
                                            label=move || t_string!(i18n, settings.run_cost_budget_currency_label).to_owned()
                                            description=move || t_string!(i18n, settings.run_cost_budget_currency_help).to_owned()
                                            error=move || t_string!(i18n, settings.run_cost_budget_currency_error).to_owned()
                                            invalid=currency_invalid
                                            disabled=Signal::derive(move || saving.get() || write_lock.get())
                                        >
                                            <Input value=currency placeholder="USD" />
                                        </Field>
                                        <Field
                                            control_id="run-cost-cap-amount"
                                            label=move || t_string!(i18n, settings.run_cost_budget_amount_label).to_owned()
                                            description=move || t_string!(i18n, settings.run_cost_budget_amount_help).to_owned()
                                            error=move || t_string!(i18n, settings.run_cost_budget_amount_error).to_owned()
                                            invalid=amount_invalid
                                            disabled=Signal::derive(move || saving.get() || write_lock.get())
                                        >
                                            <Input
                                                value=amount
                                                placeholder=move || t_string!(i18n, settings.run_cost_budget_amount_placeholder).to_owned()
                                            />
                                        </Field>
                                    </div>
                                </Show>
                                <div class="ob-run-cost-budget-footer">
                                    <Button
                                        variant=ButtonVariant::Primary
                                        size=ButtonSize::Medium
                                        loading=saving
                                        disabled=write_lock
                                        on_activate=save
                                    >
                                        {move || t!(i18n, common.save)}
                                    </Button>
                                    <Show when=move || saving.get()>
                                        <p class="ob-preference-saving" role="status">
                                            {move || t!(i18n, settings.run_cost_budget_saving)}
                                        </p>
                                    </Show>
                                    <Show when=move || saved_form.get().as_ref() == Some(&current_form())>
                                        <p class="ob-run-cost-budget-saved" role="status">
                                            {move || if cap_enabled.get() {
                                                t_string!(i18n, settings.run_cost_budget_saved).to_owned()
                                            } else {
                                                t_string!(i18n, settings.run_cost_budget_disabled).to_owned()
                                            }}
                                        </p>
                                    </Show>
                                </div>
                                <Show when=move || save_error_form.get().as_ref() == Some(&current_form())>
                                    <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                                        {move || t!(i18n, settings.run_cost_budget_save_error)}
                                    </Notice>
                                </Show>
                            </Show>
                        </div>
                    </div>
                </div>
                <div class="ob-settings-preference-status">
                    <PreferenceSaveStatus id_prefix="settings-preferences-editor"/>
                </div>
            </PageSection>
        </PageShell>
    }
}

fn install_run_cost_budget_loader(
    reload_generation: RwSignal<u64>,
    cap_enabled: RwSignal<bool>,
    currency: RwSignal<String>,
    amount: RwSignal<String>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let generation = reload_generation.get();
        loading.set(true);
        load_error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = load_run_cost_budget().await.and_then(|preference| {
                apply_run_cost_budget_preference(preference, cap_enabled, currency, amount)
                    .map_err(|_| crate::api::ApiError::InvalidResponse)
            });
            if reload_generation.get_untracked() != generation {
                return;
            }
            if result.is_err() {
                load_error.set(true);
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        reload_generation,
        cap_enabled,
        currency,
        amount,
        loading,
        load_error,
    );
}

fn budget_form_snapshot(
    cap_enabled: RwSignal<bool>,
    currency: RwSignal<String>,
    amount: RwSignal<String>,
) -> BudgetFormSnapshot {
    BudgetFormSnapshot {
        enabled: cap_enabled.get_untracked(),
        currency: currency.get_untracked(),
        amount: amount.get_untracked(),
    }
}

fn build_run_cost_budget_preference(
    enabled: bool,
    currency: &str,
    amount: &str,
) -> Result<RunCostBudgetPreference, AmountInputError> {
    if !enabled {
        return Ok(RunCostBudgetPreference::default());
    }
    if !valid_currency(currency) {
        return Err(AmountInputError::InvalidDecimal);
    }
    Ok(RunCostBudgetPreference {
        cap: Some(RunCostCapInput {
            currency: currency.to_owned(),
            max_cost_micro_units: parse_main_currency_amount(amount)?,
        }),
    })
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn apply_run_cost_budget_preference(
    preference: RunCostBudgetPreference,
    cap_enabled: RwSignal<bool>,
    currency: RwSignal<String>,
    amount: RwSignal<String>,
) -> Result<(), AmountInputError> {
    match preference.cap {
        Some(cap) if valid_currency(&cap.currency) => {
            let formatted = format_micro_units(&cap.max_cost_micro_units)?;
            currency.set(cap.currency);
            amount.set(formatted);
            cap_enabled.set(true);
            Ok(())
        }
        Some(_) => Err(AmountInputError::InvalidDecimal),
        None => {
            cap_enabled.set(false);
            currency.set("USD".to_owned());
            amount.set(String::new());
            Ok(())
        }
    }
}

fn valid_currency(currency: &str) -> bool {
    currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn parse_main_currency_amount(raw: &str) -> Result<String, AmountInputError> {
    let value = raw.trim();
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) if !fraction.contains('.') => (whole, fraction),
        Some(_) => return Err(AmountInputError::InvalidDecimal),
        None => (value, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AmountInputError::InvalidDecimal);
    }
    if fraction.len() > 6 {
        return Err(AmountInputError::TooPrecise);
    }
    let whole = whole
        .parse::<u128>()
        .map_err(|_| AmountInputError::TooLarge)?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u128>()
            .map_err(|_| AmountInputError::InvalidDecimal)?
            * 10_u128.pow(6_u32.saturating_sub(fraction.len() as u32))
    };
    let micro_units = whole
        .checked_mul(MICRO_UNITS_PER_UNIT)
        .and_then(|whole| whole.checked_add(fraction))
        .ok_or(AmountInputError::TooLarge)?;
    if micro_units == 0 {
        return Err(AmountInputError::NotPositive);
    }
    if micro_units > MAX_COST_MICRO_UNITS {
        return Err(AmountInputError::TooLarge);
    }
    Ok(micro_units.to_string())
}

fn format_micro_units(raw: &str) -> Result<String, AmountInputError> {
    let bytes = raw.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 19
        || !matches!(bytes[0], b'1'..=b'9')
        || !bytes[1..].iter().all(u8::is_ascii_digit)
    {
        return Err(AmountInputError::InvalidDecimal);
    }
    let micro_units = raw
        .parse::<u128>()
        .map_err(|_| AmountInputError::TooLarge)?;
    if micro_units > MAX_COST_MICRO_UNITS {
        return Err(AmountInputError::TooLarge);
    }
    let whole = micro_units / MICRO_UNITS_PER_UNIT;
    let fraction = micro_units % MICRO_UNITS_PER_UNIT;
    if fraction == 0 {
        return Ok(whole.to_string());
    }
    let fraction = format!("{fraction:06}");
    Ok(format!("{whole}.{}", fraction.trim_end_matches('0')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_currency_amounts_convert_to_exact_positive_micro_unit_strings() {
        assert_eq!(parse_main_currency_amount("1").unwrap(), "1000000");
        assert_eq!(parse_main_currency_amount("12.34").unwrap(), "12340000");
        assert_eq!(parse_main_currency_amount("0.000001").unwrap(), "1");
        assert_eq!(
            parse_main_currency_amount(" 0001.230000 ").unwrap(),
            "1230000"
        );
        assert_eq!(
            parse_main_currency_amount("9223372036854.775807").unwrap(),
            i64::MAX.to_string()
        );
    }

    #[test]
    fn main_currency_amounts_reject_rounding_non_positive_and_out_of_range_values() {
        assert_eq!(
            parse_main_currency_amount("0").unwrap_err(),
            AmountInputError::NotPositive
        );
        assert_eq!(
            parse_main_currency_amount("0.0000001").unwrap_err(),
            AmountInputError::TooPrecise
        );
        assert_eq!(
            parse_main_currency_amount("9223372036854.775808").unwrap_err(),
            AmountInputError::TooLarge
        );
        for invalid in ["", ".5", "-1", "+1", "1e3", "1,25", "1.2.3"] {
            assert_eq!(
                parse_main_currency_amount(invalid).unwrap_err(),
                AmountInputError::InvalidDecimal,
                "{invalid}"
            );
        }
    }

    #[test]
    fn canonical_micro_units_format_without_float_rounding() {
        assert_eq!(format_micro_units("1").unwrap(), "0.000001");
        assert_eq!(format_micro_units("1000000").unwrap(), "1");
        assert_eq!(format_micro_units("12340000").unwrap(), "12.34");
        assert_eq!(
            format_micro_units(&i64::MAX.to_string()).unwrap(),
            "9223372036854.775807"
        );
        for invalid in ["", "0", "01", "1.0", "9223372036854775808"] {
            assert!(format_micro_units(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn form_wire_is_closed_and_currency_is_exact_uppercase() {
        assert!(valid_currency("USD"));
        assert!(!valid_currency("usd"));
        assert!(!valid_currency("US"));
        assert_eq!(
            build_run_cost_budget_preference(true, "USD", "2.50").unwrap(),
            RunCostBudgetPreference {
                cap: Some(RunCostCapInput {
                    currency: "USD".to_owned(),
                    max_cost_micro_units: "2500000".to_owned(),
                }),
            }
        );
        assert_eq!(
            build_run_cost_budget_preference(false, "bad", "bad").unwrap(),
            RunCostBudgetPreference::default()
        );
    }
}
