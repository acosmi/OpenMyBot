use std::collections::BTreeSet;

use toml::Value;

use crate::icons::Icon;

#[test]
fn token_contrast_wcag_aa_covers_all_84_required_pairs() {
    let tokens = tokens();
    let color = table(&tokens, "color");
    let text = strings(color.get("text_tokens").expect("text_tokens"));
    let surfaces = strings(color.get("surface_tokens").expect("surface_tokens"));
    let graphics = strings(color.get("graphic_tokens").expect("graphic_tokens"));
    let mut pairs = 0;
    for theme in ["light", "dark"] {
        let colors = child_table(color, theme);
        for foreground in &text {
            for background in &surfaces {
                assert_contrast(colors, foreground, background, 4.5, theme);
                pairs += 1;
            }
        }
        assert_contrast(colors, "fg_inverse", "bg_inverse", 4.5, theme);
        pairs += 1;
        for graphic in &graphics {
            assert_contrast(colors, graphic, "bg", 3.0, theme);
            pairs += 1;
        }
    }
    assert_eq!(pairs, 84);
}

#[test]
fn compact_visual_roles_keep_aa_on_their_declared_surfaces() {
    let tokens = tokens();
    let color = table(&tokens, "color");
    for theme in ["light", "dark"] {
        let colors = child_table(color, theme);
        for (foreground, background) in [
            ("fg_rail", "bg_rail"),
            ("fg_weak", "bg"),
            ("fg_weak", "bg_sidebar"),
            ("fg_weak", "bg_pane"),
            ("fg_nav_group", "bg_sidebar"),
            ("fg_agent_row", "bg_sidebar"),
            ("fg_agent_row", "bg_agent_selected"),
            ("fg_agent_row", "bg_row_hover"),
            ("fg", "bg_row_hover"),
            ("fg_secondary", "bg_row_hover"),
            ("fg_muted", "bg_row_hover"),
            ("fg", "bg_agent_selected"),
            ("fg_secondary", "bg_agent_selected"),
            ("fg_muted", "bg_agent_selected"),
            ("fg_breadcrumb", "bg"),
            ("fg_user_bubble", "bg_user_bubble"),
            ("fg_review_positive", "bg_review_positive"),
            ("fg_library_title", "bg"),
            ("fg_library_muted", "bg"),
        ] {
            assert_contrast(colors, foreground, background, 4.5, theme);
        }
        assert_contrast(colors, "fg_library_icon", "bg_library_icon", 3.0, theme);
    }
}

#[test]
fn app_css_handwritten_theme_values_match_tokens_toml() {
    let tokens = tokens();
    let css = include_str!("../design/app.css");
    let typography = table(&tokens, "typography");
    assert_css(css, "font-sans", string(typography, "font_sans"));
    assert_css(css, "font-mono", string(typography, "font_mono"));

    let scale = child_table(typography, "scale");
    for name in ["xs", "sm", "base", "lg", "xl", "2xl"] {
        let step = child_table(scale, name);
        assert_css(
            css,
            &format!("text-{name}"),
            &format!("{}px", integer(step, "size")),
        );
        assert_css(
            css,
            &format!("text-{name}--line-height"),
            &format!("{}px", integer(step, "line_height")),
        );
    }

    let radius = table(&tokens, "radius");
    for name in ["sm", "md", "lg", "xl", "full"] {
        assert_css(css, &format!("radius-{name}"), string(radius, name));
    }
    let motion = table(&tokens, "motion");
    assert_css(css, "ease-enter", string(motion, "ease_enter"));
    assert_css(css, "ease-exit", string(motion, "ease_exit"));
    let breakpoint = table(&tokens, "breakpoint");
    for name in ["md", "lg"] {
        assert_css(css, &format!("breakpoint-{name}"), string(breakpoint, name));
    }
}

#[test]
fn root_and_app_layout_css_keep_one_viewport_with_inner_scroll_ownership() {
    let css = include_str!("../design/app.css");
    let root = css
        .split_once(".ob-root-layout {")
        .expect("root layout CSS")
        .1
        .split_once('}')
        .expect("root layout rule")
        .0;
    assert!(root.contains("width: 100%"));
    assert!(root.contains("min-height: 100dvh"));

    let app = css
        .split_once(".ob-app-shell {")
        .expect("app shell CSS")
        .1
        .split_once('}')
        .expect("app shell rule")
        .0;
    assert!(app.contains("height: 100dvh"));
    assert!(app.contains("overflow: hidden"));
    let main = css
        .split_once(".ob-main {")
        .expect("main pane CSS")
        .1
        .split_once('}')
        .expect("main pane rule")
        .0;
    assert!(main.contains("min-height: 0"));
    assert!(main.contains("overflow: auto"));

    // The document itself never adds a second scroll container below the app shell.
    for selector in ["\nhtml {", "\nbody {"] {
        let rule = css
            .split_once(selector)
            .unwrap_or_else(|| panic!("{selector} rule"))
            .1
            .split_once('}')
            .expect("root rule")
            .0;
        assert!(
            !rule.contains("min-height"),
            "{selector} must not set min-height"
        );
    }
    // UI spec v5.2 §5.5: width breakpoints are 700/701 and 1100/1101 only.
    for line in css
        .lines()
        .filter(|line| line.starts_with("@media") && line.contains("width"))
    {
        for value in line
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        {
            assert!(
                matches!(value, "700px" | "701px" | "1100px"),
                "stray breakpoint {value} in `{line}`"
            );
        }
    }
}

#[test]
fn app_css_references_only_defined_custom_properties() {
    let app = include_str!("../design/app.css");
    let generated = include_str!("../design/tokens.css");
    let mut declared = BTreeSet::from(["spacing"]); // Tailwind's own spacing theme variable.
    for css in [app, generated] {
        for (index, _) in css.match_indices("--") {
            let name = custom_property_name(&css[index + 2..]);
            if css[index + 2 + name.len()..].trim_start().starts_with(':') {
                declared.insert(name);
            }
        }
    }
    let undefined = app
        .match_indices("var(--")
        .map(|(index, _)| custom_property_name(&app[index + 6..]))
        .filter(|name| !declared.contains(name))
        .collect::<BTreeSet<_>>();
    assert!(
        undefined.is_empty(),
        "app.css reads undefined custom properties: {undefined:?}"
    );
}

#[test]
fn cjk_rule_overrides_scale_line_heights_without_setting_line_height() {
    let generated = include_str!("../design/tokens.css");
    let rule = generated
        .split_once(":lang(zh) {")
        .expect("generated CJK rule")
        .1
        .split_once('}')
        .expect("CJK rule terminator")
        .0;
    assert!(!rule.contains("\n  line-height:"));
    for (step, size) in [("xs", 12), ("sm", 13), ("base", 14)] {
        assert!(rule.contains(&format!(
            "--text-{step}--line-height: calc({size}px * 1.6);"
        )));
    }
}

#[test]
fn generated_icons_and_array_table_tokens_are_complete() {
    assert_eq!(Icon::ALL.len(), 74);
    for icon in Icon::ALL {
        assert_eq!(Icon::from_name(icon.name()), Some(*icon));
        assert!(icon.svg().starts_with("<svg"));
    }
    assert_eq!(
        crate::tokens::TYPOGRAPHY_FONT_FACE_0_FAMILY,
        "Inter Variable"
    );
    assert_eq!(crate::tokens::TYPOGRAPHY_FONT_FACE_1_STYLE, "italic");
    assert!(include_str!("../design/tokens.css").starts_with("/* @generated"));
}

#[test]
fn reduced_motion_constructively_stops_every_declared_css_animation() {
    let css = include_str!("../design/app.css");
    assert!(css.contains("animation: ob-skeleton-pulse"));
    assert!(css.contains("animation: ob-agent-presence-spin"));
    assert!(css.contains("animation: ob-agent-presence-speak"));
    assert!(css.contains("animation: ob-agent-presence-error"));
    assert!(css.contains("var(--motion-agent-presence-cycle)"));
    assert!(css.contains("var(--motion-agent-presence-error)"));
    let reduced = css
        .split_once("@media (prefers-reduced-motion: reduce)")
        .expect("reduced-motion media query")
        .1;
    assert!(reduced.contains("transition-duration: 0ms !important"));
    assert!(reduced.contains("animation: none !important"));
}

#[test]
fn computer_placeholder_is_one_neutral_id_free_svg_source() {
    let art = include_str!("features/settings/computer_placeholder_art.rs");
    let wrapper = include_str!("features/computer/placeholder.rs");
    assert_eq!(art.matches("<svg").count(), 1);
    assert_eq!(wrapper.matches("<svg").count(), 0);
    assert!(wrapper.contains("<ComputerPlaceholderArt"));
    assert!(art.contains("stroke=\"currentColor\""));
    assert!(art.contains("aria-hidden=\"true\""));
    assert!(art.contains("focusable=\"false\""));
    for forbidden in [
        "linearGradient",
        "radialGradient",
        "<filter",
        "<defs",
        "url(",
        "http://",
        "https://",
        " id=",
        "fill=\"#",
        "stroke=\"#",
        "stop-color",
    ] {
        assert!(!art.contains(forbidden), "forbidden SVG marker {forbidden}");
    }
}

#[test]
fn all_avatar_palettes_keep_initials_wcag_aa_in_both_themes() {
    let tokens = tokens();
    let color = table(&tokens, "color");
    for theme in ["light", "dark"] {
        let colors = child_table(color, theme);
        for index in 0..8 {
            assert_contrast(colors, "fg", &format!("avatar_{index}"), 4.5, theme);
        }
    }
}

fn custom_property_name(rest: &str) -> &str {
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or(rest.len());
    &rest[..end]
}

fn tokens() -> Value {
    toml::from_str(include_str!("../design/tokens.toml")).expect("tokens.toml must parse")
}

fn table<'a>(value: &'a Value, key: &str) -> &'a toml::Table {
    value
        .get(key)
        .and_then(Value::as_table)
        .unwrap_or_else(|| panic!("missing token table {key}"))
}

fn child_table<'a>(table: &'a toml::Table, key: &str) -> &'a toml::Table {
    table
        .get(key)
        .and_then(Value::as_table)
        .unwrap_or_else(|| panic!("missing token table {key}"))
}

fn string<'a>(table: &'a toml::Table, key: &str) -> &'a str {
    table
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing token string {key}"))
}

fn integer(table: &toml::Table, key: &str) -> i64 {
    table
        .get(key)
        .and_then(Value::as_integer)
        .unwrap_or_else(|| panic!("missing token integer {key}"))
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .expect("token string array")
}

fn assert_css(css: &str, property: &str, expected: &str) {
    let marker = format!("--{property}:");
    let value = css
        .split_once(&marker)
        .unwrap_or_else(|| panic!("app.css missing {marker}"))
        .1
        .split_once(';')
        .expect("CSS custom property terminator")
        .0
        .trim();
    assert_eq!(value, expected, "app.css property --{property} drifted");
}

fn assert_contrast(
    colors: &toml::Table,
    foreground: &str,
    background: &str,
    minimum: f64,
    theme: &str,
) {
    let ratio = contrast(string(colors, foreground), string(colors, background));
    assert!(
        ratio + f64::EPSILON >= minimum,
        "{theme} {foreground} on {background}: {ratio:.3} < {minimum}"
    );
}

fn contrast(foreground: &str, background: &str) -> f64 {
    let foreground = luminance(parse_hex(foreground));
    let background = luminance(parse_hex(background));
    (foreground.max(background) + 0.05) / (foreground.min(background) + 0.05)
}

fn parse_hex(value: &str) -> [u8; 3] {
    assert_eq!(value.len(), 7, "expected #RRGGBB: {value}");
    assert!(value.starts_with('#'), "expected #RRGGBB: {value}");
    [
        u8::from_str_radix(&value[1..3], 16).unwrap(),
        u8::from_str_radix(&value[3..5], 16).unwrap(),
        u8::from_str_radix(&value[5..7], 16).unwrap(),
    ]
}

fn luminance(rgb: [u8; 3]) -> f64 {
    let linear = rgb.map(|channel| {
        let value = f64::from(channel) / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    });
    linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722
}
