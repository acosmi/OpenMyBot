use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use sha2::{Digest as _, Sha256};

/// Generate all build-script assets from the committed design sources.
#[allow(dead_code)] // The Trunk pre-build consumer only needs `materialize_token_css`.
pub fn generate_build_assets(manifest: &Path, output: &Path) -> Result<(), Box<dyn Error>> {
    let tokens = parse_toml(&manifest.join("design/tokens.toml"))?;
    validate_fonts(manifest, &tokens)?;
    let css = generate_token_css(&tokens)?;
    fs::write(output.join("tokens.css"), &css)?;
    // `design/tokens.css` is deliberately ignored: `tokens.toml` is the only committed source.
    // Always materialize it so a clean checkout cannot require a pre-existing generated file.
    fs::write(manifest.join("design/tokens.css"), &css)?;
    fs::write(output.join("tokens.rs"), generate_rust_tokens(&tokens)?)?;
    fs::write(output.join("icons.rs"), generate_icons(manifest)?)?;
    Ok(())
}

/// Materialize only the ignored CSS prerequisite needed before Trunk starts Tailwind.
#[allow(dead_code)] // Cargo's build.rs consumer generates the full asset set instead.
pub fn materialize_token_css(manifest: &Path) -> Result<(), Box<dyn Error>> {
    let tokens = parse_toml(&manifest.join("design/tokens.toml"))?;
    validate_fonts(manifest, &tokens)?;
    fs::write(
        manifest.join("design/tokens.css"),
        generate_token_css(&tokens)?,
    )?;
    Ok(())
}

fn parse_toml(path: &Path) -> Result<toml::Value, Box<dyn Error>> {
    Ok(toml::from_str(&fs::read_to_string(path)?)?)
}

fn table<'a>(value: &'a toml::Value, key: &str) -> Result<&'a toml::Table, Box<dyn Error>> {
    value
        .get(key)
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("tokens.toml missing table {key}").into())
}

fn string<'a>(table: &'a toml::Table, key: &str) -> Result<&'a str, Box<dyn Error>> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("tokens.toml missing string {key}").into())
}

fn generate_token_css(tokens: &toml::Value) -> Result<String, Box<dyn Error>> {
    let meta = table(tokens, "meta")?;
    let color = table(tokens, "color")?;
    let light = color
        .get("light")
        .and_then(toml::Value::as_table)
        .ok_or("tokens.toml missing color.light")?;
    let dark = color
        .get("dark")
        .and_then(toml::Value::as_table)
        .ok_or("tokens.toml missing color.dark")?;
    if light.keys().collect::<BTreeSet<_>>() != dark.keys().collect::<BTreeSet<_>>() {
        return Err("color.light/color.dark key sets differ".into());
    }
    let overrides = color
        .get("css_var_overrides")
        .and_then(toml::Value::as_table);
    let mut css = String::from("/* @generated from design/tokens.toml; do not edit. */\n");
    writeln!(&mut css, "{} {{", string(meta, "light_selector")?)?;
    write_color_vars(&mut css, light, overrides)?;
    write_scalar_section(&mut css, table(tokens, "z_index")?, "z", None)?;
    write_scalar_section(&mut css, table(tokens, "size")?, "size", Some("px"))?;
    write_scalar_section(&mut css, table(tokens, "motion")?, "motion", None)?;
    write_scalar_section(&mut css, table(tokens, "opacity")?, "opacity", None)?;
    css.push_str("}\n\n");

    writeln!(&mut css, "{} {{", string(meta, "dark_selector")?)?;
    write_color_vars(&mut css, dark, overrides)?;
    css.push_str("}\n\n");
    writeln!(
        &mut css,
        "@media {} {{\n  {} {{",
        string(meta, "system_dark_media")?,
        string(meta, "system_dark_selector")?
    )?;
    write_color_vars(&mut css, dark, overrides)?;
    css.push_str("  }\n}\n\n");

    // CJK overrides only the type-scale line-height variables, never `line-height` itself:
    // rules that read the variables (helper/error text, body controls) get the roomier value,
    // while containers that declare their own line-height keep it for their descendants.
    let typography = table(tokens, "typography")?;
    let cjk = typography
        .get("cjk")
        .and_then(toml::Value::as_table)
        .ok_or("tokens.toml missing typography.cjk")?;
    let scale = typography
        .get("scale")
        .and_then(toml::Value::as_table)
        .ok_or("tokens.toml missing typography.scale")?;
    let steps = cjk
        .get("scale_steps")
        .and_then(toml::Value::as_array)
        .ok_or("tokens.toml missing typography.cjk.scale_steps")?;
    let line_height = string(cjk, "line_height")?;
    writeln!(&mut css, "{} {{", string(cjk, "selector")?)?;
    writeln!(
        &mut css,
        "  hanging-punctuation: {};",
        string(cjk, "hanging_punctuation")?
    )?;
    for step in steps {
        let step = step.as_str().ok_or("typography.cjk.scale_steps member")?;
        let size = scale
            .get(step)
            .and_then(|value| value.get("size"))
            .and_then(toml::Value::as_integer)
            .ok_or_else(|| format!("tokens.toml missing typography.scale.{step}.size"))?;
        writeln!(
            &mut css,
            "  --text-{step}--line-height: calc({size}px * {line_height});"
        )?;
    }
    css.push_str("}\n");
    Ok(css)
}

fn write_color_vars(
    output: &mut String,
    colors: &toml::Table,
    overrides: Option<&toml::Table>,
) -> Result<(), Box<dyn Error>> {
    for (key, value) in colors {
        let value = value
            .as_str()
            .ok_or_else(|| format!("color {key} is not a string"))?;
        let name = overrides
            .and_then(|overrides| overrides.get(key))
            .and_then(toml::Value::as_str)
            .map_or_else(|| key.replace('_', "-"), str::to_owned);
        writeln!(output, "  --{name}: {value};")?;
    }
    Ok(())
}

fn write_scalar_section(
    output: &mut String,
    section: &toml::Table,
    prefix: &str,
    integer_unit: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    for (key, value) in section {
        if matches!(
            key.as_str(),
            "css_prefix" | "allowed_animations" | "reduced"
        ) {
            continue;
        }
        let rendered = match value {
            toml::Value::String(value) => value.clone(),
            toml::Value::Integer(value) => format!("{value}{}", integer_unit.unwrap_or("")),
            toml::Value::Float(value) => value.to_string(),
            toml::Value::Boolean(value) => value.to_string(),
            _ => continue,
        };
        writeln!(
            output,
            "  --{prefix}-{}: {rendered};",
            key.replace('_', "-")
        )?;
    }
    Ok(())
}

fn generate_rust_tokens(tokens: &toml::Value) -> Result<String, Box<dyn Error>> {
    let meta = table(tokens, "meta")?;
    let sections = meta
        .get("rust_emit_sections")
        .and_then(toml::Value::as_array)
        .ok_or("tokens.toml missing meta.rust_emit_sections")?;
    let mut constants = BTreeMap::new();
    for section in sections {
        let section = section.as_str().ok_or("rust_emit_sections member")?;
        if let Some(value) = tokens.get(section) {
            flatten_token(section, value, &mut constants);
        }
    }
    let mut rust = String::from("// @generated from design/tokens.toml; do not edit.\n");
    for (name, value) in constants {
        writeln!(
            &mut rust,
            "pub const {}: &str = {:?};",
            const_name(&name),
            value
        )?;
    }
    Ok(rust)
}

fn flatten_token(prefix: &str, value: &toml::Value, output: &mut BTreeMap<String, String>) {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                flatten_token(&format!("{prefix}_{key}"), value, output);
            }
        }
        toml::Value::Array(values) => {
            if values.iter().all(|value| scalar_text(value).is_some()) {
                let rendered = values
                    .iter()
                    .filter_map(scalar_text)
                    .collect::<Vec<_>>()
                    .join(",");
                output.insert(prefix.to_owned(), rendered);
            } else {
                for (index, value) in values.iter().enumerate() {
                    flatten_token(&format!("{prefix}_{index}"), value, output);
                }
            }
        }
        _ => {
            if let Some(value) = scalar_text(value) {
                output.insert(prefix.to_owned(), value);
            }
        }
    }
}

fn scalar_text(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(value) => Some(value.clone()),
        toml::Value::Integer(value) => Some(value.to_string()),
        toml::Value::Float(value) => Some(value.to_string()),
        toml::Value::Boolean(value) => Some(value.to_string()),
        _ => None,
    }
}

fn const_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn generate_icons(manifest: &Path) -> Result<String, Box<dyn Error>> {
    let source = parse_toml(&manifest.join("design/icons.toml"))?;
    let entries = source
        .get("icon")
        .and_then(toml::Value::as_array)
        .ok_or("icons.toml missing [[icon]] entries")?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = entry.as_table().ok_or("icon entry not table")?;
        let name = string(entry, "name")?;
        if !names.insert(name.to_owned()) {
            return Err(format!("duplicate icon {name}").into());
        }
        let svg = fs::read_to_string(manifest.join(format!("design/icons/{name}.svg")))?;
        validate_svg(name, &svg)?;
    }
    let expected_count = source
        .get("meta")
        .and_then(toml::Value::as_table)
        .and_then(|meta| meta.get("expected_icon_count"))
        .and_then(toml::Value::as_integer)
        .ok_or("icons.toml missing meta.expected_icon_count")?;
    if i64::try_from(names.len())? != expected_count {
        return Err(format!(
            "icons.toml count drift: expected {expected_count}, got {}",
            names.len()
        )
        .into());
    }
    let actual = fs::read_dir(manifest.join("design/icons"))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            (entry.path().extension().and_then(|value| value.to_str()) == Some("svg"))
                .then(|| entry.path().file_stem()?.to_str().map(str::to_owned))
                .flatten()
        })
        .collect::<BTreeSet<_>>();
    if names != actual {
        return Err(format!(
            "icons.toml/SVG set drift: manifest_only={:?} svg_only={:?}",
            names.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&names).collect::<Vec<_>>()
        )
        .into());
    }
    let mut rust = String::from("// @generated from design/icons.toml; do not edit.\n");
    rust.push_str("#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]\npub enum Icon {\n");
    for name in &names {
        writeln!(&mut rust, "    {},", icon_variant(name))?;
    }
    rust.push_str("}\n\nimpl Icon {\n");
    rust.push_str("    pub const ALL: &[Self] = &[\n");
    for name in &names {
        writeln!(&mut rust, "        Self::{},", icon_variant(name))?;
    }
    rust.push_str(
        "    ];\n\n    pub const fn name(self) -> &'static str {\n        match self {\n",
    );
    for name in &names {
        writeln!(
            &mut rust,
            "            Self::{} => {:?},",
            icon_variant(name),
            name
        )?;
    }
    rust.push_str(
        "        }\n    }\n\n    pub const fn svg(self) -> &'static str {\n        match self {\n",
    );
    for name in &names {
        writeln!(
            &mut rust,
            "            Self::{} => include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), {:?})),",
            icon_variant(name),
            format!("/design/icons/{name}.svg")
        )?;
    }
    rust.push_str("        }\n    }\n\n    pub fn from_name(name: &str) -> Option<Self> {\n        match name {\n");
    for name in &names {
        writeln!(
            &mut rust,
            "            {:?} => Some(Self::{}),",
            name,
            icon_variant(name)
        )?;
    }
    rust.push_str("            _ => None,\n        }\n    }\n}\n\n");
    rust.push_str("pub const ICON_NAMES: &[&str] = &[\n");
    for name in &names {
        writeln!(&mut rust, "    {:?},", name)?;
    }
    rust.push_str("];\n");
    Ok(rust)
}

fn validate_svg(name: &str, svg: &str) -> Result<(), Box<dyn Error>> {
    let lower = svg.to_ascii_lowercase();
    let forbidden = [
        "<script",
        "javascript:",
        "<foreignobject",
        "<image",
        "<use",
        "href=",
        "url(",
        "style=",
        "<!doctype",
        "<?xml",
    ];
    if !svg.trim_start().starts_with("<svg")
        || !svg.trim_end().ends_with("</svg>")
        || !svg.contains("currentColor")
        || !svg.contains("stroke-width=\"1.75\"")
        || forbidden.iter().any(|needle| lower.contains(needle))
        || contains_event_handler(&lower)
    {
        return Err(format!("unsafe/malformed icon {name}").into());
    }
    Ok(())
}

fn contains_event_handler(svg: &str) -> bool {
    svg.split_ascii_whitespace().any(|part| {
        let part = part.trim_start_matches(['<', '/']);
        part.starts_with("on") && part.contains('=')
    })
}

fn icon_variant(name: &str) -> String {
    name.split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + characters.as_str()
            })
        })
        .collect()
}

fn validate_fonts(manifest: &Path, tokens: &toml::Value) -> Result<(), Box<dyn Error>> {
    let faces = table(tokens, "typography")?
        .get("font_face")
        .and_then(toml::Value::as_array)
        .ok_or("tokens.toml missing typography.font_face")?;
    for face in faces {
        let face = face.as_table().ok_or("font_face not table")?;
        let file = string(face, "file")?.trim_start_matches("../");
        let path = manifest.join(file);
        let bytes = fs::read(&path)?;
        let expected_bytes = face
            .get("bytes")
            .and_then(toml::Value::as_integer)
            .ok_or("font_face bytes")?;
        if i64::try_from(bytes.len())? != expected_bytes {
            return Err(format!("font byte size drift: {}", path.display()).into());
        }
        let digest = hex(&Sha256::digest(&bytes));
        if digest != string(face, "sha256")? {
            return Err(format!("font sha256 drift: {}", path.display()).into());
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
