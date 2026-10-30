//! RFC 8785 canonical JSON of a permission request's input, its digest and its summary.
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonical bytes: object keys in UTF-16 code-unit order, no whitespace, integers exact,
/// other numbers in ECMAScript `Number::toString` form.
pub(crate) fn jcs(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    write(value, &mut out);
    out.into_bytes()
}
/// SHA-256 over the complete canonical bytes, before any truncation.
pub(crate) fn input_sha256(jcs_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(jcs_bytes).into()
}
/// The first `PERMISSION_SUMMARY_MAX` bytes, cut back to a UTF-8 boundary.
pub(crate) fn summary(jcs_bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(jcs_bytes);
    let mut end = text.len().min(crate::PERMISSION_SUMMARY_MAX);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => match (number.as_i64(), number.as_u64(), number.as_f64()) {
            (Some(integer), _, _) => out.push_str(&integer.to_string()),
            (_, Some(integer), _) => out.push_str(&integer.to_string()),
            (_, _, Some(float)) => out.push_str(&ecmascript(float)),
            _ => out.push_str("null"),
        },
        Value::String(text) => string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(Vec<u16>, &String, &Value)> = map
                .iter()
                .map(|(key, value)| (key.encode_utf16().collect(), key, value))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (index, (_, key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                string(key, out);
                out.push(':');
                write(value, out);
            }
            out.push('}');
        }
    }
}
fn string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}
/// ECMAScript `Number::toString` of a finite double from its shortest round-trip digits.
fn ecmascript(value: f64) -> String {
    if value == 0.0 {
        return "0".into();
    }
    let mut buffer = ryu::Buffer::new();
    let shortest = buffer.format_finite(value.abs());
    let (mantissa, exponent) = match shortest.split_once('e') {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().unwrap_or(0)),
        None => (shortest, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{whole}{fraction}");
    let leading = all.len() - all.trim_start_matches('0').len();
    let digits = all.trim_start_matches('0').trim_end_matches('0');
    // value = 0.digits × 10^n
    let n = whole.len() as i32 - leading as i32 + exponent;
    let k = digits.len() as i32;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        let mantissa = if k == 1 {
            digits.to_owned()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        format!("{mantissa}e{sign}{}", e.abs())
    };
    if value < 0.0 {
        format!("-{body}")
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn text(value: &Value) -> String {
        String::from_utf8(jcs(value)).unwrap()
    }

    #[test]
    fn object_keys_sort_by_utf16_code_units() {
        // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FF5E although its code
        // point is larger.
        let value = json!({"\u{ff5e}": 1, "\u{1f600}": 2, "b": {"\u{ff5e}": 3, "\u{1f600}": 4, "a": 5}, "a": 6});
        assert_eq!(
            text(&value),
            "{\"a\":6,\"b\":{\"a\":5,\"\u{1f600}\":4,\"\u{ff5e}\":3},\"\u{1f600}\":2,\"\u{ff5e}\":1}"
        );
    }

    #[test]
    fn integers_are_exact_in_i64_and_u64_range() {
        let value: Value = serde_json::from_str(
            "[9007199254740993,-9223372036854775808,18446744073709551615,0,-1]",
        )
        .unwrap();
        assert_eq!(
            text(&value),
            "[9007199254740993,-9223372036854775808,18446744073709551615,0,-1]"
        );
    }

    #[test]
    fn floats_follow_ecmascript_number_formatting() {
        // Vectors from ECMAScript `String(x)`, computed independently of this code. The inputs
        // are Rust literals, which round correctly (serde_json's default parser does not).
        for (input, expected) in [
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (0.000001, "0.000001"),
            (123456789012345680000.0, "123456789012345680000"),
            (333333333.3333333, "333333333.3333333"),
            (-0.0, "0"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (1.5, "1.5"),
            (-2.5e-10, "-2.5e-10"),
            (100.0, "100"),
            (1e20, "100000000000000000000"),
            (4.35, "4.35"),
            (0.1, "0.1"),
        ] {
            let value = Value::Number(serde_json::Number::from_f64(input).unwrap());
            assert_eq!(text(&value), expected, "{input:e}");
        }
    }

    #[test]
    fn string_escapes_follow_rfc8785() {
        let value = json!("q\"b\\\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}é€😀/");
        assert_eq!(
            text(&value),
            "\"q\\\"b\\\\\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}é€😀/\""
        );
    }

    #[test]
    fn nested_and_empty_containers_serialize_without_whitespace() {
        let value = json!({"z": [], "y": {}, "x": [null, true, false, {"b": [1, {"a": "s"}]}]});
        assert_eq!(
            text(&value),
            "{\"x\":[null,true,false,{\"b\":[1,{\"a\":\"s\"}]}],\"y\":{},\"z\":[]}"
        );
    }
}
