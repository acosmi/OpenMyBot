use openbot_contracts::begin_thread_run_wire::{
    BeginThreadRunDecodeError, DecodedBeginThreadRunBody, decode_begin_thread_run_body,
};
use openbot_contracts::command::BeginThreadRunBody;

const V2: &str = r#"{"schemaVersion":2,"source":"custom","connectionId":"abcdef12-abcd-4bcd-8abc-abcdef123456","expectedConnectionRevision":7,"modelId":"custom:abcdef12-abcd-4bcd-8abc-abcdef123456","expectedCatalogRevision":9}"#;
const V1: &str = r#"{"connectionId":"abcdef12-abcd-4bcd-8abc-abcdef123456","expectedRevision":7}"#;

fn body(selection: &str) -> String {
    format!(
        r#"{{"modelSelection":{selection},"runId":"wire-run","botId":"wire-bot","anchor":{{"kind":"direct_bot"}},"message":"unchanged","selectedSkillSlugs":["one","two"]}}"#
    )
}

#[test]
fn exact_original_v2_span_4096_passes_and_4097_fails() {
    let remaining = 4096 - V2.len();
    let left = " ".repeat(remaining / 2);
    let right = " ".repeat(remaining - left.len());
    let exact = body(&format!("{left}{V2}{right}"));
    assert!(matches!(
        decode_begin_thread_run_body(exact.as_bytes()),
        Ok(DecodedBeginThreadRunBody::V2(_))
    ));
    let oversized = body(&format!("{left}{V2}{right} "));
    assert_eq!(
        decode_begin_thread_run_body(oversized.as_bytes()),
        Err(BeginThreadRunDecodeError::ModelSelectionTooLarge)
    );
}

#[test]
fn all_standard_json_boundary_whitespace_counts_in_original_span() {
    let spaces = String::from_utf8(vec![b' ', b'\t', b'\r', b'\n']).unwrap();
    let padding = " ".repeat(4096 - V2.len() - spaces.len() * 2);
    let exact = body(&format!("{spaces}{V2}{padding}{spaces}"));
    assert!(matches!(
        decode_begin_thread_run_body(exact.as_bytes()),
        Ok(DecodedBeginThreadRunBody::V2(_))
    ));
    let oversized = exact.replace(&format!(":{spaces}{V2}"), &format!(": {spaces}{V2}"));
    assert_eq!(
        decode_begin_thread_run_body(oversized.as_bytes()),
        Err(BeginThreadRunDecodeError::ModelSelectionTooLarge)
    );
}

#[test]
fn interior_json_whitespace_counts_without_changing_the_original_v2_intent() {
    let expected = decode_begin_thread_run_body(body(V2).as_bytes()).unwrap();
    let remaining = 4096 - V2.len();
    for whitespace in *b" \t\r\n" {
        let padding = String::from_utf8(vec![whitespace; remaining]).unwrap();
        let exact_selection = format!("{{{padding}{}", &V2[1..]);
        assert_eq!(exact_selection.len(), 4096);
        assert_eq!(
            decode_begin_thread_run_body(body(&exact_selection).as_bytes()),
            Ok(expected.clone())
        );
        let oversized_selection = format!("{{ {padding}{}", &V2[1..]);
        assert_eq!(oversized_selection.len(), 4097);
        assert_eq!(
            decode_begin_thread_run_body(body(&oversized_selection).as_bytes()),
            Err(BeginThreadRunDecodeError::ModelSelectionTooLarge)
        );
    }
}

#[test]
fn identical_text_in_another_field_never_selects_the_wrong_span() {
    let long = format!("{}{}", " ".repeat(4097 - V2.len()), V2);
    let original = format!(
        r#"{{"message":{},"modelSelection":{long},"runId":"wire-run","botId":"wire-bot","anchor":{{"kind":"direct_bot"}}}}"#,
        serde_json::to_string(V2).unwrap(),
    );
    assert_eq!(
        decode_begin_thread_run_body(original.as_bytes()),
        Err(BeginThreadRunDecodeError::ModelSelectionTooLarge)
    );
}

#[test]
fn escaped_v2_union_key_cannot_downgrade_to_legacy() {
    let escaped = V2.replace("source", "sou\\u0072ce");
    assert!(matches!(
        decode_begin_thread_run_body(body(&escaped).as_bytes()),
        Ok(DecodedBeginThreadRunBody::V2(_))
    ));
    let mixed = V1.trim_end_matches('}').to_owned() + r#","sou\u0072ce":"custom"}"#;
    assert_eq!(
        decode_begin_thread_run_body(body(&mixed).as_bytes()),
        Err(BeginThreadRunDecodeError::MalformedBody)
    );
}

#[test]
fn any_v2_union_key_is_terminal_even_with_wrong_or_missing_values() {
    for extra in [
        r#""schemaVersion":null"#,
        r#""source":"sdk_gateway""#,
        r#""expectedConnectionRevision":0"#,
        r#""modelId":"x""#,
        r#""expectedCatalogRevision":1"#,
    ] {
        let mixed = format!("{},{}{}", V1.trim_end_matches('}'), extra, "}");
        assert_eq!(
            decode_begin_thread_run_body(body(&mixed).as_bytes()),
            Err(BeginThreadRunDecodeError::MalformedBody)
        );
    }
}

#[test]
fn duplicate_escaped_and_null_then_duplicate_body_keys_are_rejected() {
    for original in [
        format!(
            r#"{{"modelSelection":null,"modelSelection":{V2},"runId":"r","botId":"b","anchor":{{"kind":"direct_bot"}},"message":"m"}}"#
        ),
        body(V2).replace(
            r#""runId":"wire-run""#,
            r#""runId":"wire-run","run\u0049d":"wire-run""#,
        ),
        body(V2).replace(
            r#""modelSelection":"#,
            r#""modelSelection":null,"model\u0053election":"#,
        ),
    ] {
        assert_eq!(
            decode_begin_thread_run_body(original.as_bytes()),
            Err(BeginThreadRunDecodeError::MalformedBody)
        );
    }
}

#[test]
fn duplicate_unknown_mixed_and_invalid_v2_selection_never_fallback() {
    for selection in [
        V2.replace(
            r#""source":"custom""#,
            r#""source":"custom","sou\u0072ce":"custom""#,
        ),
        V2.replace(
            r#""schemaVersion":2"#,
            r#""schemaVersion":2,"owner":"wire-owner""#,
        ),
        V2.replace(
            r#""schemaVersion":2"#,
            r#""schemaVersion":2,"expectedRevision":7"#,
        ),
        V2.replace(
            r#""expectedCatalogRevision":9"#,
            r#""expectedCatalogRevision":0"#,
        ),
    ] {
        assert_eq!(
            decode_begin_thread_run_body(body(&selection).as_bytes()),
            Err(BeginThreadRunDecodeError::MalformedBody)
        );
    }
}

#[test]
fn original_v1_object_and_selection_array_keep_old_dto_behavior() {
    for selection in [V1, r#"["abcdef12-abcd-4bcd-8abc-abcdef123456",7]"#, "null"] {
        let original = body(selection);
        let old: BeginThreadRunBody = serde_json::from_slice(original.as_bytes()).unwrap();
        assert_eq!(
            decode_begin_thread_run_body(original.as_bytes()),
            Ok(DecodedBeginThreadRunBody::Legacy(old))
        );
    }
}

#[test]
fn original_v1_whitespace_larger_than_4096_is_not_newly_limited() {
    let original = body(&format!("{}{V1}{}", " ".repeat(5000), " ".repeat(5000)));
    let old = serde_json::from_slice::<BeginThreadRunBody>(original.as_bytes()).unwrap();
    assert_eq!(
        decode_begin_thread_run_body(original.as_bytes()),
        Ok(DecodedBeginThreadRunBody::Legacy(old))
    );
}

#[test]
fn omitted_selection_and_original_outer_array_stay_legacy() {
    for original in [
        r#"{"runId":"wire-run","botId":"wire-bot","anchor":{"kind":"direct_bot"},"message":"unchanged"}"#,
        r#"[null,"wire-run","wire-bot",{"kind":"direct_bot"},"unchanged",[]]"#,
    ] {
        let old: BeginThreadRunBody = serde_json::from_slice(original.as_bytes()).unwrap();
        assert_eq!(
            decode_begin_thread_run_body(original.as_bytes()),
            Ok(DecodedBeginThreadRunBody::Legacy(old))
        );
    }
}

#[test]
fn outer_array_cannot_introduce_v2() {
    let original =
        format!(r#"[{V2},"wire-run","wire-bot",{{"kind":"direct_bot"}},"unchanged",[]]"#);
    assert_eq!(
        decode_begin_thread_run_body(original.as_bytes()),
        Err(BeginThreadRunDecodeError::MalformedBody)
    );
}

#[test]
fn original_uuid_casing_message_and_skill_order_are_retained() {
    let uppercase = V2.replace(
        "abcdef12-abcd-4bcd-8abc-abcdef123456",
        "ABCDEF12-ABCD-4BCD-8ABC-ABCDEF123456",
    );
    let DecodedBeginThreadRunBody::V2(parsed) =
        decode_begin_thread_run_body(body(&uppercase).as_bytes()).unwrap()
    else {
        panic!("not v2");
    };
    assert_eq!(
        parsed.model_selection.connection_id(),
        "ABCDEF12-ABCD-4BCD-8ABC-ABCDEF123456"
    );
    assert_eq!(
        parsed.model_selection.model_id(),
        "custom:ABCDEF12-ABCD-4BCD-8ABC-ABCDEF123456"
    );
    assert_eq!(parsed.message, "unchanged");
    assert_eq!(parsed.selected_skill_slugs, ["one", "two"]);
    assert!(!format!("{parsed:?}").contains("unchanged"));
}

#[test]
fn serde_json_transport_wrapper_uses_original_v2_span_too() {
    let exact = body(&format!("{V2}{}", " ".repeat(4096 - V2.len())));
    assert_eq!(
        serde_json::from_slice::<DecodedBeginThreadRunBody>(exact.as_bytes()).unwrap(),
        decode_begin_thread_run_body(exact.as_bytes()).unwrap()
    );
    let oversized = body(&format!("{V2}{}", " ".repeat(4097 - V2.len())));
    let error = serde_json::from_slice::<DecodedBeginThreadRunBody>(oversized.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(error.contains("begin_thread_run_model_selection_too_large"));
    assert!(!error.contains("wire-bot"));
}

#[test]
fn malformed_utf8_and_body_framing_return_fixed_errors() {
    for original in [
        b"null".as_slice(),
        b"{}",
        b"{",
        b"{\"message\":\"\xff\"}",
        b"{}{}",
    ] {
        assert_eq!(
            decode_begin_thread_run_body(original),
            Err(BeginThreadRunDecodeError::MalformedBody)
        );
    }
}
