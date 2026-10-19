use super::*;

use crate::command::{BeginThreadRun, BeginThreadRunBody};
use crate::model_connections::ModelConnectionSource;
use serde::de::{DeserializeOwned, value::StrDeserializer};
use serde_json::{Value, json};

const CONNECTION_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";

fn v1_value(connection_id: &str, revision: i64) -> Value {
    json!({"connectionId": connection_id, "expectedRevision": revision})
}

fn v2_value(source: ModelSelectionIntentSource) -> Value {
    json!({
        "schemaVersion": 2,
        "source": source.as_str(),
        "connectionId": CONNECTION_ID,
        "expectedConnectionRevision": 7,
        "modelId": "Model Ω A",
        "expectedCatalogRevision": 11,
    })
}

fn v2_wire(source: ModelSelectionIntentSource) -> String {
    serde_json::to_string(&v2_value(source)).unwrap()
}

fn assert_rejected(wire: &str) {
    assert!(serde_json::from_str::<VersionedRunModelSelection>(wire).is_err());
    assert_eq!(
        VersionedRunModelSelection::from_json_bytes(wire.as_bytes()),
        Err(ModelSelectionDecodeError::InvalidInput),
    );
}

fn assert_v2_rejected(wire: &str) {
    assert_rejected(wire);
    assert!(serde_json::from_str::<RunModelSelectionV2>(wire).is_err());
}

fn assert_static_error<T: DeserializeOwned>(wire: &str, canary: &str) {
    let error = match serde_json::from_str::<T>(wire) {
        Ok(_) => panic!("untrusted input was accepted"),
        Err(error) => error.to_string(),
    };
    assert!(error.starts_with(INVALID_MODEL_SELECTION));
    assert!(!error.contains(canary));
    assert!(!error.contains("invalid type"));
    assert!(!error.contains("unknown variant"));
    assert!(!error.contains("unknown field"));
}

fn with_extra_raw_field(base: &str, key: &str, raw_value: &str, first: bool) -> String {
    let inner = &base[1..base.len() - 1];
    let field = format!("\"{key}\":{raw_value}");
    if first {
        format!("{{{field},{inner}}}")
    } else {
        format!("{{{inner},{field}}}")
    }
}

#[test]
fn v1_keeps_legacy_uuid_shape_case_and_exact_wire() {
    for connection_id in [
        CONNECTION_ID,
        "ABCDEF01-2345-6789-ABCD-EF0123456789",
        "00000000-0000-0000-0000-000000000000",
        "01234567-89ab-1def-0123-456789abcdef",
        "01234567-89ab-fdef-0123-456789abcdef",
    ] {
        for revision in [1, 7, i64::MAX] {
            let input = v1_value(connection_id, revision);
            let wire = serde_json::to_string(&input).unwrap();
            let old: RunModelSelection = serde_json::from_str(&wire).unwrap();
            let parsed: VersionedRunModelSelection = serde_json::from_str(&wire).unwrap();
            assert_eq!(parsed, VersionedRunModelSelection::V1(old.clone()));
            assert!(parsed.is_valid());
            assert_eq!(
                serde_json::to_string(&parsed).unwrap(),
                serde_json::to_string(&old).unwrap()
            );
            assert_eq!(serde_json::to_value(&parsed).unwrap(), input);
            assert_eq!(
                VersionedRunModelSelection::from_json_bytes(wire.as_bytes()).unwrap(),
                parsed
            );
        }
    }

    for connection_id in [
        "",
        "bad",
        "0123456789abcdef0123456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdeg",
        "01234567_89ab-cdef-0123-456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdeé",
    ] {
        let old = RunModelSelection {
            connection_id: connection_id.to_owned(),
            expected_revision: 7,
        };
        assert!(!old.is_valid());
        let wire = serde_json::to_string(&v1_value(connection_id, 7)).unwrap();
        assert!(serde_json::from_str::<RunModelSelection>(&wire).is_err());
        assert_rejected(&wire);
        let mut v2 = v2_value(ModelSelectionIntentSource::Custom);
        v2["connectionId"] = json!(connection_id);
        assert_v2_rejected(&serde_json::to_string(&v2).unwrap());
    }

    let old = RunModelSelection {
        connection_id: "invalid manually constructed value".to_owned(),
        expected_revision: 0,
    };
    let direct = VersionedRunModelSelection::V1(old.clone());
    assert!(!direct.is_valid());
    assert_eq!(
        serde_json::to_string(&direct).unwrap(),
        serde_json::to_string(&old).unwrap()
    );
    assert_rejected(&serde_json::to_string(&direct).unwrap());

    let legacy_array = format!("[\"{CONNECTION_ID}\",7]");
    assert!(serde_json::from_str::<RunModelSelection>(&legacy_array).is_ok());
    assert_rejected(&legacy_array);
    for wire in ["null", "[]", "{}", "true", "7", "\"selection\""] {
        assert_rejected(wire);
    }
}

#[test]
fn v2_three_sources_round_trip_six_fields_only() {
    for source in [
        ModelSelectionIntentSource::Custom,
        ModelSelectionIntentSource::SdkGateway,
        ModelSelectionIntentSource::AccountBridge,
    ] {
        let value = RunModelSelectionV2::new(
            source,
            CONNECTION_ID.to_owned(),
            7,
            "Model Ω A".to_owned(),
            11,
        )
        .unwrap();
        assert_eq!(RunModelSelectionV2::SCHEMA_VERSION, 2);
        assert_eq!(value.source(), source);
        assert_eq!(value.connection_id(), CONNECTION_ID);
        assert_eq!(value.expected_connection_revision(), 7);
        assert_eq!(value.model_id(), "Model Ω A");
        assert_eq!(value.expected_catalog_revision(), 11);
        let versioned = VersionedRunModelSelection::V2(value.clone());
        assert!(versioned.is_valid());
        let wire = serde_json::to_string(&versioned).unwrap();
        let serialized: Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(serialized.as_object().unwrap().len(), 6);
        assert_eq!(serialized, v2_value(source));
        assert_eq!(
            serde_json::from_str::<VersionedRunModelSelection>(&wire).unwrap(),
            versioned
        );
        assert_eq!(
            serde_json::from_str::<RunModelSelectionV2>(&wire).unwrap(),
            value
        );
        assert_eq!(
            VersionedRunModelSelection::from_json_bytes(wire.as_bytes()).unwrap(),
            versioned
        );
        assert_eq!(
            serde_json::to_value(source).unwrap(),
            json!(source.as_str())
        );
        assert_eq!(
            serde_json::from_value::<ModelSelectionIntentSource>(json!(source.as_str())).unwrap(),
            source
        );
    }
}

#[test]
fn rejects_mixed_v1_v2_and_missing_fields() {
    let valid_v2 = v2_value(ModelSelectionIntentSource::Custom);
    for field in [
        "schemaVersion",
        "source",
        "connectionId",
        "expectedConnectionRevision",
        "modelId",
        "expectedCatalogRevision",
    ] {
        let mut missing = valid_v2.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert_v2_rejected(&serde_json::to_string(&missing).unwrap());
    }
    for field in ["connectionId", "expectedRevision"] {
        let mut missing = v1_value(CONNECTION_ID, 7);
        missing.as_object_mut().unwrap().remove(field);
        assert_rejected(&serde_json::to_string(&missing).unwrap());
    }
    let valid_v1 = serde_json::to_string(&v1_value(CONNECTION_ID, 7)).unwrap();
    assert!(serde_json::from_str::<RunModelSelectionV2>(&valid_v1).is_err());
    let valid_v2 = v2_wire(ModelSelectionIntentSource::Custom);
    for first in [false, true] {
        assert_v2_rejected(&with_extra_raw_field(
            &valid_v2,
            "expectedRevision",
            "7",
            first,
        ));
        for (field, raw_value) in [
            ("schemaVersion", "2"),
            ("source", "\"custom\""),
            ("expectedConnectionRevision", "7"),
            ("modelId", "\"model\""),
            ("expectedCatalogRevision", "11"),
        ] {
            assert_rejected(&with_extra_raw_field(&valid_v1, field, raw_value, first));
        }
    }
    for wire in ["{}", "{\"schemaVersion\":2}", "{\"source\":\"custom\"}"] {
        assert_v2_rejected(wire);
    }
}

#[test]
fn rejects_duplicate_keys_without_value_collection() {
    let v1 = serde_json::to_string(&v1_value(CONNECTION_ID, 7)).unwrap();
    let v2 = v2_wire(ModelSelectionIntentSource::Custom);
    for (key, raw_value, base) in [
        (
            "connectionId",
            "\"01234567-89ab-cdef-0123-456789abcdef\"",
            v2.as_str(),
        ),
        ("expectedRevision", "7", v1.as_str()),
        ("schemaVersion", "2", v2.as_str()),
        ("source", "\"custom\"", v2.as_str()),
        ("expectedConnectionRevision", "7", v2.as_str()),
        ("modelId", "\"Model Ω A\"", v2.as_str()),
        ("expectedCatalogRevision", "11", v2.as_str()),
    ] {
        let escaped_key = format!("\\u{:04x}{}", u32::from(key.as_bytes()[0]), &key[1..]);
        for alias in [key, escaped_key.as_str()] {
            for first in [false, true] {
                let wire = with_extra_raw_field(base, alias, raw_value, first);
                assert_rejected(&wire);
                assert_static_error::<VersionedRunModelSelection>(&wire, "duplicate canary absent");
                assert!(serde_json::from_str::<RunModelSelectionV2>(&wire).is_err());
            }
        }
    }
}

#[test]
fn rejects_unknown_fields_without_echoing_untrusted_keys() {
    const CANARY: &str = "SECRET_SELECTION_CANARY_9182";
    let v1 = serde_json::to_string(&v1_value(CONNECTION_ID, 7)).unwrap();
    let v2 = v2_wire(ModelSelectionIntentSource::Custom);
    for base in [&v1, &v2] {
        for first in [false, true] {
            let wire = with_extra_raw_field(base, CANARY, "\"private-value\"", first);
            assert_static_error::<VersionedRunModelSelection>(&wire, CANARY);
            assert_static_error::<RunModelSelectionV2>(&wire, CANARY);
            assert_eq!(
                VersionedRunModelSelection::from_json_bytes(wire.as_bytes())
                    .unwrap_err()
                    .to_string(),
                INVALID_MODEL_SELECTION
            );
        }
    }

    for (field, value) in [
        ("connectionId", json!({"secret": CANARY})),
        ("expectedConnectionRevision", json!(CANARY)),
        ("expectedCatalogRevision", json!(CANARY)),
        ("modelId", json!([CANARY])),
        ("schemaVersion", json!(CANARY)),
        ("source", json!(CANARY)),
    ] {
        let mut invalid = v2_value(ModelSelectionIntentSource::Custom);
        invalid[field] = value;
        let wire = serde_json::to_string(&invalid).unwrap();
        assert_static_error::<VersionedRunModelSelection>(&wire, CANARY);
        assert_static_error::<RunModelSelectionV2>(&wire, CANARY);
        assert_rejected(&wire);
    }
    let wrong_v1 =
        format!("{{\"connectionId\":\"{CONNECTION_ID}\",\"expectedRevision\":\"{CANARY}\"}}");
    assert_static_error::<VersionedRunModelSelection>(&wrong_v1, CANARY);
    for source_wire in [
        format!("\"{CANARY}\""),
        format!("[\"{CANARY}\"]"),
        format!("{{\"{CANARY}\":true}}"),
        "null".to_owned(),
        "false".to_owned(),
    ] {
        assert_static_error::<ModelSelectionIntentSource>(&source_wire, CANARY);
    }
    let direct = ModelSelectionIntentSource::deserialize(
        StrDeserializer::<serde::de::value::Error>::new(CANARY),
    )
    .unwrap_err();
    assert_eq!(direct.to_string(), INVALID_MODEL_SELECTION);
    for raw in [
        format!("{{\"{CANARY}\""),
        format!("\"{CANARY}"),
        format!("{{\"connectionId\":\"{CANARY}\",}}"),
    ] {
        assert_eq!(
            VersionedRunModelSelection::from_json_bytes(raw.as_bytes())
                .unwrap_err()
                .to_string(),
            INVALID_MODEL_SELECTION
        );
    }
    assert_eq!(
        ModelSelectionDecodeError::TooLarge.to_string(),
        "model_selection_json_too_large"
    );
    assert_eq!(
        ModelSelectionDecodeError::InvalidInput.to_string(),
        INVALID_MODEL_SELECTION
    );
}

#[test]
fn requires_known_source_and_exact_integer_schema_version() {
    let wire = v2_wire(ModelSelectionIntentSource::Custom);
    for lexeme in [
        "0",
        "1",
        "3",
        "-2",
        "2.0",
        "2e0",
        "2E+0",
        "\"2\"",
        "null",
        "true",
        "[]",
        "{}",
        "9223372036854775808",
    ] {
        assert_v2_rejected(&wire.replace(
            "\"schemaVersion\":2",
            &format!("\"schemaVersion\":{lexeme}"),
        ));
    }
    for source in [
        "",
        "Custom",
        "sdkGateway",
        "SDK_GATEWAY",
        "account-bridge",
        "local",
        "default",
    ] {
        let mut value = v2_value(ModelSelectionIntentSource::Custom);
        value["source"] = json!(source);
        assert_v2_rejected(&serde_json::to_string(&value).unwrap());
        assert!(serde_json::from_value::<ModelSelectionIntentSource>(json!(source)).is_err());
    }
    for source in [
        json!(null),
        json!(true),
        json!(1),
        json!(1.0),
        json!([]),
        json!({}),
    ] {
        let mut value = v2_value(ModelSelectionIntentSource::Custom);
        value["source"] = source.clone();
        assert_v2_rejected(&serde_json::to_string(&value).unwrap());
        assert!(serde_json::from_value::<ModelSelectionIntentSource>(source).is_err());
    }
    for wire in ["null", "[]", "[2,\"custom\"]", "\"custom\"", "2"] {
        assert!(serde_json::from_str::<RunModelSelectionV2>(wire).is_err());
    }
}

#[test]
fn requires_positive_i64_revisions_without_numeric_coercion() {
    let mut v2 = v2_value(ModelSelectionIntentSource::Custom);
    v2["expectedConnectionRevision"] = json!(i64::MAX);
    v2["expectedCatalogRevision"] = json!(i64::MAX);
    let parsed: RunModelSelectionV2 = serde_json::from_value(v2).unwrap();
    assert_eq!(parsed.expected_connection_revision(), i64::MAX);
    assert_eq!(parsed.expected_catalog_revision(), i64::MAX);
    let v1 = serde_json::to_string(&v1_value(CONNECTION_ID, 7)).unwrap();
    let v2 = v2_wire(ModelSelectionIntentSource::Custom);
    for (field, original, base) in [
        ("expectedRevision", "7", v1.as_str()),
        ("expectedConnectionRevision", "7", v2.as_str()),
        ("expectedCatalogRevision", "11", v2.as_str()),
    ] {
        for lexeme in [
            "0",
            "-1",
            "9223372036854775808",
            "-9223372036854775809",
            "7.0",
            "7e0",
            "\"7\"",
            "true",
            "null",
            "[]",
            "{}",
        ] {
            let invalid = base.replace(
                &format!("\"{field}\":{original}"),
                &format!("\"{field}\":{lexeme}"),
            );
            assert_rejected(&invalid);
            if field != "expectedRevision" {
                assert!(serde_json::from_str::<RunModelSelectionV2>(&invalid).is_err());
            }
        }
    }
    for (connection_revision, catalog_revision) in [(0, 1), (-1, 1), (1, 0), (1, -1)] {
        assert_eq!(
            RunModelSelectionV2::new(
                ModelSelectionIntentSource::Custom,
                CONNECTION_ID.to_owned(),
                connection_revision,
                "model".to_owned(),
                catalog_revision
            ),
            Err(ModelSelectionDecodeError::InvalidInput)
        );
    }
}

#[test]
fn model_id_enforces_utf8_control_and_edge_space_boundaries() {
    let unicode_512 = format!("{}aa", "界".repeat(170));
    let four_byte_512 = "🦀".repeat(128);
    assert_eq!(unicode_512.len(), MAX_MODEL_CONNECTION_MODEL_BYTES);
    assert_eq!(four_byte_512.len(), MAX_MODEL_CONNECTION_MODEL_BYTES);
    for model in [
        "A B  C/Ωß".to_owned(),
        "模型 e\u{301}".to_owned(),
        "Model\u{200b}X".to_owned(),
        "x".repeat(512),
        unicode_512,
        four_byte_512,
    ] {
        let typed = RunModelSelectionV2::new(
            ModelSelectionIntentSource::Custom,
            CONNECTION_ID.to_owned(),
            1,
            model.clone(),
            1,
        )
        .unwrap();
        assert_eq!(typed.model_id(), model);
        let mut value = v2_value(ModelSelectionIntentSource::Custom);
        value["modelId"] = json!(model);
        value["expectedConnectionRevision"] = json!(1);
        value["expectedCatalogRevision"] = json!(1);
        let wire = serde_json::to_string(&value).unwrap();
        assert_eq!(
            serde_json::from_str::<RunModelSelectionV2>(&wire).unwrap(),
            typed
        );
        assert_eq!(
            VersionedRunModelSelection::from_json_bytes(wire.as_bytes()).unwrap(),
            VersionedRunModelSelection::V2(typed)
        );
    }
    let unicode_513 = "界".repeat(171);
    assert_eq!(unicode_513.len(), 513);
    for model in [
        "".to_owned(),
        " ".to_owned(),
        " model".to_owned(),
        "model ".to_owned(),
        "\u{2003}model".to_owned(),
        "model\u{2003}".to_owned(),
        "a\0b".to_owned(),
        "a\nb".to_owned(),
        "a\tb".to_owned(),
        "a\u{7f}b".to_owned(),
        "a\u{85}b".to_owned(),
        "a\u{9f}b".to_owned(),
        "x".repeat(513),
        unicode_513,
    ] {
        assert_eq!(
            RunModelSelectionV2::new(
                ModelSelectionIntentSource::Custom,
                CONNECTION_ID.to_owned(),
                1,
                model.clone(),
                1
            ),
            Err(ModelSelectionDecodeError::InvalidInput)
        );
        let mut value = v2_value(ModelSelectionIntentSource::Custom);
        value["modelId"] = json!(model);
        assert_v2_rejected(&serde_json::to_string(&value).unwrap());
    }
}

#[test]
fn raw_json_entry_enforces_4096_utf8_and_single_object() {
    let object = serde_json::to_string(&v1_value(CONNECTION_ID, 7)).unwrap();
    let remaining = MAX_MODEL_SELECTION_JSON_BYTES - object.len();
    let whitespace: String = " \t\r\n".chars().cycle().take(remaining).collect();
    let split = whitespace.len() / 2;
    let input = format!("{}{}{}", &whitespace[..split], object, &whitespace[split..]);
    assert_eq!(input.len(), MAX_MODEL_SELECTION_JSON_BYTES);
    assert!(
        VersionedRunModelSelection::from_json_bytes(input.as_bytes())
            .unwrap()
            .is_valid()
    );
    let oversized = format!("{input} ");
    assert_eq!(
        VersionedRunModelSelection::from_json_bytes(oversized.as_bytes()),
        Err(ModelSelectionDecodeError::TooLarge)
    );
    assert!(serde_json::from_str::<VersionedRunModelSelection>(&oversized).is_ok());
    assert_eq!(
        VersionedRunModelSelection::from_json_bytes(&vec![
            0xff;
            MAX_MODEL_SELECTION_JSON_BYTES + 1
        ]),
        Err(ModelSelectionDecodeError::TooLarge)
    );
    assert_eq!(
        VersionedRunModelSelection::from_json_bytes(&[0xff]),
        Err(ModelSelectionDecodeError::InvalidInput)
    );
    assert_eq!(
        VersionedRunModelSelection::from_json_bytes(&vec![0xff; MAX_MODEL_SELECTION_JSON_BYTES]),
        Err(ModelSelectionDecodeError::InvalidInput)
    );
    for suffix in [
        " {}",
        " []",
        " null",
        " 7",
        " true",
        " \"second\"",
        " garbage",
        "\u{a0}",
    ] {
        let invalid = format!("{object}{suffix}");
        assert_eq!(
            VersionedRunModelSelection::from_json_bytes(invalid.as_bytes()),
            Err(ModelSelectionDecodeError::InvalidInput)
        );
    }
    for prefix in ["\u{a0}", "\u{2003}"] {
        assert_eq!(
            VersionedRunModelSelection::from_json_bytes(format!("{prefix}{object}").as_bytes()),
            Err(ModelSelectionDecodeError::InvalidInput)
        );
    }
    for input in [
        "",
        " \t\r\n",
        "null",
        "[]",
        "[{}]",
        "true",
        "2",
        "\"object\"",
        "{",
        "{}garbage",
    ] {
        assert_eq!(
            VersionedRunModelSelection::from_json_bytes(input.as_bytes()),
            Err(ModelSelectionDecodeError::InvalidInput)
        );
    }
    assert!(
        serde_json::from_str::<Option<VersionedRunModelSelection>>("null")
            .unwrap()
            .is_none()
    );
}

#[test]
fn whole_selection_equality_preserves_every_intent_field() {
    let base = RunModelSelectionV2::new(
        ModelSelectionIntentSource::Custom,
        CONNECTION_ID.to_owned(),
        7,
        "Model Ω A".to_owned(),
        11,
    )
    .unwrap();
    assert_eq!(base, base.clone());
    let versioned = VersionedRunModelSelection::V2(base.clone());
    assert_eq!(versioned, versioned.clone());
    for differing in [
        RunModelSelectionV2::new(
            ModelSelectionIntentSource::SdkGateway,
            CONNECTION_ID.to_owned(),
            7,
            "Model Ω A".to_owned(),
            11,
        )
        .unwrap(),
        RunModelSelectionV2::new(
            ModelSelectionIntentSource::AccountBridge,
            CONNECTION_ID.to_owned(),
            7,
            "Model Ω A".to_owned(),
            11,
        )
        .unwrap(),
        RunModelSelectionV2::new(
            ModelSelectionIntentSource::Custom,
            CONNECTION_ID.to_uppercase(),
            7,
            "Model Ω A".to_owned(),
            11,
        )
        .unwrap(),
        RunModelSelectionV2::new(
            ModelSelectionIntentSource::Custom,
            CONNECTION_ID.to_owned(),
            8,
            "Model Ω A".to_owned(),
            11,
        )
        .unwrap(),
        RunModelSelectionV2::new(
            ModelSelectionIntentSource::Custom,
            CONNECTION_ID.to_owned(),
            7,
            "model Ω A".to_owned(),
            11,
        )
        .unwrap(),
        RunModelSelectionV2::new(
            ModelSelectionIntentSource::Custom,
            CONNECTION_ID.to_owned(),
            7,
            "Model Ω A".to_owned(),
            12,
        )
        .unwrap(),
    ] {
        assert_ne!(base, differing);
        assert_ne!(versioned, VersionedRunModelSelection::V2(differing));
    }
    let v1 = VersionedRunModelSelection::V1(RunModelSelection {
        connection_id: CONNECTION_ID.to_owned(),
        expected_revision: 7,
    });
    assert_ne!(versioned, v1);
    let composed = RunModelSelectionV2::new(
        ModelSelectionIntentSource::Custom,
        CONNECTION_ID.to_owned(),
        7,
        "é".to_owned(),
        11,
    )
    .unwrap();
    let decomposed = RunModelSelectionV2::new(
        ModelSelectionIntentSource::Custom,
        CONNECTION_ID.to_owned(),
        7,
        "e\u{301}".to_owned(),
        11,
    )
    .unwrap();
    assert_ne!(composed, decomposed);
    assert_eq!(composed.model_id(), "é");
    assert_eq!(decomposed.model_id(), "e\u{301}");

    let debug_id = "DEADBEEF-CAFE-1234-ABCD-0123456789AB";
    let debug_model = "MODEL_DEBUG_CANARY_63521";
    let debug_v2 = RunModelSelectionV2::new(
        ModelSelectionIntentSource::Custom,
        debug_id.to_owned(),
        7654321,
        debug_model.to_owned(),
        1234567,
    )
    .unwrap();
    for debug in [
        format!("{debug_v2:?}"),
        format!("{:?}", VersionedRunModelSelection::V2(debug_v2)),
        format!(
            "{:?}",
            VersionedRunModelSelection::V1(RunModelSelection {
                connection_id: debug_id.to_owned(),
                expected_revision: 7654321
            })
        ),
        format!(
            "{:?}",
            VersionedRunModelSelection::V1(RunModelSelection {
                connection_id: debug_model.to_owned(),
                expected_revision: 0
            })
        ),
    ] {
        for canary in [
            debug_id,
            debug_model,
            "7654321",
            "1234567",
            "connection_id",
            "model_id",
        ] {
            assert!(!debug.contains(canary));
        }
        assert!(debug.contains("redacted"));
    }
}

#[test]
fn new_intent_does_not_enable_existing_begin_or_source() {
    let body =
        json!({"runId":"run","botId":"bot","anchor":{"kind":"direct_bot"},"message":"hello"});
    let mut command = body.clone();
    command["threadId"] = json!("thread");
    let selection = v1_value(CONNECTION_ID, 7);
    for raw_selection in [None, Some(Value::Null), Some(selection)] {
        let mut body_input = body.clone();
        let mut command_input = command.clone();
        if let Some(value) = raw_selection.clone() {
            body_input["modelSelection"] = value.clone();
            command_input["modelSelection"] = value;
        }
        let parsed_body: BeginThreadRunBody = serde_json::from_value(body_input).unwrap();
        let parsed_command: BeginThreadRun = serde_json::from_value(command_input).unwrap();
        assert_eq!(parsed_body.model_selection, parsed_command.model_selection);
        match raw_selection {
            Some(value) if !value.is_null() => {
                assert!(parsed_body.model_selection.unwrap().is_valid())
            }
            _ => assert!(parsed_body.model_selection.is_none()),
        }
    }
    for source in [
        ModelSelectionIntentSource::Custom,
        ModelSelectionIntentSource::SdkGateway,
        ModelSelectionIntentSource::AccountBridge,
    ] {
        let v2 = v2_value(source);
        assert!(
            serde_json::from_value::<VersionedRunModelSelection>(v2.clone())
                .unwrap()
                .is_valid()
        );
        let mut body_input = body.clone();
        body_input["modelSelection"] = v2.clone();
        let mut command_input = command.clone();
        command_input["modelSelection"] = v2;
        assert!(serde_json::from_value::<BeginThreadRunBody>(body_input).is_err());
        assert!(serde_json::from_value::<BeginThreadRun>(command_input).is_err());
    }
    assert_eq!(
        serde_json::from_str::<ModelConnectionSource>("\"custom\"").unwrap(),
        ModelConnectionSource::Custom
    );
    assert_eq!(
        serde_json::to_string(&ModelConnectionSource::Custom).unwrap(),
        "\"custom\""
    );
    for wire in ["\"sdk_gateway\"", "\"account_bridge\""] {
        assert!(serde_json::from_str::<ModelConnectionSource>(wire).is_err());
    }
}
