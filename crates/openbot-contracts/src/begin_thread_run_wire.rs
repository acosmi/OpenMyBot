//! 同一 runs body 的原字节分派；v2 的 4096 字节限额绑定原属性值 slice。
//!
//! 旧对象、数组、null 与空白只交原 DTO，不追收新 selection 限额。

use core::fmt;
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

use crate::command::{BeginThreadRunBody, BeginThreadRunV2Body};
use crate::versioned_model_selection::{ModelSelectionDecodeError, VersionedRunModelSelection};

/// 原 body 的封闭分派结果；不证明库存、dataset 或当前权限。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedBeginThreadRunBody {
    /// 直接按原 DTO 解码的旧输入。
    Legacy(BeginThreadRunBody),
    /// 已核原 selection span 的新输入。
    V2(BeginThreadRunV2Body),
}

impl<'de> Deserialize<'de> for DecodedBeginThreadRunBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Json's original from-slice deserializer lends this exact whole JSON token. Removing
        // outer framing whitespace does not remove whitespace inside the selection property.
        // Returning only owned DTOs ends this borrow before either transport awaits dispatch.
        let original = <&'de RawValue>::deserialize(deserializer)?;
        decode_begin_thread_run_body(original.get().as_bytes()).map_err(de::Error::custom)
    }
}

/// 固定解码分类，不保存原 body、字段值或底层 serde 诊断。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginThreadRunDecodeError {
    /// 原 body 不符合所选封闭 DTO。
    MalformedBody,
    /// 新 v2 的原属性值（含其首尾标准 JSON 空白）超过预算。
    ModelSelectionTooLarge,
}

impl fmt::Display for BeginThreadRunDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MalformedBody => "begin_thread_run_malformed_body",
            Self::ModelSelectionTooLarge => "begin_thread_run_model_selection_too_large",
        })
    }
}

impl std::error::Error for BeginThreadRunDecodeError {}

struct BodyProbe<'a> {
    selection: Option<&'a RawValue>,
}

impl<'de> Deserialize<'de> for BodyProbe<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BodyVisitor;
        impl<'de> Visitor<'de> for BodyVisitor {
            type Value = BodyProbe<'de>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("closed begin thread run body")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut seen = [false; 7];
                let mut selection = None;
                while let Some(key) = map.next_key::<String>()? {
                    let index = match key.as_str() {
                        "modelSelection" => 0,
                        "runId" => 1,
                        "botId" => 2,
                        "anchor" => 3,
                        "message" => 4,
                        "selectedSkillSlugs" => 5,
                        "artifactRefs" => 6,
                        _ => return Err(de::Error::custom("invalid_begin_thread_run_body")),
                    };
                    if seen[index] {
                        return Err(de::Error::custom("invalid_begin_thread_run_body"));
                    }
                    seen[index] = true;
                    if index == 0 {
                        selection = Some(map.next_value::<&'de RawValue>()?);
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(BodyProbe { selection })
            }
        }
        deserializer.deserialize_map(BodyVisitor)
    }
}

struct SelectionProbe(bool);

impl<'de> Deserialize<'de> for SelectionProbe {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SelectionVisitor;
        impl<'de> Visitor<'de> for SelectionVisitor {
            type Value = SelectionProbe;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("model selection object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut v2 = false;
                while let Some(key) = map.next_key::<String>()? {
                    v2 |= matches!(
                        key.as_str(),
                        "schemaVersion"
                            | "source"
                            | "expectedConnectionRevision"
                            | "modelId"
                            | "expectedCatalogRevision"
                    );
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(SelectionProbe(v2))
            }
        }
        deserializer.deserialize_map(SelectionVisitor)
    }
}

fn is_json_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn original_selection_span<'a>(
    input: &'a [u8],
    raw: &RawValue,
) -> Result<&'a [u8], BeginThreadRunDecodeError> {
    let malformed = BeginThreadRunDecodeError::MalformedBody;
    // RawValue was borrowed by from_slice(input); checked addresses establish the exact token,
    // rather than searching for equal text that could occur in another field or string.
    let mut start = (raw.get().as_ptr() as usize)
        .checked_sub(input.as_ptr() as usize)
        .ok_or(malformed)?;
    let mut end = start.checked_add(raw.get().len()).ok_or(malformed)?;
    if input.get(start..end) != Some(raw.get().as_bytes()) {
        return Err(malformed);
    }
    while start > 0 && is_json_space(input[start - 1]) {
        start -= 1;
    }
    while end < input.len() && is_json_space(input[end]) {
        end += 1;
    }
    if start == 0 || input[start - 1] != b':' || !matches!(input.get(end), Some(b',' | b'}')) {
        return Err(malformed);
    }
    input.get(start..end).ok_or(malformed)
}

/// 从原 whole-body 字节分派旧 DTO 或新 v2；不规范化、重序列化或降级选择。
pub fn decode_begin_thread_run_body(
    input: &[u8],
) -> Result<DecodedBeginThreadRunBody, BeginThreadRunDecodeError> {
    let malformed = BeginThreadRunDecodeError::MalformedBody;
    let legacy = || {
        serde_json::from_slice(input)
            .map(DecodedBeginThreadRunBody::Legacy)
            .map_err(|_| malformed)
    };
    let first = input.iter().copied().find(|byte| !is_json_space(*byte));
    if first != Some(b'{') {
        // This includes the original struct's legal sequence representation.
        return legacy();
    }
    let probe: BodyProbe<'_> = serde_json::from_slice(input).map_err(|_| malformed)?;
    let Some(raw) = probe.selection else {
        return legacy();
    };
    if !raw.get().starts_with('{') {
        return legacy();
    }
    let SelectionProbe(v2) = serde_json::from_str(raw.get()).map_err(|_| malformed)?;
    if !v2 {
        return legacy();
    }
    let span = original_selection_span(input, raw)?;
    let parsed =
        VersionedRunModelSelection::from_json_bytes(span).map_err(|error| match error {
            ModelSelectionDecodeError::TooLarge => {
                BeginThreadRunDecodeError::ModelSelectionTooLarge
            }
            ModelSelectionDecodeError::InvalidInput => malformed,
        })?;
    let VersionedRunModelSelection::V2(selection) = parsed else {
        return Err(malformed);
    };
    let body: BeginThreadRunV2Body = serde_json::from_slice(input).map_err(|_| malformed)?;
    if body.model_selection != selection {
        return Err(malformed);
    }
    Ok(DecodedBeginThreadRunBody::V2(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::versioned_model_selection::MAX_MODEL_SELECTION_JSON_BYTES;

    const V2: &str = r#"{"schemaVersion":2,"source":"custom","connectionId":"0196ea23-b506-73c8-8153-213383fdc24a","expectedConnectionRevision":1,"modelId":"m\u006fdel","expectedCatalogRevision":1}"#;
    const REFS: &str =
        r#"["0196ea23-b507-73c8-8153-213383fdc24a","0196ea23-b506-73c8-8153-213383fdc24a"]"#;

    fn body(selection: Option<&str>, refs: &str) -> String {
        let selection = selection.unwrap_or("null");
        format!(
            r#"{{"modelSelection":{selection},"runId":"run-1","botId":"bot-1","anchor":{{"kind":"direct_bot"}},"message":"unchanged","selectedSkillSlugs":[],"artifactRefs":{refs}}}"#
        )
    }

    #[test]
    fn artifact_refs_seventh_key_preserves_v1_v2_and_reference_order() {
        let expected = vec![
            "0196ea23-b507-73c8-8153-213383fdc24a".to_owned(),
            "0196ea23-b506-73c8-8153-213383fdc24a".to_owned(),
        ];
        for selection in [None, Some(V2)] {
            let input = body(selection, REFS);
            match decode_begin_thread_run_body(input.as_bytes()).unwrap() {
                DecodedBeginThreadRunBody::Legacy(value) => {
                    assert!(selection.is_none());
                    assert_eq!(value.artifact_refs, expected);
                }
                DecodedBeginThreadRunBody::V2(value) => {
                    assert!(selection.is_some());
                    assert_eq!(value.artifact_refs, expected);
                    assert_eq!(value.model_selection.model_id(), "model");
                }
            }
        }
    }

    #[test]
    fn artifact_refs_duplicate_key_and_escaped_alias_stay_malformed() {
        for selection in [None, Some(V2)] {
            let input = body(selection, REFS);
            let prefix = input.strip_suffix('}').unwrap();
            for duplicate in [
                format!(r#"{prefix},"artifactRefs":[]}}"#),
                format!(r#"{prefix},"artifact\u0052efs":[]}}"#),
            ] {
                assert_eq!(
                    decode_begin_thread_run_body(duplicate.as_bytes()),
                    Err(BeginThreadRunDecodeError::MalformedBody)
                );
            }
        }
    }

    #[test]
    fn artifact_refs_wrong_json_shape_and_unknown_key_stay_malformed() {
        for selection in [None, Some(V2)] {
            for refs in ["null", r#""not-an-array""#, "[null]", "[1]", "{}"] {
                let input = body(selection, refs);
                assert_eq!(
                    decode_begin_thread_run_body(input.as_bytes()),
                    Err(BeginThreadRunDecodeError::MalformedBody)
                );
            }
            let input = body(selection, REFS);
            let prefix = input.strip_suffix('}').unwrap();
            let unknown = format!(r#"{prefix},"artifactRef":[]}}"#);
            assert_eq!(
                decode_begin_thread_run_body(unknown.as_bytes()),
                Err(BeginThreadRunDecodeError::MalformedBody)
            );
        }
    }

    #[test]
    fn artifact_refs_preserve_original_v2_selection_lexeme_budget() {
        let padding = " ".repeat(MAX_MODEL_SELECTION_JSON_BYTES - V2.len());
        let exact = format!("{padding}{V2}");
        let input = body(Some(&exact), REFS);
        let DecodedBeginThreadRunBody::V2(value) =
            decode_begin_thread_run_body(input.as_bytes()).unwrap()
        else {
            panic!("original v2 selection must remain v2");
        };
        assert_eq!(value.model_selection.model_id(), "model");
        let oversized = format!(" {exact}");
        let input = body(Some(&oversized), REFS);
        assert_eq!(
            decode_begin_thread_run_body(input.as_bytes()),
            Err(BeginThreadRunDecodeError::ModelSelectionTooLarge)
        );
    }

    #[test]
    fn artifact_refs_omitted_in_original_legacy_sequence_defaults_empty() {
        let input = br#"[null,"run-1","bot-1",{"kind":"direct_bot"},"unchanged",[]]"#;
        let DecodedBeginThreadRunBody::Legacy(value) = decode_begin_thread_run_body(input).unwrap()
        else {
            panic!("original sequence must remain legacy");
        };
        assert!(value.artifact_refs.is_empty());
    }
}
