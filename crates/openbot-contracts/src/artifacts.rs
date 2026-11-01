//! R414 成果的固定预算、封闭取值与纯文本形状校验。
//!
//! 本模块不创建成果身份、不访问存储、不核当前 actor 权限。合法的身份、摘要或
//! [`ArtifactStatus::Available`] 取值都不能证明实际字节存在或当前可读；这些事实
//! 必须由后续存储、持久化和授权编排核验。预算是冻结上限，宿主只能收紧。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};

/// R424 explicit save of a selected real user message; selectors are not authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SaveRunMessageTextArtifact {
    /// UUIDv7 request locator, canonicalized before durable admission.
    pub request_id: String,
    /// Exact current source Thread.
    pub source_thread_id: ThreadId,
    /// Exact current source Run owned by the authenticated actor.
    pub source_run_id: RunId,
    /// Exact user message within both source selectors.
    pub source_message_id: String,
    /// Expected digest of the exact logical UTF-8 text, never supplied content.
    pub expected_sha256: String,
}

/// Observe an existing positive explicit-save receipt; a request locator is not authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetArtifactSaveReceipt {
    /// Original UUIDv7 request locator, canonicalized without creating a new save operation.
    pub request_id: String,
}

/// Closed metadata selector; an ID cannot grant visibility or byte access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetArtifactMetadata {
    /// Standard UUIDv7 artifact selector.
    pub artifact_id: String,
}

/// Exact source selectors for a current IDs-only observation; neither selector grants access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetSourceRunArtifactIds {
    /// Original opaque source Thread, preserved without normalization.
    pub source_thread_id: ThreadId,
    /// Original opaque source Run, preserved without normalization.
    pub source_run_id: RunId,
}

/// Bounded materialized identities from one current source observation, without byte claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceRunArtifactIds {
    /// The exact observed source Thread.
    pub source_thread_id: ThreadId,
    /// The exact observed source Run.
    pub source_run_id: RunId,
    /// At most 32 unique canonical UUIDv7 identities, in ascending byte order.
    pub artifact_ids: Vec<String>,
}

/// R424 positive local registration fact; no content or current byte/permission proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRegistrationReceipt {
    /// Rust-issued stable operation UUIDv7.
    pub operation_id: String,
    /// Rust-issued artifact UUIDv7.
    pub artifact_id: String,
    /// Canonical request UUIDv7 bound to this operation.
    pub request_id: String,
    /// The original saving owner, not a transferable authority.
    pub owner_actor_id: ActorId,
    /// Original source Thread.
    pub source_thread_id: ThreadId,
    /// Original source Run.
    pub source_run_id: RunId,
    /// Original source message.
    pub source_message_id: String,
    /// Tool provenance when present; null for the R424 user producer.
    pub source_call_seq: Option<u64>,
    /// Paired tool attempt provenance; null for the R424 user producer.
    pub source_attempt_seq: Option<u64>,
}

/// Descriptive workspace, resolved from PG; never accepted as save authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactWorkspace {
    /// Channel anchor workspace.
    Channel {
        /// Exact opaque anchor identity.
        id: String,
    },
    /// Direct conversation workspace.
    Thread {
        /// Exact Thread identity, never its Bot anchor.
        id: String,
    },
}

/// Complete live R414 record facts; byte fields describe actual observations, not estimates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRecordMetadata {
    /// Rust-issued artifact UUIDv7.
    pub artifact_id: String,
    /// Trusted deployment.
    pub deployment_id: DeploymentId,
    /// Trusted tenant namespace.
    pub tenant_id: TenantId,
    /// Registry dataset identity.
    pub dataset_id: String,
    /// Original owner.
    pub owner_actor_id: ActorId,
    /// Exact PG-resolved workspace.
    pub workspace: ArtifactWorkspace,
    /// Original source Thread.
    pub source_thread_id: ThreadId,
    /// Original source Run.
    pub source_run_id: RunId,
    /// Paired source call sequence, if tool-produced.
    pub source_call_seq: Option<u64>,
    /// Paired source attempt sequence, if tool-produced.
    pub source_attempt_seq: Option<u64>,
    /// Actual producer's media type.
    pub media_type: String,
    /// Actual observed byte length, including a real zero-length failed object.
    pub byte_length: u64,
    /// Actual full-object lowercase SHA-256.
    pub sha256: String,
    /// Frozen retention class.
    pub retention_class: ArtifactRetentionClass,
    /// Present only for an explicitly saved artifact.
    pub saved_by: Option<ActorId>,
    /// PG saving time, paired with saved_by.
    #[serde(with = "time::serde::rfc3339::option")]
    pub saved_at: Option<OffsetDateTime>,
}

/// Erased record/operation evidence: only the R424 allowed identities and sequences remain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactTombstone {
    /// Original artifact UUIDv7.
    pub artifact_id: String,
    /// Original operation UUIDv7.
    pub operation_id: String,
    /// Occupied request locator; never used to reconstruct erased content.
    pub request_id: String,
    /// Original owner identity.
    pub owner_actor_id: ActorId,
    /// Original source Thread.
    pub source_thread_id: ThreadId,
    /// Original source Run.
    pub source_run_id: RunId,
    /// Original source message.
    pub source_message_id: String,
    /// Original source call sequence.
    pub source_call_seq: Option<u64>,
    /// Original source attempt sequence.
    pub source_attempt_seq: Option<u64>,
}

/// Status-tagged record shapes; erased states cannot accidentally contain live byte fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ArtifactMetadata {
    /// A registered object; current bytes and authority still require independent checks.
    Available(ArtifactRecordMetadata),
    /// An actually observed failed object, with accurate byte facts.
    FailedPartial(ArtifactRecordMetadata),
    /// Erased state, exposed through the closed 410 application error.
    Deleted(ArtifactTombstone),
    /// Expired state, exposed through the closed 410 application error.
    Expired(ArtifactTombstone),
}

/// Sanitized gone status; arbitrary record states cannot be projected as 410.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactGoneStatus {
    /// Deleted artifact.
    Deleted,
    /// Expired artifact.
    Expired,
}

impl ArtifactGoneStatus {
    /// Closed wire/storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::Expired => "expired",
        }
    }
}

impl core::fmt::Display for ArtifactGoneStatus {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How far one deletion call of an explicitly saved artifact got. `Deleted` means the stored
/// object is durably absent and the record is a tombstone; neither state claims erasure of
/// database WAL, backups or any copy outside this artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactDeletionState {
    /// The deletion is armed; resending the same deletion resumes the rest.
    Pending,
    /// The bytes are absent, the record is a tombstone and its charge was refunded once.
    Deleted,
}

/// The fixed disclosure of every deletion receipt: artifact text already injected into Run
/// history is not removed with the artifact. It is cleared only when the history of the Thread
/// it was injected into is cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactInjectedCopies {
    /// Injected copies remain until their own Thread history is cleared.
    RetainedUntilThreadHistoryClear,
}

/// Progress of one deletion of an explicitly saved artifact by its saving owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactDeletionReceipt {
    /// Canonical lowercase UUIDv7 artifact id.
    pub artifact_id: String,
    /// Progress of this call, not a later state.
    pub state: ArtifactDeletionState,
    /// Always given, whatever the state.
    pub injected_copies: ArtifactInjectedCopies,
}

/// R414 单成果冻结大小上限：64 MiB。
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
/// R414 单个读取块冻结大小上限：4 MiB。
pub const MAX_ARTIFACT_READ_CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// R414 每个 Run 的成果数量上限。
pub const MAX_RUN_ARTIFACTS: u64 = 32;
/// R414 每个 workspace 的成果字节总量上限：16 GiB。
pub const MAX_WORKSPACE_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// R414 一次性读取句柄的有效时长：600 秒；本常量不创建或验证句柄。
pub const ARTIFACT_READ_HANDLE_SECONDS: u64 = 600;
/// R414 单次后续工作引用的成果数量上限；重复成果须由领域校验拒绝。
pub const MAX_ARTIFACT_REFS: usize = 8;
/// R414 注入为不可信用户材料的单份文本字节上限：256 KiB。
pub const MAX_ARTIFACT_TEXT_BYTES: usize = 256 * 1024;
/// R414 注入为不可信用户材料的文本字节总量上限：1 MiB。
pub const MAX_ARTIFACT_TOTAL_TEXT_BYTES: usize = 1024 * 1024;
/// R414 opaque 身份文本的 UTF-8 字节上限；不包括任何 UUID 类型的另行形状约束。
pub const MAX_ARTIFACT_IDENTITY_BYTES: usize = 512;

/// R414 成果保留类别的封闭取值；类别本身不证明保存已获授权或提交。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRetentionClass {
    /// 随所属 Run 历史保留合同处理的临时输出。
    RunOutput,
    /// 用户显式保存、保留至用户删除的成果。
    ExplicitSaved,
}

/// R414 成果记录状态的封闭取值；不作为实际可取字节或当前读取权的证据。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    /// 记录的可用状态；读取仍须重核实际存储对象和当前权限。
    Available,
    /// 未形成完整成果的失败状态，不发布可取链接。
    FailedPartial,
    /// 已删除，只保留合同允许的最小 tombstone。
    Deleted,
    /// 已到期，只保留合同允许的最小 tombstone。
    Expired,
}

/// 校验 opaque 身份的 1–512 UTF-8 字节与无 Unicode 控制字符规则。
///
/// 不修剪或规范化文本，不把 actor、Run 等 opaque 身份强制限定为 UUID，
/// 也不证明身份属于当前 deployment、workspace 或 actor。
#[must_use]
pub fn is_valid_artifact_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ARTIFACT_IDENTITY_BYTES
        && !value.chars().any(char::is_control)
}

/// 校验标准 8-4-4-4-12 UUIDv7 文本形状与 RFC 变体位。
///
/// 接受合法大小写十六进制字符，不修剪或改写原文本。不接受紧凑、URN 或括号形式；
/// 本校验不铸造 UUID，不证明身份来自 Rust 生产者或具有成果读取权。
#[must_use]
pub fn is_uuid_v7_artifact_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    bytes[14] == b'7' && matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
}

/// Parse standard UUIDv7 bytes and return its canonical lowercase hyphenated identity.
///
/// Case aliases identify one durable locator. Opaque source IDs are never passed here.
#[must_use]
pub fn canonical_artifact_uuid_v7(value: &str) -> Option<String> {
    if !is_uuid_v7_artifact_id(value) {
        return None;
    }
    let mut parsed = [0_u8; 16];
    let mut digits = value.bytes().filter(|byte| *byte != b'-');
    for byte in &mut parsed {
        let high = char::from(digits.next()?).to_digit(16)?;
        let low = char::from(digits.next()?).to_digit(16)?;
        *byte = u8::try_from(high * 16 + low).ok()?;
    }
    let hex = b"0123456789abcdef";
    let mut canonical = String::with_capacity(36);
    for (index, byte) in parsed.into_iter().enumerate() {
        if [4, 6, 8, 10].contains(&index) {
            canonical.push('-');
        }
        canonical.push(char::from(hex[usize::from(byte >> 4)]));
        canonical.push(char::from(hex[usize::from(byte & 15)]));
    }
    Some(canonical)
}

/// 校验恰好 64 个 ASCII 小写十六进制字符的 SHA-256 文本。
///
/// 不修剪、不折叠大小写；形状合法不表示摘要与实际字节一致。
#[must_use]
pub fn is_valid_artifact_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt_example() -> ArtifactRegistrationReceipt {
        ArtifactRegistrationReceipt {
            operation_id: "019a0300-0000-7000-8000-000000000001".into(),
            artifact_id: "019a0300-0000-7000-8000-000000000002".into(),
            request_id: "019a0300-0000-7000-8000-000000000003".into(),
            owner_actor_id: ActorId::new("actor"),
            source_thread_id: ThreadId::new("source-thread"),
            source_run_id: RunId::new("来源/opaque"),
            source_message_id: String::from("message"),
            source_call_seq: None,
            source_attempt_seq: None,
        }
    }

    #[test]
    fn save_and_metadata_selectors_have_exact_closed_camel_case_fields() {
        let input = SaveRunMessageTextArtifact {
            request_id: receipt_example().request_id,
            source_thread_id: ThreadId::new("thread"),
            source_run_id: RunId::new("来源/opaque"),
            source_message_id: String::from("message"),
            expected_sha256: "a".repeat(64),
        };
        let value = serde_json::to_value(&input).unwrap();
        let keys: std::collections::BTreeSet<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "requestId",
                "sourceThreadId",
                "sourceRunId",
                "sourceMessageId",
                "expectedSha256"
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            serde_json::from_value::<SaveRunMessageTextArtifact>(value.clone()).unwrap(),
            input
        );
        for key in [
            "body",
            "path",
            "ownerActorId",
            "datasetId",
            "workspace",
            "sourceCallSeq",
            "method",
        ] {
            let mut extra = value.clone();
            extra[key] = serde_json::json!("caller");
            assert!(
                serde_json::from_value::<SaveRunMessageTextArtifact>(extra).is_err(),
                "{key}"
            );
        }
        let selector = serde_json::json!({"artifactId":receipt_example().artifact_id});
        assert!(serde_json::from_value::<GetArtifactMetadata>(selector.clone()).is_ok());
        let mut extra = selector;
        extra["path"] = serde_json::json!("caller");
        assert!(serde_json::from_value::<GetArtifactMetadata>(extra).is_err());
    }

    #[test]
    fn positive_receipt_serializes_only_frozen_ids_and_null_sequences() {
        let receipt = receipt_example();
        let value = serde_json::to_value(&receipt).unwrap();
        let keys: std::collections::BTreeSet<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "operationId",
                "artifactId",
                "requestId",
                "ownerActorId",
                "sourceThreadId",
                "sourceRunId",
                "sourceMessageId",
                "sourceCallSeq",
                "sourceAttemptSeq"
            ]
            .into_iter()
            .collect()
        );
        assert!(value["sourceCallSeq"].is_null());
        assert!(value["sourceAttemptSeq"].is_null());
        for forbidden in [
            "sha256",
            "byteLength",
            "mediaType",
            "savedAt",
            "status",
            "replayed",
            "body",
            "path",
        ] {
            let mut extra = value.clone();
            extra[forbidden] = serde_json::json!("untrusted");
            assert!(serde_json::from_value::<ArtifactRegistrationReceipt>(extra).is_err());
        }
    }

    #[test]
    fn closed_commands_and_receipt_reply_roundtrip_through_registered_enum_tags() {
        use crate::command::{AppCommand, AppReply};
        let source = receipt_example();
        for command in [
            AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                request_id: source.request_id.clone(),
                source_thread_id: source.source_thread_id.clone(),
                source_run_id: source.source_run_id.clone(),
                source_message_id: source.source_message_id.clone(),
                expected_sha256: "a".repeat(64),
            }),
            AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                artifact_id: source.artifact_id.clone(),
            }),
        ] {
            let value = serde_json::to_value(&command).unwrap();
            assert_eq!(
                serde_json::from_value::<AppCommand>(value).unwrap(),
                command
            );
        }
        let reply = AppReply::ArtifactRegistrationReceipt(source);
        let value = serde_json::to_value(&reply).unwrap();
        assert_eq!(value["kind"], "artifact_registration_receipt");
        assert_eq!(serde_json::from_value::<AppReply>(value).unwrap(), reply);
    }

    #[test]
    fn live_and_tombstone_shapes_cannot_exchange_byte_fields() {
        let receipt = receipt_example();
        let tombstone = ArtifactTombstone {
            artifact_id: receipt.artifact_id.clone(),
            operation_id: receipt.operation_id,
            request_id: receipt.request_id,
            owner_actor_id: receipt.owner_actor_id.clone(),
            source_thread_id: receipt.source_thread_id.clone(),
            source_run_id: receipt.source_run_id.clone(),
            source_message_id: receipt.source_message_id,
            source_call_seq: None,
            source_attempt_seq: None,
        };
        let gone = serde_json::to_value(ArtifactMetadata::Deleted(tombstone)).unwrap();
        assert_eq!(gone["status"], "deleted");
        for key in ["sha256", "byteLength", "mediaType", "savedAt"] {
            let mut extra = gone.clone();
            extra[key] = serde_json::json!("forbidden");
            assert!(serde_json::from_value::<ArtifactMetadata>(extra).is_err());
        }
        let live = ArtifactMetadata::FailedPartial(ArtifactRecordMetadata {
            artifact_id: receipt.artifact_id,
            deployment_id: DeploymentId::new("deployment"),
            tenant_id: TenantId::new("tenant"),
            dataset_id: "dataset".into(),
            owner_actor_id: receipt.owner_actor_id.clone(),
            workspace: ArtifactWorkspace::Thread {
                id: "source-thread".into(),
            },
            source_thread_id: receipt.source_thread_id,
            source_run_id: receipt.source_run_id,
            source_call_seq: None,
            source_attempt_seq: None,
            media_type: "text/plain; charset=utf-8".into(),
            byte_length: 0,
            sha256: "a".repeat(64),
            retention_class: ArtifactRetentionClass::ExplicitSaved,
            saved_by: Some(receipt.owner_actor_id),
            saved_at: Some(OffsetDateTime::UNIX_EPOCH),
        });
        let mut value = serde_json::to_value(&live).unwrap();
        assert_eq!(value["status"], "failed_partial");
        assert_eq!(
            serde_json::from_value::<ArtifactMetadata>(value.clone()).unwrap(),
            live
        );
        value["sha256"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ArtifactMetadata>(value).is_err());
    }

    #[test]
    fn uuid_v7_case_aliases_parse_to_one_canonical_locator() {
        let lower = "019a0300-abcd-7def-8abc-123456abcdef";
        assert_eq!(canonical_artifact_uuid_v7(lower), Some(lower.into()));
        assert_eq!(
            canonical_artifact_uuid_v7(&lower.to_uppercase()),
            Some(lower.into())
        );
        for invalid in [
            lower.replace('-', ""),
            format!(" {lower}"),
            format!("urn:uuid:{lower}"),
            lower.replacen("7def", "4def", 1),
        ] {
            assert!(canonical_artifact_uuid_v7(&invalid).is_none());
        }
    }

    #[test]
    fn frozen_storage_and_injection_budgets_match_r414_exactly() {
        assert_eq!(MAX_ARTIFACT_BYTES, 67_108_864);
        assert_eq!(MAX_ARTIFACT_READ_CHUNK_BYTES, 4_194_304);
        assert_eq!(MAX_RUN_ARTIFACTS, 32);
        assert_eq!(MAX_WORKSPACE_ARTIFACT_BYTES, 17_179_869_184);
        assert_eq!(ARTIFACT_READ_HANDLE_SECONDS, 600);
        assert_eq!(MAX_ARTIFACT_REFS, 8);
        assert_eq!(MAX_ARTIFACT_TEXT_BYTES, 262_144);
        assert_eq!(MAX_ARTIFACT_TOTAL_TEXT_BYTES, 1_048_576);
        assert_eq!(MAX_ARTIFACT_IDENTITY_BYTES, 512);
    }

    #[test]
    fn opaque_identity_bounds_use_utf8_bytes_including_the_inclusive_ceiling() {
        assert!(!is_valid_artifact_identity(""));
        for length in [1, 511, 512] {
            assert!(is_valid_artifact_identity(&"a".repeat(length)));
        }
        assert!(!is_valid_artifact_identity(&"a".repeat(513)));
        let chinese_boundary = format!("{}ab", "中".repeat(170));
        assert_eq!(chinese_boundary.len(), 512);
        assert!(is_valid_artifact_identity(&chinese_boundary));
        assert!(!is_valid_artifact_identity(&(chinese_boundary + "c")));
        let emoji_boundary = "😀".repeat(128);
        assert_eq!(emoji_boundary.len(), 512);
        assert_eq!(emoji_boundary.chars().count(), 128);
        assert!(is_valid_artifact_identity(&emoji_boundary));
        assert!(!is_valid_artifact_identity(&(emoji_boundary + "a")));
    }

    #[test]
    fn identities_reject_c0_del_and_unicode_c1_controls_in_every_position() {
        for code in (0..=0x1f).chain(0x7f..=0x9f) {
            let control = char::from_u32(code).unwrap();
            for value in [
                format!("{control}actor"),
                format!("act{control}or"),
                format!("actor{control}"),
            ] {
                assert!(!is_valid_artifact_identity(&value), "control U+{code:04X}");
            }
        }
    }

    #[test]
    fn opaque_actor_and_run_ids_remain_non_uuid_and_unmodified_text_values() {
        for value in [
            "actor:alice",
            "old/run-opaque",
            " run with spaces ",
            " ",
            "中😀",
            "é",
            "e\u{301}",
        ] {
            assert!(is_valid_artifact_identity(value));
            assert!(!is_uuid_v7_artifact_id(value));
        }
        // A format character is not a Unicode control character; the identity rule
        // does not introduce an additional normalization or format-character ban.
        assert!(is_valid_artifact_identity("emoji\u{200d}sequence"));
    }

    #[test]
    fn digest_shape_accepts_all_lowercase_hex_without_claiming_matching_bytes() {
        for value in ["0".repeat(64), "f".repeat(64), "09af".repeat(16)] {
            assert!(is_valid_artifact_sha256(&value));
        }
        // Both are syntactically valid even though they cannot both identify the
        // same content: equality to actual bytes belongs to the byte store.
        assert!(is_valid_artifact_sha256(&"0".repeat(64)));
        assert!(is_valid_artifact_sha256(&"1".repeat(64)));
    }

    #[test]
    fn digest_shape_rejects_length_aliases_and_does_not_trim_or_case_fold() {
        for value in [
            "".to_owned(),
            "a".repeat(63),
            "a".repeat(65),
            format!("0x{}", "a".repeat(64)),
            format!(" {}", "a".repeat(64)),
            format!("{} ", "a".repeat(64)),
            "A".repeat(64),
        ] {
            assert!(!is_valid_artifact_sha256(&value));
        }
    }

    #[test]
    fn digest_shape_rejects_non_ascii_and_non_hex_at_the_exact_byte_length() {
        for invalid in ['A', 'F', 'g', '-', ' ', '\n', '\0'] {
            let mut value = "a".repeat(64);
            value.replace_range(31..32, &invalid.to_string());
            assert_eq!(value.len(), 64);
            assert!(!is_valid_artifact_sha256(&value));
        }
        let lookalike = format!("{}a", "０".repeat(21));
        assert_eq!(lookalike.len(), 64);
        assert!(!is_valid_artifact_sha256(&lookalike));
        assert!(!is_valid_artifact_sha256(&"０".repeat(64)));
    }

    #[test]
    fn uuid_v7_text_accepts_mixed_hex_case_and_all_rfc_variant_nibbles() {
        for variant in ['8', '9', 'a', 'A', 'b', 'B'] {
            let value = format!("01890f3a-5B42-7aBc-{variant}123-012345aBcDef");
            assert!(is_uuid_v7_artifact_id(&value));
        }
    }

    #[test]
    fn uuid_v7_text_rejects_other_versions_nil_and_non_rfc_variants() {
        for value in [
            "00000000-0000-0000-0000-000000000000",
            "01890f3a-5b42-4abc-8123-012345abcdef",
            "01890f3a-5b42-8abc-8123-012345abcdef",
        ] {
            assert!(!is_uuid_v7_artifact_id(value));
        }
        for variant in [
            '0', '1', '2', '3', '4', '5', '6', '7', 'c', 'C', 'd', 'D', 'e', 'E', 'f', 'F',
        ] {
            let value = format!("01890f3a-5b42-7abc-{variant}123-012345abcdef");
            assert!(!is_uuid_v7_artifact_id(&value));
        }
    }

    #[test]
    fn uuid_v7_text_rejects_non_standard_shapes_without_normalizing_them() {
        let valid = "01890f3a-5b42-7abc-8123-012345abcdef";
        for value in [
            "".to_owned(),
            valid.replace('-', ""),
            format!("urn:uuid:{valid}"),
            format!("{{{valid}}}"),
            format!(" {valid}"),
            format!("{valid} "),
            valid.replace("5b42", "5b4g"),
            valid.replacen('-', "f", 1),
            valid.replacen("5b42", "-b42", 1),
        ] {
            assert!(!is_uuid_v7_artifact_id(&value));
        }
        let non_ascii = valid.replacen("018", "中", 1);
        assert_eq!(non_ascii.len(), 36);
        assert!(!is_uuid_v7_artifact_id(&non_ascii));
    }

    #[test]
    fn retention_classes_roundtrip_with_only_the_two_registered_names() {
        for (value, text) in [
            (ArtifactRetentionClass::RunOutput, "run_output"),
            (ArtifactRetentionClass::ExplicitSaved, "explicit_saved"),
        ] {
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(text)
            );
            assert_eq!(
                serde_json::from_value::<ArtifactRetentionClass>(serde_json::json!(text)).unwrap(),
                value
            );
        }
        for text in [
            "",
            "RunOutput",
            "runOutput",
            "run_output ",
            "saved",
            "permanent",
        ] {
            assert!(
                serde_json::from_value::<ArtifactRetentionClass>(serde_json::json!(text)).is_err()
            );
        }
    }

    #[test]
    fn artifact_statuses_roundtrip_with_only_the_four_registered_names() {
        for (value, text) in [
            (ArtifactStatus::Available, "available"),
            (ArtifactStatus::FailedPartial, "failed_partial"),
            (ArtifactStatus::Deleted, "deleted"),
            (ArtifactStatus::Expired, "expired"),
        ] {
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(text)
            );
            assert_eq!(
                serde_json::from_value::<ArtifactStatus>(serde_json::json!(text)).unwrap(),
                value
            );
        }
        for text in [
            "",
            "Available",
            "failedPartial",
            "available ",
            "ready",
            "staging",
            "verified",
            "committed",
        ] {
            assert!(serde_json::from_value::<ArtifactStatus>(serde_json::json!(text)).is_err());
        }
    }

    #[test]
    fn enum_values_do_not_decode_as_actor_or_storage_proof_records() {
        for proof in [
            serde_json::json!({"status":"available", "actor":"alice"}),
            serde_json::json!({"available":{"sha256":"0".repeat(64), "path":"/untrusted"}}),
            serde_json::json!({"available":null,"verified":true}),
        ] {
            assert!(serde_json::from_value::<ArtifactStatus>(proof).is_err());
        }
        assert!(
            serde_json::from_value::<ArtifactRetentionClass>(
                serde_json::json!({"retention_class":"explicit_saved", "saved_by":"alice"})
            )
            .is_err()
        );
        // The plain enum value remains decodable without actor or storage context.
        // It therefore conveys only its closed value, never an authorization proof.
        assert_eq!(
            serde_json::from_value::<ArtifactStatus>(serde_json::json!("available")).unwrap(),
            ArtifactStatus::Available
        );
    }
}
