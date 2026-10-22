//! 备份材料清单与恢复计划的纯领域核（§14.4 / R235 / V5-BACKUP-01 基础子项）。
//!
//! # 范围
//!
//! 本模块只做**结构/材料核验**和**恢复计划**：给定未核清单、受控目标条件与实际观察，
//! 判定材料集合是否自洽，并产出 [`plan::RestoreOutcome`]。它不读文件、时钟、随机数、
//! 环境或数据库。实际字节观察由 infra / 未来可信恢复 owner 提供。
//!
//! 名称与结果故意停在 [`inventory::InventoryChecked`] / [`plan::StructuralRestorePlan`]：
//! 摘要相符不是 AEAD/来源真实性证明，WAL 文件名齐全不是 PostgreSQL recovery 证明。
//! 这些独立验证未完成时，计划**不能**输出 Ready / RestoreAuthorized，也不能开放
//! Application。恢复后的旧授权失效与历史保留由 [`post_restore`] 继续细化为逐对象计划，
//! 仍然不授予 RestoreAuthorized，也不签发 recovery epoch。
//!
//! # 本批明确不做
//!
//! - 冻结对外 backup wire / archive / crypto 格式（合成 JSON 只作 test-only fixture）。
//! - 签发 recovery epoch、写库、生成密钥、恢复 dispatch、重放工具。
//! - 把同机目录复制称为完整恢复。
//! - 关闭 V5-BACKUP-01 的真实加密恢复、V5-UPGRADE-01 或 A6 真机演练。
//!
//! V6-PR-037 另增 [`recovery_wrap`]：复用 Vault AES-256-GCM 包装有界恢复元数据。
//! V6-PR-038 另增 [`recovery_chunks`]：分块 AAD 绑定序号/总长/清单摘要。
//! 二者仍不是 archive / RestoreAuthorized / A6。

pub mod inventory;
pub mod plan;
pub mod post_restore;
pub mod recovery_chunks;
pub mod recovery_wrap;
/// Independent complete-PG capture format and bounded in-place AEAD; no source/restore authority.
pub mod whole_pg_carrier;

#[cfg(test)]
mod tests;

pub use inventory::{
    AuditCheckpointClaim, BackupInventoryClaim, BarrierIdentity, BundleIdentity, CheckedMaterial,
    CheckedReceipts, CompatibilitySet, ComponentRev, DatasetIdentity, EmptyCategoryClaim,
    EmptyReason, InstallationIdentity, InventoryBounds, InventoryChecked, InventoryFault,
    KeyBindingClaim, MaterialClaim, MaterialId, MaterialKind, ReceiptClaim, ReceiptSetClaim,
    RelativePath, ScramRelationClaim, VaultKeyRefClaim, WrappingRefClaim,
};
pub use plan::{
    BlockedReason, BlockedRestore, CapacityObservation, CapacityPolicy, ControlledRestoreTarget,
    FollowUpRequirements, IdentityBinding, IncompleteReason, IncompleteRestore, PendingProofs,
    ProofStatus, RestoreMode, RestoreObservations, RestoreOutcome, RestoreRequest,
    StructuralRestorePlan, plan_restore,
};
pub use post_restore::{
    AuthMaterialKind, AuthObjectClaim, CategoryRule, GlobalObligations, HistoricalDecryptRef,
    ObjectDisposition, ObjectDispositionKind, PostRestoreBounds, PostRestoreFault, PostRestorePlan,
    PostRestoreRequest, ReceiptClass, ReceiptRetention, RecoveryEpochDerivation,
    RecoveryEpochObligation, plan_post_restore,
};
pub use recovery_chunks::{
    BackupRecoveryChunkEnvelope, BackupRecoveryChunkSpec, BackupRecoveryChunkStream,
    open_backup_recovery_chunk, seal_backup_recovery_chunk,
};
pub use recovery_wrap::{
    BackupRecoveryBinding, BackupRecoveryEnvelope, open_backup_recovery_wrap,
    seal_backup_recovery_wrap,
};

pub use whole_pg_carrier::{
    FrozenWholePgManifest, WholePgBarrierClaim, WholePgCarrierBounds, WholePgCarrierFault,
    WholePgCoverageClaim, WholePgFrameParts, WholePgFrameSpec, WholePgManifestClaim,
    WholePgMaterialClaim, WholePgMaterialKind, WholePgOpenCodec, WholePgPresence,
    WholePgProvenanceClaim, WholePgSealCodec, WholePgSecretBounds, WholePgSecretClassBounds,
    WholePgSecretClasses, WholePgSourceClaim, whole_pg_secret_matches,
};
