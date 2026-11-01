//! 备份材料的流式校验与隔离暂存（§14.4 / R235 基础子项）。
//!
//! 消费 domain 已核结构与受控输入端口，把合成数据流写入**本次新建**的私有 staging。
//! 摘要完整性不是 AEAD 真实性；本模块不授予恢复切换或 Application Ready。
//!
//! 不调用 pg_ctl / initdb / SQL / 模型 / 工具，不导入或轮换密钥，不原子切换，
//! 不启动恢复后的应用。完整加密恢复、签名升级和 A6 真机演练仍归后续 owner。
//!
//! # 已知 OS 限制（交主控）
//!
//! - 创建/删除/sync 由 [`staging::FsPort`] 在**同一次操作**里核父目录与条目身份，
//!   不再先核身份再把可重解析路径交给另一调用。身份字段私有，外部不能自报
//!   dev/ino 铸造“已证明”。
//! - 稳定 Rust 无 `openat`/`unlinkat` 安全封装。StdFs 在身份核验与 syscall 之间
//!   仍有 TOCTOU；无法证明时拒绝该次操作并报告残留，不沿已替换祖先删除。
//!   该窄 OS 边界交主控，不把本批称为原子 path-bind 已完成。
//! - Unix 用 `O_NOFOLLOW`、`nlink==1` 与句柄 metadata；Windows stable 1.98 不暴露
//!   nlink，遇 reparse 或缺少 file index 即 [`StagingFault::OsBindingUnprovable`]。
//! - 完成回执只证明确认时点的输出；后续 owner 接收前必须重新核验。
//! - 可用容量来自调用方观察，不是 OS 配额预留。

pub mod archive_bundle;
pub mod checked_fs;
pub mod staging;
/// Original-owner bounded whole-PG carrier transport, separate from legacy archive/staging.
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub mod whole_pg_capture_stream;

#[cfg(test)]
mod tests;

/// 结构化失败分类。不回显路径或 I/O 原文。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagingFault {
    /// 预检拒绝。
    PrecheckRejected,
    /// 输入不是结构计划。
    PlanNotStructural,
    /// 目标 slot 已存在。
    StagingExists,
    /// 父目录不安全（符号链接/非目录）。
    ParentUnsafe,
    /// 相对路径非法。
    PathInvalid,
    /// 清单未登记或源中多出条目。
    UnregisteredEntry,
    /// 单块超过 4MiB 或配置上限。
    ChunkTooLarge,
    /// 块序号重排。
    Reordered,
    /// 终态后仍有数据。
    ExtraTail,
    /// 缺终态块。
    MissingTerminal,
    /// 短读。
    ShortRead,
    /// 实际长度超过声明。
    LengthExceeded,
    /// 摘要不符。
    DigestMismatch,
    /// 读取中来源被替换。
    SourceReplaced,
    /// 写入中目的地被替换。
    DestinationReplaced,
    /// 打开失败。
    OpenFailed,
    /// 写失败。
    WriteFailed,
    /// sync 失败。
    SyncFailed,
    /// 容量耗尽。
    CapacityExhausted,
    /// 取消。
    Cancelled,
    /// 链接或特殊文件。
    LinkOrSpecialFile,
    /// 无法证明 OS 路径绑定安全。
    OsBindingUnprovable,
    /// 源流在上一块尚未结束时再次拉取。
    ConcurrentChunk,
}

pub use archive_bundle::{
    ArchiveBundleBounds, ArchiveBundleContents, ArchiveBundleFault, UnpackedArchiveBundle,
    read_archive_bundle, unpack_archive_bundle, write_archive_bundle,
};
pub use staging::{
    CancelFlag, Chunk, CleanupReport, EntryStream, FaultInjectingFs, FileTreeSource, FsPort,
    MaterialSource, OwnedDir, OwnedFile, ScriptedSource, SinkWriteError, StagingBounds,
    StagingCompleted, StagingFailure, StagingInput, StagingOutcome, StagingRequest, StdFs,
    run_staging,
};
