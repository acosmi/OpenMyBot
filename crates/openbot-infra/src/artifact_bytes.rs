//! 私有成果字节基础。文件描述符来自可信宿主，不接受业务路径。
//!
//! blob 是预期字节绑定；只有 stage/install/open_verified 各自成功时才证明所核字节。
//! 本层不能代表产品 available 或读取授权。
//! PG 配额/来源/回执、当前 actor 可见性、一次性读取句柄及一致性备份由后续编排负责。
//! 同步磁盘 I/O 必须由宿主在阻塞任务内调用，不占异步执行器线程。
//! 目录写者须是可信宿主；0700 不隔离同 UID 敌对进程或额外 ACL 授权。
//! 描述符/身份复核检测替换，但不声称原子 compare-unlink 或 OS 沙箱证明。

use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
#[cfg(feature = "server-runtime")]
use std::time::Instant;

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
use crate::backup::whole_pg_capture_stream::CaptureClockCheck;
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant};

// Same frozen limits across WASM-safe contracts, domain arithmetic and native byte storage.
pub use openbot_contracts::artifacts::{MAX_ARTIFACT_BYTES, MAX_ARTIFACT_READ_CHUNK_BYTES};
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[cfg(all(test, feature = "server-runtime"))]
#[path = "artifact_bytes/registration_tests.rs"]
mod registration_tests;

#[cfg(feature = "server-runtime")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactByteStorageLocation {
    Staging,
    Object,
}

#[cfg(feature = "server-runtime")]
impl ArtifactByteStorageLocation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Object => "object",
        }
    }
}

#[cfg(feature = "server-runtime")]
pub(crate) enum ArtifactByteProbe {
    Absent,
    Retained {
        location: ArtifactByteStorageLocation,
        byte_length: u64,
        sha256: [u8; 32],
    },
    Indeterminate,
}

/// Original worker-local leaf ownership. No observation here grants current authorization.
#[cfg(feature = "server-runtime")]
pub(crate) struct OriginalArtifactPhysicalObject {
    directories: Arc<StoreDirectories>,
    id: Uuid,
    retained: Option<(File, FileObservation)>,
    // A preflight object must stay inside the blocking worker that owns its original IO guard.
    _worker_local: core::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(feature = "server-runtime")]
impl OriginalArtifactPhysicalObject {
    pub(crate) fn original_leaf_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.retained.as_ref().map(|(file, _)| file.as_raw_fd())
    }
}

#[cfg(feature = "server-runtime")]
pub(crate) enum ArtifactBytePhysicalUnlinkError<E> {
    Bytes(ArtifactByteError),
    Start(E),
}

#[cfg(feature = "server-runtime")]
impl<E> From<ArtifactByteError> for ArtifactBytePhysicalUnlinkError<E> {
    fn from(error: ArtifactByteError) -> Self {
        Self::Bytes(error)
    }
}

/// Trusted inspection cutpoints. `true` from the callback stops the observation; `false`
/// supplies no permission and cannot replace the real deadline or filesystem checks.
#[cfg(feature = "server-runtime")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactProbePhase {
    Entry,
    BeforeHashSegment,
    AfterHashSegment,
    BeforeEofRead,
    AfterEofRead,
    BeforeFileSync,
    AfterFileSync,
    BeforeStagingSync,
    AfterStagingSync,
    BeforeObjectsSync,
    AfterObjectsSync,
    BeforeRootSync,
    AfterRootSync,
    FinalObservation,
}

/// 内部磁盘错误；不携本机路径、正文或底层 OS 错误消息。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactByteError {
    /// 宿主尝试放宽冻结上限或传入非 UUIDv7 身份。
    #[error("invalid artifact byte binding")]
    InvalidBinding,
    /// 声明长度超出宿主允许的单成果大小。
    #[error("artifact byte limit exceeded")]
    TooLarge,
    /// 实际可用磁盘字节不足；本检查不是跨进程配额预留。
    #[error("insufficient artifact storage space")]
    InsufficientSpace,
    /// 输入的实际长度与声明不符。
    #[error("artifact input length mismatch")]
    LengthMismatch,
    /// 输入或已安装对象的真实摘要与绑定不符。
    #[error("artifact content mismatch")]
    ContentMismatch,
    /// 目录/文件不是私有普通对象，或观察期间被替换。
    #[error("unsafe artifact storage object")]
    UnsafeObject,
    /// 不覆写已有目标，包括 symlink 或已有同 ID 文件。
    #[error("artifact storage object already exists")]
    AlreadyExists,
    /// 磁盘 I/O 未完成。不能据此发布链接或自动重放登记。
    #[error("artifact storage operation failed")]
    Io,
    /// 显式清理失败；留下私有孤立对象供后续恢复核查。
    #[error("artifact staging cleanup failed")]
    CleanupFailed,
    /// 读取缓冲必须非空且不超过冻结块大小。
    #[error("invalid artifact read chunk")]
    InvalidChunk,
}

/// 可持久化的内部字节绑定。没有路径或权限事实，不能作为下载凭据。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactBlob {
    id: Uuid,
    byte_length: u64,
    sha256: [u8; 32],
}

impl ArtifactBlob {
    /// 由可信持久化记录恢复绑定；读取时仍重核实际字节。
    pub fn from_record(
        id: Uuid,
        byte_length: u64,
        sha256: [u8; 32],
    ) -> Result<Self, ArtifactByteError> {
        if id.get_version_num() != 7 || id.get_variant() != Variant::RFC4122 {
            return Err(ArtifactByteError::InvalidBinding);
        }
        if byte_length > MAX_ARTIFACT_BYTES {
            return Err(ArtifactByteError::TooLarge);
        }
        Ok(Self {
            id,
            byte_length,
            sha256,
        })
    }

    /// Rust 铸造的 UUIDv7；仅对象定位，不授予权限。
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }
    /// 预期/持久化绑定的字节长度；构造本身没有验证存储。
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
    /// 预期/持久化绑定的 SHA-256；构造本身没有验证存储。
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}
impl Identity {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct StoreDirectories {
    root: File,
    staging: File,
    objects: File,
    owner: u32,
}
impl StoreDirectories {
    fn check_private(&self) -> Result<(), ArtifactByteError> {
        for directory in [&self.root, &self.staging, &self.objects] {
            check_directory(
                &directory.metadata().map_err(|_| ArtifactByteError::Io)?,
                self.owner,
            )?;
        }
        Ok(())
    }

    #[cfg(feature = "server-runtime")]
    fn check_current_children(&self, original_deadline: Instant) -> Result<(), ArtifactByteError> {
        let root = probe_io_before(original_deadline, || {
            self.root.metadata().map_err(|_| ArtifactByteError::Io)
        })?;
        check_directory(&root, self.owner)?;
        for (name, original) in [("staging", &self.staging), ("objects", &self.objects)] {
            let before = probe_io_before(original_deadline, || {
                original.metadata().map_err(|_| ArtifactByteError::Io)
            })?;
            check_directory(&before, self.owner)?;
            if before.dev() != root.dev() {
                return Err(ArtifactByteError::UnsafeObject);
            }
            // Reopen the fixed child through the original root FD, without creating a directory
            // or following a replacement symlink. Held child FDs alone cannot prove this name.
            let current = probe_io_before(original_deadline, || {
                rustix::fs::openat(
                    &self.root,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(map_open_error)
            })?;
            let selected = probe_io_before(original_deadline, || {
                current.metadata().map_err(|_| ArtifactByteError::Io)
            })?;
            check_directory(&selected, self.owner)?;
            if Identity::of(&selected) != Identity::of(&before) || selected.dev() != root.dev() {
                return Err(ArtifactByteError::UnsafeObject);
            }
            let after = probe_io_before(original_deadline, || {
                original.metadata().map_err(|_| ArtifactByteError::Io)
            })?;
            check_directory(&after, self.owner)?;
            if Identity::of(&after) != Identity::of(&before) || after.dev() != root.dev() {
                return Err(ArtifactByteError::UnsafeObject);
            }
        }
        let after = probe_io_before(original_deadline, || {
            self.root.metadata().map_err(|_| ArtifactByteError::Io)
        })?;
        check_directory(&after, self.owner)?;
        if Identity::of(&after) != Identity::of(&root) {
            return Err(ArtifactByteError::UnsafeObject);
        }
        Ok(())
    }
}

/// 描述符绑定的本节点磁盘适配器；不读环境、不打开任何用户业务路径。
pub struct ArtifactByteStore {
    directories: Arc<StoreDirectories>,
    max_byte_length: u64,
}

/// Borrows the original three directory descriptors only inside the frozen snapshot worker.
/// The caller reserves these fixed observation slots before this factory's first effect.
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub(crate) struct ArtifactCaptureDirectoryBorrow<'a> {
    directories: &'a StoreDirectories,
    clock: &'a dyn CaptureClockCheck,
    identities: [Identity; 3],
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
impl ArtifactByteStore {
    pub(crate) fn capture_original_directories_before<'a>(
        &'a self,
        clock: &'a dyn CaptureClockCheck,
    ) -> Result<ArtifactCaptureDirectoryBorrow<'a>, WholePgCarrierFault> {
        // Compile-time qualification of the caller's elementary-field fee.
        const {
            let thin = (std::mem::size_of::<&()>(), std::mem::align_of::<&()>());
            let clock = (std::mem::size_of::<&dyn CaptureClockCheck>(),
                std::mem::align_of::<&dyn CaptureClockCheck>());
            let word = (std::mem::size_of::<u64>(), std::mem::align_of::<u64>());
            let a = if thin.1 > clock.1 { thin.1 } else { clock.1 };
            let a = if a > word.1 { a } else { word.1 };
            let thin = thin.0.checked_add(thin.1 - 1).expect("capture fee overflow");
            let clock = clock.0.checked_add(clock.1 - 1).expect("capture fee overflow");
            let words = word.0.checked_add(word.1 - 1).expect("capture fee overflow")
                .checked_mul(6).expect("capture fee overflow");
            let padding = (a - 1).checked_mul(5).expect("capture fee overflow");
            let upper = thin.checked_add(clock).expect("capture fee overflow")
                .checked_add(words).expect("capture fee overflow")
                .checked_add(padding).expect("capture fee overflow");
            assert!(std::mem::size_of::<ArtifactCaptureDirectoryBorrow<'static>>() <= upper);
        }
        // End these three observations before the second, named/held verification pass.
        // No path open, descriptor duplicate, allocation or new owner is constructed here.
        let identities = {
            let root = capture_directory_metadata_before(&self.directories.root, clock)?;
            let objects = capture_directory_metadata_before(&self.directories.objects, clock)?;
            let staging = capture_directory_metadata_before(&self.directories.staging, clock)?;
            for actual in [&root, &objects, &staging] {
                check_directory(actual, self.directories.owner)
                    .map_err(|_| WholePgCarrierFault::PathUnsafe)?;
                if actual.dev() != root.dev() {
                    return Err(WholePgCarrierFault::SourceChanged);
                }
            }
            [Identity::of(&root), Identity::of(&objects), Identity::of(&staging)]
        };
        let original = ArtifactCaptureDirectoryBorrow {
            directories: &self.directories,
            clock,
            identities,
        };
        original.verify_original_before()?;
        Ok(original)
    }
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
impl ArtifactCaptureDirectoryBorrow<'_> {
    pub(crate) fn original_fds(&self) -> (&File, &File, &File) {
        (&self.directories.root, &self.directories.objects, &self.directories.staging)
    }

    pub(crate) fn verify_original_before(&self) -> Result<(), WholePgCarrierFault> {
        let root_before = capture_directory_metadata_before(&self.directories.root, self.clock)?;
        check_directory(&root_before, self.directories.owner)
            .map_err(|_| WholePgCarrierFault::PathUnsafe)?;
        if Identity::of(&root_before) != self.identities[0] {
            return Err(WholePgCarrierFault::SourceChanged);
        }
        for (name, held, expected) in [
            ("objects", &self.directories.objects, self.identities[1]),
            ("staging", &self.directories.staging, self.identities[2]),
        ] {
            let before = capture_directory_metadata_before(held, self.clock)?;
            check_directory(&before, self.directories.owner)
                .map_err(|_| WholePgCarrierFault::PathUnsafe)?;
            if before.dev() != root_before.dev() || Identity::of(&before) != expected {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            self.clock.require_effect()?;
            let observed = rustix::fs::statat(
                &self.directories.root,
                name,
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|error| match error {
                rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => {
                    WholePgCarrierFault::SourceChanged
                }
                _ => WholePgCarrierFault::IoFailure,
            });
            // Always observe E after an attempted syscall, including Err. The original
            // syscall refusal remains the first fault if this postcheck also refuses.
            let after_effect = self.clock.require_effect();
            let named = observed?;
            after_effect?;
            if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
                || named.st_uid != self.directories.owner
                || u32::from(named.st_mode) & 0o7777 != 0o700
            {
                return Err(WholePgCarrierFault::PathUnsafe);
            }
            if named.st_dev as u64 != before.dev()
                || named.st_ino != before.ino()
                || u64::from(named.st_nlink) != before.nlink()
                || u64::try_from(named.st_size).ok() != Some(before.len())
            {
                return Err(WholePgCarrierFault::SourceChanged);
            }
            let after = capture_directory_metadata_before(held, self.clock)?;
            check_directory(&after, self.directories.owner)
                .map_err(|_| WholePgCarrierFault::PathUnsafe)?;
            if after.dev() != root_before.dev() || Identity::of(&after) != expected {
                return Err(WholePgCarrierFault::SourceChanged);
            }
        }
        let root_after = capture_directory_metadata_before(&self.directories.root, self.clock)?;
        check_directory(&root_after, self.directories.owner)
            .map_err(|_| WholePgCarrierFault::PathUnsafe)?;
        if Identity::of(&root_after) != self.identities[0] {
            return Err(WholePgCarrierFault::SourceChanged);
        }
        self.clock.require_effect()
    }
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
fn capture_directory_metadata_before(
    file: &File,
    clock: &dyn CaptureClockCheck,
) -> Result<Metadata, WholePgCarrierFault> {
    clock.require_effect()?;
    let observed = file.metadata().map_err(|_| WholePgCarrierFault::IoFailure);
    let after_effect = clock.require_effect();
    let metadata = observed?;
    after_effect?;
    Ok(metadata)
}

/// 私有 staging 中已经核长度/摘要并 fsync 的成果；不能发布为 available。
/// 丢弃时尽力清理，调用方需确定清理结果时使用 [`Self::discard`]。
pub struct VerifiedArtifactStage {
    directories: Arc<StoreDirectories>,
    file: File,
    blob: ArtifactBlob,
    armed: bool,
}

impl VerifiedArtifactStage {
    /// 只读取已验证的内部绑定，不能将此事实当成 PG 登记或授权。
    #[must_use]
    pub const fn blob(&self) -> &ArtifactBlob {
        &self.blob
    }

    /// 显式清理未安装对象，目录同步成功后返回。
    pub fn discard(mut self) -> Result<(), ArtifactByteError> {
        remove_stage(&self.directories, &self.blob.id.to_string(), &self.file)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for VerifiedArtifactStage {
    fn drop(&mut self) {
        if self.armed {
            // Drop 不声称清理成功。崩溃/清理失败后的孤立 staging 仍需恢复清理器。
            let _ = remove_stage(&self.directories, &self.blob.id.to_string(), &self.file);
        }
    }
}

impl ArtifactByteStore {
    /// 绑定可信宿主已经打开的 0700 私有根目录。所有后续 I/O 相对该描述符。
    /// 此调用可创建 staging/objects 私有子目录；不接受用户或模型给出的路径。
    pub fn bind_private_root(root: File, max_byte_length: u64) -> Result<Self, ArtifactByteError> {
        if max_byte_length > MAX_ARTIFACT_BYTES {
            return Err(ArtifactByteError::InvalidBinding);
        }
        let metadata = root.metadata().map_err(|_| ArtifactByteError::Io)?;
        check_directory(&metadata, metadata.uid())?;
        let owner = metadata.uid();
        let staging = private_directory(&root, "staging", owner)?;
        let objects = private_directory(&root, "objects", owner)?;
        root.sync_all().map_err(|_| ArtifactByteError::Io)?;
        Ok(Self {
            directories: Arc::new(StoreDirectories {
                root,
                staging,
                objects,
                owner,
            }),
            max_byte_length,
        })
    }

    /// 先核声明长度与真实磁盘余量，再有界落盘；完全一致才返回 staging。
    /// PG workspace/Run 配额必须在编排层另行原子预留；磁盘余量只是当前快照。
    pub fn stage(
        &self,
        input: &mut impl Read,
        byte_length: u64,
        expected_sha256: [u8; 32],
    ) -> Result<VerifiedArtifactStage, ArtifactByteError> {
        let blob = ArtifactBlob::from_record(Uuid::now_v7(), byte_length, expected_sha256)?;
        self.stage_for(input, &blob)
    }

    /// 可信编排先铸造成果的稳定身份后落盘，可在失败时登记准确 failed_partial。
    /// 这里只消费预期绑定，不将其当作读取权或已提交的登记回执。
    pub fn stage_for(
        &self,
        input: &mut impl Read,
        blob: &ArtifactBlob,
    ) -> Result<VerifiedArtifactStage, ArtifactByteError> {
        let byte_length = blob.byte_length;
        if byte_length > self.max_byte_length {
            return Err(ArtifactByteError::TooLarge);
        }
        self.directories.check_private()?;
        let space =
            rustix::fs::fstatvfs(&self.directories.staging).map_err(|_| ArtifactByteError::Io)?;
        let available = space
            .f_bavail
            .checked_mul(space.f_frsize)
            .ok_or(ArtifactByteError::Io)?;
        if byte_length > available {
            return Err(ArtifactByteError::InsufficientSpace);
        }
        let name = blob.id.to_string();
        let mut file = File::from(
            rustix::fs::openat(
                &self.directories.staging,
                &name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(map_open_error)?,
        );
        let result =
            write_verified(&mut file, input, blob, self.directories.owner).and_then(|()| {
                self.directories
                    .staging
                    .sync_all()
                    .map_err(|_| ArtifactByteError::Io)
            });
        if let Err(error) = result {
            // 错误路径的清理本身也需可观察，不能吞掉孤立 staging。
            remove_stage(&self.directories, &name, &file)?;
            return Err(error);
        }
        Ok(VerifiedArtifactStage {
            directories: Arc::clone(&self.directories),
            file,
            blob: blob.clone(),
            armed: true,
        })
    }

    /// 将已核字节用 NOREPLACE 原子安装；先实际存在才可由后续 PG 事务登记。
    /// 成功不是产品登记回执；失败或崩溃可留下私有孤立对象，不自动重放事务。
    pub fn install(
        &self,
        mut stage: VerifiedArtifactStage,
    ) -> Result<ArtifactBlob, ArtifactByteError> {
        if !Arc::ptr_eq(&self.directories, &stage.directories) {
            return Err(ArtifactByteError::InvalidBinding);
        }
        self.directories.check_private()?;
        let name = stage.blob.id.to_string();
        let original = stage.file.metadata().map_err(|_| ArtifactByteError::Io)?;
        check_file(&original, self.directories.owner, stage.blob.byte_length)?;
        let current = open_object(&self.directories.staging, &name)?;
        if Identity::of(&current.metadata().map_err(|_| ArtifactByteError::Io)?)
            != Identity::of(&original)
        {
            return Err(ArtifactByteError::UnsafeObject);
        }
        rustix::fs::renameat_with(
            &self.directories.staging,
            &name,
            &self.directories.objects,
            &name,
            RenameFlags::NOREPLACE,
        )
        .map_err(map_open_error)?;
        stage.armed = false;
        self.directories
            .objects
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories
            .staging
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories
            .root
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        let installed = self.open_verified(&stage.blob)?;
        if Identity::of(
            &installed
                .file
                .metadata()
                .map_err(|_| ArtifactByteError::Io)?,
        ) != Identity::of(&original)
        {
            return Err(ArtifactByteError::UnsafeObject);
        }
        Ok(stage.blob.clone())
    }

    /// 重新核普通文件、实际长度与摘要后返回内部有界 reader。
    /// 当前 actor/source-thread 授权、session/window 绑定及一次性句柄由上层负责。
    pub fn open_verified(
        &self,
        blob: &ArtifactBlob,
    ) -> Result<ArtifactBlobReader, ArtifactByteError> {
        if blob.byte_length > self.max_byte_length {
            return Err(ArtifactByteError::TooLarge);
        }
        self.directories.check_private()?;
        let mut file = open_object(&self.directories.objects, &blob.id.to_string())?;
        let original = file.metadata().map_err(|_| ArtifactByteError::Io)?;
        check_file(&original, self.directories.owner, blob.byte_length)?;
        verify_digest(&mut file, blob)?;
        if FileObservation::of(&original)
            != FileObservation::of(&file.metadata().map_err(|_| ArtifactByteError::Io)?)
        {
            return Err(ArtifactByteError::UnsafeObject);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ArtifactByteError::Io)?;
        Ok(ArtifactBlobReader {
            file,
            observation: FileObservation::of(&original),
            remaining: blob.byte_length,
            failed: false,
        })
    }

    /// The same original descriptor and full digest, with a trusted operation's stop predicate.
    /// This internal guard is checked around every real SHA segment; it grants no read authority.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn open_verified_guarded(
        &self,
        blob: &ArtifactBlob,
        is_current: &mut impl FnMut(bool) -> bool,
    ) -> Result<ArtifactBlobReader, ArtifactByteError> {
        if !is_current(false) {
            return Err(ArtifactByteError::Io);
        }
        if blob.byte_length > self.max_byte_length {
            return Err(ArtifactByteError::TooLarge);
        }
        self.directories.check_private()?;
        let mut file = open_object(&self.directories.objects, &blob.id.to_string())?;
        let original = file.metadata().map_err(|_| ArtifactByteError::Io)?;
        check_file(&original, self.directories.owner, blob.byte_length)?;
        verify_digest_guarded(&mut file, blob, is_current)?;
        if FileObservation::of(&original)
            != FileObservation::of(&file.metadata().map_err(|_| ArtifactByteError::Io)?)
        {
            return Err(ArtifactByteError::UnsafeObject);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ArtifactByteError::Io)?;
        if !is_current(false) {
            return Err(ArtifactByteError::Io);
        }
        Ok(ArtifactBlobReader {
            file,
            observation: FileObservation::of(&original),
            remaining: blob.byte_length,
            failed: false,
        })
    }

    /// Reobserve the original stable object after synchronous IO has ended. Expected bytes are
    /// deliberately absent from this interface; this is no actor or operation authorization.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn probe_actual(&self, id: Uuid) -> ArtifactByteProbe {
        self.probe_actual_inner(id)
            .unwrap_or(ArtifactByteProbe::Indeterminate)
    }

    #[cfg(feature = "server-runtime")]
    fn probe_actual_inner(&self, id: Uuid) -> Result<ArtifactByteProbe, ArtifactByteError> {
        if id.get_version_num() != 7 || id.get_variant() != Variant::RFC4122 {
            return Err(ArtifactByteError::InvalidBinding);
        }
        self.directories.check_private()?;
        let name = id.to_string();
        let staging = probe_open(&self.directories.staging, &name)?;
        let object = probe_open(&self.directories.objects, &name)?;
        let retained = match (staging, object) {
            (None, None) => None,
            (Some(file), None) => Some((ArtifactByteStorageLocation::Staging, file)),
            (None, Some(file)) => Some((ArtifactByteStorageLocation::Object, file)),
            (Some(_), Some(_)) => return Err(ArtifactByteError::UnsafeObject),
        };
        let observation = if let Some((location, mut file)) = retained {
            let before = file.metadata().map_err(|_| ArtifactByteError::Io)?;
            if !before.is_file()
                || before.uid() != self.directories.owner
                || before.nlink() != 1
                || !matches!(before.mode() & 0o7777, 0o400 | 0o600)
                || before.len() > self.max_byte_length
                || before.dev()
                    != self
                        .directories
                        .root
                        .metadata()
                        .map_err(|_| ArtifactByteError::Io)?
                        .dev()
            {
                return Err(ArtifactByteError::UnsafeObject);
            }
            let mut remaining = before.len();
            let mut hash = Sha256::new();
            let mut buffer = [0u8; COPY_BUFFER_BYTES];
            while remaining > 0 {
                let length = remaining.min(COPY_BUFFER_BYTES as u64) as usize;
                file.read_exact(&mut buffer[..length])
                    .map_err(|_| ArtifactByteError::Io)?;
                hash.update(&buffer[..length]);
                remaining -= length as u64;
            }
            if file
                .read(&mut buffer[..1])
                .map_err(|_| ArtifactByteError::Io)?
                != 0
            {
                return Err(ArtifactByteError::UnsafeObject);
            }
            file.sync_all().map_err(|_| ArtifactByteError::Io)?;
            if FileObservation::of(&before)
                != FileObservation::of(&file.metadata().map_err(|_| ArtifactByteError::Io)?)
            {
                return Err(ArtifactByteError::UnsafeObject);
            }
            // Verify the directory still selects this exact file, including after its fsync.
            let directory = match location {
                ArtifactByteStorageLocation::Staging => &self.directories.staging,
                ArtifactByteStorageLocation::Object => &self.directories.objects,
            };
            let current = probe_open(directory, &name)?.ok_or(ArtifactByteError::UnsafeObject)?;
            if FileObservation::of(&before)
                != FileObservation::of(&current.metadata().map_err(|_| ArtifactByteError::Io)?)
            {
                return Err(ArtifactByteError::UnsafeObject);
            }
            ArtifactByteProbe::Retained {
                location,
                byte_length: before.len(),
                sha256: hash.finalize().into(),
            }
        } else {
            ArtifactByteProbe::Absent
        };
        self.directories
            .staging
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories
            .objects
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories
            .root
            .sync_all()
            .map_err(|_| ArtifactByteError::Io)?;
        self.directories.check_private()?;
        if matches!(observation, ArtifactByteProbe::Absent)
            && (probe_open(&self.directories.staging, &name)?.is_some()
                || probe_open(&self.directories.objects, &name)?.is_some())
        {
            return Err(ArtifactByteError::UnsafeObject);
        }
        Ok(observation)
    }

    /// Verify the complete expected object on the exact leaf FD retained by this worker.
    /// Absence has no invented length/hash; staging or a replaced canonical name refuses.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn preflight_installed_guarded_before(
        &self,
        blob: &ArtifactBlob,
        original_deadline: Instant,
        stop: &mut impl FnMut(ArtifactProbePhase) -> bool,
    ) -> Result<OriginalArtifactPhysicalObject, ArtifactByteError> {
        if blob.id.get_version_num() != 7 || blob.id.get_variant() != Variant::RFC4122 {
            return Err(ArtifactByteError::InvalidBinding);
        }
        self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::Entry)?;
        let name = blob.id.to_string();
        let staging = probe_io_before(original_deadline, || {
            probe_open(&self.directories.staging, &name)
        })?;
        self.check_probe_current(original_deadline)?;
        if staging.is_some() {
            return Err(ArtifactByteError::UnsafeObject);
        }
        let object = probe_io_before(original_deadline, || {
            probe_open(&self.directories.objects, &name)
        })?;
        self.check_probe_current(original_deadline)?;
        let retained = if let Some(mut file) = object {
            let metadata = probe_io_before(original_deadline, || {
                file.metadata().map_err(|_| ArtifactByteError::Io)
            })?;
            self.check_probe_current(original_deadline)?;
            check_file(&metadata, self.directories.owner, blob.byte_length)?;
            let root = probe_io_before(original_deadline, || {
                self.directories
                    .root
                    .metadata()
                    .map_err(|_| ArtifactByteError::Io)
            })?;
            self.check_probe_current(original_deadline)?;
            if metadata.dev() != root.dev() || metadata.len() > self.max_byte_length {
                return Err(ArtifactByteError::UnsafeObject);
            }
            let before = FileObservation::of(&metadata);
            let mut remaining = metadata.len();
            let mut hash = Sha256::new();
            let mut buffer = [0u8; COPY_BUFFER_BYTES];
            while remaining > 0 {
                self.probe_cutpoint(
                    original_deadline,
                    stop,
                    ArtifactProbePhase::BeforeHashSegment,
                )?;
                self.check_probe_retained_current(
                    &name,
                    ArtifactByteStorageLocation::Object,
                    &file,
                    before,
                    original_deadline,
                )?;
                let length = remaining.min(COPY_BUFFER_BYTES as u64) as usize;
                probe_io_before(original_deadline, || {
                    file.read_exact(&mut buffer[..length])
                        .map_err(|_| ArtifactByteError::Io)
                })?;
                hash.update(&buffer[..length]);
                remaining -= length as u64;
                self.probe_cutpoint(
                    original_deadline,
                    stop,
                    ArtifactProbePhase::AfterHashSegment,
                )?;
                self.check_probe_retained_current(
                    &name,
                    ArtifactByteStorageLocation::Object,
                    &file,
                    before,
                    original_deadline,
                )?;
            }
            self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::BeforeEofRead)?;
            self.check_probe_retained_current(
                &name,
                ArtifactByteStorageLocation::Object,
                &file,
                before,
                original_deadline,
            )?;
            let trailing = probe_io_before(original_deadline, || {
                file.read(&mut buffer[..1])
                    .map_err(|_| ArtifactByteError::Io)
            })?;
            self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::AfterEofRead)?;
            self.check_probe_retained_current(
                &name,
                ArtifactByteStorageLocation::Object,
                &file,
                before,
                original_deadline,
            )?;
            if trailing != 0 {
                return Err(ArtifactByteError::LengthMismatch);
            }
            if <[u8; 32]>::from(hash.finalize()) != blob.sha256 {
                return Err(ArtifactByteError::ContentMismatch);
            }
            self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::BeforeFileSync)?;
            self.check_probe_retained_current(
                &name,
                ArtifactByteStorageLocation::Object,
                &file,
                before,
                original_deadline,
            )?;
            probe_io_before(original_deadline, || {
                file.sync_all().map_err(|_| ArtifactByteError::Io)
            })?;
            self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::AfterFileSync)?;
            self.check_probe_retained_current(
                &name,
                ArtifactByteStorageLocation::Object,
                &file,
                before,
                original_deadline,
            )?;
            Some((file, before))
        } else {
            None
        };
        let original = OriginalArtifactPhysicalObject {
            directories: Arc::clone(&self.directories),
            id: blob.id,
            retained,
            _worker_local: core::marker::PhantomData,
        };
        self.check_physical_object_current(&original, original_deadline)?;
        Ok(original)
    }

    #[cfg(feature = "server-runtime")]
    fn check_physical_object_current(
        &self,
        original: &OriginalArtifactPhysicalObject,
        original_deadline: Instant,
    ) -> Result<(), ArtifactByteError> {
        if !Arc::ptr_eq(&self.directories, &original.directories) {
            return Err(ArtifactByteError::InvalidBinding);
        }
        self.check_probe_current(original_deadline)?;
        let name = original.id.to_string();
        if let Some((file, before)) = &original.retained {
            self.check_probe_retained_current(
                &name,
                ArtifactByteStorageLocation::Object,
                file,
                *before,
                original_deadline,
            )?;
        } else {
            let staging = probe_io_before(original_deadline, || {
                probe_open(&self.directories.staging, &name)
            })?;
            self.check_probe_current(original_deadline)?;
            let object = probe_io_before(original_deadline, || {
                probe_open(&self.directories.objects, &name)
            })?;
            self.check_probe_current(original_deadline)?;
            if staging.is_some() || object.is_some() {
                return Err(ArtifactByteError::UnsafeObject);
            }
        }
        self.check_probe_current(original_deadline)
    }

    /// The final real filesystem check precedes the pure permission callback. The original
    /// cooperative IO guard remains held outside this method. stat -> unlink is not atomic
    /// against a hostile same-UID writer. The boolean records only an actual unlink syscall.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn execute_installed_guarded_before<E>(
        &self,
        original: &OriginalArtifactPhysicalObject,
        remove: bool,
        original_deadline: Instant,
        stop: &mut impl FnMut(ArtifactProbePhase) -> bool,
        start: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<bool, ArtifactBytePhysicalUnlinkError<E>> {
        self.probe_cutpoint(
            original_deadline,
            stop,
            ArtifactProbePhase::FinalObservation,
        )?;
        self.check_physical_object_current(original, original_deadline)?;
        start().map_err(ArtifactBytePhysicalUnlinkError::Start)?;
        // Started cannot be rolled back into Cancelled. A late syscall still has real effects.
        if Instant::now() >= original_deadline {
            return Err(ArtifactByteError::Io.into());
        }
        if !remove || original.retained.is_none() {
            return Ok(false);
        }
        rustix::fs::unlinkat(
            &self.directories.objects,
            original.id.to_string(),
            AtFlags::empty(),
        )
        .map_err(|_| ArtifactByteError::CleanupFailed)?;
        // The held original leaf remains alive for post-unlink metadata and FD-first closure.
        // Directory durability belongs to the guarded ordinary probe, even if this returns late.
        Ok(true)
    }

    /// Ordinary byte observation on the original owned blocking worker. This carries no Host,
    /// deletion, read-barrier or durable product-state authority. The supplied budget is never
    /// refreshed; a synchronous syscall that returns late leaves the observation indeterminate.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn probe_actual_guarded_before(
        &self,
        id: Uuid,
        original_deadline: Instant,
        stop: &mut impl FnMut(ArtifactProbePhase) -> bool,
    ) -> ArtifactByteProbe {
        self.probe_actual_guarded_inner(id, original_deadline, stop)
            .unwrap_or(ArtifactByteProbe::Indeterminate)
    }

    #[cfg(feature = "server-runtime")]
    fn check_probe_current(&self, original_deadline: Instant) -> Result<(), ArtifactByteError> {
        if Instant::now() >= original_deadline {
            return Err(ArtifactByteError::Io);
        }
        self.directories.check_current_children(original_deadline)?;
        if Instant::now() >= original_deadline {
            return Err(ArtifactByteError::Io);
        }
        Ok(())
    }

    #[cfg(feature = "server-runtime")]
    fn probe_cutpoint(
        &self,
        original_deadline: Instant,
        stop: &mut impl FnMut(ArtifactProbePhase) -> bool,
        phase: ArtifactProbePhase,
    ) -> Result<(), ArtifactByteError> {
        self.check_probe_current(original_deadline)?;
        if stop(phase) {
            return Err(ArtifactByteError::Io);
        }
        // The callback may have changed names or permissions. Its `false` result is not evidence.
        self.check_probe_current(original_deadline)
    }

    #[cfg(feature = "server-runtime")]
    fn check_probe_retained_current(
        &self,
        name: &str,
        location: ArtifactByteStorageLocation,
        file: &File,
        before: FileObservation,
        original_deadline: Instant,
    ) -> Result<(), ArtifactByteError> {
        self.check_probe_current(original_deadline)?;
        let metadata = probe_io_before(original_deadline, || {
            file.metadata().map_err(|_| ArtifactByteError::Io)
        })?;
        self.check_probe_current(original_deadline)?;
        if FileObservation::of(&metadata) != before {
            return Err(ArtifactByteError::UnsafeObject);
        }
        let (selected, other) = match location {
            ArtifactByteStorageLocation::Staging => {
                (&self.directories.staging, &self.directories.objects)
            }
            ArtifactByteStorageLocation::Object => {
                (&self.directories.objects, &self.directories.staging)
            }
        };
        let current = probe_io_before(original_deadline, || probe_open(selected, name))?;
        self.check_probe_current(original_deadline)?;
        let current = current.ok_or(ArtifactByteError::UnsafeObject)?;
        let selected_metadata = probe_io_before(original_deadline, || {
            current.metadata().map_err(|_| ArtifactByteError::Io)
        })?;
        self.check_probe_current(original_deadline)?;
        if FileObservation::of(&selected_metadata) != before {
            return Err(ArtifactByteError::UnsafeObject);
        }
        let other = probe_io_before(original_deadline, || probe_open(other, name))?;
        self.check_probe_current(original_deadline)?;
        if other.is_some() {
            return Err(ArtifactByteError::UnsafeObject);
        }
        Ok(())
    }

    #[cfg(feature = "server-runtime")]
    fn probe_actual_guarded_inner(
        &self,
        id: Uuid,
        original_deadline: Instant,
        stop: &mut impl FnMut(ArtifactProbePhase) -> bool,
    ) -> Result<ArtifactByteProbe, ArtifactByteError> {
        if id.get_version_num() != 7 || id.get_variant() != Variant::RFC4122 {
            return Err(ArtifactByteError::InvalidBinding);
        }
        self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::Entry)?;
        let name = id.to_string();
        let staging = probe_io_before(original_deadline, || {
            probe_open(&self.directories.staging, &name)
        })?;
        self.check_probe_current(original_deadline)?;
        let object = probe_io_before(original_deadline, || {
            probe_open(&self.directories.objects, &name)
        })?;
        self.check_probe_current(original_deadline)?;
        let retained = match (staging, object) {
            (None, None) => None,
            (Some(file), None) => Some((ArtifactByteStorageLocation::Staging, file)),
            (None, Some(file)) => Some((ArtifactByteStorageLocation::Object, file)),
            (Some(_), Some(_)) => return Err(ArtifactByteError::UnsafeObject),
        };
        // Keep this exact FD alive through all directory syncs and the final name observation.
        let mut original_file = None;
        let observation = if let Some((location, mut file)) = retained {
            let metadata = probe_io_before(original_deadline, || {
                file.metadata().map_err(|_| ArtifactByteError::Io)
            })?;
            self.check_probe_current(original_deadline)?;
            let root = probe_io_before(original_deadline, || {
                self.directories
                    .root
                    .metadata()
                    .map_err(|_| ArtifactByteError::Io)
            })?;
            self.check_probe_current(original_deadline)?;
            if !metadata.is_file()
                || metadata.uid() != self.directories.owner
                || metadata.nlink() != 1
                || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
                || metadata.len() > self.max_byte_length
                || metadata.dev() != root.dev()
            {
                return Err(ArtifactByteError::UnsafeObject);
            }
            let before = FileObservation::of(&metadata);
            let mut remaining = metadata.len();
            let mut hash = Sha256::new();
            let mut buffer = [0u8; COPY_BUFFER_BYTES];
            while remaining > 0 {
                self.probe_cutpoint(
                    original_deadline,
                    stop,
                    ArtifactProbePhase::BeforeHashSegment,
                )?;
                let length = remaining.min(COPY_BUFFER_BYTES as u64) as usize;
                probe_io_before(original_deadline, || {
                    file.read_exact(&mut buffer[..length])
                        .map_err(|_| ArtifactByteError::Io)
                })?;
                hash.update(&buffer[..length]);
                remaining -= length as u64;
                self.probe_cutpoint(
                    original_deadline,
                    stop,
                    ArtifactProbePhase::AfterHashSegment,
                )?;
            }
            self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::BeforeEofRead)?;
            let trailing = probe_io_before(original_deadline, || {
                file.read(&mut buffer[..1])
                    .map_err(|_| ArtifactByteError::Io)
            })?;
            self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::AfterEofRead)?;
            if trailing != 0 {
                return Err(ArtifactByteError::UnsafeObject);
            }
            self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::BeforeFileSync)?;
            probe_io_before(original_deadline, || {
                file.sync_all().map_err(|_| ArtifactByteError::Io)
            })?;
            self.probe_cutpoint(original_deadline, stop, ArtifactProbePhase::AfterFileSync)?;
            self.check_probe_retained_current(&name, location, &file, before, original_deadline)?;
            original_file = Some((location, file, before));
            ArtifactByteProbe::Retained {
                location,
                byte_length: metadata.len(),
                sha256: hash.finalize().into(),
            }
        } else {
            ArtifactByteProbe::Absent
        };
        for (directory, before, after) in [
            (
                &self.directories.staging,
                ArtifactProbePhase::BeforeStagingSync,
                ArtifactProbePhase::AfterStagingSync,
            ),
            (
                &self.directories.objects,
                ArtifactProbePhase::BeforeObjectsSync,
                ArtifactProbePhase::AfterObjectsSync,
            ),
            (
                &self.directories.root,
                ArtifactProbePhase::BeforeRootSync,
                ArtifactProbePhase::AfterRootSync,
            ),
        ] {
            self.probe_cutpoint(original_deadline, stop, before)?;
            probe_io_before(original_deadline, || {
                directory.sync_all().map_err(|_| ArtifactByteError::Io)
            })?;
            self.probe_cutpoint(original_deadline, stop, after)?;
        }
        self.probe_cutpoint(
            original_deadline,
            stop,
            ArtifactProbePhase::FinalObservation,
        )?;
        if let Some((location, file, before)) = original_file {
            self.check_probe_retained_current(&name, location, &file, before, original_deadline)?;
        } else {
            let staging = probe_io_before(original_deadline, || {
                probe_open(&self.directories.staging, &name)
            })?;
            self.check_probe_current(original_deadline)?;
            let object = probe_io_before(original_deadline, || {
                probe_open(&self.directories.objects, &name)
            })?;
            self.check_probe_current(original_deadline)?;
            if staging.is_some() || object.is_some() {
                return Err(ArtifactByteError::UnsafeObject);
            }
        }
        self.check_probe_current(original_deadline)?;
        Ok(observation)
    }
}

#[cfg(feature = "server-runtime")]
fn probe_open(directory: &File, name: &str) -> Result<Option<File>, ArtifactByteError> {
    match rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(map_open_error(error)),
    }
}

#[cfg(feature = "server-runtime")]
fn probe_io_before<T>(
    original_deadline: Instant,
    io: impl FnOnce() -> Result<T, ArtifactByteError>,
) -> Result<T, ArtifactByteError> {
    if Instant::now() >= original_deadline {
        return Err(ArtifactByteError::Io);
    }
    let result = io();
    if Instant::now() >= original_deadline {
        return Err(ArtifactByteError::Io);
    }
    result
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileObservation {
    identity: Identity,
    length: u64,
    mode: u32,
    links: u64,
    owner: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl FileObservation {
    fn of(m: &Metadata) -> Self {
        Self {
            identity: Identity::of(m),
            length: m.len(),
            mode: m.mode(),
            links: m.nlink(),
            owner: m.uid(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

/// 单个已核实际字节的 reader。不可 Clone，不暴露 fd 或实现任意长度 Read。
pub struct ArtifactBlobReader {
    file: File,
    observation: FileObservation,
    remaining: u64,
    failed: bool,
}
impl ArtifactBlobReader {
    /// Recheck the original retained FD without reading bytes or reopening another object.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn verify_current_descriptor(&self) -> Result<(), ArtifactByteError> {
        if self.failed {
            return Err(ArtifactByteError::Io);
        }
        self.check_observation()
    }
    /// 在调用方缓冲中返回 ≤4MiB；修改/截断/替换拒绝，EOF 返回0。
    /// 外部单次句柄/单在途响应限制仍必须由 transport 的句柄管理器落实。
    pub fn read_chunk(&mut self, output: &mut [u8]) -> Result<usize, ArtifactByteError> {
        if output.is_empty() || output.len() > MAX_ARTIFACT_READ_CHUNK_BYTES {
            return Err(ArtifactByteError::InvalidChunk);
        }
        if self.failed {
            return Err(ArtifactByteError::Io);
        }
        if let Err(error) = self.check_observation() {
            self.failed = true;
            return Err(error);
        }
        let length = usize::try_from(self.remaining.min(output.len() as u64))
            .map_err(|_| ArtifactByteError::Io)?;
        if let Err(_error) = self.file.read_exact(&mut output[..length]) {
            self.failed = true;
            output[..length].fill(0);
            return Err(ArtifactByteError::Io);
        }
        if let Err(error) = self.check_observation() {
            self.failed = true;
            output[..length].fill(0);
            return Err(error);
        }
        self.remaining -= length as u64;
        Ok(length)
    }
    fn check_observation(&self) -> Result<(), ArtifactByteError> {
        let observed = self.file.metadata().map_err(|_| ArtifactByteError::Io)?;
        if FileObservation::of(&observed) != self.observation {
            return Err(ArtifactByteError::UnsafeObject);
        }
        Ok(())
    }
}

fn private_directory(root: &File, name: &str, owner: u32) -> Result<File, ArtifactByteError> {
    match rustix::fs::mkdirat(root, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(ArtifactByteError::Io),
    }
    let file = File::from(
        rustix::fs::openat(
            root,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_open_error)?,
    );
    let metadata = file.metadata().map_err(|_| ArtifactByteError::Io)?;
    check_directory(&metadata, owner)?;
    if metadata.dev() != root.metadata().map_err(|_| ArtifactByteError::Io)?.dev() {
        return Err(ArtifactByteError::UnsafeObject);
    }
    Ok(file)
}

fn check_directory(metadata: &Metadata, owner: u32) -> Result<(), ArtifactByteError> {
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
        return Err(ArtifactByteError::UnsafeObject);
    }
    Ok(())
}
fn check_file(metadata: &Metadata, owner: u32, length: u64) -> Result<(), ArtifactByteError> {
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o400
    {
        return Err(ArtifactByteError::UnsafeObject);
    }
    if metadata.len() != length {
        return Err(ArtifactByteError::LengthMismatch);
    }
    Ok(())
}
fn open_object(directory: &File, name: &str) -> Result<File, ArtifactByteError> {
    rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(map_open_error)
}
fn map_open_error(error: rustix::io::Errno) -> ArtifactByteError {
    match error {
        rustix::io::Errno::EXIST => ArtifactByteError::AlreadyExists,
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => ArtifactByteError::UnsafeObject,
        _ => ArtifactByteError::Io,
    }
}
fn remove_stage(
    directories: &StoreDirectories,
    name: &str,
    expected: &File,
) -> Result<(), ArtifactByteError> {
    // 已观察到叶子替换时不盲删。核身份后 unlink 依赖可信目录写者；不是原子 compare-unlink。
    let current =
        open_object(&directories.staging, name).map_err(|_| ArtifactByteError::CleanupFailed)?;
    let current = current
        .metadata()
        .map_err(|_| ArtifactByteError::CleanupFailed)?;
    let original = expected
        .metadata()
        .map_err(|_| ArtifactByteError::CleanupFailed)?;
    if !current.is_file() || Identity::of(&current) != Identity::of(&original) {
        return Err(ArtifactByteError::CleanupFailed);
    }
    rustix::fs::unlinkat(&directories.staging, name, AtFlags::empty())
        .map_err(|_| ArtifactByteError::CleanupFailed)?;
    directories
        .staging
        .sync_all()
        .map_err(|_| ArtifactByteError::CleanupFailed)
}
fn write_verified(
    file: &mut File,
    input: &mut impl Read,
    blob: &ArtifactBlob,
    owner: u32,
) -> Result<(), ArtifactByteError> {
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    let mut remaining = blob.byte_length;
    let mut hash = Sha256::new();
    while remaining > 0 {
        let limit = remaining.min(COPY_BUFFER_BYTES as u64) as usize;
        let read = match input.read(&mut buffer[..limit]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ArtifactByteError::Io),
            Ok(0) => return Err(ArtifactByteError::LengthMismatch),
            Ok(length) => length,
        };
        file.write_all(&buffer[..read])
            .map_err(|_| ArtifactByteError::Io)?;
        hash.update(&buffer[..read]);
        remaining -= read as u64;
    }
    loop {
        match input.read(&mut buffer[..1]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ArtifactByteError::Io),
            Ok(0) => break,
            Ok(_) => return Err(ArtifactByteError::LengthMismatch),
        }
    }
    if <[u8; 32]>::from(hash.finalize()) != blob.sha256 {
        return Err(ArtifactByteError::ContentMismatch);
    }
    file.sync_all().map_err(|_| ArtifactByteError::Io)?;
    rustix::fs::fchmod(&*file, Mode::RUSR).map_err(|_| ArtifactByteError::Io)?;
    file.sync_all().map_err(|_| ArtifactByteError::Io)?;
    check_file(
        &file.metadata().map_err(|_| ArtifactByteError::Io)?,
        owner,
        blob.byte_length,
    )?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ArtifactByteError::Io)?;
    // 校验的是实际落盘字节，不能只用输入流的摘要声称存储一致。
    verify_digest(file, blob)
}
fn verify_digest(file: &mut File, blob: &ArtifactBlob) -> Result<(), ArtifactByteError> {
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    let mut hash = Sha256::new();
    let mut remaining = blob.byte_length;
    while remaining > 0 {
        let length = remaining.min(COPY_BUFFER_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..length])
            .map_err(|_| ArtifactByteError::LengthMismatch)?;
        hash.update(&buffer[..length]);
        remaining -= length as u64;
    }
    if file
        .read(&mut buffer[..1])
        .map_err(|_| ArtifactByteError::Io)?
        != 0
    {
        return Err(ArtifactByteError::LengthMismatch);
    }
    if <[u8; 32]>::from(hash.finalize()) != blob.sha256 {
        return Err(ArtifactByteError::ContentMismatch);
    }
    Ok(())
}

#[cfg(feature = "server-runtime")]
fn verify_digest_guarded(
    file: &mut File,
    blob: &ArtifactBlob,
    is_current: &mut impl FnMut(bool) -> bool,
) -> Result<(), ArtifactByteError> {
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    let mut hash = Sha256::new();
    let mut remaining = blob.byte_length;
    while remaining > 0 {
        if !is_current(false) {
            return Err(ArtifactByteError::Io);
        }
        let length = remaining.min(COPY_BUFFER_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..length])
            .map_err(|_| ArtifactByteError::LengthMismatch)?;
        hash.update(&buffer[..length]);
        remaining -= length as u64;
        // Only this call follows an actually completed original SHA segment.
        if !is_current(true) {
            return Err(ArtifactByteError::Io);
        }
    }
    if !is_current(false) {
        return Err(ArtifactByteError::Io);
    }
    let extra = file
        .read(&mut buffer[..1])
        .map_err(|_| ArtifactByteError::Io)?;
    if !is_current(false) {
        return Err(ArtifactByteError::Io);
    }
    if extra != 0 {
        return Err(ArtifactByteError::LengthMismatch);
    }
    if <[u8; 32]>::from(hash.finalize()) != blob.sha256 {
        return Err(ArtifactByteError::ContentMismatch);
    }
    Ok(())
}
