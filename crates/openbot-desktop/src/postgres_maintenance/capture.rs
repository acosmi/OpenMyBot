//! Real capture-source ownership. This module cannot initialize or adopt an arbitrary database.
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use openbot_domain::backup::whole_pg_carrier::{WholePgCarrierFault as Fault, WholePgMaterialKind};
use openbot_domain::vault::SecretBytes;
use openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tokio_postgres::tls::NoTlsStream;
use tokio_postgres::{Client, Connection, NoTls};
use openbot_infra::db::pool::CapturePgIo;

use super::{
    MaintenanceError,
    bundle::{Program, VerifiedMaintenanceBundle},
    clock::OperationClock,
    limits::{self, MaintenanceProfile},
    runner,
};
/// Closed material facts remain paired with the unique original source and kernel lease.
pub(crate) struct CaptureMaterialsClosed {
    pub(crate) source: CaptureSourceOwner,
    pub(crate) materials: crate::tauri_background::capture::CapturedNormalMaterials,
}

impl CaptureMaterialsClosed {
    /// Forward the same original witness; do not consume or reconstruct source/materials.
    pub(crate) fn intent_witness(
        &self,
    ) -> Result<&crate::tauri_background::capture::CaptureIntentWitness, Fault> {
        self.source.intent_witness()
    }
}

pub(crate) async fn run_capture(
    mut source: CaptureSourceOwner,
    operation: &CaptureOperation,
) -> Result<CaptureMaterialsClosed, RetainedCaptureFailure> {
    // Keep the original source outside this borrowed synchronous prelude.
    // Preserve the existing ordinary identity-error classification exactly.
    let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match operation.shared_original() {
            Ok(operation) if Arc::ptr_eq(&source.operation, &operation) => Ok(operation),
            _ => Err(Fault::IntentMismatch),
        }
    }));
    let operation = match prepared {
        Ok(Ok(operation)) => operation,
        Ok(Err(fault)) => {
            return Err(RetainedCaptureFailure::from_source(source, fault));
        }
        Err(payload) => {
            source.borrowed_panic = Some(payload);
            return Err(RetainedCaptureFailure::from_source(
                source,
                Fault::ClosingPending,
            ));
        }
    };
    match catch_borrowed_source_step(
        crate::tauri_background::capture::finish_original_capture_materials(
            &mut source, &operation,
        ),
    ).await {
        Ok(Ok(materials)) => Ok(CaptureMaterialsClosed { source, materials }),
        Ok(Err(fault)) => Err(RetainedCaptureFailure::from_source(source, fault)),
        Err(payload) => {
            source.borrowed_panic = Some(payload);
            Err(RetainedCaptureFailure::from_source(source, Fault::ClosingPending))
        }
    }
}
use crate::tauri_background::capture::{
    CaptureOperation, CaptureStartPermit, NormalCaptureMaterials, RetainedCaptureFailure,
};

type Connecting =
    JoinHandle<Result<(Client, Connection<CapturePgIo, NoTlsStream>), tokio_postgres::Error>>;

fn original_capture_connect(
    original: Option<(tokio_postgres::Config, CapturePgIo)>,
) -> impl std::future::Future<
    Output = Result<(Client, Connection<CapturePgIo, NoTlsStream>), tokio_postgres::Error>
> + Send {
    async move {
        let (config, io) = original.expect("only admitted original source inputs are polled");
        config.connect_raw(io, NoTls).await
    }
}

// Same actual unpolled factory, private DATA only. No socket/config/key is created.
pub(crate) fn checked_original_source_connect_metadata_bytes(attempts: u64)
    -> Result<u64, Fault>
{
    let original = original_capture_connect(None);
    let raw = u64::try_from(std::alloc::Layout::for_value(&original).size())
        .map_err(|_| Fault::BoundsOverflow)?;
    let connection = u64::try_from(std::mem::size_of::<Connection<CapturePgIo, NoTlsStream>>())
        .map_err(|_| Fault::BoundsOverflow)?;
    raw.checked_add(connection).and_then(|n| n.checked_mul(attempts))
        .ok_or(Fault::BoundsOverflow)
}

/// An ordinary file already opened and checked by the original closed producer.
pub(crate) struct CaptureOwnedMaterialFile {
    pub(crate) kind: WholePgMaterialKind,
    pub(crate) material_id: String,
    pub(crate) relative_path: String,
    pub(crate) file: File,
    pub(crate) plain_len: u64,
    pub(crate) plain_sha256: [u8; 32],
}
enum SecretMovePhase {
    Unentered,
    Entered,
}
struct ClosedMaintenanceSource {
    postmaster: runner::ToolObservation,
    stop_helper: Option<runner::ToolObservation>,
    sql_driver_result: Result<(), ()>,
}

/// The private constructor will consume only a real post-stop consumer permit.
/// Every original source task remains in this owner or its one resident awaited future.
pub(crate) struct CaptureSourceOwner {
    permit: CaptureStartPermit,
    operation: Arc<CaptureOperation>,
    profile: MaintenanceProfile,
    work_path: PathBuf,
    work_directory: Option<File>,
    socket_path: PathBuf,
    socket_directory: Option<File>,
    // The fixed / -> private -> tmp walk and the real exclusive child remain resident.
    socket_ancestors: [Option<File>; 3],
    socket_identities: [Option<OriginalSocketDirectoryIdentity>; 4],
    socket_mkdir_result: Option<Result<(), rustix::io::Errno>>,
    socket_parent_sync_result: Option<std::io::Result<()>>,
    output_path: PathBuf,
    secret: Option<Arc<SecretBytes>>,
    postmaster: Option<runner::ProgramOwner>,
    postmaster_identity: Option<wrok_bot_macos_process::ProcessIdentity>,
    postmaster_birth: Option<[u8; 32]>,
    postmaster_retirement: Option<Result<(), rustix::io::Errno>>,
    stop_helper: Option<runner::ProgramOwner>,
    connecting: Option<Connecting>,
    sql_client: Option<Client>,
    sql_driver: Option<JoinHandle<Result<(), tokio_postgres::Error>>>,
    sql_driver_result: Option<Result<(), ()>>,
    native: Option<runner::NativeOwner>,
    native_receipt: Option<runner::NativeReceipt>,
    physical: Option<runner::MaterialInventory>,
    closed: Option<ClosedMaintenanceSource>,
    postmaster_observation: Option<runner::ToolObservation>,
    stop_observation: Option<runner::ToolObservation>,
    material_files: Option<Vec<CaptureOwnedMaterialFile>>,
    material_open_entered: bool,
    material_fd_slots: Vec<Option<File>>,
    provenance_open_entered: bool,
    provenance_files: [Option<File>; 3],
    original_driver_material: Option<crate::tauri_background::capture::OriginalDriverMaterial>,
    original_provenance_material: Option<(openbot_domain::backup::whole_pg_carrier::WholePgProvenanceClaim, Vec<u8>)>,
    stream_master: Option<SecretBytes>,
    stream_scram: Option<SecretBytes>,
    stream_master_journal: Option<File>,
    stream_master_journal_bytes: Option<zeroize::Zeroizing<Vec<u8>>>,
    retained_vault_failure: Option<crate::desktop_vault::ArmedCaptureVault>,
    secret_move_phase: SecretMovePhase,
    start_phase: SourceStartPhase,
    start_configuration: [Option<File>; 3],
    start_main: Vec<u8>,
    source_data_directory: Option<File>,
    source_wal_directory: Option<File>,
    source_tablespace_directory: Option<File>,
    source_tablespace_scan: Option<rustix::fs::Dir>,
    connection_result: Option<SourceConnectResult>,
    connection_failures: Vec<SourceConnectFailure>,
    original_connect_tasks_started: u64,
    original_connect_tasks_joined: u64,
    start_child_exit: Option<std::process::ExitStatus>,
    start_fd_admissions: u64,
    start_password_admissions: u64,
    borrowed_panic: Option<Box<dyn std::any::Any + Send + 'static>>,
    metadata_work: Option<Arc<std::sync::Mutex<OriginalMetadataWork>>>,
    metadata_task: Option<JoinHandle<OriginalMetadataCompletion>>,
    metadata_joined: Option<OriginalMetadataJoin>,
}


type OriginalMetadataCompletion = (Result<(), Fault>, Result<(u64, u64), Fault>);
type OriginalMetadataJoin = Result<OriginalMetadataCompletion, tokio::task::JoinError>;

// This is the original source's retained slot, not a replacement source owner.
// Inputs are installed before the sole blocking closure can borrow them.
struct OriginalMetadataWork {
    materials: Option<NormalCaptureMaterials>,
    originals: Option<Vec<CaptureOwnedMaterialFile>>,
    directory: Option<File>,
    path: Option<PathBuf>,
    range: Option<(String, String, u32, u32)>,
    returned: Option<OriginalMetadataCompletion>,
    panic: Option<Box<dyn std::any::Any + Send + 'static>>,
}

impl CaptureSourceOwner {
    /// Forward the genuine permit's borrowed witness, without a new token or check result.
    pub(crate) fn intent_witness(
        &self,
    ) -> Result<&crate::tauri_background::capture::CaptureIntentWitness, Fault> {
        self.permit.intent_witness()
    }
    /// Implementation-only bridge. Only the sidecar's registered factory delegates here.
    pub(crate) async fn start_from_permit(
        permit: CaptureStartPermit,
        operation: &CaptureOperation,
    ) -> Result<Self, RetainedCaptureFailure> {
        let original = match operation.shared_original() {
            Ok(original) => original,
            Err(fault) => return Err(RetainedCaptureFailure::from_permit(permit, fault)),
        };
        // This preparation allocates only closed, nonsecret metadata. No file/task is created.
        let prepared = (|| {
            let encoded = serde_json::to_vec(&original.profile().native)
                .map_err(|_| Fault::ProfileInvalid)?;
            if encoded.len() as u64 > original.profile().carrier.max_metadata_bytes {
                return Err(Fault::CapacityExceeded);
            }
            let profile = limits::parse_profile(&encoded).map_err(map_maintenance)?;
            let port = permit.stopped()?.port();
            if port == 0 { return Err(Fault::ProfileInvalid); }
            let work = permit.operation_path().to_path_buf();
            let data = permit.stopped()?.data_dir();
            let socket = planned_original_socket_path(&original, port)?;
            let main = source_include_config(data, &work, &socket, port, &original)?;
            let secret = permit.stopped()?.native_scram_allocation()?;
            Ok((profile, port, work, socket, main, secret))
        })();
        let (profile, port, work_path, socket_path, main, secret) = match prepared {
            Ok(prepared) => prepared,
            Err(fault) => return Err(RetainedCaptureFailure::from_permit(permit, fault)),
        };
        // Starting is real custody, not permission: every actual result is installed here
        // before any fallible postcheck or borrowed wait. There is no dummy FD/Child.
        let mut source = Self {
            permit, operation: original, profile,
            output_path: work_path.join("pg"), socket_path, work_path,
            work_directory: None, socket_directory: None,
            socket_ancestors: [None, None, None], socket_identities: [None, None, None, None],
            socket_mkdir_result: None, socket_parent_sync_result: None,
            secret: Some(secret), postmaster: None, postmaster_identity: None,
            postmaster_birth: None, postmaster_retirement: None, stop_helper: None,
            connecting: None, sql_client: None, sql_driver: None, sql_driver_result: None,
            native: None, native_receipt: None, physical: None, closed: None,
            postmaster_observation: None, stop_observation: None, material_files: None,
            material_open_entered: false, material_fd_slots: Vec::new(),
            provenance_open_entered: false, provenance_files: [None, None, None],
            original_driver_material: None, original_provenance_material: None,
            stream_master: None, stream_scram: None,
            stream_master_journal: None, stream_master_journal_bytes: None,
            retained_vault_failure: None, secret_move_phase: SecretMovePhase::Unentered,
            start_phase: SourceStartPhase::Starting,
            start_configuration: [None, None, None], start_main: main,
            source_data_directory: None, source_wal_directory: None, source_tablespace_directory: None,
            source_tablespace_scan: None, connection_result: None,
            connection_failures: Vec::new(), start_child_exit: None,
            original_connect_tasks_started: 0, original_connect_tasks_joined: 0,
            start_fd_admissions: 0, start_password_admissions: 0,
            borrowed_panic: None,
            metadata_work: None, metadata_task: None, metadata_joined: None,
        };
        match catch_borrowed_source_step(source.start_original(port)).await {
            Ok(Ok(())) => Ok(source),
            Ok(Err(fault)) => Err(RetainedCaptureFailure::from_source(source, fault)),
            Err(payload) => {
                source.borrowed_panic = Some(payload);
                Err(RetainedCaptureFailure::from_source(source, Fault::ClosingPending))
            }
        }
    }

    async fn start_original(&mut self, port: u16) -> Result<(), Fault> {
        let operation = Arc::clone(&self.operation);
        operation.require_effect()?;
        self.permit.revalidate_original(&operation)?;
        self.reserve_start_fds(1)?;
        operation.require_effect()?;
        let actual = self.permit.operation_directory().try_clone();
        match actual {
            Ok(file) => self.work_directory = Some(file),
            Err(_) => { operation.require_effect()?; return Err(Fault::IoFailure); }
        }
        operation.require_effect()?;
        self.create_original_socket_directory()?;
        checked_directory(self.work_directory()?, &self.work_path, &operation)?;
        self.revalidate_original_socket_directory()?;
        self.reserve_start_fds(1)?;
        operation.require_effect()?;
        let actual = self.permit.stopped()?.data_directory_file();
        match actual {
            Ok(file) => self.source_data_directory = Some(file),
            Err(_) => { operation.require_effect()?; return Err(Fault::IoFailure); }
        }
        operation.require_effect()?;
        // This duplicate is real, admitted, and resident; it is not described as a borrow.
        for name in ["recovery.signal", "standby.signal"] {
            require_source_name_absent(self.source_data_directory.as_ref().ok_or(Fault::MaterialMissing)?, name, &operation)?;
        }
        for index in 0..2 {
            self.reserve_start_fds(1)?;
            operation.require_effect()?;
            let name = if index == 0 { "pg_wal" } else { "pg_tblspc" };
            let actual = rustix::fs::openat(
                self.source_data_directory.as_ref().ok_or(Fault::MaterialMissing)?, name,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            );
            match actual {
                Ok(file) if index == 0 => self.source_wal_directory = Some(File::from(file)),
                Ok(file) => self.source_tablespace_directory = Some(File::from(file)),
                Err(_) => { operation.require_effect()?; return Err(Fault::PathUnsafe); }
            }
            operation.require_effect()?;
        }
        self.reserve_start_fds(1)?;
        operation.require_effect()?;
        let actual = rustix::fs::Dir::read_from(
            self.source_tablespace_directory.as_ref().ok_or(Fault::MaterialMissing)?,
        );
        match actual {
            Ok(directory) => self.source_tablespace_scan = Some(directory),
            Err(_) => { operation.require_effect()?; return Err(Fault::IoFailure); }
        }
        operation.require_effect()?;
        loop {
            operation.require_effect()?;
            let actual = self.source_tablespace_scan.as_mut().ok_or(Fault::MaterialMissing)?.next();
            operation.require_effect()?;
            let Some(entry) = actual else { break; };
            let entry = entry.map_err(|_| Fault::IoFailure)?;
            if entry.file_name().to_bytes() != b"." && entry.file_name().to_bytes() != b".." {
                return Err(Fault::ExtraMaterial);
            }
        }
        for name in [SOURCE_MAIN, SOURCE_HBA, SOURCE_IDENT, "pg"] {
            require_source_name_absent(self.work_directory()?, name, &operation)?;
        }
        for name in [format!(".s.PGSQL.{port}"), format!(".s.PGSQL.{port}.lock")] {
            require_source_name_absent(self.socket_directory()?, &name, &operation)?;
        }
        for index in 0..3 {
            self.reserve_start_fds(1)?;
            operation.require_effect()?;
            let actual = rustix::fs::openat(
                self.work_directory()?, [SOURCE_MAIN, SOURCE_HBA, SOURCE_IDENT][index],
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            );
            match actual {
                Ok(file) => self.start_configuration[index] = Some(File::from(file)),
                Err(_) => { operation.require_effect()?; return Err(Fault::IoFailure); }
            }
            operation.require_effect()?;
            let bytes = match index {
                0 => self.start_main.as_slice(),
                1 => SOURCE_HBA_BYTES,
                _ => b"",
            };
            write_source_configuration(
                self.start_configuration[index].as_ref().ok_or(Fault::MaterialMissing)?,
                bytes, &operation,
            )?;
        }
        operation.require_effect()?;
        let synced = self.work_directory()?.sync_all();
        operation.require_effect()?;
        synced.map_err(|_| Fault::IoFailure)?;
        // Reobserve the four original held files after writing the three independent files.
        // This gate does not hash/read/reopen the original payload or stop SameUID writers.
        self.permit.revalidate_original(&operation)?;
        self.revalidate_source_configuration()?;
        self.revalidate_original_socket_directory()?;
        self.native_capacity_check().map_err(map_maintenance)?;
        operation.require_effect()?;
        let actual = self.native_bundle().checked_command(Program::Postgres);
        operation.require_effect()?;
        let mut command = actual.map_err(map_maintenance)?;
        command.arg("-D").arg(self.permit.stopped()?.data_dir())
            .arg("-p").arg(port.to_string()).current_dir(&self.work_path);
        for (name, value) in [
            ("config_file", self.work_path.join(SOURCE_MAIN)),
            ("hba_file", self.work_path.join(SOURCE_HBA)),
            ("ident_file", self.work_path.join(SOURCE_IDENT)),
        ] {
            let path = value.to_str().ok_or(Fault::PathUnsafe)?;
            command.arg("-c").arg(format!("{name}={path}"));
        }
        command.arg("-c").arg(format!(
            "unix_socket_directories=\"{}\"", self.socket_path.to_str().ok_or(Fault::PathUnsafe)?,
        ));
        for setting in SOURCE_SAFETY_ARGV {
            command.arg("-c").arg(setting);
        }
        self.reserve_start_fds(3)?;
        self.native_fd_budget(3).map_err(map_maintenance)?;
        operation.require_effect()?;
        let actual = runner::spawn_program(
            command, "capture-original-postgres", operation.original_clock(),
            Arc::clone(self.native_secret()), false,
            (self.profile.fields().max_status_bytes, self.profile.fields().max_stderr_bytes, false),
            false,
        );
        match actual {
            Ok(owner) => self.postmaster = Some(owner),
            Err(error) => { operation.require_effect()?; return Err(map_maintenance(error)); }
        }
        operation.require_effect()?;
        self.retain_original_postmaster_identity()?;
        self.connect_original_ready(port).await?;
        self.permit.revalidate_original(&operation)?;
        self.revalidate_source_configuration()?;
        self.revalidate_original_socket_directory()?;
        operation.require_effect()?;
        // Only the real authenticated Client + original running Connection driver get Ready.
        if self.sql_client.is_none() || self.sql_driver.is_none() || self.start_child_exit.is_some() {
            return Err(Fault::SourceChanged);
        }
        self.start_phase = SourceStartPhase::Ready;
        Ok(())
    }

    fn create_original_socket_directory(&mut self) -> Result<(), Fault> {
        let operation = Arc::clone(&self.operation);
        operation.require_effect()?;
        if self.start_phase != SourceStartPhase::Starting
            || self.socket_directory.is_some()
            || self.socket_ancestors.iter().any(Option::is_some)
            || self.socket_identities.iter().any(Option::is_some)
            || self.socket_mkdir_result.is_some() || self.socket_parent_sync_result.is_some()
            || self.socket_path.as_os_str().as_encoded_bytes() != original_socket_path_bytes(&operation).as_slice()
        {
            return Err(Fault::IntentMismatch);
        }
        let flags = rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
        for index in 0..3 {
            self.reserve_start_fds(1)?;
            operation.require_effect()?;
            let opened = match index {
                0 => rustix::fs::open("/", flags, rustix::fs::Mode::empty()),
                _ => rustix::fs::openat(
                    self.socket_ancestors[index - 1].as_ref().ok_or(Fault::SourceChanged)?,
                    if index == 1 { "private" } else { "tmp" }, flags, rustix::fs::Mode::empty(),
                ),
            };
            match opened {
                Ok(file) => self.socket_ancestors[index] = Some(File::from(file)),
                Err(_) => { operation.require_effect()?; return Err(Fault::IoFailure); }
            }
            operation.require_effect()?;
            self.socket_identities[index] = Some(self.observe_original_socket_directory(index)?);
        }
        let name_bytes = original_socket_name(&operation);
        let name = std::str::from_utf8(&name_bytes).map_err(|_| Fault::PathUnsafe)?;
        // The fixed parent is observed before the first directory allocation. Free space is
        // an admission observation, never an exclusive reservation or a new allowance.
        operation.require_effect()?;
        let available = rustix::fs::fstatvfs(
            self.socket_ancestors[2].as_ref().ok_or(Fault::SourceChanged)?,
        );
        operation.require_effect()?;
        let available = available.map_err(|_| Fault::IoFailure)?;
        let free = available.f_bavail.checked_mul(available.f_frsize).ok_or(Fault::BoundsOverflow)?;
        let carrier = &operation.profile().carrier;
        let native = self.profile.fields();
        let future = carrier.max_total_allocation_bytes.checked_add(native.max_wal_bytes)
            .and_then(|n| n.checked_add(carrier.capacity_reserve_bytes.max(native.capacity_reserve_bytes)))
            .ok_or(Fault::BoundsOverflow)?;
        if free.checked_sub(carrier.free_floor_bytes.max(native.free_floor_bytes))
            .is_none_or(|remaining| remaining < future)
        {
            return Err(Fault::CapacityExceeded);
        }
        // EEXIST is a refusal. No existing directory is opened or adopted.
        operation.require_effect()?;
        self.socket_mkdir_result = Some(rustix::fs::mkdirat(
            self.socket_ancestors[2].as_ref().ok_or(Fault::SourceChanged)?, name,
            rustix::fs::Mode::from_raw_mode(0o700),
        ));
        operation.require_effect()?;
        self.socket_mkdir_result.as_ref().ok_or(Fault::ClosingPending)?
            .as_ref().map_err(|_| Fault::PathUnsafe)?;
        self.reserve_start_fds(1)?;
        operation.require_effect()?;
        let opened = rustix::fs::openat(
            self.socket_ancestors[2].as_ref().ok_or(Fault::SourceChanged)?, name,
            flags, rustix::fs::Mode::empty(),
        );
        match opened {
            Ok(file) => self.socket_directory = Some(File::from(file)),
            Err(_) => { operation.require_effect()?; return Err(Fault::IoFailure); }
        }
        operation.require_effect()?;
        self.socket_identities[3] = Some(self.observe_original_socket_directory(3)?);
        operation.require_effect()?;
        self.socket_parent_sync_result = Some(
            self.socket_ancestors[2].as_ref().ok_or(Fault::SourceChanged)?.sync_all(),
        );
        operation.require_effect()?;
        self.socket_parent_sync_result.as_ref().ok_or(Fault::ClosingPending)?
            .as_ref().map_err(|_| Fault::IoFailure)?;
        self.revalidate_original_socket_directory()
    }

    fn observe_original_socket_directory(
        &self, index: usize,
    ) -> Result<OriginalSocketDirectoryIdentity, Fault> {
        let operation = self.operation.as_ref();
        let file = match index {
            0..=2 => self.socket_ancestors[index].as_ref(),
            3 => self.socket_directory.as_ref(),
            _ => return Err(Fault::IntentMismatch),
        }.ok_or(Fault::SourceChanged)?;
        operation.require_effect()?;
        let held = file.metadata();
        operation.require_effect()?;
        let held = held.map_err(|_| Fault::IoFailure)?;
        let identity = OriginalSocketDirectoryIdentity {
            device: held.dev(), inode: held.ino(), uid: held.uid(), mode: held.mode(),
        };
        let expected_uid = if index == 3 { rustix::process::geteuid().as_raw() } else { 0 };
        let safe_mode = match index {
            0 | 1 => held.mode() & 0o022 == 0,
            2 => held.mode() & 0o7777 == 0o1777,
            _ => held.mode() & 0o7777 == 0o700,
        };
        if !held.is_dir() || held.uid() != expected_uid || !safe_mode {
            return Err(Fault::PathUnsafe);
        }
        if index == 0 {
            operation.require_effect()?;
            let named = std::fs::symlink_metadata("/");
            operation.require_effect()?;
            let named = named.map_err(|_| Fault::IoFailure)?;
            if !named.is_dir() || identity != (OriginalSocketDirectoryIdentity {
                device: named.dev(), inode: named.ino(), uid: named.uid(), mode: named.mode(),
            }) {
                return Err(Fault::SourceChanged);
            }
        } else {
            let name_bytes = original_socket_name(operation);
            let name = match index {
                1 => "private", 2 => "tmp",
                _ => std::str::from_utf8(&name_bytes).map_err(|_| Fault::PathUnsafe)?,
            };
            let parent = self.socket_ancestors[(index - 1).min(2)].as_ref()
                .ok_or(Fault::SourceChanged)?;
            operation.require_effect()?;
            let named = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
            operation.require_effect()?;
            let named = named.map_err(|_| Fault::SourceChanged)?;
            if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
                || identity != (OriginalSocketDirectoryIdentity {
                    device: named.st_dev as u64, inode: named.st_ino as u64,
                    uid: named.st_uid, mode: named.st_mode as u32,
                })
            {
                return Err(Fault::SourceChanged);
            }
        }
        operation.require_effect()?;
        Ok(identity)
    }

    fn revalidate_original_socket_directory(&self) -> Result<(), Fault> {
        self.operation.require_effect()?;
        if !matches!(self.socket_mkdir_result, Some(Ok(())))
            || !matches!(self.socket_parent_sync_result, Some(Ok(())))
        {
            return Err(Fault::ClosingPending);
        }
        for index in 0..4 {
            let actual = self.observe_original_socket_directory(index)?;
            if self.socket_identities[index] != Some(actual) {
                return Err(Fault::SourceChanged);
            }
        }
        self.operation.require_effect()
    }

    /// Pure original source_started DATA. The real source still holds all four FDs.
    pub(crate) fn original_socket_directory_observations(
        &self,
    ) -> Result<((u64, u64), (u64, u64)), Fault> {
        if self.start_phase != SourceStartPhase::Ready
            || !matches!(self.socket_mkdir_result, Some(Ok(())))
            || !matches!(self.socket_parent_sync_result, Some(Ok(())))
            || self.socket_directory.is_none()
            || self.socket_ancestors.iter().any(Option::is_none)
        {
            return Err(Fault::ClosingPending);
        }
        let parent = self.socket_identities[2].ok_or(Fault::ClosingPending)?;
        let child = self.socket_identities[3].ok_or(Fault::ClosingPending)?;
        Ok(((parent.device, parent.inode), (child.device, child.inode)))
    }

    fn revalidate_source_configuration(&self) -> Result<(), Fault> {
        for (index, name) in [SOURCE_MAIN, SOURCE_HBA, SOURCE_IDENT].iter().enumerate() {
            let file = self.start_configuration[index].as_ref().ok_or(Fault::MaterialMissing)?;
            self.operation.require_effect()?;
            let held = file.metadata();
            self.operation.require_effect()?;
            let held = held.map_err(|_| Fault::IoFailure)?;
            self.operation.require_effect()?;
            let named = std::fs::symlink_metadata(self.work_path.join(name));
            self.operation.require_effect()?;
            let named = named.map_err(|_| Fault::IoFailure)?;
            let length = match index { 0 => self.start_main.len() as u64,
                1 => SOURCE_HBA_BYTES.len() as u64, _ => 0 };
            if !held.is_file() || !named.is_file() || held.nlink() != 1
                || held.uid() != rustix::process::geteuid().as_raw()
                || held.mode() & 0o777 != 0o600 || held.len() != length
                || identity(&held) != identity(&named) {
                return Err(Fault::SourceChanged);
            }
        }
        self.operation.require_effect()
    }
    fn reserve_start_fds(&mut self, count: u64) -> Result<(), Fault> {
        let total = self.start_fd_admissions.checked_add(count).ok_or(Fault::BoundsOverflow)?;
        if total > self.profile.fields().max_open_files
            || total > self.operation.profile().carrier.max_open_files {
            return Err(Fault::CapacityExceeded);
        }
        // Known constructor plus material-walk admissions, including the local SQL peer.
        // This is not a whole-operation remainder or PostgreSQL's opaque descriptor census.
        self.operation.reserve_original_resources(count, 0)?;
        self.start_fd_admissions = total;
        Ok(())
    }
    fn reserve_connect_attempt(&mut self) -> Result<(), Fault> {
        let next = self.start_password_admissions.checked_add(1).ok_or(Fault::BoundsOverflow)?;
        let profile = self.operation.profile();
        let class = &profile.secrets.classes.pg_config_passwords;
        let old_known = next.checked_mul(
            (std::mem::size_of::<SourceConnectFailure>() as u64)
                .checked_add(std::mem::size_of::<tokio_postgres::Config>() as u64)
                .and_then(|n| n.checked_add(self.socket_path.as_os_str().as_encoded_bytes().len() as u64))
                .ok_or(Fault::BoundsOverflow)?,
        ).ok_or(Fault::BoundsOverflow)?;
        let io_known = CapturePgIo::checked_metadata_bytes(next)
            .map_err(|_| Fault::BoundsOverflow)?;
        let raw_known = checked_original_source_connect_metadata_bytes(next)?;
        // The old local formula already includes each original Config header once.
        let config_headers = next.checked_mul(std::mem::size_of::<tokio_postgres::Config>() as u64)
            .ok_or(Fault::BoundsOverflow)?;
        let known = old_known.checked_add(io_known).and_then(|n| n.checked_add(raw_known))
            .and_then(|n| n.checked_sub(config_headers)).ok_or(Fault::BoundsOverflow)?;
        if class.max_one_bytes < 64 || next > class.max_count
            || known > profile.drivers.max_owner_metadata_bytes
            || known > profile.carrier.max_metadata_bytes
            || profile.drivers.max_pending_connects < 1
            || profile.drivers.max_live_original_tasks < 3
            || profile.drivers.max_unjoined_original_tasks < 3 {
            return Err(Fault::CapacityExceeded);
        }
        self.connection_failures.try_reserve_exact(1).map_err(|_| Fault::CapacityExceeded)?;
        // No retry refunds. Opaque SASL/PG/error allocations remain a separate HOLD.
        let new_known = CapturePgIo::checked_metadata_bytes(1)
            .map_err(|_| Fault::BoundsOverflow)?
            .checked_add(checked_original_source_connect_metadata_bytes(1)?)
            .ok_or(Fault::BoundsOverflow)?;
        self.operation.reserve_original_resources(0, new_known)?;
        self.start_password_admissions = next;
        self.reserve_start_fds(2)
    }
    fn observe_start_child(&mut self) -> Result<(), Fault> {
        let operation = Arc::clone(&self.operation);
        operation.require_effect()?;
        if self.start_child_exit.is_some() { return Err(Fault::SourceChanged); }
        let observed = self.postmaster.as_mut().ok_or(Fault::SourceChanged)?
            .original_child_mut().try_wait();
        match observed {
            Ok(status) => self.start_child_exit = status,
            Err(_) => { operation.require_effect()?; return Err(Fault::IoFailure); }
        }
        operation.require_effect()?;
        if self.start_child_exit.is_some() { return Err(Fault::SourceChanged); }
        let identity = self.postmaster_identity.as_ref().ok_or(Fault::SourceChanged)?;
        operation.require_effect()?;
        let current = identity.revalidate();
        operation.require_effect()?;
        current.map_err(|_| Fault::SourceChanged)?;
        Ok(())
    }
    async fn connect_original_ready(&mut self, port: u16) -> Result<(), Fault> {
        let operation = Arc::clone(&self.operation);
        loop {
            operation.require_effect()?;
            self.observe_start_child()?;
            self.native_capacity_check().map_err(map_maintenance)?;
            self.reserve_connect_attempt()?;
            self.native_fd_budget(2).map_err(map_maintenance)?;
            // Check the original runtime before transferring the real connection future.
            let runtime = tokio::runtime::Handle::try_current().map_err(|_| Fault::ClosingPending)?;
            let mut config = tokio_postgres::Config::new();
            config.host_path(&self.socket_path).port(port)
                .user(openbot_contracts::desktop::DESKTOP_LOCAL_POSTGRES_ADMIN_USER)
                .dbname("postgres").password(self.native_secret().expose());
            let next_started = self.original_connect_tasks_started.checked_add(1)
                .ok_or(Fault::BoundsOverflow)?;
            operation.require_effect()?;
            let decode = self.permit.materials_mut()?.original_decode_budget();
            let prepared = CapturePgIo::prepare(&config, decode);
            operation.require_effect()?;
            let original_io = prepared.map_err(|_| Fault::CapacityExceeded)?;
            self.connecting = Some(runtime.spawn(original_capture_connect(Some((config, original_io)))));
            self.original_connect_tasks_started = next_started;
            operation.require_effect()?;
            loop {
                self.observe_start_child()?;
                operation.require_effect()?;
                let wait = std::time::Duration::from_nanos(operation.effect_remaining_ns()?)
                    .min(std::time::Duration::from_millis(100));
                let observed = {
                    let original = self.connecting.as_mut().ok_or(Fault::SourceChanged)?;
                    tokio::select! { result = original => Some(result), _ = tokio::time::sleep(wait) => None }
                };
                if let Some(result) = observed {
                    self.connection_result = Some(result);
                    self.original_connect_tasks_joined = self.original_connect_tasks_joined
                        .checked_add(1).ok_or(Fault::BoundsOverflow)?;
                    // Only remove the completed handle after the result is safely resident.
                    self.connecting.take();
                }
                operation.require_effect()?;
                if self.connection_result.is_some() { break; }
            }
            let result = self.connection_result.take().ok_or(Fault::SourceChanged)?;
            match result {
                Ok(Ok((client, connection))) => {
                    self.sql_client = Some(client);
                    self.sql_driver = Some(runtime.spawn(connection));
                    operation.require_effect()?;
                    self.observe_start_child()?;
                    if self.sql_driver.as_ref().is_none_or(JoinHandle::is_finished) {
                        return Err(Fault::SourceChanged);
                    }
                    return Ok(());
                }
                Ok(Err(error)) => {
                    let retry = retryable_source_connect(&error);
                    self.connection_failures.push(SourceConnectFailure::Postgres(error));
                    operation.require_effect()?;
                    if !retry { return Err(Fault::SourceChanged); }
                    self.observe_start_child()?;
                    let wait = std::time::Duration::from_nanos(operation.effect_remaining_ns()?)
                        .min(std::time::Duration::from_millis(20));
                    tokio::time::sleep(wait).await;
                    operation.require_effect()?;
                }
                Err(error) => {
                    self.connection_failures.push(SourceConnectFailure::Join(error));
                    operation.require_effect()?;
                    return Err(Fault::ClosingPending);
                }
            }
        }
    }
    fn work_directory(&self) -> Result<&File, Fault> {
        self.work_directory.as_ref().ok_or(Fault::SourceChanged)
    }
    fn socket_directory(&self) -> Result<&File, Fault> {
        self.socket_directory.as_ref().ok_or(Fault::SourceChanged)
    }

    pub(crate) fn shared_operation(&self) -> Arc<CaptureOperation> {
        Arc::clone(&self.operation)
    }
    pub(super) fn native_clock(&self) -> &OperationClock {
        self.operation.original_clock()
    }
    pub(super) fn native_profile(&self) -> &MaintenanceProfile {
        &self.profile
    }
    pub(super) fn native_bundle(&self) -> &VerifiedMaintenanceBundle {
        &self.operation.reviewed().maintenance
    }
    pub(super) fn native_operation(&self) -> [u8; 16] {
        self.operation.operation_id()
    }
    pub(super) fn native_port(&self) -> Result<u16, MaintenanceError> {
        let port = self.permit.stopped().map_err(map_fault)?.port();
        if port == 0 {
            return Err(MaintenanceError::InvalidArguments);
        }
        Ok(port)
    }
    pub(super) fn native_secret(&self) -> &Arc<SecretBytes> {
        self.secret
            .as_ref()
            .expect("actual active source retains its original SCRAM allocation")
    }
    pub(super) fn native_root(&self) -> &Path {
        &self.work_path
    }
    pub(super) fn native_output(&self) -> &Path {
        &self.output_path
    }
    pub(super) fn native_socket(&self) -> &Path {
        &self.socket_path
    }
    fn retain_original_postmaster_identity(&mut self) -> Result<(), Fault> {
        self.operation.require_effect()?;
        if self.postmaster_identity.is_some() || self.postmaster_birth.is_some() {
            return Err(Fault::IntentMismatch);
        }
        let owner = self.postmaster.as_ref().ok_or(Fault::SourceChanged)?;
        let actual = wrok_bot_macos_process::ProcessIdentity::capture(owner.original_pid());
        match actual {
            Ok(identity) => self.postmaster_identity = Some(identity),
            Err(_) => { self.operation.require_effect()?; return Err(Fault::SourceChanged); }
        }
        self.operation.require_effect()?;
        let identity = self.postmaster_identity.as_ref().ok_or(Fault::SourceChanged)?;
        self.operation.require_effect()?;
        let birth = identity.evidence_bytes();
        match birth {
            Ok(birth) => self.postmaster_birth = Some(birth),
            Err(_) => { self.operation.require_effect()?; return Err(Fault::SourceChanged); }
        }
        self.operation.require_effect()?;
        let actual = identity.revalidate();
        self.operation.require_effect()?;
        actual.map_err(|_| Fault::SourceChanged)
    }
    pub(super) fn native_owner(&self) -> &Option<runner::NativeOwner> {
        &self.native
    }
    pub(super) fn native_owner_mut(&mut self) -> &mut Option<runner::NativeOwner> {
        &mut self.native
    }
    pub(super) fn native_and_clock(
        &mut self,
    ) -> (&mut Option<runner::NativeOwner>, &OperationClock) {
        (&mut self.native, self.operation.original_clock())
    }
    pub(super) fn validate_native_request(
        &self,
        output: &Path,
        socket: &Path,
        index: usize,
    ) -> Result<(), MaintenanceError> {
        self.operation.require_effect().map_err(map_fault)?;
        self.permit
            .revalidate_original(&self.operation)
            .map_err(map_fault)?;
        if self.start_phase != SourceStartPhase::Ready
            || index != 0
            || self.postmaster.is_none()
            || self.closed.is_some()
            || output != self.output_path
            || socket != self.socket_path
        {
            return Err(MaintenanceError::InvalidArguments);
        }
        // Preserve the original exists predicate, including its std error-to-false policy.
        // This envelope does not certify opaque helper-internal IO or source authority.
        self.operation.require_effect().map_err(map_fault)?;
        let output_exists = output.exists();
        self.operation.require_effect().map_err(map_fault)?;
        if output_exists || output.parent() != Some(self.work_path.as_path()) {
            return Err(MaintenanceError::InvalidArguments);
        }
        checked_directory(self.work_directory().map_err(map_fault)?, &self.work_path, &self.operation)
            .map_err(map_fault)?;
        checked_directory(self.socket_directory().map_err(map_fault)?, &self.socket_path, &self.operation)
            .map_err(map_fault)?;
        self.revalidate_original_socket_directory().map_err(map_fault)?;
        Ok(())
    }
    pub(super) fn native_fd_budget(&self, additional: u64) -> Result<(), MaintenanceError> {
        let native = u64::from(self.native.as_ref().is_some_and(|n| !n.physically_closed()));
        let known = 10u64
            .checked_add(u64::from(self.postmaster.is_some()) * 2)
            .and_then(|n| n.checked_add(u64::from(self.stop_helper.is_some()) * 2))
            .and_then(|n| n.checked_add(u64::from(self.sql_driver.is_some())))
            .and_then(|n| n.checked_add(u64::from(self.connecting.is_some())))
            .and_then(|n| n.checked_add(native * 3))
            .and_then(|n| n.checked_add(self.start_configuration.iter().filter(|file| file.is_some()).count() as u64))
            .and_then(|n| n.checked_add(u64::from(self.source_data_directory.is_some())))
            .and_then(|n| n.checked_add(u64::from(self.source_wal_directory.is_some())))
            .and_then(|n| n.checked_add(u64::from(self.source_tablespace_directory.is_some())))
            .and_then(|n| n.checked_add(u64::from(self.source_tablespace_scan.is_some())))
            // Slots remain charged after a raw final File moves to the original audit owner.
            .and_then(|n| n.checked_add(self.material_fd_slots.len() as u64))
            .and_then(|n| n.checked_add(self.provenance_files.iter().filter(|file| file.is_some()).count() as u64))
            .and_then(|n| n.checked_add(self.socket_ancestors.iter().filter(|file| file.is_some()).count() as u64))
            .and_then(|n| n.checked_add(additional))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        if known > self.profile.fields().max_open_files
            || known > self.operation.profile().carrier.max_open_files
        {
            return Err(MaintenanceError::CapacityExceeded);
        }
        Ok(())
    }

    pub(super) fn native_capacity_check(&mut self) -> Result<(), MaintenanceError> {
        self.operation.require_effect().map_err(map_fault)?;
        checked_directory(self.work_directory().map_err(map_fault)?, &self.work_path, &self.operation)
            .map_err(map_fault)?;
        checked_directory(self.socket_directory().map_err(map_fault)?, &self.socket_path, &self.operation)
            .map_err(map_fault)?;
        self.revalidate_original_socket_directory().map_err(map_fault)?;
        let p = self.profile.fields();
        let maximum_nodes = p
            .max_material_files
            .checked_add(p.max_directories)
            .and_then(|n| n.checked_add(8))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        self.operation.require_effect().map_err(map_fault)?;
        let observed_allocation = runner::allocated_tree(&self.work_path, maximum_nodes);
        self.operation.require_effect().map_err(map_fault)?;
        // Necessary outer envelope only; the existing walker has its own internal-IO gap.
        let allocated = observed_allocation?;
        self.operation.require_effect().map_err(map_fault)?;
        let socket_metadata = self.socket_directory().map_err(map_fault)?.metadata();
        self.operation.require_effect().map_err(map_fault)?;
        let socket_metadata = socket_metadata.map_err(|_| MaintenanceError::IoFailure)?;
        self.operation.require_effect().map_err(map_fault)?;
        let work_metadata = self.work_directory().map_err(map_fault)?.metadata();
        self.operation.require_effect().map_err(map_fault)?;
        let work_metadata = work_metadata.map_err(|_| MaintenanceError::IoFailure)?;
        if (socket_metadata.dev(), socket_metadata.ino()) == (work_metadata.dev(), work_metadata.ino()) {
            return Err(MaintenanceError::InvalidArguments);
        }
        // allocated_tree covers only the original operation spool. The fixed external
        // socket directory is a distinct actual object, added once, never RAM or wire bytes.
        let allocated = socket_metadata.blocks().checked_mul(512)
            .and_then(|n| allocated.checked_add(n))
            .ok_or(MaintenanceError::CapacityExceeded)?;
        let carrier = &self.operation.profile().carrier;
        if allocated > carrier.max_spool_bytes || allocated > carrier.max_total_allocation_bytes {
            return Err(MaintenanceError::CapacityExceeded);
        }
        let future = carrier
            .max_total_allocation_bytes
            .checked_sub(allocated)
            .and_then(|n| n.checked_add(p.max_wal_bytes))
            .and_then(|n| {
                n.checked_add(carrier.capacity_reserve_bytes.max(p.capacity_reserve_bytes))
            })
            .ok_or(MaintenanceError::CapacityExceeded)?;
        for file in [self.work_directory().map_err(map_fault)?, self.socket_directory().map_err(map_fault)?] {
            self.operation.require_effect().map_err(map_fault)?;
            let observed = rustix::fs::fstatvfs(file);
            self.operation.require_effect().map_err(map_fault)?;
            let fs = observed.map_err(|_| MaintenanceError::IoFailure)?;
            let free = fs
                .f_bavail
                .checked_mul(fs.f_frsize)
                .ok_or(MaintenanceError::CapacityExceeded)?;
            if free
                .checked_sub(carrier.free_floor_bytes.max(p.free_floor_bytes))
                .is_none_or(|remaining| remaining < future)
            {
                return Err(MaintenanceError::CapacityExceeded);
            }
        }
        Ok(())
    }

    /// The original source keeps all worker inputs and actual results resident.
    pub(crate) async fn freeze_original_audit_material(
        &mut self,
        operation: &Arc<CaptureOperation>,
        range: (String, String, u32, u32),
    ) -> Result<(String, String, u32, u32), Fault> {
        if !Arc::ptr_eq(&self.operation, operation)
            || self.metadata_work.is_some() || self.metadata_task.is_some()
            || self.metadata_joined.is_some()
        {
            return Err(Fault::IntentMismatch);
        }
        self.require_sources_closed()?;
        self.permit.revalidate_original(operation)?;
        if self.original_driver_material.is_some() || self.original_provenance_material.is_some() {
            return Err(Fault::IntentMismatch);
        }
        self.original_driver_material = Some(
            crate::tauri_background::capture::original_closed_driver_material(
                self.closed_driver_facts()?, operation.as_ref(),
            )?,
        );
        self.original_provenance_material = Some(self.capture_provenance_material()?);
        self.permit.materials_mut()?.retain_original_auxiliary_materials(
            &mut self.original_provenance_material, &mut self.original_driver_material,
        )?;
        self.permit.materials_mut()?.begin_original_audit_material()?;
        let originals = self.take_closed_material_files()?;
        self.material_files = Some(originals);
        if self.work_directory.is_none() || self.work_path.as_os_str().is_empty() {
            return Err(Fault::SourceChanged);
        }
        // One requested ArcInner<Mutex<Work>>, original Source's new field/result
        // slots and the actual closure/runtime handle. Existing FD/payload/range
        // allocations move; none is cloned or re-admitted here.
        let allocation = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<std::sync::Mutex<OriginalMetadataWork>>())
            .map_err(|_| Fault::BoundsOverflow)?.0.pad_to_align().size();
        let known = [
            allocation,
            std::mem::size_of::<Option<Arc<std::sync::Mutex<OriginalMetadataWork>>>>(),
            std::mem::size_of::<Option<JoinHandle<OriginalMetadataCompletion>>>(),
            std::mem::size_of::<Option<OriginalMetadataJoin>>(),
            std::mem::size_of::<OriginalMetadataCompletion>(),
            std::mem::size_of::<Option<Box<dyn std::any::Any + Send + 'static>>>(),
            std::mem::size_of::<std::sync::MutexGuard<'_, OriginalMetadataWork>>(),
            std::mem::size_of::<std::sync::LockResult<std::sync::MutexGuard<'_, OriginalMetadataWork>>>(),
            std::mem::size_of::<Result<Result<OriginalMetadataCompletion, Fault>, Box<dyn std::any::Any + Send + 'static>>>(),
            // Synchronous inner worker slots exist before its async future is charged.
            std::mem::size_of::<Result<Result<(), Fault>, Box<dyn std::any::Any + Send + 'static>>>(),
            std::mem::size_of::<Result<(), Fault>>(),
            std::mem::size_of::<Result<(u64, u64), Fault>>(),
            std::mem::size_of::<OriginalMetadataCompletion>(),
            std::mem::size_of::<Result<OriginalMetadataCompletion, Fault>>(),
            // Seven separate borrowed captures of the inner catch closure.
            std::mem::size_of::<&mut NormalCaptureMaterials>(),
            std::mem::size_of::<&mut Option<Vec<CaptureOwnedMaterialFile>>>(),
            std::mem::size_of::<&File>(),
            std::mem::size_of::<&std::path::Path>(),
            std::mem::size_of::<&(String, String, u32, u32)>(),
            std::mem::size_of::<&Arc<CaptureOperation>>(),
            std::mem::size_of::<&tokio::runtime::Handle>(),
            // Outer catch borrows these independently of the spawn move captures.
            std::mem::size_of::<&mut std::sync::MutexGuard<'_, OriginalMetadataWork>>(),
            std::mem::size_of::<&Arc<CaptureOperation>>(),
            std::mem::size_of::<&tokio::runtime::Handle>(),
            // Closure's three separately moved captures.
            std::mem::size_of::<Arc<std::sync::Mutex<OriginalMetadataWork>>>(),
            std::mem::size_of::<Arc<CaptureOperation>>(),
            std::mem::size_of::<tokio::runtime::Handle>(),
        ].into_iter().try_fold(0usize, |n, size| n.checked_add(size).ok_or(Fault::BoundsOverflow))?;
        operation.reserve_original_resources(0, u64::try_from(known).map_err(|_| Fault::BoundsOverflow)?)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| Fault::ClosingPending)?;
        self.metadata_work = Some(Arc::new(std::sync::Mutex::new(OriginalMetadataWork {
            materials: None, originals: None, directory: None, path: None, range: None,
            returned: None, panic: None,
        })));
        {
            let slot = self.metadata_work.as_ref().expect("original metadata slot installed");
            let mut work = slot.lock().map_err(|_| Fault::ClosingPending)?;
            // This fallible original take precedes all other ownership moves.
            work.materials = Some(self.permit.take_materials()?);
            work.originals = self.material_files.take();
            work.directory = self.work_directory.take();
            work.path = Some(std::mem::take(&mut self.work_path));
            work.range = Some(range);
        }
        let slot = Arc::clone(self.metadata_work.as_ref().expect("original metadata slot retained"));
        let clock = Arc::clone(operation);
        self.metadata_task = Some(tokio::task::spawn_blocking(move || {
            let mut work = match slot.lock() {
                Ok(work) => work,
                Err(poisoned) => {
                    let mut work = poisoned.into_inner();
                    let result = (Err(Fault::ClosingPending), Err(Fault::ClosingPending));
                    work.returned = Some(result);
                    return result;
                }
            };
            // The guard and all original owners are outside this borrowed body.
            // The method's inner catch retains actual body panic and snapshot DATA;
            // this outer catch also covers preparation before that borrow begins.
            let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let OriginalMetadataWork { materials, originals, directory, path, range, panic, .. } = &mut *work;
                let materials = materials.as_mut().ok_or(Fault::MaterialMissing)?;
                let directory = directory.as_ref().ok_or(Fault::MaterialMissing)?;
                let path = path.as_ref().ok_or(Fault::MaterialMissing)?;
                let range = range.as_ref().ok_or(Fault::MaterialMissing)?;
                Ok::<_, Fault>(materials.run_original_metadata_worker(
                    originals, directory, path, range, &clock, &runtime, panic,
                ))
            }));
            let result = match returned {
                Ok(Ok(result)) => result,
                Ok(Err(fault)) => (Err(fault), Err(Fault::ClosingPending)),
                Err(payload) => {
                    work.panic = Some(payload);
                    (Err(Fault::ClosingPending), Err(Fault::ClosingPending))
                }
            };
            work.returned = Some(result);
            result
        }));
        // No original is solely in the closure; handle and source slot precede
        // the first postcheck/borrowed wait. There is no abort or restart path.
        operation.require_effect()?;
        let remaining = operation.effect_remaining_ns()?;
        let waited = tokio::time::timeout(
            std::time::Duration::from_nanos(remaining),
            self.metadata_task.as_mut().expect("original metadata handle retained"),
        ).await;
        let actual = match waited {
            Err(_) => {
                operation.require_effect()?;
                // In particular, do not lock a mutex still held by the worker.
                return Err(Fault::ClosingPending);
            }
            Ok(actual) => actual,
        };
        self.metadata_joined = Some(actual);
        self.metadata_task.take();
        operation.require_effect()?;
        let completed = match self.metadata_joined.as_ref().expect("actual metadata join resident") {
            Ok(completed) => *completed,
            Err(_) => return Err(Fault::ClosingPending),
        };
        completed.0?;
        let snapshot = completed.1?;
        if snapshot != (1, 1) {
            return Err(Fault::ClosingPending);
        }
        // A genuine completed join precedes this lock. No timeout/JoinError/body
        // refusal path above ever locks the possibly active original worker.
        let slot = self.metadata_work.as_ref().expect("original metadata slot retained");
        let mut work = slot.lock().map_err(|_| Fault::ClosingPending)?;
        if work.returned != Some(completed) || work.panic.is_some()
            || work.materials.is_none() || work.directory.is_none()
            || work.path.is_none() || work.range.is_none() || work.originals.is_some()
            || self.work_directory.is_some() || !self.work_path.as_os_str().is_empty()
        {
            return Err(Fault::IntentMismatch);
        }
        let materials = work.materials.take().expect("checked original material state retained");
        if let Err(materials) = self.permit.restore_materials(materials) {
            work.materials = Some(materials);
            return Err(Fault::IntentMismatch);
        }
        // Original restore returned successfully. All remaining takes are pure.
        self.work_directory = work.directory.take();
        self.work_path = work.path.take().expect("checked original path retained");
        Ok(work.range.take().expect("checked original range retained"))
    }

    pub(crate) fn capture_sql_client(&mut self) -> Result<&mut Client, Fault> {
        self.operation.require_effect()?;
        if self.start_phase != SourceStartPhase::Ready
            || self.closed.is_some()
            || self.sql_driver_result.is_some()
            || self.sql_driver.as_ref().is_none_or(JoinHandle::is_finished)
        {
            return Err(Fault::SourceChanged);
        }
        self.sql_client.as_mut().ok_or(Fault::SourceChanged)
    }
    pub(crate) fn capture_sql_and_materials(
        &mut self,
    ) -> Result<(&mut Client, &mut NormalCaptureMaterials), Fault> {
        self.operation.require_effect()?;
        if self.start_phase != SourceStartPhase::Ready
            || self.closed.is_some()
            || self.sql_driver_result.is_some()
            || self.sql_driver.as_ref().is_none_or(JoinHandle::is_finished)
        {
            return Err(Fault::SourceChanged);
        }
        Ok((
            self.sql_client.as_mut().ok_or(Fault::SourceChanged)?,
            self.permit.materials_mut()?,
        ))
    }
    pub(crate) fn materials_mut(&mut self) -> Result<&mut NormalCaptureMaterials, Fault> {
        self.permit.materials_mut()
    }
    pub(crate) fn take_materials(&mut self) -> Result<NormalCaptureMaterials, Fault> {
        self.permit.take_materials()
    }
    pub(crate) fn store_materials(
        &mut self,
        materials: NormalCaptureMaterials,
    ) -> Result<(), NormalCaptureMaterials> {
        self.permit.restore_materials(materials)
    }
    pub(crate) fn capture_vault(&self) -> Result<&crate::desktop_vault::ArmedCaptureVault, Fault> {
        self.permit.vault()
    }

    /// Pure observations of this same maintenance source's original tasks.
    /// This grants no IO, source, clock, normal-driver or outer-completion authority.
    pub(crate) fn original_source_task_observations(&self) -> Result<(u64, u64, u64), Fault> {
        fn add(left: u64, right: u64) -> Result<u64, Fault> {
            left.checked_add(right).ok_or(Fault::BoundsOverflow)
        }
        fn closed_program(observation: &runner::ToolObservation) -> Result<(u64, u64), Fault> {
            let (child, input, output, error) = observation.original_wait_and_pipe_join_ok();
            // The two source spawn_program calls use write_secret=false. Each healthy
            // original owns its Child and two actual output/error reader tasks, no writer.
            if !observation.closed_success() || !child || input.is_some() || !output || !error {
                return Err(Fault::ClosingPending);
            }
            Ok((3, add(add(u64::from(child), u64::from(output))?, u64::from(error))?))
        }
        if self.start_phase != SourceStartPhase::Ready
            || self.borrowed_panic.is_some()
            || self.connecting.is_some()
            || self.connection_result.is_some()
            || self.original_connect_tasks_started == 0
            || self.original_connect_tasks_joined != self.original_connect_tasks_started
            || self.connection_failures.iter().any(|failure| matches!(failure, SourceConnectFailure::Join(_)))
        {
            return Err(Fault::ClosingPending);
        }
        // Every failed retry is the retained original Ok(Err(Postgres)) join result;
        // the final authenticated connection has its real Client/driver or closed result below.
        let failed = u64::try_from(self.connection_failures.len()).map_err(|_| Fault::BoundsOverflow)?;
        if add(failed, 1)? != self.original_connect_tasks_started {
            return Err(Fault::IntentMismatch);
        }
        let mut original = self.original_connect_tasks_started;
        let mut joined = self.original_connect_tasks_joined;
        if let Some(closed) = &self.closed {
            if self.postmaster.is_some() || self.stop_helper.is_some()
                || self.sql_client.is_some() || self.sql_driver.is_some()
                || self.postmaster_observation.is_some() || self.stop_observation.is_some()
                || self.start_child_exit.is_some()
                || self.sql_driver_result != Some(Ok(())) || closed.sql_driver_result.is_err()
            {
                return Err(Fault::ClosingPending);
            }
            let (created, waited) = closed_program(&closed.postmaster)?;
            original = add(original, created)?;
            joined = add(joined, waited)?;
            if let Some(helper) = &closed.stop_helper {
                let (created, waited) = closed_program(helper)?;
                original = add(original, created)?;
                joined = add(joined, waited)?;
            } else if !matches!(self.postmaster_retirement, Some(Ok(()))) {
                // Absence is not a helper-closure result. Only the recorded exact
                // original postmaster retirement branch explains no helper creation.
                return Err(Fault::ClosingPending);
            }
            // This is the stored result of awaiting the one original authenticated SQL driver.
            original = add(original, 1)?;
            joined = add(joined, 1)?;
            let native = self.native.as_ref().ok_or(Fault::ClosingPending)?;
            let receipt = self.native_receipt.as_ref().ok_or(Fault::ClosingPending)?;
            let (child, pipes, worker_created, worker_waited) =
                receipt.original_wait_pipe_worker_observations();
            if !native.physically_closed() || self.physical.is_none()
                || !child || pipes.iter().any(|joined| !*joined)
                || !worker_created || !worker_waited
            {
                return Err(Fault::ClosingPending);
            }
            // The original native Child, three original pipe tasks, and its actually
            // created PostgreSQL worker each keep separate creation/wait evidence.
            original = add(original, add(4, u64::from(worker_created))?)?;
            let pipe_joins = pipes.into_iter().try_fold(0u64, |n, joined| add(n, u64::from(joined)))?;
            joined = add(joined, add(add(u64::from(child), pipe_joins)?, u64::from(worker_waited))?)?;
        } else {
            let postmaster = self.postmaster.as_ref().ok_or(Fault::ClosingPending)?;
            if postmaster.original_pid() == 0
                || postmaster.original_pipe_handles() != [false, true, true]
                || self.postmaster_identity.is_none() || self.postmaster_birth.is_none()
                || self.start_child_exit.is_some() || self.postmaster_retirement.is_some()
                || self.sql_client.is_none() || self.sql_driver.is_none()
                || self.sql_driver_result.is_some()
                || self.stop_helper.is_some() || self.stop_observation.is_some()
                || self.postmaster_observation.is_some()
                || self.native.is_some() || self.native_receipt.is_some() || self.physical.is_some()
            {
                return Err(Fault::ClosingPending);
            }
            // These are still-live original Child/readers/SQL-driver handles, not joins.
            // ProgramOwner retains each original reader handle, even if it has finished.
            original = add(original, 4)?;
        }
        // Only this original Source's actual worker handle/JoinResult supplies
        // these additional counts. Never lock its active work slot or infer a
        // join from is_finished. Closed local unissued snapshot is explicit DATA.
        match (&self.metadata_work, &self.metadata_task, &self.metadata_joined) {
            (None, None, None) => {}
            (Some(_), None, Some(Ok((_, Ok((snapshot_original, snapshot_joined)))))) => {
                if snapshot_joined > snapshot_original {
                    return Err(Fault::IntentMismatch);
                }
                original = add(original, add(1, *snapshot_original)?)?;
                joined = add(joined, add(1, *snapshot_joined)?)?;
            }
            _ => return Err(Fault::ClosingPending),
        }
        if joined > original {
            return Err(Fault::IntentMismatch);
        }
        // This closed source implementation creates only the original handles enumerated
        // above. Its caller observes the actual returned phase; it creates no proxy
        // observer task/future owner. The local zero follows these exact original checks,
        // and is not borrowed from normal-driver facts or generalized to outer workers.
        Ok((original, joined, 0))
    }

    pub(crate) fn closed_driver_facts(
        &self,
    ) -> Result<&crate::tauri_background::capture::DriverClosureFacts, Fault> {
        self.operation.require_effect()?;
        self.permit.closed_driver_facts()
    }

    /// A bounded projection of the original authenticated bundle, not a new tool scan.
    pub(crate) fn capture_provenance_material(
        &mut self,
    ) -> Result<
        (
            openbot_domain::backup::whole_pg_carrier::WholePgProvenanceClaim,
            Vec<u8>,
        ),
        Fault,
    > {
        self.operation.require_effect()?;
        if self.provenance_open_entered { return Err(Fault::IntentMismatch); }
        self.provenance_open_entered = true;
        let operation = Arc::clone(&self.operation);
        let reviewed = operation.reviewed();
        // The six original 64-byte receipt fields are authenticated by the retained bundle.
        // JSON's fixed field names/scalars fit 1024 bytes; its Vec old+new peak is <=3072.
        // Charge known simultaneous receipt/identity/loop/result slots before the first copy.
        let fixed = (std::mem::size_of::<super::bundle::BundleVerificationReceipt>() as u64)
            .checked_add(std::mem::size_of::<AuthenticatedBundleReceipt>() as u64)
            .and_then(|n| n.checked_add(6 * 64 * 2 + 64 + 3 * 1024))
            .and_then(|n| n.checked_add(std::mem::size_of::<[Option<std::fs::Metadata>; 3]>() as u64))
            .and_then(|n| n.checked_add((std::mem::size_of::<std::fs::Metadata>() as u64).checked_mul(6)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<std::fs::Metadata, std::io::Error>>() as u64).checked_mul(3)?))
            .and_then(|n| n.checked_add((std::mem::size_of::<rustix::fs::Stat>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<[(usize, usize, &str, bool); 2]>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::slice::Iter<'_, (usize, usize, &str, bool)>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<&(usize, usize, &str, bool)>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<(usize, usize, &str, bool)>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::iter::Enumerate<std::slice::Iter<'_, Option<std::fs::Metadata>>>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<(usize, &Option<std::fs::Metadata>)>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<(usize, &Option<std::fs::Metadata>)>() as u64))
            .and_then(|n| n.checked_add((std::mem::size_of::<(u64, u64, u32, u32, u64, u64, i64, i64, i64, i64)>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<CaptureToolInventory>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<AuthenticatedBundleReceipt, serde_json::Error>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<AuthenticatedToolInventory, serde_json::Error>>() as u64))
            .and_then(|n| n.checked_add((std::mem::size_of::<Result<Vec<u8>, serde_json::Error>>() as u64).checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<Vec<u8>, Fault>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<usize, std::io::Error>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<serde_json::Serializer<&mut Vec<u8>>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<[&String; 8]>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::array::IntoIter<&String, 8>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::slice::Iter<'_, AuthenticatedFile>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<std::slice::Iter<'_, AuthenticatedTool>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<&AuthenticatedFile>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<&AuthenticatedTool>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Option<(openbot_domain::backup::whole_pg_carrier::WholePgProvenanceClaim, Vec<u8>)>>() as u64))
            .and_then(|n| n.checked_add("tool-inventory".len() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Sha256>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fd::OwnedFd, rustix::io::Errno>>() as u64))
            .and_then(|n| n.checked_add(std::mem::size_of::<Result<(), Fault>>() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        operation.reserve_original_resources(0, fixed)?;
        let receipt_bytes = serde_json::to_vec(&reviewed.maintenance.verification_receipt())
            .map_err(|_| Fault::ManifestInvalid)?;
        if receipt_bytes.len() > 1024 || receipt_bytes.capacity() > 2048 {
            return Err(Fault::CapacityExceeded);
        }
        let receipt: AuthenticatedBundleReceipt =
            serde_json::from_slice(&receipt_bytes).map_err(|_| Fault::ManifestInvalid)?;
        if receipt.schema != "wrokbot-pg-maintenance-verification"
            || receipt.schema_version != 1
            || receipt.program_count != 4
            || !receipt.source_authenticated
            || receipt.platform_signature_verified
            || receipt.production_release_authorized
            || decode_sha(&receipt.outer_sha256)? != reviewed.maintenance_digest
        {
            return Err(Fault::SourceChanged);
        }
        // Only the returned bundle root and the two fixed-path descriptors are known here.
        // The original bundle helper's internal FD/E behavior remains opaque, not credited as three.
        self.native_fd_budget(3).map_err(map_maintenance)?;
        self.reserve_start_fds(3)?;
        operation.require_effect()?;
        let observed_directory = super::bundle::open_directory(reviewed.maintenance.root());
        match observed_directory {
            Ok(directory) => self.provenance_files[0] = Some(directory),
            Err(error) => { operation.require_effect()?; return Err(map_maintenance(error)); }
        }
        operation.require_effect()?;
        let mut original_identity: [Option<std::fs::Metadata>; 3] = [None, None, None];
        {
            let root = self.provenance_files[0].as_ref().ok_or(Fault::MaterialMissing)?;
            operation.require_effect()?;
            let observed_held = root.metadata();
            operation.require_effect()?;
            let held = observed_held.map_err(|_| Fault::IoFailure)?;
            operation.require_effect()?;
            let observed_named = std::fs::symlink_metadata(reviewed.maintenance.root());
            operation.require_effect()?;
            let named = observed_named.map_err(|_| Fault::IoFailure)?;
            if !held.is_dir() || !named.is_dir() || identity(&held) != identity(&named) {
                return Err(Fault::SourceChanged);
            }
            original_identity[0] = Some(held);
        }
        // Fixed original manifest path: no generic walker, root clone or temporary File owner.
        let steps: [(usize, usize, &str, bool); 2] = [
            (0, 1, "postgres-maintenance", false), (1, 2, "manifest.json", true),
        ];
        for &(parent, slot, name, last) in &steps {
            operation.require_effect()?;
            let observed_named = rustix::fs::statat(
                self.provenance_files[parent].as_ref().ok_or(Fault::MaterialMissing)?,
                name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            );
            operation.require_effect()?;
            let named = observed_named.map_err(|_| Fault::PathUnsafe)?;
            let named_len = u64::try_from(named.st_size).map_err(|_| Fault::PathUnsafe)?;
            let expected_type = if last { rustix::fs::FileType::RegularFile }
                else { rustix::fs::FileType::Directory };
            if rustix::fs::FileType::from_raw_mode(named.st_mode) != expected_type
                || (last && named.st_nlink != 1) {
                return Err(Fault::PathUnsafe);
            }
            let flags = rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK
                | if last { rustix::fs::OFlags::empty() } else { rustix::fs::OFlags::DIRECTORY };
            operation.require_effect()?;
            let observed = rustix::fs::openat(
                self.provenance_files[parent].as_ref().ok_or(Fault::MaterialMissing)?,
                name, flags, rustix::fs::Mode::empty(),
            );
            match observed {
                Ok(file) => self.provenance_files[slot] = Some(File::from(file)),
                Err(_) => { operation.require_effect()?; return Err(Fault::PathUnsafe); }
            }
            operation.require_effect()?;
            let file = self.provenance_files[slot].as_ref().ok_or(Fault::MaterialMissing)?;
            operation.require_effect()?;
            let observed_held = file.metadata();
            operation.require_effect()?;
            let held = observed_held.map_err(|_| Fault::IoFailure)?;
            if (last && (!held.is_file() || held.nlink() != 1)) || (!last && !held.is_dir())
                || identity(&held)
                    != (named.st_dev as u64, named.st_ino, named.st_uid,
                        u32::from(named.st_mode), u64::from(named.st_nlink), named_len,
                        i64::try_from(named.st_mtime).map_err(|_| Fault::BoundsOverflow)?,
                        i64::try_from(named.st_mtime_nsec).map_err(|_| Fault::BoundsOverflow)?,
                        i64::try_from(named.st_ctime).map_err(|_| Fault::BoundsOverflow)?,
                        i64::try_from(named.st_ctime_nsec).map_err(|_| Fault::BoundsOverflow)?) {
                return Err(Fault::SourceChanged);
            }
            original_identity[slot] = Some(held);
        }
        let file = self.provenance_files[2].as_ref().ok_or(Fault::MaterialMissing)?;
        operation.require_effect()?;
        let observed_before = file.metadata();
        operation.require_effect()?;
        let before = observed_before.map_err(|_| Fault::IoFailure)?;
        let bound = operation.profile().carrier.max_metadata_bytes
            .min(operation.profile().carrier.max_single_plain_bytes)
            .min(8 * 1024 * 1024);
        if !before.is_file() || before.nlink() != 1 || before.len() == 0 || before.len() > bound {
            return Err(Fault::CapacityExceeded);
        }
        // Include the raw input, decoded inventory and encoded projection in the local bound.
        let peak = before.len().checked_mul(8).ok_or(Fault::BoundsOverflow)?;
        if peak > operation.profile().carrier.max_metadata_bytes {
            return Err(Fault::CapacityExceeded);
        }
        // Derive known payload C+T from this actual input length, never a fresh full profile.
        // At most N one-byte JSON items: two Vec element backings/old growth are bounded by
        // (3N+4) slots each; decoded strings plus scratch by 3N. The output escapes at most
        // six bytes per original byte plus the fixed receipt, with old+new Vec peak 3*bound.
        let input_len = before.len();
        let encoded_bound = input_len.checked_mul(6).and_then(|n| n.checked_add(1024))
            .ok_or(Fault::BoundsOverflow)?;
        let decoded_bound = input_len.checked_mul(3).and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_mul((std::mem::size_of::<AuthenticatedFile>() as u64)
                .checked_add(std::mem::size_of::<AuthenticatedTool>() as u64)?))
            .and_then(|n| n.checked_add(input_len.checked_mul(3)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<AuthenticatedToolInventory>() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        let known = input_len.checked_add(decoded_bound)
            .and_then(|n| n.checked_add(encoded_bound.max(128).checked_mul(3)?))
            .ok_or(Fault::BoundsOverflow)?;
        if known.checked_add(fixed).ok_or(Fault::BoundsOverflow)?
            > operation.profile().carrier.max_total_allocation_bytes {
            return Err(Fault::CapacityExceeded);
        }
        // This covers only known requested buffers and slots, not allocator/serde opaque T.
        operation.reserve_original_resources(0, known)?;
        let bytes = read_exact_metadata(file, before.len(), &operation)?;
        if bytes.capacity() as u64 != input_len { return Err(Fault::CapacityExceeded); }
        operation.require_effect()?;
        let observed_after = file.metadata();
        operation.require_effect()?;
        let after = observed_after.map_err(|_| Fault::IoFailure)?;
        if identity(&before) != identity(&after)
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != decode_sha(&receipt.inner_sha256)?
        {
            return Err(Fault::SourceChanged);
        }
        let inventory: AuthenticatedToolInventory =
            serde_json::from_slice(&bytes).map_err(|_| Fault::ManifestInvalid)?;
        if inventory.files.len() != receipt.file_count
            || inventory.build_tools.is_empty()
            || inventory.source_archive_sha256 != receipt.source_archive_sha256
            || inventory.product_patch_sha256 != receipt.product_patch_sha256
            || inventory.recipe_sha256 != receipt.recipe_sha256
            || inventory.build_profile_sha256 != receipt.build_profile_sha256
        {
            return Err(Fault::SourceChanged);
        }
        let mut decoded_actual = (std::mem::size_of::<AuthenticatedToolInventory>() as u64)
            .checked_add((inventory.files.capacity() as u64)
                .checked_mul(std::mem::size_of::<AuthenticatedFile>() as u64).ok_or(Fault::BoundsOverflow)?)
            .and_then(|n| n.checked_add((inventory.build_tools.capacity() as u64)
                .checked_mul(std::mem::size_of::<AuthenticatedTool>() as u64)?))
            .ok_or(Fault::BoundsOverflow)?;
        for value in [
            &inventory.source_archive_sha256, &inventory.product_patch_sha256,
            &inventory.recipe_sha256, &inventory.build_profile_sha256,
            &inventory.programs.postgres, &inventory.programs.initdb,
            &inventory.programs.pg_ctl, &inventory.programs.basebackup,
        ] {
            decoded_actual = decoded_actual.checked_add(value.capacity() as u64)
                .ok_or(Fault::BoundsOverflow)?;
        }
        for item in &inventory.files {
            decoded_actual = decoded_actual.checked_add(item.path.capacity() as u64)
                .and_then(|n| n.checked_add(item.sha256.capacity() as u64))
                .ok_or(Fault::BoundsOverflow)?;
        }
        for item in &inventory.build_tools {
            decoded_actual = decoded_actual.checked_add(item.role.capacity() as u64)
                .and_then(|n| n.checked_add(item.path.capacity() as u64))
                .and_then(|n| n.checked_add(item.sha256.capacity() as u64))
                .ok_or(Fault::BoundsOverflow)?;
        }
        if decoded_actual > decoded_bound { return Err(Fault::CapacityExceeded); }
        let provenance = openbot_domain::backup::whole_pg_carrier::WholePgProvenanceClaim {
            release_sha256: reviewed.release_digest,
            maintenance_sha256: reviewed.maintenance_digest,
            upstream_source_sha256: decode_sha(&receipt.source_archive_sha256)?,
            derived_patch_sha256: decode_sha(&receipt.product_patch_sha256)?,
            build_recipe_sha256: decode_sha(&receipt.recipe_sha256)?,
            tool_inventory_material_id: "tool-inventory".into(),
        };
        let encoded = serde_json::to_vec(&CaptureToolInventory {
            schema: "wrokbot-capture-tool-inventory",
            version: 1,
            original_verification: receipt,
            inventory,
        })
        .map_err(|_| Fault::ManifestInvalid)?;
        if encoded.len() as u64 > bound
            || encoded.capacity() as u64 > encoded_bound.max(128).checked_mul(2).ok_or(Fault::BoundsOverflow)?
            || provenance.tool_inventory_material_id.capacity() != "tool-inventory".len() {
            return Err(Fault::CapacityExceeded);
        }
        // Read, parse and encoding have completed with all original descriptors still in Source.
        // Compare every genuine held identity again; this does not close any ordinary resource.
        for (slot, original) in original_identity.iter().enumerate() {
            operation.require_effect()?;
            let observed = self.provenance_files[slot].as_ref().ok_or(Fault::MaterialMissing)?.metadata();
            operation.require_effect()?;
            let held = observed.map_err(|_| Fault::IoFailure)?;
            if identity(original.as_ref().ok_or(Fault::MaterialMissing)?) != identity(&held) {
                return Err(Fault::SourceChanged);
            }
        }
        operation.require_effect()?;
        let observed_root = std::fs::symlink_metadata(reviewed.maintenance.root());
        operation.require_effect()?;
        let root = observed_root.map_err(|_| Fault::IoFailure)?;
        if !root.is_dir()
            || identity(original_identity[0].as_ref().ok_or(Fault::MaterialMissing)?) != identity(&root) {
            return Err(Fault::SourceChanged);
        }
        for &(parent, slot, name, last) in &steps {
            operation.require_effect()?;
            let observed = rustix::fs::statat(
                self.provenance_files[parent].as_ref().ok_or(Fault::MaterialMissing)?,
                name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            );
            operation.require_effect()?;
            let named = observed.map_err(|_| Fault::PathUnsafe)?;
            let named_len = u64::try_from(named.st_size).map_err(|_| Fault::PathUnsafe)?;
            let held = original_identity[slot].as_ref().ok_or(Fault::MaterialMissing)?;
            let expected_type = if last { rustix::fs::FileType::RegularFile }
                else { rustix::fs::FileType::Directory };
            if rustix::fs::FileType::from_raw_mode(named.st_mode) != expected_type
                || identity(held)
                    != (named.st_dev as u64, named.st_ino, named.st_uid,
                        u32::from(named.st_mode), u64::from(named.st_nlink), named_len,
                        i64::try_from(named.st_mtime).map_err(|_| Fault::BoundsOverflow)?,
                        i64::try_from(named.st_mtime_nsec).map_err(|_| Fault::BoundsOverflow)?,
                        i64::try_from(named.st_ctime).map_err(|_| Fault::BoundsOverflow)?,
                        i64::try_from(named.st_ctime_nsec).map_err(|_| Fault::BoundsOverflow)?) {
                return Err(Fault::SourceChanged);
            }
        }
        operation.require_effect()?;
        Ok((provenance, encoded))
    }

    pub(crate) async fn run_backup_before_postcheck(
        &mut self,
        operation: &Arc<CaptureOperation>,
    ) -> Result<(), Fault> {
        same_operation(&self.operation, operation)?;
        self.operation.require_effect()?;
        if self.native.is_some() || self.native_receipt.is_some() || self.physical.is_some() {
            return Err(Fault::IntentMismatch);
        }
        let receipt = runner::run_capture_native(self)
            .await
            .map_err(map_maintenance)?;
        // Preserve the actual original receipt before another fallible phase.
        self.native_receipt = Some(receipt);
        self.operation.require_effect()?;
        let physical = runner::verify_capture_physical_material(
            &self.output_path,
            &self.profile,
            self.operation.original_clock(),
            self.native_receipt.as_ref().ok_or(Fault::MaterialMissing)?,
        )
        .map_err(map_maintenance)?;
        self.physical = Some(physical);
        self.operation.require_effect()
    }

    pub(crate) async fn stop_after_material_read(
        &mut self,
        operation: &Arc<CaptureOperation>,
    ) -> Result<(), Fault> {
        same_operation(&self.operation, operation)?;
        self.stop_native_source().await.map_err(map_maintenance)?;
        self.operation.require_effect()?;
        if self.native.as_ref().is_none_or(|n| !n.physically_closed())
            || self.native_receipt.is_none()
            || self.physical.is_none()
        {
            return Err(Fault::ClosingPending);
        }
        // All original readers/writers/drivers are joined; release only this borrowed Arc.
        self.secret.take();
        self.permit.stopped()?.revalidate(operation.as_ref())?;
        Ok(())
    }

    pub(super) async fn stop_native_source(&mut self) -> Result<(), MaintenanceError> {
        self.operation.require_closing().map_err(map_fault)?;
        if let Some(closed) = &self.closed {
            if closed.postmaster.closed_success()
                && closed.sql_driver_result.is_ok()
                && closed
                    .stop_helper
                    .as_ref()
                    .is_none_or(|helper| helper.closed_success())
                && self.postmaster.is_none()
                && self.stop_helper.is_none()
                && self.sql_client.is_none()
                && self.sql_driver.is_none()
                && self.connecting.is_none()
            {
                return Ok(());
            }
            return Err(MaintenanceError::HelperWaitUnknown);
        }
        let operation = Arc::clone(&self.operation);
        // No query future is discarded here. Its normal owning caller has already observed it.
        self.sql_client.take();
        if let Some(driver) = self.sql_driver.as_mut() {
            let result = driver.await;
            self.sql_driver_result = Some(match result {
                Ok(Ok(())) => Ok(()),
                _ => Err(()),
            });
            self.sql_driver.take();
        }
        if self.connecting.is_some() || self.connection_result.is_some() {
            return Err(MaintenanceError::ConnectionFailed);
        }
        if self.postmaster_observation.is_none() {
            if operation.require_effect().is_ok() {
                if self.stop_helper.is_none() {
                    let mut command = self.native_bundle().checked_command(Program::PgCtl)?;
                    command
                        .arg("-D")
                        .arg(self.permit.stopped().map_err(map_fault)?.data_dir())
                        .args(["-m", "fast", "-w", "-t", "5", "stop"])
                        .current_dir(&self.work_path);
                    self.native_fd_budget(3)?;
                    self.stop_helper = Some(runner::spawn_program(
                        command,
                        "capture-pgctl-stop",
                        operation.original_clock(),
                        Arc::clone(self.native_secret()),
                        false,
                        (
                            self.profile.fields().max_status_bytes,
                            self.profile.fields().max_stderr_bytes,
                            false,
                        ),
                        false,
                    )?);
                }
                let helper = self
                    .stop_helper
                    .take()
                    .ok_or(MaintenanceError::HelperWaitUnknown)?;
                let closed = runner::wait_capture_program(helper, self, true, true).await?;
                let (observation, error) = closed.into_closed_observation();
                self.stop_observation = Some(observation);
                if let Some(error) = error {
                    return Err(error);
                }
            } else {
                // C permits retirement of this exact still-owned, unreaped original Child only.
                operation.require_closing().map_err(map_fault)?;
                let owner = self
                    .postmaster
                    .as_ref()
                    .ok_or(MaintenanceError::HelperWaitUnknown)?;
                let raw = i32::try_from(owner.original_pid())
                    .map_err(|_| MaintenanceError::HelperWaitUnknown)?;
                let pid = rustix::process::Pid::from_raw(raw)
                    .ok_or(MaintenanceError::HelperWaitUnknown)?;
                let identity = self
                    .postmaster_identity
                    .as_ref()
                    .ok_or(MaintenanceError::HelperWaitUnknown)?;
                identity
                    .revalidate()
                    .map_err(|_| MaintenanceError::HelperWaitUnknown)?;
                if identity
                    .evidence_bytes()
                    .map_err(|_| MaintenanceError::HelperWaitUnknown)?
                    != self
                        .postmaster_birth
                        .ok_or(MaintenanceError::HelperWaitUnknown)?
                {
                    return Err(MaintenanceError::HelperWaitUnknown);
                }
                if self.postmaster_retirement.is_none() {
                    operation.require_closing().map_err(map_fault)?;
                    let actual = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
                    self.postmaster_retirement = Some(actual);
                    actual.map_err(|_| MaintenanceError::IoFailure)?;
                }
            }
            if let Some(owner) = self.postmaster.take() {
                let closed = runner::wait_capture_program(owner, self, true, false).await?;
                let (observation, error) = closed.into_closed_observation();
                self.postmaster_observation = Some(observation);
                if let Some(error) = error {
                    return Err(error);
                }
            }
        }
        let sql_driver_result = self
            .sql_driver_result
            .ok_or(MaintenanceError::ConnectionFailed)?;
        let postmaster = self
            .postmaster_observation
            .take()
            .ok_or(MaintenanceError::HelperWaitUnknown)?;
        if !postmaster.closed_success()
            || sql_driver_result.is_err()
            || self
                .stop_observation
                .as_ref()
                .is_some_and(|o| !o.closed_success())
        {
            self.postmaster_observation = Some(postmaster);
            return Err(MaintenanceError::HelperWaitUnknown);
        }
        self.closed = Some(ClosedMaintenanceSource {
            postmaster,
            stop_helper: self.stop_observation.take(),
            sql_driver_result,
        });
        Ok(())
    }

    pub(crate) fn require_sources_closed(&self) -> Result<(), Fault> {
        self.operation.require_effect()?;
        let closed = self.closed.as_ref().ok_or(Fault::ClosingPending)?;
        if !closed.postmaster.closed_success()
            || closed.sql_driver_result.is_err()
            || closed
                .stop_helper
                .as_ref()
                .is_some_and(|s| !s.closed_success())
            || self.postmaster.is_some()
            || self.stop_helper.is_some()
            || self.sql_client.is_some()
            || self.sql_driver.is_some()
            || self.connecting.is_some()
            || self.connection_result.is_some()
            || self.native.as_ref().is_none_or(|n| !n.physically_closed())
            || self.native_receipt.is_none()
            || self.physical.is_none()
        {
            return Err(Fault::ClosingPending);
        }
        Ok(())
    }
    /// The actual closed plain-backup directory names, including empty PostgreSQL directories.
    pub(crate) fn closed_pg_directory_inventory(&self) -> Result<Vec<String>, Fault> {
        self.require_sources_closed()?;
        self.operation.require_effect()?;
        let observed_pg = rustix::fs::openat(
            self.work_directory()?,
            "pg",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        );
        self.operation.require_effect()?;
        let pg = File::from(observed_pg.map_err(|_| Fault::PathUnsafe)?);
        let mut names = Vec::new();
        let mut nodes = 0u64;
        let mut metadata = 0u64;
        closed_directories(
            &pg,
            "",
            0,
            &self.operation,
            &mut names,
            &mut nodes,
            &mut metadata,
        )?;
        let physical = self.physical.as_ref().ok_or(Fault::MaterialMissing)?;
        let all_directories = (names.len() as u64)
            .checked_add(1)
            .ok_or(Fault::BoundsOverflow)?;
        let all_nodes = (physical.files.len() as u64)
            .checked_add(all_directories)
            .and_then(|n| n.checked_sub(1))
            .ok_or(Fault::BoundsOverflow)?;
        if all_directories != physical.directory_count()
            || nodes != all_nodes
            || all_directories > self.operation.profile().carrier.max_directories
        {
            return Err(Fault::SourceChanged);
        }
        let root_cost = 6u64
            .checked_add(std::mem::size_of::<String>() as u64)
            .ok_or(Fault::BoundsOverflow)?;
        if metadata
            .checked_add(root_cost)
            .is_none_or(|n| n > self.operation.profile().carrier.max_metadata_bytes)
        {
            return Err(Fault::CapacityExceeded);
        }
        names
            .try_reserve_exact(1)
            .map_err(|_| Fault::CapacityExceeded)?;
        names.push("pgdata".into());
        names.sort();
        Ok(names)
    }
    pub(crate) fn closed_backup_range(&self) -> Result<(String, String, u32, u32), Fault> {
        self.require_sources_closed()?;
        let terminal = self
            .native_receipt
            .as_ref()
            .ok_or(Fault::MaterialMissing)?
            .terminal()
            .map_err(map_maintenance)?;
        if terminal.timeline == 0
            || terminal.start_lsn >= terminal.stop_lsn
            || terminal.wal_segment_bytes == 0
        {
            return Err(Fault::ManifestInvalid);
        }
        Ok((
            lsn(terminal.start_lsn),
            lsn(terminal.stop_lsn),
            terminal.timeline,
            terminal.wal_segment_bytes,
        ))
    }

    pub(crate) fn take_closed_material_files(
        &mut self,
    ) -> Result<Vec<CaptureOwnedMaterialFile>, Fault> {
        use std::fmt::Write as _;
        self.require_sources_closed()?;
        if self.material_open_entered || self.material_files.is_some() {
            return Err(Fault::IntentMismatch);
        }
        // Sticky even after the successful outgoing Vec has moved to the original audit owner.
        self.material_open_entered = true;
        let operation = Arc::clone(&self.operation);
        let bounds = &operation.profile().carrier;
        let native = self.profile.fields();
        let physical = self.physical.as_ref().ok_or(Fault::MaterialMissing)?;
        let count = physical.files.len();
        let count_u64 = u64::try_from(count).map_err(|_| Fault::BoundsOverflow)?;
        if count_u64 > bounds.max_material_files.min(native.max_material_files) {
            return Err(Fault::CapacityExceeded);
        }
        // Decimal usize formatting needs no more than this checked, finite reservation.
        let id_capacity = 3usize.checked_add(usize::MAX.ilog10() as usize)
            .and_then(|n| n.checked_add(1)).ok_or(Fault::BoundsOverflow)?;
        let metadata_limit = bounds.max_metadata_bytes.min(bounds.max_total_allocation_bytes);
        let mut slot_count = 1u64; // The actual pg root, with no extra root clone.
        let mut string_bytes = 0u64;
        let mut plain_bytes = 0u64;
        for row in &physical.files {
            if row.path.is_empty() || row.path.contains('\0') || row.path.contains('\\')
                || row.path.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
                return Err(Fault::PathUnsafe);
            }
            let mut depth = 0u64;
            for part in Path::new(&row.path).components() {
                if !matches!(part, Component::Normal(_)) { return Err(Fault::PathUnsafe); }
                depth = depth.checked_add(1).ok_or(Fault::BoundsOverflow)?;
            }
            let relative_len = row.path.len().checked_add(7).ok_or(Fault::BoundsOverflow)?;
            let carrier_depth = depth.checked_add(1).ok_or(Fault::BoundsOverflow)?;
            if depth == 0 || depth > native.max_depth || carrier_depth > bounds.max_path_depth
                || relative_len as u64 > bounds.max_path_bytes.min(native.max_path_bytes)
                || row.bytes > bounds.max_single_plain_bytes.min(native.max_single_file_bytes) {
                return Err(Fault::CapacityExceeded);
            }
            slot_count = slot_count.checked_add(depth).ok_or(Fault::BoundsOverflow)?;
            string_bytes = string_bytes.checked_add(id_capacity as u64)
                .and_then(|n| n.checked_add(relative_len as u64)).ok_or(Fault::BoundsOverflow)?;
            plain_bytes = plain_bytes.checked_add(row.bytes).ok_or(Fault::BoundsOverflow)?;
        }
        if plain_bytes > bounds.max_material_plain_bytes.min(native.max_material_plain_bytes)
            || slot_count > bounds.max_open_files.min(native.max_open_files) {
            return Err(Fault::CapacityExceeded);
        }
        let requested_metadata = slot_count
            .checked_mul(std::mem::size_of::<Option<File>>() as u64)
            .and_then(|n| count_u64.checked_mul(std::mem::size_of::<CaptureOwnedMaterialFile>() as u64)
                .and_then(|entries| n.checked_add(entries)))
            .and_then(|n| n.checked_add(string_bytes)).ok_or(Fault::BoundsOverflow)?;
        if requested_metadata > metadata_limit { return Err(Fault::CapacityExceeded); }
        // One monotonic known-admission account includes constructor and all planned material FDs.
        // This is not a global/opaque descriptor census or a second full FD budget.
        self.native_fd_budget(slot_count).map_err(map_maintenance)?;
        self.reserve_start_fds(slot_count)?;
        let slots = usize::try_from(slot_count).map_err(|_| Fault::BoundsOverflow)?;
        self.material_fd_slots.try_reserve_exact(slots).map_err(|_| Fault::CapacityExceeded)?;
        self.material_files = Some(Vec::new());
        self.material_files.as_mut().ok_or(Fault::MaterialMissing)?
            .try_reserve_exact(count).map_err(|_| Fault::CapacityExceeded)?;
        let destination_capacity = self.material_files.as_ref().ok_or(Fault::MaterialMissing)?.capacity();
        let mut metadata = (self.material_fd_slots.capacity() as u64)
            .checked_mul(std::mem::size_of::<Option<File>>() as u64)
            .and_then(|n| (destination_capacity as u64)
                .checked_mul(std::mem::size_of::<CaptureOwnedMaterialFile>() as u64)
                .and_then(|entries| n.checked_add(entries)))
            .ok_or(Fault::BoundsOverflow)?;
        if metadata.checked_add(string_bytes).is_none_or(|n| n > metadata_limit) {
            return Err(Fault::CapacityExceeded);
        }
        operation.require_effect()?;
        let observed_named = rustix::fs::statat(
            self.work_directory()?, "pg", rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        );
        operation.require_effect()?;
        let named = observed_named.map_err(|_| Fault::PathUnsafe)?;
        if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
            || named.st_uid != rustix::process::geteuid().as_raw() || named.st_mode & 0o077 != 0 {
            return Err(Fault::PathUnsafe);
        }
        // The reserved empty slot is installed before open; no allocation follows its Ok result.
        if self.material_fd_slots.len() >= self.material_fd_slots.capacity() {
            return Err(Fault::CapacityExceeded);
        }
        self.material_fd_slots.push(None);
        operation.require_effect()?;
        let observed_pg = rustix::fs::openat(
            self.work_directory()?, "pg",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        );
        match observed_pg {
            Ok(file) => self.material_fd_slots[0] = Some(File::from(file)),
            Err(_) => { operation.require_effect()?; return Err(Fault::PathUnsafe); }
        }
        operation.require_effect()?;
        let pg = self.material_fd_slots[0].as_ref().ok_or(Fault::MaterialMissing)?;
        operation.require_effect()?;
        let observed_held = pg.metadata();
        operation.require_effect()?;
        let held = observed_held.map_err(|_| Fault::IoFailure)?;
        if !held.is_dir() || held.uid() != rustix::process::geteuid().as_raw()
            || held.mode() & 0o077 != 0
            || (held.dev(), held.ino(), held.uid(), held.mode())
                != (named.st_dev as u64, named.st_ino, named.st_uid, u32::from(named.st_mode)) {
            return Err(Fault::SourceChanged);
        }
        let mut remaining_strings = string_bytes;
        for index in 0..count {
            let file_slot = self.open_material_relative_regular(index)?;
            let row = self.physical.as_ref().ok_or(Fault::MaterialMissing)?
                .files.get(index).ok_or(Fault::MaterialMissing)?;
            let file = self.material_fd_slots.get(file_slot)
                .and_then(Option::as_ref).ok_or(Fault::MaterialMissing)?;
            operation.require_effect()?;
            let observed_held = file.metadata();
            operation.require_effect()?;
            let held = observed_held.map_err(|_| Fault::IoFailure)?;
            if !held.is_file() || held.len() != row.bytes || held.nlink() != 1
                || held.uid() != rustix::process::geteuid().as_raw() || held.mode() & 0o077 != 0 {
                return Err(Fault::SourceChanged);
            }
            let expected = decode_sha(&row.sha256)?;
            if hash_file(file, row.bytes, &operation)? != expected { return Err(Fault::SourceChanged); }
            operation.require_effect()?;
            let observed_after = file.metadata();
            operation.require_effect()?;
            let after = observed_after.map_err(|_| Fault::IoFailure)?;
            if identity(&held) != identity(&after) { return Err(Fault::SourceChanged); }
            let kind = if row.path.starts_with("pg_wal/") {
                WholePgMaterialKind::WalSegment
            } else if ["postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf"]
                .contains(&row.path.as_str()) {
                WholePgMaterialKind::PostgresConfig
            } else { WholePgMaterialKind::PostgresBase };
            let relative_len = row.path.len().checked_add(7).ok_or(Fault::BoundsOverflow)?;
            let requested_strings = (id_capacity as u64).checked_add(relative_len as u64)
                .ok_or(Fault::BoundsOverflow)?;
            remaining_strings = remaining_strings.checked_sub(requested_strings)
                .ok_or(Fault::BoundsOverflow)?;
            // All fallible string preparation and actual-capacity checks occur with raw File resident.
            let mut material_id = String::new();
            material_id.try_reserve_exact(id_capacity).map_err(|_| Fault::CapacityExceeded)?;
            let mut relative_path = String::new();
            relative_path.try_reserve_exact(relative_len).map_err(|_| Fault::CapacityExceeded)?;
            metadata = metadata.checked_add(material_id.capacity() as u64)
                .and_then(|n| n.checked_add(relative_path.capacity() as u64)).ok_or(Fault::BoundsOverflow)?;
            if metadata.checked_add(remaining_strings).is_none_or(|n| n > metadata_limit) {
                return Err(Fault::CapacityExceeded);
            }
            write!(&mut material_id, "pg-{index}").map_err(|_| Fault::ManifestInvalid)?;
            relative_path.push_str("pgdata/");
            relative_path.push_str(&row.path);
            if material_id.len() > id_capacity || relative_path.len() != relative_len {
                return Err(Fault::CapacityExceeded);
            }
            let plain_len = row.bytes;
            let destination = self.material_files.as_mut().ok_or(Fault::MaterialMissing)?;
            if destination.len() >= destination.capacity() { return Err(Fault::CapacityExceeded); }
            let slot = self.material_fd_slots.get_mut(file_slot).ok_or(Fault::MaterialMissing)?;
            operation.require_effect()?;
            // Unique promotion: the successful take goes straight into preallocated typed storage.
            // No check, allocation or await is interposed after the actual File leaves its raw slot.
            match slot.take() {
                Some(file) => destination.push(CaptureOwnedMaterialFile {
                    kind, material_id, relative_path, file, plain_len, plain_sha256: expected,
                }),
                None => return Err(Fault::MaterialMissing),
            }
        }
        operation.require_effect()?;
        self.material_files.take().ok_or(Fault::MaterialMissing)
    }

    /// Only the original material inventory may select a path and the same Source owns every FD.
    /// The separate provenance caller and its original free helper are outside this repair.
    fn open_material_relative_regular(&mut self, row_index: usize) -> Result<usize, Fault> {
        let path = &self.physical.as_ref().ok_or(Fault::MaterialMissing)?
            .files.get(row_index).ok_or(Fault::MaterialMissing)?.path;
        let mut parts = Path::new(path).components().peekable();
        let mut directory_slot = 0usize;
        while let Some(part) = parts.next() {
            let Component::Normal(name) = part else { return Err(Fault::PathUnsafe); };
            let last = parts.peek().is_none();
            self.operation.require_effect()?;
            let observed_named = rustix::fs::statat(
                self.material_fd_slots.get(directory_slot).and_then(Option::as_ref)
                    .ok_or(Fault::MaterialMissing)?, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            );
            self.operation.require_effect()?;
            let named = observed_named.map_err(|_| Fault::PathUnsafe)?;
            let expected_type = if last { rustix::fs::FileType::RegularFile }
                else { rustix::fs::FileType::Directory };
            if rustix::fs::FileType::from_raw_mode(named.st_mode) != expected_type
                || named.st_uid != rustix::process::geteuid().as_raw() || named.st_mode & 0o077 != 0
                || (last && named.st_nlink != 1) {
                return Err(Fault::PathUnsafe);
            }
            let slot = self.material_fd_slots.len();
            if slot >= self.material_fd_slots.capacity() { return Err(Fault::CapacityExceeded); }
            self.material_fd_slots.push(None);
            let flags = rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK
                | if last { rustix::fs::OFlags::empty() } else { rustix::fs::OFlags::DIRECTORY };
            self.operation.require_effect()?;
            let observed_next = rustix::fs::openat(
                self.material_fd_slots[directory_slot].as_ref().ok_or(Fault::MaterialMissing)?,
                name, flags, rustix::fs::Mode::empty(),
            );
            match observed_next {
                Ok(file) => self.material_fd_slots[slot] = Some(File::from(file)),
                Err(_) => { self.operation.require_effect()?; return Err(Fault::PathUnsafe); }
            }
            self.operation.require_effect()?;
            let file = self.material_fd_slots[slot].as_ref().ok_or(Fault::MaterialMissing)?;
            self.operation.require_effect()?;
            let observed_held = file.metadata();
            self.operation.require_effect()?;
            let held = observed_held.map_err(|_| Fault::IoFailure)?;
            if (last && (!held.is_file() || held.nlink() != 1)) || (!last && !held.is_dir())
                || held.uid() != rustix::process::geteuid().as_raw() || held.mode() & 0o077 != 0
                || (held.dev(), held.ino(), held.uid(), held.mode())
                    != (named.st_dev as u64, named.st_ino, named.st_uid, u32::from(named.st_mode)) {
                return Err(Fault::SourceChanged);
            }
            if last { return Ok(slot); }
            directory_slot = slot;
        }
        Err(Fault::PathUnsafe)
    }

    pub(crate) fn take_original_secrets(
        &mut self,
    ) -> Result<(SecretBytes, SecretBytes, File, zeroize::Zeroizing<Vec<u8>>), Fault> {
        self.require_sources_closed()?;
        if self.secret.is_some() {
            return Err(Fault::ClosingPending);
        }
        if !matches!(self.secret_move_phase, SecretMovePhase::Unentered)
            || self.stream_master.is_some()
            || self.stream_scram.is_some()
        {
            return Err(Fault::IntentMismatch);
        }
        self.secret_move_phase = SecretMovePhase::Entered;
        let vault = self.permit.take_vault()?;
        match vault.into_original_master_before(self.operation.as_ref()) {
            Ok((master, journal, bytes)) => {
                self.stream_master = Some(master);
                self.stream_master_journal = Some(journal);
                self.stream_master_journal_bytes = Some(zeroize::Zeroizing::new(bytes));
            }
            Err((vault, fault)) => {
                if let Err(vault) = self.permit.restore_vault(vault) {
                    self.retained_vault_failure = Some(vault);
                }
                return Err(fault);
            }
        }
        // Store each original allocation before the following fallible step.
        self.stream_scram = Some(
            self.permit
                .stopped_mut()?
                .take_original_scram(self.operation.as_ref())?,
        );
        // Validate the whole outgoing tuple while every original is still resident.
        // Nothing below changes these slots until the final infallible handoff.
        if self.stream_master.is_none() || self.stream_scram.is_none() {
            return Err(Fault::SecretInvalid);
        }
        if self.stream_master_journal.is_none() || self.stream_master_journal_bytes.is_none() {
            return Err(Fault::MaterialMissing);
        }

        // The sole original stream-preparation caller already completed the closed
        // material transfer and the provenance's final held/named identity checks.
        // Release only auxiliary originals in reverse acquisition order. A C failure
        // leaves the remaining FDs and all four sensitive inputs in this Source.
        // Safe Drop returning is not a close ACK, task join or completion grant.
        for file in self.provenance_files.iter_mut().rev() {
            if file.is_some() {
                self.operation.require_closing()?;
                drop(file.take());
                self.operation.require_closing()?;
            }
        }
        // Every final material File was uniquely promoted into the actual outgoing
        // Vec; the remaining occupied raw slots are the walk's directory handles.
        // Keep the slot count/capacity and cumulative admission account unchanged.
        for file in self.material_fd_slots.iter_mut().rev() {
            if file.is_some() {
                self.operation.require_closing()?;
                drop(file.take());
                self.operation.require_closing()?;
            }
        }
        // These are the maintenance configuration FDs. The separate original normal
        // configuration material owner, permit and continuous kernel lease stay held.
        for file in self.start_configuration.iter_mut().rev() {
            if file.is_some() {
                self.operation.require_closing()?;
                drop(file.take());
                self.operation.require_closing()?;
            }
        }
        if self.source_tablespace_scan.is_some() {
            self.operation.require_closing()?;
            drop(self.source_tablespace_scan.take());
            self.operation.require_closing()?;
        }
        for file in [
            &mut self.source_tablespace_directory,
            &mut self.source_wal_directory,
            &mut self.source_data_directory,
        ] {
            if file.is_some() {
                self.operation.require_closing()?;
                drop(file.take());
                self.operation.require_closing()?;
            }
        }

        // All fallible work precedes the first unique sensitive move. The checked
        // originals go straight to the caller; no clock check or await can lose them.
        Ok((
            self.stream_master.take().expect("checked original master remains resident"),
            self.stream_scram.take().expect("checked original SCRAM remains resident"),
            self.stream_master_journal.take().expect("checked original journal remains resident"),
            self.stream_master_journal_bytes.take().expect("checked original journal bytes remain resident"),
        ))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedBundleReceipt {
    schema: String,
    schema_version: u32,
    outer_sha256: String,
    inner_sha256: String,
    source_archive_sha256: String,
    product_patch_sha256: String,
    recipe_sha256: String,
    build_profile_sha256: String,
    program_count: usize,
    file_count: usize,
    source_authenticated: bool,
    platform_signature_verified: bool,
    production_release_authorized: bool,
}
#[derive(Deserialize, Serialize)]
struct AuthenticatedToolInventory {
    source_archive_sha256: String,
    product_patch_sha256: String,
    recipe_sha256: String,
    build_profile_sha256: String,
    programs: AuthenticatedPrograms,
    files: Vec<AuthenticatedFile>,
    build_tools: Vec<AuthenticatedTool>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedPrograms {
    postgres: String,
    initdb: String,
    pg_ctl: String,
    basebackup: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedFile {
    path: String,
    bytes: u64,
    sha256: String,
    mode: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedTool {
    role: String,
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Serialize)]
struct CaptureToolInventory {
    schema: &'static str,
    version: u32,
    original_verification: AuthenticatedBundleReceipt,
    inventory: AuthenticatedToolInventory,
}
fn read_exact_metadata(
    file: &File,
    length: u64,
    operation: &CaptureOperation,
) -> Result<Vec<u8>, Fault> {
    use std::os::unix::fs::FileExt as _;
    let mut bytes = vec![0u8; usize::try_from(length).map_err(|_| Fault::BoundsOverflow)?];
    let mut offset = 0usize;
    while offset < bytes.len() {
        operation.require_effect()?;
        let end = offset
            .checked_add(8192)
            .ok_or(Fault::BoundsOverflow)?
            .min(bytes.len());
        let observed = file.read_at(&mut bytes[offset..end], offset as u64);
        operation.require_effect()?;
        let n = observed.map_err(|_| Fault::IoFailure)?;
        if n == 0 {
            return Err(Fault::ShortRead);
        }
        offset = offset.checked_add(n).ok_or(Fault::BoundsOverflow)?;
    }
    let mut tail = zeroize::Zeroizing::new([0u8; 1]);
    operation.require_effect()?;
    let observed_tail = file.read_at(&mut *tail, length);
    operation.require_effect()?;
    if observed_tail.map_err(|_| Fault::IoFailure)? != 0 {
        return Err(Fault::ExtraTail);
    }
    operation.require_effect()?;
    Ok(bytes)
}

fn closed_directories(
    directory: &File,
    relative: &str,
    depth: u64,
    operation: &CaptureOperation,
    names: &mut Vec<String>,
    nodes: &mut u64,
    metadata: &mut u64,
) -> Result<(), Fault> {
    operation.require_effect()?;
    let observed_before = directory.metadata();
    operation.require_effect()?;
    let before = observed_before.map_err(|_| Fault::IoFailure)?;
    let bounds = &operation.profile().carrier;
    let native = &operation.profile().native;
    if !before.is_dir()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o077 != 0
        || depth > bounds.max_path_depth.min(native.max_depth)
    {
        return Err(Fault::PathUnsafe);
    }
    if !relative.is_empty() {
        *metadata = metadata
            .checked_add(
                (relative.len() as u64)
                    .checked_add(7)
                    .ok_or(Fault::BoundsOverflow)?,
            )
            .and_then(|n| n.checked_add(std::mem::size_of::<String>() as u64))
            .ok_or(Fault::BoundsOverflow)?;
        if *metadata > bounds.max_metadata_bytes
            || names.len() as u64 >= bounds.max_directories.min(native.max_directories)
        {
            return Err(Fault::CapacityExceeded);
        }
        names
            .try_reserve_exact(1)
            .map_err(|_| Fault::CapacityExceeded)?;
        names.push(format!("pgdata/{relative}"));
    }
    operation.require_effect()?;
    let observed_entries = rustix::fs::Dir::read_from(directory);
    operation.require_effect()?;
    let mut entries = observed_entries.map_err(|_| Fault::IoFailure)?;
    loop {
        operation.require_effect()?;
        let observed_entry = entries.next();
        operation.require_effect()?;
        let Some(entry) = observed_entry else {
            break;
        };
        let entry = entry.map_err(|_| Fault::IoFailure)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *nodes = nodes.checked_add(1).ok_or(Fault::BoundsOverflow)?;
        if *nodes
            > bounds
                .max_material_files
                .min(native.max_material_files)
                .checked_add(bounds.max_directories.min(native.max_directories))
                .ok_or(Fault::BoundsOverflow)?
        {
            return Err(Fault::CapacityExceeded);
        }
        let name_str = name.to_str().map_err(|_| Fault::PathUnsafe)?;
        if name_str.is_empty() || name_str.contains('/') || name_str.contains('\\') {
            return Err(Fault::PathUnsafe);
        }
        let next = if relative.is_empty() {
            name_str.to_owned()
        } else {
            format!("{relative}/{name_str}")
        };
        if next.len() as u64 > bounds.max_path_bytes.min(native.max_path_bytes) {
            return Err(Fault::CapacityExceeded);
        }
        operation.require_effect()?;
        let observed_named =
            rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
        operation.require_effect()?;
        let st = observed_named.map_err(|_| Fault::SourceChanged)?;
        if st.st_uid != before.uid() || st.st_mode & 0o077 != 0 {
            return Err(Fault::PathUnsafe);
        }
        match rustix::fs::FileType::from_raw_mode(st.st_mode) {
            rustix::fs::FileType::Directory => {
                // These are the original necessary local depth/FD guards, before the FD effect.
                if depth
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(2))
                    .and_then(|n| n.checked_add(5))
                    .is_none_or(|n| n > bounds.max_open_files.min(native.max_open_files))
                {
                    return Err(Fault::SourceChanged);
                }
                let child_depth = depth.checked_add(1).ok_or(Fault::BoundsOverflow)?;
                if child_depth > bounds.max_path_depth.min(native.max_depth) {
                    return Err(Fault::PathUnsafe);
                }
                operation.require_effect()?;
                let observed_child = rustix::fs::openat(
                    directory,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                );
                operation.require_effect()?;
                let child = File::from(observed_child.map_err(|_| Fault::PathUnsafe)?);
                operation.require_effect()?;
                let observed_held = child.metadata();
                operation.require_effect()?;
                let held = observed_held.map_err(|_| Fault::IoFailure)?;
                if (held.dev(), held.ino(), held.uid()) != (st.st_dev as u64, st.st_ino, st.st_uid)
                {
                    return Err(Fault::SourceChanged);
                }
                closed_directories(
                    &child,
                    &next,
                    child_depth,
                    operation,
                    names,
                    nodes,
                    metadata,
                )?;
            }
            rustix::fs::FileType::RegularFile if st.st_nlink == 1 => {}
            _ => return Err(Fault::PathUnsafe),
        }
    }
    operation.require_effect()?;
    let observed_after = directory.metadata();
    operation.require_effect()?;
    let after = observed_after.map_err(|_| Fault::IoFailure)?;
    if identity(&before) != identity(&after) {
        return Err(Fault::SourceChanged);
    }
    operation.require_effect()
}

const SOURCE_MAIN: &str = "source-postgresql.conf";
const SOURCE_HBA: &str = "source-pg-hba.conf";
const SOURCE_IDENT: &str = "source-pg-ident.conf";
const SOURCE_HBA_BYTES: &[u8] = b"local postgres desktop_admin scram-sha-256\nlocal replication desktop_admin scram-sha-256\nlocal all all reject\nlocal replication all reject\n";
// Command-line settings override FILE/auto without inventing new memory/WAL defaults.
const SOURCE_SAFETY_ARGV: &[&str] = &[
    "listen_addresses=", "unix_socket_permissions=0600", "ssl=off",
    "password_encryption=scram-sha-256", "logging_collector=off",
    "dynamic_shared_memory_type=posix", "shared_preload_libraries=",
    "session_preload_libraries=", "local_preload_libraries=", "archive_mode=off",
    "archive_command=", "archive_library=", "restore_command=",
    "archive_cleanup_command=", "recovery_end_command=", "external_pid_file=",
    "primary_conninfo=", "primary_slot_name=", "log_statement=none",
    "log_min_error_statement=panic",
];
#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceStartPhase { Starting, Ready }
#[derive(Clone, Copy, PartialEq, Eq)]
struct OriginalSocketDirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}
enum SourceConnectFailure {
    Postgres(tokio_postgres::Error),
    Join(tokio::task::JoinError),
}
type SourceConnectResult = Result<
    Result<(Client, Connection<CapturePgIo, NoTlsStream>), tokio_postgres::Error>,
    tokio::task::JoinError,
>;

/// Only borrowed ordinary poll unwinds are caught. The actual source stays outside this
/// future. This does not certify abort/OOM, destructor panic or opaque internal ownership.
async fn catch_borrowed_source_step<F: std::future::Future>(
    future: F,
) -> Result<F::Output, Box<dyn std::any::Any + Send + 'static>> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|context| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            future.as_mut().poll(context)
        })) {
            Ok(std::task::Poll::Ready(result)) => std::task::Poll::Ready(Ok(result)),
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Err(payload) => std::task::Poll::Ready(Err(payload)),
        }
    }).await
}
fn original_socket_name(operation: &CaptureOperation) -> [u8; 49] {
    let mut bytes = [0u8; 49];
    bytes[..17].copy_from_slice(b".wrokbot-capture-");
    let alphabet = b"0123456789abcdef";
    for (index, byte) in operation.operation_id().iter().enumerate() {
        bytes[17 + index * 2] = alphabet[usize::from(byte >> 4)];
        bytes[18 + index * 2] = alphabet[usize::from(byte & 15)];
    }
    bytes
}
fn original_socket_path_bytes(operation: &CaptureOperation) -> [u8; 62] {
    let mut bytes = [0u8; 62];
    bytes[..13].copy_from_slice(b"/private/tmp/");
    bytes[13..].copy_from_slice(&original_socket_name(operation));
    bytes
}
fn planned_original_socket_path(
    operation: &CaptureOperation, port: u16,
) -> Result<PathBuf, Fault> {
    operation.require_effect()?;
    // u16::MAX yields the actual largest socket77B and lock82B. These limits are
    // representation bounds, not a prediction of a future directory inode.
    if port == 0
        || operation.profile().native.max_path_bytes < 82
        || operation.profile().carrier.max_path_bytes < 82
        || operation.profile().native.max_directories < 1
        || operation.profile().carrier.max_directories < 1
    {
        return Err(Fault::PathUnsafe);
    }
    let known = (std::mem::size_of::<[Option<File>; 3]>() as u64)
        .checked_add(std::mem::size_of::<[Option<OriginalSocketDirectoryIdentity>; 4]>() as u64)
        .and_then(|n| n.checked_add(std::mem::size_of::<Option<Result<(), rustix::io::Errno>>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Option<std::io::Result<()>>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<std::fs::Metadata, std::io::Error>>() as u64 * 2))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<rustix::fs::StatVfs, rustix::io::Errno>>() as u64))
        .and_then(|n| n.checked_add(std::mem::size_of::<OriginalSocketDirectoryIdentity>() as u64 * 2))
        .and_then(|n| n.checked_add((49 + 62 + 62) as u64))
        .ok_or(Fault::BoundsOverflow)?;
    operation.reserve_original_resources(0, known)?;
    let bytes = original_socket_path_bytes(operation);
    let text = std::str::from_utf8(&bytes).map_err(|_| Fault::PathUnsafe)?;
    let mut path = PathBuf::new();
    path.try_reserve_exact(62).map_err(|_| Fault::CapacityExceeded)?;
    path.push(text);
    // Pinned RawVec exact requested backing is charged above. No full allocator,
    // source/driver baseline or whole-operation global peak is asserted here.
    if path.capacity() != 62 || path.as_os_str().as_encoded_bytes() != bytes.as_slice() {
        return Err(Fault::CapacityExceeded);
    }
    operation.require_effect()?;
    Ok(path)
}
fn source_include_config(
    data: &Path, work: &Path, socket_directory: &Path, port: u16, operation: &CaptureOperation,
) -> Result<Vec<u8>, Fault> {
    // These strict representation checks grant no path/root authority; Permit owns both.
    for path in [data, work, socket_directory] {
        let value = path.to_str().ok_or(Fault::PathUnsafe)?;
        if !path.is_absolute() || value.is_empty()
            || path.components().any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            || value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'\\' | b'\'' | b'"' | b','))
            || value.len() as u64 > operation.profile().carrier.max_path_bytes
            || value.len() as u64 > operation.profile().native.max_path_bytes {
            return Err(Fault::PathUnsafe);
        }
    }
    let socket = socket_directory.join(format!(".s.PGSQL.{port}"));
    if port == 0 || socket.as_os_str().as_encoded_bytes().len() >= 104 {
        return Err(Fault::PathUnsafe);
    }
    for path in [
        data.join("postgresql.conf"), work.join(SOURCE_MAIN), work.join(SOURCE_HBA),
        work.join(SOURCE_IDENT), work.join("pg"), socket,
        socket_directory.join(format!(".s.PGSQL.{port}.lock")),
    ] {
        let length = path.as_os_str().as_encoded_bytes().len() as u64;
        if length > operation.profile().native.max_path_bytes
            || length > operation.profile().carrier.max_path_bytes {
            return Err(Fault::PathUnsafe);
        }
    }
    let main = data.join("postgresql.conf");
    let bytes = format!("include = '{}'\n", main.to_str().ok_or(Fault::PathUnsafe)?).into_bytes();
    let total = (bytes.len() as u64).checked_add(SOURCE_HBA_BYTES.len() as u64)
        .ok_or(Fault::BoundsOverflow)?;
    if total > operation.profile().native.max_control_bytes
        || total > operation.profile().carrier.max_metadata_bytes {
        return Err(Fault::CapacityExceeded);
    }
    Ok(bytes)
}
fn require_source_name_absent(
    directory: &File, name: &str, operation: &CaptureOperation,
) -> Result<(), Fault> {
    operation.require_effect()?;
    let observed = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
    operation.require_effect()?;
    match observed {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Ok(_) => Err(Fault::ExtraMaterial),
        Err(_) => Err(Fault::IoFailure),
    }
}
fn write_source_configuration(
    file: &File, bytes: &[u8], operation: &CaptureOperation,
) -> Result<(), Fault> {
    use std::os::unix::fs::FileExt as _;
    let mut offset = 0usize;
    while offset < bytes.len() {
        operation.require_effect()?;
        let actual = file.write_at(&bytes[offset..], offset as u64);
        operation.require_effect()?;
        let written = actual.map_err(|_| Fault::IoFailure)?;
        if written == 0 { return Err(Fault::IoFailure); }
        offset = offset.checked_add(written).ok_or(Fault::BoundsOverflow)?;
    }
    operation.require_effect()?;
    let actual = file.sync_all();
    operation.require_effect()?;
    actual.map_err(|_| Fault::IoFailure)
}
fn retryable_source_connect(error: &tokio_postgres::Error) -> bool {
    if let Some(database) = error.as_db_error() {
        return database.code().code() == "57P03";
    }
    let mut cause = std::error::Error::source(error);
    while let Some(error) = cause {
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            return matches!(io.raw_os_error(), Some(code) if code == rustix::io::Errno::NOENT.raw_os_error()
                || code == rustix::io::Errno::CONNREFUSED.raw_os_error());
        }
        cause = error.source();
    }
    false
}

fn same_operation(a: &Arc<CaptureOperation>, b: &Arc<CaptureOperation>) -> Result<(), Fault> {
    if !Arc::ptr_eq(a, b) {
        return Err(Fault::IntentMismatch);
    }
    b.require_effect()
}
fn checked_directory(file: &File, path: &Path, operation: &CaptureOperation) -> Result<(), Fault> {
    operation.require_effect()?;
    let observed_held = file.metadata();
    operation.require_effect()?;
    let a = observed_held.map_err(|_| Fault::IoFailure)?;
    operation.require_effect()?;
    let observed_named = std::fs::symlink_metadata(path);
    operation.require_effect()?;
    let b = observed_named.map_err(|_| Fault::IoFailure)?;
    if !a.is_dir()
        || !b.is_dir()
        || (a.dev(), a.ino(), a.uid(), a.mode()) != (b.dev(), b.ino(), b.uid(), b.mode())
        || a.uid() != rustix::process::geteuid().as_raw()
        || a.mode() & 0o777 != 0o700
    {
        return Err(Fault::SourceChanged);
    }
    Ok(())
}
fn identity(m: &std::fs::Metadata) -> (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn hash_file(file: &File, length: u64, operation: &CaptureOperation) -> Result<[u8; 32], Fault> {
    use std::os::unix::fs::FileExt as _;
    let mut hash = Sha256::new();
    let mut buffer = zeroize::Zeroizing::new([0u8; 8192]);
    let mut offset = 0u64;
    while offset < length {
        operation.require_effect()?;
        let count = usize::try_from((length - offset).min(buffer.len() as u64))
            .map_err(|_| Fault::BoundsOverflow)?;
        let observed = file.read_at(&mut buffer[..count], offset);
        operation.require_effect()?;
        let n = observed.map_err(|_| Fault::IoFailure)?;
        if n == 0 {
            return Err(Fault::ShortRead);
        }
        hash.update(&buffer[..n]);
        offset = offset.checked_add(n as u64).ok_or(Fault::BoundsOverflow)?;
    }
    let mut tail = zeroize::Zeroizing::new([0u8; 1]);
    operation.require_effect()?;
    let observed_tail = file.read_at(&mut *tail, length);
    operation.require_effect()?;
    if observed_tail.map_err(|_| Fault::IoFailure)? != 0 {
        return Err(Fault::ExtraTail);
    }
    operation.require_effect()?;
    Ok(hash.finalize().into())
}
fn decode_sha(value: &str) -> Result<[u8; 32], Fault> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Fault::ManifestInvalid);
    }
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| Fault::ManifestInvalid)?;
    }
    Ok(result)
}
fn lsn(value: u64) -> String {
    format!("{:X}/{:X}", value >> 32, value & 0xffff_ffff)
}
fn map_fault(fault: Fault) -> MaintenanceError {
    match fault {
        Fault::DeadlineExpired => MaintenanceError::DeadlineExpired,
        Fault::ClosingPending => MaintenanceError::ClosingPending,
        Fault::ClockUnavailable => MaintenanceError::ClockUnavailable,
        Fault::SecretInvalid => MaintenanceError::SecretInvalid,
        Fault::CapacityExceeded | Fault::BoundsOverflow => MaintenanceError::CapacityExceeded,
        _ => MaintenanceError::IoFailure,
    }
}
fn map_maintenance(error: MaintenanceError) -> Fault {
    match error {
        MaintenanceError::DeadlineExpired => Fault::DeadlineExpired,
        MaintenanceError::ClosingPending
        | MaintenanceError::HelperWaitUnknown
        | MaintenanceError::WalWorkerWaitUnknown => Fault::ClosingPending,
        MaintenanceError::ClockUnavailable => Fault::ClockUnavailable,
        MaintenanceError::SecretInvalid => Fault::SecretInvalid,
        MaintenanceError::CapacityExceeded => Fault::CapacityExceeded,
        MaintenanceError::ManifestInvalid | MaintenanceError::WalRangeInvalid => {
            Fault::ManifestInvalid
        }
        _ => Fault::IoFailure,
    }
}
