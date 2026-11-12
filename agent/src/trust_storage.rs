//! Bounded opaque storage, not a TUF verifier or an installer.
//!
//! Inspection establishes filesystem/format/binding facts only. A checksum cannot
//! authenticate metadata or recover lost high-water marks. No existing-state update
//! API is exposed until a verifier and conditional executor are connected.
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};
/// This slice's input budget, not a capacity claim for a future TUF role manifest.
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
const PURPOSE: &str = "UNVERIFIED_STORAGE_BOUNDARY";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    InvalidContext,
    MissingDirectory,
    MissingAuthority,
    PermissionDenied,
    UnsafeFilesystem,
    BindingMismatch,
    InvalidEnvelope,
    ReadBudgetExceeded,
    RecoveryRequired,
    GenerationChanged,
    Conflict,
    WriterBusy,
    CommitOutcomeUnknown,
    Io,
}
pub type Result<T> = std::result::Result<T, StorageError>;
impl StorageError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidContext => "INVALID_EXPECTED_CONTEXT",
            Self::MissingDirectory => "MISSING_DIRECTORY",
            Self::MissingAuthority => "MISSING_AUTHORITY",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::UnsafeFilesystem => "UNSAFE_FILESYSTEM",
            Self::BindingMismatch => "EXPECTED_BINDING_MISMATCH",
            Self::InvalidEnvelope => "INVALID_STORAGE_ENVELOPE",
            Self::ReadBudgetExceeded => "READ_BUDGET_EXCEEDED",
            Self::RecoveryRequired => "ORIGINAL_INTENT_REQUIRES_REVIEW",
            Self::GenerationChanged => "EXPECTED_GENERATION_CHANGED",
            Self::Conflict => "EXISTING_TARGET_CONFLICT",
            Self::WriterBusy => "WRITER_BUSY",
            Self::CommitOutcomeUnknown => "COMMIT_OUTCOME_UNKNOWN",
            Self::Io => "STORAGE_IO_ERROR",
        }
    }
}
/// Independent caller input. Never derive this from the inspected envelope.
/// This validates shape, not provenance: a protected installer must supply the facts.
#[derive(Clone)]
pub struct ExpectedInstallation {
    path: PathBuf,
    installation_id: String,
    source_config_id: String,
    owner_uid: u32,
}
impl ExpectedInstallation {
    pub fn new(path: &Path, installation: &str, source: &str, owner_uid: u32) -> Result<Self> {
        if !path.is_absolute()
            || path
                .to_str()
                .is_none_or(|p| p.len() > 4096 || p.as_bytes().contains(&0))
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            || path.components().count() < 2
            || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
            || !crate::identity::uuid(installation)
            || !crate::identity::public_id(source)
        {
            return Err(StorageError::InvalidContext);
        }
        Ok(Self {
            path: path.to_owned(),
            installation_id: installation.into(),
            source_config_id: source.into(),
            owner_uid,
        })
    }
}
/// Assertion from protected install apply, not proof of a safe installation.
/// Caller first establishes new lifecycle, initial trust and absence of conflicting
/// service/identity/config/queue state outside this dedicated directory. No CLI init.
pub struct NewInstallationIntent {
    expected: ExpectedInstallation,
    operation_id: String,
}
impl NewInstallationIntent {
    pub fn new(expected: ExpectedInstallation, operation_id: &str) -> Result<Self> {
        if !crate::identity::uuid(operation_id) {
            return Err(StorageError::InvalidContext);
        }
        Ok(Self {
            expected,
            operation_id: operation_id.into(),
        })
    }
}
/// Structurally readable opaque bytes; NOT authenticated or suitable for authorizing
/// downloads, installs or rollback decisions. Fields cannot be mutated by callers.
pub struct UnverifiedSnapshot {
    generation: u64,
    content_sha256: String,
    initialization_operation_id: String,
    payload: Vec<u8>,
    file_identity: (u64, u64),
}
impl UnverifiedSnapshot {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }
    pub fn initialization_operation_id(&self) -> &str {
        &self.initialization_operation_id
    }
    pub fn opaque_payload(&self) -> &[u8] {
        &self.payload
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Record {
    schema_version: u32,
    purpose: String,
    installation_id: String,
    source_config_id: String,
    state_location: String,
    owner_uid: u32,
    initialization_operation_id: String,
    generation: u64,
    payload_base64: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Envelope {
    record: Record,
    checksum_sha256: String,
}
fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn private(
    metadata: &fs::Metadata,
    expected: &ExpectedInstallation,
    directory: bool,
) -> Result<()> {
    if metadata.uid() != expected.owner_uid
        || metadata.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !metadata.is_dir() || metadata.nlink() == 0
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err(StorageError::UnsafeFilesystem);
    }
    Ok(())
}
fn io_error(error: std::io::Error, directory: bool) -> StorageError {
    match error.kind() {
        std::io::ErrorKind::NotFound => {
            if directory {
                StorageError::MissingDirectory
            } else {
                StorageError::MissingAuthority
            }
        }
        std::io::ErrorKind::PermissionDenied => StorageError::PermissionDenied,
        _ => StorageError::Io,
    }
}
fn directory(expected: &ExpectedInstallation) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&expected.path)
        .map_err(|e| io_error(e, true))?;
    private(
        &file.metadata().map_err(|_| StorageError::Io)?,
        expected,
        true,
    )?;
    Ok(file)
}
fn openat(dir: &File, name: &CStr, flags: i32) -> Result<File> {
    // SAFETY: dir is live, name is NUL-terminated; mode is supplied for O_CREAT.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error(), false));
    }
    // SAFETY: openat returned a new, uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
/// '.' gets an independent offset. Enumeration itself is bounded; unknown entries block.
fn entries(dir: &File) -> Result<Vec<Vec<u8>>> {
    use std::os::fd::IntoRawFd;
    let fd = openat(dir, c".", libc::O_DIRECTORY | libc::O_RDONLY)?.into_raw_fd();
    // SAFETY: fd is an owned directory descriptor; fdopendir takes it on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and left ownership with us.
        unsafe { libc::close(fd) };
        return Err(StorageError::Io);
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: guard uniquely owns the successful fdopendir stream.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(stream);
    let mut found = Vec::new();
    loop {
        // SAFETY: errno is thread-local, stream is live and exclusively used here.
        let item = unsafe {
            #[cfg(target_os = "linux")]
            {
                *libc::__errno_location() = 0;
            }
            #[cfg(target_os = "macos")]
            {
                *libc::__error() = 0;
            }
            libc::readdir(stream.0)
        };
        if item.is_null() {
            if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                return Err(StorageError::Io);
            }
            return Ok(found);
        }
        // SAFETY: readdir's dirent is valid until the next call, with terminated name.
        let name = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if found.len() >= 2 {
            return Err(StorageError::RecoveryRequired);
        }
        found.push(name.to_vec());
    }
}
fn read_snapshot(dir: &File, expected: &ExpectedInstallation) -> Result<UnverifiedSnapshot> {
    private(
        &dir.metadata().map_err(|_| StorageError::Io)?,
        expected,
        true,
    )?;
    if entries(dir)?.iter().any(|n| n != b"authority.json") {
        return Err(StorageError::RecoveryRequired);
    }
    let file = openat(dir, c"authority.json", libc::O_RDONLY)?;
    let before = file.metadata().map_err(|_| StorageError::Io)?;
    private(&before, expected, false)?;
    if before.len() > MAX_ENVELOPE_BYTES as u64 {
        return Err(StorageError::ReadBudgetExceeded);
    }
    let mut bytes = Vec::new();
    (&file)
        .take((MAX_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(e, false))?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(StorageError::ReadBudgetExceeded);
    }
    let after = file.metadata().map_err(|_| StorageError::Io)?;
    private(&after, expected, false)?;
    if (
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(StorageError::GenerationChanged);
    }
    let envelope: Envelope =
        serde_json::from_slice(&bytes).map_err(|_| StorageError::InvalidEnvelope)?;
    let record = envelope.record;
    if record.schema_version != 1
        || record.purpose != PURPOSE
        || record.generation == 0
        || !crate::identity::uuid(&record.initialization_operation_id)
        || envelope.checksum_sha256
            != sha256(&serde_json::to_vec(&record).map_err(|_| StorageError::InvalidEnvelope)?)
    {
        return Err(StorageError::InvalidEnvelope);
    }
    if record.installation_id != expected.installation_id
        || record.source_config_id != expected.source_config_id
        || record.state_location != expected.path.to_str().ok_or(StorageError::InvalidContext)?
        || record.owner_uid != expected.owner_uid
    {
        return Err(StorageError::BindingMismatch);
    }
    if record.payload_base64.len() > MAX_PAYLOAD_BYTES.div_ceil(3) * 4 {
        return Err(StorageError::ReadBudgetExceeded);
    }
    let payload = STANDARD
        .decode(&record.payload_base64)
        .map_err(|_| StorageError::InvalidEnvelope)?;
    if payload.is_empty() {
        return Err(StorageError::InvalidEnvelope);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(StorageError::ReadBudgetExceeded);
    }
    Ok(UnverifiedSnapshot {
        generation: record.generation,
        content_sha256: sha256(&bytes),
        initialization_operation_id: record.initialization_operation_id,
        payload,
        file_identity: (before.dev(), before.ino()),
    })
}
/// Pure read-only: no lock, creation, time write, permissions repair or cleanup.
pub fn inspect_existing(expected: &ExpectedInstallation) -> Result<UnverifiedSnapshot> {
    read_snapshot(&directory(expected)?, expected)
}
/// Read-only handle retaining the original directory and expected content generation.
/// A future update capability requires verifier integration and a real conditional
/// executor covering the complete lifetime of blocking file work.
pub struct ExistingStore {
    directory: File,
    expected: ExpectedInstallation,
    generation: u64,
    content_sha256: String,
    file_identity: (u64, u64),
    stopped: std::cell::Cell<bool>,
}
impl ExistingStore {
    pub fn read(&self) -> Result<UnverifiedSnapshot> {
        if self.stopped.get() {
            return Err(StorageError::RecoveryRequired);
        }
        let result = self.read_checked();
        if result.is_err() {
            self.stopped.set(true);
        }
        result
    }
    fn read_checked(&self) -> Result<UnverifiedSnapshot> {
        // Recheck the named location only for identity; read bytes from the original FD.
        let named = directory(&self.expected)?
            .metadata()
            .map_err(|_| StorageError::Io)?;
        let anchored = self.directory.metadata().map_err(|_| StorageError::Io)?;
        if (named.dev(), named.ino()) != (anchored.dev(), anchored.ino()) {
            return Err(StorageError::GenerationChanged);
        }
        let snapshot = read_snapshot(&self.directory, &self.expected)?;
        if snapshot.generation != self.generation
            || snapshot.content_sha256 != self.content_sha256
            || snapshot.file_identity != self.file_identity
        {
            return Err(StorageError::GenerationChanged);
        }
        Ok(snapshot)
    }
}
pub fn open_existing(expected: &ExpectedInstallation) -> Result<ExistingStore> {
    let directory = directory(expected)?;
    let snapshot = read_snapshot(&directory, expected)?;
    Ok(ExistingStore {
        directory,
        expected: expected.clone(),
        generation: snapshot.generation,
        content_sha256: snapshot.content_sha256,
        file_identity: snapshot.file_identity,
        stopped: std::cell::Cell::new(false),
    })
}
struct Writer<'a>(&'a File);
impl Drop for Writer<'_> {
    fn drop(&mut self) {
        // SAFETY: the live directory descriptor owns this cooperative flock.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
/// Publish opaque initial bytes without replacing an existing authority. This is NOT
/// INIT_NEW authorization, trusted root acceptance or installer apply. Any failure
/// after creating the temp entry preserves evidence; never retry as a fresh install.
pub fn initialize_new(
    intent: &NewInstallationIntent,
    payload: &[u8],
) -> Result<UnverifiedSnapshot> {
    // SAFETY: geteuid has no preconditions or memory access. A writer must own
    // its future 0600 files; root access cannot substitute another expected owner.
    if intent.expected.owner_uid != unsafe { libc::geteuid() } {
        return Err(StorageError::InvalidContext);
    }
    if payload.is_empty() {
        return Err(StorageError::InvalidEnvelope);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(StorageError::ReadBudgetExceeded);
    }
    let expected = &intent.expected;
    let dir = directory(expected)?;
    // SAFETY: dir is live; flock only serializes cooperating writers of this directory.
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(StorageError::WriterBusy);
    }
    let _writer = Writer(&dir);
    if !entries(&dir)?.is_empty() {
        return Err(StorageError::Conflict);
    }
    let record = Record {
        schema_version: 1,
        purpose: PURPOSE.into(),
        installation_id: expected.installation_id.clone(),
        source_config_id: expected.source_config_id.clone(),
        state_location: expected
            .path
            .to_str()
            .ok_or(StorageError::InvalidContext)?
            .into(),
        owner_uid: expected.owner_uid,
        initialization_operation_id: intent.operation_id.clone(),
        generation: 1,
        payload_base64: STANDARD.encode(payload),
    };
    let checksum_sha256 =
        sha256(&serde_json::to_vec(&record).map_err(|_| StorageError::InvalidEnvelope)?);
    let bytes = serde_json::to_vec(&Envelope {
        record,
        checksum_sha256,
    })
    .map_err(|_| StorageError::InvalidEnvelope)?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(StorageError::ReadBudgetExceeded);
    }
    let mut next = openat(
        &dir,
        c"authority.next",
        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
    )
    .map_err(|_| StorageError::Conflict)?;
    // From the first created entry onward, failure does not imply no effect.
    let mut publish = || -> std::io::Result<()> {
        #[cfg(test)]
        checkpoint(CommitStage::Created, &dir)?;
        next.write_all(&bytes)?;
        #[cfg(test)]
        checkpoint(CommitStage::Written, &dir)?;
        next.sync_all()?;
        #[cfg(test)]
        checkpoint(CommitStage::FileSynced, &dir)?;
        // SAFETY: both directory descriptors are live and literal names terminated.
        if unsafe {
            libc::linkat(
                dir.as_raw_fd(),
                c"authority.next".as_ptr(),
                dir.as_raw_fd(),
                c"authority.json".as_ptr(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        #[cfg(test)]
        checkpoint(CommitStage::Published, &dir)?;
        // SAFETY: only the temporary name created O_EXCL by this attempt is removed.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), c"authority.next".as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        #[cfg(test)]
        checkpoint(CommitStage::Unlinked, &dir)?;
        dir.sync_all()?;
        #[cfg(test)]
        checkpoint(CommitStage::ParentSynced, &dir)?;
        Ok(())
    };
    publish().map_err(|_| StorageError::CommitOutcomeUnknown)?;
    read_snapshot(&dir, expected).map_err(|_| StorageError::CommitOutcomeUnknown)
}
/// Read-only observation of the original intent. Partial evidence, another operation,
/// missing state or an ambiguous publication window blocks; no cleanup/resume occurs.
pub fn inspect_original_intent(intent: &NewInstallationIntent) -> Result<UnverifiedSnapshot> {
    let snapshot = inspect_existing(&intent.expected)?;
    if snapshot.initialization_operation_id != intent.operation_id {
        return Err(StorageError::Conflict);
    }
    Ok(snapshot)
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitStage {
    Created,
    Written,
    FileSynced,
    Published,
    Unlinked,
    ParentSynced,
}
#[cfg(test)]
thread_local! {
    static FAIL_AT: std::cell::Cell<Option<CommitStage>> = const { std::cell::Cell::new(None) };
    static RACE_WINNER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
fn checkpoint(stage: CommitStage, dir: &File) -> std::io::Result<()> {
    if stage == CommitStage::FileSynced && RACE_WINNER.replace(false) {
        let mut winner = openat(
            dir,
            c"authority.json",
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
        )
        .unwrap();
        winner.write_all(b"independent race winner").unwrap();
        winner.sync_all().unwrap();
    }
    if FAIL_AT.get() == Some(stage) {
        Err(std::io::Error::other("injected storage barrier failure"))
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn intent(path: &Path) -> NewInstallationIntent {
        // SAFETY: geteuid has no preconditions or memory access.
        let uid = unsafe { libc::geteuid() };
        NewInstallationIntent::new(
            ExpectedInstallation::new(
                path,
                "d1068b94-754c-4aa3-8b70-2dd4f04fbe3d",
                "test-source",
                uid,
            )
            .unwrap(),
            "a12378e9-2248-46aa-8826-965b75bd260a",
        )
        .unwrap()
    }
    #[test]
    fn failed_publication_barriers_preserve_evidence_and_block_new_initialization() {
        for stage in [
            CommitStage::Created,
            CommitStage::Written,
            CommitStage::FileSynced,
            CommitStage::Published,
            CommitStage::Unlinked,
            CommitStage::ParentSynced,
        ] {
            let d = tempfile::tempdir().unwrap();
            fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let intent = intent(d.path());
            FAIL_AT.set(Some(stage));
            let result = initialize_new(&intent, b"unverified test payload");
            FAIL_AT.set(None);
            assert!(
                matches!(result, Err(StorageError::CommitOutcomeUnknown)),
                "an injected publication failure cannot report a known result"
            );
            assert!(matches!(
                initialize_new(&intent, b"replacement"),
                Err(StorageError::Conflict)
            ));
            let names: Vec<_> = fs::read_dir(d.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert!(!names.is_empty());
            if [
                CommitStage::Created,
                CommitStage::Written,
                CommitStage::FileSynced,
                CommitStage::Published,
            ]
            .contains(&stage)
            {
                assert!(d.path().join("authority.next").exists());
                assert!(matches!(
                    inspect_original_intent(&intent),
                    Err(StorageError::RecoveryRequired)
                ));
            } else {
                assert_eq!(
                    inspect_original_intent(&intent).unwrap().opaque_payload(),
                    b"unverified test payload"
                );
            }
        }
    }
    #[test]
    fn last_moment_uncooperative_publisher_cannot_be_overwritten() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        RACE_WINNER.set(true);
        assert!(matches!(
            initialize_new(&intent(d.path()), b"loser payload"),
            Err(StorageError::CommitOutcomeUnknown)
        ));
        assert_eq!(
            fs::read(d.path().join("authority.json")).unwrap(),
            b"independent race winner"
        );
        assert!(d.path().join("authority.next").exists());
        assert!(matches!(
            inspect_existing(&intent(d.path()).expected),
            Err(StorageError::RecoveryRequired)
        ));
    }
}
