use crate::identity::{self, Binding, IdentityStore, Result, Status, Target};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};

pub(super) const DB: &str = "ssh-buffer.sqlite3";
pub(super) const JOURNAL: &str = "ssh-buffer.sqlite3-journal";
pub(super) const OWNER: &str = "ssh-buffer.owner";
pub(super) const APPLICATION_ID: u32 = 0x4e44_5351;
pub(super) const SCHEMA_VERSION: u32 = 7;
const OWNER_LIMIT: u64 = 2048;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct QueueBinding {
    pub(super) target: Target,
    pub(super) binding: Binding,
    pub(super) operation_id: String,
}
impl QueueBinding {
    pub(super) fn new(identity: &IdentityStore) -> Result<Self> {
        if identity.status() != Status::Bound {
            return Err("IDENTITY_NOT_CONFIRMED");
        }
        identity.credential()?;
        Ok(Self {
            target: identity.target().clone(),
            binding: identity.binding().ok_or("IDENTITY_NOT_CONFIRMED")?.clone(),
            operation_id: identity.operation_id().to_owned(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Owner {
    version: u32,
    database_inode: u64,
    binding: QueueBinding,
}

pub(super) struct QueueDirectory {
    directory: File,
    path: PathBuf,
    existing: bool,
}

/// Files created exclusively by a single call while the empty directory is
/// locked. Held descriptors let cleanup distinguish these from replacements.
pub(super) struct NewQueueFiles<'a> {
    directory: &'a QueueDirectory,
    database: File,
    marker: Option<File>,
}
impl Drop for QueueDirectory {
    fn drop(&mut self) {
        // SAFETY: the guard owns the opened directory description and its flock.
        unsafe { libc::flock(self.directory.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn optional_entry(directory: &File, path: &Path, name: &str) -> Result<Option<File>> {
    match fs::symlink_metadata(path.join(name)) {
        Ok(_) => Ok(Some(identity::entry(directory, name, false)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("UNSAFE_SSH_QUEUE_DIRECTORY"),
    }
}

// SQLite opens journals by pathname. Prove that only root or the effective
// user can replace a component, including when the path passes through /tmp.
fn trusted_path(path: &Path, directory: &File) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|_| "UNSAFE_SSH_QUEUE_DIRECTORY")?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let mut leaf = None;
    for ancestor in canonical.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| "UNSAFE_SSH_QUEUE_DIRECTORY")?;
        if !metadata.is_dir()
            || ![0, uid].contains(&metadata.uid())
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err("UNSAFE_SSH_QUEUE_DIRECTORY");
        }
        leaf.get_or_insert((metadata.dev(), metadata.ino()));
    }
    let opened = directory.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
    if leaf != Some((opened.dev(), opened.ino())) {
        return Err("UNSAFE_SSH_QUEUE_DIRECTORY");
    }
    Ok(canonical)
}

impl QueueDirectory {
    pub(super) fn open(
        path: &Path,
        identity: &IdentityStore,
        binding: &QueueBinding,
    ) -> Result<Self> {
        let directory = identity::directory(path)?;
        if identity.shares_directory(&directory)? {
            return Err("SSH_QUEUE_DIRECTORY_NOT_SEPARATE");
        }
        let path = trusted_path(path, &directory)?;
        // SAFETY: flock accesses no Rust memory; the directory descriptor is live.
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("SSH_QUEUE_LOCKED");
        }
        let mut guarded = Self {
            directory,
            path,
            existing: false,
        };
        guarded.existing = guarded.check_layout(binding)?;
        Ok(guarded)
    }

    fn require_entries(&self, expected: &[&str]) -> Result<()> {
        // SAFETY: The directory descriptor is live and held under our flock.
        if unsafe { libc::lseek(self.directory.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
            return Err("LOCAL_STORAGE_ERROR");
        }
        identity::entries(&self.directory, expected)
    }

    fn check_layout(&self, binding: &QueueBinding) -> Result<bool> {
        let marker = optional_entry(&self.directory, &self.path, OWNER)?;
        let main = optional_entry(&self.directory, &self.path, DB)?;
        let journal = optional_entry(&self.directory, &self.path, JOURNAL)?;
        let expected: Vec<_> = [
            (OWNER, marker.is_some()),
            (DB, main.is_some()),
            (JOURNAL, journal.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, present)| present.then_some(name))
        .collect();
        self.require_entries(&expected)?;
        if expected.is_empty() {
            return Ok(false);
        }
        let (Some(marker), Some(mut main)) = (marker, main) else {
            return Err("INVALID_SSH_QUEUE_STATE");
        };
        let mut bytes = Vec::new();
        marker
            .take(OWNER_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "LOCAL_STORAGE_ERROR")?;
        if bytes.len() as u64 > OWNER_LIMIT {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        let marker: Owner =
            serde_json::from_slice(&bytes).map_err(|_| "INVALID_SSH_QUEUE_STATE")?;
        if marker.version != 1 || marker.binding != *binding {
            return Err("SSH_QUEUE_BINDING_MISMATCH");
        }
        let metadata = main.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        if metadata.ino() != marker.database_inode {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        // Check before SQLite can recover a rollback journal. WAL and foreign
        // SQLite applications must not be opened for writing as this queue.
        let mut header = [0; 100];
        main.read_exact(&mut header)
            .map_err(|_| "INVALID_SSH_QUEUE_STATE")?;
        let version = u32::from_be_bytes(header[60..64].try_into().unwrap());
        if &header[..16] != b"SQLite format 3\0"
            || header[18..20] != [1, 1]
            || !(1..=SCHEMA_VERSION).contains(&version)
            || header[68..72] != APPLICATION_ID.to_be_bytes()
        {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        Ok(true)
    }

    pub(super) fn database_path(&self) -> PathBuf {
        self.path.join(DB)
    }
    pub(super) fn descriptor(&self) -> &File {
        &self.directory
    }
    pub(super) fn is_existing(&self) -> bool {
        self.existing
    }

    /// Bound possible hot-journal recovery before SQLite opens the database.
    pub(super) fn shared_recovery_pages(&self) -> Result<(u64, u64)> {
        let mut main = identity::entry(&self.directory, DB, false)?;
        let mut header = [0; 100];
        main.read_exact(&mut header)
            .map_err(|_| "INVALID_SSH_QUEUE_STATE")?;
        let page_size = match u16::from_be_bytes([header[16], header[17]]) {
            1 => 65_536,
            size => u64::from(size),
        };
        // The shared envelope assumes a fixed page size and no auto-vacuum.
        if !valid_sqlite_block_size(page_size) || header[52..56] != [0; 4] {
            return Err("UNSUPPORTED_SSH_QUEUE_STORAGE_LAYOUT");
        }
        let length = main.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?.len();
        let mut journal_synced = false;
        if let Some(journal) = optional_entry(&self.directory, &self.path, JOURNAL)? {
            let mut head = Vec::with_capacity(28);
            journal
                .take(28)
                .read_to_end(&mut head)
                .map_err(|_| "LOCAL_STORAGE_ERROR")?;
            // A zero magic prefix is an unsynced journal. It cannot restore
            // pages. A synced journal begins with this fixed SQLite magic.
            if !head.iter().take(8).all(|byte| *byte == 0) {
                const MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
                if head.len() != 28 || head[..8] != MAGIC {
                    return Err("UNSUPPORTED_SSH_QUEUE_STORAGE_LAYOUT");
                }
                let field = |offset: usize| {
                    u64::from(u32::from_be_bytes(
                        head[offset..offset + 4].try_into().unwrap(),
                    ))
                };
                let original_pages = field(16);
                let sector_size = field(20);
                if original_pages == 0
                    || !valid_sqlite_block_size(sector_size)
                    || field(24) != page_size
                {
                    return Err("UNSUPPORTED_SSH_QUEUE_STORAGE_LAYOUT");
                }
                // Shared mode can recover the queue's ordinary append/write
                // crashes. An older journal that would extend the main file
                // needs separate recovery because its existing footprint is
                // outside the shared single-header write model.
                if original_pages * page_size > length {
                    return Err("SSH_QUEUE_RECOVERY_REQUIRED");
                }
                journal_synced = true;
            }
        }
        if !journal_synced && length % page_size != 0 {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        Ok((page_size, length.div_ceil(page_size)))
    }

    pub(super) fn begin_creation(&self) -> Result<NewQueueFiles<'_>> {
        self.require_entries(&[])?;
        Ok(NewQueueFiles {
            directory: self,
            database: identity::entry(&self.directory, DB, true)?,
            marker: None,
        })
    }
}

fn valid_sqlite_block_size(bytes: u64) -> bool {
    (512..=65_536).contains(&bytes) && bytes.is_power_of_two()
}

impl NewQueueFiles<'_> {
    fn check_inode(&self, name: &str, created: &File) -> Result<()> {
        let entry = identity::entry(&self.directory.directory, name, false)?;
        let entry = entry.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        let created = created.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        if (entry.dev(), entry.ino()) != (created.dev(), created.ino()) {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        Ok(())
    }

    pub(super) fn publish_owner(&mut self, binding: &QueueBinding) -> Result<()> {
        self.directory.require_entries(&[DB])?;
        self.check_inode(DB, &self.database)?;
        let owner = Owner {
            version: 1,
            database_inode: self
                .database
                .metadata()
                .map_err(|_| "LOCAL_STORAGE_ERROR")?
                .ino(),
            binding: binding.clone(),
        };
        let bytes = serde_json::to_vec(&owner).map_err(|_| "LOCAL_STORAGE_ERROR")?;
        if bytes.len() as u64 > OWNER_LIMIT {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        self.database
            .sync_all()
            .map_err(|_| "LOCAL_STORAGE_ERROR")?;
        let marker = self
            .marker
            .insert(identity::entry(&self.directory.directory, OWNER, true)?);
        marker
            .write_all(&bytes)
            .and_then(|()| marker.sync_all())
            .map_err(|_| "LOCAL_STORAGE_ERROR")?;
        self.directory
            .directory
            .sync_all()
            .map_err(|_| "LOCAL_STORAGE_ERROR")
    }

    /// The caller must have closed SQLite. The unpublished schema transaction
    /// uses an in-memory journal, so any extra entry here is unexpected.
    pub(super) fn cleanup(self) -> Result<()> {
        let expected: &[&str] = if self.marker.is_some() {
            &[DB, OWNER]
        } else {
            &[DB]
        };
        self.directory.require_entries(expected)?;
        self.check_inode(DB, &self.database)?;
        if let Some(marker) = &self.marker {
            self.check_inode(OWNER, marker)?;
            self.remove(OWNER)?;
        }
        self.remove(DB)?;
        self.directory
            .directory
            .sync_all()
            .map_err(|_| "LOCAL_STORAGE_ERROR")
    }

    fn remove(&self, name: &str) -> Result<()> {
        let name = CString::new(name).map_err(|_| "LOCAL_STORAGE_ERROR")?;
        // SAFETY: The locked directory descriptor is live and name is one of
        // the verified fixed-role entries, NUL-terminated and relative.
        if unsafe { libc::unlinkat(self.directory.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err("LOCAL_STORAGE_ERROR");
        }
        Ok(())
    }
}
