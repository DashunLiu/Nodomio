//! Shared admission for the HOST manifest and the SSH rollback journal store.
use super::{
    Admission, QueueTime, SourceDisposition, SourcePosition, SshCompaction, SshQueue,
    SshSourceCounters,
    directory::{DB, JOURNAL, OWNER},
};
use crate::{
    identity::{self, IdentityStore, Result},
    protocol::{AgentConfiguration, CollectionConfiguration},
    runtime::RuntimeStore,
};
use std::{
    ffi::CString,
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

const WRITE_RESERVE: u64 = 65_536;
const JOURNAL_HEADER_MAX: u64 = 65_536;
const MIN_SQLITE_PAGE_SIZE: u64 = 512;
// Bound the source for the in-memory SQLite rebuild while holding the writer lock.
const MAX_COMPACTION_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const HOST_FILES: [&str; 3] = ["runtime.lock", "runtime.json", "runtime.next"];
const SSH_FILES: [&str; 3] = [OWNER, DB, JOURNAL];

pub struct SharedBufferPaths<'a> {
    pub host: &'a Path,
    pub ssh: &'a Path,
}

/// Two stores charged to one configuration, persisted with the HOST manifest.
pub struct SharedBuffer {
    pub host: RuntimeStore,
    pub ssh: SshQueue,
    budget: SharedBudget,
    collector_epoch: String,
}

impl SharedBuffer {
    pub fn open(
        paths: SharedBufferPaths<'_>,
        identity: &IdentityStore,
        epoch: &str,
        configuration: &AgentConfiguration,
        time: &QueueTime,
    ) -> Result<Self> {
        time.validated_monotonic_ns()?;
        validate_configuration(configuration, identity)?;
        let persisted = RuntimeStore::persisted_configuration(paths.host, identity)?;
        let effective = persisted.as_ref().unwrap_or(configuration);
        let mut buffer = Self::open_stores(paths, identity, epoch, effective, persisted.as_ref())?;
        buffer.apply_configuration(configuration)?;
        Ok(buffer)
    }

    /// Restore the locally committed settings before attempting a newer target.
    /// The manager's receipt state is scoped separately to its collector epoch.
    pub fn recover(
        paths: SharedBufferPaths<'_>,
        identity: &IdentityStore,
        epoch: &str,
    ) -> Result<Self> {
        let persisted = RuntimeStore::persisted_configuration(paths.host, identity)?
            .ok_or("CONFIGURATION_NOT_APPLIED")?;
        Self::open_stores(paths, identity, epoch, &persisted, Some(&persisted))
    }

    fn open_stores(
        paths: SharedBufferPaths<'_>,
        identity: &IdentityStore,
        epoch: &str,
        effective: &AgentConfiguration,
        persisted: Option<&AgentConfiguration>,
    ) -> Result<Self> {
        SshQueue::preflight(paths.ssh, identity)?;
        let settings = &effective.target.configuration;
        let budget = SharedBudget::open(
            &paths,
            settings.buffer_max_bytes,
            settings.buffer_max_age_seconds,
        )?;
        let host = RuntimeStore::open_shared(paths.host, identity, epoch, budget.clone())?;
        if host.configuration() != persisted {
            return Err("BUFFER_CONFIGURATION_CHANGED");
        }
        let ssh = SshQueue::open_shared(
            paths.ssh,
            identity,
            u64::from(settings.buffer_max_age_seconds),
            budget.clone(),
        )?;
        Ok(Self {
            host,
            ssh,
            budget,
            collector_epoch: epoch.to_ascii_lowercase(),
        })
    }

    /// Check and publish the target under the writer lock. This transition
    /// keeps pending bodies intact and leaves age cleanup to ordinary queue work.
    pub fn apply_configuration(&mut self, configuration: &AgentConfiguration) -> Result<()> {
        if !self.ssh.safely_reportable() {
            return Err("SSH_QUEUE_RECOVERY_REQUIRED");
        }
        self.host.apply_shared(configuration)
    }

    /// Reclaim unused SSH database pages under the shared writer budget.
    pub fn compact_ssh(&mut self) -> Result<Option<SshCompaction>> {
        self.ssh.compact()
    }

    /// Commit a source record that has no SSH event to send.
    pub fn commit_source_disposition(
        &mut self,
        position: &SourcePosition,
        disposition: SourceDisposition,
    ) -> Result<Admission> {
        self.ssh
            .commit_source_disposition(&self.collector_epoch, position, disposition)
    }

    /// Parsing counts for this owner's collector epoch.
    pub fn ssh_source_counters(&self) -> Result<SshSourceCounters> {
        self.ssh.ssh_source_counters(&self.collector_epoch)
    }

    pub fn safely_reportable(&self) -> bool {
        self.host.safely_reportable() && self.ssh.safely_reportable() && self.budget.lock().is_ok()
    }

    /// Filesystem allocation reported for the files and directories of both stores.
    pub fn allocated_bytes(&self) -> Result<u64> {
        self.budget.lock()?.verify_allocation()
    }

    #[cfg(test)]
    pub(crate) fn observed_peak_bytes(&self) -> Result<u64> {
        self.allocated_bytes()?;
        Ok(self
            .budget
            .0
            .observed_peak
            .load(std::sync::atomic::Ordering::Relaxed))
    }

    #[cfg(test)]
    pub(crate) fn observed_journal_peak_bytes(&self) -> Result<u64> {
        self.allocated_bytes()?;
        Ok(self
            .budget
            .0
            .observed_journal_peak
            .load(std::sync::atomic::Ordering::Relaxed))
    }
}

fn validate_configuration(
    configuration: &AgentConfiguration,
    identity: &IdentityStore,
) -> Result<()> {
    AgentConfiguration::decode(
        &serde_json::to_vec(configuration).map_err(|_| "INVALID_PROTOCOL")?,
    )?;
    let binding = identity.binding().ok_or("IDENTITY_NOT_CONFIRMED")?;
    if configuration.agent_id != binding.agent_id
        || configuration.binding_revision != binding.binding_revision
    {
        return Err("CONFIGURATION_BINDING_MISMATCH");
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct SharedBudget(Arc<Budget>);

struct Budget {
    host: File,
    ssh: File,
    host_unit: u64,
    ssh_unit: u64,
    writer: Mutex<EffectiveBudget>,
    #[cfg(test)]
    observed_peak: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    observed_journal_peak: std::sync::atomic::AtomicU64,
}

struct EffectiveBudget {
    limit: u64,
    age_limit: u32,
    host_manifest_bound: u64,
    recovery_required: bool,
}

pub(crate) struct BudgetGuard<'a> {
    budget: &'a Budget,
    effective: MutexGuard<'a, EffectiveBudget>,
}

impl SharedBudget {
    fn open(paths: &SharedBufferPaths<'_>, limit: u64, age_limit: u32) -> Result<Self> {
        let host = identity::directory(paths.host)?;
        let ssh = identity::directory(paths.ssh)?;
        let host_meta = host.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        let ssh_meta = ssh.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        if (host_meta.dev(), host_meta.ino()) == (ssh_meta.dev(), ssh_meta.ino()) {
            return Err("BUFFER_DIRECTORIES_NOT_SEPARATE");
        }
        let budget = Self(Arc::new(Budget {
            host_unit: allocation_unit(&host)?,
            ssh_unit: allocation_unit(&ssh)?,
            host,
            ssh,
            writer: Mutex::new(EffectiveBudget {
                limit,
                age_limit,
                host_manifest_bound: 0,
                recovery_required: false,
            }),
            #[cfg(test)]
            observed_peak: 0.into(),
            #[cfg(test)]
            observed_journal_peak: 0.into(),
        }));
        budget.lock()?.verify_allocation()?;
        Ok(budget)
    }

    pub(crate) fn check_host_directory(&self, directory: &File) -> Result<()> {
        same_directory(&self.0.host, directory)
    }

    pub(crate) fn check_ssh_directory(&self, directory: &File) -> Result<()> {
        same_directory(&self.0.ssh, directory)
    }

    pub(crate) fn lock(&self) -> Result<BudgetGuard<'_>> {
        let effective = self
            .0
            .writer
            .lock()
            .map_err(|_| "BUFFER_RECOVERY_REQUIRED")?;
        if effective.recovery_required {
            return Err("BUFFER_RECOVERY_REQUIRED");
        }
        Ok(BudgetGuard {
            budget: &self.0,
            effective,
        })
    }
}

fn same_directory(expected: &File, opened: &File) -> Result<()> {
    let expected = expected.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
    let opened = opened.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
    if (expected.dev(), expected.ino()) != (opened.dev(), opened.ino()) {
        return Err("BUFFER_DIRECTORY_CHANGED");
    }
    Ok(())
}

fn filesystem_stats(directory: &File) -> Result<libc::statvfs> {
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: directory is live and info is a valid output pointer.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err("LOCAL_STORAGE_ERROR");
    }
    // SAFETY: fstatvfs succeeded and initialized the output.
    Ok(unsafe { info.assume_init() })
}

fn allocation_unit(directory: &File) -> Result<u64> {
    let unit = filesystem_stats(directory)?.f_frsize;
    #[allow(clippy::unnecessary_cast)]
    let unit = unit as u64;
    if unit == 0 || unit > WRITE_RESERVE || !unit.is_power_of_two() {
        return Err("UNSUPPORTED_BUFFER_ALLOCATION_UNIT");
    }
    Ok(unit.max(4096))
}

fn round(bytes: u64, unit: u64) -> u64 {
    bytes.div_ceil(unit).saturating_mul(unit)
}

#[derive(Clone, Copy, Default)]
struct Entry {
    present: bool,
    length: u64,
    allocated: u64,
    charged: u64,
}

struct Files {
    directory_bytes: u64,
    entries: [Entry; 3],
}

impl Files {
    fn allocated(&self) -> u64 {
        self.entries
            .iter()
            .fold(self.directory_bytes, |total, file| {
                total.saturating_add(file.allocated)
            })
    }

    fn charged(&self) -> u64 {
        self.entries
            .iter()
            .fold(self.directory_bytes, |total, file| {
                total.saturating_add(file.charged)
            })
    }
}

fn files(directory: &File, names: [&str; 3], unit: u64) -> Result<Files> {
    let mut entries = [Entry::default(); 3];
    let mut present = Vec::with_capacity(names.len());
    for (i, name) in names.into_iter().enumerate() {
        let c_name = CString::new(name).map_err(|_| "LOCAL_STORAGE_ERROR")?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the descriptor and relative name are valid and stat is writable.
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                continue;
            }
            return Err("LOCAL_STORAGE_ERROR");
        }
        // SAFETY: fstatat succeeded. Read metadata without opening a second
        // descriptor that could release SQLite's process-wide POSIX locks.
        let stat = unsafe { stat.assume_init() };
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        if stat.st_uid != uid
            || stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
        {
            return Err("UNSAFE_PRIVATE_STATE");
        }
        let length = u64::try_from(stat.st_size).map_err(|_| "LOCAL_STORAGE_ERROR")?;
        let allocated = u64::try_from(stat.st_blocks)
            .map_err(|_| "LOCAL_STORAGE_ERROR")?
            .saturating_mul(512);
        entries[i] = Entry {
            present: true,
            length,
            allocated,
            charged: allocated.max(round(length, unit)),
        };
        present.push(name);
    }
    // SAFETY: the held directory is read under the budget's writer lock.
    if unsafe { libc::lseek(directory.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err("LOCAL_STORAGE_ERROR");
    }
    identity::entries(directory, &present)?;
    let directory_bytes = directory
        .metadata()
        .map_err(|_| "LOCAL_STORAGE_ERROR")?
        .blocks()
        .saturating_mul(512);
    Ok(Files {
        directory_bytes,
        entries,
    })
}

fn journal_bytes(database_bytes: u64, unit: u64) -> u64 {
    if database_bytes == 0 {
        return 0;
    }
    // DELETE without cache spill, ATTACH or on-disk temp files. Each original
    // page is journaled at most once with an eight-byte record overhead.
    // Use the smallest supported page for the per-page overhead. Both
    // stores can use the same bound without opening the live database.
    let record_overhead = database_bytes
        .div_ceil(MIN_SQLITE_PAGE_SIZE)
        .saturating_mul(8);
    round(
        JOURNAL_HEADER_MAX
            .saturating_add(database_bytes)
            .saturating_add(record_overhead),
        unit,
    )
}

fn valid_page_size(size: u64) -> bool {
    (MIN_SQLITE_PAGE_SIZE..=65_536).contains(&size) && size.is_power_of_two()
}

impl BudgetGuard<'_> {
    pub(crate) fn limit(&self) -> u64 {
        self.effective.limit
    }

    pub(crate) fn age_limit(&self) -> u32 {
        self.effective.age_limit
    }

    fn files(&self) -> Result<(Files, Files)> {
        let budget = self.budget;
        Ok((
            files(&budget.host, HOST_FILES, budget.host_unit)?,
            files(&budget.ssh, SSH_FILES, budget.ssh_unit)?,
        ))
    }

    fn within(used: u64, limit: u64) -> Result<()> {
        if used > limit {
            return Err("RESOURCE_LIMIT");
        }
        Ok(())
    }

    pub(crate) fn verify_allocation(&self) -> Result<u64> {
        self.verify_allocation_with_limit(self.limit())
    }

    pub(crate) fn verify_allocation_with_limit(&self, limit: u64) -> Result<u64> {
        let (host, ssh) = self.files()?;
        self.verify_file_allocation(&host, &ssh, limit)
    }

    fn verify_file_allocation(&self, host: &Files, ssh: &Files, limit: u64) -> Result<u64> {
        let total = host.allocated().saturating_add(ssh.allocated());
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            self.budget
                .observed_peak
                .fetch_max(total, Ordering::Relaxed);
            self.budget
                .observed_journal_peak
                .fetch_max(ssh.entries[2].allocated, Ordering::Relaxed);
        }
        Self::within(host.charged().saturating_add(ssh.charged()), limit)?;
        Ok(total)
    }

    pub(crate) fn check_host_write(&self, next_bytes: u64, max_future_manifest: u64) -> Result<()> {
        self.check_host_write_with_limit(next_bytes, max_future_manifest, self.limit())
    }

    pub(crate) fn check_host_resize(
        &self,
        next_bytes: u64,
        max_future_manifest: u64,
        settings: &CollectionConfiguration,
    ) -> Result<()> {
        self.check_host_write_with_limit(next_bytes, max_future_manifest, settings.buffer_max_bytes)
    }

    fn check_host_write_with_limit(
        &self,
        next_bytes: u64,
        max_future_manifest: u64,
        limit: u64,
    ) -> Result<()> {
        let (host, ssh) = self.files()?;
        let [lock, _, _] = host.entries;
        let [owner, main, _] = ssh.entries;
        let next = round(next_bytes, self.budget.host_unit);
        let host_metadata = host.directory_bytes.saturating_add(lock.charged);
        let ssh_after = ssh
            .directory_bytes
            .saturating_add(owner.charged)
            .saturating_add(main.charged);
        let ssh_journal = journal_bytes(main.length, self.budget.ssh_unit);
        // The validated HOST shape includes the size after begin copies the
        // latest sample to inflight. Later admission reserves its own space.
        let host_manifest = round(max_future_manifest.max(next_bytes), self.budget.host_unit);
        let immediate = host
            .charged()
            .saturating_add(ssh.charged())
            .saturating_add(next);
        let future = host_metadata
            .saturating_add(ssh_after)
            .saturating_add(host_manifest)
            .saturating_add(host_manifest.max(ssh_journal));
        Self::within(immediate.max(future).saturating_add(WRITE_RESERVE), limit)
    }

    pub(crate) fn record_host_manifest_bound(&mut self, bytes: u64) {
        self.effective.host_manifest_bound = bytes;
    }

    pub(crate) fn mark_recovery_required(&mut self) {
        self.effective.recovery_required = true;
    }

    pub(crate) fn finish_host_publication(
        &mut self,
        bytes: u64,
        settings: Option<&CollectionConfiguration>,
    ) {
        self.record_host_manifest_bound(bytes);
        if let Some(settings) = settings {
            self.effective.limit = settings.buffer_max_bytes;
            self.effective.age_limit = settings.buffer_max_age_seconds;
        }
        self.effective.recovery_required = false;
    }

    pub(crate) fn check_sqlite_compaction(
        &self,
        logical_bytes: u64,
        free_pages: u64,
    ) -> Result<Option<u64>> {
        let (host, ssh) = self.files()?;
        let [_, main, journal] = ssh.entries;
        if journal.present {
            return Err("SSH_QUEUE_RECOVERY_REQUIRED");
        }
        if logical_bytes == 0 || main.length < logical_bytes {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        if free_pages == 0 && main.length == logical_bytes {
            return Ok(None);
        }
        if main.length > MAX_COMPACTION_SOURCE_BYTES {
            return Err("SSH_QUEUE_COMPACTION_WORK_LIMIT");
        }

        // The in-memory rebuild is copied into the existing main file. Its
        // page limit prevents growth and the rollback journal holds old pages.
        let journal_reserve =
            journal_bytes(main.length, self.budget.ssh_unit).saturating_add(WRITE_RESERVE);
        Self::within(
            host.charged()
                .saturating_add(ssh.charged())
                .saturating_add(journal_reserve),
            self.limit(),
        )?;

        // Sparse main pages already count toward the shared budget, but filling
        // them would consume additional blocks on the target filesystem.
        let sparse_bytes = main.charged.saturating_sub(main.allocated);
        let stats = filesystem_stats(&self.budget.ssh)?;
        #[allow(clippy::unnecessary_cast)]
        let available = (stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64);
        Self::within(journal_reserve.saturating_add(sparse_bytes), available)?;
        Ok(Some(main.allocated))
    }

    pub(crate) fn sqlite_main_allocation(&self) -> Result<u64> {
        let (host, ssh) = self.files()?;
        let [_, main, journal] = ssh.entries;
        if journal.present {
            return Err("SSH_QUEUE_RECOVERY_REQUIRED");
        }
        if main.length == 0 {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        self.verify_file_allocation(&host, &ssh, self.limit())?;
        Ok(main.allocated)
    }

    pub(crate) fn sqlite_max_pages(&self, page_size: u64, creating_owner: bool) -> Result<u64> {
        if !valid_page_size(page_size) {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        let (host, ssh) = self.files()?;
        let [_, manifest, _] = host.entries;
        let [owner, main, _] = ssh.entries;
        let ssh_unit = self.budget.ssh_unit;
        let host_manifest =
            round(self.effective.host_manifest_bound, self.budget.host_unit).max(manifest.charged);
        let extra_main = main.charged.saturating_sub(round(main.length, ssh_unit));
        let owner = if creating_owner {
            owner.charged.max(ssh_unit)
        } else {
            owner.charged
        };
        let available = self.limit().saturating_sub(
            host.charged()
                .saturating_sub(manifest.charged)
                .saturating_add(host_manifest)
                .saturating_add(ssh.directory_bytes)
                .saturating_add(owner)
                .saturating_add(extra_main)
                .saturating_add(WRITE_RESERVE),
        );
        // The owner serializes writes. Either a HOST replacement or a full
        // SQLite rollback journal can coexist with the maximum stable DB.
        let mut lower = 0;
        let mut upper = available / page_size;
        while lower < upper {
            let pages = lower + (upper - lower).div_ceil(2);
            let database_bytes = pages * page_size;
            let database = round(database_bytes, ssh_unit);
            let transient = host_manifest.max(journal_bytes(database_bytes, ssh_unit));
            if database.saturating_add(transient) <= available {
                lower = pages;
            } else {
                upper = pages - 1;
            }
        }
        if lower == 0 || main.length.div_ceil(page_size) > lower {
            return Err("RESOURCE_LIMIT");
        }
        Ok(lower)
    }
}

#[cfg(test)]
#[path = "budget_tests.rs"]
mod tests;
