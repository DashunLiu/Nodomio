//! Bounded HOST development storage and collection.
use crate::{
    buffer::budget::{BudgetGuard, SharedBudget},
    collect::Collector,
    identity::{self, Binding, IdentityStore, Result, Target},
    model::*,
    protocol::{AgentConfiguration, CollectionConfiguration},
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const MAX_METRIC_REQUEST: usize = 4 * 1024 * 1024;
const MAX_MANIFEST: usize = 20 * 1024 * 1024;
/// Before first-install settlement only the configuration is persisted here.
pub const FIRST_HEALTH_MANIFEST_MAX_BYTES: usize = 8 * 1024;
const RESERVE: u64 = 64 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StoredSample {
    pub sample_id: String,
    pub boot_id: String,
    pub monotonic_ns: u64,
    pub body: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    target: Target,
    binding: Binding,
    operation_id: String,
    configuration: Option<AgentConfiguration>,
    latest: Option<StoredSample>,
    inflight: Option<StoredSample>,
    discarded_samples_total: u64,
    #[serde(default)]
    discarded_collector_epoch: Option<String>,
}
/// The protocol IdentityStore is held simultaneously, so one writer owns both stores.
pub struct RuntimeStore {
    directory: File,
    lock: File,
    manifest: Manifest,
    poisoned: bool,
    collector_epoch: String,
    attempt_active: bool,
    shared_budget: Option<SharedBudget>,
}
impl Drop for RuntimeStore {
    fn drop(&mut self) {
        // SAFETY: lock is a live uniquely owned file descriptor; flock accesses no Rust memory.
        unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
        // SAFETY: this store also owns the cooperative directory initialization lock.
        unsafe { libc::flock(self.directory.as_raw_fd(), libc::LOCK_UN) };
    }
}
fn remove(directory: &File, name: &str) -> Result<()> {
    let name = CString::new(name).map_err(|_| "LOCAL_STORAGE_ERROR")?;
    // SAFETY: directory is live and name is NUL terminated, relative and fixed by callers.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err("LOCAL_STORAGE_ERROR");
    }
    Ok(())
}
fn file_bytes(file: &File) -> Result<u64> {
    file.metadata()
        .map(|m| m.blocks().saturating_mul(512))
        .map_err(|_| "LOCAL_STORAGE_ERROR")
}
fn encoded_len(value: &impl Serialize) -> Result<u64> {
    struct Length(u64);
    impl Write for Length {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("manifest length overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut length = Length(0);
    serde_json::to_writer(&mut length, value).map_err(|_| "INVALID_RUNTIME_STATE")?;
    Ok(length.0)
}

fn host_manifest_bound(manifest: &Manifest, bytes: u64, epoch: &str) -> Result<u64> {
    // Begin can replace the inflight slot with a duplicate of latest. Derive
    // its exact encoded growth without allocating another copy of either body.
    let begin_growth = if manifest.latest.is_some() {
        encoded_len(&manifest.latest)?.saturating_sub(encoded_len(&manifest.inflight)?)
    } else {
        0
    };
    // Normalize the two bookkeeping fields that can grow on begin/ACK even
    // when the retained payloads are unchanged or smaller.
    let counter_growth = encoded_len(&u64::MAX)? - encoded_len(&manifest.discarded_samples_total)?;
    let epoch_growth = encoded_len(&Some(epoch))?
        .saturating_sub(encoded_len(&manifest.discarded_collector_epoch)?);
    bytes
        .checked_add(begin_growth)
        .and_then(|bound| bound.checked_add(counter_growth))
        .and_then(|bound| bound.checked_add(epoch_growth))
        .ok_or("RESOURCE_LIMIT")
}
// Bounded exact decimal numeric tokens; no independent binary-float rounding.
fn ns_number(ns: u64) -> Result<serde_json::Number> {
    format!("{}.{:09}", ns / 1_000_000_000, ns % 1_000_000_000)
        .parse()
        .map_err(|_| "INVALID_METRIC_SAMPLE")
}
fn exact_nanoseconds(value: &serde_json::Value) -> Option<u64> {
    let token = value.as_number()?.to_string();
    if token.len() > 64 || token.starts_with('-') {
        return None;
    }
    let (mantissa, exponent) = match token.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
        None => (token.as_str(), 0),
    };
    let fractional = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len() as i32);
    let mut power = 9i32.checked_add(exponent)?.checked_sub(fractional)?;
    let mut digits = mantissa.bytes().filter(|b| *b != b'.').collect::<Vec<_>>();
    if digits.is_empty() || digits.iter().any(|b| !b.is_ascii_digit()) {
        return None;
    }
    while digits.last() == Some(&b'0') && power < 0 {
        digits.pop();
        power += 1;
    }
    if digits.iter().all(|b| *b == b'0') || digits.is_empty() {
        return Some(0);
    }
    if !(0..=20).contains(&power) {
        return None;
    }
    let integer = digits.into_iter().try_fold(0u128, |n, b| {
        n.checked_mul(10)?.checked_add(u128::from(b - b'0'))
    })?;
    u64::try_from(integer.checked_mul(10u128.checked_pow(power as u32)?)?).ok()
}
pub(crate) fn valid_sample(sample: &StoredSample) -> Result<()> {
    if !identity::uuid(&sample.sample_id)
        || !identity::uuid(&sample.boot_id)
        || sample.body.len() + 14 > MAX_METRIC_REQUEST
    {
        return Err("INVALID_METRIC_SAMPLE");
    }
    let value: serde_json::Value =
        serde_json::from_str(&sample.body).map_err(|_| "INVALID_METRIC_SAMPLE")?;
    if value["sampleId"] != sample.sample_id
        || value["bootId"] != sample.boot_id
        || exact_nanoseconds(&value["monotonicSeconds"]) != Some(sample.monotonic_ns)
        || value["collectionGroup"] != serde_json::json!({"kind":"HOST","subjectId":null})
        || value["collectionStatus"] != "PARTIAL"
        || !value["collectorEpoch"].as_str().is_some_and(identity::uuid)
        || !value["clockEpoch"].as_str().is_some_and(identity::uuid)
        || value["observedAt"]
            .as_str()
            .is_none_or(|s| OffsetDateTime::parse(s, &Rfc3339).is_err())
        || !value["points"]
            .as_array()
            .is_some_and(|p| !p.is_empty() && p.len() <= 10000)
    {
        return Err("INVALID_METRIC_SAMPLE");
    }
    Ok(())
}
// Read-only preflight. Every existing entry is inspected before any creation or
// recovery cleanup; enumeration is rewound on this held directory description.
fn runtime_layout(directory: &File) -> Result<Vec<&'static str>> {
    let mut expected = Vec::new();
    for name in ["runtime.lock", "runtime.json", "runtime.next"] {
        let c_name = CString::new(name).map_err(|_| "LOCAL_STORAGE_ERROR")?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fixed name and directory are live; stat is a valid writable out-pointer.
        let found = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if found == 0 {
            identity::entry(directory, name, false)?;
            expected.push(name);
        } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err("UNSAFE_PRIVATE_STATE");
        }
    }
    // SAFETY: directory is a held directory descriptor; resetting its enumeration position has no write effect.
    if unsafe { libc::lseek(directory.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err("LOCAL_STORAGE_ERROR");
    }
    identity::entries(directory, &expected)?;
    if !expected.is_empty() && !expected.contains(&"runtime.lock") {
        return Err("INVALID_RUNTIME_STATE");
    }
    Ok(expected)
}
fn read_manifest(
    directory: &File,
    name: &str,
    identity: &IdentityStore,
    binding: &Binding,
) -> Result<Manifest> {
    let file = identity::entry(directory, name, false)?;
    let mut bytes = Vec::new();
    file.take((MAX_MANIFEST + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "LOCAL_STORAGE_ERROR")?;
    if bytes.len() > MAX_MANIFEST {
        return Err("RESOURCE_LIMIT");
    }
    let value: Manifest = serde_json::from_slice(&bytes).map_err(|_| "INVALID_RUNTIME_STATE")?;
    if value.schema_version != 1
        || value.target != *identity.target()
        || value.binding != *binding
        || value.operation_id != identity.operation_id()
        || value
            .discarded_collector_epoch
            .as_deref()
            .is_some_and(|epoch| !identity::uuid(epoch))
    {
        return Err("RUNTIME_BINDING_MISMATCH");
    }
    if let Some(config) = &value.configuration {
        AgentConfiguration::decode(
            &serde_json::to_vec(config).map_err(|_| "INVALID_RUNTIME_STATE")?,
        )?;
        if config.agent_id != binding.agent_id
            || config.binding_revision != binding.binding_revision
        {
            return Err("RUNTIME_BINDING_MISMATCH");
        }
    } else if value.latest.is_some() || value.inflight.is_some() {
        return Err("INVALID_RUNTIME_STATE");
    }
    for sample in [&value.latest, &value.inflight].into_iter().flatten() {
        valid_sample(sample)?;
    }
    if let (Some(latest), Some(inflight)) = (&value.latest, &value.inflight)
        && latest.sample_id == inflight.sample_id
        && latest != inflight
    {
        return Err("INVALID_RUNTIME_STATE");
    }
    Ok(value)
}
impl RuntimeStore {
    /// CLI performs this read-only role check before even its identity HTTP
    /// reconciliation can publish identity state. Opening later revalidates it.
    pub fn preflight(path: &Path, identity: &IdentityStore) -> Result<()> {
        Self::persisted_configuration(path, identity).map(|_| ())
    }

    /// Only the original bounded startup may reuse this configuration-only
    /// state. Validate it without creating, removing or repairing files.
    pub fn preflight_first_health(path: &Path, identity: &IdentityStore) -> Result<()> {
        let directory = identity::directory(path)?;
        if identity.shares_directory(&directory)? || identity.status() != identity::Status::Bound {
            return Err("INVALID_INSTALL_STARTUP");
        }
        let binding = identity.binding().ok_or("IDENTITY_NOT_CONFIRMED")?;
        let entries = runtime_layout(&directory)?;
        if entries.contains(&"runtime.next") {
            return Err("INVALID_INSTALL_STARTUP");
        }
        if entries.contains(&"runtime.json") {
            let state = read_manifest(&directory, "runtime.json", identity, binding)?;
            if state.latest.is_some()
                || state.inflight.is_some()
                || state.configuration.is_none()
                || encoded_len(&state)? > FIRST_HEALTH_MANIFEST_MAX_BYTES as u64
            {
                return Err("INVALID_INSTALL_STARTUP");
            }
        }
        Ok(())
    }

    /// Recover settings only from the committed manifest. A complete staging
    /// file is still validated before either store can open or remove it.
    pub(crate) fn persisted_configuration(
        path: &Path,
        identity: &IdentityStore,
    ) -> Result<Option<AgentConfiguration>> {
        let directory = identity::directory(path)?;
        if identity.shares_directory(&directory)? {
            return Err("RUNTIME_DIRECTORY_NOT_SEPARATE");
        }
        if identity.status() != identity::Status::Bound {
            return Err("IDENTITY_NOT_CONFIRMED");
        }
        let binding = identity.binding().ok_or("IDENTITY_NOT_CONFIRMED")?;
        let expected = runtime_layout(&directory)?;
        let configuration = if expected.contains(&"runtime.json") {
            read_manifest(&directory, "runtime.json", identity, binding)?.configuration
        } else {
            None
        };
        if expected.contains(&"runtime.next") {
            read_manifest(&directory, "runtime.next", identity, binding)?;
        }
        Ok(configuration)
    }
    pub fn open(path: &Path, identity: &IdentityStore, epoch: &str) -> Result<Self> {
        Self::open_inner(path, identity, epoch, None)
    }
    pub(crate) fn open_shared(
        path: &Path,
        identity: &IdentityStore,
        epoch: &str,
        budget: SharedBudget,
    ) -> Result<Self> {
        Self::open_inner(path, identity, epoch, Some(budget))
    }
    fn open_inner(
        path: &Path,
        identity: &IdentityStore,
        epoch: &str,
        shared_budget: Option<SharedBudget>,
    ) -> Result<Self> {
        if !identity::uuid(epoch) {
            return Err("INVALID_COLLECTOR_EPOCH");
        }
        let directory = identity::directory(path)?;
        if let Some(budget) = &shared_budget {
            budget.check_host_directory(&directory)?;
        }
        if identity.shares_directory(&directory)? {
            return Err("RUNTIME_DIRECTORY_NOT_SEPARATE");
        }
        if identity.status() != identity::Status::Bound {
            return Err("IDENTITY_NOT_CONFIRMED");
        }
        let binding = identity.binding().ok_or("IDENTITY_NOT_CONFIRMED")?.clone();
        runtime_layout(&directory)?;
        // Serialize initialization/preflight without creating or touching another role's lock.
        // SAFETY: directory is a live owned descriptor; flock does not access Rust memory.
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("RUNTIME_LOCKED");
        }
        let expected = runtime_layout(&directory)?;
        // Validate all existing persisted facts before any cleanup or initial creation.
        let manifest = if expected.contains(&"runtime.json") {
            read_manifest(&directory, "runtime.json", identity, &binding)?
        } else {
            Manifest {
                schema_version: 1,
                target: identity.target().clone(),
                binding: binding.clone(),
                operation_id: identity.operation_id().into(),
                configuration: None,
                latest: None,
                inflight: None,
                discarded_samples_total: 0,
                discarded_collector_epoch: None,
            }
        };
        if expected.contains(&"runtime.next") {
            read_manifest(&directory, "runtime.next", identity, &binding)?;
        }
        let mut budget = shared_budget.as_ref().map(SharedBudget::lock).transpose()?;
        if let Some(guard) = &budget {
            guard.verify_allocation()?;
            if !expected.contains(&"runtime.lock") {
                guard.check_host_write(0, 0)?;
            }
        }
        let lock = identity::entry(
            &directory,
            "runtime.lock",
            !expected.contains(&"runtime.lock"),
        )?;
        // SAFETY: lock is a live uniquely owned descriptor; nonblocking flock touches no Rust memory.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("RUNTIME_LOCKED");
        }
        let current = runtime_layout(&directory)?;
        if current.len() != expected.len() + usize::from(!expected.contains(&"runtime.lock")) {
            return Err("INVALID_RUNTIME_STATE");
        }
        let named = identity::entry(&directory, "runtime.lock", false)?
            .metadata()
            .map_err(|_| "LOCAL_STORAGE_ERROR")?;
        let held = lock.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        if named.dev() != held.dev() || named.ino() != held.ino() {
            return Err("UNSAFE_PRIVATE_STATE");
        }
        if expected.contains(&"runtime.next") {
            // Only a complete, private candidate belonging to this exact binding/operation
            // can be recovered. Partial/foreign candidates fail above without deletion.
            remove(&directory, "runtime.next")?;
            directory.sync_all().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        }
        if let Some(guard) = &mut budget {
            guard.verify_allocation()?;
            guard.record_host_manifest_bound(host_manifest_bound(
                &manifest,
                encoded_len(&manifest)?,
                epoch,
            )?);
        }
        drop(budget);
        Ok(Self {
            directory,
            lock,
            manifest,
            poisoned: false,
            collector_epoch: epoch.into(),
            attempt_active: false,
            shared_budget,
        })
    }
    fn commit(&mut self, next: Manifest, limit: u64) -> Result<()> {
        self.commit_manifest(next, limit, None)
    }

    fn commit_manifest(
        &mut self,
        next: Manifest,
        limit: u64,
        resize: Option<&CollectionConfiguration>,
    ) -> Result<()> {
        if self.poisoned {
            return Err("RUNTIME_RECOVERY_REQUIRED");
        }
        let shared_budget = self.shared_budget.clone();
        if resize.is_some() && shared_budget.is_none() {
            return Err("SHARED_BUFFER_LIMIT_MISMATCH");
        }
        let bytes = serde_json::to_vec(&next).map_err(|_| "INVALID_RUNTIME_STATE")?;
        if bytes.len() > MAX_MANIFEST {
            return Err("RESOURCE_LIMIT");
        }
        let mut budget = if let Some(budget) = &shared_budget {
            let bound = host_manifest_bound(&next, bytes.len() as u64, &self.collector_epoch)?;
            let guard = budget.lock()?;
            if let Some(settings) = resize {
                guard.check_host_resize(bytes.len() as u64, bound, settings)?;
            } else {
                if guard.limit() != limit
                    || next.configuration.as_ref().is_some_and(|config| {
                        config.target.configuration.buffer_max_age_seconds != guard.age_limit()
                    })
                {
                    return Err("SHARED_BUFFER_LIMIT_MISMATCH");
                }
                guard.check_host_write(bytes.len() as u64, bound)?;
            }
            Some((guard, bound))
        } else {
            None
        };
        let legacy_current = if budget.is_some() {
            0
        } else {
            let current = self.allocated_bytes()?;
            let rounded = (bytes.len() as u64).div_ceil(4096) * 4096;
            if current.saturating_add(rounded).saturating_add(RESERVE) > limit {
                return Err("RESOURCE_LIMIT");
            }
            current
        };
        let mut file = identity::entry(&self.directory, "runtime.next", true)?;
        if file
            .write_all(&bytes)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            let _ = self.discard_candidate(budget.as_mut().map(|(guard, _)| guard));
            return Err("LOCAL_STORAGE_ERROR");
        }
        let verification = if let Some((guard, _)) = &budget {
            guard.verify_allocation_with_limit(limit).map(|_| ())
        } else if legacy_current.saturating_add(file_bytes(&file)?) > limit {
            Err("RESOURCE_LIMIT")
        } else {
            Ok(())
        };
        if let Err(code) = verification {
            self.discard_candidate(budget.as_mut().map(|(guard, _)| guard))?;
            return Err(code);
        }
        #[cfg(test)]
        if let Err(code) = checkpoint(1) {
            if let Some((guard, _)) = &mut budget {
                self.discard_candidate(Some(guard))?;
            }
            return Err(code);
        }
        // SAFETY: both names are fixed relative entries and directory is held open.
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                c"runtime.next".as_ptr(),
                self.directory.as_raw_fd(),
                c"runtime.json".as_ptr(),
            )
        } != 0
        {
            let _ = self.discard_candidate(budget.as_mut().map(|(guard, _)| guard));
            return Err("LOCAL_STORAGE_ERROR");
        }
        self.poisoned = true;
        if let Some((guard, _)) = &mut budget {
            guard.mark_recovery_required();
        }
        #[cfg(test)]
        checkpoint(2)?;
        self.directory
            .sync_all()
            .map_err(|_| "LOCAL_STORAGE_ERROR")?;
        self.manifest = next;
        if let Some((guard, bound)) = &mut budget {
            guard.finish_host_publication(*bound, resize);
        }
        self.poisoned = false;
        Ok(())
    }

    fn discard_candidate(&mut self, budget: Option<&mut BudgetGuard<'_>>) -> Result<()> {
        let removed = remove(&self.directory, "runtime.next");
        let Some(guard) = budget else {
            return removed;
        };
        let result =
            removed.and_then(|()| self.directory.sync_all().map_err(|_| "LOCAL_STORAGE_ERROR"));
        if result.is_err() {
            self.poisoned = true;
            guard.mark_recovery_required();
        }
        result
    }
    pub fn safely_reportable(&self) -> bool {
        !self.poisoned
    }
    pub fn allocated_bytes(&self) -> Result<u64> {
        let mut total = file_bytes(&self.directory)?.saturating_add(file_bytes(&self.lock)?);
        if let Ok(file) = identity::entry(&self.directory, "runtime.json", false) {
            total = total.saturating_add(file_bytes(&file)?);
        }
        Ok(total)
    }
    pub fn configuration(&self) -> Option<&AgentConfiguration> {
        self.manifest.configuration.as_ref()
    }
    pub fn discarded_samples_total(&self) -> u64 {
        if self.manifest.discarded_collector_epoch.as_deref() == Some(&self.collector_epoch) {
            self.manifest.discarded_samples_total
        } else {
            0
        }
    }
    pub fn has_pending_sample(&self) -> bool {
        self.manifest.latest.is_some() || self.manifest.inflight.is_some()
    }

    /// Borrow the exact envelope currently owned by the data dispatcher.
    pub fn active_upload_sample(&self, id: &str) -> Option<&StoredSample> {
        if !self.attempt_active {
            return None;
        }
        self.manifest
            .inflight
            .as_ref()
            .filter(|sample| sample.sample_id == id)
    }
    fn next_manifest(&self) -> Manifest {
        let mut next = self.manifest.clone();
        if next.discarded_collector_epoch.as_deref() != Some(&self.collector_epoch) {
            next.discarded_collector_epoch = Some(self.collector_epoch.clone());
            next.discarded_samples_total = 0;
        }
        next
    }
    /// The bounded HTTP attempt has ended without a usable ACK. The immutable
    /// last submitted body stays durable; only its live request protection ends.
    pub fn attempt_finished(&mut self, id: &str) -> Result<()> {
        if self
            .manifest
            .inflight
            .as_ref()
            .map(|s| s.sample_id.as_str())
            != Some(id)
        {
            return Err("UNKNOWN_INFLIGHT_SAMPLE");
        }
        self.attempt_active = false;
        Ok(())
    }
    fn settings(&self) -> Result<&crate::protocol::CollectionConfiguration> {
        Ok(&self
            .configuration()
            .ok_or("CONFIGURATION_NOT_APPLIED")?
            .target
            .configuration)
    }
    pub fn apply(&mut self, config: &AgentConfiguration, boot: &str, now: u64) -> Result<()> {
        let mut next = self.with_configuration(config)?;
        expire(&mut next, boot, now, self.attempt_active);
        self.commit(next, config.target.configuration.buffer_max_bytes)
    }

    /// Persist the actual first-health configuration without retaining a HOST
    /// sample or opening SQLite. Reopening an earlier attempt is idempotent.
    pub fn apply_first_health_configuration(&mut self, config: &AgentConfiguration) -> Result<()> {
        if self.shared_budget.is_some()
            || self.manifest.latest.is_some()
            || self.manifest.inflight.is_some()
        {
            return Err("INVALID_INSTALL_STARTUP");
        }
        let next = self.with_configuration(config)?;
        if encoded_len(&next)? > FIRST_HEALTH_MANIFEST_MAX_BYTES as u64 {
            return Err("RESOURCE_LIMIT");
        }
        if self.configuration() == Some(config) {
            return Ok(());
        }
        self.commit(next, config.target.configuration.buffer_max_bytes)
    }

    /// The shared owner publishes both limits atomically with this manifest.
    /// Subsequent admissions and attempts apply age limits to retained records.
    pub(crate) fn apply_shared(&mut self, config: &AgentConfiguration) -> Result<()> {
        let next = self.with_configuration(config)?;
        let settings = &config.target.configuration;
        self.commit_manifest(next, settings.buffer_max_bytes, Some(settings))
    }

    fn with_configuration(&self, config: &AgentConfiguration) -> Result<Manifest> {
        AgentConfiguration::decode(&serde_json::to_vec(config).map_err(|_| "INVALID_PROTOCOL")?)?;
        if config.agent_id != self.manifest.binding.agent_id
            || config.binding_revision != self.manifest.binding.binding_revision
        {
            return Err("CONFIGURATION_BINDING_MISMATCH");
        }
        if self.configuration().is_some_and(|old| {
            config.target.generation < old.target.generation
                || (config.target.generation == old.target.generation && old != config)
        }) {
            return Err("CONFIGURATION_REGRESSION");
        }
        let mut next = self.next_manifest();
        next.configuration = Some(config.clone());
        Ok(next)
    }
    pub fn admit(&mut self, sample: StoredSample) -> Result<()> {
        valid_sample(&sample)?;
        for old in [&self.manifest.latest, &self.manifest.inflight]
            .into_iter()
            .flatten()
        {
            if old.sample_id == sample.sample_id && old != &sample {
                return Err("SAMPLE_ID_CONFLICT");
            }
        }
        let mut next = self.next_manifest();
        expire(
            &mut next,
            &sample.boot_id,
            sample.monotonic_ns,
            self.attempt_active,
        );
        next.latest = Some(sample);
        self.commit(next, self.settings()?.buffer_max_bytes)
    }
    pub fn begin(&mut self, boot: &str, now: u64) -> Result<Option<StoredSample>> {
        if self.attempt_active {
            return Err("METRIC_ATTEMPT_ACTIVE");
        }
        let mut next = self.next_manifest();
        expire(&mut next, boot, now, self.attempt_active);
        // Newer latest replaces a failed old in-flight attempt; no offline FIFO replay.
        if next.latest.is_some() {
            next.inflight = next.latest.clone();
        }
        let selected = next.inflight.clone();
        self.commit(next, self.settings()?.buffer_max_bytes)?;
        self.attempt_active = selected.is_some();
        Ok(selected)
    }
    pub fn acknowledge(&mut self, id: &str) -> Result<()> {
        if self
            .manifest
            .inflight
            .as_ref()
            .map(|s| s.sample_id.as_str())
            != Some(id)
        {
            return Err("UNKNOWN_INFLIGHT_SAMPLE");
        }
        let mut next = self.next_manifest();
        next.inflight = None;
        if next
            .latest
            .as_ref()
            .is_some_and(|sample| sample.sample_id == id)
        {
            next.latest = None;
        }
        self.commit(next, self.settings()?.buffer_max_bytes)?;
        self.attempt_active = false;
        Ok(())
    }
}
fn expire(next: &mut Manifest, boot: &str, now: u64, protect_inflight: bool) {
    let age = next.configuration.as_ref().map_or(0, |c| {
        u64::from(c.target.configuration.buffer_max_age_seconds) * 1_000_000_000
    });
    let mut expired = Vec::new();
    for (index, slot) in [&mut next.latest, &mut next.inflight]
        .into_iter()
        .enumerate()
    {
        if index == 1 && protect_inflight {
            continue;
        }
        if slot.as_ref().is_some_and(|s| {
            s.boot_id != boot || now < s.monotonic_ns || now - s.monotonic_ns > age
        }) && let Some(s) = slot.take()
            && !expired.contains(&s.sample_id)
        {
            expired.push(s.sample_id);
        }
    }
    let terminal = expired
        .iter()
        .filter(|id| {
            ![&next.latest, &next.inflight]
                .into_iter()
                .flatten()
                .any(|s| &s.sample_id == *id)
        })
        .count();
    next.discarded_samples_total = next.discarded_samples_total.saturating_add(terminal as u64);
}
pub fn metric_body(sample: &StoredSample) -> Result<Vec<u8>> {
    valid_sample(sample)?;
    let bytes = format!("{{\"samples\":[{}]}}", sample.body).into_bytes();
    if bytes.len() > MAX_METRIC_REQUEST {
        return Err("REQUEST_TOO_LARGE");
    }
    Ok(bytes)
}
/// Rate baseline and continuity are local collection facts, independent of retained latest.
pub struct HostCollector {
    collector: Collector,
    epoch: String,
    clock_epoch: String,
    previous: Option<String>,
    last: Option<ObservationTime>,
    broken: bool,
    boot: Option<String>,
}
impl HostCollector {
    pub fn new(epoch: &str) -> Result<Self> {
        if !identity::uuid(epoch) {
            return Err("INVALID_COLLECTOR_EPOCH");
        }
        Ok(Self {
            collector: Collector::new(epoch),
            epoch: epoch.into(),
            clock_epoch: identity::new_collector_epoch()?,
            previous: None,
            last: None,
            broken: true,
            boot: None,
        })
    }
    pub fn interrupt(&mut self) {
        self.broken = true;
    }
    pub fn collect(&mut self, raw: RawSnapshot) -> Result<StoredSample> {
        let time = raw.cpu_observed;
        let mut discontinuous =
            self.broken || self.boot.as_ref().is_some_and(|boot| boot != &raw.boot_id);
        if self.boot.as_ref().is_some_and(|boot| boot != &raw.boot_id) {
            self.clock_epoch = identity::new_collector_epoch()?;
            self.previous = None;
        }
        if let Some(last) = self.last {
            // A material wall/boottime delta mismatch includes rollback and suspend.
            let mono = i128::from(time.monotonic_ns) - i128::from(last.monotonic_ns);
            let wall = i128::try_from(time.observed_unix_ns).map_err(|_| "LOCAL_CLOCK_ERROR")?
                - i128::try_from(last.observed_unix_ns).map_err(|_| "LOCAL_CLOCK_ERROR")?;
            if mono <= 0 || wall < 0 || (wall - mono).abs() > 1_000_000_000 {
                self.clock_epoch = identity::new_collector_epoch()?;
                discontinuous = true;
            }
        }
        if discontinuous {
            self.collector = Collector::new(&self.epoch);
        }
        let id = identity::new_collector_epoch()?;
        let boot = raw.boot_id.clone();
        self.boot = Some(boot.clone());
        let snapshot = self.collector.collect(raw);
        let points: Vec<_> = snapshot
            .points
            .into_iter()
            .filter(|p| !p.metric.ends_with("BytesPerSecond"))
            .collect();
        if points.is_empty() || points.len() > 10000 {
            self.previous = Some(id);
            self.last = Some(time);
            self.broken = true;
            return Err("RESOURCE_LIMIT");
        }
        let observed = OffsetDateTime::from_unix_timestamp_nanos(
            i128::try_from(time.observed_unix_ns).map_err(|_| "LOCAL_CLOCK_ERROR")?,
        )
        .map_err(|_| "LOCAL_CLOCK_ERROR")?;
        let observed = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            observed.year(),
            u8::from(observed.month()),
            observed.day(),
            observed.hour(),
            observed.minute(),
            observed.second(),
            observed.nanosecond()
        );
        let mut points = serde_json::to_value(points).map_err(|_| "INVALID_METRIC_SAMPLE")?;
        for point in points.as_array_mut().ok_or("INVALID_METRIC_SAMPLE")? {
            if point["metric"]
                .as_str()
                .is_some_and(|m| m.starts_with("cpu."))
                && point["availability"] == "AVAILABLE"
            {
                let duration = time
                    .monotonic_ns
                    .checked_sub(self.last.ok_or("INVALID_METRIC_SAMPLE")?.monotonic_ns)
                    .filter(|n| *n > 0)
                    .ok_or("INVALID_METRIC_SAMPLE")?;
                point["interval"]["durationSeconds"] =
                    serde_json::Value::Number(ns_number(duration)?);
            }
        }
        let body=serde_json::to_string(&serde_json::json!({"sampleId":id,"bootId":boot,"observedAt":observed,"monotonicSeconds":ns_number(time.monotonic_ns)?,"collectorEpoch":self.epoch,"clockEpoch":self.clock_epoch,"collectionGroup":{"kind":"HOST","subjectId":null},"collectionStatus":"PARTIAL","continuity":{"previousSampleId":self.previous,"isContinuous":!discontinuous},"points":points})).map_err(|_|"INVALID_METRIC_SAMPLE")?;
        self.previous = Some(id.clone());
        self.last = Some(time);
        self.broken = false;
        let sample = StoredSample {
            sample_id: id,
            boot_id: boot,
            monotonic_ns: time.monotonic_ns,
            body,
        };
        valid_sample(&sample)?;
        Ok(sample)
    }
}
#[cfg(test)]
thread_local! { static FAIL_COMMIT: std::cell::Cell<u8> = const {std::cell::Cell::new(0)}; }
#[cfg(test)]
fn checkpoint(stage: u8) -> Result<()> {
    if FAIL_COMMIT.get() == stage {
        Err("LOCAL_STORAGE_ERROR")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};
    pub(super) const BOOT: &str = "00000000-0000-4000-8000-000000000001";
    pub(super) const EPOCH: &str = "00000000-0000-4000-8000-000000000002";
    pub(super) fn raw(ns: u64) -> RawSnapshot {
        let observed = ObservationTime {
            monotonic_ns: ns,
            observed_unix_ns: 1_800_000_000_000_000_000 + u128::from(ns),
        };
        RawSnapshot {
            boot_id: BOOT.into(),
            monotonic_ns: ns,
            observed_unix_ns: observed.observed_unix_ns,
            cpu_observed: observed,
            memory_observed: observed,
            load_observed: observed,
            swap_observed: observed,
            page_size: Ok(4096),
            cpu: Ok(BTreeMap::from([(
                "total".into(),
                [ns, 0, ns, ns, 0, 0, 0, 0, 0, 0],
            )])),
            memory: Ok(BTreeMap::from([
                ("MemTotal".into(), Ok(100)),
                ("MemAvailable".into(), Ok(60)),
                ("Cached".into(), Ok(20)),
                ("SwapTotal".into(), Ok(0)),
                ("SwapFree".into(), Ok(0)),
            ])),
            load: Ok([1.0, 0.5, 0.1]),
            swap: Err(Availability::Unsupported),
        }
    }
    pub(super) fn config(generation: u64) -> AgentConfiguration {
        AgentConfiguration::decode(format!(r#"{{"agentId":"agent:fixture","bindingRevision":2,"schemaVersion":1,"target":{{"configId":"00000000-0000-4000-8000-{generation:012}","generation":{generation},"configuration":{{"samplingIntervalSeconds":30,"bufferMaxAgeSeconds":3600,"bufferMaxBytes":1000000}}}}}}"#).as_bytes()).unwrap()
    }
    pub(super) fn identity() -> (tempfile::TempDir, IdentityStore) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("identity");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut identity = IdentityStore::initialize(
            &path,
            Target::new("https://localhost:443", "server-1").unwrap(),
        )
        .unwrap();
        identity
            .confirm(Binding {
                agent_id: "agent:fixture".into(),
                server_id: "server-1".into(),
                binding_revision: 2,
            })
            .unwrap();
        let runtime = temp.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        (temp, identity)
    }
    #[test]
    fn old_ack_does_not_delete_new_latest_across_restart() {
        let (temp, identity) = identity();
        let path = temp.path().join("runtime");
        let mut store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
        store.apply(&config(1), BOOT, 1).unwrap();
        let mut collector = HostCollector::new(EPOCH).unwrap();
        let a = collector.collect(raw(1)).unwrap();
        store.admit(a.clone()).unwrap();
        assert_eq!(store.begin(BOOT, 1).unwrap().unwrap(), a);
        let b = collector.collect(raw(2)).unwrap();
        store.admit(b.clone()).unwrap();
        drop(store);
        let mut store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
        store.acknowledge(&a.sample_id).unwrap();
        drop(store);
        let mut store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
        let retry = store.begin(BOOT, 2).unwrap().unwrap();
        assert_eq!(retry, b);
        assert_eq!(metric_body(&retry).unwrap(), metric_body(&b).unwrap());
        assert_eq!(
            store.acknowledge(&a.sample_id),
            Err("UNKNOWN_INFLIGHT_SAMPLE")
        );
        store.attempt_finished(&b.sample_id).unwrap();
        assert_eq!(store.begin(BOOT, 2).unwrap().unwrap(), b);
    }
    #[test]
    fn same_id_cannot_replace_immutable_body() {
        let (temp, identity) = identity();
        let mut store = RuntimeStore::open(&temp.path().join("runtime"), &identity, EPOCH).unwrap();
        store.apply(&config(1), BOOT, 1).unwrap();
        let mut collector = HostCollector::new(EPOCH).unwrap();
        let a = collector.collect(raw(1)).unwrap();
        store.admit(a.clone()).unwrap();
        store.begin(BOOT, 1).unwrap();
        store.attempt_finished(&a.sample_id).unwrap();
        let mut changed = a.clone();
        let mut body: serde_json::Value = serde_json::from_str(&changed.body).unwrap();
        body["points"][0]["value"] = serde_json::json!(45.0);
        changed.body = body.to_string();
        assert_eq!(store.admit(changed), Err("SAMPLE_ID_CONFLICT"));
        assert_eq!(store.begin(BOOT, 1).unwrap().unwrap(), a);
    }
    #[test]
    fn unknown_file_cannot_escape_physical_budget() {
        let (temp, identity) = identity();
        let path = temp.path().join("runtime");
        fs::write(path.join("hidden"), [0u8; 4096]).unwrap();
        assert!(RuntimeStore::open(&path, &identity, EPOCH).is_err());
    }
    #[test]
    fn publication_failure_preserves_last_good_and_restart_revalidates() {
        for stage in [1, 2] {
            let (temp, identity) = identity();
            let path = temp.path().join("runtime");
            let mut store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
            store.apply(&config(1), BOOT, 1).unwrap();
            FAIL_COMMIT.set(stage);
            assert_eq!(store.apply(&config(2), BOOT, 2), Err("LOCAL_STORAGE_ERROR"));
            FAIL_COMMIT.set(0);
            assert_eq!(store.configuration(), Some(&config(1)));
            drop(store);
            let store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
            assert_eq!(
                store.configuration(),
                Some(&config(if stage == 1 { 1 } else { 2 }))
            );
        }
    }
    #[test]
    fn shared_resize_failure_fences_uncertain_publication_and_recovers_both_stores() {
        use crate::buffer::{QueueTime, SharedBuffer, SharedBufferPaths, SourcePosition};

        for stage in [1, 2] {
            let (temp, identity) = identity();
            let runtime = temp.path().join("runtime");
            let ssh = temp.path().join("ssh");
            fs::create_dir(&ssh).unwrap();
            fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
            let paths = || SharedBufferPaths {
                host: &runtime,
                ssh: &ssh,
            };
            let now = QueueTime {
                boot_id: BOOT.into(),
                monotonic_ns: 1,
                unix_seconds: 1_800_000_000,
            };
            let mut old = config(1);
            old.target.configuration.buffer_max_bytes = 2_000_000;
            old.target.configuration.buffer_max_age_seconds = 7200;
            let desired = config(2);
            let mut buffer = SharedBuffer::open(paths(), &identity, EPOCH, &old, &now).unwrap();
            let sample = HostCollector::new(EPOCH).unwrap().collect(raw(1)).unwrap();
            buffer.host.admit(sample.clone()).unwrap();
            assert_eq!(buffer.host.begin(BOOT, 1).unwrap(), Some(sample.clone()));
            let position = SourcePosition {
                stream: "runtime-resize".into(),
                sequence: 1,
                cursor: b"1".to_vec(),
            };
            let event = serde_json::json!({
                "eventId": "00000000-0000-4000-8000-000000000005",
                "bootId": BOOT,
                "occurredAt": "2026-11-10T12:00:00Z",
                "eventType": "SSH_AUTH_FAILED",
                "sourceIp": null,
                "username": null,
            })
            .to_string();
            buffer
                .ssh
                .enqueue(&position, event.as_bytes(), &now)
                .unwrap();

            FAIL_COMMIT.set(stage);
            let failed = buffer.apply_configuration(&desired);
            FAIL_COMMIT.set(0);
            assert_eq!(failed, Err("LOCAL_STORAGE_ERROR"));
            assert_eq!(buffer.host.configuration(), Some(&old));
            assert!(!runtime.join("runtime.next").exists());
            if stage == 1 {
                assert!(buffer.safely_reportable());
                assert!(buffer.allocated_bytes().is_ok());
                assert!(buffer.ssh.prepare(&now).unwrap().is_some());
            } else {
                assert!(!buffer.safely_reportable());
                assert_eq!(buffer.allocated_bytes(), Err("BUFFER_RECOVERY_REQUIRED"));
                assert_eq!(
                    buffer.ssh.prepare(&now).err(),
                    Some("BUFFER_RECOVERY_REQUIRED")
                );
                assert_eq!(
                    buffer.host.admit(sample.clone()),
                    Err("RUNTIME_RECOVERY_REQUIRED")
                );
            }
            drop(buffer);

            let mut recovered = SharedBuffer::recover(paths(), &identity, EPOCH).unwrap();
            assert_eq!(
                recovered.host.configuration(),
                Some(if stage == 1 { &old } else { &desired })
            );
            assert_eq!(recovered.host.begin(BOOT, 1).unwrap(), Some(sample));
            assert_eq!(
                recovered.ssh.prepare(&now).unwrap().unwrap().body,
                format!(r#"{{"events":[{event}]}}"#).into_bytes()
            );
            assert_eq!(
                recovered.ssh.checkpoint(&position.stream).unwrap(),
                Some(position)
            );
        }
    }
    #[test]
    fn age_and_boot_expire_pending_without_fake_ack() {
        let (temp, identity) = identity();
        let mut store = RuntimeStore::open(&temp.path().join("runtime"), &identity, EPOCH).unwrap();
        store.apply(&config(1), BOOT, 1).unwrap();
        let sample = HostCollector::new(EPOCH).unwrap().collect(raw(1)).unwrap();
        store.admit(sample).unwrap();
        store.begin(BOOT, 1).unwrap();
        let id = store.manifest.inflight.as_ref().unwrap().sample_id.clone();
        store.attempt_finished(&id).unwrap();
        assert!(store.begin(BOOT, 3_600_000_000_002).unwrap().is_none());
        assert_eq!(store.discarded_samples_total(), 1);
        let sample = HostCollector::new(EPOCH)
            .unwrap()
            .collect(raw(4_000_000_000_000))
            .unwrap();
        store.admit(sample).unwrap();
        assert!(store.begin(EPOCH, 4_000_000_000_001).unwrap().is_none());
        assert_eq!(store.discarded_samples_total(), 2);
    }
    #[test]
    fn interruption_and_wall_rollback_never_extend_cpu_rate() {
        let mut collector = HostCollector::new(EPOCH).unwrap();
        let a = collector.collect(raw(1_000_000_000)).unwrap();
        let b = collector.collect(raw(31_000_000_000)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&b.body).unwrap();
        assert_eq!(value["continuity"]["previousSampleId"], a.sample_id);
        assert_eq!(value["continuity"]["isContinuous"], true);
        assert_eq!(value["points"][0]["interval"]["durationSeconds"], 30.0);
        collector.interrupt();
        let c = collector.collect(raw(91_000_000_000)).unwrap();
        let c: serde_json::Value = serde_json::from_str(&c.body).unwrap();
        assert_eq!(c["points"][0]["availability"], "NO_BASELINE");
        assert_eq!(c["continuity"]["isContinuous"], false);
        let mut rollback = raw(121_000_000_000);
        rollback.cpu_observed.observed_unix_ns = 1_799_000_000_000_000_000;
        let d = collector.collect(rollback).unwrap();
        let d: serde_json::Value = serde_json::from_str(&d.body).unwrap();
        assert_ne!(d["clockEpoch"], c["clockEpoch"]);
        assert_eq!(d["points"][0]["availability"], "NO_BASELINE");
    }
    #[test]
    fn changed_boot_breaks_continuity_even_when_clocks_increase() {
        let mut collector = HostCollector::new(EPOCH).unwrap();
        collector.collect(raw(1)).unwrap();
        let mut next = raw(2);
        next.boot_id = EPOCH.into();
        let sample = collector.collect(next).unwrap();
        let value: serde_json::Value = serde_json::from_str(&sample.body).unwrap();
        assert_eq!(value["continuity"]["isContinuous"], false);
        assert_eq!(
            value["continuity"]["previousSampleId"],
            serde_json::Value::Null
        );
    }
}

#[cfg(test)]
mod resource_tests {
    use super::tests::EPOCH;
    use super::*;
    use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};
    fn setup(path: &Path) -> (tempfile::TempDir, IdentityStore, RuntimeStore) {
        let parent = tempfile::tempdir().unwrap();
        let state = parent.path().join("identity");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let mut identity = IdentityStore::initialize(
            &state,
            Target::new("https://localhost:443", "server-1").unwrap(),
        )
        .unwrap();
        identity
            .confirm(Binding {
                agent_id: "agent:fixture".into(),
                server_id: "server-1".into(),
                binding_revision: 2,
            })
            .unwrap();
        let mut runtime = RuntimeStore::open(path, &identity, EPOCH).unwrap();
        runtime
            .apply(&super::tests::config(1), super::tests::BOOT, 1)
            .unwrap();
        (parent, identity, runtime)
    }
    #[test]
    fn large_host_sample_cannot_exceed_minimum_physical_budget_or_replace_config() {
        let path = tempfile::tempdir().unwrap();
        fs::set_permissions(path.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (_parent, _identity, mut runtime) = setup(path.path());
        let mut raw = super::tests::raw(1);
        raw.cpu = Ok((0..1000)
            .map(|i| (i.to_string(), [1, 0, 1, 1, 0, 0, 0, 0, 0, 0]))
            .collect::<BTreeMap<_, _>>());
        let sample = HostCollector::new(super::tests::EPOCH)
            .unwrap()
            .collect(raw)
            .unwrap();
        assert!(sample.body.len() > 1_000_000);
        assert_eq!(runtime.admit(sample), Err("RESOURCE_LIMIT"));
        assert_eq!(runtime.configuration(), Some(&super::tests::config(1)));
        assert!(runtime.allocated_bytes().unwrap() < 1_000_000);
        assert!(runtime.begin(super::tests::BOOT, 1).unwrap().is_none());
    }
    #[test]
    fn real_enospc_preserves_last_good_configuration_and_pending_body() {
        let Ok(root) = std::env::var("NODOMI_RUNTIME_ENOSPC_DIR") else {
            return;
        };
        let root = Path::new(&root);
        let path = tempfile::tempdir_in(root).unwrap();
        fs::set_permissions(path.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (_parent, _identity, mut runtime) = setup(path.path());
        let sample = HostCollector::new(super::tests::EPOCH)
            .unwrap()
            .collect(super::tests::raw(1))
            .unwrap();
        runtime.admit(sample.clone()).unwrap();
        runtime.begin(super::tests::BOOT, 1).unwrap();
        let filler_path = root.join(format!("runtime-fill-{}", std::process::id()));
        let mut filler = File::create(&filler_path).unwrap();
        let chunk = [0u8; 4096];
        let full = loop {
            if let Err(error) = filler.write_all(&chunk) {
                break error;
            }
        };
        assert_eq!(full.raw_os_error(), Some(libc::ENOSPC));
        assert_eq!(
            runtime.apply(&super::tests::config(2), super::tests::BOOT, 2),
            Err("LOCAL_STORAGE_ERROR")
        );
        assert_eq!(runtime.configuration(), Some(&super::tests::config(1)));
        fs::remove_file(filler_path).unwrap();
        drop(filler);
        runtime.attempt_finished(&sample.sample_id).unwrap();
        assert_eq!(
            runtime.begin(super::tests::BOOT, 2).unwrap().unwrap(),
            sample
        );
        runtime
            .apply(&super::tests::config(2), super::tests::BOOT, 2)
            .unwrap();
    }
}

#[cfg(test)]
mod review_regressions {
    use super::tests::{BOOT, EPOCH, config, identity, raw};
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    fn exact_ns(value: &serde_json::Value) -> u64 {
        let token = value.to_string();
        let (whole, fraction) = token.split_once('.').unwrap_or((&token, ""));
        assert!(
            fraction.len() <= 9 && fraction.bytes().all(|b| b.is_ascii_digit()),
            "non-nanosecond token {token}"
        );
        whole.parse::<u64>().unwrap() * 1_000_000_000
            + if fraction.is_empty() {
                0
            } else {
                fraction.parse::<u64>().unwrap() * 10u64.pow(9 - fraction.len() as u32)
            }
    }
    #[test]
    fn long_uptime_wire_clocks_and_cpu_durations_are_exact_nanoseconds() {
        let values = [
            10_000_000_002_026_474,
            10_000_030_002_553_679,
            10_000_060_003_039_926,
            10_000_090_004_763_219,
        ];
        let mut collector = HostCollector::new(EPOCH).unwrap();
        let mut previous = None;
        for ns in values {
            let sample = collector.collect(raw(ns)).unwrap();
            let value: serde_json::Value = serde_json::from_str(&sample.body).unwrap();
            assert_eq!(exact_ns(&value["monotonicSeconds"]), ns);
            if let Some(old) = previous {
                for point in value["points"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|p| p["metric"].as_str().unwrap().starts_with("cpu."))
                {
                    assert_eq!(point["availability"], "AVAILABLE");
                    assert_eq!(exact_ns(&point["interval"]["durationSeconds"]), ns - old);
                    assert_eq!(
                        exact_ns(&value["monotonicSeconds"])
                            - exact_ns(&point["interval"]["durationSeconds"]),
                        old
                    );
                }
            }
            previous = Some(ns);
        }
    }
    #[test]
    fn nearby_valid_long_uptime_survives_validation_admission_reopen_and_retry() {
        let (temp, identity) = identity();
        let path = temp.path().join("runtime");
        let mut store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
        store
            .apply(&config(1), BOOT, 10_000_000_002_026_474)
            .unwrap();
        let mut collector = HostCollector::new(EPOCH).unwrap();
        collector.collect(raw(10_000_000_002_026_474)).unwrap();
        let sample = collector
            .collect(raw(10_000_030_001_540_442))
            .expect("healthy source-adjacent timestamp");
        store.admit(sample.clone()).unwrap();
        let body = metric_body(&store.begin(BOOT, sample.monotonic_ns).unwrap().unwrap()).unwrap();
        drop(store);
        let mut store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
        assert_eq!(
            metric_body(&store.begin(BOOT, sample.monotonic_ns).unwrap().unwrap()).unwrap(),
            body
        );
    }
    #[test]
    fn supersession_and_two_confirmations_are_not_discards() {
        let (temp, identity) = identity();
        let mut store = RuntimeStore::open(&temp.path().join("runtime"), &identity, EPOCH).unwrap();
        store.apply(&config(1), BOOT, 1).unwrap();
        let mut collector = HostCollector::new(EPOCH).unwrap();
        let a = collector.collect(raw(1)).unwrap();
        let b = collector.collect(raw(2)).unwrap();
        store.admit(a.clone()).unwrap();
        store.begin(BOOT, 1).unwrap();
        store.admit(b.clone()).unwrap();
        assert_eq!(store.discarded_samples_total(), 0);
        store.acknowledge(&a.sample_id).unwrap();
        store.begin(BOOT, 2).unwrap();
        store.acknowledge(&b.sample_id).unwrap();
        assert_eq!(store.discarded_samples_total(), 0);
    }
    #[test]
    fn active_attempt_is_not_replaced_or_counted_before_confirmation() {
        let (temp, identity) = identity();
        let mut store = RuntimeStore::open(&temp.path().join("runtime"), &identity, EPOCH).unwrap();
        store.apply(&config(1), BOOT, 1).unwrap();
        let mut collector = HostCollector::new(EPOCH).unwrap();
        let a = collector.collect(raw(1)).unwrap();
        let b = collector.collect(raw(3_600_000_000_002)).unwrap();
        store.admit(a.clone()).unwrap();
        store.begin(BOOT, 1).unwrap();
        store.admit(b).unwrap();
        assert_eq!(store.discarded_samples_total(), 0, "A remains inflight");
        assert!(
            store.begin(BOOT, 3_600_000_000_002).is_err(),
            "one active fixed request only"
        );
        store.acknowledge(&a.sample_id).unwrap();
        assert_eq!(
            store.discarded_samples_total(),
            0,
            "A received durable confirmation"
        );
    }
    fn fingerprint(path: &Path) -> Vec<(String, String, String)> {
        let mut result = fs::read_dir(path)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let m = e.metadata().unwrap();
                (
                    e.file_name().to_str().unwrap().into(),
                    ring::digest::digest(&ring::digest::SHA256, &fs::read(e.path()).unwrap())
                        .as_ref()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                    format!(
                        "{}:{}:{}:{}:{}:{}:{}",
                        m.mode(),
                        m.uid(),
                        m.nlink(),
                        m.mtime(),
                        m.mtime_nsec(),
                        m.ctime(),
                        m.ctime_nsec()
                    ),
                )
            })
            .collect::<Vec<_>>();
        result.sort();
        result
    }
    #[test]
    fn rejected_identity_alias_and_foreign_roles_are_read_only() {
        let (temp, identity) = identity();
        let protocol = temp.path().join("identity");
        let before = fingerprint(&protocol);
        for path in [
            protocol.clone(),
            protocol.join("../identity"),
            protocol.join("."),
        ] {
            assert!(RuntimeStore::open(&path, &identity, EPOCH).is_err());
            assert_eq!(fingerprint(&protocol), before);
        }
        for role in ["authority.json", "execution.lock", "unknown"] {
            let path = temp.path().join(role.replace('.', "-"));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(path.join(role), "original").unwrap();
            fs::set_permissions(path.join(role), fs::Permissions::from_mode(0o600)).unwrap();
            let before = fingerprint(&path);
            assert!(RuntimeStore::open(&path, &identity, EPOCH).is_err());
            assert_eq!(fingerprint(&path), before);
        }
        let target = identity.target().clone();
        drop(identity);
        assert!(IdentityStore::open(&protocol, &target).is_ok());
    }
    #[test]
    fn collector_epoch_reset_keeps_pending_original_body_and_actual_configuration() {
        const NEXT: &str = "00000000-0000-4000-8000-000000000009";
        let (temp, identity) = identity();
        let path = temp.path().join("runtime");
        let mut store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
        store.apply(&config(1), BOOT, 1).unwrap();
        let mut collector = HostCollector::new(EPOCH).unwrap();
        let expired = collector.collect(raw(1)).unwrap();
        store.admit(expired).unwrap();
        assert!(store.begin(BOOT, 3_600_000_000_002).unwrap().is_none());
        assert_eq!(store.discarded_samples_total(), 1);
        let pending = collector.collect(raw(4_000_000_000_000)).unwrap();
        store.admit(pending.clone()).unwrap();
        drop(store);
        let mut store = RuntimeStore::open(&path, &identity, NEXT).unwrap();
        assert_eq!(store.configuration(), Some(&config(1)));
        assert_eq!(
            store.discarded_samples_total(),
            0,
            "past epoch loss is not current loss"
        );
        assert_eq!(
            store.begin(BOOT, pending.monotonic_ns).unwrap().unwrap(),
            pending
        );
        let current: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("runtime.json")).unwrap()).unwrap();
        assert_eq!(current["discardedCollectorEpoch"], NEXT);
        assert_eq!(current["discardedSamplesTotal"], 0);
        assert_eq!(
            current["configuration"],
            serde_json::to_value(config(1)).unwrap()
        );
    }
    #[test]
    fn exact_wire_boundaries_survive_source_error_hotplug_and_clock_interrupt() {
        let start = 10_000_000_002_026_474;
        let step = 30_000_527_205;
        let mut collector = HostCollector::new(EPOCH).unwrap();
        let mut previous = None;
        for round in 0..9 {
            let ns = start + step * round;
            let mut source = raw(ns);
            if round == 2 {
                source.cpu = Err(Availability::CollectionError);
            }
            if round >= 5
                && let Ok(cpus) = &mut source.cpu
            {
                cpus.insert("0".into(), [ns, 0, ns, ns, 0, 0, 0, 0, 0, 0]);
            }
            if round == 7 {
                collector.interrupt();
            }
            let sample = collector.collect(source).unwrap();
            let value: serde_json::Value = serde_json::from_str(&sample.body).unwrap();
            assert_eq!(exact_ns(&value["monotonicSeconds"]), ns);
            let expected = match round {
                0 | 3 | 5 | 7 => "NO_BASELINE",
                2 => "COLLECTION_ERROR",
                _ => "AVAILABLE",
            };
            for point in value["points"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|p| p["metric"].as_str().unwrap().starts_with("cpu."))
            {
                assert_eq!(point["availability"], expected);
                if expected == "AVAILABLE" {
                    assert_eq!(exact_ns(&point["interval"]["durationSeconds"]), step);
                } else {
                    assert!(point["interval"].is_null());
                }
            }
            assert_eq!(
                value["continuity"]["previousSampleId"].as_str(),
                previous.as_deref()
            );
            previous = Some(sample.sample_id);
        }
    }
    #[test]
    fn exact_retained_time_rejects_subnanoseconds_but_accepts_exact_legacy_numeric_forms() {
        let mut sample = HostCollector::new(EPOCH)
            .unwrap()
            .collect(raw(1_000_000_001))
            .unwrap();
        for token in ["1.000000001", "1.0000000010", "1000000001e-9"] {
            let mut value: serde_json::Value = serde_json::from_str(&sample.body).unwrap();
            value["monotonicSeconds"] = serde_json::from_str(token).unwrap();
            sample.body = value.to_string();
            assert!(valid_sample(&sample).is_ok());
        }
        for token in ["1.0000000011", "1.000000002", "-1", "1e999"] {
            let mut value: serde_json::Value = serde_json::from_str(&sample.body).unwrap();
            value["monotonicSeconds"] = serde_json::from_str(token).unwrap();
            sample.body = value.to_string();
            assert_eq!(valid_sample(&sample), Err("INVALID_METRIC_SAMPLE"));
        }
    }
    #[test]
    fn terminal_expiry_counts_alias_once_in_new_epoch_and_never_failed_admission() {
        const NEXT: &str = "00000000-0000-4000-8000-000000000009";
        let (temp, identity) = identity();
        let path = temp.path().join("runtime");
        let mut store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
        store.apply(&config(1), BOOT, 1).unwrap();
        let sample = HostCollector::new(EPOCH).unwrap().collect(raw(1)).unwrap();
        store.admit(sample.clone()).unwrap();
        store.begin(BOOT, 1).unwrap();
        drop(store);
        let mut store = RuntimeStore::open(&path, &identity, NEXT).unwrap();
        store.apply(&config(1), NEXT, 1).unwrap();
        assert_eq!(store.discarded_samples_total(), 1);
        assert!(store.begin(NEXT, 1).unwrap().is_none());
        assert_eq!(store.discarded_samples_total(), 1);
        let mut invalid = sample;
        invalid.body = "invalid".into();
        assert!(store.admit(invalid).is_err());
        assert_eq!(store.discarded_samples_total(), 1);
    }
    #[test]
    fn foreign_or_partial_runtime_state_is_rejected_without_recovery_cleanup() {
        let (temp, identity) = identity();
        let path = temp.path().join("runtime");
        let mut store = RuntimeStore::open(&path, &identity, EPOCH).unwrap();
        store.apply(&config(1), BOOT, 1).unwrap();
        drop(store);
        fs::write(path.join("runtime.next"), "partial candidate").unwrap();
        fs::set_permissions(path.join("runtime.next"), fs::Permissions::from_mode(0o600)).unwrap();
        let before = fingerprint(&path);
        assert!(RuntimeStore::open(&path, &identity, EPOCH).is_err());
        assert_eq!(fingerprint(&path), before);
        fs::remove_file(path.join("runtime.next")).unwrap();
        let file = path.join("runtime.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        value["operationId"] = serde_json::json!("00000000-0000-4000-8000-000000000099");
        fs::write(&file, value.to_string()).unwrap();
        let before = fingerprint(&path);
        assert!(RuntimeStore::open(&path, &identity, EPOCH).is_err());
        assert_eq!(fingerprint(&path), before);
    }
}
