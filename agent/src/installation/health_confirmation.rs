//! Protected local evidence of authenticated first-install health.
//!
//! Event methods are for the trusted service owner, strictly AFTER its matching
//! authenticated request succeeded. Typed local observations are not network
//! authority: only client/session and live-service integration establish that.
use super::plan_store::{
    TemporaryPlan, check_directory, check_file, effective_uid, open_at, same_snapshot, stat,
};
use crate::{
    identity::{Binding, Target, public_id, uuid},
    protocol::{AgentConfiguration, IngestionResult},
    runtime::{StoredSample, valid_sample},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    time::Duration,
};

const MAX_HEALTH_BYTES: usize = 8192;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
const NAME: &std::ffi::CStr = c"health-confirmation.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthError {
    InvalidContext,
    ContextMismatch,
    Incomplete,
    NotAccepted,
    Stale,
    InvalidRecord,
    NotFound,
    UnsafeStorage,
    Busy,
    Conflict,
    Io,
    CommitOutcomeUnknown,
}
type Result<T> = std::result::Result<T, HealthError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthContext {
    target: Target,
    binding: Binding,
    identity_operation_id: String,
    collector_epoch: String,
}
impl HealthContext {
    pub fn new(
        target: Target,
        binding: Binding,
        identity_operation_id: &str,
        collector_epoch: &str,
    ) -> Result<Self> {
        let value = Self {
            target,
            binding,
            identity_operation_id: identity_operation_id.into(),
            collector_epoch: collector_epoch.into(),
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if Target::new(&self.target.origin, &self.target.expected_server_id)
            .ok()
            .as_ref()
            != Some(&self.target)
            || self.target.origin.len() > 2048
            || self.binding.server_id != self.target.expected_server_id
            || !public_id(&self.binding.agent_id)
            || !(1..=MAX_SAFE).contains(&self.binding.binding_revision)
            || !uuid(&self.identity_operation_id)
            || !uuid(&self.collector_epoch)
        {
            return Err(HealthError::InvalidContext);
        }
        Ok(())
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub fn identity_operation_id(&self) -> &str {
        &self.identity_operation_id
    }
    pub fn collector_epoch(&self) -> &str {
        &self.collector_epoch
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Applied {
    config_id: String,
    generation: u64,
    observed_ns: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptedHost {
    sample_id: String,
    sampled_ns: u64,
    accepted_ns: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthProof {
    schema_version: u32,
    context: HealthContext,
    boot_id: String,
    supervisor_pid: u32,
    started_ns: u64,
    heartbeat_ns: u64,
    applied: Applied,
    host: AcceptedHost,
}
impl HealthProof {
    pub fn context(&self) -> &HealthContext {
        &self.context
    }
    pub fn collector_epoch(&self) -> &str {
        self.context.collector_epoch()
    }
    pub fn supervisor_pid(&self) -> u32 {
        self.supervisor_pid
    }
    pub fn started_boottime_ns(&self) -> u64 {
        self.started_ns
    }
    pub fn accepted_boottime_ns(&self) -> u64 {
        self.host.accepted_ns
    }
    pub fn config_id(&self) -> &str {
        &self.applied.config_id
    }
    pub fn sample_id(&self) -> &str {
        &self.host.sample_id
    }
    fn validate(&self) -> Result<()> {
        self.context
            .validate()
            .map_err(|_| HealthError::InvalidRecord)?;
        if self.schema_version != 1
            || !uuid(&self.boot_id)
            || self.supervisor_pid <= 1
            || !uuid(&self.applied.config_id)
            || !(1..=MAX_SAFE).contains(&self.applied.generation)
            || !uuid(&self.host.sample_id)
            || self.started_ns > self.heartbeat_ns
            || self.heartbeat_ns > self.applied.observed_ns
            || self.applied.observed_ns > self.host.sampled_ns
            || self.host.sampled_ns > self.host.accepted_ns
        {
            return Err(HealthError::InvalidRecord);
        }
        Ok(())
    }
}

/// CLOCK_BOOTTIME includes suspend and is also used by real HOST samples.
pub fn health_boottime_ns() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time is a live writable timespec; CLOCK_BOOTTIME has no other prerequisites.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(HealthError::Io);
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return Err(HealthError::Io);
    }
    (time.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(time.tv_nsec as u64))
        .ok_or(HealthError::Io)
}
pub(super) fn boot_id() -> Result<String> {
    let mut bytes = Vec::new();
    File::open("/proc/sys/kernel/random/boot_id")
        .map_err(|_| HealthError::Io)?
        .take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| HealthError::Io)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| HealthError::Io)?
        .trim();
    if !uuid(value) {
        return Err(HealthError::Io);
    }
    Ok(value.into())
}
fn parent_pid() -> Result<u32> {
    // SAFETY: getppid has no preconditions.
    let pid = unsafe { libc::getppid() };
    if pid <= 1 {
        return Err(HealthError::InvalidContext);
    }
    Ok(pid as u32)
}

pub struct HealthTracker {
    context: HealthContext,
    boot_id: String,
    supervisor_pid: u32,
    started_ns: u64,
    heartbeat_ns: Option<u64>,
    applied: Option<Applied>,
    host: Option<AcceptedHost>,
}
impl HealthTracker {
    pub fn new(context: HealthContext) -> Result<Self> {
        context.validate()?;
        Ok(Self {
            context,
            boot_id: boot_id()?,
            supervisor_pid: parent_pid()?,
            started_ns: health_boottime_ns()?,
            heartbeat_ns: None,
            applied: None,
            host: None,
        })
    }
    pub fn context(&self) -> &HealthContext {
        &self.context
    }
    fn check(&self, context: &HealthContext) -> Result<u64> {
        if context != &self.context || parent_pid()? != self.supervisor_pid {
            return Err(HealthError::ContextMismatch);
        }
        let now = health_boottime_ns()?;
        if now < self.started_ns {
            return Err(HealthError::Stale);
        }
        Ok(now)
    }
    /// Call only after this identity/epoch's authenticated heartbeat ACK.
    pub fn record_heartbeat(&mut self, context: &HealthContext) -> Result<()> {
        let now = self.check(context)?;
        self.heartbeat_ns.get_or_insert(now);
        Ok(())
    }
    /// Call only after durable runtime activation AND the APPLIED receipt ACK.
    pub fn record_applied(
        &mut self,
        context: &HealthContext,
        config: &AgentConfiguration,
    ) -> Result<()> {
        let now = self.check(context)?;
        self.heartbeat_ns.ok_or(HealthError::Incomplete)?;
        let bytes = serde_json::to_vec(config).map_err(|_| HealthError::InvalidContext)?;
        AgentConfiguration::decode(&bytes).map_err(|_| HealthError::InvalidContext)?;
        if config.agent_id != context.binding.agent_id
            || config.binding_revision != context.binding.binding_revision
        {
            return Err(HealthError::ContextMismatch);
        }
        if let Some(old) = &self.applied {
            if config.target.generation < old.generation
                || (config.target.generation == old.generation
                    && config.target.config_id != old.config_id)
            {
                return Err(HealthError::ContextMismatch);
            }
            if config.target.config_id == old.config_id
                && config.target.generation == old.generation
            {
                return Ok(());
            }
        }
        self.applied = Some(Applied {
            config_id: config.target.config_id.clone(),
            generation: config.target.generation,
            observed_ns: now,
        });
        self.host = None;
        Ok(())
    }
    /// Call only for this exact submitted real HOST sample, AFTER finish_metric_upload
    /// verified its identity authority and returned an accepted (not duplicate) ACK.
    pub fn record_host_accepted(
        &mut self,
        context: &HealthContext,
        sample: &StoredSample,
        ack: &IngestionResult,
    ) -> Result<()> {
        let now = self.check(context)?;
        let applied = self.applied.as_ref().ok_or(HealthError::Incomplete)?;
        if ack.accepted_count != 1 || ack.duplicate_count != 0 || ack.expired_count != 0 {
            return Err(HealthError::NotAccepted);
        }
        valid_sample(sample).map_err(|_| HealthError::InvalidRecord)?;
        let value: serde_json::Value =
            serde_json::from_str(&sample.body).map_err(|_| HealthError::InvalidRecord)?;
        if !value["points"].as_array().is_some_and(|points| {
            points
                .iter()
                .any(|point| point["availability"] == "AVAILABLE" && point["value"].is_number())
        }) {
            return Err(HealthError::Incomplete);
        }
        if sample.boot_id != self.boot_id
            || value["collectorEpoch"].as_str() != Some(context.collector_epoch())
        {
            return Err(HealthError::ContextMismatch);
        }
        if sample.monotonic_ns < applied.observed_ns || sample.monotonic_ns > now {
            return Err(HealthError::Stale);
        }
        self.host.get_or_insert(AcceptedHost {
            sample_id: sample.sample_id.clone(),
            sampled_ns: sample.monotonic_ns,
            accepted_ns: now,
        });
        Ok(())
    }
    /// Persists only a complete observation. The owner stops tracking after success.
    pub fn persist(&self, store: &HealthConfirmationStore) -> Result<HealthProof> {
        self.check(&self.context)?;
        let proof = HealthProof {
            schema_version: 1,
            context: self.context.clone(),
            boot_id: self.boot_id.clone(),
            supervisor_pid: self.supervisor_pid,
            started_ns: self.started_ns,
            heartbeat_ns: self.heartbeat_ns.ok_or(HealthError::Incomplete)?,
            applied: self.applied.clone().ok_or(HealthError::Incomplete)?,
            host: self.host.clone().ok_or(HealthError::Incomplete)?,
        };
        proof.validate()?;
        store.save(&proof, File::sync_all)?;
        Ok(proof)
    }
}

/// Anchors an existing dedicated private directory. Creates no directory and
/// stores no credentials. Callers supply the fixed, protected health directory.
pub struct HealthConfirmationStore {
    directory: File,
}
impl HealthConfirmationStore {
    pub fn open(directory: File) -> Result<Self> {
        check_directory(&directory, effective_uid()).map_err(|_| HealthError::UnsafeStorage)?;
        let directory = open_at(&directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|_| HealthError::Io)?;
        check_directory(&directory, effective_uid()).map_err(|_| HealthError::UnsafeStorage)?;
        Ok(Self { directory })
    }
    pub fn verify_for_install(
        &self,
        target: &Target,
        binding: &Binding,
        identity_operation_id: &str,
        min_started_boottime_ns: u64,
        max_age: Duration,
    ) -> Result<HealthProof> {
        let proof = self.read()?;
        if &proof.context.target != target
            || &proof.context.binding != binding
            || proof.context.identity_operation_id != identity_operation_id
        {
            return Err(HealthError::ContextMismatch);
        }
        let now = health_boottime_ns()?;
        if proof.boot_id != boot_id()?
            || proof.started_ns < min_started_boottime_ns
            || proof.host.accepted_ns > now
            || u128::from(now - proof.heartbeat_ns) > max_age.as_nanos()
        {
            return Err(HealthError::Stale);
        }
        // The writer's rename can become visible before its directory sync.
        // Establish durability and re-read the same proof before settling.
        self.directory.sync_all().map_err(|_| HealthError::Io)?;
        if self.read()? != proof {
            return Err(HealthError::Stale);
        }
        Ok(proof)
    }

    #[cfg(test)]
    pub(super) fn check_previous_boot(
        &self,
        target: &Target,
        binding: &Binding,
        identity_operation_id: &str,
    ) -> Result<()> {
        let proof = match self.read() {
            Ok(proof) => proof,
            Err(HealthError::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        };
        if &proof.context.target != target
            || &proof.context.binding != binding
            || proof.context.identity_operation_id != identity_operation_id
            || proof.boot_id == boot_id()?
        {
            return Err(HealthError::ContextMismatch);
        }
        Ok(())
    }
    fn read(&self) -> Result<HealthProof> {
        check_directory(&self.directory, effective_uid())
            .map_err(|_| HealthError::UnsafeStorage)?;
        let listed = stat(&self.directory, Some(NAME)).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                HealthError::NotFound
            } else {
                HealthError::Io
            }
        })?;
        let size = check_file(&listed, effective_uid()).map_err(|_| HealthError::UnsafeStorage)?;
        if size > MAX_HEALTH_BYTES {
            return Err(HealthError::InvalidRecord);
        }
        let file = open_at(&self.directory, NAME, libc::O_RDONLY)
            .map_err(|_| HealthError::UnsafeStorage)?;
        let opened = stat(&file, None).map_err(|_| HealthError::Io)?;
        if !same_snapshot(&listed, &opened) {
            return Err(HealthError::UnsafeStorage);
        }
        let mut bytes = Vec::with_capacity(size);
        (&file)
            .take((MAX_HEALTH_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| HealthError::Io)?;
        let after = stat(&file, None).map_err(|_| HealthError::Io)?;
        let named = stat(&self.directory, Some(NAME)).map_err(|_| HealthError::UnsafeStorage)?;
        if bytes.len() != size || !same_snapshot(&opened, &after) || !same_snapshot(&opened, &named)
        {
            return Err(HealthError::UnsafeStorage);
        }
        check_directory(&self.directory, effective_uid())
            .map_err(|_| HealthError::UnsafeStorage)?;
        let proof: HealthProof =
            serde_json::from_slice(&bytes).map_err(|_| HealthError::InvalidRecord)?;
        proof.validate()?;
        Ok(proof)
    }
    fn save(
        &self,
        proof: &HealthProof,
        sync_parent: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<()> {
        // Separate open description makes this advisory writer lock independent
        // even when one store object is shared. Readers require no writer lock.
        let lock = open_at(&self.directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|_| HealthError::Io)?;
        // SAFETY: lock owns a live directory FD, dropped on every return path.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(HealthError::Busy);
        }
        match self.read() {
            Ok(previous) => {
                if previous.context.collector_epoch == proof.context.collector_epoch
                    && previous != *proof
                {
                    return Err(HealthError::Conflict);
                }
                if previous.context.target != proof.context.target
                    || previous.context.binding != proof.context.binding
                    || previous.context.identity_operation_id != proof.context.identity_operation_id
                {
                    return Err(HealthError::ContextMismatch);
                }
            }
            Err(HealthError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let bytes = serde_json::to_vec(proof).map_err(|_| HealthError::InvalidRecord)?;
        if bytes.len() > MAX_HEALTH_BYTES {
            return Err(HealthError::InvalidRecord);
        }
        let mut temporary = TemporaryPlan::create(&self.directory).map_err(|_| HealthError::Io)?;
        temporary
            .file
            .write_all(&bytes)
            .and_then(|()| temporary.file.sync_all())
            .map_err(|_| HealthError::Io)?;
        let written = stat(&temporary.file, None).map_err(|_| HealthError::Io)?;
        if check_file(&written, effective_uid()).ok() != Some(bytes.len()) || !temporary.owns_name()
        {
            return Err(HealthError::UnsafeStorage);
        }
        check_directory(&self.directory, effective_uid())
            .map_err(|_| HealthError::UnsafeStorage)?;
        // SAFETY: both names are fixed or randomly generated single components
        // under the same held private directory; the writer lock serializes saves.
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                temporary.name.as_ptr(),
                self.directory.as_raw_fd(),
                NAME.as_ptr(),
            )
        } != 0
        {
            return Err(HealthError::Io);
        }
        temporary.published = true;
        sync_parent(&self.directory).map_err(|_| HealthError::CommitOutcomeUnknown)?;
        if self.read().map_err(|_| HealthError::CommitOutcomeUnknown)? != *proof {
            return Err(HealthError::CommitOutcomeUnknown);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "health_confirmation/tests.rs"]
mod tests;
