//! First-health capacity inventory with explicit evidence boundaries.
//!
//! This module contains NO default production startup footprint. A filesystem
//! snapshot is neither a transient peak nor an allocation upper bound. The
//! trusted owner must establish complete phase costs AND enforce the declared
//! workload limits before a complete profile can admit capacity. This arithmetic
//! is not installation authorization, quota proof, reservation or runtime control.
mod manager_capacity;
pub use manager_capacity::{
    ConfiguredLogStream, ManagerCapacityDestination, ManagerCapacityInventory,
    ManagerCapacityUnknown, ManagerDestinationRole, ManagerDestinationStatus,
    ManagerEnablementEvidence, ManagerEnablementStatus, SystemdLoggingError,
    SystemdLoggingObservation,
};

use super::plan_store::{open_at, same_snapshot, stat};
use super::{
    AllocationCharge, AllocationObservation, DiskAssessment, DiskBudgetError, PhaseBudget,
    assess_allocation,
};
use std::{
    collections::HashSet,
    ffi::CString,
    fs::File,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupBudgetError {
    InvalidProfile,
    ArithmeticOverflow,
    Storage,
    UnstableObservation,
    TraversalLimit,
    CrossMount,
    UnsupportedObject,
    Disk(DiskBudgetError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupStage {
    ControlPreparation,
    PackagePublication,
    StatePreparation,
    IdentityRegistration,
    RuntimeInitialization,
    FirstHealth,
}
impl StartupStage {
    pub const ALL: [Self; 6] = [
        Self::ControlPreparation,
        Self::PackagePublication,
        Self::StatePreparation,
        Self::IdentityRegistration,
        Self::RuntimeInitialization,
        Self::FirstHealth,
    ];
    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|value| *value == self)
            .expect("exhaustive startup stage")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupComponent {
    Program,
    Control,
    Identity,
    /// service.json, update-mode.json, optional CA, and final health evidence.
    StateAndHealth,
    RuntimeAndSqlite,
    ServiceFiles,
    ManagerRuntime,
    FilesystemMetadata,
}
impl StartupComponent {
    pub const ALL: [Self; 8] = [
        Self::Program,
        Self::Control,
        Self::Identity,
        Self::StateAndHealth,
        Self::RuntimeAndSqlite,
        Self::ServiceFiles,
        Self::ManagerRuntime,
        Self::FilesystemMetadata,
    ];
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupBudgetEvidence {
    /// A conservative upper bound established by the trusted implementation
    /// owner for this exact phase/workload/filesystem. Never inferred from one run.
    Bounded,
    /// A snapshot or sampled maximum; unobserved temporary peaks may exist.
    ObservedOnly,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupComponentBudget {
    pub component: StartupComponent,
    pub evidence: StartupBudgetEvidence,
    /// Additional concurrently allocated bytes/inodes for EVERY destination,
    /// in the same order as observations. Include retained state in later phases.
    /// Explicit zero is required where this component has no effect.
    pub charges: Vec<AllocationCharge>,
}

/// Limits for the whole service-start to first-health interval, not the user's
/// steady-state queue cap. Merely describing them here does NOT enforce them.
/// The owner must constrain all paths including SSH ingestion, JSON replacements,
/// SQLite rollback journals, timeout/retry, and configuration changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupWorkloadLimits {
    pub max_duration_ms: u64,
    pub max_runtime_manifest_bytes: u64,
    pub max_sqlite_database_bytes: u64,
    pub max_sqlite_journal_bytes: u64,
}
impl StartupWorkloadLimits {
    fn valid(self) -> bool {
        [
            self.max_duration_ms,
            self.max_runtime_manifest_bytes,
            self.max_sqlite_database_bytes,
            self.max_sqlite_journal_bytes,
        ]
        .into_iter()
        .all(|value| value != 0)
            && self.max_duration_ms.checked_mul(1_000_000).is_some()
            && self
                .max_runtime_manifest_bytes
                .checked_mul(2)
                .and_then(|value| value.checked_add(self.max_sqlite_database_bytes))
                .and_then(|value| value.checked_add(self.max_sqlite_journal_bytes))
                .is_some()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupBudgetProfile {
    destinations: usize,
    limits: StartupWorkloadLimits,
    stages: Vec<Vec<StartupComponentBudget>>,
}
impl StartupBudgetProfile {
    pub fn unknown(
        destinations: usize,
        limits: StartupWorkloadLimits,
    ) -> Result<Self, StartupBudgetError> {
        if !(1..=16).contains(&destinations) || !limits.valid() {
            return Err(StartupBudgetError::InvalidProfile);
        }
        let unknown = StartupComponent::ALL
            .into_iter()
            .map(|component| StartupComponentBudget {
                component,
                evidence: StartupBudgetEvidence::Unknown,
                charges: vec![AllocationCharge::UNKNOWN; destinations],
            })
            .collect::<Vec<_>>();
        Ok(Self {
            destinations,
            limits,
            stages: vec![unknown; StartupStage::ALL.len()],
        })
    }
    pub fn limits(&self) -> StartupWorkloadLimits {
        self.limits
    }
    pub fn destination_count(&self) -> usize {
        self.destinations
    }
    pub fn record_phase(
        &mut self,
        stage: StartupStage,
        components: Vec<StartupComponentBudget>,
    ) -> Result<(), StartupBudgetError> {
        if components.len() != StartupComponent::ALL.len()
            || StartupComponent::ALL.iter().any(|component| {
                components
                    .iter()
                    .filter(|value| value.component == *component)
                    .count()
                    != 1
            })
            || components
                .iter()
                .any(|value| value.charges.len() != self.destinations)
        {
            return Err(StartupBudgetError::InvalidProfile);
        }
        self.stages[stage.index()] = components;
        Ok(())
    }
    /// Includes the actual unresolved destination indices so /run, persistent
    /// journal storage, or enablement mounts cannot disappear into an aggregate.
    pub fn unresolved(&self) -> Vec<(StartupStage, StartupComponent, usize)> {
        let mut result = Vec::new();
        for stage in StartupStage::ALL {
            for component in &self.stages[stage.index()] {
                for (index, charge) in component.charges.iter().enumerate() {
                    if component.evidence != StartupBudgetEvidence::Bounded
                        || charge.bytes.is_none()
                        || charge.inodes.is_none()
                    {
                        result.push((stage, component.component, index));
                    }
                }
            }
        }
        result
    }
}

/// Pure evidence arithmetic. `limits_enforced` is an assertion by the trusted
/// workload owner, not an installer capability. Pass false for today's ordinary
/// service until its first-health write paths implement these separate limits.
/// An empty directory measurement or a configured 100 MB queue cap cannot set it.
pub fn assess_startup_budget(
    observations: &[AllocationObservation],
    profile: &StartupBudgetProfile,
    limits_enforced: bool,
) -> Result<DiskAssessment, StartupBudgetError> {
    if observations.len() != profile.destinations {
        return Err(StartupBudgetError::InvalidProfile);
    }
    let mut phases = Vec::with_capacity(7);
    for stage in StartupStage::ALL {
        let mut totals = vec![AllocationCharge::ZERO; profile.destinations];
        for component in &profile.stages[stage.index()] {
            for (total, charge) in totals.iter_mut().zip(&component.charges) {
                let charge = if component.evidence == StartupBudgetEvidence::Bounded {
                    *charge
                } else {
                    AllocationCharge::UNKNOWN
                };
                total.bytes = sum(total.bytes, charge.bytes)?;
                total.inodes = sum(total.inodes, charge.inodes)?;
            }
        }
        phases.push(PhaseBudget { charges: totals });
    }
    if !limits_enforced {
        phases.push(PhaseBudget {
            charges: vec![AllocationCharge::UNKNOWN; profile.destinations],
        });
    }
    assess_allocation(observations, &phases).map_err(StartupBudgetError::Disk)
}
fn sum(left: Option<u64>, right: Option<u64>) -> Result<Option<u64>, StartupBudgetError> {
    match (left, right) {
        (Some(left), Some(right)) => left
            .checked_add(right)
            .map(Some)
            .ok_or(StartupBudgetError::ArithmeticOverflow),
        _ => Ok(None),
    }
}

/// Sum of st_blocks * 512 and distinct inodes in a bounded tree, including its
/// root. It is NOT exclusive pool consumption (e.g. reflinks), filesystem metadata
/// overhead, a transient peak, or a global atomic snapshot. Quiesce writers when
/// comparing points; no final snapshot can establish missing temporary files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StartupFootprintSnapshot {
    pub allocated_bytes: u64,
    pub inodes: u64,
    pub regular_files: u64,
    pub directories: u64,
    pub symlinks: u64,
}
pub fn measure_startup_tree(
    directory: &File,
) -> Result<StartupFootprintSnapshot, StartupBudgetError> {
    let root = stat(directory, None).map_err(|_| StartupBudgetError::Storage)?;
    if root.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(StartupBudgetError::UnsupportedObject);
    }
    let mut measurement = Measurement {
        device: root.st_dev,
        seen: HashSet::new(),
        entries: 0,
        output: StartupFootprintSnapshot::default(),
    };
    measurement.visit(directory, 0)?;
    Ok(measurement.output)
}
struct Measurement {
    device: libc::dev_t,
    seen: HashSet<(libc::dev_t, libc::ino_t)>,
    entries: usize,
    output: StartupFootprintSnapshot,
}
impl Measurement {
    fn add(&mut self, info: &libc::stat) -> Result<bool, StartupBudgetError> {
        self.entries += 1;
        if self.entries > 4096 {
            return Err(StartupBudgetError::TraversalLimit);
        }
        if info.st_dev != self.device {
            return Err(StartupBudgetError::CrossMount);
        }
        if !self.seen.insert((info.st_dev, info.st_ino)) {
            return Ok(false);
        }
        let blocks = u64::try_from(info.st_blocks)
            .ok()
            .and_then(|blocks| blocks.checked_mul(512))
            .ok_or(StartupBudgetError::ArithmeticOverflow)?;
        self.output.allocated_bytes = self
            .output
            .allocated_bytes
            .checked_add(blocks)
            .ok_or(StartupBudgetError::ArithmeticOverflow)?;
        self.output.inodes += 1;
        match info.st_mode & libc::S_IFMT {
            libc::S_IFDIR => self.output.directories += 1,
            libc::S_IFREG => self.output.regular_files += 1,
            libc::S_IFLNK => self.output.symlinks += 1,
            _ => return Err(StartupBudgetError::UnsupportedObject),
        }
        Ok(true)
    }
    fn visit(&mut self, directory: &File, depth: usize) -> Result<(), StartupBudgetError> {
        if depth > 16 {
            return Err(StartupBudgetError::TraversalLimit);
        }
        let before = stat(directory, None).map_err(|_| StartupBudgetError::Storage)?;
        if !self.add(&before)? {
            return Ok(());
        }
        // procfs follows exactly our held directory FD, not the caller's original
        // pathname; children are inspected by nofollow fstatat/openat below.
        let entries = std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| StartupBudgetError::Storage)?;
        for entry in entries {
            let entry = entry.map_err(|_| StartupBudgetError::Storage)?;
            let name = CString::new(entry.file_name().as_bytes())
                .map_err(|_| StartupBudgetError::UnsupportedObject)?;
            let info = stat(directory, Some(&name))
                .map_err(|_| StartupBudgetError::UnstableObservation)?;
            if info.st_mode & libc::S_IFMT == libc::S_IFDIR {
                let child = open_at(directory, &name, libc::O_RDONLY | libc::O_DIRECTORY)
                    .map_err(|_| StartupBudgetError::UnstableObservation)?;
                let opened = stat(&child, None).map_err(|_| StartupBudgetError::Storage)?;
                if !same_snapshot(&info, &opened) {
                    return Err(StartupBudgetError::UnstableObservation);
                }
                self.visit(&child, depth + 1)?;
            } else {
                self.add(&info)?;
            }
            let after = stat(directory, Some(&name))
                .map_err(|_| StartupBudgetError::UnstableObservation)?;
            if !same_snapshot(&info, &after) {
                return Err(StartupBudgetError::UnstableObservation);
            }
        }
        let after = stat(directory, None).map_err(|_| StartupBudgetError::Storage)?;
        if !same_snapshot(&before, &after) {
            return Err(StartupBudgetError::UnstableObservation);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "startup_budget/tests.rs"]
mod tests;
