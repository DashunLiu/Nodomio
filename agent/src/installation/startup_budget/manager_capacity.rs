//! Protected manager destinations. Possible log paths are not effective policy.
//!
//! The selected service manager and its effective configuration are verified by
//! their existing owners. Directory inventory reads no logs, config secrets,
//! machine IDs, or credentials. The separate logging observer executes only a
//! pinned systemctl with fixed read-only arguments. All paths are fixed names.
#[path = "manager_enablement.rs"]
mod manager_enablement;
#[path = "systemd_logging.rs"]
mod systemd_logging;
use super::super::{
    AllocationCharge, AllocationObservation, DiskAssessment, DiskBudgetError, DiskBudgetReason,
    DiskBudgetState, PhaseBudget, ServiceManagerObservation, assess_allocation, observe_allocation,
};
use super::super::{
    layout::{LayoutEntry, open_root},
    plan_store::{open_at, same_snapshot, stat},
    service_readiness::openrc_runtime,
};
use super::{StartupBudgetEvidence, StartupComponent, StartupComponentBudget};
pub use manager_enablement::{ManagerEnablementEvidence, ManagerEnablementStatus};
use std::{ffi::CStr, fs::File, io};
pub use systemd_logging::{ConfiguredLogStream, SystemdLoggingError, SystemdLoggingObservation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerDestinationRole {
    RunRoot,
    Runtime,
    Enablement,
    VolatileJournal,
    PersistentJournal,
    OpenRcLogParent,
    /// A fixed known subdirectory, observed separately for nested mounts.
    RuntimeSubdirectory(&'static str),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerDestinationStatus {
    Existing,
    /// Allocation describes the nearest existing protected ancestor. Missing
    /// directory creation and future mount changes still need explicit accounting.
    MissingBelowProtectedParent {
        missing_components: usize,
    },
    Unsafe,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerCapacityUnknown {
    UnsupportedManager,
    EffectiveLoggingRoute,
    ManagerWriteBounds,
    /// Generators, logging forwards, or manager configuration can write elsewhere.
    UninventoriedManagerEffects,
    MissingDestination,
    UnsafeDestination,
    UnavailableDestination,
    AllocationUnavailable,
    UnprovenPool,
    UnprovenQuota,
    ReadOnlyDestination,
}

#[derive(Debug)]
pub struct ManagerCapacityDestination {
    pub role: ManagerDestinationRole,
    /// Static intended directory; not a statement that it currently exists.
    pub path: &'static str,
    pub status: ManagerDestinationStatus,
    pub allocation: Option<AllocationObservation>,
    anchor: Option<File>,
}
impl ManagerCapacityDestination {
    /// The pinned directory observed above. If missing, this is its nearest
    /// protected ancestor, NOT authority to create the intended destination.
    pub fn anchor(&self) -> Option<&File> {
        self.anchor.as_ref()
    }
}

#[derive(Debug)]
pub struct ManagerCapacityInventory {
    manager: ServiceManagerObservation,
    destinations: Vec<ManagerCapacityDestination>,
    unresolved: Vec<ManagerCapacityUnknown>,
}
impl ManagerCapacityInventory {
    /// Observe loaded unit logging properties for this running invocation. This
    /// does not clear EffectiveLoggingRoute or ManagerWriteBounds: configured
    /// routes are not running descriptor attribution or physical write bounds.
    pub fn observe_systemd_logging(
        &self,
        main_pid: u32,
        invocation_id: u128,
    ) -> Result<SystemdLoggingObservation, SystemdLoggingError> {
        if self.manager != ServiceManagerObservation::Systemd {
            return Err(SystemdLoggingError::UnsupportedManager);
        }
        systemd_logging::observe(main_pid, invocation_id)
    }
    pub fn inspect(manager: ServiceManagerObservation) -> Self {
        match open_root() {
            Ok(root) => inspect_at(&root, 0, manager),
            Err(_) => unavailable(manager),
        }
    }
    pub fn manager(&self) -> ServiceManagerObservation {
        self.manager
    }
    pub fn destinations(&self) -> &[ManagerCapacityDestination] {
        &self.destinations
    }
    pub fn unresolved(&self) -> &[ManagerCapacityUnknown] {
        &self.unresolved
    }
    /// Same stable order as destinations(). Missing observations cannot be
    /// replaced with a fabricated statvfs record or silently omitted.
    pub fn allocation_observations(&self) -> Option<Vec<AllocationObservation>> {
        if self.destinations.is_empty() {
            return None;
        }
        self.destinations
            .iter()
            .map(|destination| destination.allocation.clone())
            .collect()
    }
    pub fn unknown_component_budget(&self) -> StartupComponentBudget {
        StartupComponentBudget {
            component: StartupComponent::ManagerRuntime,
            evidence: StartupBudgetEvidence::Unknown,
            charges: vec![AllocationCharge::UNKNOWN; self.destinations.len()],
        }
    }
    /// Reuses capacity arithmetic for explicit owner-supplied phases. The
    /// inventory does not establish effective log routes or manager write bounds,
    /// so it NEVER upgrades a sufficient numerical comparison into readiness.
    /// Caller must not treat all possible log destinations as simultaneous writes.
    pub fn assess(&self, phases: &[PhaseBudget]) -> Result<DiskAssessment, DiskBudgetError> {
        let Some(observations) = self.allocation_observations() else {
            return Ok(DiskAssessment {
                state: DiskBudgetState::Unknown,
                reasons: vec![
                    DiskBudgetReason::CapacityUnknown,
                    DiskBudgetReason::AllocationUnknown,
                ],
                pools: Vec::new(),
            });
        };
        let mut assessment = assess_allocation(&observations, phases)?;
        if !assessment
            .reasons
            .contains(&DiskBudgetReason::AllocationUnknown)
        {
            assessment.reasons.push(DiskBudgetReason::AllocationUnknown);
        }
        if assessment.state == DiskBudgetState::Sufficient {
            assessment.state = DiskBudgetState::Unknown;
        }
        Ok(assessment)
    }
}

struct DestinationSpec {
    role: ManagerDestinationRole,
    path: &'static str,
    components: &'static [&'static CStr],
}
fn specs(manager: ServiceManagerObservation) -> Vec<DestinationSpec> {
    use ManagerDestinationRole::*;
    let (runtime, runtime_components, enable, enable_components) = match manager {
        ServiceManagerObservation::Systemd => (
            "/run/systemd",
            &[c"run", c"systemd"][..],
            "/etc/systemd/system/multi-user.target.wants",
            &[c"etc", c"systemd", c"system", c"multi-user.target.wants"][..],
        ),
        ServiceManagerObservation::OpenRc => (
            "/run/openrc",
            &[c"run", c"openrc"][..],
            "/etc/runlevels/default",
            &[c"etc", c"runlevels", c"default"][..],
        ),
        _ => return Vec::new(),
    };
    let mut result = vec![
        DestinationSpec {
            role: RunRoot,
            path: "/run",
            components: &[c"run"],
        },
        DestinationSpec {
            role: Runtime,
            path: runtime,
            components: runtime_components,
        },
        DestinationSpec {
            role: Enablement,
            path: enable,
            components: enable_components,
        },
    ];
    match manager {
        ServiceManagerObservation::Systemd => {
            result.extend([
                DestinationSpec {
                    role: VolatileJournal,
                    path: "/run/log/journal",
                    components: &[c"run", c"log", c"journal"],
                },
                DestinationSpec {
                    role: PersistentJournal,
                    path: "/var/log/journal",
                    components: &[c"var", c"log", c"journal"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("units"),
                    path: "/run/systemd/units",
                    components: &[c"run", c"systemd", c"units"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("transient"),
                    path: "/run/systemd/transient",
                    components: &[c"run", c"systemd", c"transient"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("generator"),
                    path: "/run/systemd/generator",
                    components: &[c"run", c"systemd", c"generator"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("generator.early"),
                    path: "/run/systemd/generator.early",
                    components: &[c"run", c"systemd", c"generator.early"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("generator.late"),
                    path: "/run/systemd/generator.late",
                    components: &[c"run", c"systemd", c"generator.late"],
                },
            ]);
        }
        ServiceManagerObservation::OpenRc => {
            // These are the directories already inspected by require_stopped.
            // OpenRC logging is not presumed to use journald. Its possible
            // logger destination is /var/log; forwards/custom routes remain unknown.
            result.extend([
                DestinationSpec {
                    role: OpenRcLogParent,
                    path: "/var/log",
                    components: &[c"var", c"log"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("started"),
                    path: "/run/openrc/started",
                    components: &[c"run", c"openrc", c"started"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("starting"),
                    path: "/run/openrc/starting",
                    components: &[c"run", c"openrc", c"starting"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("stopping"),
                    path: "/run/openrc/stopping",
                    components: &[c"run", c"openrc", c"stopping"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("inactive"),
                    path: "/run/openrc/inactive",
                    components: &[c"run", c"openrc", c"inactive"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("failed"),
                    path: "/run/openrc/failed",
                    components: &[c"run", c"openrc", c"failed"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("options"),
                    path: "/run/openrc/options",
                    components: &[c"run", c"openrc", c"options"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("daemons"),
                    path: "/run/openrc/daemons",
                    components: &[c"run", c"openrc", c"daemons"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("exclusive"),
                    path: "/run/openrc/exclusive",
                    components: &[c"run", c"openrc", c"exclusive"],
                },
                DestinationSpec {
                    role: RuntimeSubdirectory("init.d"),
                    path: "/run/openrc/init.d",
                    components: &[c"run", c"openrc", c"init.d"],
                },
            ]);
        }
        _ => {}
    }
    result
}
fn unavailable(manager: ServiceManagerObservation) -> ManagerCapacityInventory {
    let destinations = specs(manager)
        .into_iter()
        .map(|spec| ManagerCapacityDestination {
            role: spec.role,
            path: spec.path,
            status: ManagerDestinationStatus::Unavailable,
            allocation: None,
            anchor: None,
        })
        .collect();
    finish(manager, destinations)
}
fn inspect_at(
    root: &File,
    owner: libc::uid_t,
    manager: ServiceManagerObservation,
) -> ManagerCapacityInventory {
    let destinations = specs(manager)
        .into_iter()
        .map(|spec| observe_destination(root, owner, manager, spec))
        .collect();
    finish(manager, destinations)
}
fn finish(
    manager: ServiceManagerObservation,
    destinations: Vec<ManagerCapacityDestination>,
) -> ManagerCapacityInventory {
    use ManagerCapacityUnknown::*;
    if destinations.is_empty() {
        return ManagerCapacityInventory {
            manager,
            destinations,
            unresolved: vec![UnsupportedManager],
        };
    }
    let mut unresolved = vec![
        EffectiveLoggingRoute,
        ManagerWriteBounds,
        UninventoriedManagerEffects,
    ];
    let mut add = |reason| {
        if !unresolved.contains(&reason) {
            unresolved.push(reason);
        }
    };
    for destination in &destinations {
        match destination.status {
            ManagerDestinationStatus::MissingBelowProtectedParent { .. } => add(MissingDestination),
            ManagerDestinationStatus::Unsafe => add(UnsafeDestination),
            ManagerDestinationStatus::Unavailable => add(UnavailableDestination),
            ManagerDestinationStatus::Existing => {}
        }
        match &destination.allocation {
            Some(observed) => {
                if !observed.proven_pool() {
                    add(UnprovenPool);
                }
                if observed.quotas != [super::super::QuotaObservation::Disabled; 3] {
                    add(UnprovenQuota);
                }
                if observed.space.read_only {
                    add(ReadOnlyDestination);
                }
            }
            None => add(AllocationUnavailable),
        }
    }
    ManagerCapacityInventory {
        manager,
        destinations,
        unresolved,
    }
}
fn protected(directory: &File, owner: libc::uid_t) -> bool {
    stat(directory, None).is_ok_and(|info| {
        info.st_mode & libc::S_IFMT == libc::S_IFDIR
            && info.st_uid == owner
            && info.st_mode & 0o022 == 0
    })
}
fn observe_destination(
    root: &File,
    owner: libc::uid_t,
    manager: ServiceManagerObservation,
    spec: DestinationSpec,
) -> ManagerCapacityDestination {
    let failure = |status| ManagerCapacityDestination {
        role: spec.role,
        path: spec.path,
        status,
        allocation: None,
        anchor: None,
    };
    if !protected(root, owner) {
        return failure(ManagerDestinationStatus::Unsafe);
    }
    let mut current = match open_at(root, c".", libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(file) => file,
        Err(_) => return failure(ManagerDestinationStatus::Unavailable),
    };
    for (index, component) in spec.components.iter().enumerate() {
        let listed = match stat(&current, Some(component)) {
            Ok(info) => info,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let allocation = observe_allocation(&current).ok();
                return ManagerCapacityDestination {
                    role: spec.role,
                    path: spec.path,
                    status: ManagerDestinationStatus::MissingBelowProtectedParent {
                        missing_components: spec.components.len() - index,
                    },
                    allocation,
                    anchor: Some(current),
                };
            }
            Err(_) => return failure(ManagerDestinationStatus::Unavailable),
        };
        if listed.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return failure(ManagerDestinationStatus::Unsafe);
        }
        let next = if manager == ServiceManagerObservation::OpenRc
            && *component == c"openrc"
            && index == 1
        {
            // Reuse the existing narrow Alpine root-group/ACL exception for
            // /run/openrc 0775; do not extend it to /run or other ancestors.
            match openrc_runtime(root, owner) {
                Ok(file) => file,
                Err(LayoutEntry::Unsafe) => return failure(ManagerDestinationStatus::Unsafe),
                Err(_) => return failure(ManagerDestinationStatus::Unavailable),
            }
        } else {
            match open_at(&current, component, libc::O_RDONLY | libc::O_DIRECTORY) {
                Ok(file) if protected(&file, owner) => file,
                Ok(_) => return failure(ManagerDestinationStatus::Unsafe),
                Err(error) if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {
                    return failure(ManagerDestinationStatus::Unsafe);
                }
                Err(_) => return failure(ManagerDestinationStatus::Unavailable),
            }
        };
        let opened = match stat(&next, None) {
            Ok(info) => info,
            Err(_) => return failure(ManagerDestinationStatus::Unavailable),
        };
        if !same_snapshot(&listed, &opened)
            || !stat(&current, Some(component)).is_ok_and(|named| same_snapshot(&opened, &named))
        {
            return failure(ManagerDestinationStatus::Unavailable);
        }
        current = next;
    }
    let allocation = observe_allocation(&current).ok();
    ManagerCapacityDestination {
        role: spec.role,
        path: spec.path,
        status: ManagerDestinationStatus::Existing,
        allocation,
        anchor: Some(current),
    }
}

#[cfg(test)]
#[path = "manager_capacity_tests.rs"]
mod tests;
