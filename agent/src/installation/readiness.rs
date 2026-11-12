//! Local publication evidence recorded in the formal first-install plan.

use super::{
    AllocationCharge, AllocationObservation, DirectorySpace, DiskBudgetState, FormalPackage,
    ManagerEnablementEvidence, PackageDiskInputs, PhaseBudget, ServiceManagerObservation,
    assess_allocation, assess_publication_lower_bound,
    layout::{open_root, program_parent, state_parent},
    observe_allocation,
    plan_store::stat,
    service_readiness::{ManagerReadiness, ServiceDestination, inspect_service_readiness},
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::ErrorKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallPublicationReadiness {
    pub service: ServiceObservation,
    pub program_space: Option<DirectorySpace>,
    pub state_space: Option<DirectorySpace>,
    pub service_space: Option<DirectorySpace>,
    /// Logical member lengths. Complete allocation and quota evidence is separate.
    pub package: Option<PackageDiskInputs>,
    /// Program, state, selected service. Older v4 records have no pool observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation: Option<[Option<AllocationObservation>; 3]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceObservation {
    InterfaceObserved,
    DestinationExisting,
    DestinationUnsafe,
    ManagerConflict,
    Unavailable,
}

pub(super) enum ControlCapacity<'a> {
    Missing,
    Existing(&'a File),
    Unavailable,
}

impl InstallPublicationReadiness {
    pub(super) fn inspect(package: &FormalPackage, manager: ServiceManagerObservation) -> Self {
        let root = open_root().ok();
        let program = root
            .as_ref()
            .and_then(|root| program_parent(root, 0).ok())
            .and_then(|directory| observe_allocation(&directory).ok());
        let state = root
            .as_ref()
            .and_then(|root| state_parent(root, 0).ok())
            .and_then(|directory| observe_allocation(&directory).ok());
        let inspection = inspect_service_readiness(manager);
        let (service, service_allocation) = match inspection.destination {
            ServiceDestination::Existing => (ServiceObservation::DestinationExisting, None),
            ServiceDestination::Unsafe => (ServiceObservation::DestinationUnsafe, None),
            ServiceDestination::Unavailable if inspection.manager == ManagerReadiness::Conflict => {
                (ServiceObservation::ManagerConflict, None)
            }
            ServiceDestination::Unavailable => (ServiceObservation::Unavailable, None),
            ServiceDestination::Missing { parent, name } => {
                let observation = match (manager, inspection.manager, name.to_bytes()) {
                    (
                        ServiceManagerObservation::Systemd,
                        ManagerReadiness::InterfaceObserved,
                        b"nodomi-agent.service",
                    )
                    | (
                        ServiceManagerObservation::OpenRc,
                        ManagerReadiness::InterfaceObserved,
                        b"nodomi-agent",
                    ) => ServiceObservation::InterfaceObserved,
                    (_, ManagerReadiness::Conflict, _) => ServiceObservation::ManagerConflict,
                    _ => ServiceObservation::Unavailable,
                };
                (observation, observe_allocation(&parent).ok())
            }
        };
        Self::from_observations(
            package,
            manager,
            service,
            [program, state, service_allocation],
        )
    }

    #[cfg(test)]
    pub(super) fn from_held_targets(
        package: &FormalPackage,
        manager: ServiceManagerObservation,
        targets: [&File; 3],
    ) -> Self {
        Self::from_observations(
            package,
            manager,
            ServiceObservation::InterfaceObserved,
            targets.map(|directory| observe_allocation(directory).ok()),
        )
    }

    fn from_observations(
        package: &FormalPackage,
        manager: ServiceManagerObservation,
        service: ServiceObservation,
        allocation: [Option<AllocationObservation>; 3],
    ) -> Self {
        let [program_space, state_space, service_space] = allocation
            .each_ref()
            .map(|value| value.as_ref().map(|item| item.space));
        Self {
            service,
            program_space,
            state_space,
            service_space,
            package: PackageDiskInputs::from_package(package, manager).ok(),
            allocation: Some(allocation),
        }
    }

    pub(super) fn allocation_consistent(&self) -> bool {
        self.allocation.as_ref().is_none_or(|observations| {
            observations
                .each_ref()
                .map(|observation| observation.as_ref().map(|item| item.space))
                == [self.program_space, self.state_space, self.service_space]
        })
    }

    pub(super) fn definite_disk_shortage(&self) -> bool {
        if self.definite_inode_shortage() {
            return true;
        }
        let (Some([Some(program), Some(state), Some(service)]), Some(package)) =
            (&self.allocation, &self.package)
        else {
            return false;
        };
        assess_publication_lower_bound(&[program.clone(), state.clone(), service.clone()], package)
            .is_ok_and(|result| result.state == DiskBudgetState::Insufficient)
    }

    pub(super) fn definite_inode_shortage(&self) -> bool {
        let Some(package) = &self.package else {
            return false;
        };
        // The private program tree has four directories and a current pointer
        // in addition to the installed package files. The service temp file is
        // renamed in place. Additional state and enablement costs remain open.
        let program_inodes = 5 + package.program_files.len() as u64;
        [
            (self.program_space, program_inodes),
            (self.service_space, 1),
        ]
        .into_iter()
        .any(|(space, required)| {
            space
                .and_then(|space| space.available_inodes)
                .is_some_and(|available| available < required)
        })
    }

    pub(super) fn definite_startup_shortage(
        &self,
        enablement: &ManagerEnablementEvidence,
        fresh: Option<(ControlCapacity<'_>, bool)>,
    ) -> bool {
        self.definite_disk_shortage()
            || enablement
                .assess_minimum()
                .is_ok_and(|assessment| assessment.state == DiskBudgetState::Insufficient)
            || fresh.is_some_and(|(control, explicit_ca)| {
                self.definite_retained_inode_shortage(enablement, control, explicit_ca)
            })
    }

    /// Inodes that coexist at first health, grouped across verified pools.
    /// The caller has observed fresh program, state and service destinations.
    fn definite_retained_inode_shortage(
        &self,
        enablement: &ManagerEnablementEvidence,
        control: ControlCapacity<'_>,
        explicit_ca: bool,
    ) -> bool {
        let (Some(observations), Some(package)) = (&self.allocation, &self.package) else {
            return false;
        };
        let existing_control = match control {
            ControlCapacity::Existing(directory) => observe_control_minimum(directory),
            ControlCapacity::Missing | ControlCapacity::Unavailable => None,
        };
        retained_inode_shortage(
            observations,
            5 + package.program_files.len() as u64,
            enablement
                .allocation()
                .zip(enablement.required_additional_inodes()),
            existing_control
                .as_ref()
                .map(|(allocation, count)| (allocation, *count)),
            matches!(control, ControlCapacity::Missing),
            explicit_ca,
        )
    }
}

fn observe_control_minimum(directory: &File) -> Option<(AllocationObservation, u64)> {
    // The successful settlement creates a temporary replacement while the old
    // control record is still live. Charge any required names still absent too.
    let inodes = [c"publication.json", c"supervisor.lock"]
        .into_iter()
        .filter(|name| {
            stat(directory, Some(name)).is_err_and(|error| error.kind() == ErrorKind::NotFound)
        })
        .count() as u64
        + 1;
    Some((observe_allocation(directory).ok()?, inodes))
}

fn retained_inode_shortage(
    publication: &[Option<AllocationObservation>; 3],
    program_inodes: u64,
    enablement: Option<(&AllocationObservation, u64)>,
    existing_control: Option<(&AllocationObservation, u64)>,
    fresh_control: bool,
    explicit_ca: bool,
) -> bool {
    // State: root and four subdirectories, two settings files, identity lock
    // and record, runtime lock and manifest, and the first-health proof.
    let state_inodes = 12 + u64::from(explicit_ca);
    // A new control domain shares the state-parent pool. Its five retained
    // inodes coexist with the temporary replacement at successful settlement.
    let control_inodes = if fresh_control { 6 } else { 0 };
    let (observations, charges): (Vec<_>, Vec<_>) = publication
        .iter()
        .zip([program_inodes, state_inodes + control_inodes, 1])
        .filter_map(|(observation, inodes)| observation.as_ref().map(|item| (item, inodes)))
        .chain(enablement)
        .chain(existing_control)
        .map(|(observation, inodes)| {
            let charge = if observation.proven_pool() {
                AllocationCharge {
                    bytes: None,
                    inodes: Some(inodes),
                }
            } else {
                AllocationCharge::UNKNOWN
            };
            (observation.clone(), charge)
        })
        .unzip();
    // The service parent already exists, so a missing enablement parent is
    // separate from the published service file. No temporary or manager
    // runtime allocation is inferred from this retained-name minimum.
    assess_allocation(&observations, &[PhaseBudget { charges }])
        .is_ok_and(|result| result.state == DiskBudgetState::Insufficient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation::{AllocationFilesystem, QuotaObservation};

    fn allocation(device: u64, mount: u64, free: u64) -> AllocationObservation {
        AllocationObservation {
            space: DirectorySpace {
                device,
                inode: mount,
                available_bytes: None,
                available_inodes: Some(free),
                fragment_bytes: Some(4096),
                read_only: false,
            },
            filesystem: AllocationFilesystem::Ext,
            mount_id: Some(mount),
            mount_verified: true,
            quotas: [QuotaObservation::Unknown; 3],
            ext_counters_unscoped: Some(true),
        }
    }

    #[test]
    fn counts_coexisting_first_health_inodes_across_binds_and_distinct_pools() {
        let mut publication = [
            Some(allocation(1, 10, 22)),
            Some(allocation(1, 11, 22)),
            Some(allocation(1, 12, 22)),
        ];
        let link = allocation(1, 13, 22);
        assert!(retained_inode_shortage(
            &publication,
            9,
            Some((&link, 1)),
            None,
            false,
            false
        ));
        assert!(!retained_inode_shortage(
            &publication,
            9,
            None,
            None,
            false,
            false
        ));
        assert!(retained_inode_shortage(
            &publication,
            9,
            None,
            None,
            false,
            true
        ));
        assert!(retained_inode_shortage(
            &publication,
            9,
            None,
            None,
            true,
            false
        ));

        publication[1] = Some(allocation(2, 11, 22));
        assert!(!retained_inode_shortage(
            &publication,
            9,
            Some((&link, 1)),
            None,
            true,
            true
        ));
    }

    #[test]
    fn settlement_replacement_uses_the_control_directory_pool() {
        let mut publication = [
            Some(allocation(1, 10, 27)),
            Some(allocation(1, 11, 27)),
            Some(allocation(1, 12, 27)),
        ];
        assert!(retained_inode_shortage(
            &publication,
            9,
            None,
            None,
            true,
            false
        ));
        for observation in publication.iter_mut().flatten() {
            observation.space.available_inodes = Some(24);
        }
        let shared = allocation(1, 13, 24);
        let separate = allocation(2, 14, 3);
        assert!(retained_inode_shortage(
            &publication,
            9,
            None,
            Some((&shared, 3)),
            false,
            false
        ));
        assert!(!retained_inode_shortage(
            &publication,
            9,
            None,
            Some((&separate, 3)),
            false,
            false
        ));
    }
}
