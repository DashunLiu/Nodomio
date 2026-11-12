//! Exact pre-install enablement object inventory, not a manager write bound.
//!
//! One absent link and each absent parent require one additional filesystem
//! inode on a proven ext allocator. This is a lower bound on the manager's
//! work, never an upper bound on allocation: parent directory growth, xattrs,
//! encrypted symlink contents, journaling and unrelated manager writes are not
//! established by the link target length or one observed st_blocks snapshot.
use super::{
    AllocationCharge, AllocationObservation, DiskAssessment, DiskBudgetError, DiskBudgetReason,
    DiskBudgetState, ManagerDestinationRole, ManagerDestinationStatus, PhaseBudget,
    ServiceManagerObservation, assess_allocation, observe_allocation, observe_destination,
    open_root, same_snapshot, specs, stat,
};
use std::{ffi::CStr, fs::File, io, os::fd::AsRawFd};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerEnablementStatus {
    LinkAbsent,
    ParentDirectoriesAbsent,
    ExpectedLinkPresent,
    ConflictingObject,
    UnsafeParent,
    Unavailable,
    UnsupportedManager,
}

#[derive(Debug)]
pub struct ManagerEnablementEvidence {
    manager: ServiceManagerObservation,
    status: ManagerEnablementStatus,
    missing_directories: usize,
    additional_inodes: Option<u64>,
    existing_link_allocated_bytes: Option<u64>,
    allocation: Option<AllocationObservation>,
    anchor: Option<File>,
}
impl ManagerEnablementEvidence {
    /// Read-only. Reobserve under the install lease; this is neither permission
    /// to create an existing path nor authority to replace an unexpected object.
    pub fn inspect(manager: ServiceManagerObservation) -> Self {
        match open_root() {
            Ok(root) => inspect_at(&root, 0, manager),
            Err(_) => failure(manager, ManagerEnablementStatus::Unavailable),
        }
    }
    #[cfg(test)]
    pub(in crate::installation) fn inspect_held_root(
        root: &File,
        owner: libc::uid_t,
        manager: ServiceManagerObservation,
    ) -> Self {
        inspect_at(root, owner, manager)
    }
    pub fn manager(&self) -> ServiceManagerObservation {
        self.manager
    }
    pub fn status(&self) -> ManagerEnablementStatus {
        self.status
    }
    pub fn missing_directories(&self) -> usize {
        self.missing_directories
    }
    /// Necessary objects for the exact enablement path, not a whole-command cap.
    /// Missing ancestors may also belong to service-publication costs; the phase
    /// owner must deduplicate them before combining component inventories.
    pub fn required_additional_inodes(&self) -> Option<u64> {
        self.additional_inodes
    }
    /// Current st_blocks * 512 for an already-existing exact link. Zero may mean
    /// an inline link. This is never substituted for future allocation cost.
    pub fn existing_link_allocated_bytes(&self) -> Option<u64> {
        self.existing_link_allocated_bytes
    }
    pub fn allocation(&self) -> Option<&AllocationObservation> {
        self.allocation.as_ref()
    }
    /// Existing nearest protected ancestor; missing parents are not created.
    pub fn anchor(&self) -> Option<&File> {
        self.anchor.as_ref()
    }
    pub fn allocated_byte_upper_bound(&self) -> Option<u64> {
        None
    }
    /// Can reject a proven ext inode shortage. Never sufficient: unsupported
    /// pool accounting, whole-command allocation and write bounds stay unknown.
    pub fn assess_minimum(&self) -> Result<DiskAssessment, DiskBudgetError> {
        let (Some(observation), Some(inodes)) = (&self.allocation, self.additional_inodes) else {
            return Ok(unknown());
        };
        if !observation.proven_pool() {
            return Ok(unknown());
        }
        assess_allocation(
            std::slice::from_ref(observation),
            &[
                PhaseBudget {
                    charges: vec![AllocationCharge {
                        bytes: Some(0),
                        inodes: Some(inodes),
                    }],
                },
                PhaseBudget {
                    charges: vec![AllocationCharge::UNKNOWN],
                },
            ],
        )
    }
}

fn unknown() -> DiskAssessment {
    DiskAssessment {
        state: DiskBudgetState::Unknown,
        reasons: vec![
            DiskBudgetReason::AllocationUnknown,
            DiskBudgetReason::CapacityUnknown,
        ],
        pools: Vec::new(),
    }
}
fn failure(
    manager: ServiceManagerObservation,
    status: ManagerEnablementStatus,
) -> ManagerEnablementEvidence {
    ManagerEnablementEvidence {
        manager,
        status,
        missing_directories: 0,
        additional_inodes: None,
        existing_link_allocated_bytes: None,
        allocation: None,
        anchor: None,
    }
}

fn inspect_at(
    root: &File,
    owner: libc::uid_t,
    manager: ServiceManagerObservation,
) -> ManagerEnablementEvidence {
    let Some(spec) = specs(manager)
        .into_iter()
        .find(|s| s.role == ManagerDestinationRole::Enablement)
    else {
        return failure(manager, ManagerEnablementStatus::UnsupportedManager);
    };
    let components = spec.components;
    let destination = observe_destination(root, owner, manager, spec);
    let missing = match destination.status {
        ManagerDestinationStatus::Existing => 0,
        ManagerDestinationStatus::MissingBelowProtectedParent { missing_components } => {
            missing_components
        }
        ManagerDestinationStatus::Unsafe => {
            return failure(manager, ManagerEnablementStatus::UnsafeParent);
        }
        ManagerDestinationStatus::Unavailable => {
            return failure(manager, ManagerEnablementStatus::Unavailable);
        }
    };
    let Some(anchor) = destination.anchor else {
        return failure(manager, ManagerEnablementStatus::Unavailable);
    };
    let Ok(before) = stat(&anchor, None) else {
        return failure(manager, ManagerEnablementStatus::Unavailable);
    };
    let (name, allowed): (&CStr, &[&[u8]]) = match manager {
        ServiceManagerObservation::Systemd => (
            c"nodomi-agent.service",
            &[
                b"/etc/systemd/system/nodomi-agent.service",
                b"../nodomi-agent.service",
            ],
        ),
        ServiceManagerObservation::OpenRc => (
            c"nodomi-agent",
            &[b"/etc/init.d/nodomi-agent", b"../../init.d/nodomi-agent"],
        ),
        _ => return failure(manager, ManagerEnablementStatus::UnsupportedManager),
    };
    let mut result = failure(manager, ManagerEnablementStatus::Unavailable);
    if missing != 0 {
        // Repeat the absent-component check inside the stable held-parent
        // interval; do not reuse a stale absence from the initial path walk.
        match stat(&anchor, Some(components[components.len() - missing])) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                result.status = ManagerEnablementStatus::ParentDirectoriesAbsent;
                result.missing_directories = missing;
                result.additional_inodes = Some(missing as u64 + 1);
            }
            _ => return result,
        }
    } else {
        match stat(&anchor, Some(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                result.status = ManagerEnablementStatus::LinkAbsent;
                result.additional_inodes = Some(1);
            }
            Err(_) => return result,
            Ok(link) => {
                if link.st_mode & libc::S_IFMT != libc::S_IFLNK
                    || link.st_uid != owner
                    || link.st_nlink != 1
                {
                    return failure(manager, ManagerEnablementStatus::ConflictingObject);
                }
                let mut target = [0_u8; 128];
                // SAFETY: held directory and C name are live; target is writable.
                let length = unsafe {
                    libc::readlinkat(
                        anchor.as_raw_fd(),
                        name.as_ptr(),
                        target.as_mut_ptr().cast(),
                        target.len(),
                    )
                };
                let Ok(length) = usize::try_from(length) else {
                    return result;
                };
                if !target
                    .get(..length)
                    .is_some_and(|target| allowed.contains(&target))
                {
                    return failure(manager, ManagerEnablementStatus::ConflictingObject);
                }
                if !stat(&anchor, Some(name)).is_ok_and(|now| same_snapshot(&link, &now)) {
                    return result;
                }
                result.status = ManagerEnablementStatus::ExpectedLinkPresent;
                result.additional_inodes = Some(0);
                result.existing_link_allocated_bytes = u64::try_from(link.st_blocks)
                    .ok()
                    .and_then(|blocks| blocks.checked_mul(512));
            }
        }
    }
    result.allocation = observe_allocation(&anchor).ok();
    if !stat(&anchor, None).is_ok_and(|after| same_snapshot(&before, &after)) {
        return failure(manager, ManagerEnablementStatus::Unavailable);
    }
    result.anchor = Some(anchor);
    result
}

#[cfg(test)]
#[path = "manager_enablement_tests.rs"]
mod tests;
