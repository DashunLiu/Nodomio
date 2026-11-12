//! Read-only first-install capacity evidence and phase/pool arithmetic.
//!
//! These values are observations, not installation authority. The plan owner
//! must bind them to its held targets and repeat observation under its lease.
//! Pool identity, absence of applicable quotas, allocation overhead and the
//! complete phase inventory require independent evidence; statvfs cannot prove
//! them. Unknown inputs never become a sufficient budget.

use super::{FormalPackage, ServiceManagerObservation, package::formal_member_lengths_valid};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    mem::MaybeUninit,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

const MAX_DESTINATIONS: usize = 16;
const MAX_PHASES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskBudgetError {
    Io,
    NotDirectory,
    InvalidBudget,
    InvalidPackage,
    UnknownServiceManager,
    InvalidAllocationProfile,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectorySpace {
    pub device: u64,
    pub inode: u64,
    pub available_bytes: Option<u64>,
    pub available_inodes: Option<u64>,
    /// Filesystem accounting fragment, not proof of file allocation overhead.
    pub fragment_bytes: Option<u64>,
    pub read_only: bool,
}

/// Read the filesystem containing the held destination directory. This does
/// not reopen a pathname, test writes, reserve space or verify its owner.
pub fn observe_directory(directory: &File) -> Result<DirectorySpace, DiskBudgetError> {
    let metadata = directory.metadata().map_err(|_| DiskBudgetError::Io)?;
    if !metadata.is_dir() {
        return Err(DiskBudgetError::NotDirectory);
    }
    let mut raw = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the held file descriptor is live and raw has writable statvfs storage.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), raw.as_mut_ptr()) } != 0 {
        return Err(DiskBudgetError::Io);
    }
    // SAFETY: successful fstatvfs initialized raw.
    let raw = unsafe { raw.assume_init() };
    let fragment = u64::try_from(u128::from(raw.f_frsize))
        .ok()
        .filter(|value| *value != 0);
    let available_bytes = fragment
        .filter(|_| {
            raw.f_bavail <= raw.f_blocks
                && u128::from(raw.f_bavail) != u128::from(libc::fsblkcnt_t::MAX)
        })
        .and_then(|fragment| {
            u128::from(raw.f_bavail)
                .checked_mul(u128::from(fragment))
                .and_then(|value| u64::try_from(value).ok())
        });
    // Zero total or an all-ones sentinel does not establish inode accounting.
    let available_inodes = (raw.f_files != 0
        && raw.f_files != libc::fsfilcnt_t::MAX
        && raw.f_favail <= raw.f_files
        && u128::from(raw.f_favail) != u128::from(libc::fsfilcnt_t::MAX))
    .then(|| u64::try_from(u128::from(raw.f_favail)).ok())
    .flatten();
    Ok(DirectorySpace {
        device: metadata.dev(),
        inode: metadata.ino(),
        available_bytes,
        available_inodes,
        fragment_bytes: fragment,
        read_only: raw.f_flag & libc::ST_RDONLY != 0,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaEvidence {
    Unknown,
    /// Caller has verified that no applicable user/group/project/subvolume
    /// quota further limits this target. Root or statvfs alone cannot prove it.
    VerifiedAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationBudget {
    pub space: DirectorySpace,
    /// Equal IDs mean a shared allocation pool. Distinct IDs require actual
    /// independent-pool evidence, not different mount IDs or device numbers.
    pub pool: Option<u32>,
    pub quota: QuotaEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationCharge {
    /// Required allocation including measured metadata/temporary-file costs.
    /// None means the complete charge has not been established.
    pub bytes: Option<u64>,
    pub inodes: Option<u64>,
}

impl AllocationCharge {
    pub const ZERO: Self = Self {
        bytes: Some(0),
        inodes: Some(0),
    };
    pub const UNKNOWN: Self = Self {
        bytes: None,
        inodes: None,
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseBudget {
    /// Exactly one simultaneous additional charge for each destination, in
    /// destination order. Renaming the same object adds no second charge;
    /// simultaneously retained copies must both be included by the owner.
    pub charges: Vec<AllocationCharge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskBudgetState {
    Sufficient,
    Insufficient,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskBudgetReason {
    AllocationUnknown,
    CapacityUnknown,
    PoolUnknown,
    ConflictingPoolEvidence,
    QuotaUnknown,
    ReadOnly,
    ArithmeticOverflow,
    BytesInsufficient,
    InodesInsufficient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolBudget {
    pub pool: u32,
    pub available_bytes: Option<u64>,
    pub available_inodes: Option<u64>,
    pub peak_bytes: Option<u64>,
    pub peak_inodes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskAssessment {
    pub state: DiskBudgetState,
    pub reasons: Vec<DiskBudgetReason>,
    pub pools: Vec<PoolBudget>,
}

fn reason(reasons: &mut Vec<DiskBudgetReason>, value: DiskBudgetReason) {
    if !reasons.contains(&value) {
        reasons.push(value);
    }
}

fn shortage(
    required: Option<u64>,
    available: Option<u64>,
    kind: DiskBudgetReason,
    reasons: &mut Vec<DiskBudgetReason>,
) {
    if required
        .zip(available)
        .is_some_and(|(required, available)| required > available)
    {
        reason(reasons, kind);
    }
}

/// Compare the owner's complete measured phase inventory to current evidence.
/// This is not a reservation or a promise that subsequent writes cannot fail.
/// Applicable quotas are currently conservative UNKNOWN, not silently ignored.
pub fn assess_budget(
    destinations: &[DestinationBudget],
    phases: &[PhaseBudget],
) -> Result<DiskAssessment, DiskBudgetError> {
    use DiskBudgetReason::*;
    if destinations.is_empty()
        || destinations.len() > MAX_DESTINATIONS
        || phases.is_empty()
        || phases.len() > MAX_PHASES
        || phases
            .iter()
            .any(|phase| phase.charges.len() != destinations.len())
    {
        return Err(DiskBudgetError::InvalidBudget);
    }
    // Contradictory ownership makes the proposed pool model unusable. Do not
    // derive shortage or sufficient capacity from internally inconsistent inputs.
    if destinations.iter().enumerate().any(|(index, destination)| {
        destinations[..index].iter().any(|other| {
            other.space.device == destination.space.device
                && other.pool.is_some()
                && destination.pool.is_some()
                && other.pool != destination.pool
        })
    }) {
        return Ok(DiskAssessment {
            state: DiskBudgetState::Unknown,
            reasons: vec![ConflictingPoolEvidence],
            pools: Vec::new(),
        });
    }
    let mut reasons = Vec::new();
    let mut pool_ids = Vec::new();
    for (index, destination) in destinations.iter().enumerate() {
        if destination.space.read_only {
            reason(&mut reasons, ReadOnly);
        }
        if destination.quota == QuotaEvidence::Unknown {
            reason(&mut reasons, QuotaUnknown);
        }
        if destination.space.available_bytes.is_none()
            || destination.space.available_inodes.is_none()
        {
            reason(&mut reasons, CapacityUnknown);
        }
        match destination.pool {
            Some(pool) if !pool_ids.contains(&pool) => pool_ids.push(pool),
            None => reason(&mut reasons, PoolUnknown),
            _ => {}
        }
        for phase in phases {
            let charge = phase.charges[index];
            if charge.bytes.is_none() || charge.inodes.is_none() {
                reason(&mut reasons, AllocationUnknown);
            }
            shortage(
                charge.bytes,
                destination.space.available_bytes,
                BytesInsufficient,
                &mut reasons,
            );
            shortage(
                charge.inodes,
                destination.space.available_inodes,
                InodesInsufficient,
                &mut reasons,
            );
        }
    }
    let mut pools = Vec::new();
    for pool in pool_ids {
        let indices: Vec<_> = destinations
            .iter()
            .enumerate()
            .filter(|(_, destination)| destination.pool == Some(pool))
            .map(|(index, _)| index)
            .collect();
        // Repeated observations of the same pool may differ as other writers
        // run. Never sum its free capacity; use the lowest observed value.
        let available_bytes = indices
            .iter()
            .filter_map(|index| destinations[*index].space.available_bytes)
            .min();
        let available_inodes = indices
            .iter()
            .filter_map(|index| destinations[*index].space.available_inodes)
            .min();
        let mut peak_bytes = Some(0);
        let mut peak_inodes = Some(0);
        for phase in phases {
            let mut bytes = 0_u64;
            let mut inodes = 0_u64;
            let mut bytes_known = true;
            let mut inodes_known = true;
            for index in &indices {
                let charge = phase.charges[*index];
                for (value, total, known) in [
                    (charge.bytes, &mut bytes, &mut bytes_known),
                    (charge.inodes, &mut inodes, &mut inodes_known),
                ] {
                    match value {
                        None => *known = false,
                        Some(value) => match total.checked_add(value) {
                            Some(sum) => *total = sum,
                            None => {
                                *known = false;
                                reason(&mut reasons, ArithmeticOverflow);
                            }
                        },
                    }
                }
            }
            // Known contributions can already exceed capacity even when an
            // additional destination's complete allocation remains unknown.
            shortage(
                Some(bytes),
                available_bytes,
                BytesInsufficient,
                &mut reasons,
            );
            shortage(
                Some(inodes),
                available_inodes,
                InodesInsufficient,
                &mut reasons,
            );
            peak_bytes = peak_bytes
                .filter(|_| bytes_known)
                .map(|peak| peak.max(bytes));
            peak_inodes = peak_inodes
                .filter(|_| inodes_known)
                .map(|peak| peak.max(inodes));
        }
        pools.push(PoolBudget {
            pool,
            available_bytes,
            available_inodes,
            peak_bytes,
            peak_inodes,
        });
    }
    let state = if reasons.contains(&BytesInsufficient) || reasons.contains(&InodesInsufficient) {
        DiskBudgetState::Insufficient
    } else if reasons.is_empty() {
        DiskBudgetState::Sufficient
    } else {
        DiskBudgetState::Unknown
    };
    Ok(DiskAssessment {
        state,
        reasons,
        pools,
    })
}

/// Measured filesystem-specific allocation requirements. statvfs fragment size
/// alone does not provide this profile. Directory/initial-state costs are separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAllocationProfile {
    pub allocation_unit: u64,
    pub metadata_bytes_per_file: u64,
}

pub fn file_charge(
    lengths: &[u64],
    profile: FileAllocationProfile,
) -> Result<AllocationCharge, DiskBudgetError> {
    if profile.allocation_unit == 0 {
        return Err(DiskBudgetError::InvalidAllocationProfile);
    }
    let mut bytes = 0_u64;
    for length in lengths {
        let blocks =
            length / profile.allocation_unit + u64::from(length % profile.allocation_unit != 0);
        let charged = blocks
            .checked_mul(profile.allocation_unit)
            .and_then(|value| value.checked_add(profile.metadata_bytes_per_file))
            .ok_or(DiskBudgetError::ArithmeticOverflow)?;
        bytes = bytes
            .checked_add(charged)
            .ok_or(DiskBudgetError::ArithmeticOverflow)?;
    }
    Ok(AllocationCharge {
        bytes: Some(bytes),
        inodes: Some(
            u64::try_from(lengths.len()).map_err(|_| DiskBudgetError::ArithmeticOverflow)?,
        ),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveStorage {
    AlreadyHeld,
    NewCopy,
}

/// Member sizes from the inspected package, not proof of release or ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageDiskInputs {
    /// Agent, agentctl, supervisor, LICENSE. The unselected service is not installed.
    pub program_files: [u64; 4],
    pub service_file: u64,
    pub archive_bytes: u64,
}

impl PackageDiskInputs {
    pub fn from_package(
        package: &FormalPackage,
        manager: ServiceManagerObservation,
    ) -> Result<Self, DiskBudgetError> {
        const EXPECTED: [(&str, u32); 6] = [
            ("bin/nodomi-agent", 0o755),
            ("bin/nodomi-agentctl", 0o755),
            ("bin/nodomi-agent-supervisor", 0o755),
            ("services/systemd/nodomi-agent.service", 0o644),
            ("services/openrc/nodomi-agent", 0o755),
            ("LICENSE", 0o644),
        ];
        if package.members.len() != EXPECTED.len()
            || package
                .members
                .iter()
                .zip(EXPECTED)
                .any(|(member, (path, mode))| member.path != path || member.mode != mode)
            || !(1..=512 * 1024 * 1024).contains(&package.archive_bytes)
        {
            return Err(DiskBudgetError::InvalidPackage);
        }
        let lengths: [u64; 6] = std::array::from_fn(|index| package.members[index].length);
        if !formal_member_lengths_valid(lengths)
            || lengths.iter().sum::<u64>() != package.expanded_member_bytes
        {
            return Err(DiskBudgetError::InvalidPackage);
        }
        let service_file = match manager {
            ServiceManagerObservation::Systemd => lengths[3],
            ServiceManagerObservation::OpenRc => lengths[4],
            _ => return Err(DiskBudgetError::UnknownServiceManager),
        };
        Ok(Self {
            program_files: [lengths[0], lengths[1], lengths[2], lengths[5]],
            service_file,
            archive_bytes: package.archive_bytes,
        })
    }

    pub fn archive_charge(
        &self,
        storage: ArchiveStorage,
        profile: FileAllocationProfile,
    ) -> Result<AllocationCharge, DiskBudgetError> {
        match storage {
            ArchiveStorage::AlreadyHeld => Ok(AllocationCharge::ZERO),
            ArchiveStorage::NewCopy => file_charge(&[self.archive_bytes], profile),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write};

    fn destination(pool: u32, free: u64) -> DestinationBudget {
        DestinationBudget {
            pool: Some(pool),
            quota: QuotaEvidence::VerifiedAbsent,
            space: DirectorySpace {
                device: u64::from(pool),
                inode: 1,
                available_bytes: Some(free),
                available_inodes: Some(100),
                fragment_bytes: Some(1),
                read_only: false,
            },
        }
    }
    fn phase(bytes: &[u64]) -> PhaseBudget {
        PhaseBudget {
            charges: bytes
                .iter()
                .map(|bytes| AllocationCharge {
                    bytes: Some(*bytes),
                    inodes: Some(1),
                })
                .collect(),
        }
    }

    #[test]
    fn shared_pool_sums_simultaneous_charges_and_independent_pools_do_not() {
        let shared = [destination(1, 14), destination(1, 14), destination(1, 14)];
        let phases = [phase(&[12, 2, 1])];
        let result = assess_budget(&shared, &phases).unwrap();
        assert_eq!(result.state, DiskBudgetState::Insufficient);
        assert_eq!(result.pools[0].peak_bytes, Some(15));
        let independent = [destination(1, 12), destination(2, 2), destination(3, 1)];
        assert_eq!(
            assess_budget(&independent, &phases).unwrap().state,
            DiskBudgetState::Sufficient
        );
        let low = [destination(1, 100), destination(2, 1), destination(3, 100)];
        assert_eq!(
            assess_budget(&low, &phases).unwrap().state,
            DiskBudgetState::Insufficient
        );
    }

    #[test]
    fn uses_phase_peak_not_sum_of_nonoverlapping_destination_peaks() {
        let destinations = [destination(1, 10), destination(1, 10)];
        let result = assess_budget(&destinations, &[phase(&[8, 1]), phase(&[1, 8])]).unwrap();
        assert_eq!(result.state, DiskBudgetState::Sufficient);
        assert_eq!(result.pools[0].peak_bytes, Some(9));
        assert_eq!(
            assess_budget(&destinations, &[phase(&[8, 8])])
                .unwrap()
                .state,
            DiskBudgetState::Insufficient
        );
    }

    #[test]
    fn unknown_pool_quota_allocation_or_capacity_never_passes() {
        let original = destination(1, 100);
        for modified in [
            DestinationBudget {
                pool: None,
                ..original
            },
            DestinationBudget {
                quota: QuotaEvidence::Unknown,
                ..original
            },
            DestinationBudget {
                space: DirectorySpace {
                    available_inodes: None,
                    ..original.space
                },
                ..original
            },
            DestinationBudget {
                space: DirectorySpace {
                    read_only: true,
                    ..original.space
                },
                ..original
            },
        ] {
            assert_eq!(
                assess_budget(&[modified], &[phase(&[1])]).unwrap().state,
                DiskBudgetState::Unknown
            );
        }
        assert_eq!(
            assess_budget(
                &[original],
                &[PhaseBudget {
                    charges: vec![AllocationCharge::UNKNOWN]
                }]
            )
            .unwrap()
            .state,
            DiskBudgetState::Unknown
        );
        let contradictory = DestinationBudget {
            pool: Some(2),
            ..original
        };
        let result = assess_budget(&[original, contradictory], &[phase(&[1, 1])]).unwrap();
        assert_eq!(result.state, DiskBudgetState::Unknown);
        assert!(
            result
                .reasons
                .contains(&DiskBudgetReason::ConflictingPoolEvidence)
        );
        let contradictory_shortage =
            assess_budget(&[original, contradictory], &[phase(&[101, 101])]).unwrap();
        assert_eq!(contradictory_shortage.state, DiskBudgetState::Unknown);
        assert_eq!(
            contradictory_shortage.reasons,
            vec![DiskBudgetReason::ConflictingPoolEvidence]
        );
    }

    #[test]
    fn detects_inodes_and_known_shortage_even_when_other_cost_is_unknown() {
        let mut target = destination(1, 100);
        target.space.available_inodes = Some(0);
        assert_eq!(
            assess_budget(&[target], &[phase(&[1])]).unwrap().state,
            DiskBudgetState::Insufficient
        );
        let destinations = [destination(1, 10), destination(1, 10)];
        let phase = PhaseBudget {
            charges: vec![
                AllocationCharge {
                    bytes: Some(11),
                    inodes: Some(1),
                },
                AllocationCharge::UNKNOWN,
            ],
        };
        assert_eq!(
            assess_budget(&destinations, &[phase]).unwrap().state,
            DiskBudgetState::Insufficient
        );
    }

    #[test]
    fn checked_allocation_rounding_and_held_archive_accounting() {
        let profile = FileAllocationProfile {
            allocation_unit: 4,
            metadata_bytes_per_file: 2,
        };
        assert_eq!(
            file_charge(&[1, 4, 5], profile).unwrap(),
            AllocationCharge {
                bytes: Some(22),
                inodes: Some(3)
            }
        );
        assert_eq!(
            file_charge(&[u64::MAX], profile),
            Err(DiskBudgetError::ArithmeticOverflow)
        );
        let package = PackageDiskInputs {
            program_files: [3, 3, 3, 3],
            service_file: 1,
            archive_bytes: 3,
        };
        assert_eq!(
            package
                .archive_charge(ArchiveStorage::AlreadyHeld, profile)
                .unwrap(),
            AllocationCharge::ZERO
        );
        assert_eq!(
            package
                .archive_charge(ArchiveStorage::NewCopy, profile)
                .unwrap()
                .bytes,
            Some(6)
        );
        let destinations = [destination(1, 17), destination(1, 17), destination(1, 17)];
        assert_eq!(
            assess_budget(&destinations, &[phase(&[12, 2, 1])])
                .unwrap()
                .state,
            DiskBudgetState::Sufficient
        );
        assert_eq!(
            assess_budget(&destinations, &[phase(&[15, 2, 1])])
                .unwrap()
                .state,
            DiskBudgetState::Insufficient
        );
    }

    #[test]
    fn package_sizes_select_only_the_installed_service_and_validate_all_members() {
        use super::super::FormalPackageMember;
        use crate::release::manifest::Platform;
        let members = [
            ("bin/nodomi-agent", 0o755, 64),
            ("bin/nodomi-agentctl", 0o755, 128),
            ("bin/nodomi-agent-supervisor", 0o755, 256),
            ("services/systemd/nodomi-agent.service", 0o644, 8),
            ("services/openrc/nodomi-agent", 0o755, 9),
            ("LICENSE", 0o644, 11),
        ];
        let mut package = FormalPackage {
            platform: Platform::LinuxAarch64,
            archive_bytes: 100,
            archive_sha256: "a".repeat(64),
            expanded_member_bytes: 476,
            members: members
                .into_iter()
                .map(|(path, mode, length)| FormalPackageMember {
                    path,
                    mode,
                    length,
                    sha256: "b".repeat(64),
                    executable: None,
                })
                .collect(),
        };
        let systemd =
            PackageDiskInputs::from_package(&package, ServiceManagerObservation::Systemd).unwrap();
        assert_eq!(systemd.program_files, [64, 128, 256, 11]);
        assert_eq!(systemd.service_file, 8);
        assert_eq!(
            PackageDiskInputs::from_package(&package, ServiceManagerObservation::OpenRc)
                .unwrap()
                .service_file,
            9
        );
        assert_eq!(
            PackageDiskInputs::from_package(&package, ServiceManagerObservation::Unknown),
            Err(DiskBudgetError::UnknownServiceManager)
        );
        package.members.swap(3, 4);
        assert_eq!(
            PackageDiskInputs::from_package(&package, ServiceManagerObservation::Systemd),
            Err(DiskBudgetError::InvalidPackage)
        );
    }

    #[test]
    fn overflow_and_incomplete_phase_inventory_cannot_be_sufficient() {
        let destinations = [destination(1, u64::MAX), destination(1, u64::MAX)];
        let result = assess_budget(&destinations, &[phase(&[u64::MAX, 1])]).unwrap();
        assert_eq!(result.state, DiskBudgetState::Unknown);
        assert!(
            result
                .reasons
                .contains(&DiskBudgetReason::ArithmeticOverflow)
        );
        assert_eq!(
            assess_budget(&destinations, &[phase(&[1])]),
            Err(DiskBudgetError::InvalidBudget)
        );
        assert_eq!(assess_budget(&[], &[]), Err(DiskBudgetError::InvalidBudget));
    }

    #[test]
    fn real_held_directory_observation_is_read_only_and_survives_path_rename() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("original");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("canary"), b"unchanged").unwrap();
        let directory = File::open(&path).unwrap();
        let moved = temporary.path().join("moved");
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        let observed = observe_directory(&directory).unwrap();
        assert_eq!(observed.inode, fs::metadata(&moved).unwrap().ino());
        assert!(observed.available_bytes.is_some());
        assert_eq!(fs::read(moved.join("canary")).unwrap(), b"unchanged");
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 1);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"not a directory").unwrap();
        assert_eq!(observe_directory(&file), Err(DiskBudgetError::NotDirectory));
    }
}
