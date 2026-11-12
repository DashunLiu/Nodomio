//! Read-only kernel allocation evidence for first-install capacity admission.
//!
//! A kernel mount ID identifies a mount, not an allocation pool. For ext2/3/4,
//! the held directory's device identifies the kernel block-filesystem allocator.
//! Tmpfs uses a unique anonymous device per live superblock; statx binds its
//! mount/device/inode to the held descriptor before accepting the same grouping.
//! Bind mounts on that device share a budget when their counters describe
//! the filesystem rather than a directory project quota. Unsupported/stacked
//! filesystems never acquire a pool merely from a device or mount ID.
//! This observes filesystem accounting, not physical thin-pool provisioning,
//! reservations, tmpfs RAM/cgroup availability, or freedom from concurrent
//! writers. Reobserve under the lease and retain the handles while combining.
use super::{
    AllocationCharge, DestinationBudget, DirectorySpace, DiskAssessment, DiskBudgetError,
    PackageDiskInputs, PhaseBudget, QuotaEvidence, assess_budget, observe_directory,
    plan_store::open_at,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read},
    mem::MaybeUninit,
    os::fd::AsRawFd,
};

const MAX_PROC_BYTES: usize = 2 * 1024 * 1024;
const MAX_MOUNTS: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AllocationFilesystem {
    Ext,
    Tmpfs,
    Xfs,
    Unsupported,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuotaObservation {
    Disabled,
    Enabled,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationObservation {
    pub space: DirectorySpace,
    pub filesystem: AllocationFilesystem,
    pub mount_id: Option<u64>,
    pub mount_verified: bool,
    /// User, group, project, in Linux quota-type order. Enabled does not mean
    /// this UID is limited; it means absence of all relevant quotas is unproven.
    pub quotas: [QuotaObservation; 3],
    /// Whether the held ext directory's counters are proven filesystem-wide.
    /// Missing evidence, including in older plans, cannot justify aggregation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext_counters_unscoped: Option<bool>,
}
impl AllocationObservation {
    pub fn proven_pool(&self) -> bool {
        // XFS realtime inheritance/allocation must be checked before treating
        // its ordinary data-device statvfs counter as this destination's pool.
        matches!(
            self.filesystem,
            AllocationFilesystem::Ext | AllocationFilesystem::Tmpfs
        ) && self.mount_verified
            && self.mount_id.is_some_and(|id| id != 0)
            && self.space.device != 0
    }

    pub fn counters_share_pool(&self) -> bool {
        self.proven_pool()
            && (self.filesystem != AllocationFilesystem::Ext
                || self.ext_counters_unscoped == Some(true))
    }
}

/// Observe the held directory only; no path walk, probe file, mount or quota write.
/// Missing proc/kernel support reduces evidence to UNKNOWN rather than absence.
pub fn observe_allocation(directory: &File) -> Result<AllocationObservation, DiskBudgetError> {
    let mut raw = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the held FD is live and raw points to a writable statfs buffer.
    let fs = if unsafe { libc::fstatfs(directory.as_raw_fd(), raw.as_mut_ptr()) } == 0 {
        // SAFETY: successful fstatfs initialized the complete buffer.
        Some(unsafe { raw.assume_init() })
    } else {
        None
    };
    let filesystem = match fs.as_ref().map(|fs| fs.f_type as u64) {
        Some(0xef53) => AllocationFilesystem::Ext,
        Some(0x01021994) => AllocationFilesystem::Tmpfs,
        Some(0x58465342) => AllocationFilesystem::Xfs,
        _ => AllocationFilesystem::Unsupported,
    };
    // The caller can hold an O_PATH anchor, which does not accept ioctl.
    // Reopen its own inode without traversing any unpinned path component.
    let ext_directory = (filesystem == AllocationFilesystem::Ext)
        .then(|| open_at(directory, c".", libc::O_RDONLY | libc::O_DIRECTORY).ok())
        .flatten();
    // ext4_statfs_project can clamp both bytes and inodes for a directory with
    // PROJINHERIT. Verify a clear flag or absent project quotas on both sides
    // of the actual capacity sample.
    let inherit_before = ext_directory.as_ref().and_then(ext_project_inherit);
    let project_quota_before = (filesystem == AllocationFilesystem::Ext
        && inherit_before != Some(false))
    .then(|| observe_quota(directory, 2));
    let mut space = observe_directory(directory)?;
    let inherit_after = ext_directory.as_ref().and_then(ext_project_inherit);
    // shmem_statfs leaves f_blocks/f_bavail zero for size=0 (no filesystem
    // limit). Zero in that case is UNKNOWN, not evidence of a full filesystem.
    if filesystem == AllocationFilesystem::Tmpfs && fs.as_ref().is_some_and(|fs| fs.f_blocks == 0) {
        space.available_bytes = None;
    }
    let mount_id = read_proc(
        &format!("/proc/self/fdinfo/{}", directory.as_raw_fd()),
        16384,
    )
    .ok()
    .and_then(|s| parse_mount_id(&s));
    let mut mount_verified = mount_id.is_some_and(|id| {
        read_proc("/proc/self/mountinfo", MAX_PROC_BYTES)
            .is_ok_and(|s| verify_mount(&s, id, space.device, filesystem))
    });
    if filesystem == AllocationFilesystem::Tmpfs {
        mount_verified &= mount_id.is_some() && statx_mount_id(directory, &space) == mount_id;
    }
    let quotas = if filesystem != AllocationFilesystem::Unsupported && mount_verified {
        std::array::from_fn(|kind| observe_quota(directory, kind as libc::c_int))
    } else {
        [QuotaObservation::Unknown; 3]
    };
    let ext_counters_unscoped =
        (filesystem == AllocationFilesystem::Ext && mount_verified).then(|| {
            (inherit_before == Some(false) && inherit_after == Some(false))
                || (project_quota_before == Some(QuotaObservation::Disabled)
                    && quotas[2] == QuotaObservation::Disabled)
        });
    // Pin the final identity too. A missing statx result must not fall back to
    // an inferred tmpfs pool from a path, device number, or stale mount table.
    if filesystem == AllocationFilesystem::Tmpfs {
        mount_verified &= statx_mount_id(directory, &space) == mount_id;
    }
    Ok(AllocationObservation {
        space,
        filesystem,
        mount_id,
        mount_verified,
        quotas,
        ext_counters_unscoped,
    })
}

fn ext_project_inherit(directory: &File) -> Option<bool> {
    // Linux include/uapi/linux/fs.h: FS_PROJINHERIT_FL. fs/ioctl.c writes an
    // int for FS_IOC_GETFLAGS even though the request encodes sizeof(long).
    const FS_PROJINHERIT: libc::c_int = 0x2000_0000;
    let mut flags = 0 as libc::c_int;
    // SAFETY: the held FD is live and the request writes to this int only.
    let result = unsafe { libc::ioctl(directory.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
    (result == 0).then_some(flags & FS_PROJINHERIT != 0)
}

/// Linux fs/stat.c vfs_statx_path reports the mount containing the held object;
/// AT_EMPTY_PATH performs no path traversal. mm/shmem.c shmem_get_tree uses
/// get_tree_nodev; fs/super.c set_anon_super allocates a unique live s_dev.
/// Sources: https://github.com/torvalds/linux/blob/v6.12/fs/stat.c
/// https://github.com/torvalds/linux/blob/v6.12/fs/super.c
fn statx_mount_id(directory: &File, space: &DirectorySpace) -> Option<u64> {
    // libc does not expose statx on all supported musl targets. These are the
    // architecture-independent Linux UAPI masks and 256-byte structure.
    let mut raw = MaybeUninit::<KernelStatx>::zeroed();
    let mask = 0x1000 | 0x0100 | 0x0001; // MNT_ID | INO | TYPE
    // SAFETY: live FD, empty C path and writable correctly sized statx buffer.
    let result = unsafe {
        libc::syscall(
            libc::SYS_statx,
            directory.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            mask,
            raw.as_mut_ptr(),
        )
    };
    if result != 0 {
        return None;
    }
    // SAFETY: successful statx initialized the requested fields and mask.
    let raw = unsafe { raw.assume_init() };
    (raw.stx_mask & mask == mask
        && u32::from(raw.stx_mode) & libc::S_IFMT == libc::S_IFDIR
        && raw.stx_ino == space.inode
        && raw.stx_dev_major == libc::major(space.device)
        && raw.stx_dev_minor == libc::minor(space.device)
        && raw.stx_mnt_id != 0)
        .then_some(raw.stx_mnt_id)
}

// include/uapi/linux/stat.h. The reserved tail retains all kernel output space,
// including fields added after stx_mnt_id which this observer does not request.
#[repr(C)]
struct KernelStatxTimestamp {
    seconds: i64,
    nanoseconds: u32,
    reserved: i32,
}
#[repr(C)]
struct KernelStatx {
    stx_mask: u32,
    block_size: u32,
    attributes: u64,
    links: u32,
    uid: u32,
    gid: u32,
    stx_mode: u16,
    reserved0: u16,
    stx_ino: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    timestamps: [KernelStatxTimestamp; 4],
    rdev_major: u32,
    rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    reserved_tail: [u8; 104],
}
const _: () = assert!(std::mem::size_of::<KernelStatx>() == 256);
const _: () = assert!(std::mem::offset_of!(KernelStatx, stx_mode) == 28);
const _: () = assert!(std::mem::offset_of!(KernelStatx, stx_ino) == 32);
const _: () = assert!(std::mem::offset_of!(KernelStatx, stx_dev_major) == 136);
const _: () = assert!(std::mem::offset_of!(KernelStatx, stx_mnt_id) == 144);
fn read_proc(path: &str, limit: usize) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("bounded proc observation exceeded"));
    }
    String::from_utf8(bytes).map_err(|_| io::Error::other("invalid proc observation"))
}
fn parse_mount_id(fdinfo: &str) -> Option<u64> {
    let mut matches = fdinfo
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:"));
    let id = matches.next()?.trim().parse::<u64>().ok()?;
    if id == 0 || matches.next().is_some() {
        None
    } else {
        Some(id)
    }
}
fn verify_mount(table: &str, id: u64, device: u64, filesystem: AllocationFilesystem) -> bool {
    if table.len() > MAX_PROC_BYTES || table.lines().count() > MAX_MOUNTS {
        return false;
    }
    let mut found = false;
    for line in table.lines() {
        if line.len() > 16384 {
            return false;
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.first().and_then(|v| v.parse::<u64>().ok()) != Some(id) {
            continue;
        }
        if found || fields.len() < 10 {
            return false;
        }
        found = true;
        let Some((major, minor)) = fields[2].split_once(':') else {
            return false;
        };
        if major.parse::<u32>().ok() != Some(libc::major(device))
            || minor.parse::<u32>().ok() != Some(libc::minor(device))
        {
            return false;
        }
        let Some(separator) = fields
            .iter()
            .position(|field| *field == "-")
            .filter(|index| *index >= 6)
        else {
            return false;
        };
        let Some(kind) = fields.get(separator + 1) else {
            return false;
        };
        if !matches!(
            (filesystem, *kind),
            (AllocationFilesystem::Ext, "ext2" | "ext3" | "ext4")
                | (AllocationFilesystem::Xfs, "xfs")
                | (AllocationFilesystem::Tmpfs, "tmpfs")
        ) {
            return false;
        }
        if fields.len() != separator + 4 {
            return false;
        }
    }
    found
}

// Linux UAPI include/uapi/linux/quota.h if_dqinfo, identical on supported 64-bit
// x86_64/aarch64 ABIs. Q_GETINFO never mutates quota configuration.
#[repr(C)]
#[derive(Default)]
struct QuotaInfo {
    block_grace: u64,
    inode_grace: u64,
    flags: u32,
    valid: u32,
}
fn observe_quota(directory: &File, kind: libc::c_int) -> QuotaObservation {
    // Modern tmpfs can enable user/group quotas (mm/shmem.c shmem_fill_super).
    // Do not infer their absence from tmpfs type or missing mount option text.
    // An unsupported type/syscall or denied query remains unknown, including
    // project quotas on kernels which do not implement that tmpfs quota type.
    let mut info = QuotaInfo::default();
    // SAFETY: FD remains live; Q_GETINFO takes this fixed writable if_dqinfo
    // structure, a quota type in 0..3, and ignores the numeric ID.
    let result = unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            directory.as_raw_fd(),
            libc::QCMD(libc::Q_GETINFO, kind),
            0,
            &mut info as *mut QuotaInfo,
        )
    };
    quota_result(
        result,
        if result < 0 {
            io::Error::last_os_error().raw_os_error()
        } else {
            None
        },
    )
}
fn quota_result(result: libc::c_long, error: Option<i32>) -> QuotaObservation {
    // fs/quota/quota.c quota_getinfo returns ESRCH only when this type's
    // QCI_ACCT_ENABLED is absent. ENOSYS/EINVAL/denials do not establish it.
    if result == 0 {
        QuotaObservation::Enabled
    } else if result == -1 && error == Some(libc::ESRCH) {
        QuotaObservation::Disabled
    } else {
        QuotaObservation::Unknown
    }
}

/// The caller supplies the complete, bounded, measured phase inventory. There
/// are no default startup, metadata, queue or manager-overhead numbers here.
/// Persisted observations are not authority; collect fresh ones at apply.
pub fn assess_allocation(
    observations: &[AllocationObservation],
    phases: &[PhaseBudget],
) -> Result<DiskAssessment, DiskBudgetError> {
    if observations.is_empty() || observations.len() > 16 {
        return Err(DiskBudgetError::InvalidBudget);
    }
    if observations.iter().enumerate().any(|(index, observation)| {
        observations[..index].iter().any(|other| {
            (other.space.device == observation.space.device
                && other.filesystem != observation.filesystem)
                || (other.mount_id.is_some()
                    && other.mount_id == observation.mount_id
                    && other.space.device != observation.space.device)
        })
    }) {
        return Ok(DiskAssessment {
            state: super::DiskBudgetState::Unknown,
            reasons: vec![super::DiskBudgetReason::ConflictingPoolEvidence],
            pools: Vec::new(),
        });
    }
    // Contradictory observations of a device cannot establish separate pools.
    // Group only comparable filesystem-wide counters. A project-scoped ext
    // observation still supports its own destination check, but must not
    // constrain the sum for other directories on the same physical device.
    let mut devices = Vec::new();
    let destinations: Vec<_> = observations
        .iter()
        .map(|observation| {
            let coherent = !observations.iter().any(|other| {
                other.space.device == observation.space.device
                    && other.filesystem != observation.filesystem
            });
            let pool = if observation.counters_share_pool() && coherent {
                let index = if let Some(index) = devices
                    .iter()
                    .position(|device| *device == observation.space.device)
                {
                    index
                } else {
                    devices.push(observation.space.device);
                    devices.len() - 1
                };
                Some(index as u32)
            } else {
                None
            };
            DestinationBudget {
                space: observation.space,
                pool,
                quota: if observation.proven_pool()
                    && observation.quotas == [QuotaObservation::Disabled; 3]
                {
                    QuotaEvidence::VerifiedAbsent
                } else {
                    QuotaEvidence::Unknown
                },
            }
        })
        .collect();
    assess_budget(&destinations, phases)
}

/// Conservative, known package-publication minimum in [program,state,service]
/// order. Actual member bytes and program/service inode counts can prove a
/// shortage, but this function NEVER proves sufficiency: pointer, metadata,
/// control/state, queue, enablement and runtime peaks remain unmeasured.
/// The already-held archive is not charged again; a new copy belongs in the
/// caller's actual measured inventory if that implementation creates one.
pub fn assess_publication_lower_bound(
    observations: &[AllocationObservation; 3],
    package: &PackageDiskInputs,
) -> Result<DiskAssessment, DiskBudgetError> {
    // Ext inline-data can place small contents in already allocated inode space.
    // Deduct a whole accounting fragment per file, rather than treating all
    // logical bytes as necessarily new allocation. Unsupported allocators have
    // no byte/inode minimum here (e.g. compression and stacked filesystems).
    let lower_bound = |observation: &AllocationObservation,
                       lengths: &[u64],
                       inodes: u64|
     -> Result<AllocationCharge, DiskBudgetError> {
        if !observation.proven_pool() {
            return Ok(AllocationCharge::UNKNOWN);
        }
        let bytes = match observation.space.fragment_bytes.filter(|unit| *unit != 0) {
            Some(unit) => Some(
                lengths
                    .iter()
                    .try_fold(0_u64, |sum, length| {
                        sum.checked_add(length.saturating_sub(unit))
                    })
                    .ok_or(DiskBudgetError::ArithmeticOverflow)?,
            ),
            None => None,
        };
        Ok(AllocationCharge {
            bytes,
            inodes: Some(inodes),
        })
    };
    let minimum = PhaseBudget {
        charges: vec![
            lower_bound(&observations[0], &package.program_files, 9)?, // four dirs + four members + current.json
            AllocationCharge::ZERO,
            lower_bound(&observations[2], &[package.service_file], 1)?,
        ],
    };
    let unknown = PhaseBudget {
        charges: vec![AllocationCharge::UNKNOWN; 3],
    };
    assess_allocation(observations, &[minimum, unknown])
}

#[cfg(test)]
#[path = "allocation_admission/tests.rs"]
mod tests;
