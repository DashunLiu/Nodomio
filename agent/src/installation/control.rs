use super::{
    LayoutEntry,
    control_record::{ControlPhase, ControlRecord, read_record},
    layout::{CONTROL_NAME, open_root, state_parent},
    operation_journal::{InstallOperationResult, result_by_id},
    plan::valid_plan_id,
    plan_store::{check_directory, check_file, effective_uid, open_at, same_inode, stat},
};
use crate::identity::uuid;
use std::{ffi::CStr, fs::File, io::ErrorKind};

pub(super) const LOCK_NAME: &CStr = c"execution.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallControlObservation {
    Missing,
    Unavailable,
    Unsafe,
    RecoveryRequired,
    /// Control preparation is recorded and the lock has the expected shape.
    /// The original intent remains pending until the operation owner settles it.
    Prepared,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallPreparationLookup {
    /// Only the original control preparation is known. It is not business acceptance.
    Original {
        operation_id: String,
        control: InstallControlObservation,
    },
    ConflictingConfirmation,
    OtherPendingIntent,
    InvalidConfirmation,
    Unavailable(InstallControlObservation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallStatusError {
    InvalidInput,
    PermissionDenied,
    NotFound,
    RecoveryRequired,
}

/// Read the original result from the fixed control location. Pending work is
/// reported as UNKNOWN unless an executor can prove it is still active.
pub fn lookup_install_operation(
    operation_id: &str,
    target_id: &str,
) -> Result<InstallOperationResult, InstallStatusError> {
    use InstallStatusError::*;
    if !uuid(operation_id) || !uuid(target_id) {
        return Err(InvalidInput);
    }
    if effective_uid() != 0 {
        return Err(PermissionDenied);
    }
    let root = open_root().map_err(|_| RecoveryRequired)?;
    let (record, _) = read_at(&root, 0).map_err(|observation| match observation {
        InstallControlObservation::Missing => NotFound,
        _ => RecoveryRequired,
    })?;
    result_by_id(&record, operation_id, target_id)
        .map_err(|_| RecoveryRequired)?
        .ok_or(NotFound)
}

/// Inspect the fixed control location without acquiring a lease or writing files.
pub fn inspect_install_control() -> InstallControlObservation {
    match open_root() {
        Ok(root) => inspect_at(&root, 0),
        Err(status) => path_status(status),
    }
}

/// Read back an original preparation using its exact confirmation and UUID key.
/// An expired plan does not change the preparation record or allow a new begin.
pub fn lookup_install_preparation(
    idempotency_key: &str,
    plan_id: &str,
    installation_id: &str,
    digest: &str,
) -> InstallPreparationLookup {
    match open_root() {
        Ok(root) => lookup_at(&root, 0, idempotency_key, plan_id, installation_id, digest),
        Err(status) => InstallPreparationLookup::Unavailable(path_status(status)),
    }
}

pub(super) fn lookup_at(
    root: &File,
    owner: libc::uid_t,
    idempotency_key: &str,
    plan_id: &str,
    installation_id: &str,
    digest: &str,
) -> InstallPreparationLookup {
    use InstallPreparationLookup::*;
    if !uuid(idempotency_key)
        || !valid_plan_id(plan_id)
        || !valid_plan_id(installation_id)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return InvalidConfirmation;
    }
    let (record, control) = match read_at(root, owner) {
        Ok(observed) => observed,
        Err(status) => return Unavailable(status),
    };
    let claim = record.claim();
    if !claim.idempotency_key.eq_ignore_ascii_case(idempotency_key) {
        return OtherPendingIntent;
    }
    if claim.plan_id != plan_id
        || claim.installation_id != installation_id
        || claim.plan_digest != digest
    {
        return ConflictingConfirmation;
    }
    Original {
        operation_id: claim.operation_id.clone(),
        control,
    }
}

fn path_status(status: LayoutEntry) -> InstallControlObservation {
    match status {
        LayoutEntry::Unsafe => InstallControlObservation::Unsafe,
        _ => InstallControlObservation::Unavailable,
    }
}

pub(super) fn inspect_at(root: &File, owner: libc::uid_t) -> InstallControlObservation {
    match read_at(root, owner) {
        Ok((_, status)) | Err(status) => status,
    }
}

fn read_at(
    root: &File,
    owner: libc::uid_t,
) -> Result<(ControlRecord, InstallControlObservation), InstallControlObservation> {
    use InstallControlObservation::*;
    let parent = match state_parent(root, owner) {
        Ok(parent) => parent,
        Err(status) => return Err(path_status(status)),
    };
    let directory = match open_at(&parent, CONTROL_NAME, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(directory) => directory,
        Err(error) if error.kind() == ErrorKind::NotFound => return Err(Missing),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {
            return Err(Unsafe);
        }
        Err(_) => return Err(Unavailable),
    };
    if check_directory(&directory, owner).is_err() {
        return Err(Unsafe);
    }
    let Ok(record) = read_record(&directory) else {
        return Err(RecoveryRequired);
    };
    if !is_named_control(&parent, &directory) || check_directory(&directory, owner).is_err() {
        return Err(RecoveryRequired);
    }
    let status =
        if record.phase() == ControlPhase::Ready && lock_identity(&directory, owner).is_some() {
            Prepared
        } else {
            RecoveryRequired
        };
    Ok((record, status))
}

pub(super) fn is_named_control(parent: &File, directory: &File) -> bool {
    match (stat(parent, Some(CONTROL_NAME)), stat(directory, None)) {
        (Ok(named), Ok(opened)) => same_inode(&named, &opened),
        _ => false,
    }
}

pub(super) fn lock_identity(directory: &File, owner: libc::uid_t) -> Option<(u64, u64)> {
    let metadata = stat(directory, Some(LOCK_NAME)).ok()?;
    check_file(&metadata, owner).ok()?;
    Some((metadata.st_dev, metadata.st_ino))
}
