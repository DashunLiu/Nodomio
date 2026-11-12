//! Reconcile a possible registration using its protected original journal marker.

use super::{
    control_record::{ControlPhase, ControlRecord, ControlRecordError, read_record},
    plan_store::{check_directory, effective_uid, open_at, same_inode, stat},
    registration::{RegistrationError, recover_registration},
};
use crate::protocol::AgentIdentity;
use std::{fs::File, os::fd::AsRawFd, path::Path, time::Duration};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RegistrationRecoveryError {
    Control(ControlRecordError),
    ControlChanged,
    InvalidPhase,
    InvalidState,
    Identity(RegistrationError),
}

/// The caller holds the original dual execution lease and has freshly pinned
/// the fixed control and state directories. It establishes old-work drainage
/// and validates any required release/source facts before using this proof.
/// This function only performs the original credential's identity GET. It
/// never advances the operation journal or starts a service.
pub(super) fn recover_original_registration(
    control: &File,
    expected: &ControlRecord,
    state: &File,
    explicit_ca: Option<&[u8]>,
    timeout: Duration,
) -> Result<AgentIdentity, RegistrationRecoveryError> {
    let current = read_record(control).map_err(RegistrationRecoveryError::Control)?;
    if &current != expected {
        return Err(RegistrationRecoveryError::ControlChanged);
    }
    if current.phase() != ControlPhase::Ready {
        return Err(RegistrationRecoveryError::InvalidPhase);
    }
    let identity_operation_id = current
        .business()
        .and_then(|business| business.pending_registration_id())
        .ok_or(RegistrationRecoveryError::InvalidPhase)?;

    let owner = effective_uid();
    check_directory(state, owner).map_err(|_| RegistrationRecoveryError::InvalidState)?;
    let control_stat = stat(control, None).map_err(|_| RegistrationRecoveryError::InvalidState)?;
    let state_stat = stat(state, None).map_err(|_| RegistrationRecoveryError::InvalidState)?;
    if same_inode(&control_stat, &state_stat) {
        return Err(RegistrationRecoveryError::InvalidState);
    }
    let identity = open_at(state, c"identity", libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|_| RegistrationRecoveryError::InvalidState)?;
    check_directory(&identity, owner).map_err(|_| RegistrationRecoveryError::InvalidState)?;
    let identity_stat =
        stat(&identity, None).map_err(|_| RegistrationRecoveryError::InvalidState)?;
    if same_inode(&identity_stat, &state_stat) || same_inode(&identity_stat, &control_stat) {
        return Err(RegistrationRecoveryError::InvalidState);
    }
    check_named_identity(state, &identity_stat)?;

    // The final dot lets IdentityStore independently open the pinned directory
    // with O_NOFOLLOW. Replacing the state child cannot redirect that open.
    let path = format!("/proc/self/fd/{}/.", identity.as_raw_fd());
    let observed = recover_registration(
        Path::new(&path),
        &current.claim().target,
        identity_operation_id,
        explicit_ca,
        timeout,
    )
    .map_err(RegistrationRecoveryError::Identity)?;

    if read_record(control).map_err(RegistrationRecoveryError::Control)? != current {
        return Err(RegistrationRecoveryError::ControlChanged);
    }
    check_directory(state, owner).map_err(|_| RegistrationRecoveryError::InvalidState)?;
    check_directory(&identity, owner).map_err(|_| RegistrationRecoveryError::InvalidState)?;
    check_named_identity(state, &identity_stat)?;
    Ok(observed)
}

fn check_named_identity(
    state: &File,
    identity: &libc::stat,
) -> Result<(), RegistrationRecoveryError> {
    if !stat(state, Some(c"identity")).is_ok_and(|named| same_inode(&named, identity)) {
        return Err(RegistrationRecoveryError::InvalidState);
    }
    Ok(())
}
