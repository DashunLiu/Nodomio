//! Fixed local state prepared under the original install's execution lease.

use super::{
    InstallUpdateMode, MAX_SERVICE_SETTINGS_BYTES,
    layout::state_parent,
    plan_store::{check_directory, check_file, open_at, same_inode, stat},
    staging::{
        PublicationError, create_directory, create_file, open_private_directory,
        verify_private_bytes,
    },
};
use crate::{execution::Locked, identity::Target};
use std::{
    ffi::CStr,
    fs::{File, Permissions, read_dir},
    io::Write,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::PathBuf,
};

pub(super) struct InstallState {
    root: File,
    pub(super) health: File,
}

impl InstallState {
    pub(super) fn directory(&self) -> &File {
        &self.root
    }

    /// Valid only while this owner retains the anchor. IdentityStore opens the
    /// final private directory with no-follow and holds its own independent lock.
    pub(super) fn identity_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}/identity", self.root.as_raw_fd()))
    }
}

/// Called after the state/instance-lock creation marker. No retry may call
/// this constructor after the marker: any existing name is recovery evidence.
pub(super) fn prepare_install_state(
    root: &File,
    control: &File,
    owner: libc::uid_t,
    target: &Target,
    update_mode: InstallUpdateMode,
    ca: Option<&[u8]>,
) -> Result<InstallState, PublicationError> {
    if let Some(ca) = ca {
        super::validate_service_ca(ca).map_err(|_| PublicationError::InvalidContext)?;
    }
    let settings = service_settings(target, true)?;
    let update = update_settings(update_mode)?;
    let parent = state_parent(root, owner).map_err(|_| PublicationError::InvalidContext)?;
    let parent = open_at(&parent, c".", libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(super::staging::io_error)?;
    check_directory(control, owner).map_err(|_| PublicationError::InvalidContext)?;
    let state = create_directory(&parent, c"nodomi-agent")?;
    let identity = create_directory(&state, c"identity")?;
    let runtime = create_directory(&state, c"runtime")?;
    let ssh = create_directory(&state, c"ssh-queue")?;
    let health = create_directory(&state, c"health")?;
    write_private(&state, c"service.json", &settings)?;
    write_private(&state, c"update-mode.json", &update)?;
    if let Some(ca) = ca {
        write_private(&state, c"ca.pem", ca)?;
    }
    for directory in [&identity, &runtime, &ssh, &health, &state, &parent] {
        directory.sync_all().map_err(super::staging::io_error)?;
    }
    write_private(control, c"supervisor.lock", b"")?;
    control.sync_all().map_err(super::staging::io_error)?;
    Ok(InstallState {
        root: state,
        health,
    })
}

/// Reopen only the original pre-service state. Never create or repair a name.
pub(super) fn reopen_registration_state(
    root: &File,
    control: &File,
    owner: libc::uid_t,
    target: &Target,
    update_mode: InstallUpdateMode,
    ca: &[u8],
) -> Result<InstallState, PublicationError> {
    reopen_state(root, control, owner, target, update_mode, ca, false).map(|(state, _guard)| state)
}

pub(super) fn reopen_service_start_state(
    root: &File,
    control: &File,
    owner: libc::uid_t,
    target: &Target,
    update_mode: InstallUpdateMode,
    ca: &[u8],
) -> Result<(InstallState, Locked), PublicationError> {
    reopen_state(root, control, owner, target, update_mode, ca, true)
}

fn reopen_state(
    root: &File,
    control: &File,
    owner: libc::uid_t,
    target: &Target,
    update_mode: InstallUpdateMode,
    ca: &[u8],
    service_may_have_started: bool,
) -> Result<(InstallState, Locked), PublicationError> {
    super::validate_service_ca(ca).map_err(|_| PublicationError::InvalidContext)?;
    let lock =
        open_at(control, c"supervisor.lock", libc::O_RDONLY).map_err(super::staging::io_error)?;
    let lock_metadata = stat(&lock, None).map_err(super::staging::io_error)?;
    if check_file(&lock_metadata, owner).ok() != Some(0) {
        return Err(PublicationError::Conflict);
    }
    let guard = Locked::acquire(lock).map_err(|_| PublicationError::Conflict)?;
    let parent = state_parent(root, owner).map_err(|_| PublicationError::InvalidContext)?;
    let state = open_private_directory(&parent, c"nodomi-agent", owner)?;
    let runtime = open_private_directory(&state, c"runtime", owner)?;
    let ssh = open_private_directory(&state, c"ssh-queue", owner)?;
    let health = open_private_directory(&state, c"health", owner)?;
    let empty_directories: &[&File] = if service_may_have_started {
        &[&ssh]
    } else {
        &[&runtime, &ssh, &health]
    };
    for directory in empty_directories {
        let mut entries = read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(super::staging::io_error)?;
        if entries.next().is_some() {
            return Err(PublicationError::Conflict);
        }
    }
    verify_private_bytes(
        &state,
        c"service.json",
        owner,
        &service_settings(target, true)?,
    )
    .or_else(|error| {
        if !matches!(
            error,
            PublicationError::Conflict | PublicationError::InvalidContext
        ) {
            return Err(error);
        }
        // Existing exact plans may own the pre-window settings bytes.
        verify_private_bytes(
            &state,
            c"service.json",
            owner,
            &service_settings(target, false)?,
        )
    })?;
    verify_private_bytes(
        &state,
        c"update-mode.json",
        owner,
        &update_settings(update_mode)?,
    )?;
    verify_private_bytes(&state, c"ca.pem", owner, ca)?;
    let opened = stat(&state, None).map_err(super::staging::io_error)?;
    if !stat(&parent, Some(c"nodomi-agent")).is_ok_and(|named| same_inode(&opened, &named))
        || !stat(control, Some(c"supervisor.lock")).is_ok_and(|named| {
            same_inode(&lock_metadata, &named) && check_file(&named, owner).ok() == Some(0)
        })
    {
        return Err(PublicationError::Conflict);
    }
    Ok((
        InstallState {
            root: state,
            health,
        },
        guard,
    ))
}

fn service_settings(
    target: &Target,
    require_startup_window: bool,
) -> Result<Vec<u8>, PublicationError> {
    let mut settings = serde_json::json!({
        "managementOrigin": target.origin,
        "expectedServerId": target.expected_server_id,
    });
    if require_startup_window {
        settings["startupWindowRequired"] = serde_json::Value::Bool(true);
    }
    let bytes = serde_json::to_vec(&settings).map_err(|_| PublicationError::InvalidContext)?;
    if bytes.len() > MAX_SERVICE_SETTINGS_BYTES {
        return Err(PublicationError::InvalidContext);
    }
    Ok(bytes)
}

fn update_settings(update_mode: InstallUpdateMode) -> Result<Vec<u8>, PublicationError> {
    serde_json::to_vec(&serde_json::json!({"updateMode": update_mode}))
        .map_err(|_| PublicationError::InvalidContext)
}

fn write_private(directory: &File, name: &CStr, bytes: &[u8]) -> Result<(), PublicationError> {
    let mut file = create_file(directory, name)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all())
        .map_err(super::staging::io_error)?;
    let owner = super::plan_store::effective_uid();
    let opened = stat(&file, None).map_err(super::staging::io_error)?;
    if opened.st_mode & libc::S_IFMT != libc::S_IFREG
        || opened.st_uid != owner
        || opened.st_nlink != 1
        || opened.st_mode & 0o7777 != 0o600
        || u64::try_from(opened.st_size).ok() != Some(bytes.len() as u64)
    {
        return Err(PublicationError::InvalidContext);
    }
    if !stat(directory, Some(name)).is_ok_and(|named| same_inode(&opened, &named)) {
        return Err(PublicationError::CommitUnknown);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn oversized_service_settings_are_rejected_before_state_creation() {
        let fixture = tempfile::tempdir().unwrap();
        let root_path = fixture.path();
        let control_path = root_path.join("control");
        fs::create_dir(&control_path).unwrap();
        fs::set_permissions(&control_path, Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(root_path.join("var/lib")).unwrap();
        let root = File::open(root_path).unwrap();
        let control = File::open(&control_path).unwrap();
        let owner = super::super::plan_store::effective_uid();
        let target =
            Target::new(&format!("https://{}invalid", "a.".repeat(2048)), "server-1").unwrap();

        assert!(matches!(
            prepare_install_state(
                &root,
                &control,
                owner,
                &target,
                InstallUpdateMode::Manual,
                None,
            ),
            Err(PublicationError::InvalidContext)
        ));
        assert!(!root_path.join("var/lib/nodomi-agent").exists());
        assert_eq!(fs::read_dir(control_path).unwrap().count(), 0);
    }
}
