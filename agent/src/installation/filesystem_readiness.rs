//! Read-only filesystem facts for the fixed first-install parents.
use super::layout::{LayoutEntry, open_root, program_parent, state_parent};
use serde::{Deserialize, Serialize};
use std::{fs::File, mem::MaybeUninit, os::fd::AsRawFd};

/// Mount observations for /opt and /var/lib. The latter is the shared parent
/// for the new state and control directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallFilesystemReadiness {
    pub program_parent: FilesystemObservation,
    pub state_parent: FilesystemObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FilesystemObservation {
    Observed {
        /// statvfs blocks available outside the privileged reserve, in bytes.
        /// This observation does not establish the complete install budget.
        available_bytes: Option<u64>,
        read_only: bool,
        no_exec: bool,
    },
    Unsafe,
    Unavailable,
}

/// Observe the trusted fixed parents without testing writes or reserving space.
pub fn inspect_filesystem_readiness() -> InstallFilesystemReadiness {
    match open_root() {
        Ok(root) => inspect_at(&root, 0),
        Err(status) => InstallFilesystemReadiness {
            program_parent: inaccessible(status),
            state_parent: inaccessible(status),
        },
    }
}

pub(super) fn inspect_at(root: &File, owner: libc::uid_t) -> InstallFilesystemReadiness {
    InstallFilesystemReadiness {
        program_parent: observe(program_parent(root, owner)),
        state_parent: observe(state_parent(root, owner)),
    }
}

fn inaccessible(status: LayoutEntry) -> FilesystemObservation {
    if status == LayoutEntry::Unsafe {
        FilesystemObservation::Unsafe
    } else {
        FilesystemObservation::Unavailable
    }
}

fn observe(directory: Result<File, LayoutEntry>) -> FilesystemObservation {
    let directory = match directory {
        Ok(directory) => directory,
        Err(status) => return inaccessible(status),
    };
    let mut output = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the directory is pinned and output points to writable statvfs storage.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), output.as_mut_ptr()) } != 0 {
        return FilesystemObservation::Unavailable;
    }
    // SAFETY: successful fstatvfs initialized the output.
    let output = unsafe { output.assume_init() };
    mount_observation(
        u128::from(output.f_bavail),
        u128::from(output.f_frsize),
        output.f_flag,
    )
}

fn mount_observation(
    available_fragments: u128,
    fragment_bytes: u128,
    flags: libc::c_ulong,
) -> FilesystemObservation {
    let available_bytes = if fragment_bytes == 0 {
        None
    } else {
        available_fragments
            .checked_mul(fragment_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok())
    };
    FilesystemObservation::Observed {
        available_bytes,
        read_only: flags & libc::ST_RDONLY != 0,
        no_exec: flags & libc::ST_NOEXEC != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
    };

    fn directory(path: &Path, mode: u32) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn owner() -> libc::uid_t {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn reads_both_pinned_filesystems_without_creating_install_entries() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        for name in ["", "opt", "var", "var/lib"] {
            directory(&root.join(name), 0o755);
        }
        fs::write(root.join("var/lib/canary"), b"unchanged").unwrap();
        let anchored = File::open(&root).unwrap();
        let moved = temporary.path().join("moved");
        fs::rename(&root, &moved).unwrap();
        directory(&root, 0o755);

        let observed = inspect_at(&anchored, owner());
        for parent in [observed.program_parent, observed.state_parent] {
            assert!(
                matches!(
                    parent,
                    FilesystemObservation::Observed {
                        available_bytes: Some(_),
                        read_only: false,
                        ..
                    }
                ),
                "{parent:?}"
            );
        }
        assert_eq!(
            fs::read(moved.join("var/lib/canary")).unwrap(),
            b"unchanged"
        );
        assert_eq!(fs::read_dir(moved.join("opt")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(moved.join("var/lib")).unwrap().count(), 1);
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
    }

    #[test]
    fn unavailable_and_unsafe_parents_are_distinguished() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        directory(&root, 0o755);
        directory(&root.join("var"), 0o755);
        let outside = temporary.path().join("outside");
        directory(&outside, 0o755);
        fs::write(outside.join("canary"), b"outside unchanged").unwrap();
        symlink(&outside, root.join("opt")).unwrap();
        let anchored = File::open(&root).unwrap();

        assert_eq!(
            inspect_at(&anchored, owner()),
            InstallFilesystemReadiness {
                program_parent: FilesystemObservation::Unsafe,
                state_parent: FilesystemObservation::Unavailable,
            },
        );
        directory(&root.join("var/lib"), 0o775);
        assert_eq!(
            inspect_at(&anchored, owner()).state_parent,
            FilesystemObservation::Unsafe
        );
        assert_eq!(
            fs::read(outside.join("canary")).unwrap(),
            b"outside unchanged"
        );
    }

    #[test]
    fn preserves_read_only_and_unknown_capacity_facts_independently() {
        assert_eq!(
            mount_observation(3, 4096, libc::ST_RDONLY | libc::ST_NOSUID),
            FilesystemObservation::Observed {
                available_bytes: Some(12_288),
                read_only: true,
                no_exec: false,
            },
        );
        assert_eq!(
            mount_observation(0, 4096, libc::ST_NOEXEC),
            FilesystemObservation::Observed {
                available_bytes: Some(0),
                read_only: false,
                no_exec: true,
            },
        );
        for (blocks, unit) in [(1, 0), (u128::from(u64::MAX), 2), (u128::MAX, 2)] {
            assert_eq!(
                mount_observation(blocks, unit, libc::ST_RDONLY),
                FilesystemObservation::Observed {
                    available_bytes: None,
                    read_only: true,
                    no_exec: false,
                },
            );
        }
    }
}
