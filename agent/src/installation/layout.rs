use std::{
    ffi::CStr,
    fs::File,
    io,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::MetadataExt,
    },
};

pub(super) const CONTROL_NAME: &CStr = c"nodomi-agent-control";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LayoutEntry {
    /// The name is absent under its verified parent directory.
    Missing,
    /// The directory metadata meets the ownership and permission checks.
    Present,
    /// The path contains an unexpected type, owner or writable permissions.
    Unsafe,
    /// A protected parent is missing, or its metadata could not be read.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallLayout {
    pub program: LayoutEntry,
    pub state: LayoutEntry,
    pub control: LayoutEntry,
}

/// Inspect only the three fixed Linux installation directory entries.
pub fn inspect_layout() -> InstallLayout {
    match open_root() {
        Ok(root) => inspect_at(&root, 0),
        Err(status) => uniform(status),
    }
}

pub(super) fn open_root() -> Result<File, LayoutEntry> {
    open_directory(libc::AT_FDCWD, c"/")
}

fn uniform(status: LayoutEntry) -> InstallLayout {
    InstallLayout {
        program: status,
        state: status,
        control: status,
    }
}

pub(super) fn inspect_at(root: &File, owner: libc::uid_t) -> InstallLayout {
    if let Err(status) = check_directory(root, owner) {
        return uniform(status);
    }
    let program = match program_parent(root, owner) {
        Ok(opt) => inspect_entry(&opt, c"nodomi-agent", owner, None),
        Err(status) => status,
    };
    let lib = state_parent(root, owner);
    let (state, control) = match lib {
        Ok(lib) => (
            inspect_entry(&lib, c"nodomi-agent", owner, None),
            inspect_entry(&lib, CONTROL_NAME, owner, Some(0o700)),
        ),
        Err(status) => (status, status),
    };
    InstallLayout {
        program,
        state,
        control,
    }
}

pub(super) fn program_parent(root: &File, owner: libc::uid_t) -> Result<File, LayoutEntry> {
    check_directory(root, owner)?;
    trusted_child(root, c"opt", owner)
}

pub(super) fn state_parent(root: &File, owner: libc::uid_t) -> Result<File, LayoutEntry> {
    check_directory(root, owner)?;
    trusted_child(root, c"var", owner).and_then(|var| trusted_child(&var, c"lib", owner))
}

fn open_directory(base: RawFd, name: &CStr) -> Result<File, LayoutEntry> {
    // SAFETY: base is a held directory descriptor or AT_FDCWD and name is NUL-terminated.
    // The flags do not request creation, and O_PATH only opens a metadata handle.
    let fd = unsafe {
        libc::openat(
            base,
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(match io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOTDIR | libc::ELOOP) => LayoutEntry::Unsafe,
            _ => LayoutEntry::Unavailable,
        });
    }
    // SAFETY: successful openat returned a new, uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn trusted_child(parent: &File, name: &CStr, owner: libc::uid_t) -> Result<File, LayoutEntry> {
    let child = open_directory(parent.as_raw_fd(), name)?;
    check_directory(&child, owner)?;
    Ok(child)
}

fn check_directory(directory: &File, owner: libc::uid_t) -> Result<(), LayoutEntry> {
    let metadata = directory.metadata().map_err(|_| LayoutEntry::Unavailable)?;
    if trusted_metadata(metadata.mode(), metadata.uid(), owner) {
        Ok(())
    } else {
        Err(LayoutEntry::Unsafe)
    }
}

fn trusted_metadata(mode: libc::mode_t, uid: libc::uid_t, owner: libc::uid_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFDIR && uid == owner && mode & 0o022 == 0
}

fn inspect_entry(
    parent: &File,
    name: &CStr,
    owner: libc::uid_t,
    required_mode: Option<libc::mode_t>,
) -> LayoutEntry {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent is held, name is NUL-terminated and stat is writable.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return match io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) => LayoutEntry::Missing,
            _ => LayoutEntry::Unavailable,
        };
    }
    // SAFETY: successful fstatat initialized the output structure.
    let stat = unsafe { stat.assume_init() };
    if trusted_metadata(stat.st_mode, stat.st_uid, owner)
        && required_mode.is_none_or(|mode| stat.st_mode & 0o7777 == mode)
    {
        LayoutEntry::Present
    } else {
        LayoutEntry::Unsafe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
    };

    const CANARY: &[u8] = b"fixture contents must not change";

    struct Fixture {
        temporary: tempfile::TempDir,
        root: File,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root_path = temporary.path().join("root");
            for name in ["", "opt", "var", "var/lib"] {
                make_dir(&root_path.join(name), 0o755);
            }
            let root = File::open(root_path).unwrap();
            Self { temporary, root }
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.temporary.path().join("root").join(relative)
        }

        fn inspect(&self) -> InstallLayout {
            inspect_at(&self.root, uid())
        }
    }

    fn make_dir(path: &Path, mode: u32) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn uid() -> libc::uid_t {
        // SAFETY: geteuid takes no arguments and has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn layout(program: LayoutEntry, state: LayoutEntry, control: LayoutEntry) -> InstallLayout {
        InstallLayout {
            program,
            state,
            control,
        }
    }

    use LayoutEntry::*;

    #[test]
    fn reports_missing_and_present_without_creating_or_changing_contents() {
        let fixture = Fixture::new();
        assert_eq!(fixture.inspect(), layout(Missing, Missing, Missing));
        for parent in ["opt", "var/lib"] {
            assert_eq!(fs::read_dir(fixture.path(parent)).unwrap().count(), 0);
        }

        for name in [
            "opt/nodomi-agent",
            "var/lib/nodomi-agent",
            "var/lib/nodomi-agent-control",
        ] {
            let directory = fixture.path(name);
            make_dir(&directory, 0o700);
            fs::write(directory.join("canary"), CANARY).unwrap();
        }
        assert_eq!(fixture.inspect(), layout(Present, Present, Present));
        for name in [
            "opt/nodomi-agent",
            "var/lib/nodomi-agent",
            "var/lib/nodomi-agent-control",
        ] {
            let directory = fixture.path(name);
            assert_eq!(fs::read(directory.join("canary")).unwrap(), CANARY);
            assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
        }
    }

    #[test]
    fn final_symlink_file_and_writable_directory_are_unsafe() {
        let fixture = Fixture::new();
        let external = fixture.temporary.path().join("external");
        make_dir(&external, 0o700);
        fs::write(external.join("canary"), CANARY).unwrap();

        let program = fixture.path("opt/nodomi-agent");
        symlink(&external, &program).unwrap();
        let state = fixture.path("var/lib/nodomi-agent");
        fs::write(&state, CANARY).unwrap();
        make_dir(&fixture.path("var/lib/nodomi-agent-control"), 0o770);

        assert_eq!(fixture.inspect(), layout(Unsafe, Unsafe, Unsafe));
        assert_eq!(fs::read_link(program).unwrap(), external);
        assert_eq!(fs::read(external.join("canary")).unwrap(), CANARY);
        assert_eq!(fs::read(state).unwrap(), CANARY);
    }

    #[test]
    fn symlink_ancestor_is_not_followed() {
        let fixture = Fixture::new();
        let external = fixture.temporary.path().join("external");
        make_dir(&external, 0o700);
        make_dir(&external.join("nodomi-agent"), 0o700);
        fs::write(external.join("nodomi-agent/canary"), CANARY).unwrap();
        let opt = fixture.path("opt");
        fs::remove_dir(&opt).unwrap();
        symlink(&external, &opt).unwrap();

        assert_eq!(fixture.inspect(), layout(Unsafe, Missing, Missing));
        assert_eq!(fs::read_link(opt).unwrap(), external);
        assert_eq!(
            fs::read(external.join("nodomi-agent/canary")).unwrap(),
            CANARY
        );
    }

    #[test]
    fn missing_ancestor_is_unavailable_and_writable_ancestor_is_unsafe() {
        let fixture = Fixture::new();
        let lib = fixture.path("var/lib");
        fs::remove_dir(&lib).unwrap();
        assert_eq!(fixture.inspect(), layout(Missing, Unavailable, Unavailable));
        assert!(!lib.exists());

        make_dir(&lib, 0o777);
        let control = lib.join("nodomi-agent-control");
        make_dir(&control, 0o700);
        fs::write(control.join("canary"), CANARY).unwrap();
        assert_eq!(fixture.inspect(), layout(Missing, Unsafe, Unsafe));
        assert_eq!(fs::read(control.join("canary")).unwrap(), CANARY);
    }

    #[test]
    fn control_requires_exact_private_mode() {
        let fixture = Fixture::new();
        for name in [
            "opt/nodomi-agent",
            "var/lib/nodomi-agent",
            "var/lib/nodomi-agent-control",
        ] {
            make_dir(&fixture.path(name), 0o755);
        }
        assert_eq!(fixture.inspect(), layout(Present, Present, Unsafe));

        let control = fixture.path("var/lib/nodomi-agent-control");
        fs::set_permissions(control, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fixture.inspect(), layout(Present, Present, Present));
    }

    #[test]
    fn anchored_root_is_not_reopened_by_path_and_owner_is_checked() {
        let fixture = Fixture::new();
        make_dir(&fixture.path("opt/nodomi-agent"), 0o700);
        let root_path = fixture.path("");
        fs::rename(&root_path, fixture.temporary.path().join("original")).unwrap();
        make_dir(&root_path, 0o700);

        assert_eq!(fixture.inspect(), layout(Present, Missing, Missing));
        assert_eq!(
            inspect_at(&fixture.root, uid().wrapping_add(1)),
            layout(Unsafe, Unsafe, Unsafe),
        );
    }
}
