use nodomi_agent::{
    buffer::SharedBufferPaths,
    identity::{Result, Target},
    installation::{MAX_SERVICE_SETTINGS_BYTES, validate_service_ca as validate_ca},
};
use serde::Deserialize;
use std::{
    ffi::CString,
    fs::{File, Metadata, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

const BAD_LAYOUT: &str = "INVALID_SERVICE_LAYOUT";
const BAD_LOCK: &str = "INVALID_SUPERVISOR_LOCK";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Settings {
    management_origin: String,
    expected_server_id: String,
    #[serde(default)]
    startup_window_required: bool,
}

pub(super) struct ServiceFiles {
    pub(super) target: Target,
    pub(super) ca: Option<Vec<u8>>,
    pub(super) identity: PathBuf,
    pub(super) host: PathBuf,
    pub(super) ssh: PathBuf,
    pub(super) health: Option<File>,
    pub(super) startup_window_required: bool,
}

impl ServiceFiles {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let root = protected_root(path)?;
        let bytes = protected_bytes(
            &root,
            "service.json",
            MAX_SERVICE_SETTINGS_BYTES as u64,
            false,
        )?
        .ok_or("SERVICE_CONFIGURATION_REQUIRED")?;
        let (target, startup_window_required) = decode_settings(&bytes)?;
        let ca = protected_bytes(&root, "ca.pem", 65_536, true)?;
        if let Some(pem) = &ca {
            validate_ca(pem)?;
        }
        for name in ["identity", "runtime", "ssh-queue"] {
            let directory =
                open_child(&root, name.as_bytes(), libc::O_DIRECTORY).map_err(|_| BAD_LAYOUT)?;
            check_directory(&directory, true)?;
        }
        let health = match open_child(&root, b"health", libc::O_DIRECTORY) {
            Ok(directory) => {
                check_directory(&directory, true)?;
                Some(directory)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(_) => return Err(BAD_LAYOUT),
        };
        Ok(Self {
            target,
            ca,
            identity: path.join("identity"),
            host: path.join("runtime"),
            ssh: path.join("ssh-queue"),
            health,
            startup_window_required,
        })
    }

    pub(super) fn buffer_paths(&self) -> SharedBufferPaths<'_> {
        SharedBufferPaths {
            host: &self.host,
            ssh: &self.ssh,
        }
    }
}

fn decode_settings(bytes: &[u8]) -> Result<(Target, bool)> {
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return Err("INVALID_SERVICE_CONFIGURATION");
    }
    let settings: Settings =
        serde_json::from_slice(bytes).map_err(|_| "INVALID_SERVICE_CONFIGURATION")?;
    let target = Target::new(&settings.management_origin, &settings.expected_server_id)
        .map_err(|_| "INVALID_SERVICE_CONFIGURATION")?;
    Ok((target, settings.startup_window_required))
}

fn open_child(directory: &File, name: &[u8], flags: libc::c_int) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the parent descriptor and name are live, and success returns an owned FD.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | flags,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by openat and has no other owner.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn check_directory(file: &File, private: bool) -> Result<()> {
    let meta = file.metadata().map_err(|_| BAD_LAYOUT)?;
    let mode = meta.mode() & 0o7777;
    if !meta.is_dir()
        || meta.uid() != 0
        || meta.gid() != 0
        || (if private {
            mode != 0o700
        } else {
            mode & 0o022 != 0
        })
    {
        return Err(BAD_LAYOUT);
    }
    Ok(())
}

fn protected_root(path: &Path) -> Result<File> {
    let mut components = path.components().peekable();
    if components.next() != Some(Component::RootDir) {
        return Err(BAD_LAYOUT);
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")
        .map_err(|_| BAD_LAYOUT)?;
    check_directory(&directory, false)?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(BAD_LAYOUT);
        };
        directory =
            open_child(&directory, name.as_bytes(), libc::O_DIRECTORY).map_err(|_| BAD_LAYOUT)?;
        check_directory(&directory, components.peek().is_none())?;
    }
    Ok(directory)
}

fn private_regular(file: &File) -> Result<Metadata> {
    let meta = file.metadata().map_err(|_| BAD_LAYOUT)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
    {
        return Err(BAD_LAYOUT);
    }
    Ok(meta)
}

fn protected_bytes(
    directory: &File,
    name: &str,
    limit: u64,
    optional: bool,
) -> Result<Option<Vec<u8>>> {
    let file = match open_child(directory, name.as_bytes(), 0) {
        Ok(file) => file,
        Err(error) if optional && error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err("SERVICE_CONFIGURATION_REQUIRED");
        }
        Err(_) => return Err(BAD_LAYOUT),
    };
    let metadata = private_regular(&file)?;
    if !(1..=limit).contains(&metadata.len()) {
        return Err(BAD_LAYOUT);
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BAD_LAYOUT)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(BAD_LAYOUT);
    }
    Ok(Some(bytes))
}

pub(super) fn supervisor_lock(control: &Path, fd: i32) -> Result<(File, File)> {
    let mut death_signal: libc::c_int = 0;
    // SAFETY: the output pointer is valid for PR_GET_PDEATHSIG, and the other
    // calls return process metadata without accessing application memory.
    if unsafe {
        libc::geteuid() != 0
            || libc::getppid() <= 1
            || libc::prctl(
                libc::PR_GET_PDEATHSIG,
                &raw mut death_signal,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
    } || death_signal != libc::SIGKILL
    {
        return Err(BAD_LOCK);
    }
    // SAFETY: fcntl returns an error for a closed descriptor. The entry point
    // accepts ownership of this inherited descriptor before opening other files.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    // SAFETY: fd and its flags are valid after the preceding successful call.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
        return Err(BAD_LOCK);
    }
    // SAFETY: fd is an inherited, validated descriptor with no other Rust owner.
    let inherited = unsafe { File::from_raw_fd(fd) };
    let directory = protected_root(control).map_err(|_| BAD_LOCK)?;
    let probe = open_child(&directory, b"supervisor.lock", 0).map_err(|_| BAD_LOCK)?;
    confirm_supervisor_lock(&inherited, &probe)?;
    Ok((inherited, directory))
}

fn confirm_supervisor_lock(inherited: &File, probe: &File) -> Result<()> {
    let expected = private_regular(probe).map_err(|_| BAD_LOCK)?;
    let actual = private_regular(inherited).map_err(|_| BAD_LOCK)?;
    if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
        return Err(BAD_LOCK);
    }
    // A fresh open must contend and the inherited open-file description must
    // already own the lock. Never explicitly unlock the shared description.
    // SAFETY: probe belongs to a live file.
    let probe_locked =
        unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if probe_locked || io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
        return Err(BAD_LOCK);
    }
    // SAFETY: inherited belongs to a live file.
    if unsafe { libc::flock(inherited.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(BAD_LOCK);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_allow_only_the_exact_nonsecret_object() {
        let good =
            br#"{"managementOrigin":"https://example.invalid","expectedServerId":"server-1"}"#;
        assert_eq!(
            decode_settings(good).unwrap().0.expected_server_id,
            "server-1"
        );
        assert!(!decode_settings(good).unwrap().1);
        assert!(decode_settings(br#"{"managementOrigin":"https://example.invalid","expectedServerId":"server-1","startupWindowRequired":true}"#).unwrap().1);
        for invalid in [
            br#"["https://example.invalid","server-1"]"#.as_slice(),
            br#"{"managementOrigin":"http://example.invalid","expectedServerId":"server-1"}"#,
            br#"{"managementOrigin":"https://user:pass@example.invalid","expectedServerId":"server-1"}"#,
            br#"{"managementOrigin":"https://example.invalid","expectedServerId":"server-1","credential":"fixture"}"#,
            br#"{"managementOrigin":"https://example.invalid","expectedServerId":"server-1","expectedServerId":"server-2"}"#,
        ] {
            assert_eq!(decode_settings(invalid), Err("INVALID_SERVICE_CONFIGURATION"));
        }
    }

    #[test]
    fn explicit_ca_accepts_certificate_only() {
        let pem = include_bytes!("../tests/fixtures/tls/ca.pem");
        assert_eq!(validate_ca(pem), Ok(()));
        let mut mixed = pem.to_vec();
        mixed.extend_from_slice(b"private text");
        assert_eq!(validate_ca(&mixed), Err("INVALID_CA"));
        assert_eq!(validate_ca(b"invalid"), Err("INVALID_CA"));
    }

    #[test]
    fn absent_optional_ca_does_not_allow_links_or_insecure_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temporary = tempfile::tempdir().unwrap();
        let directory = File::open(temporary.path()).unwrap();
        assert_eq!(
            protected_bytes(&directory, "ca.pem", 65_536, true),
            Ok(None)
        );
        let ca = temporary.path().join("ca.pem");
        symlink("absent", &ca).unwrap();
        assert_eq!(
            protected_bytes(&directory, "ca.pem", 65_536, true),
            Err(BAD_LAYOUT)
        );
        std::fs::remove_file(&ca).unwrap();
        std::fs::write(&ca, include_bytes!("../tests/fixtures/tls/ca.pem")).unwrap();
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            protected_bytes(&directory, "ca.pem", 65_536, true),
            Err(BAD_LAYOUT)
        );
    }
}
