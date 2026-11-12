use super::SupervisorResult;
use nodomi_agent::{
    installation::{EXECUTABLE_PREFIX_BYTES, inspect_executable},
    release::manifest::Platform,
};
use ring::digest::{Context, SHA256};
use serde::Deserialize;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read},
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, RawFd},
};

const ROOT_UID: libc::uid_t = 0;
const CURRENT_MAX_BYTES: u64 = 1024;
const ELF_MAX_BYTES: u64 = 512 * 1024 * 1024;

pub(super) struct Layout {
    program: File,
    control: File,
}

impl Layout {
    pub(super) fn open() -> SupervisorResult<Self> {
        let root = open_at(libc::AT_FDCWD, c"/", libc::O_RDONLY | libc::O_DIRECTORY)?;
        check_directory(&root, None)?;
        let opt = directory_at(&root, c"opt", None)?;
        let var = directory_at(&root, c"var", None)?;
        let state_parent = directory_at(&var, c"lib", None)?;
        Ok(Self {
            program: directory_at(&opt, c"nodomi-agent", None)?,
            control: directory_at(&state_parent, c"nodomi-agent-control", Some(0o700))?,
        })
    }

    pub(super) fn check_running_supervisor(&self) -> SupervisorResult<()> {
        let bin = directory_at(&self.program, c"bin", None)?;
        let fixed = regular_at(&bin, c"nodomi-agent-supervisor", 0o755)?;
        let running =
            File::open("/proc/self/exe").map_err(|_| "SUPERVISOR_IDENTITY_UNAVAILABLE")?;
        if !same_inode(&stat(&fixed, None)?, &stat(&running, None)?) {
            return Err("SUPERVISOR_IDENTITY_MISMATCH");
        }
        Ok(())
    }

    pub(super) fn lock_instance(&self) -> SupervisorResult<File> {
        let lock = regular_at(&self.control, c"supervisor.lock", 0o600)?;
        // SAFETY: lock is a live, independently opened descriptor.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(
                if io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK) {
                    "SUPERVISOR_ALREADY_ACTIVE"
                } else {
                    "SUPERVISOR_LOCK_UNAVAILABLE"
                },
            );
        }
        check_directory(&self.control, Some(0o700))?;
        let opened = stat(&lock, None)?;
        let named = stat(&self.control, Some(c"supervisor.lock"))?;
        check_regular(&opened, 0o600)?;
        if !same_snapshot(&opened, &named) {
            return Err("UNSAFE_INSTALL_LAYOUT");
        }
        // Close releases this lock only once the collector's duplicate closes.
        // An explicit LOCK_UN would invalidate both copies.
        Ok(lock)
    }

    pub(super) fn verify_collector(&self) -> SupervisorResult<File> {
        let pointer = regular_at(&self.program, c"current.json", 0o600)?;
        let pointer_stat = stat(&pointer, None)?;
        let bytes = read_pointer(&pointer)?;
        let current = Current::parse(&bytes)?;
        ensure_unchanged(&self.program, c"current.json", &pointer, &pointer_stat)?;

        let releases = directory_at(&self.program, c"releases", None)?;
        let release_name =
            CString::new(current.release_id).map_err(|_| "INVALID_CURRENT_RELEASE")?;
        let release = directory_at(&releases, &release_name, None)?;
        let executable = regular_at(&release, c"nodomi-agent", 0o755)?;
        let executable_stat = stat(&executable, None)?;
        reject_file_capabilities(&executable)?;
        verify_contents(&executable, &executable_stat, &current.sha256)?;

        ensure_unchanged(&release, c"nodomi-agent", &executable, &executable_stat)?;
        ensure_unchanged(&self.program, c"current.json", &pointer, &pointer_stat)?;
        Ok(executable)
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Current {
    release_id: String,
    sha256: String,
}

impl Current {
    fn parse(bytes: &[u8]) -> SupervisorResult<Self> {
        if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
            return Err("INVALID_CURRENT_RELEASE");
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "INVALID_CURRENT_RELEASE")?;
        let id = value.release_id.as_bytes();
        if id.len() != 36
            || id.iter().enumerate().any(|(index, &byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte != b'-'
                } else {
                    !hex_digit(byte)
                }
            })
            || value.sha256.len() != 64
            || !value.sha256.bytes().all(hex_digit)
        {
            return Err("INVALID_CURRENT_RELEASE");
        }
        Ok(value)
    }
}

fn hex_digit(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn read_pointer(file: &File) -> SupervisorResult<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(CURRENT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "INSTALL_LAYOUT_UNAVAILABLE")?;
    if bytes.len() as u64 > CURRENT_MAX_BYTES {
        return Err("INVALID_CURRENT_RELEASE");
    }
    Ok(bytes)
}

fn verify_contents(file: &File, metadata: &libc::stat, expected: &str) -> SupervisorResult<()> {
    let length = u64::try_from(metadata.st_size).map_err(|_| "INVALID_COLLECTOR_ELF")?;
    if !(1..=ELF_MAX_BYTES).contains(&length) {
        return Err("INVALID_COLLECTOR_ELF");
    }
    let platform = if cfg!(target_arch = "aarch64") {
        Platform::LinuxAarch64
    } else if cfg!(target_arch = "x86_64") {
        Platform::LinuxX86_64
    } else {
        return Err("UNSUPPORTED_HOST");
    };
    let mut reader = file.take(length + 1);
    let prefix_size = length.min(EXECUTABLE_PREFIX_BYTES as u64) as usize;
    let mut prefix = vec![0; prefix_size];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| "COLLECTOR_READ_FAILED")?;
    inspect_executable(&prefix, length, platform).map_err(|_| "INVALID_COLLECTOR_ELF")?;

    let mut context = Context::new(&SHA256);
    context.update(&prefix);
    let mut total = prefix_size as u64;
    let mut buffer = [0; 32 * 1024];
    loop {
        let size = reader
            .read(&mut buffer)
            .map_err(|_| "COLLECTOR_READ_FAILED")?;
        if size == 0 {
            break;
        }
        total += size as u64;
        context.update(&buffer[..size]);
    }
    let actual: String = context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if total != length || actual != expected {
        return Err("COLLECTOR_DIGEST_MISMATCH");
    }
    Ok(())
}

fn reject_file_capabilities(file: &File) -> SupervisorResult<()> {
    // SAFETY: file is live and the zero-sized query has no output storage.
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size >= 0 {
        return Err("UNSAFE_COLLECTOR_ELF");
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ENODATA | libc::EOPNOTSUPP) => Ok(()),
        _ => Err("COLLECTOR_CAPABILITIES_UNAVAILABLE"),
    }
}

fn open_at(parent: RawFd, name: &CStr, flags: libc::c_int) -> SupervisorResult<File> {
    // SAFETY: name is NUL-terminated, and all callers hold the parent descriptor.
    // No creation flags are accepted by callers.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(
            if matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ELOOP | libc::ENOTDIR)
            ) {
                "UNSAFE_INSTALL_LAYOUT"
            } else {
                "INSTALL_LAYOUT_UNAVAILABLE"
            },
        );
    }
    // SAFETY: successful openat returned a uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn directory_at(
    parent: &File,
    name: &CStr,
    exact_mode: Option<libc::mode_t>,
) -> SupervisorResult<File> {
    let directory = open_at(parent.as_raw_fd(), name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    check_directory(&directory, exact_mode)?;
    Ok(directory)
}

fn check_directory(directory: &File, exact_mode: Option<libc::mode_t>) -> SupervisorResult<()> {
    let metadata = stat(directory, None)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != ROOT_UID
        || metadata.st_nlink == 0
        || metadata.st_mode & 0o022 != 0
        || exact_mode.is_some_and(|mode| metadata.st_mode & 0o7777 != mode)
    {
        return Err("UNSAFE_INSTALL_LAYOUT");
    }
    Ok(())
}

fn regular_at(parent: &File, name: &CStr, mode: libc::mode_t) -> SupervisorResult<File> {
    let named = stat(parent, Some(name))?;
    check_regular(&named, mode)?;
    let file = open_at(parent.as_raw_fd(), name, libc::O_RDONLY)?;
    let opened = stat(&file, None)?;
    if !same_snapshot(&named, &opened) {
        return Err("UNSAFE_INSTALL_LAYOUT");
    }
    Ok(file)
}

fn check_regular(metadata: &libc::stat, mode: libc::mode_t) -> SupervisorResult<()> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != ROOT_UID
        || metadata.st_gid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o7777 != mode
    {
        return Err("UNSAFE_INSTALL_LAYOUT");
    }
    Ok(())
}

fn ensure_unchanged(
    parent: &File,
    name: &CStr,
    file: &File,
    original: &libc::stat,
) -> SupervisorResult<()> {
    if !same_snapshot(original, &stat(file, None)?)
        || !same_snapshot(original, &stat(parent, Some(name))?)
    {
        return Err("INSTALL_LAYOUT_CHANGED");
    }
    Ok(())
}

fn stat(file: &File, name: Option<&CStr>) -> SupervisorResult<libc::stat> {
    let mut output = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: file and any NUL-terminated name are live, with writable output.
    let result = unsafe {
        match name {
            Some(name) => libc::fstatat(
                file.as_raw_fd(),
                name.as_ptr(),
                output.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            ),
            None => libc::fstat(file.as_raw_fd(), output.as_mut_ptr()),
        }
    };
    if result != 0 {
        return Err("INSTALL_LAYOUT_UNAVAILABLE");
    }
    // SAFETY: successful stat initialized the output.
    Ok(unsafe { output.assume_init() })
}

fn same_inode(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn same_snapshot(left: &libc::stat, right: &libc::stat) -> bool {
    same_inode(left, right)
        && left.st_size == right.st_size
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_nlink == right.st_nlink
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_requires_a_single_canonical_target_object() {
        let id = "9bd73031-81c4-4fd4-85bb-8ad7b1945d36";
        let digest = "a".repeat(64);
        let accepted = format!(r#"{{"releaseId":"{id}","sha256":"{digest}"}}"#);
        assert_eq!(Current::parse(accepted.as_bytes()).unwrap().release_id, id);
        for invalid in [
            format!(r#"["{id}","{digest}"]"#),
            format!(r#"{{"releaseId":"../escape","sha256":"{digest}"}}"#),
            format!(r#"{{"releaseId":"{id}","releaseId":"{id}","sha256":"{digest}"}}"#),
            format!(r#"{{"releaseId":"{id}","sha256":"{digest}","argv":[]}}"#),
            format!(
                r#"{{"releaseId":"{id}","sha256":"{}"}}"#,
                digest.to_uppercase()
            ),
        ] {
            assert_eq!(
                Current::parse(invalid.as_bytes()),
                Err("INVALID_CURRENT_RELEASE")
            );
        }
    }
}
