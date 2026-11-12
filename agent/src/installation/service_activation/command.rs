use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::{fs::OpenOptionsExt, net::UnixStream},
    },
    ptr, thread,
    time::{Duration, Instant},
};

const MAX_OUTPUT: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Run the held manager executable by descriptor. The child never inherits a
/// user-controlled environment or stdin, and the deadline includes exec.
pub(super) fn run(executable: &File, argv: &[&str], timeout: Duration) -> io::Result<Vec<u8>> {
    let args = argv
        .iter()
        .map(|argument| CString::new(*argument))
        .collect::<Result<Vec<_>, _>>()?;
    let mut arguments = args
        .iter()
        .map(|argument| argument.as_ptr())
        .collect::<Vec<_>>();
    arguments.push(ptr::null());
    let environment = [
        c"PATH=/usr/sbin:/usr/bin:/sbin:/bin".as_ptr(),
        c"LC_ALL=C".as_ptr(),
        c"SYSTEMD_COLORS=0".as_ptr(),
        ptr::null(),
    ];
    let (mut reader, writer) = UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/null")?;
    let (executable, writer_fd, null_fd) =
        (executable.as_raw_fd(), writer.as_raw_fd(), null.as_raw_fd());
    if [executable, writer_fd, null_fd]
        .into_iter()
        .any(|fd| fd <= libc::STDERR_FILENO)
    {
        return Err(io::Error::other("standard descriptors are unavailable"));
    }
    let mut unblocked = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: unblocked points to writable storage and getpid has no preconditions.
    let parent = unsafe {
        if libc::sigemptyset(unblocked.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        libc::getpid()
    };
    let deadline = Instant::now() + timeout;
    // SAFETY: the child uses only prepared data and async-signal-safe syscalls
    // until execveat or _exit. All descriptors and strings are live across fork.
    let pid = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
                || libc::getppid() != parent
                || libc::setpgid(0, 0) != 0
                || libc::sigprocmask(libc::SIG_SETMASK, unblocked.as_ptr(), ptr::null_mut()) != 0
                || libc::chdir(c"/".as_ptr()) != 0
                || libc::dup2(null_fd, libc::STDIN_FILENO) < 0
                || libc::dup2(null_fd, libc::STDERR_FILENO) < 0
                || libc::dup2(writer_fd, libc::STDOUT_FILENO) < 0
                || !seal_inherited_descriptors()
            {
                libc::_exit(127);
            }
            libc::syscall(
                libc::SYS_execveat,
                executable,
                c"".as_ptr(),
                arguments.as_ptr(),
                environment.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            libc::_exit(127);
        }
        pid
    };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    drop(writer);
    let mut child = Child(Some(pid));
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut eof = false;
    loop {
        if !eof {
            match reader.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(length) if output.len() + length <= MAX_OUTPUT => {
                    output.extend_from_slice(&buffer[..length])
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "manager output exceeds limit",
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if eof && let Some(status) = child.reap()? {
            return if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                Ok(output)
            } else {
                Err(io::Error::other("manager command failed"))
            };
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "manager command timed out",
            ));
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn seal_inherited_descriptors() -> bool {
    // SAFETY: this runs in the fork child and marks only that child's fd table.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } == 0
    {
        return true;
    }

    // Linux before close_range(CLOEXEC) can enumerate its own fd table without
    // heap allocation or relying on RLIMIT_NOFILE (which may have been lowered).
    // SAFETY: the path is constant and open allocates a new child-only descriptor.
    let entries = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if entries < 0 {
        return false;
    }
    let mut buffer = [0_u8; 4096];
    // A finite scan also keeps exec from hanging on an excessive inherited table.
    for _ in 0..256 {
        // SAFETY: entries is live and buffer is valid storage for raw linux_dirent64 records.
        let bytes = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                entries,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if bytes == 0 {
            return true;
        }
        let Some(records) = usize::try_from(bytes)
            .ok()
            .and_then(|bytes| buffer.get(..bytes))
        else {
            return false;
        };
        if !seal_dirents(records) {
            return false;
        }
    }
    false
}

fn seal_dirents(mut records: &[u8]) -> bool {
    // linux_dirent64 contains d_ino:u64, d_off:i64, d_reclen:u16, d_type:u8, d_name[].
    while !records.is_empty() {
        let Some(length) = records
            .get(16..18)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_ne_bytes)
        else {
            return false;
        };
        let length = usize::from(length);
        let Some(record) = records.get(..length).and_then(|record| record.get(19..)) else {
            return false;
        };
        let Ok(name) = std::ffi::CStr::from_bytes_until_nul(record) else {
            return false;
        };
        if !matches!(name.to_bytes(), b"." | b"..") {
            let Ok(name) = name.to_str() else {
                return false;
            };
            let Ok(fd) = name.parse::<libc::c_int>() else {
                return false;
            };
            // SAFETY: this is a descriptor from the current fork child's own table.
            if fd > libc::STDERR_FILENO
                && unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
            {
                return false;
            }
        }
        records = &records[length..];
    }
    true
}

struct Child(Option<libc::pid_t>);

impl Child {
    fn reap(&mut self) -> io::Result<Option<libc::c_int>> {
        let Some(pid) = self.0 else {
            return Ok(None);
        };
        let mut status = 0;
        // SAFETY: pid is our child and status points to writable storage.
        match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
            0 => Ok(None),
            result if result == pid => {
                self.0 = None;
                Ok(Some(status))
            }
            _ => {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                self.0 = None;
                Err(error)
            }
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let Some(pid) = self.0 else {
            return;
        };
        let mut status = MaybeUninit::<libc::siginfo_t>::uninit();
        // SAFETY: WNOWAIT leaves our child unreaped, keeping its PID reserved
        // while we signal its process group and the leader. This also refuses
        // to signal when a host has made children unavailable to waitid.
        unsafe {
            if libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                status.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ) != 0
            {
                return;
            }
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
        // Avoid blocking if the kernel has not yet delivered SIGKILL. The
        // activation result remains uncertain and the journal retains ownership.
        let deadline = Instant::now() + Duration::from_millis(250);
        while matches!(self.reap(), Ok(None)) && Instant::now() < deadline {
            thread::sleep(POLL_INTERVAL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::FromRawFd, time::Instant};

    #[test]
    fn child_runs_with_fixed_clean_environment_and_captures_output() {
        let shell = File::open("/bin/sh").unwrap();
        let output = run(
            &shell,
            &[
                "sh",
                "-c",
                "printf '%s|%s|%s' \"$PATH\" \"$LC_ALL\" \"$HOME\"",
            ],
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(output, b"/usr/sbin:/usr/bin:/sbin:/bin|C|");
    }

    #[test]
    fn timeout_fences_a_stalled_command_and_output_is_bounded() {
        let shell = File::open("/bin/sh").unwrap();
        let begin = Instant::now();
        let error = run(&shell, &["sh", "-c", "sleep 5"], Duration::from_millis(50)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(begin.elapsed() < Duration::from_secs(1));
        let error = run(&shell, &["sh", "-c", "yes"], Duration::from_secs(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn child_cannot_inherit_non_cloexec_descriptor() {
        let shell = File::open("/bin/sh").unwrap();
        // SAFETY: shell is a live fd and F_DUPFD returns a new owned descriptor.
        let inherited = unsafe { libc::fcntl(shell.as_raw_fd(), libc::F_DUPFD, 100) };
        assert!(inherited >= 100);
        // SAFETY: inherited is uniquely owned by this test.
        let _hold = unsafe { File::from_raw_fd(inherited) };
        let probe = format!("test ! -e /proc/self/fd/{inherited}");
        assert!(run(&shell, &["sh", "-c", &probe], Duration::from_secs(1)).is_ok());
    }
}
