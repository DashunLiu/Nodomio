use super::SupervisorResult;
use nodomi_agent::installation::AWAITING_INSTALL_TAKEOVER_EXIT;
use std::{
    ffi::CString,
    fs::{self, File},
    io,
    mem::{MaybeUninit, size_of},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
    ptr, thread,
    time::{Duration, Instant},
};

const POLL_MS: libc::c_int = 100;
const GRACEFUL_STOP: Duration = Duration::from_secs(8);
const MAX_INHERITED_ENTRIES: usize = 4096;

/// Keep only standard I/O and the explicit instance-lock handoff across exec.
pub(super) fn seal_inherited_descriptors() -> SupervisorResult<()> {
    let entries = fs::read_dir("/proc/self/fd").map_err(|_| "FD_LAYOUT_UNAVAILABLE")?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_INHERITED_ENTRIES {
            return Err("FD_LAYOUT_UNAVAILABLE");
        }
        let name = entry.map_err(|_| "FD_LAYOUT_UNAVAILABLE")?.file_name();
        let fd = name
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
            .ok_or("FD_LAYOUT_UNAVAILABLE")?;
        if fd < 3 {
            continue;
        }
        // SAFETY: fcntl only inspects a descriptor in this single-threaded process.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err("FD_LAYOUT_UNAVAILABLE");
        }
        // SAFETY: fd is live and F_SETFD changes only its descriptor flags.
        if flags & libc::FD_CLOEXEC == 0
            && unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
        {
            return Err("FD_LAYOUT_UNAVAILABLE");
        }
    }
    Ok(())
}

pub(super) struct Signals {
    descriptor: File,
    previous: libc::sigset_t,
    child_mask: libc::sigset_t,
}

impl Signals {
    pub(super) fn capture() -> SupervisorResult<Self> {
        let mut selected = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: sigemptyset initializes writable sigset_t storage.
        if unsafe { libc::sigemptyset(selected.as_mut_ptr()) } != 0 {
            return Err("SIGNAL_SETUP_FAILED");
        }
        // SAFETY: sigemptyset initialized selected.
        let mut selected = unsafe { selected.assume_init() };
        // SAFETY: selected is live and the signal numbers are valid.
        if unsafe { libc::sigaddset(&mut selected, libc::SIGTERM) } != 0
            || unsafe { libc::sigaddset(&mut selected, libc::SIGINT) } != 0
        {
            return Err("SIGNAL_SETUP_FAILED");
        }

        // Make direct children waitable even if a launcher ignored SIGCHLD.
        // SAFETY: all-zero sigaction fields have valid integer/pointer representations.
        let mut child_action = unsafe { MaybeUninit::<libc::sigaction>::zeroed().assume_init() };
        child_action.sa_sigaction = libc::SIG_DFL;
        // SAFETY: the action is initialized and no old action is requested.
        if unsafe { libc::sigaction(libc::SIGCHLD, &child_action, ptr::null_mut()) } != 0 {
            return Err("SIGNAL_SETUP_FAILED");
        }

        let mut previous = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: selected is live and previous is writable.
        if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &selected, previous.as_mut_ptr()) } != 0
        {
            return Err("SIGNAL_SETUP_FAILED");
        }
        // SAFETY: successful pthread_sigmask initialized previous.
        let previous = unsafe { previous.assume_init() };
        // SAFETY: selected is live, and -1 requests an independent descriptor.
        let fd = unsafe { libc::signalfd(-1, &selected, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if fd < 0 {
            restore_mask(&previous);
            return Err("SIGNAL_SETUP_FAILED");
        }
        // SAFETY: successful signalfd returned a uniquely owned descriptor.
        let descriptor = unsafe { File::from_raw_fd(fd) };
        let mut child_mask = previous;
        // The child needs to receive TERM and INT even if the launcher had them blocked.
        // SAFETY: child_mask is live and the signal numbers are valid.
        if unsafe { libc::sigdelset(&mut child_mask, libc::SIGTERM) } != 0
            || unsafe { libc::sigdelset(&mut child_mask, libc::SIGINT) } != 0
        {
            restore_mask(&previous);
            return Err("SIGNAL_SETUP_FAILED");
        }
        Ok(Self {
            descriptor,
            previous,
            child_mask,
        })
    }

    pub(super) fn stop_requested(&self, wait_ms: libc::c_int) -> SupervisorResult<bool> {
        let mut event = libc::pollfd {
            fd: self.descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: event refers to one live pollfd.
        let result = unsafe { libc::poll(&mut event, 1, wait_ms) };
        if result == 0
            || (result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted)
        {
            return Ok(false);
        }
        if result < 0 || event.revents & libc::POLLIN == 0 {
            return Err("SIGNAL_READ_FAILED");
        }
        let mut event = MaybeUninit::<libc::signalfd_siginfo>::uninit();
        // SAFETY: signalfd is live and event has room for a full signal record.
        let count = unsafe {
            libc::read(
                self.descriptor.as_raw_fd(),
                event.as_mut_ptr().cast(),
                size_of::<libc::signalfd_siginfo>(),
            )
        };
        if count == size_of::<libc::signalfd_siginfo>() as libc::ssize_t {
            return Ok(true);
        }
        if count < 0
            && matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            )
        {
            return Ok(false);
        }
        Err("SIGNAL_READ_FAILED")
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        restore_mask(&self.previous);
    }
}

fn restore_mask(previous: &libc::sigset_t) {
    // SAFETY: previous is the initialized mask saved from this thread.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, previous, ptr::null_mut()) };
}

pub(super) fn supervise(
    executable: &File,
    instance: &File,
    signals: &Signals,
) -> SupervisorResult<()> {
    let mut child = spawn(executable, instance, &signals.child_mask)?;
    loop {
        match signals.stop_requested(POLL_MS) {
            Ok(true) => return drain(&mut child, GRACEFUL_STOP),
            Ok(false) => {}
            Err(code) => {
                drain(&mut child, GRACEFUL_STOP)?;
                return Err(code);
            }
        }
        if let Some(status) = child.try_wait().map_err(|_| "COLLECTOR_WAIT_FAILED")? {
            if status.code() == Some(i32::from(AWAITING_INSTALL_TAKEOVER_EXIT)) {
                return Ok(());
            }
            return Err("COLLECTOR_EXITED");
        }
    }
}

fn spawn(
    executable: &File,
    instance: &File,
    child_mask: &libc::sigset_t,
) -> SupervisorResult<Child> {
    let executable_fd = executable.as_raw_fd();
    let instance_fd = instance.as_raw_fd();
    let instance_arg =
        CString::new(instance_fd.to_string()).map_err(|_| "COLLECTOR_START_FAILED")?;
    // SAFETY: getpid has no preconditions. The foreground thread remains the parent.
    let parent = unsafe { libc::getpid() };
    let child_mask = *child_mask;
    // The hook always execs the held file descriptor or returns an error.
    let mut command = Command::new("/opt/nodomi-agent/bin/nodomi-agent-supervisor");
    command.env_clear().current_dir("/").stdin(Stdio::null());
    // SAFETY: the child hook only uses async-signal-safe syscalls and prepared
    // arguments. Parent holds both descriptors until Command::spawn returns.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // Closes the race if the supervisor exited before the prctl call.
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if libc::sigprocmask(libc::SIG_SETMASK, &child_mask, ptr::null_mut()) != 0
                || libc::fcntl(instance_fd, libc::F_SETFD, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let argv = [
                c"nodomi-agent".as_ptr(),
                c"serve".as_ptr(),
                c"--supervisor-lock-fd".as_ptr(),
                instance_arg.as_ptr(),
                ptr::null(),
            ];
            let environment: [*const libc::c_char; 1] = [ptr::null()];
            libc::syscall(
                libc::SYS_execveat,
                executable_fd,
                c"".as_ptr(),
                argv.as_ptr(),
                environment.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            Err(io::Error::last_os_error())
        });
    }
    command.spawn().map_err(|_| "COLLECTOR_START_FAILED")
}

fn drain(child: &mut Child, grace: Duration) -> SupervisorResult<()> {
    signal_live(child, libc::SIGTERM)?;
    let deadline = Instant::now() + grace;
    loop {
        if child
            .try_wait()
            .map_err(|_| "COLLECTOR_WAIT_FAILED")?
            .is_some()
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(POLL_MS as u64)));
    }
    signal_live(child, libc::SIGKILL)?;
    // Do not release the instance lock until the owned child is actually reaped.
    child.wait().map_err(|_| "COLLECTOR_WAIT_FAILED")?;
    Ok(())
}

fn signal_live(child: &mut Child, signal: libc::c_int) -> SupervisorResult<()> {
    if child
        .try_wait()
        .map_err(|_| "COLLECTOR_WAIT_FAILED")?
        .is_some()
    {
        return Ok(());
    }
    let pid = libc::pid_t::try_from(child.id())
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or("COLLECTOR_SIGNAL_FAILED")?;
    // SAFETY: this process owns the child and is its sole waiter. Its PID
    // cannot be reused between try_wait and kill without being reaped.
    if unsafe { libc::kill(pid, signal) } != 0
        && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Err("COLLECTOR_SIGNAL_FAILED");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        os::unix::process::ExitStatusExt,
    };

    #[test]
    fn stop_escalates_and_reaps_an_owned_child_that_ignores_term() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; printf 'ready\\n'; while :; do :; done"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready, "ready\n");
        drain(&mut child, Duration::from_millis(10)).unwrap();
        assert_eq!(
            child.try_wait().unwrap().unwrap().signal(),
            Some(libc::SIGKILL)
        );
    }
}
