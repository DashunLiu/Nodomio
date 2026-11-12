//! Read-only loaded-unit configuration and live direct log sink evidence.
//!
//! systemd.exec(5): rate limits count messages processed by journald; direct file
//! output bypasses them. A loaded setting can also differ from an already-open
//! process descriptor after reload. Verified null descriptors discard their
//! direct payload. PID1 lifecycle logs, forwarding, journal metadata, and
//! generators still need independent physical write bounds.
//! https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
use super::super::super::{
    layout::open_root,
    plan_store::{open_at, same_inode, same_snapshot, stat},
    service_readiness::protected_descendants,
};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::File,
    io::Read,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd},
    time::Duration,
};

// Share the existing bounded, clean-environment, descriptor-exec implementation
// without widening the activation owner's API or copying its implementation.
#[path = "../service_activation/command.rs"]
mod command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdLoggingError {
    UnsupportedManager,
    InvalidIdentity,
    Unavailable,
    UnsafeExecutable,
    InvalidProperties,
    WrongInvocation,
    UnstableObservation,
}

/// Category only: configured file paths and named descriptor values are not
/// exposed. This is the loaded configuration, not the running process's sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredLogStream {
    Null,
    Inherit,
    Journal,
    JournalAndConsole,
    Kernel,
    KernelAndConsole,
    Terminal,
    File,
    Socket,
    NamedDescriptor,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdLoggingObservation {
    main_pid: u32,
    invocation_id: u128,
    stdout: ConfiguredLogStream,
    stderr: ConfiguredLogStream,
    default_namespace: bool,
    configured_interval: String,
    configured_burst: u32,
    live_null: [bool; 2],
}
impl SystemdLoggingObservation {
    pub fn main_pid(&self) -> u32 {
        self.main_pid
    }
    pub fn invocation_id(&self) -> u128 {
        self.invocation_id
    }
    pub fn stdout(&self) -> ConfiguredLogStream {
        self.stdout
    }
    pub fn stderr(&self) -> ConfiguredLogStream {
        self.stderr
    }
    pub fn default_namespace(&self) -> bool {
        self.default_namespace
    }
    /// Raw bounded systemctl time rendering, not seconds or a byte allowance.
    /// Zero/default values may inherit journald configuration.
    pub fn configured_rate_interval(&self) -> &str {
        &self.configured_interval
    }
    /// Message count, not bytes or allocated blocks; zero is not zero writes.
    pub fn configured_rate_burst(&self) -> u32 {
        self.configured_burst
    }
    /// Direct payload allocation by the currently verified fd 1 handle only.
    pub fn stdout_direct_payload_byte_upper_bound(&self) -> Option<u64> {
        self.live_null[0].then_some(0)
    }
    /// Direct payload allocation by the currently verified fd 2 handle only.
    pub fn stderr_direct_payload_byte_upper_bound(&self) -> Option<u64> {
        self.live_null[1].then_some(0)
    }
    /// Direct payload allocation by both currently verified handles. Future
    /// descriptor changes and other logging paths require separate evidence.
    pub fn direct_payload_byte_upper_bound(&self) -> Option<u64> {
        (self.live_null == [true; 2]).then_some(0)
    }
    /// Full logging allocation remains unknown even with two null streams.
    pub fn allocated_byte_upper_bound(&self) -> Option<u64> {
        None
    }
}

const PROPERTIES: &str = "Id,LoadState,FragmentPath,DropInPaths,SourcePath,Transient,NeedDaemonReload,ActiveState,SubState,MainPID,InvocationID,StandardInput,StandardOutput,StandardError,LogNamespace,LogRateLimitIntervalUSec,LogRateLimitBurst";

pub(super) fn observe(
    pid: u32,
    invocation: u128,
) -> Result<SystemdLoggingObservation, SystemdLoggingError> {
    validate_identity(pid, invocation)?;
    let root = open_root().map_err(|_| SystemdLoggingError::Unavailable)?;
    let parent = protected_descendants(&root, &[c"usr", c"bin"], 0)
        .map_err(|_| SystemdLoggingError::UnsafeExecutable)?;
    let executable = open_at(&parent, c"systemctl", libc::O_RDONLY)
        .map_err(|_| SystemdLoggingError::Unavailable)?;
    let before = stat(&executable, None).map_err(|_| SystemdLoggingError::Unavailable)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_mode & 0o111 == 0
        || before.st_nlink != 1
    {
        return Err(SystemdLoggingError::UnsafeExecutable);
    }
    let named = stat(&parent, Some(c"systemctl")).map_err(|_| SystemdLoggingError::Unavailable)?;
    if !same_snapshot(&before, &named) {
        return Err(SystemdLoggingError::UnstableObservation);
    }
    let args = [
        "systemctl",
        "--system",
        "--no-pager",
        "--no-ask-password",
        "show",
        "--all",
        "--property",
        PROPERTIES,
        "nodomi-agent.service",
    ];
    let mut query = || {
        command::run(&executable, &args, Duration::from_secs(5))
            .map_err(|_| SystemdLoggingError::Unavailable)
    };
    let observation = observe_pair(&mut query, pid, invocation, Some(&root))?;
    let after = stat(&executable, None).map_err(|_| SystemdLoggingError::Unavailable)?;
    let named = stat(&parent, Some(c"systemctl")).map_err(|_| SystemdLoggingError::Unavailable)?;
    if !same_snapshot(&before, &after) || !same_snapshot(&after, &named) {
        return Err(SystemdLoggingError::UnstableObservation);
    }
    Ok(observation)
}

fn validate_identity(pid: u32, invocation: u128) -> Result<(), SystemdLoggingError> {
    if pid <= 1 || pid > i32::MAX as u32 || invocation == 0 {
        Err(SystemdLoggingError::InvalidIdentity)
    } else {
        Ok(())
    }
}

fn observe_pair(
    query: &mut impl FnMut() -> Result<Vec<u8>, SystemdLoggingError>,
    pid: u32,
    invocation: u128,
    root: Option<&File>,
) -> Result<SystemdLoggingObservation, SystemdLoggingError> {
    validate_identity(pid, invocation)?;
    let first = properties(&query()?)?;
    let mut observation = parse(&first, pid, invocation)?;
    let sinks = root.and_then(|root| LiveSinks::open(root, pid));
    let before = sinks.as_ref().map(LiveSinks::observe);
    let second = properties(&query()?)?;
    parse(&second, pid, invocation)?;
    // Compare all original values, even redacted file paths/namespace names.
    if first != second {
        return Err(SystemdLoggingError::UnstableObservation);
    }
    if let (Some(sinks), Some(before)) = (sinks, before) {
        let after = sinks.observe();
        if sinks.is_current() {
            observation.live_null = std::array::from_fn(|index| before[index] && after[index]);
        }
    }
    Ok(observation)
}

struct LiveSinks {
    procfs: File,
    process: File,
    fd_dir: File,
    pidfd: File,
    pid_name: CString,
    start_ticks: u64,
    // Keep the verified node pinned even if its name is later replaced.
    null: File,
}

impl LiveSinks {
    fn open(root: &File, pid: u32) -> Option<Self> {
        let procfs = protected_descendants(root, &[c"proc"], 0).ok()?;
        if !is_procfs(&procfs) {
            return None;
        }
        let pid_name = CString::new(pid.to_string()).ok()?;
        // SAFETY: validated pid and flags=0. Success returns an owned pidfd.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        if fd < 0 {
            return None;
        }
        // SAFETY: the successful syscall returned a unique descriptor.
        let pidfd = unsafe { File::from_raw_fd(fd as libc::c_int) };
        // Check the procfs mount's PID mapping using the kernel record for
        // this actual pidfd. A procfs mounted from another PID namespace
        // need not use the caller's PID numbers.
        let current = proc_magic_link(&procfs, c"self", libc::O_DIRECTORY)?;
        let fdinfo = proc_directory(&current, c"fdinfo")?;
        let pidfd_name = CString::new(pidfd.as_raw_fd().to_string()).ok()?;
        let info = proc_bytes(&fdinfo, &pidfd_name)?;
        if !info.split(|byte| *byte == b'\n').any(|line| {
            line.strip_prefix(b"Pid:\t")
                .is_some_and(|value| value == pid_name.as_bytes())
        }) {
            return None;
        }
        let process = proc_directory(&procfs, &pid_name)?;
        let fd_dir = proc_directory(&process, c"fd")?;
        let start_ticks = process_start_ticks(&process, &pid_name)?;
        let dev = protected_descendants(root, &[c"dev"], 0).ok()?;
        let null = open_at(&dev, c"null", libc::O_PATH).ok()?;
        let node = stat(&null, None).ok()?;
        if node.st_mode & libc::S_IFMT != libc::S_IFCHR
            || node.st_uid != 0
            || node.st_rdev != libc::makedev(1, 3)
        {
            return None;
        }
        let sinks = Self {
            procfs,
            process,
            fd_dir,
            pidfd,
            pid_name,
            start_ticks,
            null,
        };
        sinks.is_current().then_some(sinks)
    }

    fn is_current(&self) -> bool {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd and no waiting. A pidfd becomes
        // readable when the task exits, including before it is reaped.
        (unsafe { libc::poll(&mut poll, 1, 0) == 0 })
            && process_start_ticks(&self.process, &self.pid_name) == Some(self.start_ticks)
            && stat(&self.process, None)
                .ok()
                .zip(stat(&self.procfs, Some(&self.pid_name)).ok())
                .is_some_and(|(held, named)| same_inode(&held, &named))
    }

    fn observe(&self) -> [bool; 2] {
        let Ok(null) = stat(&self.null, None) else {
            return [false; 2];
        };
        [c"1", c"2"].map(|number| {
            proc_magic_link(&self.fd_dir, number, 0)
                .and_then(|sink| stat(&sink, None).ok())
                .is_some_and(|sink| {
                    sink.st_mode & libc::S_IFMT == libc::S_IFCHR
                        && sink.st_rdev == null.st_rdev
                        && same_inode(&sink, &null)
                })
        })
    }
}

fn is_procfs(file: &File) -> bool {
    let mut output = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: output is writable and file holds a live descriptor.
    if unsafe { libc::fstatfs(file.as_raw_fd(), output.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: successful fstatfs initialized output.
    unsafe { output.assume_init() }.f_type as u64 == libc::PROC_SUPER_MAGIC as u64
}

fn proc_directory(parent: &File, name: &CStr) -> Option<File> {
    let file = open_at(parent, name, libc::O_PATH | libc::O_DIRECTORY).ok()?;
    is_procfs(&file).then_some(file)
}

fn proc_magic_link(parent: &File, name: &CStr, flags: libc::c_int) -> Option<File> {
    if !is_procfs(parent) {
        return None;
    }
    // SAFETY: this follows only fixed kernel-provided procfs magic links.
    // O_PATH pins the resolved inode without opening the device or file for I/O.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | flags,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: a successful openat returned a uniquely owned descriptor.
    Some(unsafe { File::from_raw_fd(fd) })
}

fn proc_bytes(parent: &File, name: &CStr) -> Option<Vec<u8>> {
    const LIMIT: u64 = 4096;
    let file = open_at(parent, name, libc::O_RDONLY).ok()?;
    if !is_procfs(&file) {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= LIMIT as usize).then_some(bytes)
}

fn process_start_ticks(process: &File, pid_name: &CStr) -> Option<u64> {
    let bytes = proc_bytes(process, c"stat")?;
    let record = bytes
        .strip_prefix(pid_name.to_bytes())?
        .strip_prefix(b" (")?;
    // The comm field can contain spaces, closing parentheses, and non-UTF-8.
    let comm_end = record.iter().rposition(|byte| *byte == b')')?;
    let mut fields = record
        .get(comm_end + 1..)?
        .strip_prefix(b" ")?
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let state = fields.next()?;
    if state.len() != 1 || matches!(state, b"Z" | b"X" | b"x") {
        return None;
    }
    // State is field 3, starttime is field 22.
    std::str::from_utf8(fields.nth(18)?).ok()?.parse().ok()
}

fn properties(bytes: &[u8]) -> Result<BTreeMap<String, String>, SystemdLoggingError> {
    let invalid = SystemdLoggingError::InvalidProperties;
    if bytes.len() > 16 * 1024 {
        return Err(invalid);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid)?;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        if line.bytes().any(|c| c < 32 || c == 127) {
            return Err(invalid);
        }
        let (key, value) = line.split_once('=').ok_or(invalid)?;
        if !PROPERTIES.split(',').any(|name| name == key)
            || value.len() > 4096
            || result.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(invalid);
        }
    }
    if result.len() != PROPERTIES.split(',').count() {
        return Err(invalid);
    }
    Ok(result)
}

fn parse(
    p: &BTreeMap<String, String>,
    pid: u32,
    invocation: u128,
) -> Result<SystemdLoggingObservation, SystemdLoggingError> {
    for (key, expected) in [
        ("Id", "nodomi-agent.service"),
        ("LoadState", "loaded"),
        ("FragmentPath", "/etc/systemd/system/nodomi-agent.service"),
        ("DropInPaths", ""),
        ("SourcePath", ""),
        ("Transient", "no"),
        ("NeedDaemonReload", "no"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("StandardInput", "null"),
    ] {
        if p[key] != expected {
            return Err(SystemdLoggingError::InvalidProperties);
        }
    }
    if p["MainPID"] != pid.to_string() || p["InvocationID"] != format!("{invocation:032x}") {
        return Err(SystemdLoggingError::WrongInvocation);
    }
    let interval = &p["LogRateLimitIntervalUSec"];
    if interval.is_empty() || interval.len() > 128 || !interval.is_ascii() {
        return Err(SystemdLoggingError::InvalidProperties);
    }
    let burst = &p["LogRateLimitBurst"];
    if burst.is_empty() || !burst.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SystemdLoggingError::InvalidProperties);
    }
    Ok(SystemdLoggingObservation {
        main_pid: pid,
        invocation_id: invocation,
        stdout: stream(&p["StandardOutput"]),
        stderr: stream(&p["StandardError"]),
        default_namespace: p["LogNamespace"].is_empty(),
        configured_interval: interval.clone(),
        configured_burst: burst
            .parse()
            .map_err(|_| SystemdLoggingError::InvalidProperties)?,
        live_null: [false; 2],
    })
}

fn stream(value: &str) -> ConfiguredLogStream {
    use ConfiguredLogStream::*;
    match value {
        "null" => Null,
        "inherit" => Inherit,
        "journal" => Journal,
        "journal+console" => JournalAndConsole,
        "kmsg" => Kernel,
        "kmsg+console" => KernelAndConsole,
        "tty" => Terminal,
        "socket" => Socket,
        "file" | "append" | "truncate" => File,
        "fd" => NamedDescriptor,
        _ if ["file:", "append:", "truncate:"]
            .iter()
            .any(|prefix| value.starts_with(prefix)) =>
        {
            File
        }
        _ if value.starts_with("fd:") => NamedDescriptor,
        _ => Unknown,
    }
}

#[cfg(test)]
#[path = "systemd_logging_tests.rs"]
mod tests;
