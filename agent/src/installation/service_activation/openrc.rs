use super::{
    ActivationError, ProtectedFile, classify_path_error, command, directory, exact_link, trusted,
};
use crate::installation::{
    layout::LayoutEntry,
    plan_store::{open_at, same_inode, same_snapshot, stat},
    service_readiness::{
        conf_fragments, openrc_runlevel_config, openrc_runtime, protected_descendants,
    },
};
use std::{
    ffi::CStr,
    fs::File,
    io::{self, Read},
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd},
    time::Duration,
};

pub(super) const NAME: &CStr = c"nodomi-agent";
pub(super) const TEMPLATE_PARENT: &[&CStr] = &[c"etc", c"init.d"];
const SCRIPT: &str = "/etc/init.d/nodomi-agent";
const SUPERVISOR: &str = "/opt/nodomi-agent/bin/nodomi-agent-supervisor";
const DAEMON_PID: &CStr = c"supervise-nodomi-agent.pid";
const TOOL_PARENT: &[&CStr] = &[c"sbin"];
const DEFAULT_RUNLEVEL: &[&CStr] = &[c"etc", c"runlevels", c"default"];
const SUPERVISOR_PARENT: &[&CStr] = &[c"opt", c"nodomi-agent", c"bin"];
const SUPERVISOR_NAME: &CStr = c"nodomi-agent-supervisor";

pub(super) struct OpenRc {
    service: ProtectedFile,
    update: ProtectedFile,
    runner: ProtectedFile,
    daemon: ProtectedFile,
    supervisor: ProtectedFile,
}

impl OpenRc {
    pub(super) fn prepare(root: &File) -> Result<Self, ActivationError> {
        check_configuration(root)?;
        let tool = |name| open_executable(root, TOOL_PARENT, name);
        Ok(Self {
            service: tool(c"rc-service")?,
            update: tool(c"rc-update")?,
            runner: tool(c"openrc-run")?,
            daemon: tool(c"supervise-daemon")?,
            supervisor: open_executable(root, SUPERVISOR_PARENT, SUPERVISOR_NAME)?,
        })
    }

    pub(super) fn recheck(&self, root: &File) -> Result<(), ActivationError> {
        check_configuration(root)?;
        for (file, name) in [
            (&self.service, c"rc-service"),
            (&self.update, c"rc-update"),
            (&self.runner, c"openrc-run"),
            (&self.daemon, c"supervise-daemon"),
        ] {
            file.recheck(root, TOOL_PARENT, name, 0)?;
        }
        self.supervisor
            .recheck(root, SUPERVISOR_PARENT, SUPERVISOR_NAME, 0)
    }

    pub(super) fn resolve_script(&self) -> Result<(), ActivationError> {
        let output = command::run(
            &self.service.file,
            &["rc-service", "--resolve", "nodomi-agent"],
            Duration::from_secs(5),
        )
        .map_err(|_| ActivationError::Unavailable)?;
        if output.strip_suffix(b"\n") != Some(SCRIPT.as_bytes()) {
            return Err(ActivationError::Blocked);
        }
        Ok(())
    }

    pub(super) fn enable(&self) -> Result<(), ActivationError> {
        command::run(
            &self.update.file,
            &["rc-update", "add", "nodomi-agent", "default"],
            Duration::from_secs(30),
        )
        .map(|_| ())
        .map_err(|_| ActivationError::OutcomeUnknown)
    }

    pub(super) fn start(&self) -> Result<(), ActivationError> {
        command::run(
            &self.service.file,
            &["rc-service", "--nodeps", SCRIPT, "start"],
            Duration::from_secs(30),
        )
        .map(|_| ())
        .map_err(|_| ActivationError::OutcomeUnknown)
    }

    pub(super) fn require_stopped(root: &File) -> Result<(), ActivationError> {
        Self::require_drained(root, false)
    }

    /// OpenRC 0.63 marks STOPPED, clears runtime state, then marks FAILED when
    /// its respawn limit is exhausted. Its next native start consumes that
    /// exact failure mark. All other live or stale entries remain conflicts.
    pub(super) fn require_drained(root: &File, allow_failed: bool) -> Result<(), ActivationError> {
        let runtime = openrc_runtime(root, 0).map_err(layout_error)?;
        for state in [
            c"started",
            c"starting",
            c"stopping",
            c"inactive",
            c"options",
            c"daemons",
            c"exclusive",
            c"init.d",
            c"wasinactive",
            c"hotplugged",
        ] {
            absent_below(&runtime, &[state], NAME)?;
        }
        if allow_failed {
            absent_below(&runtime, &[], c"rc.starting")?;
            absent_below(&runtime, &[], c"rc.stopping")?;
            if let Some(failed) = protected_child_if_present(&runtime, c"failed")? {
                exact_link_if_present(&failed, NAME, &[SCRIPT.as_bytes()])?;
            }
        } else {
            absent_below(&runtime, &[c"failed"], NAME)?;
        }
        absent_below(&runtime, &[], c"supervise-nodomi-agent.ctl")?;
        absent(root, &[c"run"], DAEMON_PID)
    }

    pub(super) fn cold_enabled(root: &File, allow_disabled: bool) -> Result<bool, ActivationError> {
        let runtime = openrc_runtime(root, 0).map_err(layout_error)?;
        if openrc_runlevel_config(&runtime, 0).as_deref() != Some(c"nodomi-agent.default") {
            return Err(ActivationError::Unavailable);
        }
        absent_below(&runtime, &[], c"rc.starting")?;
        absent_below(&runtime, &[], c"rc.stopping")?;
        let level = directory(root, DEFAULT_RUNLEVEL, 0)?;
        let enabled = exact_link_if_present(
            &level,
            NAME,
            &[SCRIPT.as_bytes(), b"../../init.d/nodomi-agent"],
        )?;
        if !enabled && !allow_disabled {
            return Err(ActivationError::Blocked);
        }
        Self::require_drained(root, enabled)?;
        Ok(enabled)
    }

    pub(super) fn enabled_link(root: &File, sync: bool) -> Result<(), ActivationError> {
        let level = directory(root, DEFAULT_RUNLEVEL, 0)?;
        exact_link(
            &level,
            NAME,
            &[SCRIPT.as_bytes(), b"../../init.d/nodomi-agent"],
        )?;
        if sync {
            let parent = directory(root, &[c"etc", c"runlevels"], 0)?;
            level
                .sync_all()
                .and_then(|()| parent.sync_all())
                .map_err(|_| ActivationError::OutcomeUnknown)?;
        }
        Ok(())
    }

    pub(super) fn observe(&self, root: &File) -> Result<(u32, u128), ActivationError> {
        let runtime = openrc_runtime(root, 0).map_err(layout_error)?;
        let started = protected_descendants(&runtime, &[c"started"], 0).map_err(layout_error)?;
        exact_link(&started, NAME, &[SCRIPT.as_bytes()])?;
        for state in [c"starting", c"stopping", c"inactive", c"failed"] {
            absent_below(&runtime, &[state], NAME)?;
        }
        let options =
            protected_descendants(&runtime, &[c"options", NAME], 0).map_err(layout_error)?;
        let run = directory(root, &[c"run"], 0)?;
        let child_pid = read_pid(&options, c"child_pid")?;
        let daemon_pid = read_pid(&run, DAEMON_PID)?;
        for (name, value) in [
            (c"exec", SUPERVISOR.as_bytes()),
            (c"argv_0", SUPERVISOR.as_bytes()),
            (c"argc", &b"1"[..]),
            (c"pidfile", &b"/var/run/supervise-nodomi-agent.pid"[..]),
        ] {
            if read_record(&options, name, 128)? != value {
                return Err(ActivationError::Blocked);
            }
        }

        let procfs = proc_directory(root)?;
        let daemon = Process::observe(&procfs, daemon_pid, &self.daemon)?;
        let child = Process::observe(&procfs, child_pid, &self.supervisor)?;
        let mut daemon_args = daemon.argv.split(|byte| *byte == 0);
        if child.parent != daemon_pid
            || !matches!(
                daemon_args.next(),
                Some(b"supervise-daemon" | b"/sbin/supervise-daemon")
            )
            || daemon_args.next() != Some(b"nodomi-agent")
            || daemon_args.next() != Some(b"--start")
            || child.argv.strip_suffix(b"\0") != Some(SUPERVISOR.as_bytes())
            || read_pid(&options, c"child_pid")? != child_pid
            || read_pid(&run, DAEMON_PID)? != daemon_pid
        {
            return Err(ActivationError::Blocked);
        }
        exact_link(&started, NAME, &[SCRIPT.as_bytes()])?;
        let epoch = (u128::from(daemon.ticks) << 64) | u128::from(child.ticks);
        Ok((child_pid, epoch))
    }
}

fn open_executable(
    root: &File,
    parents: &[&CStr],
    name: &CStr,
) -> Result<ProtectedFile, ActivationError> {
    ProtectedFile::open(root, parents, name, 0, libc::O_PATH, |info| {
        info.st_mode & 0o7100 == 0o100
    })
}

pub(super) fn check_configuration(root: &File) -> Result<(), ActivationError> {
    let runtime = openrc_runtime(root, 0).map_err(layout_error)?;
    let level = openrc_runlevel_config(&runtime, 0).ok_or(ActivationError::Unavailable)?;
    for conf in [NAME, c"nodomi-agent.default", &level] {
        absent(root, &[c"etc", c"conf.d"], conf)?;
    }
    match conf_fragments(root, &[c"etc", c"rc.conf.d"], 0) {
        Some(false) => {}
        Some(true) => return Err(ActivationError::Blocked),
        None => return Err(ActivationError::Unavailable),
    }
    // openrc-run sources this extra shell file only on a live system image.
    absent(root, TOOL_PARENT, c"livecd-functions.sh")?;
    let var = directory(root, &[c"var"], 0)?;
    exact_link(&var, c"run", &[b"../run", b"/run"])?;
    let etc = directory(root, &[c"etc"], 0)?;
    match stat(&etc, Some(c"rc.conf")) {
        Ok(_) => {
            if !global_config_is_safe(&read_record(&etc, c"rc.conf", 64 * 1024)?) {
                return Err(ActivationError::Blocked);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(classify_path_error(error)),
    }
    Ok(())
}

fn layout_error(error: LayoutEntry) -> ActivationError {
    if error == LayoutEntry::Unsafe {
        ActivationError::Blocked
    } else {
        ActivationError::Unavailable
    }
}

fn absent(root: &File, parents: &[&CStr], name: &CStr) -> Result<(), ActivationError> {
    directory(root, &[], 0)?;
    absent_below(root, parents, name)
}

fn absent_below(anchor: &File, parents: &[&CStr], name: &CStr) -> Result<(), ActivationError> {
    let parent = match protected_descendants(anchor, parents, 0) {
        Ok(parent) => parent,
        Err(LayoutEntry::Missing) => return Ok(()),
        Err(error) => return Err(layout_error(error)),
    };
    match stat(&parent, Some(name)) {
        Ok(_) => Err(ActivationError::Blocked),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(classify_path_error(error)),
    }
}

fn protected_child_if_present(anchor: &File, name: &CStr) -> Result<Option<File>, ActivationError> {
    match protected_descendants(anchor, &[name], 0) {
        Ok(directory) => Ok(Some(directory)),
        Err(LayoutEntry::Missing) => Ok(None),
        Err(error) => Err(layout_error(error)),
    }
}

fn exact_link_if_present(
    parent: &File,
    name: &CStr,
    allowed: &[&[u8]],
) -> Result<bool, ActivationError> {
    match stat(parent, Some(name)) {
        Ok(_) => exact_link(parent, name, allowed).map(|()| true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(classify_path_error(error)),
    }
}

fn read_record(parent: &File, name: &CStr, limit: usize) -> Result<Vec<u8>, ActivationError> {
    let named = stat(parent, Some(name)).map_err(classify_path_error)?;
    if !trusted(&named, 0, libc::S_IFREG)
        || named.st_nlink != 1
        || !(0..=limit as libc::off_t).contains(&named.st_size)
    {
        return Err(ActivationError::Blocked);
    }
    let file = open_at(parent, name, libc::O_RDONLY).map_err(classify_path_error)?;
    let opened = stat(&file, None).map_err(classify_path_error)?;
    if !same_snapshot(&named, &opened) {
        return Err(ActivationError::Blocked);
    }
    let bytes = read_bounded(&file, limit)?;
    if bytes.len() != named.st_size as usize
        || !same_snapshot(&named, &stat(&file, None).map_err(classify_path_error)?)
        || !same_snapshot(
            &named,
            &stat(parent, Some(name)).map_err(classify_path_error)?,
        )
    {
        return Err(ActivationError::Blocked);
    }
    Ok(bytes)
}

fn read_bounded(file: &File, limit: usize) -> Result<Vec<u8>, ActivationError> {
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(classify_path_error)?;
    if bytes.len() > limit {
        return Err(ActivationError::Unavailable);
    }
    Ok(bytes)
}

fn read_pid(parent: &File, name: &CStr) -> Result<u32, ActivationError> {
    let raw = read_record(parent, name, 16)?;
    let raw = raw.strip_suffix(b"\n").unwrap_or(&raw);
    let pid = std::str::from_utf8(raw)
        .ok()
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| (2..=i32::MAX as u32).contains(value));
    pid.ok_or(ActivationError::Blocked)
}

fn proc_directory(root: &File) -> Result<File, ActivationError> {
    let proc = directory(root, &[c"proc"], 0)?;
    let mut metadata = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the descriptor is live and output points to writable statfs storage.
    if unsafe { libc::fstatfs(proc.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(ActivationError::Unavailable);
    }
    // SAFETY: fstatfs initialized metadata on success.
    if unsafe { metadata.assume_init() }.f_type as u64 != libc::PROC_SUPER_MAGIC as u64 {
        return Err(ActivationError::Blocked);
    }
    Ok(proc)
}

struct Process {
    parent: u32,
    ticks: u64,
    argv: Vec<u8>,
}

impl Process {
    fn observe(proc: &File, pid: u32, executable: &ProtectedFile) -> Result<Self, ActivationError> {
        let name =
            std::ffi::CString::new(pid.to_string()).map_err(|_| ActivationError::Unavailable)?;
        let process = directory(proc, &[&name], 0)?;
        let before = proc_stat(&process, pid)?;
        // SAFETY: after checking procfs, follow its kernel-provided exe link
        // from this already-open process directory and pin the resulting inode.
        let fd = unsafe {
            libc::openat(
                process.as_raw_fd(),
                c"exe".as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(ActivationError::Unavailable);
        }
        // SAFETY: a successful openat returns a uniquely owned fd.
        let image = unsafe { File::from_raw_fd(fd) };
        if !same_inode(
            &executable.snapshot,
            &stat(&image, None).map_err(classify_path_error)?,
        ) {
            return Err(ActivationError::Blocked);
        }
        let status = proc_bytes(&process, c"status", 16 * 1024)?;
        let status = std::str::from_utf8(&status).map_err(|_| ActivationError::Unavailable)?;
        if !status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .is_some_and(|uids| uids.split_ascii_whitespace().eq(["0", "0", "0", "0"]))
        {
            return Err(ActivationError::Blocked);
        }
        let argv = proc_bytes(&process, c"cmdline", 4096)?;
        if before != proc_stat(&process, pid)? {
            return Err(ActivationError::Unavailable);
        }
        Ok(Self {
            parent: before.0,
            ticks: before.1,
            argv,
        })
    }
}

fn proc_bytes(process: &File, name: &CStr, limit: usize) -> Result<Vec<u8>, ActivationError> {
    let file = open_at(process, name, libc::O_RDONLY).map_err(classify_path_error)?;
    read_bounded(&file, limit)
}

fn proc_stat(process: &File, pid: u32) -> Result<(u32, u64), ActivationError> {
    let bytes = proc_bytes(process, c"stat", 4096)?;
    process_epoch(&bytes, pid).ok_or(ActivationError::Unavailable)
}

fn process_epoch(bytes: &[u8], pid: u32) -> Option<(u32, u64)> {
    let stat = std::str::from_utf8(bytes).ok()?;
    let (head, tail) = stat.rsplit_once(") ")?;
    let (number, _) = head.split_once(" (")?;
    if number.parse::<u32>().ok()? != pid {
        return None;
    }
    let mut fields = tail.split_ascii_whitespace();
    if matches!(fields.next()?, "Z" | "X" | "x") {
        return None;
    }
    let parent = fields.next()?.parse().ok()?;
    let ticks = fields.nth(17)?.parse::<u64>().ok()?;
    (ticks > 0).then_some((parent, ticks))
}

pub(super) fn fixed_template(bytes: &[u8]) -> bool {
    let Ok(text) = shell_text(bytes) else {
        return false;
    };
    let Some(body) = text.strip_prefix("#!/sbin/openrc-run\n") else {
        return false;
    };
    let expected = [
        ("description", "Nodomi Agent supervisor"),
        ("supervisor", "supervise-daemon"),
        ("command", SUPERVISOR),
        ("command_user", "root:root"),
        ("command_args", ""),
        ("command_args_foreground", ""),
        ("retry", "TERM/10/KILL/5"),
        ("respawn_delay", "2"),
        ("respawn_max", "3"),
        ("respawn_period", "30"),
    ];
    let mut present = [false; 10];
    for line in active_lines(body) {
        let Some(assignment) = scalar_assignment(line) else {
            return false;
        };
        let Some(index) = expected.iter().position(|entry| *entry == assignment) else {
            return false;
        };
        if std::mem::replace(&mut present[index], true) {
            return false;
        }
    }
    present.into_iter().all(|item| item)
}

fn global_config_is_safe(bytes: &[u8]) -> bool {
    let Ok(text) = shell_text(bytes) else {
        return false;
    };
    active_lines(text).all(|line| {
        let Some((name, value)) = scalar_assignment(line) else {
            return false;
        };
        match name {
            // Packaged Alpine defaults. The service template sets its own respawn policy.
            "rc_tty_number" | "respawn_delay" | "respawn_max" | "respawn_period" => {
                !value.is_empty()
                    && value.bytes().all(|byte| byte.is_ascii_digit())
                    && value.parse::<u32>().is_ok()
            }
            // Runlevel presentation and scheduling options do not change this service's command.
            "rc_verbose" | "rc_parallel" | "rc_interactive" | "rc_depend_strict" | "rc_logger"
            | "rc_autostart_user" => ["yes", "no", "true", "false", "on", "off", "1", "0"]
                .iter()
                .any(|option| value.eq_ignore_ascii_case(option)),
            _ => false,
        }
    })
}

fn shell_text(bytes: &[u8]) -> Result<&str, ()> {
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    if text
        .bytes()
        .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t'))
    {
        return Err(());
    }
    Ok(text)
}

fn active_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(|line| line.trim_matches([' ', '\t']))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

fn scalar_assignment(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once('=')?;
    let (value, suffix) = match value.as_bytes().first() {
        Some(b'\'' | b'"') => {
            let quote = value.as_bytes()[0] as char;
            value[1..].split_once(quote)?
        }
        _ => {
            let index = value.find([' ', '\t']).unwrap_or(value.len());
            value.split_at(index)
        }
    };
    if !suffix.is_empty()
        && (!suffix.starts_with([' ', '\t'])
            || !suffix.trim_start_matches([' ', '\t']).starts_with('#'))
    {
        return None;
    }
    Some((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpine_packaged_config_accepts_stock_and_safe_scalar_settings() {
        assert!(global_config_is_safe(b"# alpine config\nrc_tty_number=12\nrespawn_delay=2\nrespawn_max=5\nrespawn_period=1800\nrc_verbose=\"NO\" # comment\nrc_parallel='YES'\n"));
    }

    #[test]
    fn shell_and_material_global_overrides_are_refused() {
        for conf in [
            "command=/untrusted",
            "directory=/untrusted",
            "supervise_daemon_args='--pidfile /untrusted'",
            "rc_ulimit='$(touch /untrusted)'",
            "rc_verbose=\"$(touch /untrusted)\"",
            "rc_parallel=YES; touch /untrusted",
            "rc_parallel=YES # comment\nstart_pre() { :; }",
            "rc_parallel=YES \\nrc_verbose=NO",
            "rc_verbose=\"NO\" # ignored\r. /tmp/x",
        ] {
            assert!(!global_config_is_safe(conf.as_bytes()), "{conf:?}");
        }
    }
}
