//! Read-only observations for the fixed first-install service destinations.
use super::{
    host::{ServiceManagerObservation, inspect_host},
    layout::{LayoutEntry, open_root},
    plan_store::{open_at, same_snapshot, stat},
};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read},
    os::fd::{AsRawFd, IntoRawFd},
};

const SYSTEMD_UNIT: &CStr = c"nodomi-agent.service";
const OPENRC_SERVICE: &CStr = c"nodomi-agent";
const SYSTEMD_PARENT: &[&CStr] = &[c"etc", c"systemd", c"system"];
const OPENRC_PARENT: &[&CStr] = &[c"etc", c"init.d"];

#[derive(Debug)]
pub(super) struct ServiceReadiness {
    pub(super) destination: ServiceDestination,
    pub(super) manager: ManagerReadiness,
}

#[derive(Debug)]
pub(super) enum ServiceDestination {
    /// The parent is pinned and supports directory sync. Publication must
    /// still use no-replace semantics and recheck the current namespace.
    Missing {
        parent: File,
        name: &'static CStr,
    },
    Existing,
    Unsafe,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ManagerReadiness {
    /// Matching host markers and the fixed local interface were observed.
    /// The effective configuration still requires verification before start.
    InterfaceObserved,
    Conflict,
    Unknown,
}

pub(super) fn inspect_service_readiness(expected: ServiceManagerObservation) -> ServiceReadiness {
    let Ok(root) = open_root() else {
        return unavailable();
    };
    inspect_at(&root, 0, expected, inspect_host().service_manager)
}

fn unavailable() -> ServiceReadiness {
    ServiceReadiness {
        destination: ServiceDestination::Unavailable,
        manager: ManagerReadiness::Unknown,
    }
}

pub(super) fn inspect_at(
    root: &File,
    owner: libc::uid_t,
    expected: ServiceManagerObservation,
    observed: ServiceManagerObservation,
) -> ServiceReadiness {
    use ServiceManagerObservation::{OpenRc, Systemd};
    let (parents, name) = match expected {
        Systemd => (SYSTEMD_PARENT, SYSTEMD_UNIT),
        OpenRc => (OPENRC_PARENT, OPENRC_SERVICE),
        _ => return unavailable(),
    };
    let destination = inspect_destination(root, owner, parents, name);
    let manager = match (expected, observed) {
        (Systemd, Systemd) => systemd(root, owner, false),
        (OpenRc, OpenRc) => openrc(root, owner, false),
        (Systemd, OpenRc) | (OpenRc, Systemd) => ManagerReadiness::Conflict,
        _ => ManagerReadiness::Unknown,
    };
    ServiceReadiness {
        destination,
        manager,
    }
}

/// The recovery owner verifies the exact original enablement and drained
/// runtime separately. Source and override probes still apply.
pub(super) fn inspect_service_recovery(
    root: &File,
    owner: libc::uid_t,
    manager: ServiceManagerObservation,
) -> ServiceReadiness {
    match manager {
        ServiceManagerObservation::Systemd => ServiceReadiness {
            destination: inspect_destination(root, owner, SYSTEMD_PARENT, SYSTEMD_UNIT),
            manager: systemd(root, owner, true),
        },
        ServiceManagerObservation::OpenRc => ServiceReadiness {
            destination: inspect_destination(root, owner, OPENRC_PARENT, OPENRC_SERVICE),
            manager: openrc(root, owner, true),
        },
        _ => unavailable(),
    }
}

fn inspect_destination(
    root: &File,
    owner: libc::uid_t,
    components: &[&CStr],
    name: &'static CStr,
) -> ServiceDestination {
    let parent = match directory(root, components, owner) {
        Ok(parent) => parent,
        Err(LayoutEntry::Unsafe) => return ServiceDestination::Unsafe,
        Err(_) => return ServiceDestination::Unavailable,
    };
    match stat(&parent, Some(name)) {
        Ok(info) if trusted_type(&info, owner, libc::S_IFREG) && info.st_nlink == 1 => {
            ServiceDestination::Existing
        }
        Ok(_) => ServiceDestination::Unsafe,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            ServiceDestination::Missing { parent, name }
        }
        Err(_) => ServiceDestination::Unavailable,
    }
}

fn directory(root: &File, components: &[&CStr], owner: libc::uid_t) -> Result<File, LayoutEntry> {
    check_directory(root, owner)?;
    protected_descendants(root, components, owner)
}

/// The caller has already checked the anchor directory. Descendants retain
/// the ordinary no-symlink and no group/other write requirements.
pub(super) fn protected_descendants(
    anchor: &File,
    components: &[&CStr],
    owner: libc::uid_t,
) -> Result<File, LayoutEntry> {
    let mut current = anchor.try_clone().map_err(|_| LayoutEntry::Unavailable)?;
    for component in components {
        current =
            open_at(&current, component, libc::O_RDONLY | libc::O_DIRECTORY).map_err(|error| {
                match error.raw_os_error() {
                    Some(libc::ENOENT) => LayoutEntry::Missing,
                    Some(libc::ENOTDIR | libc::ELOOP) => LayoutEntry::Unsafe,
                    _ => LayoutEntry::Unavailable,
                }
            })?;
        check_directory(&current, owner)?;
    }
    Ok(current)
}

fn check_directory(directory: &File, owner: libc::uid_t) -> Result<(), LayoutEntry> {
    let info = stat(directory, None).map_err(|_| LayoutEntry::Unavailable)?;
    if trusted_type(&info, owner, libc::S_IFDIR) {
        Ok(())
    } else {
        Err(LayoutEntry::Unsafe)
    }
}

fn trusted_type(info: &libc::stat, owner: libc::uid_t, kind: libc::mode_t) -> bool {
    info.st_mode & libc::S_IFMT == kind && info.st_uid == owner && info.st_mode & 0o022 == 0
}

fn entry(
    root: &File,
    parents: &[&CStr],
    name: &CStr,
    owner: libc::uid_t,
) -> Result<Option<libc::stat>, LayoutEntry> {
    check_directory(root, owner)?;
    entry_below(root, parents, name, owner)
}

fn entry_below(
    anchor: &File,
    parents: &[&CStr],
    name: &CStr,
    owner: libc::uid_t,
) -> Result<Option<libc::stat>, LayoutEntry> {
    let parent = match protected_descendants(anchor, parents, owner) {
        Ok(parent) => parent,
        Err(LayoutEntry::Missing) => return Ok(None),
        Err(error) => return Err(error),
    };
    match stat(&parent, Some(name)) {
        Ok(info) => Ok(Some(info)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(LayoutEntry::Unavailable),
    }
}

fn occupied(root: &File, parents: &[&CStr], name: &CStr, owner: libc::uid_t) -> Option<bool> {
    entry(root, parents, name, owner)
        .ok()
        .map(|entry| entry.is_some())
}

fn executable(root: &File, parents: &[&CStr], name: &CStr, owner: libc::uid_t) -> bool {
    entry(root, parents, name, owner)
        .ok()
        .flatten()
        .is_some_and(|info| trusted_type(&info, owner, libc::S_IFREG) && info.st_mode & 0o100 != 0)
}

fn classify_manager(
    interface: bool,
    probes: impl IntoIterator<Item = Option<bool>>,
) -> ManagerReadiness {
    let mut complete = interface;
    for probe in probes {
        match probe {
            Some(true) => return ManagerReadiness::Conflict,
            None => complete = false,
            Some(false) => {}
        }
    }
    if complete {
        ManagerReadiness::InterfaceObserved
    } else {
        ManagerReadiness::Unknown
    }
}

fn systemd(
    root: &File,
    owner: libc::uid_t,
    inspect_enablement_separately: bool,
) -> ManagerReadiness {
    const UNIT_PATHS: &[&[&CStr]] = &[
        SYSTEMD_PARENT,
        &[c"etc", c"systemd", c"system.control"],
        &[c"etc", c"systemd", c"system.attached"],
        &[c"run", c"systemd", c"system"],
        &[c"run", c"systemd", c"system.control"],
        &[c"run", c"systemd", c"system.attached"],
        &[c"run", c"systemd", c"transient"],
        &[c"run", c"systemd", c"generator.early"],
        &[c"run", c"systemd", c"generator"],
        &[c"run", c"systemd", c"generator.late"],
        &[c"usr", c"local", c"lib", c"systemd", c"system"],
        &[c"usr", c"lib", c"systemd", c"system"],
    ];
    let socket = entry(root, &[c"run", c"systemd"], c"private", owner)
        .ok()
        .flatten()
        .is_some_and(|info| trusted_type(&info, owner, libc::S_IFSOCK));
    let marker = directory(root, &[c"run", c"systemd", c"system"], owner).is_ok();
    let interface = marker && socket && executable(root, &[c"usr", c"bin"], c"systemctl", owner);

    let standard = UNIT_PATHS
        .iter()
        .flat_map(|parents| systemd_unit_path(root, parents, owner));
    // Debian can use /lib/systemd/system. On merged-/usr systems recognize
    // only the standard alias and inspect its canonical path independently.
    let legacy = (!merged_lib_alias(root, owner))
        .then(|| systemd_unit_path(root, &[c"lib", c"systemd", c"system"], owner))
        .into_iter()
        .flatten();
    let enable_link = if inspect_enablement_separately {
        Some(false)
    } else {
        occupied(
            root,
            &[c"etc", c"systemd", c"system", c"multi-user.target.wants"],
            SYSTEMD_UNIT,
            owner,
        )
    };
    classify_manager(interface, standard.chain(legacy).chain([enable_link]))
}

fn systemd_unit_path(root: &File, parents: &[&CStr], owner: libc::uid_t) -> [Option<bool>; 4] {
    let mut probes = [Some(false); 4];
    if parents != SYSTEMD_PARENT {
        probes[0] = occupied(root, parents, SYSTEMD_UNIT, owner);
    }
    for (probe, drop_in) in probes[1..].iter_mut().zip([
        c"nodomi-agent.service.d",
        c"nodomi-.service.d",
        c"service.d",
    ]) {
        let mut path = parents.to_vec();
        path.push(drop_in);
        *probe = conf_fragments(root, &path, owner);
    }
    probes
}

fn merged_lib_alias(root: &File, owner: libc::uid_t) -> bool {
    let Ok(Some(link)) = entry(root, &[], c"lib", owner) else {
        return false;
    };
    if link.st_mode & libc::S_IFMT != libc::S_IFLNK || link.st_uid != owner {
        return false;
    }
    let mut target = [0_u8; 16];
    // SAFETY: root is live and the bounded buffer is writable. readlinkat
    // reports the link contents without opening or traversing the target.
    let count = unsafe {
        libc::readlinkat(
            root.as_raw_fd(),
            c"lib".as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    matches!(
        usize::try_from(count)
            .ok()
            .and_then(|count| target.get(..count)),
        Some(b"usr/lib" | b"/usr/lib")
    )
}

pub(super) fn conf_fragments(root: &File, parents: &[&CStr], owner: libc::uid_t) -> Option<bool> {
    let directory = match directory(root, parents, owner) {
        Ok(directory) => directory,
        Err(LayoutEntry::Missing) => return Some(false),
        Err(_) => return None,
    };
    let fd = directory.into_raw_fd();
    // SAFETY: fd is a fresh, owned directory descriptor. The stream takes
    // ownership on success, and the caller retains ownership on failure.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and did not consume the owned descriptor.
        unsafe { libc::close(fd) };
        return None;
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: this guard owns the only reference to the directory stream.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(stream);
    for _ in 0..4096 {
        // SAFETY: errno is thread-local and the stream is live and exclusive.
        let item = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream.0)
        };
        if item.is_null() {
            return (io::Error::last_os_error().raw_os_error() == Some(0)).then_some(false);
        }
        // SAFETY: a nonnull item has a NUL-terminated name valid until the next read.
        let name = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) };
        if name.to_bytes().ends_with(b".conf") {
            return Some(true);
        }
    }
    None
}

fn openrc(root: &File, owner: libc::uid_t, inspect_state_separately: bool) -> ManagerReadiness {
    let runtime = openrc_runtime(root, owner);
    let runlevel = runtime
        .as_ref()
        .ok()
        .and_then(|runtime| openrc_runlevel_config(runtime, owner));
    // These files are sourced as shell code. A host-level fragment is not
    // by itself an agent-specific conflict, and its effect is unknown here.
    let host_fragments = conf_fragments(root, &[c"etc", c"rc.conf.d"], owner);
    let host_config = match entry(root, &[c"etc"], c"rc.conf", owner) {
        Ok(None) => true,
        Ok(Some(info)) => trusted_type(&info, owner, libc::S_IFREG),
        Err(_) => false,
    };
    let interface = runlevel.is_some()
        && host_fragments == Some(false)
        && host_config
        && directory(root, &[c"etc", c"runlevels", c"default"], owner).is_ok()
        && [
            c"rc-service",
            c"rc-update",
            c"openrc-run",
            c"supervise-daemon",
        ]
        .into_iter()
        .all(|tool| executable(root, &[c"sbin"], tool, owner));
    let locations: &[&[&CStr]] = &[&[c"usr", c"local", c"etc", c"init.d"], &[c"etc", c"conf.d"]];
    let service = locations
        .iter()
        .map(|parents| occupied(root, parents, OPENRC_SERVICE, owner));
    let default_conf = occupied(root, &[c"etc", c"conf.d"], c"nodomi-agent.default", owner);
    let runtime_conf =
        runlevel.and_then(|runlevel| occupied(root, &[c"etc", c"conf.d"], &runlevel, owner));
    let runtime_entries = [c"started", c"starting", c"inactive", c"stopping", c"init.d"]
        .into_iter()
        .filter(|_| !inspect_state_separately)
        .map(|name| {
            entry_below(runtime.as_ref().ok()?, &[name], OPENRC_SERVICE, owner)
                .ok()
                .map(|entry| entry.is_some())
        });
    classify_manager(
        interface,
        service.chain(runtime_entries).chain([
            default_conf,
            runtime_conf,
            if inspect_state_separately {
                Some(false)
            } else {
                occupied(
                    root,
                    &[c"etc", c"runlevels", c"default"],
                    OPENRC_SERVICE,
                    owner,
                )
            },
        ]),
    )
}

pub(super) fn openrc_runtime(root: &File, owner: libc::uid_t) -> Result<File, LayoutEntry> {
    let run = directory(root, &[c"run"], owner)?;
    let runtime = open_at(&run, c"openrc", libc::O_RDONLY | libc::O_DIRECTORY).map_err(
        |error| match error.raw_os_error() {
            Some(libc::ENOENT) => LayoutEntry::Missing,
            Some(libc::ENOTDIR | libc::ELOOP) => LayoutEntry::Unsafe,
            _ => LayoutEntry::Unavailable,
        },
    )?;
    let info = stat(&runtime, None).map_err(|_| LayoutEntry::Unavailable)?;
    if trusted_type(&info, owner, libc::S_IFDIR) {
        return Ok(runtime);
    }
    // Alpine creates this one directory as root:root 0775. Validate the
    // local root group and its locked maintenance accounts before treating
    // this directory as root-controlled. Named ACLs can grant other access.
    if owner == 0
        && info.st_uid == 0
        && info.st_gid == 0
        && info.st_mode & 0o7777 == 0o775
        && no_acl(&runtime, c"system.posix_acl_access")
        && no_acl(&runtime, c"system.posix_acl_default")
        && private_root_group(root)
    {
        return Ok(runtime);
    }
    Err(LayoutEntry::Unsafe)
}

fn no_acl(directory: &File, name: &CStr) -> bool {
    // SAFETY: directory is live; null with zero length queries the xattr size.
    let size = unsafe {
        libc::fgetxattr(
            directory.as_raw_fd(),
            name.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    size < 0
        && matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENODATA | libc::ENOTSUP)
        )
}

fn private_root_group(root: &File) -> bool {
    let Some(group) = account_file(root, c"group") else {
        return false;
    };
    let mut root_groups = group.lines().filter_map(|line| {
        let fields: Vec<_> = line.split(':').collect();
        (fields.len() == 4 && fields[2].parse::<u32>() == Ok(0)).then_some(fields)
    });
    let Some(record) = root_groups.next() else {
        return false;
    };
    if root_groups.next().is_some()
        || record[0] != "root"
        || !matches!(record[1], "x" | "!" | "*")
        || !matches!(record[3], "" | "root")
    {
        return false;
    }
    let Some(passwd) = account_file(root, c"passwd") else {
        return false;
    };
    let mut locked = Vec::new();
    for line in passwd.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7
            || fields[2].parse::<u32>().is_err()
            || fields[3].parse::<u32>().is_err()
        {
            return false;
        }
        if fields[3].parse::<u32>() != Ok(0) || fields[2].parse::<u32>() == Ok(0) {
            continue;
        }
        if !matches!(
            (fields[0], fields[2], fields[6]),
            ("sync", "5", "/bin/sync")
                | ("shutdown", "6", "/sbin/shutdown")
                | ("halt", "7", "/sbin/halt")
        ) || locked.contains(&fields[0])
        {
            return false;
        }
        match fields[1] {
            "x" => locked.push(fields[0]),
            "!" | "*" => {}
            _ => return false,
        }
    }
    if locked.is_empty() {
        return true;
    }
    let Some(shadow) = account_file(root, c"shadow") else {
        return false;
    };
    locked.into_iter().all(|account| {
        let mut passwords = shadow.lines().filter_map(|line| {
            let mut fields = line.split(':');
            (fields.next() == Some(account))
                .then(|| fields.next())
                .flatten()
        });
        matches!(passwords.next(), Some("!" | "*" | "!!")) && passwords.next().is_none()
    })
}

fn account_file(root: &File, name: &CStr) -> Option<String> {
    const LIMIT: u64 = 256 * 1024;
    let etc = directory(root, &[c"etc"], 0).ok()?;
    let named = stat(&etc, Some(name)).ok()?;
    if !trusted_type(&named, 0, libc::S_IFREG)
        || !(1..=LIMIT as libc::off_t).contains(&named.st_size)
    {
        return None;
    }
    let file = open_at(&etc, name, libc::O_RDONLY).ok()?;
    let mut contents = String::new();
    if !same_snapshot(&named, &stat(&file, None).ok()?)
        || (&file).take(LIMIT + 1).read_to_string(&mut contents).ok()?
            != usize::try_from(named.st_size).ok()?
        || !same_snapshot(&named, &stat(&file, None).ok()?)
        || !same_snapshot(&named, &stat(&etc, Some(name)).ok()?)
    {
        return None;
    }
    Some(contents)
}

pub(super) fn openrc_runlevel_config(parent: &File, owner: libc::uid_t) -> Option<CString> {
    let named = stat(parent, Some(c"softlevel")).ok()?;
    if !trusted_type(&named, owner, libc::S_IFREG) || !(1..=64).contains(&named.st_size) {
        return None;
    }
    let file = open_at(parent, c"softlevel", libc::O_RDONLY).ok()?;
    let opened = stat(&file, None).ok()?;
    if !same_snapshot(&named, &opened) {
        return None;
    }
    let mut bytes = Vec::new();
    (&file).take(65).read_to_end(&mut bytes).ok()?;
    if bytes.len() != usize::try_from(opened.st_size).ok()?
        || !same_snapshot(&opened, &stat(&file, None).ok()?)
        || !same_snapshot(&opened, &stat(parent, Some(c"softlevel")).ok()?)
    {
        return None;
    }
    let runlevel = std::str::from_utf8(&bytes).ok()?.trim_end_matches('\n');
    if runlevel.is_empty()
        || !runlevel
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return None;
    }
    CString::new(format!("nodomi-agent.{runlevel}")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ServiceManagerObservation::{Ambiguous, OpenRc, Systemd};
    use std::{
        fs,
        os::unix::{
            fs::{MetadataExt, PermissionsExt, symlink},
            net::UnixListener,
        },
        path::Path,
    };

    struct Fixture {
        temporary: tempfile::TempDir,
        root: File,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root = File::open(temporary.path()).unwrap();
            Self { temporary, root }
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.temporary.path().join(name)
        }

        fn write(&self, name: &str, bytes: &[u8], mode: u32) {
            let path = self.path(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }

        fn systemd(&self) -> UnixListener {
            fs::create_dir_all(self.path("etc/systemd/system")).unwrap();
            fs::create_dir_all(self.path("run/systemd/system")).unwrap();
            self.write("usr/bin/systemctl", b"synthetic executable", 0o755);
            let socket = self.path("run/systemd/private");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).unwrap();
            listener
        }

        fn openrc(&self) {
            fs::create_dir_all(self.path("etc/init.d")).unwrap();
            fs::create_dir_all(self.path("etc/runlevels/default")).unwrap();
            self.write("run/openrc/softlevel", b"default\n", 0o644);
            for tool in ["rc-service", "rc-update", "openrc-run", "supervise-daemon"] {
                self.write(&format!("sbin/{tool}"), b"synthetic executable", 0o755);
            }
        }

        fn inspect(&self, manager: ServiceManagerObservation) -> ServiceReadiness {
            self.inspect_with(manager, manager)
        }

        fn inspect_with(
            &self,
            expected: ServiceManagerObservation,
            observed: ServiceManagerObservation,
        ) -> ServiceReadiness {
            let owner = self.root.metadata().unwrap().uid();
            inspect_at(&self.root, owner, expected, observed)
        }
    }

    fn assert_pinned_missing(
        observation: ServiceReadiness,
        expected_name: &CStr,
        expected_dir: &Path,
    ) {
        let ServiceDestination::Missing { parent, name } = observation.destination else {
            panic!(
                "expected a pinned missing destination, got {:?}",
                observation.destination
            );
        };
        let actual = parent.metadata().unwrap();
        let expected = fs::metadata(expected_dir).unwrap();
        assert_eq!(
            (actual.dev(), actual.ino()),
            (expected.dev(), expected.ino())
        );
        assert_eq!(name, expected_name);
        parent.sync_all().unwrap();
    }

    #[test]
    fn missing_fixed_destinations_return_pinned_parents_and_observe_interfaces() {
        let fixture = Fixture::new();
        let _socket = fixture.systemd();
        fixture.openrc();
        let systemd = fixture.inspect(Systemd);
        assert_eq!(systemd.manager, ManagerReadiness::InterfaceObserved);
        assert_pinned_missing(
            systemd,
            c"nodomi-agent.service",
            &fixture.path("etc/systemd/system"),
        );
        let openrc = fixture.inspect(OpenRc);
        assert_eq!(openrc.manager, ManagerReadiness::InterfaceObserved);
        assert_pinned_missing(openrc, c"nodomi-agent", &fixture.path("etc/init.d"));
        assert!(
            !fixture
                .path("etc/systemd/system/nodomi-agent.service")
                .exists()
        );
        assert!(!fixture.path("etc/init.d/nodomi-agent").exists());
    }

    #[test]
    fn existing_service_file_is_preserved_and_untrusted_entry_is_unsafe() {
        let fixture = Fixture::new();
        let _socket = fixture.systemd();
        let destination = "etc/systemd/system/nodomi-agent.service";
        fixture.write(destination, b"original unit", 0o644);
        assert!(matches!(
            fixture.inspect(Systemd).destination,
            ServiceDestination::Existing
        ));
        assert_eq!(
            fs::read(fixture.path(destination)).unwrap(),
            b"original unit"
        );
        fs::set_permissions(fixture.path(destination), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            fixture.inspect(Systemd).destination,
            ServiceDestination::Unsafe
        ));
        fs::remove_file(fixture.path(destination)).unwrap();
        symlink("/dev/null", fixture.path(destination)).unwrap();
        assert!(matches!(
            fixture.inspect(Systemd).destination,
            ServiceDestination::Unsafe
        ));
    }

    #[test]
    fn missing_parent_and_symlink_parent_remain_distinct() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.path("etc")).unwrap();
        assert!(matches!(
            fixture.inspect(OpenRc).destination,
            ServiceDestination::Unavailable
        ));
        fixture.write("elsewhere/nodomi-agent", b"canary", 0o755);
        symlink("../elsewhere", fixture.path("etc/init.d")).unwrap();
        assert!(matches!(
            fixture.inspect(OpenRc).destination,
            ServiceDestination::Unsafe
        ));
        assert_eq!(
            fs::read(fixture.path("elsewhere/nodomi-agent")).unwrap(),
            b"canary"
        );
    }

    #[test]
    fn systemd_conflicts_with_generator_unit_or_configured_drop_in() {
        let fixture = Fixture::new();
        let _socket = fixture.systemd();
        let alternate = "run/systemd/generator.early/nodomi-agent.service";
        fixture.write(alternate, b"other unit", 0o644);
        assert_eq!(fixture.inspect(Systemd).manager, ManagerReadiness::Conflict);
        fs::remove_file(fixture.path(alternate)).unwrap();
        fixture.write(
            "usr/lib/systemd/system/nodomi-.service.d/README",
            b"not a drop-in",
            0o644,
        );
        assert_eq!(
            fixture.inspect(Systemd).manager,
            ManagerReadiness::InterfaceObserved
        );
        fixture.write(
            "usr/lib/systemd/system/nodomi-.service.d/custom.conf",
            b"override",
            0o644,
        );
        assert_eq!(fixture.inspect(Systemd).manager, ManagerReadiness::Conflict);
    }

    #[test]
    fn openrc_conflicts_with_runtime_service_link_or_runlevel_override() {
        let fixture = Fixture::new();
        fixture.openrc();
        fs::create_dir_all(fixture.path("run/openrc/started")).unwrap();
        let started = fixture.path("run/openrc/started/nodomi-agent");
        symlink("/custom/init.d/nodomi-agent", &started).unwrap();
        assert_eq!(fixture.inspect(OpenRc).manager, ManagerReadiness::Conflict);
        fs::remove_file(started).unwrap();
        fixture.write("run/openrc/softlevel", b"maintenance", 0o644);
        fixture.write(
            "etc/conf.d/nodomi-agent.maintenance",
            b"command=/custom/bin/agent",
            0o644,
        );
        assert_eq!(fixture.inspect(OpenRc).manager, ManagerReadiness::Conflict);
    }

    #[test]
    fn openrc_host_configuration_fragment_keeps_manager_evidence_unknown() {
        let fixture = Fixture::new();
        fixture.openrc();
        fixture.write(
            "etc/rc.conf.d/local.conf",
            b"# local shell configuration",
            0o644,
        );
        assert_eq!(fixture.inspect(OpenRc).manager, ManagerReadiness::Unknown);
    }

    #[test]
    fn alpine_root_group_runtime_accepts_only_locked_maintenance_accounts() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let fixture = Fixture::new();
        fixture.openrc();
        fs::set_permissions(
            fixture.path("run/openrc"),
            fs::Permissions::from_mode(0o775),
        )
        .unwrap();
        fixture.write("etc/group", b"root:x:0:root\nusers:x:100:\n", 0o644);
        fixture.write("etc/passwd", b"root:x:0:0::/root:/bin/sh\nsync:x:5:0::/sbin:/bin/sync\nshutdown:x:6:0::/sbin:/sbin/shutdown\nhalt:x:7:0::/sbin:/sbin/halt\n", 0o644);
        fixture.write(
            "etc/shadow",
            b"root:*:::::::\nsync:!:::::::\nshutdown:!:::::::\nhalt:!:::::::\n",
            0o640,
        );
        assert_eq!(
            fixture.inspect(OpenRc).manager,
            ManagerReadiness::InterfaceObserved
        );
        fixture.write("etc/group", b"root:x:0:root,operator\n", 0o644);
        assert_eq!(fixture.inspect(OpenRc).manager, ManagerReadiness::Unknown);
        fixture.write("etc/group", b"root:x:0:root\n", 0o644);
        fixture.write(
            "etc/shadow",
            b"root:*:::::::\nsync::\nshutdown:!:::::::\nhalt:!:::::::\n",
            0o640,
        );
        assert_eq!(fixture.inspect(OpenRc).manager, ManagerReadiness::Unknown);
    }

    #[test]
    fn systemd_recognizes_only_the_standard_merged_usr_alias() {
        let fixture = Fixture::new();
        let _socket = fixture.systemd();
        fs::create_dir_all(fixture.path("usr/lib/systemd/system")).unwrap();
        symlink("usr/lib", fixture.path("lib")).unwrap();
        assert_eq!(
            fixture.inspect(Systemd).manager,
            ManagerReadiness::InterfaceObserved
        );
        fs::remove_file(fixture.path("lib")).unwrap();
        symlink("custom/lib", fixture.path("lib")).unwrap();
        assert_eq!(fixture.inspect(Systemd).manager, ManagerReadiness::Unknown);
    }

    #[test]
    fn manager_change_is_a_conflict_and_uncertainty_stays_unknown() {
        let fixture = Fixture::new();
        let socket = fixture.systemd();
        assert_eq!(
            fixture.inspect_with(Systemd, OpenRc).manager,
            ManagerReadiness::Conflict
        );
        assert_eq!(
            fixture.inspect_with(Systemd, Ambiguous).manager,
            ManagerReadiness::Unknown
        );
        drop(socket);
        let socket_path = fixture.path("run/systemd/private");
        fs::remove_file(socket_path).unwrap();
        fixture.write("run/systemd/private", b"regular file", 0o600);
        assert_eq!(fixture.inspect(Systemd).manager, ManagerReadiness::Unknown);
    }
}
