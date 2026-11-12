//! Protected activation under the original first-install execution lease.
use super::{
    host::{ServiceManagerObservation, inspect_host},
    layout::open_root,
    plan_store::{open_at, same_snapshot, stat},
    service_readiness::{
        ManagerReadiness, ServiceDestination, ServiceReadiness, inspect_service_readiness,
        inspect_service_recovery,
    },
};
use std::{
    ffi::CStr,
    fs::File,
    io::{self, Read},
    os::fd::AsRawFd,
};

#[path = "service_activation/command.rs"]
mod command;
#[path = "service_activation/openrc.rs"]
mod openrc;
#[path = "service_activation/systemd.rs"]
mod systemd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActivationError {
    /// A specific conflicting object or manager state was found before this call's mutation.
    Blocked,
    /// This call could not establish the prerequisites for a manager mutation.
    Unavailable,
    /// A manager command may have had effects. Its client exit is not proof of cleanup.
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ServiceStarted {
    pub(super) manager: ServiceManagerObservation,
    pub(super) main_pid: Option<u32>,
    invocation_id: u128,
}

const SERVICE_NAME: &CStr = c"nodomi-agent.service";
const SERVICE_PARENT: &[&CStr] = &[c"etc", c"systemd", c"system"];
const SYSTEMCTL_PARENT: &[&CStr] = &[c"usr", c"bin"];
const MAX_TEMPLATE: u64 = 16 * 1024;

pub(super) struct ServiceActivation {
    root: File,
    template: ProtectedFile,
    driver: Driver,
}

enum Driver {
    Systemd(ProtectedFile),
    OpenRc(Box<openrc::OpenRc>),
}

impl ServiceActivation {
    pub(super) fn supports(manager: ServiceManagerObservation) -> bool {
        matches!(
            manager,
            ServiceManagerObservation::Systemd | ServiceManagerObservation::OpenRc
        )
    }

    /// Check the host-specific global OpenRC settings before accepting effects.
    pub(super) fn check_manager_configuration(
        manager: ServiceManagerObservation,
    ) -> Result<(), ActivationError> {
        match manager {
            ServiceManagerObservation::OpenRc => {
                let root = open_root().map_err(|_| ActivationError::Unavailable)?;
                openrc::check_configuration(&root)
            }
            ServiceManagerObservation::Systemd => Ok(()),
            _ => Err(ActivationError::Unavailable),
        }
    }

    /// Prepare only from the fixed local namespace after the verified template
    /// has been published. This method issues no service-manager commands.
    pub(super) fn prepare(
        manager: ServiceManagerObservation,
        expected_template_sha256: &[u8; 32],
    ) -> Result<Self, ActivationError> {
        if !Self::supports(manager) || super::plan_store::effective_uid() != 0 {
            return Err(ActivationError::Unavailable);
        }
        require_fresh_layout(manager)?;
        let root = open_root().map_err(|_| ActivationError::Unavailable)?;
        Self::prepare_from_layout(root, manager, expected_template_sha256)
    }

    pub(super) fn prepare_recovery(
        manager: ServiceManagerObservation,
        expected_template_sha256: &[u8; 32],
    ) -> Result<Self, ActivationError> {
        if !Self::supports(manager)
            || super::plan_store::effective_uid() != 0
            || inspect_host().service_manager != manager
        {
            return Err(ActivationError::Unavailable);
        }
        let root = open_root().map_err(|_| ActivationError::Unavailable)?;
        require_existing_layout(inspect_service_recovery(&root, 0, manager))?;
        Self::prepare_from_layout(root, manager, expected_template_sha256)
    }

    fn prepare_from_layout(
        root: File,
        manager: ServiceManagerObservation,
        expected_template_sha256: &[u8; 32],
    ) -> Result<Self, ActivationError> {
        let template = open_template(&root, 0, expected_template_sha256, manager)?;
        let driver = match manager {
            ServiceManagerObservation::Systemd => Driver::Systemd(ProtectedFile::open(
                &root,
                SYSTEMCTL_PARENT,
                c"systemctl",
                0,
                libc::O_PATH,
                |info| info.st_mode & 0o7100 == 0o100,
            )?),
            ServiceManagerObservation::OpenRc => {
                Driver::OpenRc(Box::new(openrc::OpenRc::prepare(&root)?))
            }
            _ => return Err(ActivationError::Unavailable),
        };
        Ok(Self {
            root,
            template,
            driver,
        })
    }

    /// The original executor must already hold its execution lease and have
    /// durably recorded ServiceStartPossible before either mutating method.
    pub(super) fn enable(&self) -> Result<(), ActivationError> {
        require_fresh_layout(self.manager())?;
        self.recheck()?;
        match &self.driver {
            Driver::Systemd(systemctl) => {
                // A newly published unit can already be loaded on demand.
                // Refresh only when needed to prove the disabled, inactive unit.
                if self.require_systemd_inactive(systemctl, false).is_err() {
                    self.recheck()?;
                    systemd::reload(&systemctl.file)?;
                    self.require_systemd_inactive(systemctl, false)
                        .map_err(|_| ActivationError::OutcomeUnknown)?;
                }
                // Native enablement refreshes the live dependency graph.
                systemd::enable(&systemctl.file)?;
                self.require_systemd_inactive(systemctl, true)
                    .map_err(|_| ActivationError::OutcomeUnknown)?;
            }
            Driver::OpenRc(openrc) => {
                openrc::OpenRc::require_stopped(&self.root)?;
                openrc
                    .resolve_script()
                    .map_err(|_| ActivationError::OutcomeUnknown)?;
                self.recheck()
                    .map_err(|_| ActivationError::OutcomeUnknown)?;
                openrc.enable()?;
                self.recheck()
                    .map_err(|_| ActivationError::OutcomeUnknown)?;
                openrc::OpenRc::require_stopped(&self.root)
                    .map_err(|_| ActivationError::OutcomeUnknown)?;
            }
        }
        self.enabled_link(true)
            .map_err(|_| ActivationError::OutcomeUnknown)
    }

    pub(super) fn start(&self, recover_enabled: bool) -> Result<ServiceStarted, ActivationError> {
        self.enabled_link(false)?;
        match &self.driver {
            Driver::Systemd(systemctl) => {
                self.require_systemd_inactive(systemctl, true)?;
                systemd::start(&systemctl.file)?;
                self.observe_started()
                    .map_err(|_| ActivationError::OutcomeUnknown)
            }
            Driver::OpenRc(openrc) => {
                self.recheck()?;
                openrc::OpenRc::require_drained(&self.root, recover_enabled)?;
                openrc
                    .resolve_script()
                    .map_err(|_| ActivationError::OutcomeUnknown)?;
                self.recheck()
                    .map_err(|_| ActivationError::OutcomeUnknown)?;
                openrc::OpenRc::require_drained(&self.root, recover_enabled)?;
                openrc.start()?;
                // OpenRC may mark the service started before its child execs.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                loop {
                    if let Ok(instance) = self.observe_started() {
                        return Ok(instance);
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(ActivationError::OutcomeUnknown);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    }

    /// Prove this manager's original service is drained before renewal.
    pub(super) fn cold_enabled(&self, allow_disabled: bool) -> Result<bool, ActivationError> {
        self.recheck()?;
        require_existing_layout(inspect_service_recovery(&self.root, 0, self.manager()))?;
        match &self.driver {
            Driver::Systemd(tool) => self.cold_systemd_enabled(tool, allow_disabled),
            Driver::OpenRc(openrc) => {
                let enabled = openrc::OpenRc::cold_enabled(&self.root, allow_disabled)?;
                openrc.resolve_script()?;
                self.recheck()?;
                if openrc::OpenRc::cold_enabled(&self.root, allow_disabled)? != enabled {
                    return Err(ActivationError::Blocked);
                }
                Ok(enabled)
            }
        }
    }

    fn cold_systemd_enabled(
        &self,
        tool: &ProtectedFile,
        allow_disabled: bool,
    ) -> Result<bool, ActivationError> {
        let parent = directory(&self.root, SERVICE_PARENT, 0)?;
        let enabled = match stat(&parent, Some(c"multi-user.target.wants")) {
            Ok(_) => {
                let wants = directory(&parent, &[c"multi-user.target.wants"], 0)?;
                match stat(&wants, Some(SERVICE_NAME)) {
                    Ok(_) => {
                        self.enabled_link(false)?;
                        true
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                    Err(error) => return Err(classify_path_error(error)),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(classify_path_error(error)),
        };
        if !allow_disabled && !enabled {
            return Err(ActivationError::Blocked);
        }
        self.require_systemd_inactive(tool, enabled)?;
        Ok(enabled)
    }

    /// Reobserve the same loaded unit after the independent runtime health proof.
    pub(super) fn observe_started(&self) -> Result<ServiceStarted, ActivationError> {
        self.recheck()?;
        self.enabled_link(false)?;
        let (pid, invocation_id) = match &self.driver {
            Driver::Systemd(systemctl) => {
                let instance =
                    systemd::observe(&systemctl.file, true)?.ok_or(ActivationError::Blocked)?;
                (instance.pid, instance.invocation_id)
            }
            Driver::OpenRc(openrc) => openrc.observe(&self.root)?,
        };
        self.recheck()?;
        Ok(ServiceStarted {
            manager: self.manager(),
            main_pid: Some(pid),
            invocation_id,
        })
    }

    fn require_systemd_inactive(
        &self,
        systemctl: &ProtectedFile,
        enabled: bool,
    ) -> Result<(), ActivationError> {
        self.recheck()?;
        if systemd::observe(&systemctl.file, enabled)?.is_some() {
            return Err(ActivationError::Blocked);
        }
        self.recheck()
    }

    fn manager(&self) -> ServiceManagerObservation {
        match self.driver {
            Driver::Systemd(_) => ServiceManagerObservation::Systemd,
            Driver::OpenRc(_) => ServiceManagerObservation::OpenRc,
        }
    }

    fn recheck(&self) -> Result<(), ActivationError> {
        let observed = inspect_host().service_manager;
        match observed {
            manager if manager == self.manager() => {}
            ServiceManagerObservation::Systemd | ServiceManagerObservation::OpenRc => {
                return Err(ActivationError::Blocked);
            }
            _ => return Err(ActivationError::Unavailable),
        }
        let (parents, name, _, _) = template_details(self.manager())?;
        self.template.recheck(&self.root, parents, name, 0)?;
        match &self.driver {
            Driver::Systemd(systemctl) => {
                systemctl.recheck(&self.root, SYSTEMCTL_PARENT, c"systemctl", 0)
            }
            Driver::OpenRc(openrc) => openrc.recheck(&self.root),
        }
    }

    fn enabled_link(&self, sync: bool) -> Result<(), ActivationError> {
        if matches!(self.driver, Driver::OpenRc(_)) {
            return openrc::OpenRc::enabled_link(&self.root, sync);
        }
        let parent = directory(&self.root, SERVICE_PARENT, 0)?;
        let wants = directory(&parent, &[c"multi-user.target.wants"], 0)?;
        exact_link(
            &wants,
            SERVICE_NAME,
            &[
                b"/etc/systemd/system/nodomi-agent.service",
                b"../nodomi-agent.service",
            ],
        )?;
        if sync {
            wants
                .sync_all()
                .and_then(|()| parent.sync_all())
                .map_err(|_| ActivationError::OutcomeUnknown)?;
        }
        Ok(())
    }
}

fn exact_link(parent: &File, name: &CStr, allowed: &[&[u8]]) -> Result<(), ActivationError> {
    let link = stat(parent, Some(name)).map_err(classify_path_error)?;
    if link.st_uid != 0 || link.st_mode & libc::S_IFMT != libc::S_IFLNK || link.st_nlink != 1 {
        return Err(ActivationError::Blocked);
    }
    let mut target = [0_u8; 128];
    // SAFETY: parent is a held directory and target is a writable bounded buffer.
    let length = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    let length = usize::try_from(length).map_err(|_| ActivationError::Unavailable)?;
    if !target
        .get(..length)
        .is_some_and(|target| allowed.contains(&target))
        || !same_snapshot(
            &link,
            &stat(parent, Some(name)).map_err(classify_path_error)?,
        )
    {
        return Err(ActivationError::Blocked);
    }
    Ok(())
}

fn require_fresh_layout(manager: ServiceManagerObservation) -> Result<(), ActivationError> {
    require_existing_layout(inspect_service_readiness(manager))
}

fn require_existing_layout(observation: ServiceReadiness) -> Result<(), ActivationError> {
    match (observation.destination, observation.manager) {
        (ServiceDestination::Existing, ManagerReadiness::InterfaceObserved) => Ok(()),
        (ServiceDestination::Unsafe, _) | (_, ManagerReadiness::Conflict) => {
            Err(ActivationError::Blocked)
        }
        _ => Err(ActivationError::Unavailable),
    }
}

type TemplateDetails = (
    &'static [&'static CStr],
    &'static CStr,
    libc::mode_t,
    fn(&[u8]) -> bool,
);

fn template_details(
    manager: ServiceManagerObservation,
) -> Result<TemplateDetails, ActivationError> {
    match manager {
        ServiceManagerObservation::Systemd => Ok((
            SERVICE_PARENT,
            SERVICE_NAME,
            0o644,
            systemd::fixed_install_target,
        )),
        ServiceManagerObservation::OpenRc => Ok((
            openrc::TEMPLATE_PARENT,
            openrc::NAME,
            0o755,
            openrc::fixed_template,
        )),
        _ => Err(ActivationError::Unavailable),
    }
}

fn open_template(
    root: &File,
    owner: libc::uid_t,
    expected: &[u8; 32],
    manager: ServiceManagerObservation,
) -> Result<ProtectedFile, ActivationError> {
    let (parents, name, mode, valid) = template_details(manager)?;
    let template = ProtectedFile::open(root, parents, name, owner, libc::O_RDONLY, |info| {
        info.st_mode & 0o7777 == mode
            && info.st_nlink == 1
            && (1..=MAX_TEMPLATE as libc::off_t).contains(&info.st_size)
    })?;
    let mut bytes = Vec::new();
    (&template.file)
        .take(MAX_TEMPLATE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ActivationError::Unavailable)?;
    if bytes.len() as libc::off_t != template.snapshot.st_size
        || ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref() != expected
        || !valid(&bytes)
    {
        return Err(ActivationError::Blocked);
    }
    template.recheck(root, parents, name, owner)?;
    Ok(template)
}

struct ProtectedFile {
    file: File,
    snapshot: libc::stat,
}

impl ProtectedFile {
    fn open(
        root: &File,
        components: &[&CStr],
        name: &CStr,
        owner: libc::uid_t,
        flags: libc::c_int,
        validate: impl FnOnce(&libc::stat) -> bool,
    ) -> Result<Self, ActivationError> {
        let parent = directory(root, components, owner)?;
        let named = stat(&parent, Some(name)).map_err(classify_path_error)?;
        if !trusted(&named, owner, libc::S_IFREG) || !validate(&named) {
            return Err(ActivationError::Blocked);
        }
        let file = open_at(&parent, name, flags).map_err(classify_path_error)?;
        let snapshot = stat(&file, None).map_err(classify_path_error)?;
        if !same_snapshot(&named, &snapshot) {
            return Err(ActivationError::Blocked);
        }
        Ok(Self { file, snapshot })
    }

    fn recheck(
        &self,
        root: &File,
        components: &[&CStr],
        name: &CStr,
        owner: libc::uid_t,
    ) -> Result<(), ActivationError> {
        let parent = directory(root, components, owner)?;
        let named = stat(&parent, Some(name)).map_err(classify_path_error)?;
        let held = stat(&self.file, None).map_err(classify_path_error)?;
        if same_snapshot(&self.snapshot, &named) && same_snapshot(&self.snapshot, &held) {
            Ok(())
        } else {
            Err(ActivationError::Blocked)
        }
    }
}

fn directory(
    root: &File,
    components: &[&CStr],
    owner: libc::uid_t,
) -> Result<File, ActivationError> {
    let mut current = root.try_clone().map_err(classify_path_error)?;
    for component in components {
        if !trusted(
            &stat(&current, None).map_err(classify_path_error)?,
            owner,
            libc::S_IFDIR,
        ) {
            return Err(ActivationError::Blocked);
        }
        current = open_at(&current, component, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(classify_path_error)?;
    }
    if !trusted(
        &stat(&current, None).map_err(classify_path_error)?,
        owner,
        libc::S_IFDIR,
    ) {
        return Err(ActivationError::Blocked);
    }
    Ok(current)
}

fn trusted(info: &libc::stat, owner: libc::uid_t, kind: libc::mode_t) -> bool {
    info.st_mode & libc::S_IFMT == kind && info.st_uid == owner && info.st_mode & 0o022 == 0
}

fn classify_path_error(error: io::Error) -> ActivationError {
    match error.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => ActivationError::Blocked,
        _ => ActivationError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };

    #[test]
    fn protected_published_template_is_checked_for_bytes_inode_and_enable_target() {
        let directory = tempfile::tempdir().unwrap();
        let root = File::open(directory.path()).unwrap();
        let owner = root.metadata().unwrap().uid();
        let path = directory
            .path()
            .join("etc/systemd/system/nodomi-agent.service");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = b"[Service]\nType=simple\n[Install]\nWantedBy=multi-user.target\n";
        let digest = ring::digest::digest(&ring::digest::SHA256, original);
        let expected = digest.as_ref().try_into().unwrap();
        let manager = ServiceManagerObservation::Systemd;
        fs::write(&path, original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let pinned = open_template(&root, owner, expected, manager).unwrap();
        assert!(matches!(
            open_template(&root, owner, &[0; 32], manager),
            Err(ActivationError::Blocked)
        ));
        fs::rename(&path, path.with_extension("original")).unwrap();
        fs::write(&path, original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            pinned.recheck(&root, SERVICE_PARENT, SERVICE_NAME, owner),
            Err(ActivationError::Blocked)
        );
        fs::remove_file(&path).unwrap();
        symlink(path.with_extension("original"), &path).unwrap();
        assert!(matches!(
            open_template(&root, owner, expected, manager),
            Err(ActivationError::Blocked)
        ));
        assert_eq!(fs::read(path.with_extension("original")).unwrap(), original);
    }

    #[test]
    fn unsupported_manager_blocks_activation_before_manager_commands() {
        assert!(!ServiceActivation::supports(
            ServiceManagerObservation::Unknown
        ));
        assert!(matches!(
            ServiceActivation::prepare(ServiceManagerObservation::Unknown, &[0; 32]),
            Err(ActivationError::Unavailable)
        ));
    }
}
