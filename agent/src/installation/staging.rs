//! Protected local publication for the original admitted first install.

use super::{
    FormalPackage, PackageInspectionError, ServiceManagerObservation,
    control::lock_identity,
    package::stage_formal_members,
    plan::valid_plan_id,
    plan_store::{TemporaryPlan, check_directory, open_at, same_inode, same_snapshot, stat},
};
use ring::digest::{Context, SHA256, digest};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString},
    fs::{File, Permissions},
    io::{self, ErrorKind, Read, Write},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicationError {
    InvalidContext,
    Conflict,
    Archive(PackageInspectionError),
    Space,
    Io,
    CommitUnknown,
}

const RECEIPT_NAME: &CStr = c"publication.json";
const PROGRAM_NAME: &CStr = c"nodomi-agent";
const MAX_RECEIPT_BYTES: u64 = 4096;

pub(super) struct PublicationContext<'a> {
    pub(super) control: &'a File,
    pub(super) program_parent: &'a File,
    pub(super) service_parent: &'a File,
    pub(super) owner: libc::uid_t,
    pub(super) manager: ServiceManagerObservation,
    pub(super) operation_id: &'a str,
    pub(super) plan_digest: &'a str,
    pub(super) release_id: &'a str,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationReceipt {
    version: u8,
    operation_id: String,
    plan_digest: String,
    release_id: String,
    archive_sha256: String,
    manager: ServiceManagerObservation,
    worker_boot_id: String,
    anchors: PublicationAnchors,
    program: ObjectIdentity,
    service: ObjectIdentity,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationAnchors {
    control: ObjectIdentity,
    execution_lock: ObjectIdentity,
    program_parent: ObjectIdentity,
    service_parent: ObjectIdentity,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

impl ObjectIdentity {
    fn observe(file: &File) -> Result<Self, PublicationError> {
        let info = stat(file, None).map_err(io_error)?;
        Ok(Self {
            device: info.st_dev,
            inode: info.st_ino,
        })
    }
}

struct PublicationNames {
    program_stage: CString,
    service_stage: CString,
    service: &'static CStr,
    service_index: usize,
}

impl PublicationContext<'_> {
    fn anchors(&self) -> Result<PublicationAnchors, PublicationError> {
        let (device, inode) =
            lock_identity(self.control, self.owner).ok_or(PublicationError::InvalidContext)?;
        Ok(PublicationAnchors {
            control: ObjectIdentity::observe(self.control)?,
            execution_lock: ObjectIdentity { device, inode },
            program_parent: ObjectIdentity::observe(self.program_parent)?,
            service_parent: ObjectIdentity::observe(self.service_parent)?,
        })
    }

    fn names(
        &self,
        package: &FormalPackage,
        boot: &str,
    ) -> Result<PublicationNames, PublicationError> {
        use PublicationError::InvalidContext;
        if !valid_plan_id(self.operation_id)
            || !valid_plan_id(self.release_id)
            || !valid_plan_id(boot)
            || !valid_digest(self.plan_digest)
            || !valid_digest(&package.archive_sha256)
            || package.members.len() != 6
        {
            return Err(InvalidContext);
        }
        check_directory(self.control, self.owner).map_err(|_| InvalidContext)?;
        let (service, service_index) = match self.manager {
            ServiceManagerObservation::Systemd => (c"nodomi-agent.service", 3),
            ServiceManagerObservation::OpenRc => (c"nodomi-agent", 4),
            _ => return Err(InvalidContext),
        };
        Ok(PublicationNames {
            program_stage: CString::new(format!(".nodomi-install-{}", self.operation_id))
                .map_err(|_| InvalidContext)?,
            service_stage: CString::new(format!(".nodomi-install-{}.service", self.operation_id))
                .map_err(|_| InvalidContext)?,
            service,
            service_index,
        })
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The caller holds the original execution lease and has durably recorded
/// LocalPublicationPossible. A failure after creation leaves named evidence for
/// recovery; this function never retries, removes, or overwrites another file.
pub(super) fn publish_formal_package(
    context: &PublicationContext<'_>,
    archive: &File,
    package: &FormalPackage,
    worker_boot_id: &str,
    after_program_published: impl FnOnce() -> Result<(), PublicationError>,
) -> Result<(), PublicationError> {
    use PublicationError::InvalidContext;
    let names = context.names(package, worker_boot_id)?;
    let anchors = context.anchors()?;
    let collector = package
        .members
        .first()
        .filter(|member| member.path == "bin/nodomi-agent")
        .ok_or(InvalidContext)?;
    let release_name = CString::new(context.release_id).map_err(|_| InvalidContext)?;
    let program_parent = context.program_parent;
    let service_parent = context.service_parent;

    require_missing(context.control, RECEIPT_NAME)?;
    require_missing(program_parent, PROGRAM_NAME)?;
    require_missing(service_parent, names.service)?;
    require_missing(service_parent, &names.service_stage)?;

    let staging = create_directory(program_parent, &names.program_stage)?;
    let bin = create_directory(&staging, c"bin")?;
    let releases = create_directory(&staging, c"releases")?;
    let release = create_directory(&releases, &release_name)?;
    let mut agent = create_file(&release, c"nodomi-agent")?;
    let mut ctl = create_file(&bin, c"nodomi-agentctl")?;
    let mut supervisor = create_file(&bin, c"nodomi-agent-supervisor")?;
    let mut license = create_file(&staging, c"LICENSE")?;
    let mut service = create_file(service_parent, &names.service_stage)?;
    let (systemd, openrc) = if context.manager == ServiceManagerObservation::Systemd {
        (Some(&mut service), None)
    } else {
        (None, Some(&mut service))
    };
    stage_formal_members(
        archive,
        package,
        [
            Some(&mut agent),
            Some(&mut ctl),
            Some(&mut supervisor),
            systemd,
            openrc,
            Some(&mut license),
        ],
    )
    .map_err(|error| match error {
        PackageInspectionError::StageSpace => PublicationError::Space,
        error => PublicationError::Archive(error),
    })?;
    let mut pointer = create_file(&staging, c"current.json")?;
    let current = current_pointer(context.release_id, &collector.sha256)?;
    pointer.write_all(&current).map_err(io_error)?;
    for (file, mode) in [
        (&agent, 0o755),
        (&ctl, 0o755),
        (&supervisor, 0o755),
        (&license, 0o644),
        (&pointer, 0o600),
        (&service, package.members[names.service_index].mode),
    ] {
        file.set_permissions(Permissions::from_mode(mode))
            .and_then(|()| file.sync_all())
            .map_err(io_error)?;
    }
    for directory in [&release, &releases, &bin, &staging] {
        directory.sync_all().map_err(io_error)?;
    }
    sync_parent(program_parent)?;
    sync_parent(service_parent)?;
    if anchors != context.anchors()? {
        return Err(PublicationError::Conflict);
    }
    let receipt = PublicationReceipt {
        version: 1,
        operation_id: context.operation_id.to_owned(),
        plan_digest: context.plan_digest.to_owned(),
        release_id: context.release_id.to_owned(),
        archive_sha256: package.archive_sha256.clone(),
        manager: context.manager,
        worker_boot_id: worker_boot_id.to_owned(),
        anchors,
        program: ObjectIdentity::observe(&staging)?,
        service: ObjectIdentity::observe(&service)?,
    };
    publish_receipt(context.control, &receipt)?;

    publish_named(program_parent, &names.program_stage, PROGRAM_NAME, &staging)?;
    after_program_published()?;
    publish_named(
        service_parent,
        &names.service_stage,
        names.service,
        &service,
    )
}

fn sync_parent(parent: &File) -> Result<(), PublicationError> {
    let directory = open_at(parent, c".", libc::O_RDONLY | libc::O_DIRECTORY).map_err(io_error)?;
    directory.sync_all().map_err(io_error)
}

fn publish_receipt(control: &File, receipt: &PublicationReceipt) -> Result<(), PublicationError> {
    let mut temp = TemporaryPlan::create(control).map_err(|_| PublicationError::Io)?;
    let bytes = serde_json::to_vec(receipt).map_err(|_| PublicationError::InvalidContext)?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(PublicationError::InvalidContext);
    }
    temp.file
        .write_all(&bytes)
        .and_then(|()| temp.file.sync_all())
        .map_err(io_error)?;
    publish_named(control, &temp.name, RECEIPT_NAME, &temp.file)?;
    temp.published = true;
    Ok(())
}

fn read_receipt(
    control: &File,
    owner: libc::uid_t,
) -> Result<PublicationReceipt, PublicationError> {
    let initial = stat(control, Some(RECEIPT_NAME)).map_err(io_error)?;
    if initial.st_mode & libc::S_IFMT != libc::S_IFREG
        || initial.st_nlink != 1
        || initial.st_uid != owner
        || initial.st_mode & 0o7777 != 0o600
        || !(1..=MAX_RECEIPT_BYTES as libc::off_t).contains(&initial.st_size)
    {
        return Err(PublicationError::Conflict);
    }
    let file = open_at(control, RECEIPT_NAME, libc::O_RDONLY).map_err(io_error)?;
    if !same_snapshot(&initial, &stat(&file, None).map_err(io_error)?) {
        return Err(PublicationError::Conflict);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as libc::off_t != initial.st_size
        || !same_snapshot(&initial, &stat(&file, None).map_err(io_error)?)
        || !same_snapshot(
            &initial,
            &stat(control, Some(RECEIPT_NAME)).map_err(io_error)?,
        )
    {
        return Err(PublicationError::Conflict);
    }
    serde_json::from_slice(&bytes).map_err(|_| PublicationError::Conflict)
}

/// The original publication worker only performs synchronous local I/O. A
/// different boot and the reacquired lease fence that worker before adoption.
/// Both objects are checked before either absent final name can be published.
pub(super) fn recover_formal_publication(
    context: &PublicationContext<'_>,
    package: &FormalPackage,
    current_boot_id: &str,
) -> Result<(), PublicationError> {
    let names = context.names(package, current_boot_id)?;
    let receipt = read_receipt(context.control, context.owner)?;
    if receipt.version != 1
        || receipt.operation_id != context.operation_id
        || receipt.plan_digest != context.plan_digest
        || receipt.release_id != context.release_id
        || receipt.archive_sha256 != package.archive_sha256
        || receipt.manager != context.manager
        || !valid_plan_id(&receipt.worker_boot_id)
        || receipt.worker_boot_id == current_boot_id
        || receipt.anchors != context.anchors()?
    {
        return Err(PublicationError::Conflict);
    }
    let (program_name, program_published) = locate(
        context.program_parent,
        &names.program_stage,
        PROGRAM_NAME,
        &receipt.program,
    )?;
    let (service_name, service_published) = locate(
        context.service_parent,
        &names.service_stage,
        names.service,
        &receipt.service,
    )?;
    if !program_published && service_published {
        return Err(PublicationError::Conflict);
    }
    for (parent, published) in [
        (context.program_parent, program_published),
        (context.service_parent, service_published),
    ] {
        if !published
            && super::observe_directory(parent)
                .map_err(|_| PublicationError::Io)?
                .read_only
        {
            return Err(PublicationError::Io);
        }
    }
    let program = verify_program_tree(
        context.program_parent,
        program_name,
        context.owner,
        context.release_id,
        package,
    )?;
    let member = &package.members[names.service_index];
    let (service, digest) = file_digest(
        context.service_parent,
        service_name,
        context.owner,
        member.mode,
        member.length,
    )?;
    if digest != member.sha256
        || ObjectIdentity::observe(&program)? != receipt.program
        || ObjectIdentity::observe(&service)? != receipt.service
    {
        return Err(PublicationError::Conflict);
    }
    if !program_published {
        publish_named(
            context.program_parent,
            &names.program_stage,
            PROGRAM_NAME,
            &program,
        )?;
    }
    if !service_published {
        publish_named(
            context.service_parent,
            &names.service_stage,
            names.service,
            &service,
        )?;
    }
    Ok(())
}

fn locate<'a>(
    parent: &File,
    stage: &'a CStr,
    final_name: &'a CStr,
    expected: &ObjectIdentity,
) -> Result<(&'a CStr, bool), PublicationError> {
    let named = |name| match stat(parent, Some(name)) {
        Ok(info) => Ok(Some(ObjectIdentity {
            device: info.st_dev,
            inode: info.st_ino,
        })),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(error)),
    };
    match (named(stage)?, named(final_name)?) {
        (Some(observed), None) if observed == *expected => Ok((stage, false)),
        (None, Some(observed)) if observed == *expected => Ok((final_name, true)),
        _ => Err(PublicationError::Conflict),
    }
}

/// Read back the original program tree before taking over a registration.
/// The caller separately verifies the exact selected service template.
pub(super) fn verify_published_program(
    parent: &File,
    owner: libc::uid_t,
    release_id: &str,
    package: &FormalPackage,
) -> Result<(), PublicationError> {
    verify_program_tree(parent, PROGRAM_NAME, owner, release_id, package).map(|_| ())
}

fn verify_program_tree(
    parent: &File,
    program_name: &CStr,
    owner: libc::uid_t,
    release_id: &str,
    package: &FormalPackage,
) -> Result<File, PublicationError> {
    if !valid_plan_id(release_id) {
        return Err(PublicationError::InvalidContext);
    }
    let program = open_private_directory(parent, program_name, owner)?;
    let bin = open_private_directory(&program, c"bin", owner)?;
    let releases = open_private_directory(&program, c"releases", owner)?;
    let release_name = CString::new(release_id).map_err(|_| PublicationError::InvalidContext)?;
    let release = open_private_directory(&releases, &release_name, owner)?;
    let members = &package.members;
    if members.len() != 6 {
        return Err(PublicationError::InvalidContext);
    }
    for (directory, entries) in [
        (
            &program,
            &["bin", "releases", "LICENSE", "current.json"][..],
        ),
        (&bin, &["nodomi-agentctl", "nodomi-agent-supervisor"][..]),
        (&releases, &[release_id][..]),
        (&release, &["nodomi-agent"][..]),
    ] {
        crate::identity::entries(directory, entries).map_err(|_| PublicationError::Conflict)?;
    }
    for (directory, name, member) in [
        (&release, c"nodomi-agent", &members[0]),
        (&bin, c"nodomi-agentctl", &members[1]),
        (&bin, c"nodomi-agent-supervisor", &members[2]),
        (&program, c"LICENSE", &members[5]),
    ] {
        let (_, observed) = file_digest(directory, name, owner, member.mode, member.length)?;
        if observed != member.sha256 {
            return Err(PublicationError::Conflict);
        }
    }
    let pointer = current_pointer(release_id, &members[0].sha256)?;
    let (_, observed) = file_digest(
        &program,
        c"current.json",
        owner,
        0o600,
        pointer.len() as u64,
    )?;
    if observed != hex_sha256(digest(&SHA256, &pointer).as_ref()) {
        return Err(PublicationError::Conflict);
    }
    for (directory, name, opened) in [
        (parent, program_name, &program),
        (&program, c"bin", &bin),
        (&program, c"releases", &releases),
        (&releases, release_name.as_c_str(), &release),
    ] {
        let expected = stat(opened, None).map_err(io_error)?;
        if !stat(directory, Some(name)).is_ok_and(|named| same_inode(&expected, &named)) {
            return Err(PublicationError::Conflict);
        }
    }
    Ok(program)
}

fn current_pointer(release_id: &str, sha256: &str) -> Result<Vec<u8>, PublicationError> {
    serde_json::to_vec(&serde_json::json!({
        "releaseId": release_id,
        "sha256": sha256,
    }))
    .map_err(|_| PublicationError::InvalidContext)
}

pub(super) fn open_private_directory(
    parent: &File,
    name: &CStr,
    owner: libc::uid_t,
) -> Result<File, PublicationError> {
    let directory = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY).map_err(io_error)?;
    check_directory(&directory, owner).map_err(|_| PublicationError::InvalidContext)?;
    Ok(directory)
}

pub(super) fn verify_private_bytes(
    directory: &File,
    name: &CStr,
    owner: libc::uid_t,
    expected: &[u8],
) -> Result<(), PublicationError> {
    let (_, actual) = file_digest(directory, name, owner, 0o600, expected.len() as u64)?;
    if actual != hex_sha256(digest(&SHA256, expected).as_ref()) {
        return Err(PublicationError::Conflict);
    }
    Ok(())
}

fn file_digest(
    directory: &File,
    name: &CStr,
    owner: libc::uid_t,
    mode: u32,
    length: u64,
) -> Result<(File, String), PublicationError> {
    let initial = stat(directory, Some(name)).map_err(io_error)?;
    if initial.st_mode & libc::S_IFMT != libc::S_IFREG
        || initial.st_uid != owner
        || initial.st_nlink != 1
        || initial.st_mode & 0o7777 != mode
        || u64::try_from(initial.st_size).ok() != Some(length)
    {
        return Err(PublicationError::InvalidContext);
    }
    let file = open_at(directory, name, libc::O_RDONLY).map_err(io_error)?;
    if !same_snapshot(&initial, &stat(&file, None).map_err(io_error)?) {
        return Err(PublicationError::Conflict);
    }
    let mut input = (&file).take(length.saturating_add(1));
    let mut buffer = [0_u8; 16 * 1024];
    let mut hash = Context::new(&SHA256);
    loop {
        let size = input.read(&mut buffer).map_err(io_error)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    if input.limit() != 1
        || !same_snapshot(&initial, &stat(&file, None).map_err(io_error)?)
        || !same_snapshot(&initial, &stat(directory, Some(name)).map_err(io_error)?)
    {
        return Err(PublicationError::Conflict);
    }
    Ok((file, hex_sha256(hash.finish().as_ref())))
}

fn hex_sha256(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn require_missing(parent: &File, name: &CStr) -> Result<(), PublicationError> {
    match stat(parent, Some(name)) {
        Ok(_) => Err(PublicationError::Conflict),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

pub(super) fn create_directory(parent: &File, name: &CStr) -> Result<File, PublicationError> {
    // SAFETY: the caller holds the trusted parent and name is a fixed component.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    let directory = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY).map_err(io_error)?;
    check_directory(&directory, super::plan_store::effective_uid())
        .map_err(|_| PublicationError::InvalidContext)?;
    Ok(directory)
}

pub(super) fn create_file(parent: &File, name: &CStr) -> Result<File, PublicationError> {
    open_at(parent, name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).map_err(io_error)
}

fn publish_named(
    parent: &File,
    temporary: &CStr,
    destination: &CStr,
    held: &File,
) -> Result<(), PublicationError> {
    let staged = stat(held, None).map_err(io_error)?;
    if !same_inode(&staged, &stat(parent, Some(temporary)).map_err(io_error)?) {
        return Err(PublicationError::Conflict);
    }
    let directory = open_at(parent, c".", libc::O_RDONLY | libc::O_DIRECTORY).map_err(io_error)?;
    // SAFETY: both names are single components in the same held directory.
    let renamed = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory.as_raw_fd(),
            temporary.as_ptr(),
            directory.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if renamed != 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    directory
        .sync_all()
        .map_err(|_| PublicationError::CommitUnknown)?;
    if !stat(&directory, Some(destination)).is_ok_and(|named| same_inode(&staged, &named)) {
        return Err(PublicationError::CommitUnknown);
    }
    Ok(())
}

pub(super) fn io_error(error: io::Error) -> PublicationError {
    match error.raw_os_error() {
        Some(libc::ENOSPC | libc::EDQUOT) => PublicationError::Space,
        Some(libc::EEXIST) => PublicationError::Conflict,
        _ => PublicationError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        installation::{
            inspect_formal_package,
            package::{fixture_formal_archive, package_file},
        },
        release::manifest::Platform,
    };
    use ring::digest::{SHA256, digest};
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::Path,
    };

    const OPERATION_ID: &str = "8ca60b78-bc65-4608-b6b0-a3b6fd904d84";
    const RELEASE_ID: &str = "98cb1b4c-c4e1-40ad-8742-cba28523e5b8";
    const BOOT_ID: &str = "98cb1b4c-c4e1-40ad-8742-cba28523e5b9";
    const NEXT_BOOT_ID: &str = "98cb1b4c-c4e1-40ad-8742-cba28523e5ba";
    const PLAN_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn context<'a>(
        control: &'a File,
        program: &'a File,
        service: &'a File,
        manager: ServiceManagerObservation,
    ) -> PublicationContext<'a> {
        PublicationContext {
            control,
            program_parent: program,
            service_parent: service,
            owner: super::super::plan_store::effective_uid(),
            manager,
            operation_id: OPERATION_ID,
            plan_digest: PLAN_DIGEST,
            release_id: RELEASE_ID,
        }
    }

    fn inputs() -> (Vec<u8>, FormalPackage) {
        let platform = Platform::LinuxAarch64;
        let archive = fixture_formal_archive(platform, b"fixture text\n");
        let package = inspect_formal_package(package_file(&archive), platform).unwrap();
        (archive, package)
    }

    fn open_control_fixture(path: &Path) -> File {
        fs::set_permissions(path, Permissions::from_mode(0o700)).unwrap();
        let control = File::open(path).unwrap();
        create_file(&control, super::super::control::LOCK_NAME)
            .unwrap()
            .set_permissions(Permissions::from_mode(0o600))
            .unwrap();
        control
    }

    fn invoke(
        program: &Path,
        service: &Path,
        manager: ServiceManagerObservation,
        archive: &[u8],
        package: &FormalPackage,
    ) -> Result<(), PublicationError> {
        let control = tempfile::tempdir().unwrap();
        publish_formal_package(
            &context(
                &open_control_fixture(control.path()),
                &File::open(program).unwrap(),
                &File::open(service).unwrap(),
                manager,
            ),
            &package_file(archive),
            package,
            BOOT_ID,
            || Ok(()),
        )
    }

    #[test]
    fn publishes_exact_program_files_and_only_the_selected_service_without_clobbering() {
        let (bytes, package) = inputs();
        for (manager, service_name, service_index) in [
            (
                ServiceManagerObservation::Systemd,
                "nodomi-agent.service",
                3,
            ),
            (ServiceManagerObservation::OpenRc, "nodomi-agent", 4),
        ] {
            let program = tempfile::tempdir().unwrap();
            let service = tempfile::tempdir().unwrap();
            let installed = program.path().join("nodomi-agent");
            let service_path = service.path().join(service_name);
            invoke(program.path(), service.path(), manager, &bytes, &package).unwrap();
            for (path, index) in [
                (
                    installed.join(format!("releases/{RELEASE_ID}/nodomi-agent")),
                    0,
                ),
                (installed.join("bin/nodomi-agentctl"), 1),
                (installed.join("bin/nodomi-agent-supervisor"), 2),
                (installed.join("LICENSE"), 5),
                (service_path.clone(), service_index),
            ] {
                assert_member(&path, &package.members[index]);
            }
            let pointer: serde_json::Value =
                serde_json::from_slice(&fs::read(installed.join("current.json")).unwrap()).unwrap();
            assert_eq!(pointer["releaseId"], RELEASE_ID);
            assert_eq!(pointer["sha256"], package.members[0].sha256);
            assert_eq!(fs::read_dir(service.path()).unwrap().count(), 1);
            fs::write(&service_path, b"canary").unwrap();
            assert_eq!(
                invoke(program.path(), service.path(), manager, &bytes, &package),
                Err(PublicationError::Conflict)
            );
            assert_eq!(fs::read(service_path).unwrap(), b"canary");
            let parent = File::open(program.path()).unwrap();
            let owner = super::super::plan_store::effective_uid();
            verify_published_program(&parent, owner, RELEASE_ID, &package).unwrap();
            let license = installed.join("LICENSE");
            let mut changed = fs::read(&license).unwrap();
            changed[0] ^= 1;
            fs::write(license, changed).unwrap();
            assert_eq!(
                verify_published_program(&parent, owner, RELEASE_ID, &package),
                Err(PublicationError::Conflict)
            );
        }
    }

    #[test]
    fn modified_archive_cannot_publish_any_destination_or_reuse_its_staging() {
        let (_, package) = inputs();
        let changed = fixture_formal_archive(package.platform, b"altered text\n");
        let program = tempfile::tempdir().unwrap();
        let service = tempfile::tempdir().unwrap();
        let execute = || {
            invoke(
                program.path(),
                service.path(),
                ServiceManagerObservation::Systemd,
                &changed,
                &package,
            )
        };
        assert_eq!(
            execute(),
            Err(PublicationError::Archive(
                PackageInspectionError::DigestMismatch
            ))
        );
        assert!(!program.path().join("nodomi-agent").exists());
        assert!(!service.path().join("nodomi-agent.service").exists());
        assert_eq!(fs::read_dir(program.path()).unwrap().count(), 1);
        assert_eq!(fs::read_dir(service.path()).unwrap().count(), 1);
        assert_eq!(execute(), Err(PublicationError::Conflict));
    }

    #[test]
    fn later_boot_completes_only_the_original_missing_service_rename() {
        let (bytes, package) = inputs();
        let temporary = tempfile::tempdir().unwrap();
        let control = temporary.path().join("control");
        let program = temporary.path().join("program");
        let service = temporary.path().join("service");
        for path in [&control, &program, &service] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, Permissions::from_mode(0o700)).unwrap();
        }
        let control_fd = open_control_fixture(&control);
        let program_fd = File::open(&program).unwrap();
        let service_fd = File::open(&service).unwrap();
        let context = context(
            &control_fd,
            &program_fd,
            &service_fd,
            ServiceManagerObservation::Systemd,
        );
        let recover = |boot| recover_formal_publication(&context, &package, boot);
        assert_eq!(recover(NEXT_BOOT_ID), Err(PublicationError::Io));
        assert_eq!(
            publish_formal_package(&context, &package_file(&bytes), &package, BOOT_ID, || Err(
                PublicationError::CommitUnknown
            )),
            Err(PublicationError::CommitUnknown)
        );
        let installed = program.join("nodomi-agent");
        let program_inode = fs::symlink_metadata(&installed).unwrap().ino();
        let staged = service.join(format!(".nodomi-install-{OPERATION_ID}.service"));
        let service_inode = fs::symlink_metadata(&staged).unwrap().ino();
        let final_service = service.join("nodomi-agent.service");
        assert_eq!(recover(BOOT_ID), Err(PublicationError::Conflict));
        assert!(!final_service.exists());

        let lock = control.join("execution.lock");
        let retained_lock = control.join("test-retained-lock");
        fs::rename(&lock, &retained_lock).unwrap();
        create_file(&control_fd, super::super::control::LOCK_NAME)
            .unwrap()
            .set_permissions(Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(recover(NEXT_BOOT_ID), Err(PublicationError::Conflict));
        assert!(!final_service.exists());
        fs::remove_file(&lock).unwrap();
        fs::rename(retained_lock, lock).unwrap();

        // A matching byte copy at the final path is still a foreign inode.
        fs::copy(&staged, &final_service).unwrap();
        assert_eq!(recover(NEXT_BOOT_ID), Err(PublicationError::Conflict));
        assert_eq!(fs::symlink_metadata(&staged).unwrap().ino(), service_inode);
        fs::remove_file(&final_service).unwrap();
        let unexpected = installed.join("unowned");
        fs::write(&unexpected, b"canary").unwrap();
        assert_eq!(recover(NEXT_BOOT_ID), Err(PublicationError::Conflict));
        assert_eq!(fs::read(&unexpected).unwrap(), b"canary");
        assert!(!final_service.exists());
        fs::remove_file(unexpected).unwrap();

        recover(NEXT_BOOT_ID).unwrap();
        assert_eq!(
            fs::symlink_metadata(&installed).unwrap().ino(),
            program_inode
        );
        assert_eq!(
            fs::symlink_metadata(&final_service).unwrap().ino(),
            service_inode
        );
        assert!(!staged.exists());
        recover(NEXT_BOOT_ID).unwrap();
        assert_eq!(
            fs::symlink_metadata(&final_service).unwrap().ino(),
            service_inode
        );
    }

    #[test]
    #[ignore = "requires the isolated /first-install-arm64.tar.gz archive"]
    fn real_archive_publishes_the_complete_large_members() {
        let archive = File::open("/first-install-arm64.tar.gz").unwrap();
        let package =
            inspect_formal_package(archive.try_clone().unwrap(), Platform::LinuxAarch64).unwrap();
        assert!(
            package.members[..3]
                .iter()
                .all(|member| member.length > 64 * 1024)
        );
        let program = tempfile::tempdir().unwrap();
        let service = tempfile::tempdir().unwrap();
        let control = tempfile::tempdir().unwrap();
        publish_formal_package(
            &context(
                &open_control_fixture(control.path()),
                &File::open(program.path()).unwrap(),
                &File::open(service.path()).unwrap(),
                ServiceManagerObservation::OpenRc,
            ),
            &archive,
            &package,
            BOOT_ID,
            || Ok(()),
        )
        .unwrap();
        let installed = program.path().join("nodomi-agent");
        for (path, index) in [
            (
                installed.join(format!("releases/{RELEASE_ID}/nodomi-agent")),
                0,
            ),
            (installed.join("bin/nodomi-agentctl"), 1),
            (installed.join("bin/nodomi-agent-supervisor"), 2),
            (installed.join("LICENSE"), 5),
            (service.path().join("nodomi-agent"), 4),
        ] {
            assert_member(&path, &package.members[index]);
        }
    }

    fn assert_member(path: &Path, member: &crate::installation::FormalPackageMember) {
        let contents = fs::read(path).unwrap();
        let sha256: String = digest(&SHA256, &contents)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(sha256, member.sha256);
        assert_eq!(contents.len() as u64, member.length);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            member.mode
        );
    }

    #[test]
    #[ignore = "requires the isolated /program-capacity-fixture 4 KiB tmpfs"]
    fn real_enospc_stops_before_publishing_program_or_service() {
        let (bytes, package) = inputs();
        let program = tempfile::tempdir_in("/program-capacity-fixture").unwrap();
        let service = tempfile::tempdir().unwrap();
        assert_eq!(
            invoke(
                program.path(),
                service.path(),
                ServiceManagerObservation::Systemd,
                &bytes,
                &package,
            ),
            Err(PublicationError::Space)
        );
        assert!(!program.path().join("nodomi-agent").exists());
        assert!(!service.path().join("nodomi-agent.service").exists());
    }
}
