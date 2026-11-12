//! Protected, non-overwriting storage for install plan records.
use super::plan::{InstallPlan, MAX_PLAN_BYTES, valid_plan_id};
use std::{
    ffi::{CStr, CString},
    fs::{File, Permissions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::PermissionsExt,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanStoreError {
    UnsafeDirectory,
    UnsafeEntry,
    InvalidPlanId,
    InvalidPlan,
    TooLarge,
    NotFound,
    AlreadyExists,
    Io,
    /// The new name was published, but its durability could not be confirmed.
    CommitOutcomeUnknown,
}

pub struct InstallPlanStore {
    directory: File,
}

impl InstallPlanStore {
    /// The caller opens the dedicated plan directory. This does not create it.
    pub fn open(directory: File) -> Result<Self, PlanStoreError> {
        let owner = effective_uid();
        check_directory(&directory, owner)?;
        // Obtain an independent descriptor that supports fsync, even if the
        // caller supplied an O_PATH descriptor for the anchored directory.
        let directory = open_at(&directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|_| PlanStoreError::Io)?;
        check_directory(&directory, owner)?;
        Ok(Self { directory })
    }

    pub fn save(&self, plan: &InstallPlan) -> Result<(), PlanStoreError> {
        let bytes = plan.encode().map_err(|_| PlanStoreError::InvalidPlan)?;
        self.save_bytes(plan.plan_id(), &bytes, File::sync_all)
    }

    pub fn load(&self, plan_id: &str) -> Result<InstallPlan, PlanStoreError> {
        let bytes = self.load_bytes(plan_id)?;
        let plan = InstallPlan::decode(&bytes).map_err(|_| PlanStoreError::InvalidPlan)?;
        if plan.plan_id() != plan_id {
            return Err(PlanStoreError::InvalidPlan);
        }
        Ok(plan)
    }

    fn save_bytes(
        &self,
        plan_id: &str,
        bytes: &[u8],
        sync_parent: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<(), PlanStoreError> {
        let destination = plan_name(plan_id)?;
        if bytes.is_empty() {
            return Err(PlanStoreError::InvalidPlan);
        }
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(PlanStoreError::TooLarge);
        }

        let owner = effective_uid();
        check_directory(&self.directory, owner)?;
        let mut temporary = TemporaryPlan::create(&self.directory)?;
        temporary
            .file
            .write_all(bytes)
            .map_err(|_| PlanStoreError::Io)?;
        temporary.file.sync_all().map_err(|_| PlanStoreError::Io)?;
        let written = stat(&temporary.file, None).map_err(|_| PlanStoreError::Io)?;
        if check_file(&written, owner)? != bytes.len() || !temporary.owns_name() {
            return Err(PlanStoreError::UnsafeEntry);
        }
        check_directory(&self.directory, owner)?;

        // SAFETY: both names are NUL-terminated single components and the shared
        // directory descriptor remains live. RENAME_NOREPLACE never clobbers.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.directory.as_raw_fd(),
                temporary.name.as_ptr(),
                self.directory.as_raw_fd(),
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::AlreadyExists {
                Err(PlanStoreError::AlreadyExists)
            } else {
                Err(PlanStoreError::Io)
            };
        }
        temporary.published = true;
        sync_parent(&self.directory).map_err(|_| PlanStoreError::CommitOutcomeUnknown)
    }

    fn load_bytes(&self, plan_id: &str) -> Result<Vec<u8>, PlanStoreError> {
        let name = plan_name(plan_id)?;
        let owner = effective_uid();
        check_directory(&self.directory, owner)?;

        // Reject special files before opening them. O_NOFOLLOW and O_NONBLOCK
        // also guard the open if another writer changes the entry in between.
        let listed = stat(&self.directory, Some(&name)).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                PlanStoreError::NotFound
            } else {
                PlanStoreError::Io
            }
        })?;
        let size = check_file(&listed, owner)?;
        let file = open_at(&self.directory, &name, libc::O_RDONLY)
            .map_err(|_| PlanStoreError::UnsafeEntry)?;
        let opened = stat(&file, None).map_err(|_| PlanStoreError::Io)?;
        if !same_snapshot(&listed, &opened) {
            return Err(PlanStoreError::UnsafeEntry);
        }
        let mut bytes = Vec::with_capacity(size);
        (&file)
            .take((MAX_PLAN_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| PlanStoreError::Io)?;
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(PlanStoreError::TooLarge);
        }
        let after = stat(&file, None).map_err(|_| PlanStoreError::Io)?;
        let named_after =
            stat(&self.directory, Some(&name)).map_err(|_| PlanStoreError::UnsafeEntry)?;
        if bytes.len() != size
            || !same_snapshot(&opened, &after)
            || !same_snapshot(&opened, &named_after)
        {
            return Err(PlanStoreError::UnsafeEntry);
        }
        check_directory(&self.directory, owner)?;
        Ok(bytes)
    }
}

fn plan_name(plan_id: &str) -> Result<CString, PlanStoreError> {
    if !valid_plan_id(plan_id) {
        return Err(PlanStoreError::InvalidPlanId);
    }
    CString::new(format!("{plan_id}.json")).map_err(|_| PlanStoreError::InvalidPlanId)
}

pub(super) fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

pub(super) fn check_directory(directory: &File, owner: libc::uid_t) -> Result<(), PlanStoreError> {
    let metadata = stat(directory, None).map_err(|_| PlanStoreError::Io)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != owner
        || metadata.st_mode & 0o7777 != 0o700
    {
        return Err(PlanStoreError::UnsafeDirectory);
    }
    Ok(())
}

pub(super) fn check_file(
    metadata: &libc::stat,
    owner: libc::uid_t,
) -> Result<usize, PlanStoreError> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != owner
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o7777 != 0o600
    {
        return Err(PlanStoreError::UnsafeEntry);
    }
    let size = usize::try_from(metadata.st_size).map_err(|_| PlanStoreError::TooLarge)?;
    if size > MAX_PLAN_BYTES {
        return Err(PlanStoreError::TooLarge);
    }
    Ok(size)
}

pub(super) fn open_at(directory: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: directory and name are live and a mode is supplied for O_CREAT.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat returned a uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn stat(descriptor: &File, name: Option<&CStr>) -> io::Result<libc::stat> {
    let mut output = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor and optional NUL-terminated name are live.
    // output points to enough writable space for either syscall.
    let result = unsafe {
        match name {
            Some(name) => libc::fstatat(
                descriptor.as_raw_fd(),
                name.as_ptr(),
                output.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            ),
            None => libc::fstat(descriptor.as_raw_fd(), output.as_mut_ptr()),
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful syscall initialized the output.
    Ok(unsafe { output.assume_init() })
}

pub(super) fn same_inode(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

pub(super) fn same_snapshot(left: &libc::stat, right: &libc::stat) -> bool {
    same_inode(left, right)
        && left.st_size == right.st_size
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

pub(super) struct TemporaryPlan<'a> {
    directory: &'a File,
    pub(super) name: CString,
    pub(super) file: File,
    pub(super) published: bool,
}

impl<'a> TemporaryPlan<'a> {
    pub(super) fn create(directory: &'a File) -> Result<Self, PlanStoreError> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| PlanStoreError::Io)?;
        let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = CString::new(format!(".plan-{id}.tmp")).map_err(|_| PlanStoreError::Io)?;
        let file = open_at(
            directory,
            &name,
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
        )
        .map_err(|_| PlanStoreError::Io)?;
        let temporary = Self {
            directory,
            name,
            file,
            published: false,
        };
        // Restore the exact private mode if the process umask was more restrictive.
        temporary
            .file
            .set_permissions(Permissions::from_mode(0o600))
            .map_err(|_| PlanStoreError::Io)?;
        Ok(temporary)
    }

    pub(super) fn owns_name(&self) -> bool {
        match (
            stat(&self.file, None),
            stat(self.directory, Some(&self.name)),
        ) {
            (Ok(opened), Ok(named)) => same_inode(&opened, &named),
            _ => false,
        }
    }
}

impl Drop for TemporaryPlan<'_> {
    fn drop(&mut self) {
        if !self.published && self.owns_name() {
            // SAFETY: the directory and name are live. The entry still points
            // to the exclusively created inode held by this guard.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt, symlink},
        path::{Path, PathBuf},
        sync::Barrier,
        thread,
    };

    const PLAN_ID: &str = "9bd73031-81c4-4fd4-85bb-8ad7b1945d36";
    const CONTENT: &[u8] = b"synthetic plan bytes";

    struct Fixture {
        temporary: tempfile::TempDir,
        plans: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let plans = temporary.path().join("plans");
            fs::create_dir(&plans).unwrap();
            fs::set_permissions(&plans, Permissions::from_mode(0o700)).unwrap();
            Self { temporary, plans }
        }

        fn store(&self) -> InstallPlanStore {
            InstallPlanStore::open(File::open(&self.plans).unwrap()).unwrap()
        }

        fn record(&self) -> PathBuf {
            self.plans.join(format!("{PLAN_ID}.json"))
        }
    }

    fn save(store: &InstallPlanStore, bytes: &[u8]) -> Result<(), PlanStoreError> {
        store.save_bytes(PLAN_ID, bytes, File::sync_all)
    }

    fn fixture_file(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn same_id_concurrent_saves_have_one_winner_and_preserve_its_bytes() {
        let fixture = Fixture::new();
        let first = fixture.store();
        let second = fixture.store();
        let ready = Barrier::new(2);
        let (left, right) = thread::scope(|scope| {
            let left = scope.spawn(|| {
                ready.wait();
                save(&first, b"first complete plan")
            });
            let right = scope.spawn(|| {
                ready.wait();
                save(&second, b"second complete plan")
            });
            (left.join().unwrap(), right.join().unwrap())
        });
        let winner: &[u8] = match (left, right) {
            (Ok(()), Err(PlanStoreError::AlreadyExists)) => b"first complete plan",
            (Err(PlanStoreError::AlreadyExists), Ok(())) => b"second complete plan",
            other => panic!("expected one successful publication, got {other:?}"),
        };
        let reopened = fixture.store();
        assert_eq!(reopened.load_bytes(PLAN_ID).unwrap(), winner);
        assert_eq!(fs::read(fixture.record()).unwrap(), winner);
        assert_eq!(fs::read_dir(&fixture.plans).unwrap().count(), 1);
        assert_eq!(
            fs::metadata(fixture.record()).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn rejects_symlink_hardlink_wrong_mode_and_nonregular_entries() {
        let fixture = Fixture::new();
        let record = fixture.record();
        let canary = fixture.temporary.path().join("canary");
        fixture_file(&canary, CONTENT, 0o600);
        let store = fixture.store();

        symlink(&canary, &record).unwrap();
        assert_eq!(store.load_bytes(PLAN_ID), Err(PlanStoreError::UnsafeEntry));
        assert_eq!(
            save(&store, b"overwrite"),
            Err(PlanStoreError::AlreadyExists)
        );
        assert_eq!(fs::read_link(&record).unwrap(), canary);
        fs::remove_file(&record).unwrap();

        fs::hard_link(&canary, &record).unwrap();
        assert_eq!(store.load_bytes(PLAN_ID), Err(PlanStoreError::UnsafeEntry));
        assert_eq!(fs::read(&canary).unwrap(), CONTENT);
        fs::remove_file(&record).unwrap();

        fixture_file(&record, CONTENT, 0o640);
        assert_eq!(store.load_bytes(PLAN_ID), Err(PlanStoreError::UnsafeEntry));
        assert_eq!(fs::read(&record).unwrap(), CONTENT);
        fs::remove_file(&record).unwrap();

        fixture_file(&record, CONTENT, 0o600);
        let record_metadata = stat(&File::open(&record).unwrap(), None).unwrap();
        assert_eq!(
            check_file(&record_metadata, effective_uid().wrapping_add(1)),
            Err(PlanStoreError::UnsafeEntry),
        );
        fs::remove_file(&record).unwrap();

        fs::create_dir(&record).unwrap();
        assert_eq!(store.load_bytes(PLAN_ID), Err(PlanStoreError::UnsafeEntry));
        assert_eq!(save(&store, CONTENT), Err(PlanStoreError::AlreadyExists));
        assert_eq!(fs::read(&canary).unwrap(), CONTENT);
        assert!(record.is_dir());
        assert_eq!(fs::read_dir(&fixture.plans).unwrap().count(), 1);
    }

    #[test]
    fn enforces_private_directory_and_rejects_path_components_and_oversize() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let record = fixture.record();
        assert_eq!(store.load_bytes(PLAN_ID), Err(PlanStoreError::NotFound));
        assert_eq!(
            store.load_bytes("../canary"),
            Err(PlanStoreError::InvalidPlanId)
        );
        let oversized = vec![0; MAX_PLAN_BYTES + 1];
        assert_eq!(save(&store, &oversized), Err(PlanStoreError::TooLarge));
        assert!(!record.exists());

        fixture_file(&record, &oversized, 0o600);
        assert_eq!(store.load_bytes(PLAN_ID), Err(PlanStoreError::TooLarge));
        assert_eq!(fs::read(&record).unwrap(), oversized);
        fs::remove_file(&record).unwrap();

        let max_bytes = vec![1; MAX_PLAN_BYTES];
        save(&store, &max_bytes).unwrap();
        assert_eq!(store.load_bytes(PLAN_ID).unwrap(), max_bytes);
        fs::set_permissions(&fixture.plans, Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            InstallPlanStore::open(File::open(&fixture.plans).unwrap()),
            Err(PlanStoreError::UnsafeDirectory),
        ));
        assert_eq!(save(&store, CONTENT), Err(PlanStoreError::UnsafeDirectory));
        assert_eq!(
            store.load_bytes(PLAN_ID),
            Err(PlanStoreError::UnsafeDirectory)
        );
        assert_eq!(fs::read(record).unwrap(), max_bytes);
    }

    #[test]
    fn anchored_directory_can_sync_without_reopening_its_path() {
        let fixture = Fixture::new();
        let anchored = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&fixture.plans)
            .unwrap();
        let moved = fixture.temporary.path().join("moved");
        fs::rename(&fixture.plans, &moved).unwrap();
        fs::create_dir(&fixture.plans).unwrap();
        fs::set_permissions(&fixture.plans, Permissions::from_mode(0o700)).unwrap();

        let store = InstallPlanStore::open(anchored).unwrap();
        save(&store, CONTENT).unwrap();
        let reopened = InstallPlanStore::open(File::open(moved).unwrap()).unwrap();
        assert_eq!(reopened.load_bytes(PLAN_ID).unwrap(), CONTENT);
        assert_eq!(fs::read_dir(&fixture.plans).unwrap().count(), 0);
    }

    #[test]
    fn directory_sync_failure_keeps_published_record_and_reports_uncertainty() {
        let fixture = Fixture::new();
        let store = fixture.store();
        assert_eq!(
            store.save_bytes(PLAN_ID, CONTENT, |_| Err(io::Error::from_raw_os_error(
                libc::EIO
            ))),
            Err(PlanStoreError::CommitOutcomeUnknown),
        );
        let reopened = fixture.store();
        assert_eq!(reopened.load_bytes(PLAN_ID).unwrap(), CONTENT);
        assert_eq!(
            save(&reopened, b"different retry"),
            Err(PlanStoreError::AlreadyExists)
        );
        assert_eq!(fs::read_dir(&fixture.plans).unwrap().count(), 1);
    }
}
