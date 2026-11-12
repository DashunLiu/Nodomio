//! Dedicated development protocol identity; never an installation/trust datastore.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
use zeroize::Zeroizing;

const MAX_IDENTITY_BYTES: usize = 16 * 1024;

pub type Result<T> = std::result::Result<T, &'static str>;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Target {
    pub origin: String,
    pub expected_server_id: String,
}
impl Target {
    pub fn new(origin: &str, server: &str) -> Result<Self> {
        let url = reqwest::Url::parse(origin).map_err(|_| "INVALID_TARGET")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || !public_id(server)
        {
            return Err("INVALID_TARGET");
        }
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            expected_server_id: server.into(),
        })
    }
    fn validate(&self) -> Result<()> {
        if Self::new(&self.origin, &self.expected_server_id)? != *self {
            return Err("INVALID_TARGET");
        }
        Ok(())
    }
}
pub(crate) fn public_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
pub(crate) fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Prepared,
    Uncertain,
    Bound,
    NeedsReconnect,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Binding {
    pub agent_id: String,
    pub server_id: String,
    pub binding_revision: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct State {
    schema_version: u32,
    operation_id: String,
    target: Target,
    credential: Zeroizing<String>,
    status: Status,
    binding: Option<Binding>,
}
impl State {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_json::to_vec(self).map_err(|_| "LOCAL_STORAGE_ERROR")?);
        if bytes.len() > MAX_IDENTITY_BYTES {
            return Err("LOCAL_STORAGE_ERROR");
        }
        Ok(bytes)
    }
}
/// Holds a nonblocking exclusive flock until dropped. Not Clone or Debug.
pub struct IdentityStore {
    directory: File,
    _lock: File,
    state: State,
    poisoned: bool,
}

impl Drop for IdentityStore {
    fn drop(&mut self) {
        // SAFETY: this store uniquely owns its live lock descriptor and no method can
        // run after Drop. Explicit unlock avoids a passive fork/exec child extending
        // ownership through an inherited open-file-description.
        unsafe { libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub(crate) fn private(metadata: &fs::Metadata, directory: bool, readonly: bool) -> Result<()> {
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    if metadata.uid() != unsafe { libc::geteuid() }
        || (if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        })
        || metadata.mode() & 0o7777
            != if directory {
                0o700
            } else if readonly {
                0o400
            } else {
                0o600
            }
    {
        return Err("UNSAFE_PRIVATE_STATE");
    }
    Ok(())
}
pub(crate) fn directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "UNSAFE_PRIVATE_STATE")?;
    private(
        &file.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?,
        true,
        false,
    )?;
    Ok(file)
}
pub(crate) fn entry(directory: &File, name: &str, create: bool) -> Result<File> {
    let name = CString::new(name).map_err(|_| "LOCAL_STORAGE_ERROR")?;
    let flags = libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | libc::O_CLOEXEC
        | if create {
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
    // SAFETY: directory is live, name is NUL-terminated, mode is provided for O_CREAT.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err("LOCAL_STORAGE_ERROR");
    }
    // SAFETY: successful openat returned a new, uniquely owned file descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    private(
        &file.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?,
        false,
        false,
    )?;
    Ok(file)
}
fn lock(directory: &File, create: bool) -> Result<File> {
    let file = entry(directory, "protocol.lock", create)?;
    // SAFETY: file descriptor is live. flock does not access Rust memory.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("IDENTITY_LOCKED");
    }
    Ok(file)
}
pub(crate) fn entries(directory: &File, expected: &[&str]) -> Result<()> {
    // Enumerate the opened directory, never resolve the caller's path a second time.
    let fd = directory
        .try_clone()
        .map_err(|_| "LOCAL_STORAGE_ERROR")?
        .into_raw_fd();
    // SAFETY: fd is a new owned directory descriptor. fdopendir takes ownership on success.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        // SAFETY: fdopendir failed, so fd remains ours and must be closed.
        unsafe { libc::close(fd) };
        return Err("LOCAL_STORAGE_ERROR");
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns the successful fdopendir result.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(stream);
    let mut seen = Vec::new();
    loop {
        // SAFETY: errno access is thread-local; stream is valid and exclusively borrowed.
        let item = unsafe {
            #[cfg(target_os = "linux")]
            {
                *libc::__errno_location() = 0;
            }
            #[cfg(target_os = "macos")]
            {
                *libc::__error() = 0;
            }
            libc::readdir(stream.0)
        };
        if item.is_null() {
            if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                return Err("LOCAL_STORAGE_ERROR");
            }
            break;
        }
        // SAFETY: readdir returned a valid dirent until the next readdir call, with NUL-terminated name.
        let name = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = std::str::from_utf8(name).map_err(|_| "PARTIAL_OR_UNKNOWN_STATE")?;
        if !expected.contains(&name) || seen.contains(&name.to_owned()) {
            return Err("PARTIAL_OR_UNKNOWN_STATE");
        }
        seen.push(name.to_owned());
    }
    if seen.len() != expected.len() {
        return Err("PARTIAL_OR_UNKNOWN_STATE");
    }
    Ok(())
}
pub(crate) fn random_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| "RANDOM_SOURCE_ERROR")?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let h: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
pub fn new_collector_epoch() -> Result<String> {
    random_id()
}
fn credential() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| "RANDOM_SOURCE_ERROR")?;
    Ok(Zeroizing::new(format!(
        "ndma_{}",
        URL_SAFE_NO_PAD.encode(*bytes)
    )))
}
pub(crate) fn valid_secret(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|v| v.len() == 43 && URL_SAFE_NO_PAD.decode(v).is_ok_and(|b| b.len() == 32))
}
impl IdentityStore {
    pub fn initialize(path: &Path, target: Target) -> Result<Self> {
        target.validate()?;
        let directory = directory(path)?;
        entries(&directory, &[])?;
        let state = State {
            schema_version: 1,
            operation_id: random_id()?,
            target,
            credential: credential()?,
            status: Status::Prepared,
            binding: None,
        };
        let bytes = state.encode()?;
        let lock = lock(&directory, true)?;
        lock.sync_all().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        directory.sync_all().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        let store = Self {
            directory,
            _lock: lock,
            state,
            poisoned: false,
        };
        store.persist(&bytes)?;
        Ok(store)
    }
    pub fn open(path: &Path, target: &Target) -> Result<Self> {
        target.validate()?;
        let directory = directory(path)?;
        let lock = lock(&directory, false)?;
        entries(&directory, &["protocol.lock", "identity.json"])?;
        let mut bytes = Zeroizing::new(Vec::new());
        entry(&directory, "identity.json", false)?
            .take(MAX_IDENTITY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "LOCAL_STORAGE_ERROR")?;
        if bytes.len() > MAX_IDENTITY_BYTES {
            return Err("CORRUPT_STATE");
        }
        let state: State = serde_json::from_slice(&bytes).map_err(|_| "CORRUPT_STATE")?;
        if state.schema_version != 1
            || !uuid(&state.operation_id)
            || !valid_secret(&state.credential, "ndma_")
            || state.target != *target
        {
            return Err("CORRUPT_OR_DIFFERENT_TARGET");
        }
        state.target.validate()?;
        match (&state.status, &state.binding) {
            (Status::Prepared | Status::Uncertain, None) => (),
            (Status::Bound | Status::NeedsReconnect | Status::Uncertain, Some(b))
                if public_id(&b.agent_id) && b.server_id == target.expected_server_id => {}
            _ => return Err("CORRUPT_STATE"),
        }
        Ok(Self {
            directory,
            _lock: lock,
            state,
            poisoned: false,
        })
    }
    pub(crate) fn shares_directory(&self, other: &File) -> Result<bool> {
        let own = self
            .directory
            .metadata()
            .map_err(|_| "LOCAL_STORAGE_ERROR")?;
        let candidate = other.metadata().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        Ok(own.dev() == candidate.dev() && own.ino() == candidate.ino())
    }
    pub fn status(&self) -> Status {
        self.state.status
    }
    pub fn operation_id(&self) -> &str {
        &self.state.operation_id
    }
    pub fn target(&self) -> &Target {
        &self.state.target
    }
    pub fn binding(&self) -> Option<&Binding> {
        self.state.binding.as_ref()
    }
    pub(crate) fn credential(&self) -> Result<&str> {
        if self.poisoned {
            return Err("RECOVERY_REQUIRED");
        }
        Ok(&self.state.credential)
    }
    pub(crate) fn uncertain(&mut self) -> Result<()> {
        if self.state.status != Status::Prepared {
            return Err("REGISTRATION_ALREADY_ATTEMPTED");
        }
        self.state.status = Status::Uncertain;
        self.commit()
    }
    pub(crate) fn confirm(&mut self, binding: Binding) -> Result<()> {
        if self.poisoned || self.state.status == Status::NeedsReconnect {
            return Err("IDENTITY_MISMATCH");
        }
        if binding.server_id != self.state.target.expected_server_id
            || !public_id(&binding.agent_id)
            || self.state.binding.as_ref().is_some_and(|b| b != &binding)
        {
            if self.state.binding.is_some() {
                self.state.status = Status::Uncertain;
                self.commit()?;
            }
            return Err("IDENTITY_MISMATCH");
        }
        self.state.binding = Some(binding);
        self.state.status = Status::Bound;
        self.commit()
    }
    pub(crate) fn rejected(&mut self) -> Result<()> {
        if self.state.status == Status::Bound {
            self.state.status = Status::NeedsReconnect;
            self.commit()?;
        }
        Ok(())
    }
    fn commit(&mut self) -> Result<()> {
        if self.poisoned {
            return Err("RECOVERY_REQUIRED");
        }
        self.poisoned = true;
        let bytes = self.state.encode()?;
        self.persist(&bytes)?;
        self.poisoned = false;
        Ok(())
    }

    fn persist(&self, bytes: &[u8]) -> Result<()> {
        let mut next = entry(&self.directory, "identity.next", true)?;
        next.write_all(bytes).map_err(|_| "LOCAL_STORAGE_ERROR")?;
        #[cfg(test)]
        checkpoint(CommitStage::Written)?;
        next.sync_all().map_err(|_| "LOCAL_STORAGE_ERROR")?;
        #[cfg(test)]
        checkpoint(CommitStage::FileSynced)?;
        // SAFETY: both descriptors are live; literal relative paths are NUL-terminated.
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                c"identity.next".as_ptr(),
                self.directory.as_raw_fd(),
                c"identity.json".as_ptr(),
            )
        } != 0
        {
            return Err("LOCAL_STORAGE_ERROR");
        }
        #[cfg(test)]
        checkpoint(CommitStage::Renamed)?;
        self.directory
            .sync_all()
            .map_err(|_| "LOCAL_STORAGE_ERROR")?;
        #[cfg(test)]
        checkpoint(CommitStage::ParentSynced)?;
        Ok(())
    }
}
/// Enrollment is accepted only through an explicit owned 0400 regular file.
/// No implicit stdin, environment, argv token or symlink traversal at the leaf.
pub struct Enrollment(Zeroizing<String>);
impl Enrollment {
    pub fn from_private_file(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| "UNSAFE_SECRET_INPUT")?;
        private(
            &file.metadata().map_err(|_| "UNSAFE_SECRET_INPUT")?,
            false,
            true,
        )
        .map_err(|_| "UNSAFE_SECRET_INPUT")?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(50)
            .read_to_end(&mut bytes)
            .map_err(|_| "UNSAFE_SECRET_INPUT")?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        let value =
            Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| "UNSAFE_SECRET_INPUT")?);
        if !valid_secret(&value, "ndme_") {
            return Err("UNSAFE_SECRET_INPUT");
        }
        Ok(Self(value))
    }
    pub(crate) fn secret(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitStage {
    Written,
    FileSynced,
    Renamed,
    ParentSynced,
}
#[cfg(test)]
thread_local! {static FAIL_COMMIT:std::cell::Cell<Option<CommitStage>>=const {std::cell::Cell::new(None)};}
#[cfg(test)]
fn checkpoint(stage: CommitStage) -> Result<()> {
    if FAIL_COMMIT.get() == Some(stage) {
        Err("LOCAL_STORAGE_ERROR")
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn oversized_identity_leaves_initial_or_existing_storage_intact() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = |labels| {
            Target::new(
                &format!("https://{}invalid", "a.".repeat(labels)),
                "server-1",
            )
            .unwrap()
        };
        assert!(matches!(
            IdentityStore::initialize(dir.path(), target(8192)),
            Err("LOCAL_STORAGE_ERROR")
        ));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);

        let target = target(8050);
        let mut store = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
        let original = Zeroizing::new(fs::read(dir.path().join("identity.json")).unwrap());
        assert_eq!(
            store.confirm(Binding {
                agent_id: "a".repeat(128),
                server_id: target.expected_server_id.clone(),
                binding_revision: 1,
            }),
            Err("LOCAL_STORAGE_ERROR")
        );
        assert_eq!(store.credential(), Err("RECOVERY_REQUIRED"));
        assert!(!dir.path().join("identity.next").exists());
        let retained = Zeroizing::new(fs::read(dir.path().join("identity.json")).unwrap());
        assert!(retained.as_slice() == original.as_slice());
        drop(store);
        assert_eq!(
            IdentityStore::open(dir.path(), &target).unwrap().status(),
            Status::Prepared
        );
    }

    #[test]
    fn dropping_owner_unlocks_even_if_a_forked_child_still_holds_the_description() {
        use std::process::Command;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = Target::new("https://localhost:9443", "server-1").unwrap();
        let state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
        let fd = state._lock.as_raw_fd();
        // SAFETY: fd is live. Test-only removal of CLOEXEC models a child between fork and exec.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        // SAFETY: fd and flags were obtained from this owned file descriptor.
        let changed = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        assert_eq!(changed, 0);
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        // SAFETY: restore the parent's original descriptor flags immediately after spawn.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, flags) }, 0);
        drop(state);
        let reopened = IdentityStore::open(dir.path(), &target);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            reopened.is_ok(),
            "a passive inherited descriptor retained the departed writer's lock"
        );
    }
    #[test]
    fn interrupted_atomic_commits_never_allow_network_or_credential_replacement() {
        for stage in [
            CommitStage::Written,
            CommitStage::FileSynced,
            CommitStage::Renamed,
            CommitStage::ParentSynced,
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let target = Target::new("https://localhost:9443", "server-1").unwrap();
            let mut state = IdentityStore::initialize(dir.path(), target.clone()).unwrap();
            let credential = state.state.credential.to_string();
            let operation = state.operation_id().to_owned();
            FAIL_COMMIT.set(Some(stage));
            let result = state.uncertain();
            FAIL_COMMIT.set(None);
            assert!(result.is_err(), "injected commit failure was ignored");
            assert!(state.credential().is_err());
            drop(state);
            assert!(IdentityStore::initialize(dir.path(), target.clone()).is_err());
            if [CommitStage::Written, CommitStage::FileSynced].contains(&stage) {
                assert!(IdentityStore::open(dir.path(), &target).is_err());
                assert!(dir.path().join("identity.next").exists());
            } else {
                let again = IdentityStore::open(dir.path(), &target).unwrap();
                assert_eq!(again.operation_id(), operation);
                assert_eq!(&*again.state.credential, &credential);
                assert_eq!(again.status(), Status::Uncertain);
            }
        }
    }
}
