//! Cooperative, local-filesystem execution; no installer or trust authority.
//!
//! An independent protected preparer must create a dedicated 0700 directory and
//! its fixed 0600, single-link `execution.lock` once, and keep their identity stable.
//! Opening is read-only and never creates/repairs state. Caller-supplied path/UID
//! validate shape and filesystem facts, not installation provenance. Final leaves
//! are no-follow; hostile same-UID/root, ancestor replacement, network filesystems,
//! arbitrary post-fork reuse and process supervision are outside this boundary.
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionError {
    InvalidContext,
    MissingDirectory,
    MissingLock,
    PermissionDenied,
    UnsafeFilesystem,
    IdentityChanged,
    Busy,
    Io,
    EmptyJob,
    SpawnFailed,
}
/// A trusted synchronous callback's explicit effect classification, not an OS proof.
/// Ordinary I/O errors and timeouts should use OutcomeUnknown. NoPendingEffects
/// requires the callback to know that this failed unit has no unresolved effects;
/// neither case rolls back effects of earlier successful units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitFailure {
    NoPendingEffects,
    OutcomeUnknown,
}
/// Work must finish all its effects and cleanup synchronously. Do not detach work
/// into another thread/process: the library cannot enforce this callback promise.
/// Stop is observed before each unit; a running unit cannot be forcibly cancelled.
pub type WorkUnit = Box<dyn FnOnce() -> Result<(), UnitFailure> + Send + 'static>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Completed,
    Stopped,
    FailedNoPendingEffects,
    Indeterminate,
    Panicked,
}
/// Panicked and Indeterminate cannot establish the failed unit's effect. Completed
/// is callback completion only, never installation SUCCEEDED or trusted state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobOutcome {
    pub completed_units: usize,
    pub termination: Termination,
    pub stop_requested: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitStatus {
    Active,
    Finished(JobOutcome),
}
/// Bound location and inode expectations. Holds no execution lease. No file or raw
/// lease descriptor is exposed; each start opens independent file descriptions.
pub struct ExecutionDomain {
    path: PathBuf,
    owner: u32,
    directory: File,
    lock_id: (u64, u64),
}
fn identity(m: &fs::Metadata) -> (u64, u64) {
    (m.dev(), m.ino())
}
fn private(m: &fs::Metadata, owner: u32, dir: bool) -> Result<(), ExecutionError> {
    if m.uid() != owner
        || m.mode() & 0o7777 != if dir { 0o700 } else { 0o600 }
        || if dir {
            !m.is_dir() || m.nlink() == 0
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        Err(ExecutionError::UnsafeFilesystem)
    } else {
        Ok(())
    }
}
fn io_error(e: std::io::Error, dir: bool) -> ExecutionError {
    match e.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => ExecutionError::UnsafeFilesystem,
        Some(libc::ENOENT) => {
            if dir {
                ExecutionError::MissingDirectory
            } else {
                ExecutionError::MissingLock
            }
        }
        Some(libc::EACCES | libc::EPERM) => ExecutionError::PermissionDenied,
        _ => ExecutionError::Io,
    }
}
fn directory(path: &Path, owner: u32) -> Result<File, ExecutionError> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| io_error(e, true))?;
    private(&f.metadata().map_err(|_| ExecutionError::Io)?, owner, true)?;
    Ok(f)
}
fn entry(dir: &File, name: &std::ffi::CStr, flags: i32) -> Result<File, ExecutionError> {
    // SAFETY: dir is live and name is terminated. No creation flags are accepted by callers.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error(), false));
    }
    // SAFETY: successful openat returned a new uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(crate) struct Locked(File);
impl Locked {
    pub(crate) fn acquire(f: File) -> Result<Self, ExecutionError> {
        // SAFETY: the descriptor is live; nonblocking flock accesses no Rust memory.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                ExecutionError::Busy
            } else {
                io_error(e, false)
            });
        }
        Ok(Self(f))
    }
}
impl Drop for Locked {
    fn drop(&mut self) {
        // SAFETY: this private guard uniquely controls its live lock description.
        // Explicit unlock avoids a passive inherited FD prolonging the departed
        // worker's lease; arbitrary active post-fork reuse remains unsupported.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
struct Lease {
    _file: Locked,
    _directory: Locked,
}
// The owner runs no external callback or capture destructor. The task thread is
// created first and waits at a gate; if owner spawn fails, Drop closes that gate,
// joins the task's cleanup and TLS exit, then releases the lease. No unit begins.
struct WorkerOwner {
    task: Option<JoinHandle<Termination>>,
    gate: Option<mpsc::Sender<()>>,
    _lease: Lease,
}
impl WorkerOwner {
    fn run(mut self) -> Termination {
        let _ = self.gate.take().expect("private start gate").send(());
        join_task(self.task.take().expect("private task joined once"))
    }
}
impl Drop for WorkerOwner {
    fn drop(&mut self) {
        // Dropping a still-closed gate prevents all units from starting.
        self.gate.take();
        if let Some(task) = self.task.take() {
            let _ = join_task(task);
        }
        // _lease remains live through join, including task TLS destructors.
    }
}
fn join_task(task: JoinHandle<Termination>) -> Termination {
    match task.join() {
        Ok(termination) => termination,
        // Normal callback unwind/payload cleanup is caught on the task. Unexpected
        // foreign/runtime unwind cannot safely export deferred external cleanup.
        Err(payload) => {
            std::mem::forget(payload);
            std::process::abort();
        }
    }
}
fn run_units(units: &mut Vec<WorkUnit>, stopped: &AtomicBool, count: &AtomicUsize) -> Termination {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut termination = Termination::Completed;
        for unit in units.drain(..) {
            if stopped.load(Ordering::Acquire) {
                termination = Termination::Stopped;
                break;
            }
            match unit() {
                Ok(()) => {
                    count.fetch_add(1, Ordering::Release);
                }
                Err(UnitFailure::NoPendingEffects) => {
                    termination = Termination::FailedNoPendingEffects;
                    break;
                }
                Err(UnitFailure::OutcomeUnknown) => {
                    termination = Termination::Indeterminate;
                    break;
                }
            }
        }
        termination
    }));
    match result {
        Ok(termination) => termination,
        Err(payload) => {
            dispose_panic_payload(payload);
            Termination::Panicked
        }
    }
}
fn dispose_panic_payload(payload: Box<dyn std::any::Any + Send>) {
    // Panic payloads may own cleanup. Call only while the lease is held.
    // A second cleanup panic is fatal like a double panic in unwind; never
    // pass another deferred payload to the caller after releasing the lease.
    if let Err(second) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload))) {
        std::mem::forget(second);
        std::process::abort();
    }
}
impl ExecutionDomain {
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn matches_prepared(&self, directory: &File, lock_id: (u64, u64)) -> bool {
        self.lock_id == lock_id
            && self
                .directory
                .metadata()
                .and_then(|opened| Ok(identity(&opened) == identity(&directory.metadata()?)))
                .unwrap_or(false)
    }

    pub fn open_existing(path: &Path, expected_owner_uid: u32) -> Result<Self, ExecutionError> {
        if !path.is_absolute()
            || path
                .to_str()
                .is_none_or(|s| s.len() > 4096 || s.as_bytes().contains(&0))
            || path.components().count() < 2
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        {
            return Err(ExecutionError::InvalidContext);
        }
        let directory = directory(path, expected_owner_uid)?;
        let file = entry(&directory, c"execution.lock", libc::O_RDONLY)?;
        let metadata = file.metadata().map_err(|_| ExecutionError::Io)?;
        private(&metadata, expected_owner_uid, false)?;
        Ok(Self {
            path: path.into(),
            owner: expected_owner_uid,
            directory,
            lock_id: identity(&metadata),
        })
    }
    fn acquire(&self) -> Result<Lease, ExecutionError> {
        let anchored = self.directory.metadata().map_err(|_| ExecutionError::Io)?;
        private(&anchored, self.owner, true)?;
        let named = directory(&self.path, self.owner)?;
        if identity(&named.metadata().map_err(|_| ExecutionError::Io)?) != identity(&anchored) {
            return Err(ExecutionError::IdentityChanged);
        }
        // openat(".") obtains a fresh open-file-description, unlike try_clone/dup.
        let fresh = entry(&self.directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
        let directory_lock = Locked::acquire(fresh)?;
        let file = entry(&directory_lock.0, c"execution.lock", libc::O_RDONLY)?;
        let metadata = file.metadata().map_err(|_| ExecutionError::Io)?;
        private(&metadata, self.owner, false)?;
        if identity(&metadata) != self.lock_id {
            return Err(ExecutionError::IdentityChanged);
        }
        let file = Locked::acquire(file)?;
        let named_file = entry(&directory_lock.0, c"execution.lock", libc::O_RDONLY)?;
        let metadata = named_file.metadata().map_err(|_| ExecutionError::Io)?;
        private(&metadata, self.owner, false)?;
        if identity(&metadata) != self.lock_id {
            return Err(ExecutionError::IdentityChanged);
        }
        let current = directory(&self.path, self.owner)?;
        if identity(&current.metadata().map_err(|_| ExecutionError::Io)?) != identity(&anchored) {
            return Err(ExecutionError::IdentityChanged);
        }
        Ok(Lease {
            _file: file,
            _directory: directory_lock,
        })
    }
    /// Runs synchronous trusted callbacks on a gated task under one cooperative
    /// lease owned by its private job thread. Join includes task TLS cleanup. Panic
    /// payload cleanup also runs under the lease. A second panic during that
    /// cleanup aborts the process and cannot produce a completion acknowledgement.
    /// Admission borrows caller-owned pending work. Busy, validation and first
    /// task-spawn failure leave it untouched: no external capture is moved or
    /// destroyed. Only after the task exists does this method take the Vec under
    /// the lease. A later owner-spawn failure cleans admitted work on that task
    /// and joins its TLS exit before releasing; pending then stays empty.
    /// The caller owns rejected work and must choose when it is safe to retry or
    /// clean it up. Explicit caller drop is outside this library's control.
    pub fn start(&self, pending: &mut Vec<WorkUnit>) -> Result<JobHandle, ExecutionError> {
        if pending.is_empty() {
            return Err(ExecutionError::EmptyJob);
        }
        let lease = self.acquire()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let (start, ready) = mpsc::channel();
        let admitted = Arc::new(Mutex::new(None::<Vec<WorkUnit>>));
        let task_work = admitted.clone();
        // This first spawn captures only internal empty state. Its failure can
        // never destroy caller work or initialize external TLS on the caller.
        let task = thread::Builder::new()
            .name("nodomi-work-units".into())
            .spawn(move || {
                if ready.recv().is_err() {
                    stopped.store(true, Ordering::Release);
                }
                let mut units = task_work
                    .lock()
                    .expect("private admission slot")
                    .take()
                    .unwrap_or_default();
                run_units(&mut units, &stopped, &count)
            })
            .map_err(|_| ExecutionError::SpawnFailed)?;
        // No foreign code runs with this mutex held. The live task waits for its
        // gate, so it cannot observe the slot before this admission is complete.
        *admitted.lock().expect("private admission slot") = Some(std::mem::take(pending));
        let owner = WorkerOwner {
            task: Some(task),
            gate: Some(start),
            _lease: lease,
        };
        let (ack, done) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("nodomi-execution".into())
            .spawn(move || {
                // WorkerOwner::run joins the actual task through TLS destruction;
                // its Drop then releases the private lease before this ack.
                let termination = owner.run();
                let _ = ack.send(());
                termination
            })
            .map_err(|_| ExecutionError::SpawnFailed)?;
        Ok(JobHandle {
            stop,
            completed,
            thread: Some(thread),
            done,
            outcome: None,
        })
    }
}
/// Dropping detaches the waiting handle and requests stop; the worker alone owns
/// its lease until synchronous work and capture cleanup finish. A timeout similarly
/// requests stop but is not a completion acknowledgement or a hard cancellation.
pub struct JobHandle {
    stop: Arc<AtomicBool>,
    completed: Arc<AtomicUsize>,
    thread: Option<JoinHandle<Termination>>,
    done: Receiver<()>,
    outcome: Option<JobOutcome>,
}
impl JobHandle {
    pub fn request_stop(&self) {
        if self.outcome.is_none() {
            self.stop.store(true, Ordering::Release);
        }
    }
    fn finish(&mut self) -> JobOutcome {
        if let Some(outcome) = self.outcome {
            return outcome;
        }
        let termination = join_task(self.thread.take().expect("private owner joined once"));
        let outcome = JobOutcome {
            completed_units: self.completed.load(Ordering::Acquire),
            termination,
            stop_requested: self.stop.load(Ordering::Acquire),
        };
        self.outcome = Some(outcome);
        outcome
    }
    pub fn join(mut self) -> JobOutcome {
        self.finish()
    }
    pub fn wait_timeout(&mut self, timeout: Duration) -> WaitStatus {
        if let Some(outcome) = self.outcome {
            return WaitStatus::Finished(outcome);
        }
        match self.done.recv_timeout(timeout) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => WaitStatus::Finished(self.finish()),
            Err(RecvTimeoutError::Timeout) => {
                self.request_stop();
                WaitStatus::Active
            }
        }
    }
}
impl Drop for JobHandle {
    fn drop(&mut self) {
        self.request_stop();
    }
}
