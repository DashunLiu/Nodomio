use nodomi_agent::execution::*;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt, symlink},
        net::UnixStream,
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};
const LIMIT: Duration = Duration::from_secs(5);
fn uid() -> u32 {
    // SAFETY: geteuid has no preconditions and accesses no Rust memory.
    unsafe { libc::geteuid() }
}
fn fixture() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(d.path().join("execution.lock"))
        .unwrap()
        .sync_all()
        .unwrap();
    File::open(d.path()).unwrap().sync_all().unwrap();
    d
}
fn domain(p: &Path) -> ExecutionDomain {
    ExecutionDomain::open_existing(p, uid()).unwrap()
}
fn noop() -> WorkUnit {
    Box::new(|| Ok(()))
}
fn blocked() -> (WorkUnit, UnixStream) {
    let (mut worker, caller) = UnixStream::pair().unwrap();
    caller.set_read_timeout(Some(LIMIT)).unwrap();
    caller.set_write_timeout(Some(LIMIT)).unwrap();
    (
        Box::new(move || {
            worker.write_all(b"S").unwrap();
            let mut byte = [0];
            worker
                .read_exact(&mut byte)
                .map_err(|_| UnitFailure::OutcomeUnknown)?;
            Ok(())
        }),
        caller,
    )
}
fn started(control: &mut UnixStream) {
    let mut b = [0];
    control.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"S");
}
fn busy(d: &ExecutionDomain) {
    assert!(matches!(
        d.start(&mut vec![noop()]),
        Err(ExecutionError::Busy)
    ));
}
fn reacquire(d: &ExecutionDomain) -> JobOutcome {
    let deadline = Instant::now() + LIMIT;
    loop {
        match d.start(&mut vec![noop()]) {
            Ok(h) => return h.join(),
            Err(ExecutionError::Busy) if Instant::now() < deadline => std::thread::yield_now(),
            _ => panic!("worker did not release execution rights before deadline"),
        }
    }
}
#[test]
fn serial_units_complete_and_join_ack_follows_release() {
    let d = fixture();
    let e = domain(d.path());
    let order = Arc::new(Mutex::new(vec![]));
    let mut units = (0..3)
        .map(|i| {
            let order = order.clone();
            Box::new(move || {
                order.lock().unwrap().push(i);
                Ok(())
            }) as WorkUnit
        })
        .collect();
    let outcome = e.start(&mut units).unwrap().join();
    assert_eq!(
        outcome,
        JobOutcome {
            completed_units: 3,
            termination: Termination::Completed,
            stop_requested: false
        }
    );
    assert_eq!(*order.lock().unwrap(), vec![0, 1, 2]);
    assert_eq!(
        e.start(&mut vec![noop()]).unwrap().join().termination,
        Termination::Completed
    );
    assert!(matches!(
        e.start(&mut vec![]),
        Err(ExecutionError::EmptyJob)
    ));
}
#[test]
fn cancel_and_timeout_only_stop_before_the_next_safe_unit() {
    for timeout in [false, true] {
        let d = fixture();
        let e = domain(d.path());
        let independent = domain(d.path());
        let (unit, mut c) = blocked();
        let (tx, rx) = mpsc::channel();
        let next = Box::new(move || {
            tx.send(()).unwrap();
            Ok(())
        }) as WorkUnit;
        let mut h = e.start(&mut vec![unit, next]).unwrap();
        started(&mut c);
        busy(&e);
        busy(&independent);
        if timeout {
            assert_eq!(h.wait_timeout(Duration::ZERO), WaitStatus::Active);
        } else {
            h.request_stop();
            h.request_stop();
        }
        busy(&independent);
        c.write_all(b"R").unwrap();
        let out = h.join();
        assert_eq!(
            out,
            JobOutcome {
                completed_units: 1,
                termination: Termination::Stopped,
                stop_requested: true
            }
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(
            independent
                .start(&mut vec![noop()])
                .unwrap()
                .join()
                .termination,
            Termination::Completed
        );
    }
}
#[test]
fn caller_drop_or_panic_cannot_release_a_blocked_worker() {
    for panic in [false, true] {
        let d = fixture();
        let e = domain(d.path());
        let (unit, mut c) = blocked();
        let h = e.start(&mut vec![unit, noop()]).unwrap();
        started(&mut c);
        if panic {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _h = h;
                    panic!("caller fixture panic")
                }))
                .is_err()
            );
        } else {
            drop(h);
        }
        busy(&e);
        c.write_all(b"R").unwrap();
        assert_eq!(reacquire(&e).termination, Termination::Completed);
    }
}
#[test]
fn active_unit_panic_has_unknown_effect_and_stops_later_units() {
    let d = fixture();
    let e = domain(d.path());
    let (tx, rx) = mpsc::channel();
    let h = e
        .start(&mut vec![
            noop(),
            Box::new(|| panic!("worker fixture panic")),
            Box::new(move || {
                tx.send(()).unwrap();
                Ok(())
            }),
        ])
        .unwrap();
    assert_eq!(
        h.join(),
        JobOutcome {
            completed_units: 1,
            termination: Termination::Panicked,
            stop_requested: false
        }
    );
    assert!(rx.try_recv().is_err());
    assert_eq!(
        e.start(&mut vec![noop()]).unwrap().join().termination,
        Termination::Completed
    );
}
#[test]
fn remaining_capture_destruction_holds_lease_even_during_unwind() {
    struct Cleanup(UnixStream);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            self.0.write_all(b"S").unwrap();
            let mut b = [0];
            let _ = self.0.read_exact(&mut b);
        }
    }
    for panic in [false, true] {
        let d = fixture();
        let e = domain(d.path());
        let (worker, mut c) = UnixStream::pair().unwrap();
        c.set_read_timeout(Some(LIMIT)).unwrap();
        let cleanup = Cleanup(worker);
        let first = Box::new(move || {
            if panic {
                panic!("fixture cleanup panic")
            }
            Err(UnitFailure::OutcomeUnknown)
        }) as WorkUnit;
        let remaining = Box::new(move || {
            let _keep = cleanup;
            Ok(())
        }) as WorkUnit;
        let h = e.start(&mut vec![first, remaining]).unwrap();
        started(&mut c);
        busy(&e);
        c.write_all(b"R").unwrap();
        assert_eq!(
            h.join().termination,
            if panic {
                Termination::Panicked
            } else {
                Termination::Indeterminate
            }
        );
        assert_eq!(
            e.start(&mut vec![noop()]).unwrap().join().termination,
            Termination::Completed
        );
    }
}
#[test]
fn failure_classes_do_not_claim_rollback_or_erase_completed_units() {
    for (failure, termination) in [
        (
            UnitFailure::NoPendingEffects,
            Termination::FailedNoPendingEffects,
        ),
        (UnitFailure::OutcomeUnknown, Termination::Indeterminate),
    ] {
        let d = fixture();
        let e = domain(d.path());
        let canary = d.path().join("canary");
        let write = canary.clone();
        let result = e
            .start(&mut vec![
                Box::new(move || {
                    fs::write(write, b"committed earlier unit").unwrap();
                    Ok(())
                }),
                Box::new(move || Err(failure)),
                Box::new(|| panic!("later unit ran")),
            ])
            .unwrap()
            .join();
        assert_eq!(result.termination, termination);
        assert_eq!(result.completed_units, 1);
        assert_eq!(fs::read(canary).unwrap(), b"committed earlier unit");
    }
}
#[test]
fn wait_completion_joins_and_retains_its_final_ack() {
    let d = fixture();
    let e = domain(d.path());
    let mut h = e.start(&mut vec![noop()]).unwrap();
    let WaitStatus::Finished(out) = h.wait_timeout(LIMIT) else {
        panic!("small unit failed to finish")
    };
    assert_eq!(out.termination, Termination::Completed);
    assert_eq!(h.wait_timeout(Duration::ZERO), WaitStatus::Finished(out));
    assert_eq!(h.join(), out);
    assert_eq!(
        e.start(&mut vec![noop()]).unwrap().join().termination,
        Termination::Completed
    );
}
#[test]
fn missing_paths_and_invalid_context_never_create_execution_state() {
    let d = fixture();
    let missing = d.path().join("absent");
    assert!(matches!(
        ExecutionDomain::open_existing(&missing, uid()),
        Err(ExecutionError::MissingDirectory)
    ));
    assert!(!missing.exists());
    fs::remove_file(d.path().join("execution.lock")).unwrap();
    assert!(matches!(
        ExecutionDomain::open_existing(d.path(), uid()),
        Err(ExecutionError::MissingLock)
    ));
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    for p in [
        "relative",
        "/tmp/./state",
        "/tmp//state",
        "/tmp/../state",
        "/",
    ] {
        assert!(matches!(
            ExecutionDomain::open_existing(Path::new(p), uid()),
            Err(ExecutionError::InvalidContext)
        ));
    }
}
#[test]
fn unsafe_owner_modes_links_types_and_leaf_symlinks_are_rejected() {
    for mode in [0o755, 0o1700, 0o770] {
        let d = fixture();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            ExecutionDomain::open_existing(d.path(), uid()),
            Err(ExecutionError::UnsafeFilesystem)
        ));
    }
    for mode in [0o644, 0o400, 0o1600] {
        let d = fixture();
        fs::set_permissions(
            d.path().join("execution.lock"),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert!(matches!(
            ExecutionDomain::open_existing(d.path(), uid()),
            Err(ExecutionError::UnsafeFilesystem)
        ));
    }
    let d = fixture();
    assert!(matches!(
        ExecutionDomain::open_existing(d.path(), uid().wrapping_add(1)),
        Err(ExecutionError::UnsafeFilesystem)
    ));
    let outer = fixture();
    let d = fixture();
    symlink(d.path(), outer.path().join("linked-dir")).unwrap();
    assert!(matches!(
        ExecutionDomain::open_existing(&outer.path().join("linked-dir"), uid()),
        Err(ExecutionError::UnsafeFilesystem)
    ));
    for kind in ["symlink", "hardlink", "directory", "fifo"] {
        let d = fixture();
        let lock = d.path().join("execution.lock");
        fs::remove_file(&lock).unwrap();
        match kind {
            "symlink" => {
                let outside = outer.path().join("execution.lock");
                symlink(outside, &lock).unwrap();
            }
            "hardlink" => fs::hard_link(outer.path().join("execution.lock"), &lock).unwrap(),
            "directory" => fs::create_dir(&lock).unwrap(),
            _ => {
                let path = std::ffi::CString::new(lock.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: test pathname is NUL-terminated and mode is valid.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        }
        assert!(
            matches!(
                ExecutionDomain::open_existing(d.path(), uid()),
                Err(ExecutionError::UnsafeFilesystem)
            ),
            "{kind}"
        );
        if kind == "hardlink" {
            fs::remove_file(lock).unwrap();
        }
    }
}
#[test]
fn bound_directory_and_lock_replacements_do_not_redirect_execution() {
    for replace_dir in [false, true] {
        let outer = fixture();
        let state = outer.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(
            outer.path().join("execution.lock"),
            state.join("execution.lock"),
        )
        .unwrap();
        let e = domain(&state);
        if replace_dir {
            fs::rename(&state, outer.path().join("old-state")).unwrap();
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            fs::copy(
                outer.path().join("execution.lock"),
                state.join("execution.lock"),
            )
            .unwrap();
        } else {
            fs::rename(state.join("execution.lock"), state.join("old.lock")).unwrap();
            fs::copy(
                outer.path().join("execution.lock"),
                state.join("execution.lock"),
            )
            .unwrap();
        }
        assert!(matches!(
            e.start(&mut vec![noop()]),
            Err(ExecutionError::IdentityChanged)
        ));
    }
}
#[test]
fn replaced_lock_cannot_bypass_the_still_active_directory_lease() {
    let d = fixture();
    let e = domain(d.path());
    let (unit, mut c) = blocked();
    let h = e.start(&mut vec![unit]).unwrap();
    started(&mut c);
    let old = d.path().join("old.lock");
    fs::rename(d.path().join("execution.lock"), &old).unwrap();
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(d.path().join("execution.lock"))
        .unwrap();
    let fresh = domain(d.path());
    busy(&fresh);
    c.write_all(b"R").unwrap();
    assert_eq!(h.join().termination, Termination::Completed);
    assert!(matches!(
        e.start(&mut vec![noop()]),
        Err(ExecutionError::IdentityChanged)
    ));
}
#[test]
fn reentrant_attempt_from_the_active_unit_is_busy() {
    let d = fixture();
    let p = d.path().to_owned();
    let out = domain(d.path())
        .start(&mut vec![Box::new(move || {
            busy(&domain(&p));
            Ok(())
        })])
        .unwrap()
        .join();
    assert_eq!(out.termination, Termination::Completed);
}
#[test]
#[cfg(target_os = "linux")]
#[ignore = "Explicit Linux nobody run; root bypasses permissions"]
fn linux_unprivileged_execution_denial_is_distinct() {
    assert_ne!(uid(), 0);
    let d = fixture();
    let lock = d.path().join("execution.lock");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o000)).unwrap();
    assert!(matches!(
        ExecutionDomain::open_existing(d.path(), uid()),
        Err(ExecutionError::PermissionDenied)
    ));
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::metadata(&lock).unwrap();
    let e = domain(d.path());
    assert_eq!(
        e.start(&mut vec![noop()]).unwrap().join().termination,
        Termination::Completed
    );
    let after = fs::metadata(&lock).unwrap();
    assert_eq!(
        (before.ino(), before.len(), before.mtime(), before.ctime()),
        (after.ino(), after.len(), after.mtime(), after.ctime())
    );
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn child(mode: &str, path: &Path) -> ChildGuard {
    ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "execution_child", "--nocapture"])
            .env("NODOMI_EXECUTION_CHILD", mode)
            .env("NODOMI_EXECUTION_DIRECTORY", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}
fn probe(path: &Path, expected: &str) {
    let mut c = child("probe", path);
    let output = c.0.wait_with_output_ref();
    assert!(output.0, "{}", output.1);
    assert!(output.1.contains(expected), "{}", output.1);
}
trait WaitOutput {
    fn wait_with_output_ref(&mut self) -> (bool, String);
}
impl WaitOutput for Child {
    fn wait_with_output_ref(&mut self) -> (bool, String) {
        let stdout = self.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut output = String::new();
            let mut r = BufReader::new(stdout);
            r.read_to_string(&mut output).unwrap();
            let _ = tx.send(output);
        });
        let output = rx.recv_timeout(LIMIT).unwrap();
        (self.wait().unwrap().success(), output)
    }
}
#[test]
fn independent_processes_keep_busy_after_drop_cancel_and_timeout() {
    for action in ["drop", "cancel", "timeout", "caller-panic"] {
        let d = fixture();
        let mut holder = child(action, d.path());
        let stdout = holder.0.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let _ = tx.send(line.unwrap());
            }
        });
        loop {
            if rx.recv_timeout(LIMIT).unwrap() == "HELD" {
                break;
            }
        }
        probe(d.path(), "PROBE_BUSY");
        holder.0.stdin.take().unwrap().write_all(b"R").unwrap();
        loop {
            if rx.recv_timeout(LIMIT).unwrap() == "RELEASED" {
                break;
            }
        }
        assert!(holder.0.wait().unwrap().success());
        probe(d.path(), "PROBE_ACQUIRED");
    }
}
#[test]
#[ignore = "Subprocess protocol helper, invoked only by independent_processes test"]
fn execution_child() {
    let Ok(mode) = std::env::var("NODOMI_EXECUTION_CHILD") else {
        return;
    };
    let path = std::env::var_os("NODOMI_EXECUTION_DIRECTORY").unwrap();
    let e = domain(Path::new(&path));
    if mode == "probe" {
        match e.start(&mut vec![noop()]) {
            Err(ExecutionError::Busy) => println!("PROBE_BUSY"),
            Ok(h) => {
                h.join();
                println!("PROBE_ACQUIRED")
            }
            _ => panic!("unexpected probe result"),
        };
        return;
    }
    let (unit, mut c) = blocked();
    let mut h = e.start(&mut vec![unit, noop()]).unwrap();
    started(&mut c);
    match mode.as_str() {
        "drop" => drop(h),
        "cancel" => {
            h.request_stop();
            drop(h)
        }
        "timeout" => {
            assert_eq!(h.wait_timeout(Duration::ZERO), WaitStatus::Active);
            drop(h)
        }
        "caller-panic" => {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _h = h;
                panic!("caller fixture panic")
            }));
        }
        _ => panic!("unknown child mode"),
    }
    println!("HELD");
    std::io::stdout().flush().unwrap();
    let mut b = [0];
    std::io::stdin().read_exact(&mut b).unwrap();
    c.write_all(b"R").unwrap();
    reacquire(&e);
    println!("RELEASED");
    std::io::stdout().flush().unwrap();
}

#[test]
fn panic_payload_cleanup_finishes_under_lease_before_final_ack() {
    struct Payload(UnixStream);
    impl Drop for Payload {
        fn drop(&mut self) {
            self.0.write_all(b"S").unwrap();
            let mut byte = [0];
            let _ = self.0.read_exact(&mut byte);
        }
    }
    let d = fixture();
    let e = domain(d.path());
    let (worker, mut control) = UnixStream::pair().unwrap();
    control.set_read_timeout(Some(LIMIT)).unwrap();
    let payload = Payload(worker);
    let h = e
        .start(&mut vec![Box::new(move || std::panic::panic_any(payload))])
        .unwrap();
    let waiter = std::thread::spawn(move || h.join());
    started(&mut control);
    busy(&e);
    control.write_all(b"R").unwrap();
    assert_eq!(waiter.join().unwrap().termination, Termination::Panicked);
    assert_eq!(
        e.start(&mut vec![noop()]).unwrap().join().termination,
        Termination::Completed
    );
}

#[test]
fn final_started_unit_completion_is_not_relabelled_as_cancelled() {
    let d = fixture();
    let e = domain(d.path());
    let (unit, mut control) = blocked();
    let h = e.start(&mut vec![unit]).unwrap();
    started(&mut control);
    h.request_stop();
    busy(&e);
    control.write_all(b"R").unwrap();
    assert_eq!(
        h.join(),
        JobOutcome {
            completed_units: 1,
            termination: Termination::Completed,
            stop_requested: true
        }
    );
}

#[test]
fn dropping_domain_does_not_release_worker_owned_lease() {
    let d = fixture();
    let e = domain(d.path());
    let second = domain(d.path());
    let (unit, mut control) = blocked();
    let h = e.start(&mut vec![unit]).unwrap();
    started(&mut control);
    drop(e);
    busy(&second);
    control.write_all(b"R").unwrap();
    assert_eq!(h.join().termination, Termination::Completed);
    assert_eq!(
        second.start(&mut vec![noop()]).unwrap().join().termination,
        Termination::Completed
    );
}

#[test]
fn lock_content_never_proves_right_and_fixed_file_lock_is_enforced() {
    use std::os::fd::AsRawFd;
    let d = fixture();
    let p = d.path().join("execution.lock");
    fs::write(&p, b"fake PID=999999 stale=false").unwrap();
    let e = domain(d.path());
    let external = File::open(&p).unwrap();
    // SAFETY: external is a live independently opened fixed lock descriptor.
    let locked = unsafe { libc::flock(external.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(locked, 0);
    busy(&e);
    drop(external);
    assert_eq!(
        e.start(&mut vec![noop()]).unwrap().join().termination,
        Termination::Completed
    );
    assert_eq!(fs::read(&p).unwrap(), b"fake PID=999999 stale=false");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        e.start(&mut vec![noop()]),
        Err(ExecutionError::UnsafeFilesystem)
    ));
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        e.start(&mut vec![noop()]).unwrap().join().termination,
        Termination::Completed
    );
}

#[test]
fn thread_local_cleanup_finishes_before_execution_right_is_released() {
    struct LocalCleanup(UnixStream);
    impl Drop for LocalCleanup {
        fn drop(&mut self) {
            self.0.write_all(b"S").unwrap();
            let mut byte = [0];
            let _ = self.0.read_exact(&mut byte);
        }
    }
    thread_local! { static CLEANUP: std::cell::RefCell<Option<LocalCleanup>> = const { std::cell::RefCell::new(None) }; }
    let d = fixture();
    let e = domain(d.path());
    let (worker, mut control) = UnixStream::pair().unwrap();
    control.set_read_timeout(Some(LIMIT)).unwrap();
    let h = e
        .start(&mut vec![Box::new(move || {
            CLEANUP.with(|cleanup| *cleanup.borrow_mut() = Some(LocalCleanup(worker)));
            Ok(())
        })])
        .unwrap();
    started(&mut control);
    busy(&e);
    control.write_all(b"R").unwrap();
    assert_eq!(h.join().termination, Termination::Completed);
    assert_eq!(
        e.start(&mut vec![noop()]).unwrap().join().termination,
        Termination::Completed
    );
}

#[test]
fn busy_rejection_preserves_pending_captures_without_running_cleanup() {
    struct WriteOnDrop(std::path::PathBuf);
    impl Drop for WriteOnDrop {
        fn drop(&mut self) {
            fs::write(&self.0, b"cleanup").unwrap();
        }
    }
    let d = fixture();
    let e = domain(d.path());
    let (unit, mut control) = blocked();
    let active = e.start(&mut vec![unit]).unwrap();
    started(&mut control);
    let canary = d.path().join("rejected-cleanup");
    let cleanup = WriteOnDrop(canary.clone());
    let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
        let _cleanup = cleanup;
        Ok(())
    })];
    let result = e.start(&mut pending);
    let preserved = pending.len() == 1 && !canary.exists();
    control.write_all(b"R").unwrap();
    active.join();
    assert!(matches!(result, Err(ExecutionError::Busy)));
    assert!(
        preserved,
        "Busy consumed pending captures and ran cleanup without lease"
    );
    e.start(&mut pending).unwrap().join();
    assert_eq!(fs::read(canary).unwrap(), b"cleanup");
}

#[test]
fn validation_rejection_preserves_pending_captures_without_running_cleanup() {
    struct WriteOnDrop(std::path::PathBuf);
    impl Drop for WriteOnDrop {
        fn drop(&mut self) {
            fs::write(&self.0, b"cleanup").unwrap();
        }
    }
    for identity_change in [false, true] {
        let d = fixture();
        let e = domain(d.path());
        let path = d.path().join("execution.lock");
        if identity_change {
            fs::rename(&path, d.path().join("old.lock")).unwrap();
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
        } else {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let canary = d.path().join("validation-cleanup");
        let cleanup = WriteOnDrop(canary.clone());
        let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
            let _cleanup = cleanup;
            Ok(())
        })];
        let result = e.start(&mut pending);
        assert!(matches!(
            result,
            Err(ExecutionError::UnsafeFilesystem | ExecutionError::IdentityChanged)
        ));
        assert_eq!(
            pending.len(),
            1,
            "rejected validation consumed pending captures"
        );
        assert!(!canary.exists(), "rejected validation ran cleanup");
        drop(pending);
        assert!(
            canary.exists(),
            "caller remains responsible for its unadmitted work"
        );
    }
}
