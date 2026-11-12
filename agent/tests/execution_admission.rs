#![cfg(target_os = "linux")]
use nodomi_agent::execution::*;
use std::{
    cell::RefCell,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};
const LIMIT: Duration = Duration::from_secs(5);
fn uid() -> u32 {
    // SAFETY: geteuid has no preconditions or Rust memory access.
    unsafe { libc::geteuid() }
}
fn submit(
    domain: &ExecutionDomain,
    pending: &mut Vec<WorkUnit>,
) -> Result<JobHandle, ExecutionError> {
    domain.start(pending)
}
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        println!("TLS_HELD");
        std::io::stdout().flush().unwrap();
        let mut release = [0];
        std::io::stdin().read_exact(&mut release).unwrap();
        fs::write(&self.0, b"task TLS cleanup").unwrap();
    }
}
thread_local! {static CLEANUP: RefCell<Option<Cleanup>> = const { RefCell::new(None) };}
struct Payload(Option<Cleanup>);
impl Drop for Payload {
    fn drop(&mut self) {
        CLEANUP.with(|slot| *slot.borrow_mut() = self.0.take());
    }
}
struct Capture {
    cleanup: Option<Cleanup>,
    panic: bool,
}
impl Drop for Capture {
    fn drop(&mut self) {
        if self.panic {
            std::panic::panic_any(Payload(self.cleanup.take()));
        }
        CLEANUP.with(|slot| *slot.borrow_mut() = self.cleanup.take());
    }
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
#[ignore = "Isolated pthread_create EAGAIN child protocol helper"]
fn admission_fault_child() {
    let case = std::env::var("NODOMI_EXECUTION_ADMISSION_CASE").unwrap();
    let path = PathBuf::from(std::env::var_os("NODOMI_EXECUTION_ADMISSION_DIRECTORY").unwrap());
    let domain = ExecutionDomain::open_existing(&path, uid()).unwrap();
    let cleanup = path.join("cleanup-canary");
    let body = path.join("unit-canary");
    let work_body = body.clone();
    let capture = Capture {
        cleanup: Some(Cleanup(cleanup.clone())),
        panic: case.ends_with("panic"),
    };
    let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
        let _capture = capture;
        fs::write(work_body, b"unit ran").unwrap();
        Ok(())
    })];
    let first = submit(&domain, &mut pending);
    assert!(
        matches!(first, Err(ExecutionError::SpawnFailed)),
        "injection missed requested spawn"
    );
    if case.starts_with("first") {
        assert_eq!(
            pending.len(),
            1,
            "first spawn failure consumed caller captures"
        );
        assert!(!cleanup.exists(), "first failure ran capture/TLS cleanup");
        assert!(!body.exists());
        println!("FIRST_RETAINED");
        std::io::stdout().flush().unwrap();
        // Retry the same objects after the one injected EAGAIN. This is explicit
        // caller action, never automatic library retry or unprotected cleanup.
        let result = submit(&domain, &mut pending).unwrap().join();
        assert_eq!(
            result.termination,
            if case.ends_with("panic") {
                Termination::Panicked
            } else {
                Termination::Completed
            }
        );
        assert!(body.exists());
    } else {
        assert!(
            pending.is_empty(),
            "second spawn failure must finish admitted work cleanup"
        );
        assert!(!body.exists(), "owner failure ran a unit");
    }
    assert!(pending.is_empty());
    assert!(cleanup.exists());
    let mut next: Vec<WorkUnit> = vec![Box::new(|| Ok(()))];
    assert_eq!(
        submit(&domain, &mut next).unwrap().join().termination,
        Termination::Completed
    );
    println!("CASE_PASS");
}
fn line(rx: &mpsc::Receiver<String>) -> String {
    rx.recv_timeout(LIMIT).unwrap()
}
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.path().join("execution.lock"))
        .unwrap();
    dir
}
fn probe(path: &Path) {
    let domain = ExecutionDomain::open_existing(path, uid()).unwrap();
    let mut pending: Vec<WorkUnit> = vec![Box::new(|| Ok(()))];
    assert!(matches!(
        submit(&domain, &mut pending),
        Err(ExecutionError::Busy)
    ));
    assert_eq!(pending.len(), 1, "Busy consumed the probe's pending work");
}
#[test]
#[ignore = "Explicit Linux run with NODOMI_EXECUTION_PTHREAD_INJECTOR; root and nobody"]
fn real_pthread_failures_preserve_admission_and_owner_cleanup() {
    let injector = std::env::var_os("NODOMI_EXECUTION_PTHREAD_INJECTOR")
        .expect("explicit isolated LD_PRELOAD injector required");
    for case in ["first-tls", "first-panic", "owner-tls", "owner-panic"] {
        let dir = fixture();
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "admission_fault_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("NODOMI_EXECUTION_ADMISSION_CASE", case)
                .env("NODOMI_EXECUTION_ADMISSION_DIRECTORY", dir.path())
                .env(
                    "NODOMI_FAIL_PTHREAD_AT",
                    if case.starts_with("first") { "2" } else { "3" },
                )
                .env("LD_PRELOAD", &injector)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let (tx, rx) = mpsc::channel();
        let stdout = child.0.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let _ = tx.send(line.unwrap());
            }
        });
        let mut retained = !case.starts_with("first");
        loop {
            let output = line(&rx);
            if output.ends_with("FIRST_RETAINED") {
                retained = true;
            }
            if output.ends_with("TLS_HELD") {
                if !retained {
                    child.0.stdin.take().unwrap().write_all(b"R").unwrap();
                    panic!("first pthread failure consumed work and installed caller TLS");
                }
                break;
            }
        }
        probe(dir.path());
        child.0.stdin.take().unwrap().write_all(b"R").unwrap();
        loop {
            if line(&rx).ends_with("CASE_PASS") {
                break;
            }
        }
        assert!(child.0.wait().unwrap().success(), "{case}");
        println!(
            "{case}: retained-before-admission/Busy-during-task-TLS/cleanup-and-reacquire PASS"
        );
    }
}
