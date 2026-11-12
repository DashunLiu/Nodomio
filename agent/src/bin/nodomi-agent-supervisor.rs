//! Foreground owner of a single installed Linux collector process.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
#[path = "supervisor/process.rs"]
mod process;
#[cfg(target_os = "linux")]
#[path = "supervisor/protected.rs"]
mod protected;

#[cfg(target_os = "linux")]
type SupervisorResult<T> = Result<T, &'static str>;

fn main() -> ExitCode {
    let result = if std::env::args_os().nth(1).is_some() {
        Err("INVALID_ARGUMENTS")
    } else {
        run()
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> SupervisorResult<()> {
    // SAFETY: geteuid takes no arguments and has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("ROOT_REQUIRED");
    }
    process::seal_inherited_descriptors()?;
    let signals = process::Signals::capture()?;
    let layout = protected::Layout::open()?;
    layout.check_running_supervisor()?;
    let instance = layout.lock_instance()?;
    let executable = layout.verify_collector()?;
    if signals.stop_requested(0)? {
        return Ok(());
    }
    // The service manager owns service activation. This process owns the
    // direct collector lifetime and does not resume pending install operations.
    process::supervise(&executable, &instance, &signals)
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), &'static str> {
    Err("UNSUPPORTED_HOST")
}
