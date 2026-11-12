#[cfg(target_os = "linux")]
fn run() -> Result<u8, String> {
    use nodomi_agent::{installation::inspect_formal_package, release::manifest::Platform};
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::OpenOptionsExt,
        path::Path,
    };

    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if matches!(args.as_slice(), [install, status, ..] if install == "install" && status == "status")
    {
        let ids = match args.as_slice() {
            [_, _, operation, target] => operation.to_str().zip(target.to_str()),
            _ => None,
        };
        return install_status(ids);
    }
    let [package, inspect, platform, path] = args.as_slice() else {
        return Err(USAGE.into());
    };
    if package != "package" || inspect != "inspect" {
        return Err(USAGE.into());
    }
    let platform = match platform.to_str() {
        Some("linux-aarch64") => Platform::LinuxAarch64,
        Some("linux-x86_64") => Platform::LinuxX86_64,
        _ => return Err("unsupported package platform".into()),
    };
    let path = Path::new(path);
    if !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file()) {
        return Err("package must be a regular file".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot open package")?;
    let package = inspect_formal_package(file, platform)
        .map_err(|error| format!("package inspection failed ({error:?})"))?;
    write_json(&package)?;
    Ok(0)
}

#[cfg(target_os = "linux")]
fn install_status(ids: Option<(&str, &str)>) -> Result<u8, String> {
    use nodomi_agent::installation::{InstallStatusError, lookup_install_operation};
    let result = match ids {
        Some((operation, target)) => lookup_install_operation(operation, target),
        None => Err(InstallStatusError::InvalidInput),
    };
    let error = match result {
        Ok(result) => {
            write_json(&result)?;
            return Ok(result.exit_code());
        }
        Err(error) => error,
    };
    let (exit_code, code) = match error {
        InstallStatusError::InvalidInput => (2, "INPUT_INVALID"),
        InstallStatusError::PermissionDenied => (3, "PERMISSION_DENIED"),
        InstallStatusError::NotFound => (3, "TARGET_MISMATCH"),
        InstallStatusError::RecoveryRequired => (3, "PARTIAL_INITIALIZATION"),
    };
    write_json(&serde_json::json!({
        "exitCode": exit_code,
        "errorCode": code,
        "operationId": null,
    }))?;
    Ok(exit_code)
}

#[cfg(target_os = "linux")]
fn write_json(value: &impl serde::Serialize) -> Result<(), String> {
    use std::io::{self, Write};
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, value).map_err(|_| "cannot write report")?;
    writeln!(output).map_err(|_| "cannot write report")?;
    output.flush().map_err(|_| "cannot write report".into())
}

#[cfg(target_os = "linux")]
const USAGE: &str = "usage: nodomi-agentctl package inspect <platform> <archive>\n       nodomi-agentctl install status <operation-id> <target-id>";

#[cfg(not(target_os = "linux"))]
fn run() -> Result<u8, String> {
    Err("nodomi-agentctl requires Linux".into())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => code.into(),
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::from(2)
        }
    }
}
