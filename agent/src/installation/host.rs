use crate::release::manifest::{HostLibc, Platform};
use std::{
    ffi::CStr,
    fs::{self, OpenOptions},
    io::Read,
    mem::MaybeUninit,
    os::unix::fs::OpenOptionsExt,
};

/// Facts visible in the current Linux namespace.
#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallHost {
    pub platform: Option<Platform>,
    pub kernel: Option<KernelObservation>,
    /// GNU libc version of the running process, when available.
    pub libc: Option<HostLibc>,
    pub effective_uid: u32,
    pub service_manager: ServiceManagerObservation,
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelObservation {
    pub release: String,
    pub version: Option<[u64; 3]>,
}

/// The visible init and runtime markers. Service readiness is checked by the installer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceManagerObservation {
    Systemd,
    OpenRc,
    Ambiguous,
    Unknown,
}

pub(super) fn inspect_host() -> InstallHost {
    let (platform, kernel) = kernel_facts();
    let pid_one = pid_one_name();
    let systemd =
        fs::symlink_metadata("/run/systemd/system").is_ok_and(|metadata| metadata.is_dir());
    let openrc =
        fs::symlink_metadata("/run/openrc/softlevel").is_ok_and(|metadata| metadata.is_file());
    InstallHost {
        platform,
        kernel,
        libc: libc_version(),
        // SAFETY: geteuid takes no arguments and returns the process's effective UID.
        effective_uid: unsafe { libc::geteuid() },
        service_manager: service_manager(pid_one.as_deref().map(str::trim), systemd, openrc),
    }
}

fn pid_one_name() -> Option<String> {
    const MAX_BYTES: u64 = 64;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/proc/1/comm")
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut name = String::new();
    file.take(MAX_BYTES + 1).read_to_string(&mut name).ok()?;
    (name.len() <= MAX_BYTES as usize && !name.trim().is_empty()).then_some(name)
}

fn kernel_facts() -> (Option<Platform>, Option<KernelObservation>) {
    let mut name = MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: name points to writable storage for the entire utsname.
    if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
        return (None, None);
    }
    // SAFETY: uname initializes the structure and terminates its strings on success.
    let name = unsafe { name.assume_init() };
    // SAFETY: successful uname populated NUL-terminated machine and release fields.
    let (machine, release) = unsafe {
        (
            CStr::from_ptr(name.machine.as_ptr()),
            CStr::from_ptr(name.release.as_ptr()),
        )
    };
    let platform = match machine.to_bytes() {
        b"x86_64" => Some(Platform::LinuxX86_64),
        b"aarch64" => Some(Platform::LinuxAarch64),
        _ => None,
    };
    let kernel = release.to_str().ok().map(|release| KernelObservation {
        release: release.into(),
        version: kernel_version(release),
    });
    (platform, kernel)
}

fn kernel_version(release: &str) -> Option<[u64; 3]> {
    parse_numeric_version(release.split(['-', '+']).next()?, false)
}

#[cfg(target_env = "gnu")]
fn libc_version() -> Option<HostLibc> {
    // SAFETY: glibc returns a pointer to its process-lifetime version string.
    let version = unsafe { libc::gnu_get_libc_version() };
    if version.is_null() {
        return None;
    }
    // SAFETY: the nonnull version pointer is a NUL-terminated glibc string.
    let version = unsafe { CStr::from_ptr(version) }.to_str().ok()?;
    parse_numeric_version(version, true).map(HostLibc::Glibc)
}

#[cfg(not(target_env = "gnu"))]
fn libc_version() -> Option<HostLibc> {
    None
}

fn parse_numeric_version(text: &str, allow_two_parts: bool) -> Option<[u64; 3]> {
    let mut parts = text.split('.');
    let number = |part: &str| {
        if part.bytes().all(|byte| byte.is_ascii_digit()) {
            part.parse::<u64>().ok()
        } else {
            None
        }
    };
    let major = number(parts.next()?)?;
    let minor = number(parts.next()?)?;
    let patch = match parts.next() {
        Some(part) => number(part)?,
        None if allow_two_parts => 0,
        None => return None,
    };
    parts.next().is_none().then_some([major, minor, patch])
}

fn service_manager(
    pid_one: Option<&str>,
    systemd: bool,
    openrc: bool,
) -> ServiceManagerObservation {
    use ServiceManagerObservation::*;
    match (pid_one, systemd, openrc) {
        (Some("systemd"), true, false) => Systemd,
        (Some("systemd"), _, true) | (_, true, true) => Ambiguous,
        (Some("init" | "openrc-init"), false, true) => OpenRc,
        _ => Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version_uses_only_numeric_triplet_before_suffix() {
        assert_eq!(kernel_version("6.12.18-linuxkit"), Some([6, 12, 18]));
        assert_eq!(kernel_version("5.15.0+"), Some([5, 15, 0]));
        for release in ["6.12", "6.x.18", "6.12.18.1", "6.12.18foo", "6.12."] {
            assert_eq!(kernel_version(release), None, "{release}");
        }
    }

    #[test]
    fn glibc_two_part_version_has_zero_patch() {
        assert_eq!(parse_numeric_version("2.36", true), Some([2, 36, 0]));
        assert_eq!(
            parse_numeric_version("2.39.9000", true),
            Some([2, 39, 9000])
        );
        assert_eq!(parse_numeric_version("2.36.", true), None);
    }

    #[test]
    fn manager_observation_requires_consistent_markers() {
        use ServiceManagerObservation::*;
        assert_eq!(service_manager(Some("systemd"), true, false), Systemd);
        assert_eq!(service_manager(Some("init"), false, true), OpenRc);
        assert_eq!(service_manager(Some("openrc-init"), false, true), OpenRc);
        assert_eq!(service_manager(Some("systemd"), true, true), Ambiguous);
        assert_eq!(service_manager(Some("tini"), true, false), Unknown);
        assert_eq!(service_manager(Some("tini"), false, true), Unknown);
        assert_eq!(service_manager(None, false, true), Unknown);
        assert_eq!(service_manager(Some("systemd"), false, false), Unknown);
    }

    #[test]
    fn observes_actual_linux_kernel_and_effective_uid() {
        let host = crate::installation::inspect_first_install().host;
        let expected_kernel = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
        assert_eq!(host.kernel.unwrap().release, expected_kernel.trim());
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let effective_uid: u32 = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .unwrap()
            .split_ascii_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(host.effective_uid, effective_uid);
        #[cfg(target_env = "gnu")]
        assert!(matches!(host.libc, Some(HostLibc::Glibc([2, _, _]))));
    }
}
