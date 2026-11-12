use nodomi_agent::{model::Availability::*, source::*};
use std::{
    io::{self, Cursor},
    process::Command,
};
#[test]
fn source_read_is_bounded_and_utf8_checked() {
    assert_eq!(read_bounded(Cursor::new(b"abc"), 3), Ok("abc".into()));
    assert_eq!(read_bounded(Cursor::new(b"abcd"), 3), Err(CollectionError));
    assert_eq!(read_bounded(Cursor::new([255]), 3), Err(CollectionError));
}
#[test]
fn native_read_errors_have_distinct_availability() {
    assert_eq!(
        classify_io(&io::Error::from(io::ErrorKind::NotFound)),
        Unsupported
    );
    assert_eq!(
        classify_io(&io::Error::from(io::ErrorKind::PermissionDenied)),
        PermissionDenied
    );
    assert_eq!(
        classify_io(&io::Error::from(io::ErrorKind::InvalidData)),
        CollectionError
    );
}
#[test]
fn cli_rejects_unbounded_counts_intervals_and_unknown_arguments() {
    for args in [
        vec!["--samples", "0"],
        vec!["--samples", "11"],
        vec!["--interval-ms", "0"],
        vec!["--interval-ms", "60001"],
        vec!["--url", "https://example.com"],
        vec!["--samples"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_nodomi-agent"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
#[test]
#[cfg(not(target_os = "linux"))]
fn real_collector_refuses_non_linux_host() {
    assert!(matches!(LinuxSource.capture(), Err(Unsupported)));
}
#[test]
#[cfg(target_os = "linux")]
fn linux_capture_reads_kernel_time_page_size_and_shared_sources() {
    let first = LinuxSource.capture().unwrap();
    let second = LinuxSource.capture().unwrap();
    assert!(second.monotonic_ns > first.monotonic_ns);
    assert!(first.page_size.unwrap().is_power_of_two());
    assert!(first.cpu.unwrap().contains_key("total"));
    assert!(first.memory.unwrap()["MemTotal"].unwrap() > 0);
    assert!(first.load.is_ok());
    assert!(first.swap.is_ok());
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Run explicitly as an unprivileged Linux user; root bypasses file mode permissions"]
fn real_filesystem_absence_and_permission_denial_are_distinct() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!(
        "nodomi-io-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("private-source");
    std::fs::write(&path, b"source").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let result = std::fs::File::open(&path);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(&path).unwrap();
    let absent = std::fs::File::open(&path);
    std::fs::remove_dir(&dir).unwrap();
    assert_eq!(
        classify_io(&result.expect_err("this test must run as an unprivileged user")),
        PermissionDenied
    );
    assert_eq!(classify_io(&absent.unwrap_err()), Unsupported);
}
