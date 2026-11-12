use super::*;
use std::process::{Child, Command, Stdio};

fn fixture(stdout: &str, stderr: &str) -> Vec<u8> {
    format!("Id=nodomi-agent.service\nLoadState=loaded\nFragmentPath=/etc/systemd/system/nodomi-agent.service\nDropInPaths=\nSourcePath=\nTransient=no\nNeedDaemonReload=no\nActiveState=active\nSubState=running\nMainPID=42\nInvocationID=00000000000000000000000000000001\nStandardInput=null\nStandardOutput={stdout}\nStandardError={stderr}\nLogNamespace=\nLogRateLimitIntervalUSec=0\nLogRateLimitBurst=0\n").into_bytes()
}

#[test]
fn observed_defaults_and_discard_settings_never_create_byte_bounds() {
    for (out, err, expected) in [
        ("journal", "inherit", ConfiguredLogStream::Journal),
        ("null", "null", ConfiguredLogStream::Null),
        ("future-kind", "inherit", ConfiguredLogStream::Unknown),
    ] {
        let value = fixture(out, err);
        let result = observe_pair(&mut || Ok(value.clone()), 42, 1, None).unwrap();
        assert_eq!(result.stdout(), expected);
        assert_eq!(result.main_pid(), 42);
        assert_eq!(result.invocation_id(), 1);
        assert!(result.default_namespace());
        assert_eq!(result.configured_rate_burst(), 0);
        assert_eq!(result.stdout_direct_payload_byte_upper_bound(), None);
        assert_eq!(result.stderr_direct_payload_byte_upper_bound(), None);
        assert_eq!(result.direct_payload_byte_upper_bound(), None);
        assert_eq!(result.allocated_byte_upper_bound(), None);
    }
}

#[test]
fn rejects_wrong_instance_reload_dropins_and_incomplete_properties() {
    let value = String::from_utf8(fixture("journal", "inherit")).unwrap();
    for (old, new) in [
        ("MainPID=42", "MainPID=43"),
        (
            "00000000000000000000000000000001",
            "00000000000000000000000000000002",
        ),
        ("NeedDaemonReload=no", "NeedDaemonReload=yes"),
        ("DropInPaths=", "DropInPaths=/etc/override.conf"),
        ("ActiveState=active", "ActiveState=inactive"),
        ("LogRateLimitBurst=0", "LogRateLimitBurst=-1"),
        ("LogRateLimitBurst=0", "LogRateLimitBurst=4294967296"),
        ("LogNamespace=\n", ""),
        (
            "StandardOutput=journal",
            "StandardOutput=journal\nStandardOutput=null",
        ),
    ] {
        let changed = value.replace(old, new).into_bytes();
        assert!(
            observe_pair(&mut || Ok(changed.clone()), 42, 1, None).is_err(),
            "{old}"
        );
    }
    assert!(observe_pair(&mut || panic!("must not query"), 1, 1, None).is_err());
    assert!(observe_pair(&mut || panic!("must not query"), 42, 0, None).is_err());
}

#[test]
fn redacted_destination_changes_still_reject_unstable_read() {
    let first = fixture("file:/first", "inherit");
    let second = fixture("file:/second", "inherit");
    let mut reads = [first, second].into_iter();
    assert_eq!(
        observe_pair(&mut || Ok(reads.next().unwrap()), 42, 1, None),
        Err(SystemdLoggingError::UnstableObservation)
    );
    let file = fixture("file:/private-name", "inherit");
    let result = observe_pair(&mut || Ok(file.clone()), 42, 1, None).unwrap();
    assert_eq!(result.stdout(), ConfiguredLogStream::File);
    assert!(!format!("{result:?}").contains("private-name"));
}

#[test]
fn custom_journal_namespace_and_rate_values_are_not_capacity_evidence() {
    let value = String::from_utf8(fixture("journal", "journal"))
        .unwrap()
        .replace("LogNamespace=", "LogNamespace=fixture-namespace")
        .replace("LogRateLimitIntervalUSec=0", "LogRateLimitIntervalUSec=30s")
        .replace("LogRateLimitBurst=0", "LogRateLimitBurst=1000")
        .into_bytes();
    let result = observe_pair(&mut || Ok(value.clone()), 42, 1, None).unwrap();
    assert!(!result.default_namespace());
    assert_eq!(result.configured_rate_interval(), "30s");
    assert_eq!(result.configured_rate_burst(), 1000);
    assert_eq!(result.allocated_byte_upper_bound(), None);
}

#[test]
fn query_failure_and_invalid_bytes_fail_closed() {
    assert_eq!(
        observe_pair(&mut || Err(SystemdLoggingError::Unavailable), 42, 1, None),
        Err(SystemdLoggingError::Unavailable)
    );
    for bytes in [vec![0xff], vec![b'x'; 16385], b"Id=bad\0value\n".to_vec()] {
        assert!(properties(&bytes).is_err());
    }
}

#[test]
fn actual_descriptors_are_independent_of_loaded_output_categories() {
    let temporary = tempfile::tempdir().unwrap();
    let regular_file_named_null = File::create(temporary.path().join("null")).unwrap();
    let child = SleepingChild::new(regular_file_named_null.into());
    let pid = child.0.id();
    let root = open_root().unwrap();
    let unit = fixture_for_process(pid);
    let result = observe_pair(&mut || Ok(unit.clone()), pid, 1, Some(&root)).unwrap();
    assert_eq!(result.stdout(), ConfiguredLogStream::Journal);
    assert_eq!(result.stderr(), ConfiguredLogStream::Null);
    assert_eq!(result.stdout_direct_payload_byte_upper_bound(), Some(0));
    assert_eq!(result.stderr_direct_payload_byte_upper_bound(), None);
    assert_eq!(result.direct_payload_byte_upper_bound(), None);
    assert_eq!(result.allocated_byte_upper_bound(), None);
}

#[test]
fn exited_main_process_cannot_contribute_a_direct_bound() {
    let mut child = SleepingChild::new(Stdio::null());
    let pid = child.0.id();
    let root = open_root().unwrap();
    let unit = fixture_for_process(pid);
    let mut queries = 0;
    let mut query = || {
        queries += 1;
        if queries == 2 {
            child.0.kill().unwrap();
            child.0.wait().unwrap();
        }
        Ok(unit.clone())
    };
    let result = observe_pair(&mut query, pid, 1, Some(&root)).unwrap();
    assert_eq!(queries, 2);
    assert_eq!(result.stdout_direct_payload_byte_upper_bound(), None);
    assert_eq!(result.stderr_direct_payload_byte_upper_bound(), None);
}

fn fixture_for_process(pid: u32) -> Vec<u8> {
    String::from_utf8(fixture("journal", "null"))
        .unwrap()
        .replace("MainPID=42", &format!("MainPID={pid}"))
        .into_bytes()
}

struct SleepingChild(Child);

impl SleepingChild {
    fn new(stderr: Stdio) -> Self {
        Self(
            Command::new("/bin/sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(stderr)
                .spawn()
                .unwrap(),
        )
    }
}

impl Drop for SleepingChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Only run in a dedicated real systemd container/VM with a disposable exact
/// fixture unit. This verifies command/property interoperability, not Nodomi
/// supervisor identity or full manager capacity admission.
#[test]
#[ignore = "requires dedicated systemd fixture unit"]
fn actual_systemd_loaded_logging_observation() {
    let pid: u32 = std::env::var("NODOMI_LOG_PROBE_PID")
        .unwrap()
        .parse()
        .unwrap();
    let invocation =
        u128::from_str_radix(&std::env::var("NODOMI_LOG_PROBE_INVOCATION").unwrap(), 16).unwrap();
    let result = observe(pid, invocation).unwrap();
    let (stdout, stderr, actual_stdout, actual_stderr) =
        match std::env::var("NODOMI_LOG_PROBE_SINK").as_deref() {
            Ok("null") => (
                ConfiguredLogStream::Null,
                ConfiguredLogStream::Null,
                Some(0),
                Some(0),
            ),
            Ok("file") => (
                ConfiguredLogStream::File,
                ConfiguredLogStream::Null,
                None,
                Some(0),
            ),
            _ => (
                ConfiguredLogStream::Journal,
                ConfiguredLogStream::Inherit,
                None,
                None,
            ),
        };
    assert_eq!(result.stdout(), stdout);
    assert_eq!(result.stderr(), stderr);
    assert_eq!(
        result.stdout_direct_payload_byte_upper_bound(),
        actual_stdout
    );
    assert_eq!(
        result.stderr_direct_payload_byte_upper_bound(),
        actual_stderr
    );
    assert_eq!(
        result.direct_payload_byte_upper_bound(),
        actual_stdout.and(actual_stderr)
    );
    assert_eq!(result.configured_rate_burst(), 7);
    assert_eq!(result.allocated_byte_upper_bound(), None);
    assert_eq!(
        observe(pid, invocation ^ 2),
        Err(SystemdLoggingError::WrongInvocation)
    );
}
