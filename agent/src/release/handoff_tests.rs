use super::{
    binding::{
        PlanInstallation, PlanTargetContext, ReleasePlanBinding, bind_release, public_target,
        recheck_binding,
    },
    github::{ReleaseReadOptions, VerifiedRelease},
    github_tests::Fixture,
    manifest::{GithubReleaseId, HostRequirements, Platform, ReleaseError},
};
use ring::digest::{SHA256, digest};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

const API: &str = "/repos/DashunLiu/Nodomio";
const INSTALLATION_ID: &str = "9bd73031-81c4-4fd4-85bb-8ad7b1945d36";
const EXPIRES_AT: u64 = 1_800_000_000_000;
const LOCAL_STATE: [(&str, &[u8]); 3] = [
    ("current-agent", b"previous installed program fixture\n"),
    ("identity.json", br#"{"fixture":"original local identity"}"#),
    (
        "collector-config.json",
        br#"{"fixture":"original collector configuration"}"#,
    ),
];
const PLAN_FILE: &str = "pending-release-plan.json";
const STAGED_FILE: &str = "candidate.tar.gz";
const STAGED_BYTES: &[u8] = b"nodomi arm64 release fixture\n";

fn host() -> HostRequirements {
    HostRequirements {
        platform: Platform::LinuxAarch64,
        kernel: [6, 1, 0],
        libc: None,
        wire_protocol: 1,
        supervisor_protocol: 1,
        config_format: 1,
        queue_format: 1,
    }
}

fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn local_state() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in LOCAL_STATE {
        fs::write(dir.path().join(name), bytes).unwrap();
    }
    dir
}

fn assert_local_state(dir: &Path, extra_files: &[&str]) {
    for (name, bytes) in LOCAL_STATE {
        assert_eq!(fs::read(dir.join(name)).unwrap(), bytes, "{name} changed");
    }
    let mut expected: Vec<_> = LOCAL_STATE.iter().map(|(name, _)| *name).collect();
    expected.extend_from_slice(extra_files);
    expected.sort_unstable();
    let mut actual: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    actual.sort_unstable();
    assert_eq!(actual, expected);
}

fn update_context(dir: &Path) -> PlanTargetContext {
    let current_sha256 = sha256(&fs::read(dir.join("current-agent")).unwrap());
    PlanTargetContext::new(
        PlanInstallation::Existing {
            installation_id: INSTALLATION_ID.into(),
            current_sha256,
            config_revision: 7,
        },
        EXPIRES_AT,
    )
    .unwrap()
}

fn persist_binding(dir: &Path, binding: &ReleasePlanBinding) -> ReleasePlanBinding {
    let path = dir.join(PLAN_FILE);
    let bytes = serde_json::to_vec(binding).unwrap();
    fs::write(&path, &bytes).unwrap();
    let restored = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(binding, &restored);
    restored
}

fn assert_only_reads(fixture: &Fixture, allowed: &[&str]) {
    for request in fixture.requests() {
        assert_eq!(request["method"], "GET");
        assert_eq!(request["credentials"], serde_json::json!([]));
        let path = request["path"].as_str().unwrap();
        assert!(
            path.strip_prefix(API)
                .is_some_and(|path| allowed.contains(&path)),
            "{path}"
        );
    }
}

fn expected_error(result: Result<VerifiedRelease, ReleaseError>, expected: ReleaseError) {
    assert_eq!(result.unwrap_err(), expected);
}

#[test]
fn linux_readonly_release_to_bound_plan() {
    let state = local_state();
    let fixture = Fixture::new("happy");
    let verified = fixture
        .client(ReleaseReadOptions::default())
        .discover(host())
        .unwrap();
    assert_eq!(verified.target().github_release_id.get(), 123);
    let binding = bind_release(&verified, &update_context(state.path()));
    drop(verified);
    let restored = persist_binding(state.path(), &binding);

    let mut client = fixture.client(ReleaseReadOptions::default());
    let rechecked = recheck_binding(&mut client, &restored, host()).unwrap();
    let target = public_target(&restored);
    let candidate_path = state.path().join(STAGED_FILE);
    let mut candidate = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&candidate_path)
        .unwrap();
    let downloaded = client.download(&rechecked, &mut candidate).unwrap();
    candidate.sync_all().unwrap();
    drop(candidate);
    let bytes = fs::read(&candidate_path).unwrap();
    assert_eq!(bytes, STAGED_BYTES);
    assert_eq!(downloaded.length, bytes.len() as u64);
    assert_eq!(downloaded.sha256, sha256(&bytes));
    assert_eq!(target.sha256, downloaded.sha256);
    assert_eq!(target.length, downloaded.length);
    assert_eq!(target.target_path, "agent/linux-aarch64/0.1.0-agent");
    assert_eq!(
        fs::metadata(candidate_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let paths = fixture.paths();
    for (suffix, count) in [
        ("/releases?per_page=100&page=1", 1),
        ("/releases?per_page=100&page=2", 1),
        ("/releases/123", 4),
        ("/releases/123/assets?per_page=100", 4),
        ("/releases/assets/457", 2),
        ("/releases/assets/456", 1),
    ] {
        let path = format!("{API}{suffix}");
        assert_eq!(
            paths.iter().filter(|p| p.as_str() == path).count(),
            count,
            "{path}"
        );
    }
    assert_only_reads(
        &fixture,
        &[
            "/releases?per_page=100&page=1",
            "/releases?per_page=100&page=2",
            "/releases/123",
            "/releases/123/assets?per_page=100",
            "/releases/assets/457",
            "/git/ref/tags/agent-v0.1.0",
            "/git/tags/fedcba0987654321fedcba0987654321fedcba09",
            "/releases/assets/456",
        ],
    );
    assert_local_state(state.path(), &[PLAN_FILE, STAGED_FILE]);
}

#[test]
fn offline_or_rate_limited_keeps_current_program() {
    let state = local_state();
    let mut fixture = Fixture::new("happy");
    let mut client = fixture.client(ReleaseReadOptions::default());
    let id = GithubReleaseId::new(123).unwrap();
    let verified = client.load_exact(id, host()).unwrap();
    let binding = bind_release(&verified, &update_context(state.path()));
    let restored = persist_binding(state.path(), &binding);
    let saved_plan = fs::read(state.path().join(PLAN_FILE)).unwrap();
    let before_offline = fixture.paths();

    fixture.stop();
    expected_error(
        recheck_binding(&mut client, &restored, host()),
        ReleaseError::Transport,
    );
    assert_eq!(fixture.paths(), before_offline);
    assert_local_state(state.path(), &[PLAN_FILE]);
    assert_eq!(fs::read(state.path().join(PLAN_FILE)).unwrap(), saved_plan);

    let limited = Fixture::new("rate-limited");
    expected_error(
        recheck_binding(
            &mut limited.client(ReleaseReadOptions::default()),
            &restored,
            host(),
        ),
        ReleaseError::RateLimited,
    );
    assert_eq!(limited.paths(), [format!("{API}/releases/123")]);
    assert_only_reads(&limited, &["/releases/123"]);
    assert_local_state(state.path(), &[PLAN_FILE]);
    assert_eq!(fs::read(state.path().join(PLAN_FILE)).unwrap(), saved_plan);
}

#[test]
fn same_id_prerelease_transition_is_not_new_install_authority() {
    let state = local_state();
    let stable = Fixture::new("happy");
    let id = GithubReleaseId::new(123).unwrap();
    let verified = stable
        .client(ReleaseReadOptions::default())
        .load_exact(id, host())
        .unwrap();
    let context = PlanTargetContext::new(
        PlanInstallation::FreshInstall {
            installation_id: INSTALLATION_ID.into(),
        },
        EXPIRES_AT,
    )
    .unwrap();
    let binding = bind_release(&verified, &context);
    drop(verified);
    let restored = persist_binding(state.path(), &binding);
    let saved_plan = fs::read(state.path().join(PLAN_FILE)).unwrap();

    let transitioned = Fixture::new("prerelease");
    let mut client = transitioned.client(ReleaseReadOptions::default());
    expected_error(
        recheck_binding(&mut client, &restored, host()),
        ReleaseError::Prerelease,
    );
    expected_error(client.load_exact(id, host()), ReleaseError::Prerelease);
    assert_eq!(transitioned.paths(), vec![format!("{API}/releases/123"); 2]);
    assert_only_reads(&transitioned, &["/releases/123"]);
    assert_local_state(state.path(), &[PLAN_FILE]);
    assert_eq!(fs::read(state.path().join(PLAN_FILE)).unwrap(), saved_plan);
}
