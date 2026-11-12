use super::{
    github::{ReleaseClient, ReleaseReadOptions},
    manifest::{GithubReleaseId, HostRequirements, Platform, ReleaseError, business_release_id},
};
use ring::digest::{SHA256, digest};
use serde_json::Value;
use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const API: &str = "/repos/DashunLiu/Nodomio";
const ARTIFACT: &[u8] = b"nodomi arm64 release fixture\n";
const COMMIT: &str = "1234567890abcdef1234567890abcdef12345678";
const CA: &[u8] = include_bytes!("../../tests/fixtures/tls/ca.pem");

pub(crate) struct Fixture {
    child: Child,
    state: tempfile::TempDir,
    origin: String,
}

impl Fixture {
    pub(crate) fn new(scenario: &str) -> Self {
        Self::for_platform(scenario, Platform::LinuxAarch64)
    }

    pub(crate) fn for_platform(scenario: &str, platform: Platform) -> Self {
        Self::start(scenario, platform, None)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_artifact(platform: Platform, bytes: &[u8]) -> Self {
        Self::start("happy", platform, Some(bytes))
    }

    fn start(scenario: &str, platform: Platform, artifact: Option<&[u8]>) -> Self {
        let state = tempfile::tempdir().unwrap();
        if let Some(bytes) = artifact {
            fs::write(state.path().join("artifact.tar.gz"), bytes).unwrap();
        }
        let child = Command::new("python3")
            .args([
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/https_release.py"
                ),
                scenario,
            ])
            .arg(state.path())
            .arg(platform.release_name())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut fixture = Self {
            child,
            state,
            origin: String::new(),
        };
        let mut line = String::new();
        BufReader::new(fixture.child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port: u16 = line
            .trim()
            .parse()
            .expect("release fixture failed to start");
        fixture.origin = format!("https://localhost:{port}");
        fixture
    }

    pub(crate) fn client(&self, options: ReleaseReadOptions) -> ReleaseClient {
        ReleaseClient::for_fixture(&self.origin, CA, options).unwrap()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }

    pub(crate) fn requests(&self) -> Vec<Value> {
        fs::read_to_string(self.state.path().join("requests.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    pub(crate) fn paths(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|request| request["path"].as_str().unwrap().to_owned())
            .collect()
    }

    #[cfg(target_os = "linux")]
    pub(in crate::release) fn stop(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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

fn id(value: u64) -> GithubReleaseId {
    GithubReleaseId::new(value).unwrap()
}

fn error<T>(result: Result<T, ReleaseError>) -> ReleaseError {
    match result {
        Ok(_) => panic!("untrusted response unexpectedly accepted"),
        Err(error) => error,
    }
}

#[test]
fn production_budgets_can_only_be_reduced() {
    for options in [
        ReleaseReadOptions {
            max_pages: 6,
            ..Default::default()
        },
        ReleaseReadOptions {
            max_pages: 0,
            ..Default::default()
        },
        ReleaseReadOptions {
            max_redirects: 4,
            ..Default::default()
        },
        ReleaseReadOptions {
            control_timeout: Duration::ZERO,
            ..Default::default()
        },
        ReleaseReadOptions {
            control_timeout: Duration::from_secs(61),
            ..Default::default()
        },
        ReleaseReadOptions {
            download_timeout: Duration::from_secs(301),
            ..Default::default()
        },
    ] {
        assert_eq!(
            error(ReleaseClient::official(options)),
            ReleaseError::InvalidOptions
        );
    }
}

#[test]
fn highest_agent_release_requires_complete_scan() {
    let fixture = Fixture::new("happy");
    let mut client = fixture.client(ReleaseReadOptions::default());
    let release = client.discover(host()).unwrap();
    assert_eq!(release.tag(), "agent-v0.1.0");
    assert_eq!(release.commit(), COMMIT);
    assert_eq!(release.target().github_release_id, id(123));
    assert_eq!(release.target().release_id, business_release_id(id(123)));
    assert_eq!(release.target().artifact.length, ARTIFACT.len() as u64);
    assert_eq!(
        release.manifest_bytes(),
        fs::read(fixture.state.path().join("manifest.json")).unwrap()
    );
    let mut bytes = Vec::new();
    client.download(&release, &mut bytes).unwrap();
    assert_eq!(bytes, ARTIFACT);
    let sha256: String = digest(&SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(release.target().artifact.sha256, sha256);

    let paths = fixture.paths();
    let position = |path: &str| paths.iter().position(|p| p == path).unwrap();
    assert!(
        position(&format!("{API}/releases?per_page=100&page=2"))
            < position(&format!("{API}/releases/123"))
    );
    assert!(!paths.iter().any(|path| path.ends_with("/latest")));
    assert!(!paths.iter().any(|path| path.ends_with("/releases/122")));

    let fixture = Fixture::new("too-many-pages");
    let mut client = fixture.client(ReleaseReadOptions::default());
    assert_eq!(
        error(client.discover(host())),
        ReleaseError::IncompleteCatalog
    );
    let paths = fixture.paths();
    assert_eq!(
        paths
            .iter()
            .filter(|p| p.contains("?per_page=100&page="))
            .count(),
        5
    );
    assert!(!paths.iter().any(|path| path.ends_with("/releases/123")));
}

#[test]
fn latest_other_component_and_incompatible_highest_do_not_select_old() {
    let fixture = Fixture::new("incompatible");
    let mut client = fixture.client(ReleaseReadOptions::default());
    assert_eq!(error(client.discover(host())), ReleaseError::Incompatible);
    let paths = fixture.paths();
    assert!(paths.iter().any(|p| p.ends_with("/releases/123")));
    for rejected in ["/releases/122", "/releases/124", "/releases/latest"] {
        assert!(!paths.iter().any(|p| p.ends_with(rejected)));
    }
}

#[test]
fn business_uuid_without_binding_needs_bounded_resolution() {
    let fixture = Fixture::new("happy");
    let mut client = fixture.client(ReleaseReadOptions::default());
    let wanted = business_release_id(id(123));
    let release = client.resolve_business_id(wanted, host()).unwrap();
    assert_eq!(release.target().github_release_id, id(123));
    assert!(fixture.paths().iter().any(|p| p.ends_with("page=2")));

    let fixture = Fixture::new("happy");
    let mut client = fixture.client(ReleaseReadOptions::default());
    let older = client
        .resolve_business_id(business_release_id(id(122)), host())
        .unwrap();
    assert_eq!(older.target().github_release_id, id(122));
    assert_eq!(older.tag(), "agent-v0.0.9");
    assert_eq!(older.commit(), COMMIT);

    let fixture = Fixture::new("happy");
    let mut client = fixture.client(ReleaseReadOptions {
        max_pages: 1,
        ..ReleaseReadOptions::default()
    });
    assert_eq!(
        error(client.resolve_business_id(business_release_id(id(123)), host())),
        ReleaseError::IncompleteCatalog
    );
    assert!(!fixture.paths().iter().any(|p| p.ends_with("page=2")));

    let fixture = Fixture::new("happy");
    let mut client = fixture.client(ReleaseReadOptions::default());
    assert_eq!(
        error(client.resolve_business_id(business_release_id(id(999)), host())),
        ReleaseError::NotFound
    );
}

#[test]
fn malformed_pagination_cannot_be_treated_as_complete() {
    for scenario in [
        "link-malformed",
        "link-off-domain",
        "link-cycle",
        "link-duplicate",
    ] {
        let fixture = Fixture::new(scenario);
        let mut client = fixture.client(ReleaseReadOptions::default());
        let failure = error(client.discover(host()));
        assert!(
            matches!(
                failure,
                ReleaseError::IncompleteCatalog | ReleaseError::InvalidResponse
            ),
            "{scenario}: {failure:?}"
        );
        assert!(!fixture.paths().iter().any(|p| p.ends_with("/releases/123")));
        assert_eq!(
            fixture
                .paths()
                .iter()
                .filter(|p| p.ends_with("page=1"))
                .count(),
            1,
            "{scenario} reused a previously requested page"
        );
    }
}

#[test]
fn missing_published_field_does_not_select_an_older_release() {
    let fixture = Fixture::new("published-field-missing");
    let mut client = fixture.client(ReleaseReadOptions::default());
    assert_eq!(
        error(client.discover(host())),
        ReleaseError::InvalidResponse
    );
    assert!(
        !fixture
            .paths()
            .iter()
            .any(|path| path.ends_with("/releases/122"))
    );
}

#[test]
fn missing_catalog_page_does_not_prove_business_id_absence() {
    let fixture = Fixture::new("page-not-found");
    let mut client = fixture.client(ReleaseReadOptions::default());
    assert_eq!(
        error(client.resolve_business_id(business_release_id(id(123)), host())),
        ReleaseError::IncompleteCatalog
    );
    assert!(fixture.paths().iter().any(|path| path.ends_with("page=2")));
}

#[test]
fn manifest_and_asset_swap_rejected() {
    for (scenario, expected) in [
        ("manifest-swapped", ReleaseError::AssetMismatch),
        ("asset-changed", ReleaseError::ReleaseChanged),
        ("release-changed", ReleaseError::ReleaseChanged),
        ("manifest-mismatch", ReleaseError::ManifestMismatch),
    ] {
        let fixture = Fixture::new(scenario);
        let mut client = fixture.client(ReleaseReadOptions::default());
        assert_eq!(
            error(client.load_exact(id(123), host())),
            expected,
            "{scenario}"
        );
        let paths = fixture.paths();
        assert!(paths.iter().any(|p| p.ends_with("/releases/assets/457")));
        assert!(!paths.iter().any(|p| p.ends_with("/releases/assets/456")));
        if matches!(scenario, "asset-changed" | "release-changed") {
            assert_eq!(
                paths
                    .iter()
                    .filter(|p| p.ends_with("/releases/123"))
                    .count(),
                2
            );
        }
    }
}

#[test]
fn read_limits_and_missing_metadata_fail_closed() {
    for (scenario, allowed) in [
        (
            "too-many-assets",
            &[ReleaseError::InvalidResponse, ReleaseError::AssetMismatch][..],
        ),
        (
            "asset-list-next",
            &[ReleaseError::InvalidResponse, ReleaseError::AssetMismatch][..],
        ),
        ("manifest-too-large", &[ReleaseError::ManifestTooLarge][..]),
        (
            "digest-missing",
            &[ReleaseError::AssetMismatch, ReleaseError::InvalidResponse][..],
        ),
        ("control-too-large", &[ReleaseError::InvalidResponse][..]),
    ] {
        let fixture = Fixture::new(scenario);
        let mut client = fixture.client(ReleaseReadOptions::default());
        let failure = error(client.load_exact(id(123), host()));
        assert!(allowed.contains(&failure), "{scenario}: {failure:?}");
        assert!(
            !fixture
                .paths()
                .iter()
                .any(|p| p.ends_with("/releases/assets/456"))
        );
    }
}

#[test]
fn unavailable_release_and_withdrawn_are_distinct() {
    for (scenario, expected) in [
        ("not-found", ReleaseError::NotFound),
        ("withdrawn", ReleaseError::Withdrawn),
        ("prerelease", ReleaseError::Prerelease),
        ("mutable-release", ReleaseError::Unavailable),
        ("unavailable", ReleaseError::Unavailable),
        ("rate-limited", ReleaseError::RateLimited),
    ] {
        let fixture = Fixture::new(scenario);
        let mut client = fixture.client(ReleaseReadOptions::default());
        assert_eq!(
            error(client.load_exact(id(123), host())),
            expected,
            "{scenario}"
        );
    }
}

#[test]
fn redirects_share_deadline_and_send_no_credentials() {
    let fixture = Fixture::new("redirect");
    let mut client = fixture.client(ReleaseReadOptions::default());
    let release = client.load_exact(id(123), host()).unwrap();
    let mut output = Vec::new();
    client.download(&release, &mut output).unwrap();
    assert_eq!(output, ARTIFACT);
    let requests = fixture.requests();
    for request in &requests {
        assert_eq!(request["credentials"], serde_json::json!([]));
    }
    for path in [
        format!("{API}/releases/assets/456"),
        "/fixture/redirect/second".to_string(),
        "/fixture/redirect/package?signature=fixture".to_string(),
    ] {
        assert!(requests.iter().any(|r| r["path"] == path), "{path}");
    }

    for scenario in [
        "redirect-deadline",
        "download-stalled-headers",
        "download-stalled-body",
    ] {
        let fixture = Fixture::new(scenario);
        let mut client = fixture.client(ReleaseReadOptions {
            download_timeout: Duration::from_millis(400),
            ..ReleaseReadOptions::default()
        });
        let release = client.load_exact(id(123), host()).unwrap();
        let start = Instant::now();
        assert_eq!(
            error(client.download(&release, &mut Vec::new())),
            ReleaseError::Timeout,
            "{scenario}"
        );
        assert!(start.elapsed() < Duration::from_secs(2), "{scenario}");
        let requests = fixture.requests();
        assert!(
            requests
                .iter()
                .all(|r| r["credentials"] == serde_json::json!([]))
        );
        if scenario == "redirect-deadline" {
            assert!(
                requests
                    .iter()
                    .any(|r| r["path"] == "/fixture/redirect/second")
            );
        }
    }
}

#[test]
fn unsafe_redirects_and_redirect_limits_fail_before_next_hop() {
    for scenario in [
        "redirect-off-domain",
        "redirect-http",
        "redirect-private-ip",
        "redirect-userinfo",
        "redirect-too-many",
    ] {
        let fixture = Fixture::new(scenario);
        let mut client = fixture.client(ReleaseReadOptions::default());
        let release = client.load_exact(id(123), host()).unwrap();
        assert_eq!(
            error(client.download(&release, &mut Vec::new())),
            ReleaseError::InvalidRedirect,
            "{scenario}"
        );
        assert!(
            !fixture
                .paths()
                .iter()
                .any(|p| p == "/fixture/redirect/rejected")
        );
    }

    let fixture = Fixture::new("redirect");
    let mut client = fixture.client(ReleaseReadOptions {
        max_redirects: 1,
        ..ReleaseReadOptions::default()
    });
    let release = client.load_exact(id(123), host()).unwrap();
    assert_eq!(
        error(client.download(&release, &mut Vec::new())),
        ReleaseError::InvalidRedirect
    );
    assert!(
        !fixture
            .paths()
            .iter()
            .any(|p| p.starts_with("/fixture/redirect/package"))
    );
}

#[test]
fn control_timeout_covers_headers_and_bodies() {
    for scenario in [
        "control-stalled-tls",
        "control-stalled-headers",
        "control-stalled-body",
        "control-trickle",
        "control-deadline",
    ] {
        let fixture = Fixture::new(scenario);
        let mut client = fixture.client(ReleaseReadOptions {
            control_timeout: Duration::from_millis(400),
            ..ReleaseReadOptions::default()
        });
        let start = Instant::now();
        assert_eq!(
            error(client.load_exact(id(123), host())),
            ReleaseError::Timeout,
            "{scenario}"
        );
        assert!(start.elapsed() < Duration::from_secs(2), "{scenario}");
    }
}

#[test]
fn download_requires_exact_length_and_digest() {
    for scenario in [
        "download-extra-byte",
        "download-short",
        "download-wrong-digest",
    ] {
        let fixture = Fixture::new(scenario);
        let mut client = fixture.client(ReleaseReadOptions::default());
        let release = client.load_exact(id(123), host()).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            error(client.download(&release, &mut output)),
            ReleaseError::AssetMismatch,
            "{scenario}"
        );
        assert!(output.len() <= ARTIFACT.len(), "{scenario}");
    }
}

#[test]
fn download_propagates_a_writer_failure() {
    struct RejectingWriter;
    impl Write for RejectingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture cannot write"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let fixture = Fixture::new("happy");
    let mut client = fixture.client(ReleaseReadOptions::default());
    let release = client.load_exact(id(123), host()).unwrap();
    assert_eq!(
        error(client.download(&release, &mut RejectingWriter)),
        ReleaseError::WriteFailed
    );
}

#[test]
fn release_client_rejects_an_untrusted_tls_certificate() {
    let fixture = Fixture::new("happy");
    let wrong_root = include_bytes!("../../tests/fixtures/tls/server.pem");
    let mut client =
        ReleaseClient::for_fixture(&fixture.origin, wrong_root, ReleaseReadOptions::default())
            .unwrap();
    assert_eq!(
        error(client.load_exact(id(123), host())),
        ReleaseError::Transport
    );
    assert!(!fixture.state.path().join("requests.jsonl").exists());
}
