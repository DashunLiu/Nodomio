use super::{
    PlanInstallation, PlanTargetContext, ReleasePlanBinding, bind_release, public_target,
    recheck_binding,
};
use crate::release::{
    github::{ReleaseClient, ReleaseReadOptions, VerifiedRelease},
    github_tests::Fixture,
    manifest::{GithubReleaseId, HostRequirements, Platform, ReleaseError, business_release_id},
};
use serde_json::{Value, json};

const RELEASE_ID: u64 = 123;
const EXPIRES_AT: u64 = 1_800_000_000_000;
const INSTALLATION_ID: &str = "9bd73031-81c4-4fd4-85bb-8ad7b1945d36";
const CURRENT_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const API: &str = "/repos/DashunLiu/Nodomio";

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

fn current_release(client: &mut ReleaseClient) -> VerifiedRelease {
    client
        .load_exact(GithubReleaseId::new(RELEASE_ID).unwrap(), host())
        .unwrap()
}

fn install_context() -> PlanTargetContext {
    PlanTargetContext::new(
        PlanInstallation::FreshInstall {
            installation_id: INSTALLATION_ID.into(),
        },
        EXPIRES_AT,
    )
    .unwrap()
}

fn update_context() -> PlanTargetContext {
    PlanTargetContext::new(
        PlanInstallation::Existing {
            installation_id: INSTALLATION_ID.into(),
            current_sha256: CURRENT_SHA256.into(),
            config_revision: 7,
        },
        EXPIRES_AT,
    )
    .unwrap()
}

fn expected_error(
    result: Result<VerifiedRelease, ReleaseError>,
    expected: ReleaseError,
    scenario: &str,
) {
    match result {
        Ok(_) => panic!("{scenario}: a changed or incompatible release was accepted"),
        Err(error) => assert_eq!(error, expected, "{scenario}"),
    }
}

fn assert_only_exact_requests(paths: &[String], reads: usize) {
    for (suffix, count) in [
        ("/releases/123", 2 * reads),
        ("/releases/123/assets?per_page=100", 2 * reads),
        ("/releases/assets/457", reads),
        ("/git/ref/tags/agent-v0.1.0", reads),
    ] {
        let exact_path = format!("{API}{suffix}");
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.as_str() == exact_path)
                .count(),
            count,
            "{suffix}: {paths:?}",
        );
    }
    assert!(!paths.iter().any(|path| {
        path.starts_with(&format!("{API}/releases?"))
            || path.ends_with("/releases/latest")
            || path.ends_with("/releases/122")
            || path.ends_with("/releases/assets/456")
    }));
}

#[test]
fn public_projection_cannot_rebuild_exact_plan() {
    let fixture = Fixture::new("happy");
    let verified = current_release(&mut fixture.client(ReleaseReadOptions::default()));
    let paths = fixture.paths();

    let install = bind_release(&verified, &install_context());
    let update = bind_release(&verified, &update_context());
    let projected = serde_json::to_value(public_target(&install)).unwrap();
    let artifact = &verified.target().artifact;
    assert_eq!(
        projected,
        json!({
            "releaseId": business_release_id(GithubReleaseId::new(RELEASE_ID).unwrap()).as_str(),
            "sequence": 100001,
            "version": "0.1.0",
            "sha256": artifact.sha256,
            "length": artifact.length,
            "isSecurityUpdate": false,
            "targetPath": "agent/linux-aarch64/0.1.0-agent",
        }),
    );
    assert_eq!(
        serde_json::to_value(public_target(&update)).unwrap(),
        projected
    );
    assert!(serde_json::from_value::<ReleasePlanBinding>(projected).is_err());

    let install = serde_json::to_value(install).unwrap();
    let update = serde_json::to_value(update).unwrap();
    assert_eq!(
        install["context"],
        json!({
            "expiresAtUnixMs": EXPIRES_AT,
            "installation": {"kind": "freshInstall", "installationId": INSTALLATION_ID},
        }),
    );
    assert_eq!(
        update["context"],
        json!({
            "expiresAtUnixMs": EXPIRES_AT,
            "installation": {
                "kind": "existing",
                "installationId": INSTALLATION_ID,
                "currentSha256": CURRENT_SHA256,
                "configRevision": 7,
            },
        }),
    );
    assert_eq!(install["release"], update["release"]);
    assert_eq!(fixture.paths(), paths);
}

#[test]
fn deserialized_binding_is_not_verified_release() {
    let fixture = Fixture::new("happy");
    let verified = current_release(&mut fixture.client(ReleaseReadOptions::default()));
    let before = fixture.paths();
    let binding = bind_release(&verified, &update_context());
    let serialized = serde_json::to_vec(&binding).unwrap();
    let restored: ReleasePlanBinding = serde_json::from_slice(&serialized).unwrap();
    let record = serde_json::to_value(restored).unwrap();
    assert_eq!(
        record,
        serde_json::from_slice::<Value>(&serialized).unwrap()
    );

    let artifact = &verified.target().artifact;
    let manifest = verified.manifest_asset();
    assert_eq!(record["bindingVersion"], 1);
    assert_eq!(record["release"]["repository"], "DashunLiu/Nodomio");
    assert_eq!(record["release"]["githubReleaseId"], RELEASE_ID);
    assert_eq!(record["release"]["tag"], verified.tag());
    assert_eq!(record["release"]["commit"], verified.commit());
    assert_eq!(
        record["release"]["releaseId"],
        verified.target().release_id.as_str()
    );
    assert_eq!(record["release"]["sequence"], verified.target().sequence);
    assert_eq!(
        record["release"]["version"],
        verified.target().version.to_string()
    );
    assert_eq!(record["release"]["platform"], "linux-aarch64");
    assert_eq!(record["release"]["isSecurityUpdate"], false);
    for (field, expected) in [("programAsset", artifact), ("manifestAsset", manifest)] {
        assert_eq!(
            record["release"][field],
            json!({
                "id": expected.id.get(),
                "name": expected.name,
                "length": expected.length,
                "sha256": expected.sha256,
            }),
        );
    }
    let compatibility_sha = record["release"]["compatibilitySha256"].as_str().unwrap();
    assert_eq!(
        compatibility_sha,
        "965d433f7855b1721d3ee2406183eb10e68d454d2d5dab72f433dd7a7580baef"
    );

    for path in [
        "",
        "/release",
        "/release/programAsset",
        "/release/manifestAsset",
        "/context",
        "/context/installation",
    ] {
        let mut with_extra = record.clone();
        with_extra.pointer_mut(path).unwrap()["verified"] = json!(true);
        assert!(
            serde_json::from_value::<ReleasePlanBinding>(with_extra).is_err(),
            "{path}"
        );
    }
    let positional = json!([
        record["bindingVersion"],
        record["release"],
        record["context"]
    ]);
    assert!(serde_json::from_value::<ReleasePlanBinding>(positional).is_err());

    let mut no_manifest = record.clone();
    no_manifest["release"]
        .as_object_mut()
        .unwrap()
        .remove("manifestAsset");
    assert!(serde_json::from_value::<ReleasePlanBinding>(no_manifest).is_err());
    assert_eq!(fixture.paths(), before);
}

#[test]
fn inconsistent_plan_records_fail_before_rechecking() {
    let fixture = Fixture::new("happy");
    let verified = current_release(&mut fixture.client(ReleaseReadOptions::default()));
    let binding = bind_release(&verified, &update_context());
    let before = fixture.paths();
    let record = serde_json::to_value(&binding).unwrap();
    for (path, value) in [
        ("/bindingVersion", json!(2)),
        ("/release/repository", json!("other/Nodomio")),
        ("/release/githubReleaseId", json!(124)),
        ("/release/sequence", json!(100002)),
        ("/release/platform", json!({"linux-aarch64": null})),
        (
            "/release/programAsset/name",
            json!("../nodomi-agent.tar.gz"),
        ),
        ("/release/manifestAsset/id", json!(456)),
        ("/release/manifestAsset/length", json!(65537)),
        ("/context/expiresAtUnixMs", json!(0)),
        ("/context/installation/configRevision", json!(0)),
        ("/context/installation/currentSha256", json!("missing")),
    ] {
        let mut changed = record.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            serde_json::from_value::<ReleasePlanBinding>(changed).is_err(),
            "{path}"
        );
    }
    let duplicate = serde_json::to_string(&binding).unwrap().replacen(
        r#""bindingVersion":1"#,
        r#""bindingVersion":1,"bindingVersion":1"#,
        1,
    );
    assert!(serde_json::from_str::<ReleasePlanBinding>(&duplicate).is_err());
    assert_eq!(fixture.paths(), before);
}

#[test]
fn persisted_binding_recheck_uses_ids_and_never_latest() {
    let original = Fixture::new("happy");
    let verified = current_release(&mut original.client(ReleaseReadOptions::default()));
    let saved = serde_json::to_vec(&bind_release(&verified, &update_context())).unwrap();
    let restored: ReleasePlanBinding = serde_json::from_slice(&saved).unwrap();

    let fresh = Fixture::new("happy");
    let mut client = fresh.client(ReleaseReadOptions::default());
    for _ in 0..2 {
        let rechecked = recheck_binding(&mut client, &restored, host()).unwrap();
        assert_eq!(rechecked.target(), verified.target());
        assert_eq!(rechecked.manifest_asset(), verified.manifest_asset());
        assert_eq!(rechecked.manifest_bytes(), verified.manifest_bytes());
        assert_eq!(rechecked.commit(), verified.commit());
    }
    assert_only_exact_requests(&fresh.paths(), 2);
    assert_only_exact_requests(&original.paths(), 1);

    let incompatible = HostRequirements {
        kernel: [4, 19, 0],
        ..host()
    };
    expected_error(
        recheck_binding(&mut client, &restored, incompatible),
        ReleaseError::Incompatible,
        "host no longer meets the manifest requirements",
    );
    assert_eq!(
        fresh
            .paths()
            .iter()
            .filter(|p| p.ends_with("/releases/123"))
            .count(),
        5,
    );
}

#[test]
fn manifest_or_asset_changed_recheck_fails() {
    let original = Fixture::new("happy");
    let verified = current_release(&mut original.client(ReleaseReadOptions::default()));
    let binding = bind_release(&verified, &install_context());

    for scenario in [
        "binding-manifest-bytes",
        "binding-program-id",
        "binding-manifest-id",
        "binding-source-commit",
    ] {
        let changed = Fixture::new(scenario);
        let mut client = changed.client(ReleaseReadOptions::default());

        // Each scenario represents a coherent new GitHub response for the same release ID.
        let observed = current_release(&mut client);
        assert_eq!(
            observed.target().github_release_id,
            verified.target().github_release_id
        );
        assert_eq!(observed.target().release_id, verified.target().release_id);
        assert_eq!(observed.tag(), verified.tag());
        assert_eq!(
            observed.target().artifact.sha256,
            verified.target().artifact.sha256
        );
        match scenario {
            "binding-manifest-bytes" => {
                assert_eq!(observed.target(), verified.target());
                assert_eq!(observed.commit(), verified.commit());
                assert_eq!(observed.manifest_asset().id, verified.manifest_asset().id);
                assert_eq!(
                    observed.manifest_bytes().len(),
                    verified.manifest_bytes().len()
                );
                assert_ne!(observed.manifest_bytes(), verified.manifest_bytes());
            }
            "binding-program-id" => {
                assert_ne!(observed.target().artifact.id, verified.target().artifact.id);
                assert_eq!(observed.manifest_asset().id, verified.manifest_asset().id);
                assert_eq!(observed.commit(), verified.commit());
            }
            "binding-manifest-id" => {
                assert_eq!(observed.target(), verified.target());
                assert_eq!(observed.commit(), verified.commit());
                assert_eq!(observed.manifest_bytes(), verified.manifest_bytes());
                assert_ne!(observed.manifest_asset().id, verified.manifest_asset().id);
            }
            "binding-source-commit" => {
                assert_eq!(observed.target(), verified.target());
                assert_eq!(observed.manifest_asset(), verified.manifest_asset());
                assert_eq!(observed.manifest_bytes(), verified.manifest_bytes());
                assert_ne!(observed.commit(), verified.commit());
            }
            _ => unreachable!(),
        }
        expected_error(
            recheck_binding(&mut client, &binding, host()),
            ReleaseError::ReleaseChanged,
            scenario,
        );
        let paths = changed.paths();
        assert_eq!(
            paths
                .iter()
                .filter(|p| p.ends_with("/releases/123"))
                .count(),
            4
        );
        assert!(
            !paths
                .iter()
                .any(|p| p.contains("/releases?") || p.ends_with("/releases/latest"))
        );
    }
}
