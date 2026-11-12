use super::*;
use crate::{
    installation::{
        executable::fixture_elf,
        package::{fixture_formal_archive, package_file},
    },
    release::{github::ReleaseReadOptions, github_tests::Fixture, manifest::Platform},
};
use std::{fs, os::unix::fs::MetadataExt};

const TAG: &str = "agent-v0.1.0";
const PLATFORM: Platform = Platform::LinuxAarch64;

fn host() -> HostRequirements {
    HostRequirements {
        platform: PLATFORM,
        kernel: [6, 1, 0],
        libc: None,
        wire_protocol: 1,
        supervisor_protocol: 1,
        config_format: 1,
        queue_format: 1,
    }
}

fn id() -> GithubReleaseId {
    GithubReleaseId::new(123).unwrap()
}

#[test]
fn admission_uses_the_exact_held_formal_archive() {
    let bytes = fixture_formal_archive(PLATFORM, b"official fixture\n");
    let fixture = Fixture::with_artifact(PLATFORM, &bytes);
    let mut client = fixture.client(ReleaseReadOptions::default());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("package.tar.gz");
    fs::write(&path, &bytes).unwrap();
    let file = File::open(&path).unwrap();
    let inode = file.metadata().unwrap().ino();
    fs::rename(&path, dir.path().join("original")).unwrap();
    fs::write(&path, b"substitution").unwrap();

    let admitted = admit_official_artifact(&mut client, id(), TAG, host(), file).unwrap();
    assert_eq!(admitted.release().tag(), TAG);
    assert_eq!(admitted.release().target().github_release_id, id());
    assert_eq!(admitted.archive().metadata().unwrap().ino(), inode);
    assert_eq!(admitted.package().archive_bytes, bytes.len() as u64);
    assert_eq!(admitted.package().members.len(), 6);
    let installer = admitted
        .package()
        .members
        .iter()
        .find(|m| m.path == INSTALLER_PATH)
        .unwrap();
    assert_eq!(
        verify_installer_file(&package_file(&fixture_elf(PLATFORM, None)), installer),
        Ok(())
    );
    assert_eq!(
        verify_installer_file(
            &package_file(&vec![0; installer.length as usize]),
            installer
        ),
        Err(OfficialArtifactError::InstallerMismatch)
    );
    assert_eq!(
        admitted.verify_running_installer(),
        Err(OfficialArtifactError::InstallerMismatch)
    );
}

#[test]
fn wrong_tag_and_substituted_archive_are_rejected() {
    let bytes = fixture_formal_archive(PLATFORM, b"official fixture\n");
    let fixture = Fixture::with_artifact(PLATFORM, &bytes);
    let mut client = fixture.client(ReleaseReadOptions::default());
    assert!(matches!(
        admit_official_artifact(
            &mut client,
            id(),
            "agent-v0.1.1",
            host(),
            package_file(&bytes)
        ),
        Err(OfficialArtifactError::TagMismatch)
    ));
    let changed = fixture_formal_archive(PLATFORM, b"changed fixture\n");
    assert!(matches!(
        admit_official_artifact(&mut client, id(), TAG, host(), package_file(&changed)),
        Err(OfficialArtifactError::Package(
            PackageInspectionError::DigestMismatch
        ))
    ));
}

#[test]
fn current_release_state_and_manifest_are_part_of_admission() {
    for (scenario, error) in [
        ("mutable-release", ReleaseError::Unavailable),
        ("prerelease", ReleaseError::Prerelease),
        ("manifest-swapped", ReleaseError::AssetMismatch),
    ] {
        let fixture = Fixture::new(scenario);
        let mut client = fixture.client(ReleaseReadOptions::default());
        assert!(matches!(
            admit_official_artifact(&mut client, id(), TAG, host(), package_file(b"untrusted local file")),
            Err(OfficialArtifactError::Release(actual)) if actual == error
        ));
    }
}
