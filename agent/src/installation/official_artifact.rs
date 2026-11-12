//! Read-only admission of an exact GitHub release and a held formal archive.

use super::{
    package::{FormalPackage, FormalPackageMember, PackageInspectionError, verify_formal_package},
    plan_store::{same_snapshot, stat},
};
use crate::release::{
    github::{ReleaseClient, VerifiedRelease},
    manifest::{GithubReleaseId, HostRequirements, ReleaseError, parse_agent_tag},
};
use ring::digest::{Context, SHA256};
use std::{fs::File, os::unix::fs::FileExt};

#[cfg(test)]
mod tests;

const INSTALLER_PATH: &str = "bin/nodomi-agentctl";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfficialArtifactError {
    Release(ReleaseError),
    TagMismatch,
    Package(PackageInspectionError),
    InstallerUnreadable,
    InstallerMismatch,
}

/// Release facts and exact archive observation obtained from live, verified
/// GitHub metadata. The same input file remains held for the installation
/// owner, which must recheck its binding before any later publication.
pub struct AdmittedOfficialArtifact {
    release: VerifiedRelease,
    package: FormalPackage,
    archive: File,
}

impl AdmittedOfficialArtifact {
    pub fn release(&self) -> &VerifiedRelease {
        &self.release
    }

    pub fn package(&self) -> &FormalPackage {
        &self.package
    }

    pub fn archive(&self) -> &File {
        &self.archive
    }

    pub fn into_parts(self) -> (VerifiedRelease, File, FormalPackage) {
        (self.release, self.archive, self.package)
    }

    /// Compare this Linux process's running ELF with the admitted installer
    /// member. First-use provenance must already be checked by the operator.
    pub fn verify_running_installer(&self) -> Result<(), OfficialArtifactError> {
        let member = self
            .package
            .members
            .iter()
            .find(|member| member.path == INSTALLER_PATH)
            .ok_or(OfficialArtifactError::InstallerMismatch)?;
        let executable =
            File::open("/proc/self/exe").map_err(|_| OfficialArtifactError::InstallerUnreadable)?;
        verify_installer_file(&executable, member)
    }
}

/// Verify the exact requested release through the fixed GitHub client, then
/// compare the formal package structure, compressed length and digest against
/// the release's verified program asset. Local JSON is not an input.
pub fn admit_official_artifact(
    client: &mut ReleaseClient,
    release_id: GithubReleaseId,
    expected_tag: &str,
    host: HostRequirements,
    archive: File,
) -> Result<AdmittedOfficialArtifact, OfficialArtifactError> {
    parse_agent_tag(expected_tag).map_err(OfficialArtifactError::Release)?;
    let release = client
        .load_exact(release_id, host)
        .map_err(OfficialArtifactError::Release)?;
    if release.tag() != expected_tag {
        return Err(OfficialArtifactError::TagMismatch);
    }
    let candidate = archive
        .try_clone()
        .map_err(|_| OfficialArtifactError::Package(PackageInspectionError::Io))?;
    let package =
        verify_formal_package(candidate, &release).map_err(OfficialArtifactError::Package)?;
    Ok(AdmittedOfficialArtifact {
        release,
        package,
        archive,
    })
}

fn verify_installer_file(
    file: &File,
    expected: &FormalPackageMember,
) -> Result<(), OfficialArtifactError> {
    use OfficialArtifactError::{InstallerMismatch, InstallerUnreadable};
    let before = stat(file, None).map_err(|_| InstallerUnreadable)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || u64::try_from(before.st_size) != Ok(expected.length)
    {
        return Err(InstallerMismatch);
    }
    let mut digest = Context::new(&SHA256);
    let mut buffer = [0; 32 * 1024];
    let mut offset = 0;
    while offset < expected.length {
        let size = (expected.length - offset).min(buffer.len() as u64) as usize;
        let read = file
            .read_at(&mut buffer[..size], offset)
            .map_err(|_| InstallerUnreadable)?;
        if read == 0 {
            return Err(InstallerMismatch);
        }
        digest.update(&buffer[..read]);
        offset += read as u64;
    }
    let after = stat(file, None).map_err(|_| InstallerUnreadable)?;
    let actual_sha256: String = digest
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if !same_snapshot(&before, &after) || actual_sha256 != expected.sha256 {
        return Err(InstallerMismatch);
    }
    Ok(())
}
