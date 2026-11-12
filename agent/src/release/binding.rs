//! Persist release facts and recheck the same GitHub release when applying a plan.
//!
//! The owner validates the plan, its expiry, and local state before and after
//! the network check. A binding can be read from disk; a verified release must
//! come from a current verification.
//!
//! ```no_run
//! use nodomi_agent::release::{
//!     binding::{ReleasePlanBinding, recheck_binding},
//!     github::{ReleaseClient, VerifiedRelease},
//!     manifest::{HostRequirements, ReleaseError},
//! };
//!
//! fn verify_target(
//!     client: &mut ReleaseClient,
//!     binding: &ReleasePlanBinding,
//!     host: HostRequirements,
//! ) -> Result<VerifiedRelease, ReleaseError> {
//!     recheck_binding(client, binding, host)
//! }
//! ```
//!
//! ```compile_fail
//! use nodomi_agent::release::{binding::ReleasePlanBinding, github::ReleaseClient};
//!
//! fn bypass(client: &mut ReleaseClient, binding: &ReleasePlanBinding) {
//!     client.download(binding, &mut Vec::new()).unwrap();
//! }
//! ```
//!
//! ```compile_fail
//! use nodomi_agent::release::github::VerifiedRelease;
//!
//! let _: VerifiedRelease = serde_json::from_str("{}").unwrap();
//! ```

use super::{
    github::{ReleaseClient, VerifiedRelease, is_lower_hex},
    manifest::{
        AssetId, GithubReleaseId, HostRequirements, MAX_ARTIFACT_BYTES, MAX_MANIFEST_BYTES,
        ManifestArtifact, OFFICIAL_OWNER, OFFICIAL_REPO, Platform, ReleaseError, agent_asset_stem,
        business_release_id, deserialize_enum_string, deserialize_object, is_safe_positive_integer,
        parse_agent_tag, release_sequence,
    },
};
use crate::identity::uuid;
use serde::{Deserialize, Deserializer, Serialize, de};

const BINDING_VERSION: u32 = 1;

/// Independently observed installation state supplied by the plan owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PlanInstallation {
    FreshInstall {
        installation_id: String,
    },
    Existing {
        installation_id: String,
        current_sha256: String,
        config_revision: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PlanTargetContext(ContextRecord);

impl PlanTargetContext {
    /// The owner chooses the deadline and enforces it at admission.
    pub fn new(
        installation: PlanInstallation,
        expires_at_unix_ms: u64,
    ) -> Result<Self, ReleaseError> {
        let valid_installation = match &installation {
            PlanInstallation::FreshInstall { installation_id } => uuid(installation_id),
            PlanInstallation::Existing {
                installation_id,
                current_sha256,
                config_revision,
            } => {
                uuid(installation_id)
                    && is_lower_hex(current_sha256, 64)
                    && is_safe_positive_integer(*config_revision)
            }
        };
        if !valid_installation || !is_safe_positive_integer(expires_at_unix_ms) {
            return Err(ReleaseError::InvalidBinding);
        }
        Ok(Self(ContextRecord {
            installation,
            expires_at_unix_ms,
        }))
    }

    pub fn installation(&self) -> &PlanInstallation {
        &self.0.installation
    }

    pub fn expires_at_unix_ms(&self) -> u64 {
        self.0.expires_at_unix_ms
    }
}

impl<'de> Deserialize<'de> for PlanTargetContext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields: ContextRecord = deserialize_object(deserializer)?;
        Self::new(fields.installation, fields.expires_at_unix_ms)
            .map_err(|_| de::Error::custom("invalid release plan context"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContextRecord {
    #[serde(deserialize_with = "deserialize_object")]
    installation: PlanInstallation,
    expires_at_unix_ms: u64,
}

/// Non-secret v1 record to include in the owner's complete plan digest.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReleasePlanBinding(BindingRecord);

impl ReleasePlanBinding {
    pub fn context(&self) -> &PlanTargetContext {
        &self.0.context
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn platform(&self) -> Platform {
        self.0.release.platform
    }
}

impl<'de> Deserialize<'de> for ReleasePlanBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields: BindingRecord = deserialize_object(deserializer)?;
        if fields.binding_version != BINDING_VERSION || !fields.release.is_consistent() {
            return Err(de::Error::custom("invalid release plan binding"));
        }
        Ok(Self(fields))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindingRecord {
    binding_version: u32,
    #[serde(deserialize_with = "deserialize_object")]
    release: BoundRelease,
    context: PlanTargetContext,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BoundRelease {
    repository: String,
    github_release_id: u64,
    tag: String,
    commit: String,
    #[serde(deserialize_with = "deserialize_object")]
    program_asset: BoundAsset,
    #[serde(deserialize_with = "deserialize_object")]
    manifest_asset: BoundAsset,
    release_id: String,
    sequence: u64,
    version: String,
    #[serde(deserialize_with = "deserialize_enum_string")]
    platform: Platform,
    is_security_update: bool,
    compatibility_sha256: String,
}

impl BoundRelease {
    fn from_verified(release: &VerifiedRelease) -> Self {
        let target = release.target();
        Self {
            repository: format!("{OFFICIAL_OWNER}/{OFFICIAL_REPO}"),
            github_release_id: target.github_release_id.get(),
            tag: release.tag().into(),
            commit: release.commit().into(),
            program_asset: BoundAsset::from(&target.artifact),
            manifest_asset: BoundAsset::from(release.manifest_asset()),
            release_id: target.release_id.as_str().into(),
            sequence: target.sequence,
            version: target.version.to_string(),
            platform: target.platform,
            is_security_update: target.is_security_update,
            compatibility_sha256: release.compatibility_sha256(),
        }
    }

    fn is_consistent(&self) -> bool {
        let Ok(id) = GithubReleaseId::new(self.github_release_id) else {
            return false;
        };
        let Ok(version) = parse_agent_tag(&self.tag) else {
            return false;
        };
        let stem = agent_asset_stem(version, self.platform);
        self.repository.split_once('/') == Some((OFFICIAL_OWNER, OFFICIAL_REPO))
            && is_lower_hex(&self.commit, 40)
            && self.version == version.to_string()
            && self.release_id == business_release_id(id).as_str()
            && self.sequence == release_sequence(version)
            && self
                .program_asset
                .matches_name_and_limit(&format!("{stem}.tar.gz"), MAX_ARTIFACT_BYTES)
            && self
                .manifest_asset
                .matches_name_and_limit(&format!("{stem}.release.json"), MAX_MANIFEST_BYTES as u64)
            && self.program_asset.id != self.manifest_asset.id
            && is_lower_hex(&self.compatibility_sha256, 64)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundAsset {
    id: u64,
    name: String,
    length: u64,
    sha256: String,
}

impl From<&ManifestArtifact> for BoundAsset {
    fn from(asset: &ManifestArtifact) -> Self {
        Self {
            id: asset.id.get(),
            name: asset.name.clone(),
            length: asset.length,
            sha256: asset.sha256.clone(),
        }
    }
}

impl BoundAsset {
    fn matches_name_and_limit(&self, name: &str, max_length: u64) -> bool {
        AssetId::new(self.id).is_ok()
            && self.name == name
            && (1..=max_length).contains(&self.length)
            && is_lower_hex(&self.sha256, 64)
    }
}

/// Existing local-tool contract target fields. The path is a logical name.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentUpdateTargetProjection {
    pub release_id: String,
    pub sequence: u64,
    pub version: String,
    pub sha256: String,
    pub length: u64,
    pub is_security_update: bool,
    pub target_path: String,
}

pub fn bind_release(release: &VerifiedRelease, context: &PlanTargetContext) -> ReleasePlanBinding {
    ReleasePlanBinding(BindingRecord {
        binding_version: BINDING_VERSION,
        release: BoundRelease::from_verified(release),
        context: context.clone(),
    })
}

pub fn public_target(binding: &ReleasePlanBinding) -> AgentUpdateTargetProjection {
    let release = &binding.0.release;
    AgentUpdateTargetProjection {
        release_id: release.release_id.clone(),
        sequence: release.sequence,
        version: release.version.clone(),
        sha256: release.program_asset.sha256.clone(),
        length: release.program_asset.length,
        is_security_update: release.is_security_update,
        target_path: format!(
            "agent/{}/{}-agent",
            release.platform.release_name(),
            release.version
        ),
    }
}

/// Fetch the bound numeric ID again and compare every verified release fact.
pub fn recheck_binding(
    client: &mut ReleaseClient,
    binding: &ReleasePlanBinding,
    host: HostRequirements,
) -> Result<VerifiedRelease, ReleaseError> {
    let expected = &binding.0.release;
    if host.platform != expected.platform {
        return Err(ReleaseError::Incompatible);
    }
    let id = GithubReleaseId::new(expected.github_release_id)?;
    let current = client.load_exact(id, host)?;
    if BoundRelease::from_verified(&current) != *expected {
        return Err(ReleaseError::ReleaseChanged);
    }
    Ok(current)
}

#[cfg(test)]
#[path = "binding_tests.rs"]
mod tests;
