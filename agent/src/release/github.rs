//! Read-only release discovery and verification against the official GitHub repository.

mod dns;
mod http;

use super::manifest::{
    AssetId, ExpectedArtifact, ExpectedManifest, GithubReleaseId, HostRequirements,
    MAX_ARTIFACT_BYTES, MAX_MANIFEST_BYTES, ManifestArtifact, ManifestRecord, ManifestTarget,
    ReleaseError, ReleaseId, agent_asset_stem, business_release_id, check_compatibility,
    deserialize_object, parse_agent_tag, parse_manifest,
};
use http::{Deadline, ReleaseHttp};
use reqwest::{
    Url,
    header::{HeaderMap, LINK},
};
use serde::Deserialize;
use std::{
    collections::HashSet,
    io::Write,
    time::{Duration, SystemTime},
};
use zeroize::Zeroizing;

const PAGE_SIZE: usize = 100;
const MAX_PAGES: usize = 5;
const MAX_ASSETS: usize = 16;
const MAX_REDIRECTS: usize = 3;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_TAG_OBJECTS: usize = 4;

pub struct ReleaseReadOptions {
    pub control_timeout: Duration,
    pub download_timeout: Duration,
    pub max_pages: usize,
    pub max_redirects: usize,
}

impl Default for ReleaseReadOptions {
    fn default() -> Self {
        Self {
            control_timeout: CONTROL_TIMEOUT,
            download_timeout: DOWNLOAD_TIMEOUT,
            max_pages: MAX_PAGES,
            max_redirects: MAX_REDIRECTS,
        }
    }
}

impl ReleaseReadOptions {
    fn validate(&self) -> Result<(), ReleaseError> {
        if self.control_timeout.is_zero()
            || self.control_timeout > CONTROL_TIMEOUT
            || self.download_timeout.is_zero()
            || self.download_timeout > DOWNLOAD_TIMEOUT
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || self.max_redirects > MAX_REDIRECTS
        {
            return Err(ReleaseError::InvalidOptions);
        }
        Ok(())
    }
}

pub struct ReleaseClient {
    http: ReleaseHttp,
    options: ReleaseReadOptions,
}

#[derive(Debug)]
pub struct VerifiedRelease {
    record: ManifestRecord,
    commit: String,
    tag: String,
    manifest_asset: ManifestArtifact,
    manifest_bytes: Vec<u8>,
    checked_at: SystemTime,
}

impl VerifiedRelease {
    pub fn target(&self) -> &ManifestTarget {
        self.record.target()
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn manifest_asset(&self) -> &ManifestArtifact {
        &self.manifest_asset
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub fn checked_at(&self) -> SystemTime {
        self.checked_at
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn platform_compatibility(
        &self,
        platform: Option<super::manifest::Platform>,
        kernel: Option<[u64; 3]>,
        libc: Option<super::manifest::HostLibc>,
    ) -> super::manifest::PlatformCompatibility {
        self.record.platform_compatibility(platform, kernel, libc)
    }

    pub(super) fn compatibility_sha256(&self) -> String {
        self.record.compatibility_sha256()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DownloadedArtifact {
    pub length: u64,
    pub sha256: String,
}

impl ReleaseClient {
    pub fn official(options: ReleaseReadOptions) -> Result<Self, ReleaseError> {
        options.validate()?;
        let http = ReleaseHttp::official(options.max_redirects)?;
        Ok(Self { http, options })
    }

    /// For a trusted caller with an explicitly supplied
    /// repository Contents-read credential. The token stays in memory, is
    /// absent from verified release facts, and is never sent to redirects.
    pub fn official_with_read_token(
        options: ReleaseReadOptions,
        token: Zeroizing<String>,
    ) -> Result<Self, ReleaseError> {
        options.validate()?;
        let http = ReleaseHttp::official(options.max_redirects)?.with_read_token(token)?;
        Ok(Self { http, options })
    }

    #[cfg(test)]
    pub(crate) fn for_fixture(
        origin: &str,
        ca: &[u8],
        options: ReleaseReadOptions,
    ) -> Result<Self, ReleaseError> {
        options.validate()?;
        let http = ReleaseHttp::for_fixture(origin, ca, options.max_redirects)?;
        Ok(Self { http, options })
    }

    pub fn discover(&mut self, host: HostRequirements) -> Result<VerifiedRelease, ReleaseError> {
        let deadline = Deadline::new(self.options.control_timeout);
        let selected = self
            .catalog(deadline)?
            .into_iter()
            .filter_map(|release| {
                let version = parse_agent_tag(&release.tag_name).ok()?;
                release.is_published_stable().then_some((version, release))
            })
            .max_by_key(|(version, _)| *version)
            .map(|(_, release)| release)
            .ok_or(ReleaseError::NotFound)?;
        self.verify_catalog_entry(selected, &host, deadline)
    }

    pub fn resolve_business_id(
        &mut self,
        wanted: ReleaseId,
        host: HostRequirements,
    ) -> Result<VerifiedRelease, ReleaseError> {
        let deadline = Deadline::new(self.options.control_timeout);
        let selected = self
            .catalog(deadline)?
            .into_iter()
            .find(|entry| business_release_id(entry.id) == wanted)
            .ok_or(ReleaseError::NotFound)?;
        self.verify_catalog_entry(selected, &host, deadline)
    }

    pub fn load_exact(
        &mut self,
        id: GithubReleaseId,
        host: HostRequirements,
    ) -> Result<VerifiedRelease, ReleaseError> {
        let deadline = Deadline::new(self.options.control_timeout);
        let release = self.release(id, deadline)?;
        self.verify(release, &host, deadline)
    }

    /// Writes to caller-owned staging output. Discard it on any error.
    /// The deadline bounds the network transfer; a blocked writer cannot be interrupted.
    pub fn download(
        &mut self,
        release: &VerifiedRelease,
        output: &mut dyn Write,
    ) -> Result<DownloadedArtifact, ReleaseError> {
        let artifact = &release.target().artifact;
        let deadline = Deadline::new(self.options.download_timeout);
        self.http.copy_asset(artifact, deadline, output)?;
        Ok(DownloadedArtifact {
            length: artifact.length,
            sha256: artifact.sha256.clone(),
        })
    }

    fn verify_catalog_entry(
        &self,
        entry: Release,
        host: &HostRequirements,
        deadline: Deadline,
    ) -> Result<VerifiedRelease, ReleaseError> {
        let release = self.release(entry.id, deadline)?;
        if release.tag_name != entry.tag_name {
            return Err(ReleaseError::ReleaseChanged);
        }
        self.verify(release, host, deadline)
    }

    fn verify(
        &self,
        release: Release,
        host: &HostRequirements,
        deadline: Deadline,
    ) -> Result<VerifiedRelease, ReleaseError> {
        let version = parse_agent_tag(&release.tag_name)?;
        release.require_available()?;

        let stem = agent_asset_stem(version, host.platform);
        let assets = self.assets(release.id, &stem, deadline)?;
        let mut manifest_bytes = Vec::with_capacity(assets.manifest.length as usize);
        self.http
            .copy_asset(&assets.manifest, deadline, &mut manifest_bytes)?;
        let record = parse_manifest(
            &manifest_bytes,
            &ExpectedManifest {
                release_id: release.id,
                tag: &release.tag_name,
                platform: host.platform,
                artifact: ExpectedArtifact {
                    id: assets.program.id,
                    name: &assets.program.name,
                    length: assets.program.length,
                    sha256: &assets.program.sha256,
                },
            },
        )?;
        check_compatibility(&record, host)?;
        let commit = self.resolve_commit(&release.tag_name, deadline)?;

        // Re-read exact identities after obtaining the manifest and source commit.
        // A catalog page is only a discovery hint.
        let current = self.release(release.id, deadline)?;
        if current.tag_name != release.tag_name {
            return Err(ReleaseError::ReleaseChanged);
        }
        current.require_available()?;
        if current != release || self.assets(release.id, &stem, deadline)? != assets {
            return Err(ReleaseError::ReleaseChanged);
        }
        deadline.remaining()?;
        Ok(VerifiedRelease {
            record,
            commit,
            tag: release.tag_name,
            manifest_asset: assets.manifest,
            manifest_bytes,
            checked_at: SystemTime::now(),
        })
    }

    fn catalog(&self, deadline: Deadline) -> Result<Vec<Release>, ReleaseError> {
        let mut result = Vec::new();
        let mut ids = HashSet::new();
        let mut tags = HashSet::new();
        for page in 1..=self.options.max_pages {
            let (entries, headers) = self
                .http
                .json::<Vec<Object<Release>>>(
                    &format!("/releases?per_page={PAGE_SIZE}&page={page}"),
                    deadline,
                )
                .map_err(|error| match error {
                    ReleaseError::NotFound => ReleaseError::IncompleteCatalog,
                    other => other,
                })?;
            let has_next = next_page(&headers, "/releases", page)?;
            if entries.len() > PAGE_SIZE || (has_next && entries.is_empty()) {
                return Err(ReleaseError::IncompleteCatalog);
            }
            for Object(entry) in entries {
                if !ids.insert(entry.id.get())
                    || (entry.is_published_stable()
                        && parse_agent_tag(&entry.tag_name).is_ok()
                        && !tags.insert(entry.tag_name.clone()))
                {
                    return Err(ReleaseError::IncompleteCatalog);
                }
                result.push(entry);
            }
            if !has_next {
                return Ok(result);
            }
        }
        Err(ReleaseError::IncompleteCatalog)
    }

    fn release(&self, id: GithubReleaseId, deadline: Deadline) -> Result<Release, ReleaseError> {
        let (Object(release), _) = self
            .http
            .json::<Object<Release>>(&format!("/releases/{}", id.get()), deadline)?;
        if release.id != id {
            return Err(ReleaseError::ReleaseChanged);
        }
        Ok(release)
    }

    fn assets(
        &self,
        id: GithubReleaseId,
        stem: &str,
        deadline: Deadline,
    ) -> Result<ReleaseAssets, ReleaseError> {
        let path = format!("/releases/{}/assets", id.get());
        let (assets, headers) = self
            .http
            .json::<Vec<Object<Asset>>>(&format!("{path}?per_page={PAGE_SIZE}"), deadline)?;
        if assets.len() > MAX_ASSETS || next_page(&headers, &path, 1)? {
            return Err(ReleaseError::InvalidResponse);
        }
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for Object(asset) in &assets {
            if !ids.insert(asset.id.get()) || !names.insert(&asset.name) {
                return Err(ReleaseError::AssetMismatch);
            }
        }
        let program_name = format!("{stem}.tar.gz");
        let manifest_name = format!("{stem}.release.json");
        let find = |name: &str, limit, too_large| {
            assets
                .iter()
                .find(|Object(asset)| asset.name == name)
                .ok_or(ReleaseError::AssetMismatch)?
                .0
                .verify(limit, too_large)
        };
        Ok(ReleaseAssets {
            program: find(
                &program_name,
                MAX_ARTIFACT_BYTES,
                ReleaseError::AssetMismatch,
            )?,
            manifest: find(
                &manifest_name,
                MAX_MANIFEST_BYTES as u64,
                ReleaseError::ManifestTooLarge,
            )?,
        })
    }

    fn resolve_commit(&self, tag: &str, deadline: Deadline) -> Result<String, ReleaseError> {
        let (Object(reference), _) = self
            .http
            .json::<Object<TagRef>>(&format!("/git/ref/tags/{tag}"), deadline)?;
        if reference.reference != format!("refs/tags/{tag}") {
            return Err(ReleaseError::InvalidResponse);
        }
        let mut target = reference.object;
        let mut seen = HashSet::new();
        loop {
            if !is_lower_hex(&target.sha, 40) {
                return Err(ReleaseError::InvalidResponse);
            }
            match target.kind.as_str() {
                "commit" => return Ok(target.sha),
                "tag" if seen.len() < MAX_TAG_OBJECTS && seen.insert(target.sha.clone()) => {
                    let (Object(annotation), _) = self.http.json::<Object<AnnotatedTag>>(
                        &format!("/git/tags/{}", target.sha),
                        deadline,
                    )?;
                    if annotation.sha != target.sha {
                        return Err(ReleaseError::InvalidResponse);
                    }
                    target = annotation.object;
                }
                _ => return Err(ReleaseError::InvalidResponse),
            }
        }
    }
}

// GitHub can change from /repos/OWNER/REPO to /repositories/ID in Link.
// Only read the next page number; every request uses our own fixed repo URL.
fn next_page(headers: &HeaderMap, endpoint: &str, page: usize) -> Result<bool, ReleaseError> {
    let invalid = ReleaseError::IncompleteCatalog;
    let mut links = HashSet::new();
    let mut last = None;
    for value in headers.get_all(LINK) {
        for link in value.to_str().map_err(|_| invalid)?.split(',') {
            let (target, relation) = link.trim().split_once(">;").ok_or(invalid)?;
            let url = Url::parse(target.strip_prefix('<').ok_or(invalid)?).map_err(|_| invalid)?;
            let relation = relation
                .trim()
                .strip_prefix("rel=\"")
                .and_then(|s| s.strip_suffix('"'))
                .ok_or(invalid)?;
            if !matches!(relation, "next" | "prev" | "first" | "last")
                || !links.insert(relation)
                || !http::is_api_url(&url)
            {
                return Err(invalid);
            }
            let numeric_path = url
                .path()
                .strip_prefix("/repositories/")
                .and_then(|tail| tail.split_once('/'));
            if url.path() != http::api_url(endpoint).path()
                && !numeric_path.is_some_and(|(id, suffix)| {
                    id.parse::<u64>().is_ok_and(|id| id > 0)
                        && endpoint.strip_prefix('/') == Some(suffix)
                })
            {
                return Err(invalid);
            }
            let mut next_number = None;
            let mut per_page = None;
            for (key, value) in url.query_pairs() {
                match key.as_ref() {
                    "page" if next_number.is_none() => {
                        next_number = Some(value.parse::<usize>().map_err(|_| invalid)?);
                    }
                    "per_page" if per_page.is_none() => {
                        per_page = Some(value.parse::<usize>().map_err(|_| invalid)?);
                    }
                    _ => return Err(invalid),
                }
            }
            let number = next_number.ok_or(invalid)?;
            if per_page != Some(PAGE_SIZE)
                || number == 0
                || (relation == "next" && number != page + 1)
                || (relation == "prev" && number != page.saturating_sub(1))
                || (relation == "first" && number != 1)
                || (relation == "last" && number < page)
            {
                return Err(invalid);
            }
            if relation == "last" {
                last = Some(number);
            }
        }
    }
    let has_next = links.contains("next");
    if last.is_some_and(|last| (last > page) != has_next) {
        return Err(invalid);
    }
    Ok(has_next)
}

pub(super) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Consume a subset of the upstream API. Unknown GitHub fields are harmless;
// projected fields must have the expected shape and occur only once.
#[derive(Deserialize)]
#[serde(transparent, bound(deserialize = "T: Deserialize<'de>"))]
struct Object<T>(#[serde(deserialize_with = "deserialize_object")] T);

fn release_id<'de, D: serde::Deserializer<'de>>(input: D) -> Result<GithubReleaseId, D::Error> {
    GithubReleaseId::new(u64::deserialize(input)?)
        .map_err(|_| serde::de::Error::custom("release id"))
}

fn asset_id<'de, D: serde::Deserializer<'de>>(input: D) -> Result<AssetId, D::Error> {
    AssetId::new(u64::deserialize(input)?).map_err(|_| serde::de::Error::custom("asset id"))
}

#[derive(Deserialize, PartialEq, Eq)]
struct Release {
    #[serde(deserialize_with = "release_id")]
    id: GithubReleaseId,
    tag_name: String,
    draft: bool,
    prerelease: bool,
    immutable: Option<bool>,
    #[serde(deserialize_with = "Option::deserialize")]
    published_at: Option<String>,
}

impl Release {
    fn is_published_stable(&self) -> bool {
        !self.draft && !self.prerelease && self.published_at.is_some()
    }

    fn require_available(&self) -> Result<(), ReleaseError> {
        let published = self.published_at.as_deref().filter(|_| !self.draft);
        let Some(published) = published else {
            return Err(ReleaseError::Unavailable);
        };
        if time::OffsetDateTime::parse(published, &time::format_description::well_known::Rfc3339)
            .is_err()
        {
            return Err(ReleaseError::InvalidResponse);
        }
        if self.prerelease {
            return Err(ReleaseError::Prerelease);
        }
        if self.immutable != Some(true) {
            return Err(ReleaseError::Unavailable);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct Asset {
    #[serde(deserialize_with = "asset_id")]
    id: AssetId,
    name: String,
    size: u64,
    state: String,
    #[serde(deserialize_with = "Option::deserialize")]
    digest: Option<String>,
}

impl Asset {
    fn verify(
        &self,
        limit: u64,
        too_large: ReleaseError,
    ) -> Result<ManifestArtifact, ReleaseError> {
        if self.size > limit {
            return Err(too_large);
        }
        let sha256 = self
            .digest
            .as_deref()
            .and_then(|s| s.strip_prefix("sha256:"));
        match sha256 {
            Some(digest)
                if self.state == "uploaded" && self.size > 0 && is_lower_hex(digest, 64) =>
            {
                Ok(ManifestArtifact {
                    id: self.id,
                    name: self.name.clone(),
                    length: self.size,
                    sha256: digest.into(),
                })
            }
            _ => Err(ReleaseError::AssetMismatch),
        }
    }
}

#[derive(PartialEq, Eq)]
struct ReleaseAssets {
    program: ManifestArtifact,
    manifest: ManifestArtifact,
}

#[derive(Deserialize)]
struct TagRef {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(deserialize_with = "deserialize_object")]
    object: GitObject,
}

#[derive(Deserialize)]
struct AnnotatedTag {
    sha: String,
    #[serde(deserialize_with = "deserialize_object")]
    object: GitObject,
}

#[derive(Deserialize)]
struct GitObject {
    #[serde(rename = "type")]
    kind: String,
    sha: String,
}
