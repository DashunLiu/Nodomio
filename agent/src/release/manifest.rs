//! Agent release records and compatibility checks for the GitHub release catalog.
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, digest};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::{fmt, marker::PhantomData};

pub(super) const OFFICIAL_OWNER: &str = "DashunLiu";
pub(super) const OFFICIAL_REPO: &str = "Nodomio";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_VERSION_PART: u64 = 99_999;
pub(super) const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub(crate) const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const WIRE_PROTOCOL: u64 = 1;
const URL_NAMESPACE: [u8; 16] = [
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReleaseVersion([u32; 3]);

impl fmt::Display for ReleaseVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [major, minor, patch] = self.0;
        write!(f, "{major}.{minor}.{patch}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GithubReleaseId(u64);

impl GithubReleaseId {
    pub fn new(value: u64) -> Result<Self, ReleaseError> {
        if is_safe_positive_integer(value) {
            Ok(Self(value))
        } else {
            Err(ReleaseError::InvalidGithubId)
        }
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetId(u64);

impl AssetId {
    pub fn new(value: u64) -> Result<Self, ReleaseError> {
        if is_safe_positive_integer(value) {
            Ok(Self(value))
        } else {
            Err(ReleaseError::InvalidGithubId)
        }
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReleaseId(String);

impl ReleaseId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Platform {
    #[serde(rename = "linux-x86_64")]
    LinuxX86_64,
    #[serde(rename = "linux-aarch64")]
    LinuxAarch64,
}

impl Platform {
    pub(super) fn release_name(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-x86_64",
            Self::LinuxAarch64 => "linux-aarch64",
        }
    }
}

pub(super) fn agent_asset_stem(version: ReleaseVersion, platform: Platform) -> String {
    format!("nodomi-agent-{version}-{}", platform.release_name())
}

pub struct ExpectedManifest<'a> {
    pub release_id: GithubReleaseId,
    pub tag: &'a str,
    pub platform: Platform,
    pub artifact: ExpectedArtifact<'a>,
}

pub struct ExpectedArtifact<'a> {
    pub id: AssetId,
    pub name: &'a str,
    pub length: u64,
    /// Lowercase hex digest from the GitHub asset metadata.
    pub sha256: &'a str,
}

/// Parsed manifest facts tied to the expected asset.
#[derive(Debug, PartialEq, Eq)]
pub struct ManifestRecord {
    target: ManifestTarget,
    compatibility: Compatibility,
}

impl ManifestRecord {
    pub fn target(&self) -> &ManifestTarget {
        &self.target
    }

    pub(super) fn compatibility_sha256(&self) -> String {
        // Binding v1 hashes the validated compatibility fields in their
        // declared order. Versions are numeric triplets in this encoding.
        let bytes = serde_json::to_vec(&self.compatibility)
            .expect("validated compatibility fields serialize to JSON");
        digest(&SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub(super) fn platform_compatibility(
        &self,
        platform: Option<Platform>,
        kernel: Option<[u64; 3]>,
        libc: Option<HostLibc>,
    ) -> PlatformCompatibility {
        use PlatformCompatibility::*;
        let required = &self.compatibility;
        if platform.is_some_and(|value| value != self.target.platform)
            || kernel.is_some_and(|value| value < required.min_kernel)
        {
            return Incompatible;
        }
        let libc_ok = match (required.libc, required.min_libc_version, libc) {
            (Libc::Static, None, _) => Some(true),
            (Libc::Glibc, Some(min), Some(HostLibc::Glibc(version)))
            | (Libc::Musl, Some(min), Some(HostLibc::Musl(version))) => Some(version >= min),
            (_, _, None) => None,
            _ => Some(false),
        };
        match libc_ok {
            Some(false) => Incompatible,
            Some(true) if platform.is_some() && kernel.is_some() => Compatible,
            _ => Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ManifestTarget {
    pub release_id: ReleaseId,
    pub version: ReleaseVersion,
    pub sequence: u64,
    pub platform: Platform,
    pub is_security_update: bool,
    pub github_release_id: GithubReleaseId,
    pub artifact: ManifestArtifact,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ManifestArtifact {
    pub id: AssetId,
    pub name: String,
    pub length: u64,
    pub sha256: String,
}

pub struct HostRequirements {
    pub platform: Platform,
    pub kernel: [u64; 3],
    pub libc: Option<HostLibc>,
    pub wire_protocol: u64,
    pub supervisor_protocol: u64,
    /// Initial format for a fresh install, or the current readable format of an existing install.
    pub config_format: u64,
    /// Initial format for a fresh install, or the current readable format of an existing install.
    pub queue_format: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum HostLibc {
    Glibc([u64; 3]),
    Musl([u64; 3]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PlatformCompatibility {
    Compatible,
    Incompatible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseError {
    InvalidOptions,
    InvalidBinding,
    InvalidResponse,
    IncompleteCatalog,
    NotFound,
    Unavailable,
    Prerelease,
    RateLimited,
    Timeout,
    Transport,
    InvalidRedirect,
    AssetMismatch,
    ReleaseChanged,
    WriteFailed,
    InvalidTag,
    InvalidGithubId,
    ManifestTooLarge,
    InvalidManifest,
    ManifestMismatch,
    Withdrawn,
    Incompatible,
}

pub fn parse_agent_tag(tag: &str) -> Result<ReleaseVersion, ReleaseError> {
    let parts = tag
        .strip_prefix("agent-v")
        .and_then(parse_version_triplet)
        .ok_or(ReleaseError::InvalidTag)?;
    if parts.iter().any(|part| *part > MAX_VERSION_PART) {
        return Err(ReleaseError::InvalidTag);
    }
    Ok(ReleaseVersion(parts.map(|part| part as u32)))
}

pub fn release_sequence(version: ReleaseVersion) -> u64 {
    let [major, minor, patch] = version.0.map(u64::from);
    1 + major * 10_000_000_000 + minor * 100_000 + patch
}

pub fn business_release_id(id: GithubReleaseId) -> ReleaseId {
    let url = format!(
        "https://github.com/{OFFICIAL_OWNER}/{OFFICIAL_REPO}/releases/{}",
        id.0
    );
    // RFC 9562 UUIDv5 assigns an identifier to this URL.
    let mut digest = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(&URL_NAMESPACE);
    digest.update(url.as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.finish().as_ref()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let hex = b"0123456789abcdef";
    let mut uuid = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            uuid.push('-');
        }
        uuid.push(char::from(hex[usize::from(byte >> 4)]));
        uuid.push(char::from(hex[usize::from(byte & 0x0f)]));
    }
    ReleaseId(uuid)
}

pub fn parse_manifest(
    bytes: &[u8],
    expected: &ExpectedManifest<'_>,
) -> Result<ManifestRecord, ReleaseError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ReleaseError::ManifestTooLarge);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let manifest: WireManifest =
        deserialize_object(&mut decoder).map_err(|_| ReleaseError::InvalidManifest)?;
    decoder.end().map_err(|_| ReleaseError::InvalidManifest)?;
    let metadata = manifest.custom.nodomi;
    let asset = metadata.github;
    let sha256 = manifest.hashes.sha256;
    if metadata.schema_version != 1
        || metadata.component != "AGENT"
        || metadata.channel != "STABLE"
        || !(1..=MAX_ARTIFACT_BYTES).contains(&manifest.length)
        || sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !valid_asset_name(&asset.asset_name)
    {
        return Err(ReleaseError::InvalidManifest);
    }
    metadata.compatibility.validate()?;

    let version = parse_agent_tag(expected.tag)?;
    let release_id = business_release_id(expected.release_id);
    let sequence = release_sequence(version);
    if asset.owner != OFFICIAL_OWNER
        || asset.repo != OFFICIAL_REPO
        || asset.release_id != expected.release_id.0
        || asset.asset_id != expected.artifact.id.0
        || asset.asset_name != expected.artifact.name
        || manifest.length != expected.artifact.length
        || sha256 != expected.artifact.sha256
        || metadata.platform != expected.platform
        || metadata.release_id != release_id.as_str()
        || metadata.version != version.to_string()
        || metadata.sequence != sequence
    {
        return Err(ReleaseError::ManifestMismatch);
    }
    if metadata.status == Status::Withdrawn {
        return Err(ReleaseError::Withdrawn);
    }
    Ok(ManifestRecord {
        target: ManifestTarget {
            release_id,
            version,
            sequence,
            platform: metadata.platform,
            is_security_update: metadata.is_security_update,
            github_release_id: expected.release_id,
            artifact: ManifestArtifact {
                id: expected.artifact.id,
                name: asset.asset_name,
                length: manifest.length,
                sha256,
            },
        },
        compatibility: metadata.compatibility,
    })
}

pub fn check_compatibility(
    record: &ManifestRecord,
    host: &HostRequirements,
) -> Result<(), ReleaseError> {
    let required = &record.compatibility;
    if record.platform_compatibility(Some(host.platform), Some(host.kernel), host.libc)
        != PlatformCompatibility::Compatible
        || host.wire_protocol != WIRE_PROTOCOL
        || !required.wire_protocols.contains(&host.wire_protocol)
        || !required
            .supervisor_protocols
            .contains(&host.supervisor_protocol)
        || required.write_config_format != host.config_format
        || required.write_queue_format != host.queue_format
    {
        return Err(ReleaseError::Incompatible);
    }
    Ok(())
}

pub(super) fn is_safe_positive_integer(value: u64) -> bool {
    (1..=MAX_SAFE_INTEGER).contains(&value)
}

fn valid_asset_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 200
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn parse_version_triplet(value: &str) -> Option<[u64; 3]> {
    let mut pieces = value.split('.');
    let mut version = [0; 3];
    for part in &mut version {
        let text = pieces.next()?;
        if text.is_empty()
            || (text.len() > 1 && text.starts_with('0'))
            || !text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        *part = text.parse().ok()?;
    }
    pieces.next().is_none().then_some(version)
}

// Serde's derived structs accept positional sequences as well as maps.
// Require a map at each object boundary, then retain the derived field checks.
pub(super) fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(PhantomData))
}

fn deserialize_version<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u64; 3], D::Error> {
    parse_version_triplet(&String::deserialize(deserializer)?)
        .ok_or_else(|| de::Error::custom("invalid version triplet"))
}

fn deserialize_nullable_version<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<[u64; 3]>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|text| {
            parse_version_triplet(&text).ok_or_else(|| de::Error::custom("invalid version triplet"))
        })
        .transpose()
}

pub(super) fn deserialize_enum_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value = String::deserialize(deserializer)?;
    T::deserialize(de::value::StringDeserializer::<D::Error>::new(value))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireManifest {
    length: u64,
    #[serde(deserialize_with = "deserialize_object")]
    hashes: Hashes,
    #[serde(deserialize_with = "deserialize_object")]
    custom: Custom,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hashes {
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Custom {
    #[serde(deserialize_with = "deserialize_object")]
    nodomi: ReleaseMetadata,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReleaseMetadata {
    schema_version: u64,
    component: String,
    release_id: String,
    sequence: u64,
    version: String,
    channel: String,
    #[serde(deserialize_with = "deserialize_enum_string")]
    platform: Platform,
    is_security_update: bool,
    #[serde(deserialize_with = "deserialize_object")]
    compatibility: Compatibility,
    #[serde(deserialize_with = "deserialize_object")]
    github: GithubAsset,
    #[serde(deserialize_with = "deserialize_enum_string")]
    status: Status,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Status {
    Active,
    Withdrawn,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubAsset {
    owner: String,
    repo: String,
    release_id: u64,
    asset_id: u64,
    asset_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Libc {
    Static,
    Glibc,
    Musl,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Compatibility {
    wire_protocols: Vec<u64>,
    supervisor_protocols: Vec<u64>,
    read_config_formats: Vec<u64>,
    write_config_format: u64,
    read_queue_formats: Vec<u64>,
    write_queue_format: u64,
    #[serde(deserialize_with = "deserialize_version")]
    min_kernel: [u64; 3],
    #[serde(deserialize_with = "deserialize_enum_string")]
    libc: Libc,
    #[serde(deserialize_with = "deserialize_nullable_version")]
    min_libc_version: Option<[u64; 3]>,
}

impl Compatibility {
    fn validate(&self) -> Result<(), ReleaseError> {
        for values in [
            &self.wire_protocols,
            &self.supervisor_protocols,
            &self.read_config_formats,
            &self.read_queue_formats,
        ] {
            if !(1..=16).contains(&values.len())
                || values.iter().enumerate().any(|(index, value)| {
                    !is_safe_positive_integer(*value) || values[..index].contains(value)
                })
            {
                return Err(ReleaseError::InvalidManifest);
            }
        }
        // An unchanged write format is readable because the candidate declares it here.
        if !self.read_config_formats.contains(&self.write_config_format)
            || !self.read_queue_formats.contains(&self.write_queue_format)
            || (self.libc == Libc::Static) != self.min_libc_version.is_none()
        {
            return Err(ReleaseError::InvalidManifest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const UUID: &str = "9ff55f9f-d008-5d06-a43e-f9c98a2de598";
    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ASSET: &str = "nodomi-agent-0.1.1-linux-x86_64.tar.gz";

    fn fixture() -> Value {
        json!({
            "length": 12345, "hashes": { "sha256": HASH },
            "custom": { "nodomi": {
                "schemaVersion": 1, "component": "AGENT", "releaseId": UUID,
                "sequence": 100002, "version": "0.1.1", "channel": "STABLE",
                "platform": "linux-x86_64", "isSecurityUpdate": true, "status": "ACTIVE",
                "compatibility": {
                    "wireProtocols": [1], "supervisorProtocols": [1],
                    "readConfigFormats": [1, 2], "writeConfigFormat": 1,
                    "readQueueFormats": [1, 2], "writeQueueFormat": 1,
                    "minKernel": "5.10.0", "libc": "STATIC", "minLibcVersion": null
                },
                "github": {
                    "owner": "DashunLiu", "repo": "Nodomio", "releaseId": 123,
                    "assetId": 456, "assetName": ASSET
                }
            } }
        })
    }

    fn expected() -> ExpectedManifest<'static> {
        ExpectedManifest {
            release_id: GithubReleaseId::new(123).unwrap(),
            tag: "agent-v0.1.1",
            platform: Platform::LinuxX86_64,
            artifact: ExpectedArtifact {
                id: AssetId::new(456).unwrap(),
                name: ASSET,
                length: 12345,
                sha256: HASH,
            },
        }
    }

    fn host() -> HostRequirements {
        HostRequirements {
            platform: Platform::LinuxX86_64,
            kernel: [6, 1, 0],
            libc: None,
            wire_protocol: 1,
            supervisor_protocol: 1,
            config_format: 1,
            queue_format: 1,
        }
    }

    fn parse(value: &Value) -> Result<ManifestRecord, ReleaseError> {
        parse_manifest(&serde_json::to_vec(value).unwrap(), &expected())
    }

    #[test]
    fn tag_sequence_and_uuid_are_deterministic() {
        for (tag, sequence) in [
            ("agent-v0.0.0", 1),
            ("agent-v0.0.99999", 100000),
            ("agent-v0.1.0", 100001),
            ("agent-v0.1.1", 100002),
            ("agent-v1.0.0", 10000000001),
            ("agent-v99999.99999.99999", 1000000000000000),
        ] {
            assert_eq!(
                release_sequence(parse_agent_tag(tag).unwrap()),
                sequence,
                "{tag}"
            );
        }
        assert_eq!(
            business_release_id(GithubReleaseId::new(123).unwrap()).as_str(),
            UUID
        );
    }

    #[test]
    fn noncanonical_and_non_agent_tags_are_rejected() {
        for tag in [
            "",
            "v0.1.1",
            "backend-v0.1.1",
            "agent-v0.01.1",
            "agent-v+0.1.1",
            "agent-v0.1",
            "agent-v0.1.1.0",
            "agent-v0.1.1-rc.1",
            "agent-v0.1.1+build",
            "agent-v100000.1.1",
            "agent-v0.100000.1",
            "agent-v0.1.100000",
            "agent-v0.1.1\n",
        ] {
            assert_eq!(
                parse_agent_tag(tag),
                Err(ReleaseError::InvalidTag),
                "{tag:?}"
            );
        }
    }

    #[test]
    fn github_ids_have_safe_integer_bounds() {
        assert!(GithubReleaseId::new(9_007_199_254_740_991).is_ok());
        assert!(AssetId::new(9_007_199_254_740_991).is_ok());
        for bad in [0, 9_007_199_254_740_992, u64::MAX] {
            assert_eq!(
                GithubReleaseId::new(bad),
                Err(ReleaseError::InvalidGithubId)
            );
            assert_eq!(AssetId::new(bad), Err(ReleaseError::InvalidGithubId));
        }
    }

    #[test]
    fn manifest_must_match_current_release_platform_and_asset() {
        let x86 = parse(&fixture()).unwrap();
        let x86 = x86.target();
        assert_eq!(x86.sequence, 100002);
        assert_eq!(x86.artifact.length, 12345);
        assert!(x86.is_security_update);
        let mut aarch64 = fixture();
        aarch64["custom"]["nodomi"]["platform"] = json!("linux-aarch64");
        aarch64["custom"]["nodomi"]["github"]["assetId"] = json!(457);
        aarch64["custom"]["nodomi"]["github"]["assetName"] =
            json!("nodomi-agent-0.1.1-linux-aarch64.tar.gz");
        let mut expected_arm = expected();
        expected_arm.platform = Platform::LinuxAarch64;
        expected_arm.artifact.id = AssetId::new(457).unwrap();
        expected_arm.artifact.name = "nodomi-agent-0.1.1-linux-aarch64.tar.gz";
        let arm = parse_manifest(&serde_json::to_vec(&aarch64).unwrap(), &expected_arm).unwrap();
        let arm = arm.target();
        assert_eq!(x86.release_id, arm.release_id);
        assert_eq!(x86.version, arm.version);
        assert_eq!(x86.sequence, arm.sequence);
        assert_eq!(x86.is_security_update, arm.is_security_update);
        assert_ne!(x86.artifact.id, arm.artifact.id);

        for (path, value) in [
            ("/length", json!(12346)),
            (
                "/hashes/sha256",
                json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ),
            (
                "/custom/nodomi/releaseId",
                json!("00000000-0000-5000-8000-000000000000"),
            ),
            ("/custom/nodomi/sequence", json!(100003)),
            ("/custom/nodomi/version", json!("0.1.2")),
            ("/custom/nodomi/platform", json!("linux-aarch64")),
            ("/custom/nodomi/github/owner", json!("other-owner")),
            ("/custom/nodomi/github/repo", json!("other-repo")),
            ("/custom/nodomi/github/releaseId", json!(124)),
            ("/custom/nodomi/github/assetId", json!(457)),
            ("/custom/nodomi/github/assetName", json!("other.tar.gz")),
        ] {
            let mut mismatched = fixture();
            *mismatched.pointer_mut(path).unwrap() = value;
            assert_eq!(
                parse(&mismatched),
                Err(ReleaseError::ManifestMismatch),
                "{path}"
            );
        }
        let mut withdrawn = fixture();
        withdrawn["custom"]["nodomi"]["status"] = json!("WITHDRAWN");
        assert_eq!(parse(&withdrawn), Err(ReleaseError::Withdrawn));
    }

    #[test]
    fn unknown_fields_duplicate_keys_and_oversize_fail() {
        for path in [
            "",
            "/hashes",
            "/custom",
            "/custom/nodomi",
            "/custom/nodomi/github",
            "/custom/nodomi/compatibility",
        ] {
            let mut value = fixture();
            value.pointer_mut(path).unwrap()["unexpected"] = json!(true);
            assert_eq!(parse(&value), Err(ReleaseError::InvalidManifest), "{path}");
        }
        let encoded = serde_json::to_string(&fixture()).unwrap();
        let duplicate =
            encoded.replace(r#""length":12345"#, r#""length":12345,"leng\u0074h":12345"#);
        let nested_duplicate = encoded.replace(
            r#""wireProtocols":[1]"#,
            r#""wireProtocols":[1],"wireProtocols":[1]"#,
        );
        for bytes in [
            duplicate,
            nested_duplicate,
            format!("{encoded} {{}}"),
            format!("[12345,{{\"sha256\":\"{HASH}\"}},{}]", fixture()["custom"]),
        ] {
            assert_eq!(
                parse_manifest(bytes.as_bytes(), &expected()),
                Err(ReleaseError::InvalidManifest)
            );
        }
        let mut array_hashes = fixture();
        array_hashes["hashes"] = json!([HASH]);
        assert_eq!(parse(&array_hashes), Err(ReleaseError::InvalidManifest));
        let mut bounded = encoded.into_bytes();
        bounded.resize(64 * 1024, b' ');
        assert!(parse_manifest(&bounded, &expected()).is_ok());
        bounded.push(b' ');
        assert_eq!(
            parse_manifest(&bounded, &expected()),
            Err(ReleaseError::ManifestTooLarge)
        );
    }

    #[test]
    fn compatibility_declaration_is_strict() {
        let mut missing = fixture();
        missing["custom"]["nodomi"]["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("minLibcVersion");
        assert_eq!(parse(&missing), Err(ReleaseError::InvalidManifest));
        for (key, invalid) in [
            ("wireProtocols", json!([])),
            ("wireProtocols", json!([1, 1])),
            ("supervisorProtocols", json!([0])),
            ("wireProtocols", json!([9_007_199_254_740_992u64])),
            ("readQueueFormats", json!((1..=17).collect::<Vec<_>>())),
            ("writeConfigFormat", json!(3)),
            ("writeQueueFormat", json!(3)),
            ("minKernel", json!("5.010.0")),
            ("minLibcVersion", json!("2.17.0")),
            ("libc", json!("MUSL")),
        ] {
            let mut value = fixture();
            value["custom"]["nodomi"]["compatibility"][key] = invalid;
            assert_eq!(parse(&value), Err(ReleaseError::InvalidManifest), "{key}");
        }
    }

    #[test]
    fn enum_fields_require_json_strings() {
        assert!(parse(&fixture()).is_ok());
        for (path, object) in [
            ("/custom/nodomi/platform", json!({"linux-x86_64": null})),
            ("/custom/nodomi/status", json!({"ACTIVE": null})),
            ("/custom/nodomi/compatibility/libc", json!({"STATIC": null})),
        ] {
            let mut value = fixture();
            *value.pointer_mut(path).unwrap() = object;
            assert_eq!(parse(&value), Err(ReleaseError::InvalidManifest), "{path}");
        }
    }

    #[test]
    fn write_formats_and_host_requirements_must_match() {
        let candidate = parse(&fixture()).unwrap();
        assert_eq!(check_compatibility(&candidate, &host()), Ok(()));
        for requirements in [
            HostRequirements {
                kernel: [5, 9, 99],
                ..host()
            },
            HostRequirements {
                platform: Platform::LinuxAarch64,
                ..host()
            },
            HostRequirements {
                wire_protocol: 2,
                ..host()
            },
            HostRequirements {
                supervisor_protocol: 2,
                ..host()
            },
            HostRequirements {
                config_format: 2,
                ..host()
            },
            HostRequirements {
                queue_format: 2,
                ..host()
            },
        ] {
            assert_eq!(
                check_compatibility(&candidate, &requirements),
                Err(ReleaseError::Incompatible)
            );
        }
        assert_eq!(
            check_compatibility(
                &candidate,
                &HostRequirements {
                    kernel: [5, 10, 0],
                    ..host()
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn wire_protocol_and_local_formats_are_checked_independently() {
        let mut value = fixture();
        let compatibility = &mut value["custom"]["nodomi"]["compatibility"];
        compatibility["wireProtocols"] = json!([1, 2]);
        compatibility["supervisorProtocols"] = json!([7]);
        compatibility["readConfigFormats"] = json!([2]);
        compatibility["writeConfigFormat"] = json!(2);
        compatibility["readQueueFormats"] = json!([3]);
        compatibility["writeQueueFormat"] = json!(3);
        let candidate = parse(&value).unwrap();
        let requirements = HostRequirements {
            config_format: 2,
            queue_format: 3,
            supervisor_protocol: 7,
            ..host()
        };
        assert_eq!(check_compatibility(&candidate, &requirements), Ok(()));
        assert_eq!(
            check_compatibility(
                &candidate,
                &HostRequirements {
                    wire_protocol: 2,
                    ..requirements
                },
            ),
            Err(ReleaseError::Incompatible),
        );
    }

    #[test]
    fn dynamic_packages_require_the_matching_libc_and_minimum_version() {
        let mut value = fixture();
        value["custom"]["nodomi"]["compatibility"]["libc"] = json!("GLIBC");
        value["custom"]["nodomi"]["compatibility"]["minLibcVersion"] = json!("2.17.0");
        let candidate = parse(&value).unwrap();
        for libc in [
            None,
            Some(HostLibc::Musl([2, 17, 0])),
            Some(HostLibc::Glibc([2, 9, 9])),
        ] {
            assert_eq!(
                check_compatibility(&candidate, &HostRequirements { libc, ..host() }),
                Err(ReleaseError::Incompatible)
            );
        }
        assert_eq!(
            check_compatibility(
                &candidate,
                &HostRequirements {
                    libc: Some(HostLibc::Glibc([2, 17, 0])),
                    ..host()
                }
            ),
            Ok(())
        );
    }
}
