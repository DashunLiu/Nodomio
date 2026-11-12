//! Strict bounded wire models for the current Agent API, not metric transport.
use crate::identity::{Binding, Result, public_id, uuid};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
pub const MAX_BODY: usize = 16 * 1024;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
fn text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max
}
fn date(s: &str) -> bool {
    s.len() <= 64 && OffsetDateTime::parse(s, &Rfc3339).is_ok()
}
trait Validate {
    fn validate(&self) -> Result<()>;
}
fn decode<T: DeserializeOwned + Validate>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_BODY {
        return Err("RESPONSE_TOO_LARGE");
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| "INVALID_PROTOCOL")?;
    value.validate()?;
    Ok(value)
}
macro_rules! decoding {
    ($name:ident) => {
        impl $name {
            pub fn decode(bytes: &[u8]) -> Result<Self> {
                decode(bytes)
            }
        }
    };
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentIdentity {
    pub agent_id: String,
    pub server_id: String,
    pub sampling_interval_seconds: u32,
    pub heartbeat_interval_seconds: u32,
    pub registered_at: String,
    pub binding_revision: u64,
}
impl Validate for AgentIdentity {
    fn validate(&self) -> Result<()> {
        if !public_id(&self.agent_id)
            || !public_id(&self.server_id)
            || !(5..=3600).contains(&self.sampling_interval_seconds)
            || self.heartbeat_interval_seconds != 30
            || !date(&self.registered_at)
        {
            return Err("INVALID_PROTOCOL");
        }
        Ok(())
    }
}
impl AgentIdentity {
    pub fn binding(&self) -> Binding {
        Binding {
            agent_id: self.agent_id.clone(),
            server_id: self.server_id.clone(),
            binding_revision: self.binding_revision,
        }
    }
}
decoding!(AgentIdentity);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HeartbeatAck {
    pub received_at: String,
    pub sampling_interval_seconds: u32,
    pub heartbeat_interval_seconds: u32,
}
impl Validate for HeartbeatAck {
    fn validate(&self) -> Result<()> {
        if !date(&self.received_at)
            || !(5..=3600).contains(&self.sampling_interval_seconds)
            || self.heartbeat_interval_seconds != 30
        {
            return Err("INVALID_PROTOCOL");
        }
        Ok(())
    }
}
decoding!(HeartbeatAck);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CollectionConfiguration {
    pub sampling_interval_seconds: u32,
    pub buffer_max_age_seconds: u32,
    pub buffer_max_bytes: u64,
}
impl Validate for CollectionConfiguration {
    fn validate(&self) -> Result<()> {
        if !(5..=3600).contains(&self.sampling_interval_seconds)
            || !(3600..=604800).contains(&self.buffer_max_age_seconds)
            || !(1_000_000..=1_000_000_000).contains(&self.buffer_max_bytes)
        {
            return Err("INVALID_PROTOCOL");
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfigurationTarget {
    pub config_id: String,
    pub generation: u64,
    pub configuration: CollectionConfiguration,
}
impl Validate for ConfigurationTarget {
    fn validate(&self) -> Result<()> {
        if !uuid(&self.config_id) || !(1..=MAX_SAFE).contains(&self.generation) {
            return Err("INVALID_PROTOCOL");
        }
        self.configuration.validate()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentConfiguration {
    pub agent_id: String,
    pub binding_revision: u64,
    pub schema_version: u32,
    pub target: ConfigurationTarget,
}
impl Validate for AgentConfiguration {
    fn validate(&self) -> Result<()> {
        if !public_id(&self.agent_id)
            || !(1..=MAX_SAFE).contains(&self.binding_revision)
            || self.schema_version != 1
        {
            return Err("INVALID_PROTOCOL");
        }
        self.target.validate()
    }
}
decoding!(AgentConfiguration);
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Capability {
    Available,
    Unsupported,
    PermissionDenied,
    Error,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Capabilities {
    pub system: Capability,
    pub processes: Capability,
    pub containers: Capability,
    pub ssh_events: Capability,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Architecture {
    #[serde(rename = "X86_64")]
    X86_64,
    #[serde(rename = "ARM64")]
    Arm64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RegistrationMetadata {
    pub version: String,
    pub architecture: Architecture,
    pub distribution: String,
    pub distribution_version: String,
    pub hostname: String,
    pub capabilities: Capabilities,
}
impl RegistrationMetadata {
    pub(crate) fn validate(&self) -> Result<()> {
        if !text(&self.version, 64)
            || !text(&self.distribution, 64)
            || !text(&self.distribution_version, 64)
            || !text(&self.hostname, 253)
        {
            return Err("INVALID_REGISTRATION_METADATA");
        }
        Ok(())
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Registration<'a> {
    pub agent_credential: &'a str,
    #[serde(flatten)]
    pub metadata: &'a RegistrationMetadata,
    pub expected_server_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_deployment_id: Option<&'a str>,
}

pub(crate) fn canonical_deployment_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    uuid(value)
        && !bytes.iter().any(u8::is_ascii_uppercase)
        && bytes[14] == b'4'
        && b"89ab".contains(&bytes[19])
}
/// Explicit caller-supplied local updater facts. This client does not install or update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdaterRuntime {
    pub platform: String,
    pub kernel_version: String,
    pub current_release_id: Option<String>,
    pub binary_sha256: String,
    pub protocol_version: u64,
    pub self_update: String,
    pub local_phase: String,
    pub mode: String,
    pub source: String,
    pub local_attempt_id: Option<String>,
    pub trigger: Option<String>,
    pub target_version: Option<String>,
    pub last_check_at: Option<String>,
    pub available_version: Option<String>,
    pub error_code: Option<String>,
    pub available_is_security_update: Option<bool>,
    pub result_recorded_at: Option<String>,
    pub update_events_dropped_total: u64,
    pub build_origin: String,
}
impl Validate for UpdaterRuntime {
    fn validate(&self) -> Result<()> {
        let terminal =
            ["COMMITTED", "ROLLED_BACK", "FAILED", "UNKNOWN"].contains(&self.local_phase.as_str());
        if !["linux-x86_64", "linux-aarch64", "UNSUPPORTED"].contains(&self.platform.as_str())
            || !text(&self.kernel_version, 64)
            || self.binary_sha256.len() != 64
            || !self
                .binary_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.protocol_version == 0
            || ![
                "AVAILABLE",
                "UNSUPPORTED_INSTALLATION",
                "PERMISSION_DENIED",
                "ERROR",
            ]
            .contains(&self.self_update.as_str())
            || ![
                "IDLE",
                "DOWNLOADING",
                "VERIFYING",
                "SWITCHING",
                "HEALTH_CHECK",
                "ROLLING_BACK",
                "COMMITTED",
                "ROLLED_BACK",
                "FAILED",
                "UNKNOWN",
            ]
            .contains(&self.local_phase.as_str())
            || !["AUTO", "MANUAL"].contains(&self.mode.as_str())
            || self.source != "GITHUB_RELEASES"
            || self.update_events_dropped_total > MAX_SAFE
            || !["OFFICIAL", "SELF_COMPILED", "UNKNOWN"].contains(&self.build_origin.as_str())
        {
            return Err("INVALID_UPDATER_FACTS");
        }
        if self.build_origin == "OFFICIAL" {
            if !self.current_release_id.as_deref().is_some_and(uuid) {
                return Err("INVALID_UPDATER_FACTS");
            }
        } else if self.current_release_id.is_some()
            || self.mode != "MANUAL"
            || self.self_update != "UNSUPPORTED_INSTALLATION"
        {
            return Err("INVALID_UPDATER_FACTS");
        }
        if self.local_phase == "IDLE" {
            if self.local_attempt_id.is_some()
                || self.trigger.is_some()
                || self.target_version.is_some()
            {
                return Err("INVALID_UPDATER_FACTS");
            }
        } else if !self.local_attempt_id.as_deref().is_some_and(uuid)
            || !self
                .trigger
                .as_deref()
                .is_some_and(|v| ["AUTO", "MANUAL"].contains(&v))
            || !self.target_version.as_deref().is_some_and(|v| text(v, 64))
        {
            return Err("INVALID_UPDATER_FACTS");
        }
        if self.available_version.is_some() != self.available_is_security_update.is_some()
            || self
                .available_version
                .as_deref()
                .is_some_and(|v| !text(v, 64))
            || self.last_check_at.as_deref().is_some_and(|v| !date(v))
            || terminal != self.result_recorded_at.is_some()
            || self.result_recorded_at.as_deref().is_some_and(|v| !date(v))
            || self.error_code.as_deref().is_some_and(|v| {
                ![
                    "CHECK_FAILED",
                    "SIGNATURE_INVALID",
                    "INCOMPATIBLE",
                    "INSUFFICIENT_SPACE",
                    "HEALTH_CHECK_FAILED",
                    "ROLLBACK_FAILED",
                    "UPDATE_FAILED",
                ]
                .contains(&v)
            })
        {
            return Err("INVALID_UPDATER_FACTS");
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SshSource {
    Journald,
    AuthLogFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SshContinuity {
    Contiguous,
    Gapped,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SshParseCoverage {
    Verified,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SshCounterCoverage {
    Complete,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SshSourceCounters {
    pub coverage: SshCounterCoverage,
    #[serde(deserialize_with = "Option::deserialize")]
    pub unknown_format_records_total: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub oversized_records_total: Option<String>,
}

impl SshSourceCounters {
    fn valid(&self) -> bool {
        let counts = [
            self.unknown_format_records_total.as_deref(),
            self.oversized_records_total.as_deref(),
        ];
        counts.into_iter().all(|count| match count {
            None => self.coverage == SshCounterCoverage::Partial,
            Some(count) => {
                (1..=20).contains(&count.len())
                    && (count.len() == 1 || !count.starts_with('0'))
                    && count.bytes().all(|byte| byte.is_ascii_digit())
                    && count.parse::<u64>().is_ok()
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SshGapReason {
    SourceRetention,
    FileTruncation,
    SourceReset,
    SourceSwitch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SshSourceGap {
    pub reason: SshGapReason,
    pub detected_at: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub recovered_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SshSourceDiagnostics {
    #[serde(deserialize_with = "Option::deserialize")]
    pub source: Option<SshSource>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub initialized_at: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_read_at: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub is_caught_up: Option<bool>,
    pub continuity: SshContinuity,
    #[serde(deserialize_with = "Option::deserialize")]
    pub continuous_since: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_gap: Option<SshSourceGap>,
    pub parse_coverage: SshParseCoverage,
    pub counters: SshSourceCounters,
}

impl SshSourceDiagnostics {
    fn validate(&self, capability: Capability) -> Result<()> {
        let has_read = self.last_read_at.is_some();
        let has_segment = self.continuous_since.is_some();
        let contiguous = self.continuity == SshContinuity::Contiguous;
        if (self.source.is_none()
            && (self.initialized_at.is_some() || self.parse_coverage != SshParseCoverage::Unknown))
            || (self.initialized_at.is_none()
                && (has_read || self.continuity != SshContinuity::Unknown))
            || ((self.is_caught_up.is_some() || has_segment) && !has_read)
            || (contiguous && !has_segment)
            || ((self.continuity == SshContinuity::Gapped) != self.last_gap.is_some())
            || (!matches!(capability, Capability::Available)
                && (self.is_caught_up.is_some() || has_segment))
            || [
                &self.initialized_at,
                &self.last_read_at,
                &self.continuous_since,
            ]
            .into_iter()
            .flatten()
            .any(|time| !date(time))
            || !self.counters.valid()
        {
            return Err("INVALID_HEARTBEAT");
        }
        if let Some(gap) = &self.last_gap
            && (!date(&gap.detected_at)
                || gap
                    .recovered_at
                    .as_deref()
                    .is_some_and(|time| !has_read || !date(time))
                || (has_segment && gap.recovered_at.is_none()))
        {
            return Err("INVALID_HEARTBEAT");
        }
        Ok(())
    }
}

fn present_ssh_diagnostics<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<SshSourceDiagnostics>, D::Error> {
    SshSourceDiagnostics::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Heartbeat {
    pub boot_id: String,
    pub version: String,
    pub capabilities: Capabilities,
    pub buffered_bytes: u64,
    pub discarded_samples_total: String,
    pub collector_epoch: String,
    pub updater: UpdaterRuntime,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_ssh_diagnostics"
    )]
    pub ssh_source_diagnostics: Option<SshSourceDiagnostics>,
}
impl Heartbeat {
    pub(crate) fn validate(&self) -> Result<()> {
        if !uuid(&self.boot_id)
            || !uuid(&self.collector_epoch)
            || !text(&self.version, 64)
            || self.discarded_samples_total.is_empty()
            || self.discarded_samples_total.len() > 128
            || !self
                .discarded_samples_total
                .bytes()
                .all(|b| b.is_ascii_digit())
            || (self.discarded_samples_total.len() > 1
                && self.discarded_samples_total.starts_with('0'))
        {
            return Err("INVALID_HEARTBEAT");
        }
        self.updater.validate()?;
        if let Some(diagnostics) = &self.ssh_source_diagnostics {
            diagnostics.validate(self.capabilities.ssh_events)?;
        }
        Ok(())
    }
}
/// Only FAILED is constructed here; no configuration executor exists in this slice.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnsupportedReceipt<'a> {
    pub config_id: &'a str,
    pub generation: u64,
    pub binding_revision: u64,
    pub collector_epoch: &'a str,
    pub sequence: u64,
    pub result: &'static str,
    pub applied_config_id: Option<&'a str>,
    pub error_code: &'static str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Problem {
    pub r#type: String,
    pub title: String,
    pub status: u16,
    pub detail: Option<String>,
    pub code: String,
    pub request_id: String,
    pub field_errors: Option<Vec<FieldError>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FieldError {
    pub field: String,
    pub code: String,
}
impl Problem {
    pub(crate) fn decode(bytes: &[u8], status: u16) -> Result<Self> {
        let p: Self = serde_json::from_slice(bytes).map_err(|_| "INVALID_PROTOCOL")?;
        if p.status != status
            || !public_id(&p.request_id)
            || !public_id(&p.code)
            || p.r#type.len() > 2048
            || p.title.len() > 2048
            || p.detail.as_ref().is_some_and(|v| v.len() > 4096)
            || p.field_errors.as_ref().is_some_and(|fields| {
                fields.len() > 32
                    || fields
                        .iter()
                        .any(|f| f.field.len() > 128 || !public_id(&f.code))
            })
        {
            return Err("INVALID_PROTOCOL");
        }
        Ok(p)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IngestionResult {
    pub accepted_count: u64,
    pub duplicate_count: u64,
    pub expired_count: u64,
    pub received_at: String,
}
impl Validate for IngestionResult {
    fn validate(&self) -> Result<()> {
        if !date(&self.received_at) {
            return Err("INVALID_METRIC_ACK");
        }
        Ok(())
    }
}
decoding!(IngestionResult);

#[cfg(test)]
mod ssh_diagnostics_tests {
    use super::*;
    use serde_json::{Value, json};

    const AT: &str = "2026-11-11T02:04:00Z";

    fn snapshot() -> Value {
        json!({
            "source": "JOURNALD",
            "initializedAt": AT,
            "lastReadAt": AT,
            "isCaughtUp": true,
            "continuity": "CONTIGUOUS",
            "continuousSince": AT,
            "lastGap": null,
            "parseCoverage": "PARTIAL",
            "counters": {
                "coverage": "COMPLETE",
                "unknownFormatRecordsTotal": "18446744073709551615",
                "oversizedRecordsTotal": "0"
            }
        })
    }

    fn heartbeat() -> Value {
        json!({
            "bootId": "123e4567-e89b-42d3-a456-000000000001",
            "version": "0.1.0",
            "capabilities": {
                "system": "AVAILABLE", "processes": "UNSUPPORTED",
                "containers": "UNSUPPORTED", "sshEvents": "AVAILABLE"
            },
            "bufferedBytes": 0,
            "discardedSamplesTotal": "0",
            "collectorEpoch": "123e4567-e89b-42d3-a456-000000000002",
            "updater": {
                "platform": "linux-aarch64",
                "kernelVersion": "6.12",
                "binarySha256": "a".repeat(64),
                "protocolVersion": 1,
                "selfUpdate": "UNSUPPORTED_INSTALLATION",
                "localPhase": "IDLE",
                "mode": "MANUAL",
                "source": "GITHUB_RELEASES",
                "updateEventsDroppedTotal": 0,
                "buildOrigin": "SELF_COMPILED"
            }
        })
    }

    #[test]
    fn optional_extension_requires_a_complete_snapshot_when_present() {
        let mut wire = heartbeat();
        let legacy = serde_json::from_value::<Heartbeat>(wire.clone()).unwrap();
        assert_eq!(legacy.validate(), Ok(()));
        assert!(
            serde_json::to_value(legacy)
                .unwrap()
                .get("sshSourceDiagnostics")
                .is_none()
        );
        wire["sshSourceDiagnostics"] = Value::Null;
        assert!(serde_json::from_value::<Heartbeat>(wire.clone()).is_err());
        wire["sshSourceDiagnostics"] = snapshot();
        let current = serde_json::from_value::<Heartbeat>(wire.clone()).unwrap();
        assert_eq!(current.validate(), Ok(()));
        assert_eq!(
            serde_json::to_value(current).unwrap()["sshSourceDiagnostics"],
            snapshot()
        );
        for field in [
            "source",
            "initializedAt",
            "lastReadAt",
            "isCaughtUp",
            "continuousSince",
            "lastGap",
        ] {
            let mut missing = snapshot();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<SshSourceDiagnostics>(missing).is_err(),
                "{field}"
            );
        }
        let mut missing_counter = snapshot();
        missing_counter["counters"]
            .as_object_mut()
            .unwrap()
            .remove("oversizedRecordsTotal");
        assert!(serde_json::from_value::<SshSourceDiagnostics>(missing_counter).is_err());
        let mut extra = snapshot();
        extra["cursor"] = json!("private");
        assert!(serde_json::from_value::<SshSourceDiagnostics>(extra).is_err());
    }

    #[test]
    fn exact_counter_values_and_coverage_are_checked_before_sending() {
        let mut wire = heartbeat();
        wire["sshSourceDiagnostics"] = snapshot();
        for count in ["18446744073709551616", "+1", "01", "", "1\n", "１２"] {
            wire["sshSourceDiagnostics"]["counters"]["unknownFormatRecordsTotal"] = json!(count);
            let heartbeat = serde_json::from_value::<Heartbeat>(wire.clone()).unwrap();
            assert_eq!(heartbeat.validate(), Err("INVALID_HEARTBEAT"), "{count:?}");
        }
        wire["sshSourceDiagnostics"]["counters"]["unknownFormatRecordsTotal"] = Value::Null;
        let heartbeat = serde_json::from_value::<Heartbeat>(wire.clone()).unwrap();
        assert_eq!(heartbeat.validate(), Err("INVALID_HEARTBEAT"));
        wire["sshSourceDiagnostics"]["counters"]["coverage"] = json!("PARTIAL");
        assert_eq!(
            serde_json::from_value::<Heartbeat>(wire)
                .unwrap()
                .validate(),
            Ok(())
        );
    }

    #[test]
    fn source_capability_and_confirmed_gap_constrain_the_snapshot() {
        let mut wire = heartbeat();
        wire["sshSourceDiagnostics"] = snapshot();
        wire["capabilities"]["sshEvents"] = json!("PERMISSION_DENIED");
        assert_eq!(
            serde_json::from_value::<Heartbeat>(wire.clone())
                .unwrap()
                .validate(),
            Err("INVALID_HEARTBEAT")
        );

        let mut diagnostics = serde_json::from_value::<SshSourceDiagnostics>(snapshot()).unwrap();
        diagnostics.source = None;
        assert_eq!(
            diagnostics.validate(Capability::Available),
            Err("INVALID_HEARTBEAT")
        );
        diagnostics.source = Some(SshSource::Journald);
        diagnostics.continuity = SshContinuity::Gapped;
        assert_eq!(
            diagnostics.validate(Capability::Available),
            Err("INVALID_HEARTBEAT")
        );
        diagnostics.last_gap = Some(SshSourceGap {
            reason: SshGapReason::SourceRetention,
            detected_at: AT.into(),
            recovered_at: None,
        });
        assert_eq!(
            diagnostics.validate(Capability::Available),
            Err("INVALID_HEARTBEAT")
        );
        diagnostics.last_gap.as_mut().unwrap().recovered_at = Some("2026-11-10T01:00:00Z".into());
        // A wall-clock rollback does not invalidate an observed recovery.
        assert_eq!(diagnostics.validate(Capability::Available), Ok(()));
        diagnostics.continuous_since = None;
        diagnostics.is_caught_up = None;
        assert_eq!(diagnostics.validate(Capability::PermissionDenied), Ok(()));
        diagnostics.last_read_at = None;
        assert_eq!(
            diagnostics.validate(Capability::PermissionDenied),
            Err("INVALID_HEARTBEAT")
        );
    }
}
