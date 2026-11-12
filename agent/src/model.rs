use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Availability {
    Available,
    Unsupported,
    PermissionDenied,
    CollectionError,
    NoBaseline,
    NoCapacity,
}

pub type Field<T> = Result<T, Availability>;
pub type CpuTimes = BTreeMap<String, [u64; 10]>;
pub type MemoryFields = BTreeMap<String, Field<u64>>;
pub type SwapFields = BTreeMap<String, Field<u64>>;

/// Sequential source-adjacent clock readings, not an atomic kernel snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservationTime {
    #[serde(rename = "monotonicNanoseconds", serialize_with = "decimal_string")]
    pub monotonic_ns: u64,
    #[serde(rename = "observedUnixNanoseconds", serialize_with = "decimal_string")]
    pub observed_unix_ns: u128,
}

fn decimal_string<T: std::fmt::Display, S: serde::Serializer>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

/// Internal validated-producer boundary, not a validated public ingestion API.
#[derive(Clone, Debug)]
pub struct RawSnapshot {
    pub boot_id: String,
    pub monotonic_ns: u64,
    pub observed_unix_ns: u128,
    pub cpu_observed: ObservationTime,
    pub memory_observed: ObservationTime,
    pub load_observed: ObservationTime,
    pub swap_observed: ObservationTime,
    pub page_size: Field<u64>,
    pub cpu: Field<CpuTimes>,
    pub memory: Field<MemoryFields>,
    pub load: Field<[f64; 3]>,
    pub swap: Field<SwapFields>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum MetricValue {
    Integer(u64),
    Number(f64),
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Interval {
    pub duration_seconds: f64,
    pub counter_epoch: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MetricPoint {
    pub metric: String,
    pub labels: BTreeMap<String, String>,
    pub availability: Availability,
    pub value: Option<MetricValue>,
    pub interval: Option<Interval>,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticSnapshot {
    pub diagnostic_only: bool,
    pub boot_id: String,
    pub capture_end: ObservationTime,
    pub source_observations: BTreeMap<String, ObservationTime>,
    pub page_size_bytes: Field<u64>,
    pub raw_cpu: BTreeMap<String, Vec<String>>,
    pub raw_swap: BTreeMap<String, Field<String>>,
    pub raw_memory_bytes: BTreeMap<String, Field<String>>,
    pub raw_load: Field<[f64; 3]>,
    pub points: Vec<MetricPoint>,
}

impl serde::Serialize for MetricPoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let is_rate = self.metric.starts_with("cpu.") || self.metric.ends_with("BytesPerSecond");
        let mut map = serializer.serialize_map(Some(if is_rate { 5 } else { 4 }))?;
        map.serialize_entry("metric", &self.metric)?;
        map.serialize_entry("labels", &self.labels)?;
        map.serialize_entry("availability", &self.availability)?;
        map.serialize_entry("value", &self.value)?;
        if is_rate {
            map.serialize_entry("interval", &self.interval)?;
        }
        map.end()
    }
}
