//! Stateful calculations over a single shared source snapshot, with independent baselines.
use crate::model::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const CPU_METRICS: [(&str, Option<usize>); 9] = [
    ("executionPercent", None),
    ("userPercent", Some(0)),
    ("systemPercent", Some(2)),
    ("iowaitPercent", Some(4)),
    ("stealPercent", Some(7)),
    ("nicePercent", Some(1)),
    ("irqPercent", Some(5)),
    ("softirqPercent", Some(6)),
    ("idlePercent", Some(3)),
];
static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct CpuBaseline {
    boot: String,
    ns: u64,
    counters: CpuTimes,
}
struct SwapBaseline {
    boot: String,
    ns: u64,
    pages: u64,
    count: u64,
}

pub struct Collector {
    run: String,
    cpu: Option<CpuBaseline>,
    cpu_labels: Vec<String>,
    swap: BTreeMap<String, SwapBaseline>,
    cpu_epoch: u64,
    swap_epoch: BTreeMap<String, u64>,
}

impl Collector {
    /// Prefix is diagnostic context only; process/time/sequence distinguish collector lifetimes.
    pub fn new(prefix: &str) -> Self {
        let prefix: String = prefix
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(16)
            .collect();
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self {
            run: format!("{prefix}.{}.{time}.{sequence}", std::process::id()),
            cpu: None,
            cpu_labels: vec!["total".into()],
            swap: BTreeMap::new(),
            cpu_epoch: 0,
            swap_epoch: BTreeMap::new(),
        }
    }

    pub fn collect(&mut self, raw: RawSnapshot) -> DiagnosticSnapshot {
        let mut points = Vec::new();
        self.cpu_points(&raw, &mut points);
        memory_points(&raw.memory, &mut points);
        for (index, metric) in ["system.load1", "system.load5", "system.load15"]
            .iter()
            .enumerate()
        {
            points.push(point(
                metric,
                None,
                raw.load.map(|values| MetricValue::Number(values[index])),
                None,
            ));
        }
        self.swap_points(&raw, &mut points);
        DiagnosticSnapshot {
            diagnostic_only: true,
            boot_id: raw.boot_id,
            capture_end: ObservationTime {
                monotonic_ns: raw.monotonic_ns,
                observed_unix_ns: raw.observed_unix_ns,
            },
            source_observations: BTreeMap::from([
                ("cpu".into(), raw.cpu_observed),
                ("memory".into(), raw.memory_observed),
                ("load".into(), raw.load_observed),
                ("swap".into(), raw.swap_observed),
            ]),
            page_size_bytes: raw.page_size,
            raw_cpu: raw
                .cpu
                .unwrap_or_default()
                .into_iter()
                .map(|(key, counters)| (key, counters.iter().map(u64::to_string).collect()))
                .collect(),
            raw_memory_bytes: raw
                .memory
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|(key, value)| (key, value.map(|v| v.to_string())))
                .collect(),
            raw_load: raw.load,
            raw_swap: raw
                .swap
                .unwrap_or_default()
                .into_iter()
                .map(|(key, value)| (key, value.map(|v| v.to_string())))
                .collect(),
            points,
        }
    }

    fn cpu_points(&mut self, raw: &RawSnapshot, points: &mut Vec<MetricPoint>) {
        let current = match &raw.cpu {
            Ok(current) => current,
            Err(error) => {
                self.cpu = None;
                for label in &self.cpu_labels {
                    for (metric, _) in CPU_METRICS {
                        points.push(point(
                            &format!("cpu.{metric}"),
                            Some(label),
                            Err(*error),
                            None,
                        ));
                    }
                }
                return;
            }
        };
        self.cpu_labels = current.keys().cloned().collect();
        let valid = self.cpu.as_ref().filter(|old| {
            old.boot == raw.boot_id
                && raw.cpu_observed.monotonic_ns > old.ns
                && old.counters.keys().eq(current.keys())
                && current.iter().all(|(key, values)| {
                    values.iter().zip(old.counters[key]).all(|(a, b)| *a >= b)
                        && values[..8]
                            .iter()
                            .zip(old.counters[key][..8].iter())
                            .any(|(a, b)| a > b)
                })
        });
        let interval = valid.map(|old| Interval {
            duration_seconds: (raw.cpu_observed.monotonic_ns - old.ns) as f64 / 1e9,
            counter_epoch: format!("{}.cpu.{}", self.run, self.cpu_epoch),
        });
        if valid.is_none() {
            self.cpu_epoch += 1;
        }
        for (label, values) in current {
            let deltas = valid.map(|old| {
                std::array::from_fn::<u64, 10, _>(|index| {
                    values[index] - old.counters[label][index]
                })
            });
            for (metric, index) in CPU_METRICS {
                let value = match deltas {
                    Some(delta) => {
                        let total: u128 = delta[..8].iter().map(|v| u128::from(*v)).sum();
                        let numerator: u128 = index.map_or_else(
                            || [0, 1, 2, 5, 6].iter().map(|i| u128::from(delta[*i])).sum(),
                            |i| u128::from(delta[i]),
                        );
                        Ok(MetricValue::Number(
                            (numerator as f64 / total as f64) * 100.0,
                        ))
                    }
                    None => Err(Availability::NoBaseline),
                };
                points.push(point(
                    &format!("cpu.{metric}"),
                    Some(label),
                    value,
                    interval.clone(),
                ));
            }
        }
        self.cpu = Some(CpuBaseline {
            boot: raw.boot_id.clone(),
            ns: raw.cpu_observed.monotonic_ns,
            counters: current.clone(),
        });
    }

    fn swap_points(&mut self, raw: &RawSnapshot, points: &mut Vec<MetricPoint>) {
        for (field, metric) in [
            ("pswpin", "swap.inBytesPerSecond"),
            ("pswpout", "swap.outBytesPerSecond"),
        ] {
            let current = raw
                .swap
                .as_ref()
                .map_err(|e| *e)
                .and_then(|values| field_value(values, field))
                .and_then(|count| {
                    raw.page_size.and_then(|pages| {
                        if pages > 0 {
                            Ok((count, pages))
                        } else {
                            Err(Availability::CollectionError)
                        }
                    })
                });
            let mut interval = None;
            let value = match current {
                Err(error) => {
                    self.swap.remove(field);
                    Err(error)
                }
                Ok((count, pages)) => {
                    let old = self.swap.get(field).filter(|old| {
                        old.boot == raw.boot_id
                            && raw.swap_observed.monotonic_ns > old.ns
                            && count >= old.count
                            && pages == old.pages
                    });
                    let epoch = self.swap_epoch.entry(field.into()).or_default();
                    let value = if let Some(old) = old {
                        let duration = (raw.swap_observed.monotonic_ns - old.ns) as f64 / 1e9;
                        let bytes = u128::from(count - old.count) * u128::from(pages);
                        interval = Some(Interval {
                            duration_seconds: duration,
                            counter_epoch: format!("{}.{field}.{epoch}", self.run),
                        });
                        Ok(MetricValue::Number(bytes as f64 / duration))
                    } else {
                        *epoch += 1;
                        Err(Availability::NoBaseline)
                    };
                    self.swap.insert(
                        field.into(),
                        SwapBaseline {
                            boot: raw.boot_id.clone(),
                            ns: raw.swap_observed.monotonic_ns,
                            pages,
                            count,
                        },
                    );
                    value
                }
            };
            points.push(point(metric, None, value, interval));
        }
    }
}

fn field_value(fields: &MemoryFields, name: &str) -> Field<u64> {
    fields
        .get(name)
        .copied()
        .unwrap_or(Err(Availability::Unsupported))
}
fn memory_points(source: &Field<MemoryFields>, points: &mut Vec<MetricPoint>) {
    let get = |name| {
        source
            .as_ref()
            .map_err(|e| *e)
            .and_then(|fields| field_value(fields, name))
    };
    let total = get("MemTotal");
    let available = get("MemAvailable");
    let available = available.and_then(|v| match total {
        Ok(t) if v > t => Err(Availability::CollectionError),
        _ => Ok(v),
    });
    let used = total.and_then(|t| {
        available.and_then(|a| t.checked_sub(a).ok_or(Availability::CollectionError))
    });
    for (name, value) in [
        ("memory.totalBytes", total),
        ("memory.availableBytes", available),
        ("memory.cachedBytes", get("Cached")),
        ("memory.usedBytes", used),
        ("swap.totalBytes", get("SwapTotal")),
        (
            "swap.usedBytes",
            get("SwapTotal").and_then(|t| {
                get("SwapFree").and_then(|f| t.checked_sub(f).ok_or(Availability::CollectionError))
            }),
        ),
    ] {
        points.push(point(name, None, value.map(MetricValue::Integer), None));
    }
    let usage = used.and_then(|used| {
        total.and_then(|t| {
            if t == 0 {
                Err(Availability::NoCapacity)
            } else {
                Ok(MetricValue::Number((used as f64 / t as f64) * 100.0))
            }
        })
    });
    points.push(point("memory.usagePercent", None, usage, None));
}

fn point(
    name: &str,
    label: Option<&str>,
    value: Field<MetricValue>,
    interval: Option<Interval>,
) -> MetricPoint {
    let labels = label
        .map(|v| BTreeMap::from([("cpu".into(), v.into())]))
        .unwrap_or_default();
    let (availability, value) = match value {
        Ok(value) => (Availability::Available, Some(value)),
        Err(error) => (error, None),
    };
    MetricPoint {
        metric: name.into(),
        labels,
        availability,
        value,
        interval,
    }
}
