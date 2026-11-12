//! Strict thin procfs adapters. Unknown fields are ignored; required fields retain errors.
use crate::model::*;
use std::collections::BTreeMap;

pub const MAX_CPUS: usize = 1024;
const MEMORY_KEYS: [&str; 5] = [
    "MemTotal",
    "MemAvailable",
    "Cached",
    "SwapTotal",
    "SwapFree",
];
const SWAP_KEYS: [&str; 2] = ["pswpin", "pswpout"];

fn integer(text: &str) -> Field<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Availability::CollectionError);
    }
    text.parse().map_err(|_| Availability::CollectionError)
}

pub fn parse_cpu(text: &str) -> Field<CpuTimes> {
    let mut cpus = BTreeMap::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { continue };
        if !name.starts_with("cpu") {
            continue;
        }
        let suffix = &name[3..];
        let label = if suffix.is_empty() {
            "total"
        } else {
            if suffix.len() > 10
                || !suffix.bytes().all(|b| b.is_ascii_digit())
                || (suffix.len() > 1 && suffix.starts_with('0'))
            {
                return Err(Availability::CollectionError);
            }
            suffix
        };
        let values: Vec<_> = words.take(11).collect();
        if !(8..=10).contains(&values.len()) {
            return Err(Availability::CollectionError);
        }
        let mut counters = [0_u64; 10];
        for (index, value) in values.into_iter().enumerate() {
            counters[index] = integer(value)?;
        }
        if cpus.insert(label.to_owned(), counters).is_some() || cpus.len() > MAX_CPUS + 1 {
            return Err(Availability::CollectionError);
        }
    }
    if !cpus.contains_key("total") {
        return Err(Availability::CollectionError);
    }
    Ok(cpus)
}

fn selected_fields(text: &str, keys: &[&str], kib: bool) -> MemoryFields {
    let mut result: MemoryFields = keys
        .iter()
        .map(|key| ((*key).to_owned(), Err(Availability::Unsupported)))
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let (key, data, malformed_key) = if kib {
            match line.split_once(':') {
                Some((key, data)) => (key.trim(), data, false),
                None => {
                    let key = line.split_whitespace().next().unwrap_or("");
                    (key, "", true)
                }
            }
        } else {
            let trimmed = line.trim_start();
            let boundary = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
            (&trimmed[..boundary], &trimmed[boundary..], false)
        };
        let mut words = data.split_whitespace();
        if !keys.contains(&key) {
            continue;
        }
        let duplicate = !seen.insert(key.to_owned());
        let value = (|| {
            if duplicate || malformed_key {
                return Err(Availability::CollectionError);
            }
            let raw = integer(words.next().ok_or(Availability::CollectionError)?)?;
            if kib && words.next() != Some("kB") {
                return Err(Availability::CollectionError);
            }
            if words.next().is_some() {
                return Err(Availability::CollectionError);
            }
            raw.checked_mul(if kib { 1024 } else { 1 })
                .ok_or(Availability::CollectionError)
        })();
        result.insert(key.to_owned(), value);
    }
    result
}

pub fn parse_memory(text: &str) -> MemoryFields {
    selected_fields(text, &MEMORY_KEYS, true)
}
pub fn parse_swap(text: &str) -> SwapFields {
    selected_fields(text, &SWAP_KEYS, false)
}

pub fn parse_load(text: &str) -> Field<[f64; 3]> {
    let mut words = text.split_whitespace();
    let mut loads = [0_f64; 3];
    for load in &mut loads {
        let word = words.next().ok_or(Availability::CollectionError)?;
        if word.is_empty()
            || word.bytes().filter(|&b| b == b'.').count() > 1
            || !word.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        {
            return Err(Availability::CollectionError);
        }
        *load = word.parse().map_err(|_| Availability::CollectionError)?;
        if !load.is_finite() || *load < 0.0 {
            return Err(Availability::CollectionError);
        }
    }
    Ok(loads)
}
