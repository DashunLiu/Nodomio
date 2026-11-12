//! Fixed Linux kernel source boundary. No configurable filesystem paths or shell commands.
use crate::model::*;
use std::io::{self, Read};

pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
pub const SOURCE_BUDGET: std::time::Duration = std::time::Duration::from_secs(1);

pub fn classify_io(error: &io::Error) -> Availability {
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::Unsupported => Availability::Unsupported,
        io::ErrorKind::PermissionDenied => Availability::PermissionDenied,
        _ => Availability::CollectionError,
    }
}

/// Read limit+1 to detect truncation; never treat a truncated source as complete.
pub fn read_bounded<R: Read>(reader: R, limit: usize) -> Field<String> {
    if limit > MAX_SOURCE_BYTES {
        return Err(Availability::CollectionError);
    }
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| classify_io(&error))?;
    if bytes.len() > limit {
        return Err(Availability::CollectionError);
    }
    String::from_utf8(bytes).map_err(|_| Availability::CollectionError)
}

// This private boundary keeps source ordering and time ownership testable without sleeping.
#[cfg(any(target_os = "linux", test))]
trait KernelIo {
    fn read(&mut self, path: &str, limit: usize) -> Field<String>;
    fn boottime_ns(&mut self) -> Field<u64>;
    fn page_size(&mut self) -> Field<u64>;
    fn observed_unix_ns(&mut self) -> Field<u128>;
}

#[cfg(any(target_os = "linux", test))]
fn capture_from(io: &mut impl KernelIo) -> Field<RawSnapshot> {
    use crate::parse::*;
    let boot_id = io.read("/proc/sys/kernel/random/boot_id", 64)?;
    let boot_id = boot_id.trim();
    if !valid_boot_id(boot_id) {
        return Err(Availability::CollectionError);
    }
    let cpu_text = io.read("/proc/stat", MAX_SOURCE_BYTES);
    let cpu_observed = observe(io)?;
    let cpu = cpu_text.and_then(|s| parse_cpu(&s));
    let memory_text = io.read("/proc/meminfo", MAX_SOURCE_BYTES);
    let memory_observed = observe(io)?;
    let memory = memory_text.map(|s| parse_memory(&s));
    let load_text = io.read("/proc/loadavg", MAX_SOURCE_BYTES);
    let load_observed = observe(io)?;
    let load = load_text.and_then(|s| parse_load(&s));
    let swap_text = io.read("/proc/vmstat", MAX_SOURCE_BYTES);
    let swap_observed = observe(io)?;
    let swap = swap_text.map(|s| parse_swap(&s));
    let page_size = io.page_size();
    let capture_end = observe(io)?;
    Ok(RawSnapshot {
        boot_id: boot_id.into(),
        monotonic_ns: capture_end.monotonic_ns,
        observed_unix_ns: capture_end.observed_unix_ns,
        cpu_observed,
        memory_observed,
        load_observed,
        swap_observed,
        page_size,
        cpu,
        memory,
        load,
        swap,
    })
}

/// Narrow HOST wire capture: gauges complete before the final CPU source clock.
/// The existing diagnostic source order and independent vmstat timing are unchanged.
#[cfg(any(target_os = "linux", test))]
fn capture_host_from(io: &mut impl KernelIo) -> Field<RawSnapshot> {
    use crate::parse::*;
    let boot_id = io.read("/proc/sys/kernel/random/boot_id", 64)?;
    let boot_id = boot_id.trim();
    if !valid_boot_id(boot_id) {
        return Err(Availability::CollectionError);
    }
    let memory_text = io.read("/proc/meminfo", MAX_SOURCE_BYTES);
    let memory_observed = observe(io)?;
    let memory = memory_text.map(|s| parse_memory(&s));
    let load_text = io.read("/proc/loadavg", MAX_SOURCE_BYTES);
    let load_observed = observe(io)?;
    let load = load_text.and_then(|s| parse_load(&s));
    let cpu_text = io.read("/proc/stat", MAX_SOURCE_BYTES);
    let cpu_observed = observe(io)?;
    let cpu = cpu_text.and_then(|s| parse_cpu(&s));
    Ok(RawSnapshot {
        boot_id: boot_id.into(),
        monotonic_ns: cpu_observed.monotonic_ns,
        observed_unix_ns: cpu_observed.observed_unix_ns,
        cpu_observed,
        memory_observed,
        load_observed,
        swap_observed: cpu_observed,
        cpu,
        memory,
        load,
        page_size: Err(Availability::Unsupported),
        swap: Err(Availability::Unsupported),
    })
}

#[cfg(any(target_os = "linux", test))]
fn observe(io: &mut impl KernelIo) -> Field<ObservationTime> {
    // Adjacent paired clocks locate the completed source read; unrelated work belongs outside.
    let monotonic_ns = io.boottime_ns()?;
    let observed_unix_ns = io.observed_unix_ns()?;
    Ok(ObservationTime {
        monotonic_ns,
        observed_unix_ns,
    })
}

pub struct LinuxSource;
impl LinuxSource {
    #[cfg(not(target_os = "linux"))]
    pub fn capture(&self) -> Field<RawSnapshot> {
        Err(Availability::Unsupported)
    }
    #[cfg(target_os = "linux")]
    pub fn capture_host(&self) -> Field<RawSnapshot> {
        capture_host_from(&mut LinuxKernel)
    }
    #[cfg(not(target_os = "linux"))]
    pub fn capture_host(&self) -> Field<RawSnapshot> {
        Err(Availability::Unsupported)
    }

    #[cfg(target_os = "linux")]
    pub fn capture(&self) -> Field<RawSnapshot> {
        capture_from(&mut LinuxKernel)
    }
}

#[cfg(target_os = "linux")]
struct LinuxKernel;
#[cfg(target_os = "linux")]
impl KernelIo for LinuxKernel {
    fn read(&mut self, path: &str, limit: usize) -> Field<String> {
        let start = std::time::Instant::now();
        let file = std::fs::File::open(path).map_err(|error| classify_io(&error))?;
        let result = read_bounded(file, limit);
        // This rejects late results, but cannot cancel a stalled kernel read.
        if start.elapsed() > SOURCE_BUDGET {
            Err(Availability::CollectionError)
        } else {
            result
        }
    }
    fn boottime_ns(&mut self) -> Field<u64> {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: time points to an initialized, correctly aligned libc timespec; the call writes only it.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
            return Err(classify_io(&io::Error::last_os_error()));
        }
        if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
            return Err(Availability::CollectionError);
        }
        u64::try_from(time.tv_sec)
            .ok()
            .and_then(|v| v.checked_mul(1_000_000_000))
            .and_then(|v| v.checked_add(time.tv_nsec as u64))
            .ok_or(Availability::CollectionError)
    }
    fn page_size(&mut self) -> Field<u64> {
        // SAFETY: sysconf takes a constant selector and does not dereference caller memory.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        u64::try_from(page_size)
            .ok()
            .filter(|v| v.is_power_of_two())
            .ok_or(Availability::CollectionError)
    }
    fn observed_unix_ns(&mut self) -> Field<u128> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Availability::CollectionError)
            .map(|time| time.as_nanos())
    }
}

#[cfg(any(target_os = "linux", test))]
fn valid_boot_id(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}

#[cfg(test)]
mod timing_tests {
    use super::*;
    use crate::collect::Collector;
    const WALL_BASE: u128 = 1_700_000_000_000_000_000;
    struct ScriptedKernel {
        now: u64,
        round: usize,
        memory_delays: [u64; 2],
    }
    impl KernelIo for ScriptedKernel {
        fn read(&mut self, path: &str, _: usize) -> Field<String> {
            Ok(match path {
                "/proc/sys/kernel/random/boot_id" => {
                    "00000000-0000-0000-0000-000000000001\n".into()
                }
                "/proc/stat" => {
                    if self.round == 0 {
                        "cpu 100 20 30 400 50 10 20 70 80 10\ncpu0 100 20 30 400 50 10 20 70 80 10"
                            .into()
                    } else {
                        "cpu 120 25 40 430 60 12 23 90 85 11\ncpu0 120 25 40 430 60 12 23 90 85 11"
                            .into()
                    }
                }
                "/proc/meminfo" => {
                    self.now += self.memory_delays[self.round];
                    include_str!("../tests/fixtures/meminfo.txt").into()
                }
                "/proc/loadavg" => "1.25 0.5 0.01".into(),
                "/proc/vmstat" => {
                    let value = if self.round == 0 {
                        "pswpin 1\npswpout 1"
                    } else {
                        "pswpin 4\npswpout 4"
                    };
                    self.round += 1;
                    value.into()
                }
                _ => panic!("unexpected source path"),
            })
        }
        fn boottime_ns(&mut self) -> Field<u64> {
            Ok(self.now)
        }
        fn page_size(&mut self) -> Field<u64> {
            Ok(4096)
        }
        fn observed_unix_ns(&mut self) -> Field<u128> {
            Ok(WALL_BASE + u128::from(self.now))
        }
    }

    #[test]
    fn unrelated_memory_delay_does_not_shift_cpu_duration_or_endpoint() {
        for delays in [[800_000_000, 0], [0, 800_000_000]] {
            let mut io = ScriptedKernel {
                now: 0,
                round: 0,
                memory_delays: delays,
            };
            let mut collector = Collector::new("timing");
            collector.collect(capture_from(&mut io).unwrap());
            io.now += 1_000_000_000;
            let snapshot = collector.collect(capture_from(&mut io).unwrap());
            let json = serde_json::to_value(&snapshot).unwrap();
            let cpu = snapshot
                .points
                .iter()
                .find(|p| p.metric == "cpu.executionPercent")
                .unwrap();
            let cpu_endpoint = 1_000_000_000 + delays[0];
            assert_eq!(
                cpu.interval.as_ref().unwrap().duration_seconds,
                cpu_endpoint as f64 / 1e9,
                "memory delays {delays:?}"
            );
            assert_eq!(
                json["sourceObservations"]["cpu"]["monotonicNanoseconds"],
                cpu_endpoint.to_string()
            );
            assert_eq!(
                json["sourceObservations"]["cpu"]["observedUnixNanoseconds"],
                (WALL_BASE + u128::from(cpu_endpoint)).to_string()
            );
            let swap = snapshot
                .points
                .iter()
                .find(|p| p.metric == "swap.inBytesPerSecond")
                .unwrap();
            assert_eq!(
                swap.interval.as_ref().unwrap().duration_seconds,
                (1_000_000_000 + delays[1]) as f64 / 1e9
            );
            assert_eq!(
                json["sourceObservations"]["swap"]["monotonicNanoseconds"],
                "1800000000"
            );
            assert_eq!(json["captureEnd"]["monotonicNanoseconds"], "1800000000");
            assert_eq!(
                json["captureEnd"]["observedUnixNanoseconds"],
                (WALL_BASE + 1_800_000_000).to_string()
            );
        }
    }
}

#[cfg(test)]
mod host_timing_tests {
    use super::*;
    struct HostKernel {
        now: u64,
        paths: Vec<String>,
    }
    impl KernelIo for HostKernel {
        fn read(&mut self, path: &str, _: usize) -> Field<String> {
            self.paths.push(path.into());
            self.now += 100;
            Ok(match path {
                "/proc/sys/kernel/random/boot_id" => "00000000-0000-4000-8000-000000000001",
                "/proc/meminfo" => include_str!("../tests/fixtures/meminfo.txt"),
                "/proc/loadavg" => "1.25 0.5 0.01",
                "/proc/stat" => "cpu 10 0 10 80 0 0 0 0 0 0",
                _ => panic!("unexpected HOST source"),
            }
            .into())
        }
        fn boottime_ns(&mut self) -> Field<u64> {
            Ok(self.now)
        }
        fn observed_unix_ns(&mut self) -> Field<u128> {
            Ok(1_800_000_000_000_000_000 + u128::from(self.now))
        }
        fn page_size(&mut self) -> Field<u64> {
            panic!("HOST scope does not read swap rate page size")
        }
    }
    #[test]
    fn host_gauges_complete_before_cpu_anchor_without_vmstat_retiming() {
        let mut io = HostKernel {
            now: 0,
            paths: Vec::new(),
        };
        let raw = capture_host_from(&mut io).unwrap();
        assert_eq!(
            io.paths,
            [
                "/proc/sys/kernel/random/boot_id",
                "/proc/meminfo",
                "/proc/loadavg",
                "/proc/stat"
            ]
        );
        assert!(raw.memory_observed.monotonic_ns < raw.cpu_observed.monotonic_ns);
        assert!(raw.load_observed.monotonic_ns < raw.cpu_observed.monotonic_ns);
        assert_eq!(raw.monotonic_ns, raw.cpu_observed.monotonic_ns);
        assert!(raw.swap.is_err());
    }
}
