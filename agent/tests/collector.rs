use nodomi_agent::{collect::Collector, model::*, parse::*};
fn raw(ns: u64, cpu: &str, vm: &str) -> RawSnapshot {
    RawSnapshot {
        boot_id: "boot-a".into(),
        monotonic_ns: ns,
        observed_unix_ns: 100,
        cpu_observed: ObservationTime {
            monotonic_ns: ns,
            observed_unix_ns: 100,
        },
        memory_observed: ObservationTime {
            monotonic_ns: ns,
            observed_unix_ns: 100,
        },
        load_observed: ObservationTime {
            monotonic_ns: ns,
            observed_unix_ns: 100,
        },
        swap_observed: ObservationTime {
            monotonic_ns: ns,
            observed_unix_ns: 100,
        },
        page_size: Ok(4096),
        cpu: parse_cpu(cpu),
        memory: Ok(parse_memory(include_str!("fixtures/meminfo.txt"))),
        load: parse_load("1.25 0.5 0.01"),
        swap: Ok(parse_swap(vm)),
    }
}
const CPU_A: &str = "cpu 100 20 30 400 50 10 20 70 80 10\ncpu0 100 20 30 400 50 10 20 70 80 10";
const CPU_B: &str = "cpu 120 25 40 430 60 12 23 90 85 11\ncpu0 120 25 40 430 60 12 23 90 85 11";
fn point<'a>(s: &'a DiagnosticSnapshot, name: &str) -> &'a MetricPoint {
    s.points
        .iter()
        .find(|p| p.metric == name && p.labels.get("cpu").is_none_or(|c| c == "total"))
        .unwrap()
}
fn number(s: &DiagnosticSnapshot, n: &str) -> f64 {
    match point(s, n).value {
        Some(MetricValue::Number(v)) => v,
        _ => panic!("missing number {n}"),
    }
}
#[test]
fn first_sample_has_real_gauges_and_no_derived_baseline() {
    let s = Collector::new("run-a").collect(raw(1_000_000_000, CPU_A, "pswpin 1\npswpout 2"));
    assert_eq!(s.points.len(), 30);
    assert_eq!(
        point(&s, "cpu.executionPercent").availability,
        Availability::NoBaseline
    );
    assert_eq!(
        point(&s, "swap.inBytesPerSecond").availability,
        Availability::NoBaseline
    );
    assert_eq!(
        point(&s, "memory.usedBytes").value,
        Some(MetricValue::Integer(614400))
    );
    assert_eq!(s.raw_swap["pswpin"], Ok("1".into()));
}
#[test]
fn cpu_execution_is_40_percent_with_guest_counted_once_and_steal_separate() {
    let mut c = Collector::new("run-a");
    c.collect(raw(1_000_000_000, CPU_A, "pswpin 1\npswpout 2"));
    let s = c.collect(raw(3_000_000_000, CPU_B, "pswpin 4\npswpout 3"));
    assert_eq!(number(&s, "cpu.executionPercent"), 40.0);
    assert_eq!(number(&s, "cpu.stealPercent"), 20.0);
    assert_eq!(number(&s, "cpu.userPercent"), 20.0);
    assert_eq!(
        point(&s, "cpu.executionPercent")
            .interval
            .as_ref()
            .unwrap()
            .duration_seconds,
        2.0
    );
    assert_eq!(number(&s, "swap.inBytesPerSecond"), 6144.0);
    assert_eq!(number(&s, "swap.outBytesPerSecond"), 2048.0);
}
#[test]
fn reset_topology_boot_and_invalid_time_rebuild_baselines() {
    for kind in 0..5 {
        let mut c = Collector::new("run-a");
        c.collect(raw(1_000_000_000, CPU_A, "pswpin 9\npswpout 2"));
        let mut r = raw(3_000_000_000, CPU_B, "pswpin 1\npswpout 3");
        match kind {
            0 => {
                r.cpu = parse_cpu(CPU_A);
                r.cpu.as_mut().unwrap().get_mut("total").unwrap()[0] = 1
            }
            1 => {
                r.cpu.as_mut().unwrap().insert("1".into(), [0; 10]);
            }
            2 => r.boot_id = "boot-b".into(),
            3 => r.monotonic_ns = 1_000_000_000,
            _ => r.monotonic_ns = 0,
        }
        r.cpu_observed.monotonic_ns = r.monotonic_ns;
        r.swap_observed.monotonic_ns = r.monotonic_ns;
        let s = c.collect(r);
        assert_eq!(
            point(&s, "cpu.executionPercent").availability,
            Availability::NoBaseline
        );
        assert_eq!(
            point(&s, "swap.inBytesPerSecond").availability,
            Availability::NoBaseline
        );
    }
}
#[test]
fn memory_missing_bad_relationship_and_zero_capacity_are_distinct() {
    let mut c = Collector::new("run-a");
    let mut r = raw(1, CPU_A, "");
    r.memory = Ok(parse_memory("MemTotal: 1000 kB\nCached: 3 kB"));
    let s = c.collect(r.clone());
    assert_eq!(
        point(&s, "memory.usedBytes").availability,
        Availability::Unsupported
    );
    assert_eq!(
        point(&s, "memory.totalBytes").value,
        Some(MetricValue::Integer(1024000))
    );
    r.memory = Ok(parse_memory(
        "MemTotal: 1 kB\nMemAvailable: 2 kB\nCached: 3 kB\nSwapTotal: 1 kB\nSwapFree: 2 kB",
    ));
    let s = c.collect(r.clone());
    assert_eq!(
        point(&s, "memory.usedBytes").availability,
        Availability::CollectionError
    );
    assert_eq!(
        point(&s, "swap.usedBytes").availability,
        Availability::CollectionError
    );
    r.memory = Ok(parse_memory("MemTotal: 0 kB\nMemAvailable: 0 kB"));
    assert_eq!(
        point(&c.collect(r), "memory.usagePercent").availability,
        Availability::NoCapacity
    );
}
#[test]
fn source_failure_isolated_and_recovery_needs_baseline() {
    let mut c = Collector::new("run-a");
    c.collect(raw(1, CPU_A, "pswpin 1\npswpout 2"));
    let mut r = raw(2, CPU_B, "pswpin 2\npswpout 3");
    r.cpu = Err(Availability::PermissionDenied);
    r.memory = Err(Availability::CollectionError);
    let s = c.collect(r);
    assert_eq!(
        point(&s, "cpu.executionPercent").availability,
        Availability::PermissionDenied
    );
    assert_eq!(
        point(&s, "memory.totalBytes").availability,
        Availability::CollectionError
    );
    assert_eq!(number(&s, "system.load1"), 1.25);
    let s = c.collect(raw(3, CPU_B, "pswpin 3\npswpout 4"));
    assert_eq!(
        point(&s, "cpu.executionPercent").availability,
        Availability::NoBaseline
    );
}
#[test]
fn swap_uses_64k_pages_integer_delta_and_ignores_wall_clock_jumps() {
    let mut c = Collector::new("run-a");
    let mut r = raw(1_000_000_000, CPU_A, "pswpin 9007199254740993\npswpout 1");
    r.page_size = Ok(65536);
    c.collect(r.clone());
    r.monotonic_ns = 3_000_000_000;
    r.cpu_observed.monotonic_ns = r.monotonic_ns;
    r.swap_observed.monotonic_ns = r.monotonic_ns;
    r.observed_unix_ns = 0;
    r.cpu = parse_cpu(CPU_B);
    r.swap = Ok(parse_swap("pswpin 9007199254740996\npswpout 1"));
    let s = c.collect(r);
    assert_eq!(number(&s, "swap.inBytesPerSecond"), 98304.0);
    assert_eq!(number(&s, "swap.outBytesPerSecond"), 0.0);
}
#[test]
fn diagnostic_integer_serialization_does_not_round() {
    let mut r = raw(1, CPU_A, "");
    r.memory = Ok(parse_memory("MemTotal: 9007199254740993 kB"));
    let s = Collector::new("r").collect(r);
    assert_eq!(
        point(&s, "memory.totalBytes").value,
        Some(MetricValue::Integer(9_223_372_036_854_776_832))
    );
    let json = serde_json::to_value(&s).unwrap();
    let total = json["points"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["metric"] == "memory.totalBytes")
        .unwrap();
    assert_eq!(total["value"].as_u64(), Some(9_223_372_036_854_776_832));
}
#[test]
fn metric_points_follow_interval_shape_for_unavailable_rates_and_gauges() {
    let s = Collector::new("r").collect(raw(1, CPU_A, "pswpin 1\npswpout 2"));
    let json = serde_json::to_value(&s).unwrap();
    let points = json["points"].as_array().unwrap();
    let cpu = points
        .iter()
        .find(|p| p["metric"] == "cpu.executionPercent")
        .unwrap();
    assert!(cpu.get("interval").is_some_and(serde_json::Value::is_null));
    let memory = points
        .iter()
        .find(|p| p["metric"] == "memory.totalBytes")
        .unwrap();
    assert!(memory.get("interval").is_none());
}
#[test]
fn diagnostics_expose_shared_snapshot_fields_for_independent_comparison() {
    let s = Collector::new("r").collect(raw(1, CPU_A, "pswpin 1\npswpout 2"));
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(json["rawMemoryBytes"]["MemTotal"]["Ok"], "1024000");
    assert_eq!(json["rawLoad"]["Ok"], serde_json::json!([1.25, 0.5, 0.01]));
}
#[test]
fn recovered_and_reset_sources_start_new_epoch_and_never_splice_old_counts() {
    let mut c = Collector::new("run");
    c.collect(raw(1_000_000_000, CPU_A, "pswpin 1\npswpout 1"));
    let normal = c.collect(raw(3_000_000_000, CPU_B, "pswpin 2\npswpout 2"));
    let old_epoch = point(&normal, "cpu.executionPercent")
        .interval
        .as_ref()
        .unwrap()
        .counter_epoch
        .clone();
    let reset = c.collect(raw(5_000_000_000, CPU_A, "pswpin 0\npswpout 0"));
    assert_eq!(
        point(&reset, "cpu.executionPercent").availability,
        Availability::NoBaseline
    );
    let recovered = c.collect(raw(7_000_000_000, CPU_B, "pswpin 1\npswpout 1"));
    assert_eq!(number(&recovered, "cpu.executionPercent"), 40.0);
    assert_ne!(
        point(&recovered, "cpu.executionPercent")
            .interval
            .as_ref()
            .unwrap()
            .counter_epoch,
        old_epoch
    );
    assert_eq!(number(&recovered, "swap.inBytesPerSecond"), 2048.0);
}
#[test]
fn invalid_swap_field_and_missing_page_size_do_not_invent_zero() {
    let mut c = Collector::new("run");
    c.collect(raw(1_000_000_000, CPU_A, "pswpin 1\npswpout 1"));
    let bad = c.collect(raw(3_000_000_000, CPU_B, "pswpin broken\npswpout 3"));
    assert_eq!(
        point(&bad, "swap.inBytesPerSecond").availability,
        Availability::CollectionError
    );
    assert_eq!(number(&bad, "swap.outBytesPerSecond"), 4096.0);
    let mut r = raw(5_000_000_000, CPU_B, "pswpin 4\npswpout 4");
    r.page_size = Err(Availability::Unsupported);
    let missing = c.collect(r);
    assert_eq!(
        point(&missing, "swap.inBytesPerSecond").availability,
        Availability::Unsupported
    );
    let recovery = c.collect(raw(7_000_000_000, CPU_B, "pswpin 4\npswpout 4"));
    assert_eq!(
        point(&recovery, "swap.inBytesPerSecond").availability,
        Availability::NoBaseline
    );
}
#[test]
fn cpu_total_arithmetic_is_wider_than_u64_and_remains_bounded() {
    let mut c = Collector::new("run");
    c.collect(raw(1, "cpu 0 0 0 0 0 0 0 0", ""));
    let s = c.collect(raw(
        2,
        "cpu 18446744073709551615 0 0 18446744073709551615 0 0 0 0",
        "",
    ));
    assert_eq!(number(&s, "cpu.executionPercent"), 50.0);
    assert_eq!(number(&s, "cpu.idlePercent"), 50.0);
}
