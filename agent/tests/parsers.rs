use nodomi_agent::{model::Availability::*, parse::*};

#[test]
fn cpu_preserves_guest_without_adding_it_to_first_eight_counters() {
    let cpus = parse_cpu(include_str!("fixtures/stat.txt")).unwrap();
    assert_eq!(cpus["total"], [100, 20, 30, 400, 50, 10, 20, 70, 80, 10]);
    assert_eq!(cpus["0"][..8].iter().sum::<u64>(), 700);
}
#[test]
fn cpu_rejects_duplicate_bad_overflow_and_incomplete_rows() {
    for text in [
        "cpu 1 2 3 4 5 6 7 8\ncpu 1 2 3 4 5 6 7 8\n",
        "cpu 1 2 -3 4 5 6 7 8",
        "cpu 18446744073709551616 2 3 4 5 6 7 8",
        "cpu 1 2 3",
        "cpu 1 2 3 4 5 6 7 8\ncpu01 1 2 3 4 5 6 7 8",
    ] {
        assert_eq!(parse_cpu(text), Err(CollectionError), "{text}");
    }
}
#[test]
fn memory_bytes_are_exact_above_double_integer_range() {
    let m = parse_memory("MemTotal: 9007199254740993 kB\nMemAvailable: 400 kB\nCached: 125 kB\n");
    assert_eq!(m["MemTotal"], Ok(9_223_372_036_854_776_832));
    assert_eq!(m["MemAvailable"], Ok(409600));
    assert_eq!(m["SwapTotal"], Err(Unsupported));
}
#[test]
fn memory_field_errors_do_not_poison_unrelated_values() {
    let m = parse_memory(
        "MemTotal: 1000 kB\nMemAvailable: junk kB\nCached: 2 MB\nSwapTotal: 3 kB\nSwapFree: 1 kB\n",
    );
    assert_eq!(m["MemTotal"], Ok(1024000));
    assert_eq!(m["MemAvailable"], Err(CollectionError));
    assert_eq!(m["Cached"], Err(CollectionError));
    assert_eq!(m["SwapTotal"], Ok(3072));
    assert_eq!(
        parse_memory("Cached: 1 kB\nCached: 2 kB")["Cached"],
        Err(CollectionError)
    );
    assert_eq!(
        parse_memory("Cached: 18014398509481984 kB")["Cached"],
        Err(CollectionError)
    );
}
#[test]
fn load_values_are_nonnegative_finite_kernel_windows() {
    assert_eq!(
        parse_load("1.25 0.50 0.01 2/100 42\n"),
        Ok([1.25, 0.5, 0.01])
    );
    for text in ["NaN 0 0", "inf 0 0", "-1 0 0", "1 2", "1e300 2 3"] {
        assert_eq!(parse_load(text), Err(CollectionError));
    }
}
#[test]
fn swap_fields_preserve_raw_integer_counts_and_individual_absence() {
    let s = parse_swap("pgpgin 42\npswpin 9007199254740993\npswpout 2\n");
    assert_eq!(s["pswpin"], Ok(9_007_199_254_740_993));
    assert_eq!(s["pswpout"], Ok(2));
    assert_eq!(parse_swap("pswpin 7")["pswpout"], Err(Unsupported));
    assert_eq!(
        parse_swap("pswpin 1\npswpin 2")["pswpin"],
        Err(CollectionError)
    );
}
#[test]
fn malformed_known_memory_field_is_an_error_rather_than_absent() {
    assert_eq!(
        parse_memory("MemTotal:broken kB")["MemTotal"],
        Err(CollectionError)
    );
    assert_eq!(parse_memory("MemTotal:100 kB")["MemTotal"], Ok(102400));
}
#[test]
fn excessive_cpu_topology_is_rejected_instead_of_truncated() {
    let mut text = String::from("cpu 1 2 3 4 5 6 7 8\n");
    for cpu in 0..=nodomi_agent::parse::MAX_CPUS {
        text.push_str(&format!("cpu{cpu} 1 2 3 4 5 6 7 8\n"));
    }
    assert_eq!(parse_cpu(&text), Err(CollectionError));
}
