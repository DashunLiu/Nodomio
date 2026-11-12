//! Internal development protocol tool, deliberately separate from agentctl install.
#[cfg(target_os = "linux")]
use nodomi_agent::reporting::dispatcher::{
    DeliveryCompletion, DeliveryDispatcher, with_delivery_dispatcher,
};
use nodomi_agent::{
    client::ProtocolClient,
    identity::{Enrollment, IdentityStore, Target},
    protocol::{Heartbeat, RegistrationMetadata},
};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Duration,
};
fn read_bounded(path: &str, limit: u64) -> Result<Vec<u8>, &'static str> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "INPUT_FILE_ERROR")?;
    if !file.metadata().map_err(|_| "INPUT_FILE_ERROR")?.is_file() {
        return Err("INPUT_FILE_ERROR");
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "INPUT_FILE_ERROR")?;
    if bytes.len() as u64 > limit {
        return Err("INPUT_TOO_LARGE");
    }
    Ok(bytes)
}
/// Actual facts from this Linux process, without installation or update authority.
#[cfg(target_os = "linux")]
fn development_heartbeat() -> Result<Heartbeat, &'static str> {
    use nodomi_agent::{
        identity::new_collector_epoch,
        model::Availability,
        protocol::{Capabilities, Capability, UpdaterRuntime},
        source::{LinuxSource, read_bounded},
    };
    use ring::digest::{Context, SHA256};
    let raw = LinuxSource
        .capture()
        .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
    let system_sources = [
        raw.cpu.as_ref().err(),
        raw.memory.as_ref().err(),
        raw.load.as_ref().err(),
        raw.swap.as_ref().err(),
    ];
    let system = if system_sources.iter().all(Option::is_none) {
        Capability::Available
    } else if system_sources.contains(&Some(&Availability::PermissionDenied)) {
        Capability::PermissionDenied
    } else {
        Capability::Error
    };
    let kernel = read_bounded(
        std::fs::File::open("/proc/sys/kernel/osrelease")
            .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?,
        128,
    )
    .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
    // This procfs link deliberately identifies the running executable, even if its
    // pathname was replaced. It is not an operator-supplied installation path.
    let mut executable =
        std::fs::File::open("/proc/self/exe").map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
    let metadata = executable
        .metadata()
        .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
    const MAX_EXECUTABLE: u64 = 256 * 1024 * 1024;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE {
        return Err("LOCAL_RUNTIME_UNAVAILABLE");
    }
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 64 * 1024];
    let mut read = 0u64;
    loop {
        let count = executable
            .read(&mut buffer)
            .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > MAX_EXECUTABLE {
            return Err("LOCAL_RUNTIME_UNAVAILABLE");
        }
        context.update(&buffer[..count]);
    }
    if read != metadata.len() {
        return Err("LOCAL_RUNTIME_UNAVAILABLE");
    }
    let binary_sha256 = context
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let platform = match std::env::consts::ARCH {
        "x86_64" => "linux-x86_64",
        "aarch64" => "linux-aarch64",
        _ => "UNSUPPORTED",
    };
    Ok(Heartbeat {
        boot_id: raw.boot_id,
        version: env!("CARGO_PKG_VERSION").into(),
        capabilities: Capabilities {
            system,
            processes: Capability::Unsupported,
            containers: Capability::Unsupported,
            ssh_events: Capability::Unsupported,
        },
        // No sample envelopes have been admitted by this finite development tool.
        buffered_bytes: 0,
        discarded_samples_total: "0".into(),
        collector_epoch: new_collector_epoch()?,
        ssh_source_diagnostics: None,
        updater: UpdaterRuntime {
            platform: platform.into(),
            kernel_version: kernel.trim().into(),
            current_release_id: None,
            binary_sha256,
            protocol_version: 1,
            self_update: "UNSUPPORTED_INSTALLATION".into(),
            local_phase: "IDLE".into(),
            mode: "MANUAL".into(),
            // Contract's configured distribution default, not verified install provenance.
            source: "GITHUB_RELEASES".into(),
            local_attempt_id: None,
            trigger: None,
            target_version: None,
            last_check_at: None,
            available_version: None,
            error_code: None,
            available_is_security_update: None,
            result_recorded_at: None,
            update_events_dropped_total: 0,
            build_origin: "SELF_COMPILED".into(),
        },
    })
}
#[cfg(not(target_os = "linux"))]
fn development_heartbeat() -> Result<Heartbeat, &'static str> {
    Err("UNSUPPORTED_HOST")
}

#[cfg(target_os = "linux")]
fn host_retry_delay(seconds: u64, retry_after: Option<Duration>) -> Duration {
    let mut random = [0u8; 2];
    let millis = if getrandom::fill(&mut random).is_ok() {
        u64::from(u16::from_ne_bytes(random) % 251)
    } else {
        0
    };
    Duration::from_secs(seconds)
        .max(retry_after.unwrap_or_default())
        .saturating_add(Duration::from_millis(millis))
}

#[cfg(target_os = "linux")]
fn collect_runtime(
    client: &ProtocolClient,
    state: &mut IdentityStore,
    path: &Path,
    rounds: usize,
) -> Result<serde_json::Value, &'static str> {
    with_delivery_dispatcher(|dispatch| {
        collect_with_dispatch(client, state, path, rounds, dispatch)
    })
}

#[cfg(target_os = "linux")]
fn collect_with_dispatch(
    client: &ProtocolClient,
    state: &mut IdentityStore,
    path: &Path,
    rounds: usize,
    dispatch: &mut DeliveryDispatcher,
) -> Result<serde_json::Value, &'static str> {
    use nodomi_agent::{
        client::{ConfigurationFailure, MetricUploadOutcome},
        runtime::{HostCollector, RuntimeStore},
        source::LinuxSource,
    };
    use std::time::Instant;
    let mut heartbeat = development_heartbeat()?;
    let mut runtime = RuntimeStore::open(path, state, &heartbeat.collector_epoch)?;
    let config = client.configuration(state)?;
    let first = LinuxSource
        .capture_host()
        .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
    if let Err(code) = runtime.apply(&config, &first.boot_id, first.cpu_observed.monotonic_ns) {
        if let Some(reason) =
            ConfigurationFailure::from_apply_error(code).filter(|_| runtime.safely_reportable())
        {
            heartbeat.buffered_bytes = runtime.allocated_bytes()?;
            heartbeat.discarded_samples_total = runtime.discarded_samples_total().to_string();
            client.heartbeat(state, &heartbeat)?;
            client.report_configuration_failure(
                state,
                &config,
                &heartbeat.collector_epoch,
                1,
                None,
                reason,
            )?;
        }
        return Err(code);
    }
    let mut collector = HostCollector::new(&heartbeat.collector_epoch)?;
    // These deadlines and enforced store settings are the activated complete target.
    let mut sampling = Duration::from_secs(u64::from(
        config.target.configuration.sampling_interval_seconds,
    ));
    let mut next_heartbeat = Instant::now() + Duration::from_secs(30);
    let mut next_config = Instant::now() + Duration::from_secs(30);
    heartbeat.buffered_bytes = runtime.allocated_bytes()?;
    heartbeat.discarded_samples_total = runtime.discarded_samples_total().to_string();
    client.heartbeat(state, &heartbeat)?;
    let mut sequence = 1;
    client.report_applied_configuration(state, &config, &heartbeat.collector_epoch, sequence)?;
    let mut active = config;
    let mut rejected_configuration = None::<(
        nodomi_agent::protocol::AgentConfiguration,
        Instant,
        Duration,
    )>;
    let mut receipt_failure = None;
    // Submit the durable prior body before admitting the first new round. The
    // new round may proceed while that recovery request waits for its reply.
    if runtime.has_pending_sample()
        && let Some(pending) = runtime.begin(&first.boot_id, first.cpu_observed.monotonic_ns)?
    {
        dispatch.submit_host(client, state, pending)?;
    }
    let mut next_sample = Instant::now();
    let mut completed = 0usize;
    let mut last_ns = None;
    let mut final_sample = None;
    let mut accepted = 0;
    let mut duplicates = 0;
    let mut expired = 0;
    let mut retry = None;
    let mut retry_seconds = 5u64;
    loop {
        if let Some(completion) = dispatch.take_completion()? {
            let DeliveryCompletion::Host {
                sample_id,
                finished_at,
                completion,
            } = completion
            else {
                return Err("UNEXPECTED_DELIVERY_COMPLETION");
            };
            match client.finish_metric_upload(state, completion)? {
                MetricUploadOutcome::Acknowledged(result) => {
                    runtime.acknowledge(&sample_id)?;
                    accepted += result.accepted_count;
                    duplicates += result.duplicate_count;
                    expired += result.expired_count;
                    retry = None;
                    retry_seconds = 5;
                    if final_sample.as_ref() == Some(&sample_id) {
                        break;
                    }
                }
                MetricUploadOutcome::Failed {
                    code,
                    retry_after,
                    terminal,
                } => {
                    runtime.attempt_finished(&sample_id)?;
                    if terminal || completed == rounds {
                        return Err(code);
                    }
                    let delay = host_retry_delay(retry_seconds, retry_after);
                    let deadline = finished_at
                        .checked_add(delay)
                        .ok_or("INVALID_RETRY_AFTER")?;
                    retry = Some((deadline, code));
                    retry_seconds = (retry_seconds * 2).min(30);
                }
            }
        }
        let now = Instant::now();
        if now >= next_heartbeat {
            heartbeat.buffered_bytes = runtime.allocated_bytes()?;
            heartbeat.discarded_samples_total = runtime.discarded_samples_total().to_string();
            client.heartbeat(state, &heartbeat)?;
            next_heartbeat = Instant::now() + Duration::from_secs(30);
        }
        if Instant::now() >= next_config {
            let desired = client.configuration(state)?;
            if desired != active
                && rejected_configuration
                    .as_ref()
                    .is_none_or(|(rejected, retry_at, _)| {
                        rejected != &desired || Instant::now() >= *retry_at
                    })
            {
                let raw = LinuxSource
                    .capture_host()
                    .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
                match runtime.apply(&desired, &raw.boot_id, raw.cpu_observed.monotonic_ns) {
                    Err(code) => {
                        let Some(reason) = ConfigurationFailure::from_apply_error(code)
                            .filter(|_| runtime.safely_reportable())
                        else {
                            return Err(code);
                        };
                        heartbeat.buffered_bytes = runtime.allocated_bytes()?;
                        heartbeat.discarded_samples_total =
                            runtime.discarded_samples_total().to_string();
                        client.heartbeat(state, &heartbeat)?;
                        sequence += 1;
                        client.report_configuration_failure(
                            state,
                            &desired,
                            &heartbeat.collector_epoch,
                            sequence,
                            Some(&active),
                            reason,
                        )?;
                        receipt_failure = Some(reason);
                        let delay = rejected_configuration
                            .as_ref()
                            .filter(|(rejected, _, _)| rejected == &desired)
                            .map_or(Duration::from_secs(60), |(_, _, delay)| {
                                (*delay * 2).min(Duration::from_secs(300))
                            });
                        rejected_configuration = Some((desired, Instant::now() + delay, delay));
                    }
                    Ok(()) => {
                        sampling = Duration::from_secs(u64::from(
                            desired.target.configuration.sampling_interval_seconds,
                        ));
                        active = desired;
                        sequence += 1;
                        client.report_applied_configuration(
                            state,
                            &active,
                            &heartbeat.collector_epoch,
                            sequence,
                        )?;
                        rejected_configuration = None;
                        receipt_failure = None;
                        collector.interrupt();
                        next_sample = Instant::now();
                    }
                }
            }
            next_config = Instant::now() + Duration::from_secs(30);
        }
        let mut dispatch_clock = None;
        if completed < rounds && Instant::now() >= next_sample {
            let raw = LinuxSource
                .capture_host()
                .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
            let time = raw.cpu_observed;
            if last_ns.is_some_and(|last| {
                time.monotonic_ns.saturating_sub(last) > sampling.as_nanos() as u64 + 1_000_000_000
            }) {
                collector.interrupt();
            }
            let sample = collector.collect(raw)?;
            last_ns = Some(time.monotonic_ns);
            if completed + 1 == rounds {
                final_sample = Some(sample.sample_id.clone());
            }
            dispatch_clock = Some((sample.boot_id.clone(), sample.monotonic_ns));
            // Failed admission has generated an ID; keep its predecessor fact and reset next rates.
            if let Err(code) = runtime.admit(sample) {
                collector.interrupt();
                return Err(code);
            }
            completed += 1;
            next_sample += sampling;
            if next_sample <= Instant::now() {
                collector.interrupt();
                next_sample = Instant::now() + sampling;
            }
        }

        if dispatch.active_kind().is_none() {
            let ready = retry.is_none_or(|(deadline, _)| Instant::now() >= deadline);
            if ready && runtime.has_pending_sample() {
                let (boot, monotonic_ns) = match dispatch_clock {
                    Some(clock) => clock,
                    None => {
                        let raw = LinuxSource
                            .capture_host()
                            .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
                        (raw.boot_id, raw.cpu_observed.monotonic_ns)
                    }
                };
                if let Some(pending) = runtime.begin(&boot, monotonic_ns)? {
                    dispatch.submit_host(client, state, pending)?;
                }
            }
            if completed == rounds && dispatch.active_kind().is_none() {
                // The final round is durable even if a previous failure still
                // requires backoff. Finite mode must not report it as confirmed.
                return Err(retry.map_or("METRIC_SAMPLE_NOT_CONFIRMED", |(_, code)| code));
            }
        }
        let mut deadline = next_heartbeat.min(next_config);
        if completed < rounds {
            deadline = deadline.min(next_sample);
        }
        if dispatch.active_kind().is_none()
            && runtime.has_pending_sample()
            && let Some((retry_at, _)) = retry
        {
            deadline = deadline.min(retry_at);
        }
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250)),
        );
    }
    Ok(serde_json::json!({
        "configuration": active,
        "collectorEpoch": heartbeat.collector_epoch,
        "runtime": heartbeat.updater,
        "receipt": {
            "result": if receipt_failure.is_some() { "FAILED" } else { "APPLIED" },
            "appliedConfigId": active.target.config_id,
            "errorCode": receipt_failure.map(ConfigurationFailure::code),
            "sequence": sequence,
            "acknowledged": true,
        },
        "collectedRounds": completed,
        "acknowledgedSamples": accepted + duplicates + expired,
        "acceptedSamples": accepted,
        "duplicateSamples": duplicates,
        "expiredSamples": expired,
        "bufferedBytes": runtime.allocated_bytes()?,
        "discardedSamplesTotal": runtime.discarded_samples_total().to_string(),
    }))
}
#[cfg(not(target_os = "linux"))]
fn collect_runtime(
    _client: &ProtocolClient,
    _state: &mut IdentityStore,
    _path: &Path,
    _rounds: usize,
) -> Result<serde_json::Value, &'static str> {
    Err("UNSUPPORTED_HOST")
}

fn run() -> Result<(), &'static str> {
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or("INVALID_PROTOCOL_TOOL_ARGUMENTS")?;
    if !["prepare", "enroll", "query", "status", "run", "collect"].contains(&action.as_str()) {
        return Err("INVALID_PROTOCOL_TOOL_ARGUMENTS");
    }
    let mut options = BTreeMap::new();
    while let Some(key) = args.next() {
        if ![
            "--state-dir",
            "--origin",
            "--server-id",
            "--enrollment-file",
            "--metadata-file",
            "--ca-file",
            "--runtime-dir",
            "--samples",
        ]
        .contains(&key.as_str())
        {
            return Err("INVALID_PROTOCOL_TOOL_ARGUMENTS");
        }
        let value = args.next().ok_or("INVALID_PROTOCOL_TOOL_ARGUMENTS")?;
        if options.insert(key, value).is_some() {
            return Err("INVALID_PROTOCOL_TOOL_ARGUMENTS");
        }
    }
    let option = |name: &str| {
        options
            .get(name)
            .map(String::as_str)
            .ok_or("INVALID_PROTOCOL_TOOL_ARGUMENTS")
    };
    let target = Target::new(option("--origin")?, option("--server-id")?)?;
    if action != "enroll"
        && (options.contains_key("--enrollment-file") || options.contains_key("--metadata-file"))
    {
        return Err("INVALID_PROTOCOL_TOOL_ARGUMENTS");
    }
    if ["prepare", "status"].contains(&action.as_str()) && options.contains_key("--ca-file") {
        return Err("INVALID_PROTOCOL_TOOL_ARGUMENTS");
    }
    if action != "collect"
        && (options.contains_key("--runtime-dir") || options.contains_key("--samples"))
    {
        return Err("INVALID_PROTOCOL_TOOL_ARGUMENTS");
    }
    let collection = if action == "collect" {
        let rounds = option("--samples")?
            .parse::<usize>()
            .map_err(|_| "INVALID_PROTOCOL_TOOL_ARGUMENTS")?;
        if !(1..=120).contains(&rounds) {
            return Err("INVALID_PROTOCOL_TOOL_ARGUMENTS");
        }
        Some((Path::new(option("--runtime-dir")?), rounds))
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    if action == "collect" {
        return Err("UNSUPPORTED_HOST");
    }
    let path = Path::new(option("--state-dir")?);
    let mut state = if action == "prepare" {
        IdentityStore::initialize(path, target.clone())?
    } else {
        IdentityStore::open(path, &target)?
    };
    if let Some((path, _)) = collection {
        nodomi_agent::runtime::RuntimeStore::preflight(path, &state)?;
    }
    let mut report = None;
    let heartbeat = if action == "run" {
        Some(development_heartbeat()?)
    } else {
        None
    };
    if ["enroll", "query", "run", "collect"].contains(&action.as_str()) {
        let ca = options
            .get("--ca-file")
            .map(|path| read_bounded(path, 65536))
            .transpose()?;
        let client = ProtocolClient::new(target, ca.as_deref(), Duration::from_secs(10))?;
        if action == "enroll" {
            let metadata: RegistrationMetadata =
                serde_json::from_slice(&read_bounded(option("--metadata-file")?, 16384)?)
                    .map_err(|_| "INVALID_REGISTRATION_METADATA")?;
            let enrollment =
                Enrollment::from_private_file(Path::new(option("--enrollment-file")?))?;
            client.register(&mut state, &enrollment, &metadata)?;
        } else {
            client.query_identity(&mut state)?;
            if let Some((path, rounds)) = collection {
                report = Some(collect_runtime(&client, &mut state, path, rounds)?);
            }
            if let Some(heartbeat) = heartbeat {
                let config = client.configuration(&mut state)?;
                client.heartbeat(&mut state, &heartbeat)?;
                client.report_unsupported_configuration(
                    &mut state,
                    &config,
                    &heartbeat.collector_epoch,
                    1,
                )?;
                report = Some(serde_json::json!({
                    "configuration": config,
                    "collectorEpoch": heartbeat.collector_epoch,
                    "runtime": heartbeat.updater,
                    "receipt": { "result": "FAILED", "appliedConfigId": null,
                        "errorCode": "UNSUPPORTED_CONFIGURATION", "sequence": 1, "acknowledged": true }
                }));
            }
        }
    }
    let mut status = serde_json::json!({"tool":"INTERNAL_PROTOCOL_DEVELOPMENT","operationId":state.operation_id(),"status":state.status(),"expectedServerId":state.target().expected_server_id,"binding":state.binding()});
    if let Some(report) = report {
        status
            .as_object_mut()
            .ok_or("OUTPUT_ERROR")?
            .extend(report.as_object().ok_or("OUTPUT_ERROR")?.clone());
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &status).map_err(|_| "OUTPUT_ERROR")?;
    writeln!(output).map_err(|_| "OUTPUT_ERROR")?;
    Ok(())
}
fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}
