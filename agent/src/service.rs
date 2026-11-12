//! Linux foreground collector launched by the installed supervisor.
#[path = "service_files.rs"]
mod service_files;

use self::service_files::{ServiceFiles, supervisor_lock};
use nodomi_agent::{
    buffer::{QueueTime, SharedBuffer, SshQueue},
    client::{ConfigurationFailure, MetricUploadOutcome, ProtocolClient},
    identity::{IdentityStore, Result, Status, new_collector_epoch},
    installation::{
        HealthConfirmationStore, HealthContext, HealthTracker, StartupState, StartupWindow,
        read_startup_state,
    },
    model::{Availability, RawSnapshot},
    protocol::{AgentConfiguration, Capabilities, Capability, Heartbeat, UpdaterRuntime},
    reporting::{
        SecurityEventPreparation, SecurityEventSender, SecurityEventStep,
        dispatcher::{
            DeliveryCompletion, DeliveryDispatcher, DeliveryKind, with_delivery_dispatcher,
        },
    },
    runtime::{HostCollector, RuntimeStore},
    source::{LinuxSource, read_bounded},
    ssh_source::{SourceRead, SshSourceReader, queue_time},
};
use ring::digest::{Context, SHA256};
use std::{
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

const STATE: &str = "/var/lib/nodomi-agent";
const CONTROL: &str = "/var/lib/nodomi-agent-control";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const STOP_POLL: Duration = Duration::from_millis(250);
const SSH_POLL_INTERVAL: Duration = Duration::from_secs(1);
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn install_stop_handlers() -> Result<()> {
    // SAFETY: Zero initialization is valid for sigaction. The installed handler
    // only sets a lock-free flag and does not touch the application state.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = request_stop as *const () as usize;
        if libc::sigemptyset(&mut action.sa_mask) != 0
            || libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
        {
            return Err("SERVICE_SIGNAL_SETUP_FAILED");
        }
    }
    Ok(())
}

pub(super) enum Exit {
    Stopped,
    AwaitingTakeover,
}

pub(super) fn run(fd: i32) -> Result<Exit> {
    install_stop_handlers()?;
    let (_lease, control) = supervisor_lock(Path::new(CONTROL), fd)?;
    let files = ServiceFiles::load(Path::new(STATE))?;
    run_service(
        &files,
        Some(&control),
        &STOP,
        CONTROL_INTERVAL,
        REQUEST_TIMEOUT,
    )
}

fn capture() -> Result<RawSnapshot> {
    LinuxSource
        .capture_host()
        .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")
}

fn system_capability(raw: &RawSnapshot) -> Capability {
    // HOST derives swap capacity from meminfo. The separate diagnostic
    // vmstat source is intentionally absent from capture_host.
    let errors = [
        raw.cpu.as_ref().err(),
        raw.memory.as_ref().err(),
        raw.load.as_ref().err(),
    ];
    if errors.iter().all(Option::is_none) {
        Capability::Available
    } else if errors.contains(&Some(&Availability::PermissionDenied)) {
        Capability::PermissionDenied
    } else {
        Capability::Error
    }
}

fn updater_facts() -> Result<UpdaterRuntime> {
    const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
    let kernel = read_bounded(
        File::open("/proc/sys/kernel/osrelease").map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?,
        128,
    )
    .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
    // The procfs link refers to the actual running ELF across pathname changes.
    let executable = File::open("/proc/self/exe").map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
    let metadata = executable
        .metadata()
        .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
    if !metadata.is_file() || !(1..=MAX_BINARY_BYTES).contains(&metadata.len()) {
        return Err("LOCAL_RUNTIME_UNAVAILABLE");
    }
    let mut digest = Context::new(&SHA256);
    let mut executable = executable.take(MAX_BINARY_BYTES + 1);
    let mut chunk = [0; 64 * 1024];
    let mut length = 0;
    loop {
        let read = executable
            .read(&mut chunk)
            .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?;
        if read == 0 {
            break;
        }
        length += read as u64;
        digest.update(&chunk[..read]);
    }
    if length != metadata.len() {
        return Err("LOCAL_RUNTIME_UNAVAILABLE");
    }
    Ok(UpdaterRuntime {
        platform: match std::env::consts::ARCH {
            "x86_64" => "linux-x86_64",
            "aarch64" => "linux-aarch64",
            _ => "UNSUPPORTED",
        }
        .into(),
        kernel_version: kernel.trim().into(),
        current_release_id: None,
        binary_sha256: digest
            .finish()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        protocol_version: 1,
        self_update: "UNSUPPORTED_INSTALLATION".into(),
        local_phase: "IDLE".into(),
        mode: "MANUAL".into(),
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
        build_origin: "UNKNOWN".into(),
    })
}

fn retryable_control_error(code: &str) -> bool {
    matches!(code, "NETWORK_OR_TLS_ERROR" | "REMOTE_REQUEST_REJECTED")
}

struct ConfigurationReport {
    desired: AgentConfiguration,
    sequence: Option<u64>,
    failure: Option<ConfigurationFailure>,
    acknowledged: bool,
    retry_apply_at: Instant,
}

struct InstallHealth {
    context: HealthContext,
    tracker: HealthTracker,
    store: HealthConfirmationStore,
}

impl InstallHealth {
    fn open(files: &ServiceFiles, identity: &IdentityStore, epoch: &str) -> Option<Self> {
        let directory = files.health.as_ref()?;
        let context = HealthContext::new(
            files.target.clone(),
            identity.binding()?.clone(),
            identity.operation_id(),
            epoch,
        )
        .ok()?;
        let tracker = HealthTracker::new(context.clone()).ok()?;
        let store = HealthConfirmationStore::open(directory.try_clone().ok()?).ok()?;
        Some(Self {
            context,
            tracker,
            store,
        })
    }
}

struct RunningService<'a> {
    files: &'a ServiceFiles,
    client: ProtocolClient,
    identity: IdentityStore,
    buffer: Option<SharedBuffer>,
    collector: HostCollector,
    heartbeat: Heartbeat,
    identity_confirmed: bool,
    heartbeat_confirmed: bool,
    next_identity: Instant,
    next_heartbeat: Instant,
    next_configuration: Instant,
    next_sample: Instant,
    last_sample_ns: Option<u64>,
    report: Option<ConfigurationReport>,
    last_sequence: u64,
    pending_applied: Option<(String, u64)>,
    acknowledged_effective: Option<String>,
    next_upload: Instant,
    upload_backoff: Duration,
    ssh_reader: SshSourceReader,
    ssh_sender: SecurityEventSender,
    next_ssh_read: Instant,
    next_ssh_upload: Instant,
    install_health: Option<InstallHealth>,
}

fn run_service(
    files: &ServiceFiles,
    control: Option<&File>,
    stop: &AtomicBool,
    control_interval: Duration,
    request_timeout: Duration,
) -> Result<Exit> {
    let identity = IdentityStore::open(&files.identity, &files.target)?;
    if identity.status() != Status::Bound {
        return Err("IDENTITY_NOT_CONFIRMED");
    }
    let startup = control
        .map(|directory| read_startup_state(directory, &identity, true))
        .transpose()?
        .unwrap_or(StartupState::Legacy);
    if files.startup_window_required && startup == StartupState::Legacy {
        return Err("INVALID_INSTALL_STARTUP");
    }
    if startup == StartupState::AwaitingTakeover {
        return Ok(Exit::AwaitingTakeover);
    }
    if matches!(startup, StartupState::Pending(_)) {
        RuntimeStore::preflight_first_health(&files.host, &identity)?;
    } else {
        RuntimeStore::preflight(&files.host, &identity)?;
    }
    SshQueue::preflight(&files.ssh, &identity)?;
    let client = ProtocolClient::new_for_service(
        files.target.clone(),
        files.ca.as_deref(),
        request_timeout,
    )?;
    let raw = capture()?;
    let epoch = new_collector_epoch()?;
    let heartbeat = Heartbeat {
        boot_id: raw.boot_id.clone(),
        version: env!("CARGO_PKG_VERSION").into(),
        capabilities: Capabilities {
            system: system_capability(&raw),
            processes: Capability::Unsupported,
            containers: Capability::Unsupported,
            ssh_events: Capability::Unsupported,
        },
        buffered_bytes: 0,
        discarded_samples_total: "0".into(),
        collector_epoch: epoch.clone(),
        updater: updater_facts()?,
        ssh_source_diagnostics: None,
    };
    if stop.load(Ordering::Relaxed) {
        return Ok(Exit::Stopped);
    }
    let now = Instant::now();
    let install_health = match startup {
        StartupState::Legacy => InstallHealth::open(files, &identity, &epoch),
        StartupState::Pending(_) => {
            Some(InstallHealth::open(files, &identity, &epoch).ok_or("INVALID_INSTALL_STARTUP")?)
        }
        StartupState::Settled | StartupState::AwaitingTakeover => None,
    };
    let mut service = RunningService {
        files,
        client,
        identity,
        buffer: None,
        collector: HostCollector::new(&epoch)?,
        heartbeat,
        identity_confirmed: false,
        heartbeat_confirmed: false,
        next_identity: now,
        next_heartbeat: now,
        next_configuration: now,
        next_sample: now,
        last_sample_ns: None,
        report: None,
        last_sequence: 0,
        pending_applied: None,
        acknowledged_effective: None,
        next_upload: now,
        upload_backoff: RETRY_INTERVAL,
        ssh_reader: SshSourceReader::default(),
        ssh_sender: SecurityEventSender::new(),
        next_ssh_read: now,
        next_ssh_upload: now,
        install_health,
    };
    if let StartupState::Pending(window) = startup {
        let control = control.ok_or("INVALID_INSTALL_STARTUP")?;
        match service.run_first_health(control, &window, stop, control_interval, request_timeout) {
            Ok(()) => {}
            Err("SERVICE_STOP_REQUESTED") => return Ok(Exit::Stopped),
            Err(code) => return Err(code),
        }
    }
    service.buffer = match SharedBuffer::recover(files.buffer_paths(), &service.identity, &epoch) {
        Ok(buffer) => Some(buffer),
        Err("CONFIGURATION_NOT_APPLIED") => None,
        Err(code) => return Err(code),
    };
    // The bound identity, stores and outer supervisor FD outlive the worker join.
    with_delivery_dispatcher(|dispatch| service.run_loop(dispatch, stop, control_interval))?;
    Ok(Exit::Stopped)
}

impl RunningService<'_> {
    fn run_first_health(
        &mut self,
        control: &File,
        window: &StartupWindow,
        stop: &AtomicBool,
        interval: Duration,
        request_timeout: Duration,
    ) -> Result<()> {
        let epoch = &self.heartbeat.collector_epoch;
        let health = self
            .install_health
            .take()
            .ok_or("INVALID_INSTALL_STARTUP")?;
        let InstallHealth {
            context,
            mut tracker,
            store,
        } = health;
        startup_request(window, stop, request_timeout, || {
            self.client.query_identity(&mut self.identity)
        })?;
        startup_request(window, stop, request_timeout, || {
            self.client.heartbeat(&mut self.identity, &self.heartbeat)
        })?;
        tracker
            .record_heartbeat(&context)
            .map_err(|_| "FIRST_HEALTH_UNCONFIRMED")?;
        let desired = startup_request(window, stop, request_timeout, || {
            self.client.configuration(&mut self.identity)
        })?;
        {
            startup_time(window, stop)?;
            let mut runtime = RuntimeStore::open(&self.files.host, &self.identity, epoch)?;
            startup_time(window, stop)?;
            runtime.apply_first_health_configuration(&desired)?;
        }
        startup_request(window, stop, request_timeout, || {
            self.client
                .report_applied_configuration(&mut self.identity, &desired, epoch, 1)
        })?;
        tracker
            .record_applied(&context, &desired)
            .map_err(|_| "FIRST_HEALTH_UNCONFIRMED")?;
        startup_time(window, stop)?;
        let sample = self.collector.collect(capture()?)?;
        let acknowledgement = startup_request(window, stop, request_timeout, || {
            let completed = self
                .client
                .prepare_metric_upload(&self.identity, &sample)?
                .send();
            match self
                .client
                .finish_metric_upload(&mut self.identity, completed)?
            {
                MetricUploadOutcome::Acknowledged(ack) => Ok(ack),
                MetricUploadOutcome::Failed { code, .. } => Err(code),
            }
        })?;
        tracker
            .record_host_accepted(&context, &sample, &acknowledgement)
            .map_err(|_| "FIRST_HEALTH_UNCONFIRMED")?;
        startup_time(window, stop)?;
        tracker
            .persist(&store)
            .map_err(|_| "FIRST_HEALTH_UNCONFIRMED")?;

        // Keep the queue and regular sampling closed until the original
        // installer commits the terminal result for this exact identity.
        loop {
            match read_startup_state(control, &self.identity, false)? {
                StartupState::Settled => break,
                StartupState::Pending(current) if &current == window => {}
                _ => return Err("INVALID_INSTALL_STARTUP"),
            }
            std::thread::sleep(startup_time(window, stop)?.min(STOP_POLL));
        }
        if stop.load(Ordering::Relaxed) {
            return Err("SERVICE_STOP_REQUESTED");
        }

        let now = Instant::now();
        self.identity_confirmed = true;
        self.heartbeat_confirmed = true;
        self.next_heartbeat = now + interval;
        self.next_configuration = now + interval;
        self.next_sample = now
            + Duration::from_secs(u64::from(
                desired.target.configuration.sampling_interval_seconds,
            ));
        self.last_sample_ns = Some(sample.monotonic_ns);
        self.last_sequence = 1;
        self.acknowledged_effective = Some(desired.target.config_id.clone());
        self.report = Some(ConfigurationReport {
            desired,
            sequence: Some(1),
            failure: None,
            acknowledged: true,
            retry_apply_at: now,
        });
        Ok(())
    }

    fn run_loop(
        &mut self,
        dispatch: &mut DeliveryDispatcher,
        stop: &AtomicBool,
        interval: Duration,
    ) -> Result<()> {
        while !stop.load(Ordering::Relaxed) {
            self.finish_upload(dispatch)?;
            self.read_ssh()?;
            if !self.identity_confirmed && Instant::now() >= self.next_identity {
                match self.client.query_identity(&mut self.identity) {
                    Ok(_) => self.identity_confirmed = true,
                    Err(code) if retryable_control_error(code) => {}
                    Err(code) => return Err(code),
                }
                self.next_identity = Instant::now() + RETRY_INTERVAL;
                continue;
            }
            if self.identity_confirmed && Instant::now() >= self.next_heartbeat {
                self.send_heartbeat()?;
                self.next_heartbeat = Instant::now() + interval;
                continue;
            }
            if self.heartbeat_confirmed && Instant::now() >= self.next_configuration {
                self.refresh_configuration(stop)?;
                self.next_configuration = Instant::now() + interval;
                continue;
            }
            // On restart give any pending HOST envelope a chance before a new sample.
            if self.heartbeat_confirmed && dispatch.active_kind().is_none() {
                self.start_upload(dispatch, stop)?;
            }
            if !stop.load(Ordering::Relaxed) {
                self.sample()?;
            }
            let mut wake = Instant::now() + STOP_POLL;
            if !self.identity_confirmed {
                wake = wake.min(self.next_identity);
            } else {
                wake = wake.min(self.next_heartbeat);
            }
            if self.heartbeat_confirmed {
                wake = wake.min(self.next_configuration);
            }
            if self.buffer.is_some() {
                wake = wake.min(self.next_sample);
                wake = wake.min(self.next_ssh_read);
            }
            std::thread::sleep(wake.saturating_duration_since(Instant::now()));
        }
        // Dropping the dispatcher stops new work and joins a request already
        // on the wire. Its durable envelope remains if no ACK was applied.
        Ok(())
    }

    fn read_ssh(&mut self) -> Result<()> {
        let Some(buffer) = &mut self.buffer else {
            return Ok(());
        };
        if Instant::now() < self.next_ssh_read {
            return Ok(());
        }
        let now = queue_time(&self.heartbeat.boot_id)?;
        let delay =
            match self.ssh_reader.poll(buffer, &now) {
                Ok(SourceRead::More | SourceRead::Rebased) => STOP_POLL,
                Ok(
                    SourceRead::CaughtUp | SourceRead::PendingLine | SourceRead::WaitingForRotation,
                ) => SSH_POLL_INTERVAL,
                Ok(_) => RETRY_INTERVAL,
                Err(
                    "SSH_QUEUE_CLOCK_UNCERTAIN" | "SSH_QUEUE_RESOURCE_LIMIT" | "RESOURCE_LIMIT",
                ) if buffer.safely_reportable() => RETRY_INTERVAL,
                Err(code) => return Err(code),
            };
        self.next_ssh_read = Instant::now() + delay;
        Ok(())
    }

    fn send_heartbeat(&mut self) -> Result<()> {
        let raw = capture()?;
        self.heartbeat.capabilities.system = system_capability(&raw);
        if let Some(buffer) = &mut self.buffer {
            let (capability, diagnostics) = self.ssh_reader.heartbeat_report(buffer)?;
            self.heartbeat.buffered_bytes = buffer.allocated_bytes()?;
            self.heartbeat.discarded_samples_total =
                buffer.host.discarded_samples_total().to_string();
            self.heartbeat.capabilities.ssh_events = capability;
            self.heartbeat.ssh_source_diagnostics = diagnostics;
        }
        match self.client.heartbeat(&mut self.identity, &self.heartbeat) {
            Ok(_) => {
                self.heartbeat_confirmed = true;
                if let Some(health) = &mut self.install_health {
                    let _ = health.tracker.record_heartbeat(&health.context);
                }
            }
            Err(code) if retryable_control_error(code) => {}
            Err(code) => return Err(code),
        }
        Ok(())
    }

    fn refresh_configuration(&mut self, stop: &AtomicBool) -> Result<()> {
        let desired = match self.client.configuration(&mut self.identity) {
            Ok(config) => config,
            Err(code) if retryable_control_error(code) => return Ok(()),
            Err(code) => return Err(code),
        };
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        if self.report.as_ref().is_none_or(|report| {
            report.desired != desired
                || (report.failure.is_some() && Instant::now() >= report.retry_apply_at)
        }) {
            let failure = self.apply_configuration(&desired)?;
            self.report = Some(ConfigurationReport {
                desired,
                sequence: None,
                failure,
                acknowledged: false,
                retry_apply_at: Instant::now() + Duration::from_secs(60),
            });
        }
        let report = self.report.as_mut().ok_or("CONFIGURATION_REPORT_MISSING")?;
        if report.acknowledged || stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let epoch = &self.heartbeat.collector_epoch;
        let result = if let Some(reason) = report.failure {
            let host = &self
                .buffer
                .as_ref()
                .ok_or("CONFIGURATION_NOT_APPLIED")?
                .host;
            let effective = host.configuration().ok_or("CONFIGURATION_NOT_APPLIED")?;
            let id = &effective.target.config_id;
            if Some(id) != self.acknowledged_effective.as_ref() {
                // A new epoch has no manager projection. Reassert the active
                // target before FAILED, replaying its exact sequence if sent.
                let sequence = match &self.pending_applied {
                    Some((pending, sequence)) if pending == id => *sequence,
                    _ => {
                        self.last_sequence += 1;
                        self.pending_applied = Some((id.clone(), self.last_sequence));
                        self.last_sequence
                    }
                };
                match self.client.report_retained_configuration(
                    &mut self.identity,
                    host,
                    &self.files.host,
                    epoch,
                    sequence,
                ) {
                    Ok(()) => {
                        self.acknowledged_effective = Some(id.clone());
                        self.pending_applied = None;
                    }
                    Err(code) if retryable_control_error(code) => return Ok(()),
                    Err(code) => return Err(code),
                }
                if stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
            }
            let sequence = *report.sequence.get_or_insert_with(|| {
                self.last_sequence += 1;
                self.last_sequence
            });
            self.client.report_configuration_failure(
                &mut self.identity,
                &report.desired,
                epoch,
                sequence,
                Some(effective),
                reason,
            )
        } else {
            let sequence = *report.sequence.get_or_insert_with(|| {
                self.last_sequence += 1;
                self.last_sequence
            });
            self.pending_applied = Some((report.desired.target.config_id.clone(), sequence));
            self.client.report_applied_configuration(
                &mut self.identity,
                &report.desired,
                epoch,
                sequence,
            )
        };
        match result {
            Ok(()) => {
                report.acknowledged = true;
                if report.failure.is_none() {
                    self.acknowledged_effective = Some(report.desired.target.config_id.clone());
                    self.pending_applied = None;
                    if let Some(health) = &mut self.install_health {
                        let _ = health
                            .tracker
                            .record_applied(&health.context, &report.desired);
                    }
                }
            }
            Err(code) if retryable_control_error(code) => {}
            Err(code) => return Err(code),
        }
        Ok(())
    }

    fn apply_configuration(
        &mut self,
        desired: &AgentConfiguration,
    ) -> Result<Option<ConfigurationFailure>> {
        if let Some(buffer) = &mut self.buffer {
            if buffer.host.configuration() == Some(desired) {
                return Ok(None);
            }
            if let Err(code) = buffer.apply_configuration(desired) {
                return ConfigurationFailure::from_apply_error(code)
                    .filter(|_| buffer.safely_reportable())
                    .map(Some)
                    .ok_or(code);
            }
        } else {
            let raw = capture()?;
            let time = QueueTime {
                boot_id: raw.boot_id,
                monotonic_ns: raw.cpu_observed.monotonic_ns,
                unix_seconds: i64::try_from(raw.cpu_observed.observed_unix_ns / 1_000_000_000)
                    .map_err(|_| "LOCAL_RUNTIME_UNAVAILABLE")?,
            };
            self.buffer = Some(SharedBuffer::open(
                self.files.buffer_paths(),
                &self.identity,
                &self.heartbeat.collector_epoch,
                desired,
                &time,
            )?);
        }
        self.collector.interrupt();
        self.last_sample_ns = None;
        self.next_sample = Instant::now();
        Ok(None)
    }

    fn sample(&mut self) -> Result<()> {
        let Some(buffer) = self
            .buffer
            .as_mut()
            .filter(|_| Instant::now() >= self.next_sample)
        else {
            return Ok(());
        };
        let settings = &buffer
            .host
            .configuration()
            .ok_or("CONFIGURATION_NOT_APPLIED")?
            .target
            .configuration;
        let interval = Duration::from_secs(u64::from(settings.sampling_interval_seconds));
        let raw = capture()?;
        let ns = raw.cpu_observed.monotonic_ns;
        if self.last_sample_ns.is_some_and(|last| {
            ns.saturating_sub(last) > interval.as_nanos() as u64 + 1_000_000_000
        }) {
            self.collector.interrupt();
        }
        self.last_sample_ns = Some(ns);
        let admission = self
            .collector
            .collect(raw)
            .and_then(|sample| buffer.host.admit(sample));
        match admission {
            Ok(()) => {}
            Err("RESOURCE_LIMIT") if buffer.safely_reportable() => self.collector.interrupt(),
            Err(code) => return Err(code),
        }
        self.next_sample += interval;
        if self.next_sample <= Instant::now() {
            self.collector.interrupt();
            self.next_sample = Instant::now() + interval;
        }
        Ok(())
    }

    fn start_upload(&mut self, dispatch: &mut DeliveryDispatcher, stop: &AtomicBool) -> Result<()> {
        let Some(buffer) = &mut self.buffer else {
            return Ok(());
        };
        let at = Instant::now();
        for kind in dispatch.preferred_order() {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            match kind {
                DeliveryKind::Host
                    if at >= self.next_upload && buffer.host.has_pending_sample() =>
                {
                    let time = queue_time(&self.heartbeat.boot_id)?;
                    if let Some(sample) = buffer.host.begin(&time.boot_id, time.monotonic_ns)? {
                        if !stop.load(Ordering::Relaxed) {
                            dispatch.submit_host(&self.client, &self.identity, sample)?;
                        }
                        return Ok(());
                    }
                }
                DeliveryKind::Ssh if at >= self.next_ssh_upload => {
                    self.next_ssh_upload = at + SSH_POLL_INTERVAL;
                    if buffer.ssh.queued_payload_bytes()? == 0 {
                        continue;
                    }
                    let time = queue_time(&self.heartbeat.boot_id)?;
                    let prepared = match self.ssh_sender.prepare(
                        &self.client,
                        &self.identity,
                        &mut buffer.ssh,
                        &time,
                        at,
                    ) {
                        Ok(value) => value,
                        Err(
                            "SSH_QUEUE_CLOCK_UNCERTAIN"
                            | "SSH_QUEUE_RESOURCE_LIMIT"
                            | "RESOURCE_LIMIT",
                        ) if buffer.safely_reportable() => {
                            self.next_ssh_upload = at + RETRY_INTERVAL;
                            continue;
                        }
                        Err(code) => return Err(code),
                    };
                    match prepared {
                        SecurityEventPreparation::Ready(request) => {
                            if stop.load(Ordering::Relaxed) {
                                self.ssh_sender.cancel(&mut buffer.ssh, request)?;
                            } else {
                                dispatch.submit_ssh(request)?;
                            }
                            return Ok(());
                        }
                        SecurityEventPreparation::Progress(SecurityEventStep::Stopped { code }) => {
                            return Err(code);
                        }
                        SecurityEventPreparation::Progress(_) => {}
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn finish_upload(&mut self, dispatch: &mut DeliveryDispatcher) -> Result<()> {
        let Some(completion) = dispatch.take_completion()? else {
            return Ok(());
        };
        let buffer = self.buffer.as_mut().ok_or("CONFIGURATION_NOT_APPLIED")?;
        let (sample_id, finished_at, completion) = match completion {
            DeliveryCompletion::Host {
                sample_id,
                finished_at,
                completion,
            } => (sample_id, finished_at, completion),
            DeliveryCompletion::Ssh {
                finished_at,
                completion,
            } => {
                let step = self.ssh_sender.complete(
                    &self.client,
                    &mut self.identity,
                    &mut buffer.ssh,
                    completion,
                    finished_at,
                )?;
                return match step {
                    SecurityEventStep::Stopped { code } => Err(code),
                    _ => Ok(()),
                };
            }
        };
        let host = &mut buffer.host;
        match self
            .client
            .finish_metric_upload(&mut self.identity, completion)?
        {
            MetricUploadOutcome::Acknowledged(ack) => {
                let health_confirmed = self.install_health.as_mut().is_some_and(|health| {
                    host.active_upload_sample(&sample_id).is_some_and(|sample| {
                        health
                            .tracker
                            .record_host_accepted(&health.context, sample, &ack)
                            .is_ok()
                    })
                });
                host.acknowledge(&sample_id)?;
                if health_confirmed
                    && self
                        .install_health
                        .as_ref()
                        .is_some_and(|health| health.tracker.persist(&health.store).is_ok())
                {
                    self.install_health = None;
                }
                self.next_upload = Instant::now();
                self.upload_backoff = RETRY_INTERVAL;
            }
            MetricUploadOutcome::Failed {
                code,
                retry_after,
                terminal,
            } => {
                host.attempt_finished(&sample_id)?;
                if terminal {
                    return Err(code);
                }
                let mut random = [0; 2];
                let jitter = getrandom::fill(&mut random)
                    .map(|()| Duration::from_millis(u64::from(u16::from_ne_bytes(random) % 251)))
                    .unwrap_or_default();
                self.next_upload = finished_at
                    .checked_add(
                        self.upload_backoff
                            .max(retry_after.unwrap_or_default())
                            .saturating_add(jitter),
                    )
                    .ok_or("INVALID_RETRY_AFTER")?;
                self.upload_backoff = (self.upload_backoff * 2).min(CONTROL_INTERVAL);
            }
        }
        Ok(())
    }
}

fn startup_time(window: &StartupWindow, stop: &AtomicBool) -> Result<Duration> {
    if stop.load(Ordering::Relaxed) {
        return Err("SERVICE_STOP_REQUESTED");
    }
    window.remaining()
}

fn startup_request<T>(
    window: &StartupWindow,
    stop: &AtomicBool,
    timeout: Duration,
    mut request: impl FnMut() -> Result<T>,
) -> Result<T> {
    loop {
        if startup_time(window, stop)? < timeout {
            return Err("INSTALL_STARTUP_EXPIRED");
        }
        match request() {
            Ok(result) => {
                startup_time(window, stop)?;
                return Ok(result);
            }
            Err(code) if retryable_control_error(code) => {
                let retry_at = Instant::now() + RETRY_INTERVAL;
                while Instant::now() < retry_at {
                    std::thread::sleep(startup_time(window, stop)?.min(STOP_POLL));
                }
            }
            Err(code) => return Err(code),
        }
    }
}
