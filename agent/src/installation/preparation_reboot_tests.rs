//! Two boot stages in a disposable Linux VM backed by one ext4 disk.

use super::{
    tests::{FixtureProcess, fixture_now, spawn_registration_worker, wait_registration_pending},
    *,
};
use crate::{
    identity::Binding,
    installation::{
        InstallPlanInput, InstallPlanStore, InstallUpdateMode, lookup_install_operation,
    },
    release::{github::ReleaseReadOptions, github_tests::Fixture, manifest::GithubReleaseId},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions, Permissions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::{Command, Stdio},
};

const VM_MARKER: &str = "/.nodomi-isolated-reboot-vm";
const STATE: &str = "/accept-state";
const CONTROL: &str = "/var/lib/nodomi-agent-control";
const ARCHIVE: &str = "/first-install-arm64.tar.gz";
const MANAGER_PORT: &str = "19443";
const ORIGIN: &str = "https://localhost:19443";
pub(super) const DEPLOYMENT: &str = "6dc0a032-3f68-42ae-9dd9-14dc1a41ab01";
const CA: &[u8] = include_bytes!("../../tests/fixtures/tls/ca.pem");

pub(super) fn inside_reboot_fixture() -> bool {
    std::env::var("NODOMI_INSTALL_REBOOT_FIXTURE").as_deref() == Ok("isolated")
        && fs::read(VM_MARKER).is_ok_and(|contents| contents == b"nodomi disposable ext4 fixture\n")
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceStartCheckpoint {
    control: Checkpoint,
    identity: FixtureIdentity,
    held_epoch: String,
    program_inode: u64,
    service_inode: u64,
    #[serde(default)]
    enabled_inode: Option<u64>,
    supervisor_lock_inode: u64,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureIdentity {
    operation_id: String,
    binding: Binding,
}

impl FixtureIdentity {
    fn read() -> Self {
        let identity = File::open("/var/lib/nodomi-agent/identity/identity.json").unwrap();
        serde_json::from_reader(identity).unwrap()
    }
}

#[test]
#[ignore = "requires two actual Linux VM boots on the dedicated fixture disk"]
fn service_start_recovers_after_vm_reboot() {
    service_start_recovers(ServiceManagerObservation::Systemd);
}

#[test]
#[ignore = "requires two actual Alpine Linux VM boots on the dedicated fixture disk"]
fn openrc_service_start_recovers_after_vm_reboot() {
    service_start_recovers(ServiceManagerObservation::OpenRc);
}

fn service_start_recovers(manager: ServiceManagerObservation) {
    assert!(inside_reboot_fixture());
    assert_eq!(effective_uid(), 0);
    let host = inspect_host();
    assert_eq!(host.service_manager, manager);
    let (service_path, distribution, distribution_version) = match manager {
        ServiceManagerObservation::Systemd => {
            ("/etc/systemd/system/nodomi-agent.service", "debian", "12")
        }
        ServiceManagerObservation::OpenRc => ("/etc/init.d/nodomi-agent", "alpine", "3.23"),
        _ => unreachable!("fixture requires a supported service manager"),
    };
    let enabled_path = "/etc/runlevels/default/nodomi-agent";
    let requirements = fixture_requirements(&host).unwrap();
    let stage = std::env::var("NODOMI_INSTALL_REBOOT_STAGE").unwrap();
    let state = Path::new(STATE);
    let plans = state.join("plans");
    let management = state.join("management");
    let observations = management.join("service-observations.json");
    let checkpoint_path = state.join("service-start-checkpoint.json");
    let root = super::super::layout::open_root().unwrap();
    let scenario = match stage.as_str() {
        "before" => {
            assert!(!checkpoint_path.exists());
            check_layout(&root, 0, LayoutEntry::Missing).unwrap();
            for directory in [&plans, &management] {
                fs::create_dir(directory).unwrap();
                fs::set_permissions(directory, Permissions::from_mode(0o700)).unwrap();
            }
            "reboot-service-start-before"
        }
        "after" => "reboot-service-start-after",
        _ => panic!("unsupported VM stage"),
    };
    let _management = start_management_scenario(&management, scenario);
    let release_fixture =
        Fixture::with_artifact(requirements.platform, &fs::read(ARCHIVE).unwrap());
    let mut client = release_fixture.client(ReleaseReadOptions::default());
    let archive = File::open(ARCHIVE).unwrap();
    let store = InstallPlanStore::open(File::open(&plans).unwrap()).unwrap();
    let current_boot = boot_id().unwrap();

    if stage == "before" {
        let release = client
            .load_exact(GithubReleaseId::new(123).unwrap(), requirements)
            .unwrap();
        let plan = InstallPlan::inspect_formal_and_create(
            InstallPlanInput {
                management_origin: ORIGIN,
                expected_server_id: "server-1",
                release_id: release.target().release_id.as_str(),
                update_mode: Some(InstallUpdateMode::Manual),
            },
            &release,
            Some(CA),
            archive.try_clone().unwrap(),
        )
        .unwrap();
        store.save(&plan).unwrap();
        let intent =
            AuthorizedPreparationIntent::for_fixture(plan, "ad97d508-75c2-4453-8542-845a08613769")
                .unwrap();
        let prepared = prepare_control(&root, intent, fixture_now).unwrap();
        let domain = ExecutionDomain::open_existing(Path::new(CONTROL), 0).unwrap();
        assert!(domain.matches_prepared(&prepared.directory, prepared.lock_id));
        let control = prepared.directory.try_clone().unwrap();
        let original = prepared.record.clone();
        let lock_inode = prepared.lock.metadata().unwrap().ino();
        let enrollment = fixture_service_enrollment(state);
        let (send, receive) = mpsc::channel();
        let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
            let local = super::super::target_admission::inspect_target_admission(
                &prepared.plan,
                &host,
                manager,
                Some(CA),
            )
            .unwrap();
            let proof = local.prove_remote(&enrollment, DEPLOYMENT).unwrap();
            assert_eq!(proof.binding_revision(), 1);
            let published = prepared
                .publish_under_lease(&root, manager, &mut client, &archive, fixture_now)
                .unwrap();
            let metadata = serde_json::from_value(serde_json::json!({
                "version":"0.1.0", "architecture":"ARM64", "distribution":distribution,
                "distributionVersion":distribution_version, "hostname":"fixture-service-reboot",
                "capabilities":{"system":"AVAILABLE","processes":"UNSUPPORTED",
                                "containers":"UNSUPPORTED","sshEvents":"UNSUPPORTED"}
            }))
            .unwrap();
            let result = prepared.finish_isolated_install(
                &root,
                manager,
                published,
                IsolatedEnrollment {
                    enrollment,
                    metadata: &metadata,
                    ca: CA,
                    target_proof: Some(proof),
                },
                fixture_now,
            );
            let _ = send.send(result);
            Ok(())
        })];
        let _worker = domain.start(&mut pending).unwrap();
        let deadline = Instant::now() + Duration::from_secs(25);
        let (record, held_epoch) = loop {
            assert!(
                matches!(receive.try_recv(), Err(mpsc::TryRecvError::Empty)),
                "original startup worker exited before the cut"
            );
            let record = read_record(&control).unwrap();
            let events = read_events(&observations);
            assert_eq!(
                count_events(&events, "metric"),
                0,
                "first boot received a metric ACK"
            );
            if record
                .business()
                .is_some_and(|business| business.phase() == BusinessPhase::Verifying)
                && let Some(held) = events.iter().find(|row| row["kind"] == "held-metric")
            {
                let sample = &held["body"]["samples"][0];
                assert_eq!(sample["bootId"], current_boot);
                let epoch = sample["collectorEpoch"].as_str().unwrap().to_owned();
                assert_eq!(count_events(&events, "registration-attempt"), 1);
                assert_eq!(count_events(&events, "registration"), 1);
                assert_eq!(count_events(&events, "enrollment-target"), 1);
                break (record, epoch);
            }
            assert!(
                Instant::now() < deadline,
                "missing durable startup checkpoint and withheld HOST ACK"
            );
            std::thread::sleep(Duration::from_millis(25));
        };
        assert_eq!(record.claim(), original.claim());
        let window = record.business().unwrap().startup_window().unwrap();
        assert!(window.remaining().is_ok());
        assert_eq!(
            serde_json::to_value(window).unwrap()["bootId"],
            current_boot
        );
        let mut competing: Vec<WorkUnit> = vec![Box::new(|| {
            panic!("original startup worker still owns the lease")
        })];
        assert!(matches!(
            domain.start(&mut competing),
            Err(ExecutionError::Busy)
        ));
        assert!(!Path::new("/var/lib/nodomi-agent/health/health-confirmation.json").exists());
        let claim = record.claim();
        let checkpoint = ServiceStartCheckpoint {
            control: Checkpoint {
                plan_id: claim.plan_id.clone(),
                operation_id: claim.operation_id.clone(),
                target_id: claim.installation_id.clone(),
                domain_id: record.control_domain_id().to_owned(),
                lock_inode,
                boot_id: current_boot.clone(),
            },
            identity: FixtureIdentity::read(),
            held_epoch,
            program_inode: fs::symlink_metadata("/opt/nodomi-agent").unwrap().ino(),
            service_inode: fs::symlink_metadata(service_path).unwrap().ino(),
            enabled_inode: (manager == ServiceManagerObservation::OpenRc)
                .then(|| fs::symlink_metadata(enabled_path).unwrap().ino()),
            supervisor_lock_inode: fs::symlink_metadata(format!("{CONTROL}/supervisor.lock"))
                .unwrap()
                .ino(),
        };
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(checkpoint_path)
            .unwrap();
        file.set_permissions(Permissions::from_mode(0o600)).unwrap();
        serde_json::to_writer(&mut file, &checkpoint).unwrap();
        file.sync_all().unwrap();
        File::open(state).unwrap().sync_all().unwrap();
        // SAFETY: flush the guest's persistent fixture events before its host cuts power.
        unsafe { libc::sync() };
        println!("NODOMI_VM_REBOOT_READY {current_boot}");
        thread_wait_for_power_cut();
        unreachable!("the host must stop the guest before the held request receives any ACK");
    }

    let checkpoint: ServiceStartCheckpoint =
        serde_json::from_slice(&fs::read(checkpoint_path).unwrap()).unwrap();
    assert_ne!(current_boot, checkpoint.control.boot_id);
    let plan = store.load(&checkpoint.control.plan_id).unwrap();
    let prepared =
        PreparedControl::open_fixture_control(&root, plan, &checkpoint.control.operation_id)
            .unwrap();
    assert_eq!(
        prepared.record.control_domain_id(),
        checkpoint.control.domain_id
    );
    assert_eq!(
        prepared.lock.metadata().unwrap().ino(),
        checkpoint.control.lock_inode
    );
    let business = prepared.record.business().unwrap();
    assert_eq!(business.phase(), BusinessPhase::Verifying);
    let original_window = business.startup_window().unwrap();
    assert_eq!(original_window.remaining(), Err("INSTALL_STARTUP_EXPIRED"));
    assert_eq!(
        serde_json::to_value(original_window).unwrap()["bootId"],
        checkpoint.control.boot_id
    );
    let status = lookup_install_operation(
        &checkpoint.control.operation_id,
        &checkpoint.control.target_id,
    )
    .unwrap();
    assert_eq!(status.exit_code(), 6);
    assert_eq!(read_record(&prepared.directory).unwrap(), prepared.record);
    assert_eq!(FixtureIdentity::read(), checkpoint.identity);
    assert_eq!(count_events(&read_events(&observations), "metric"), 0);
    if manager == ServiceManagerObservation::OpenRc {
        assert_eq!(
            Some(fs::symlink_metadata(enabled_path).unwrap().ino()),
            checkpoint.enabled_inode
        );
        let native_failure = Path::new("/run/openrc/failed/nodomi-agent");
        let deadline = Instant::now() + Duration::from_secs(15);
        while fs::symlink_metadata(native_failure).is_err() {
            assert!(
                Instant::now() < deadline,
                "OpenRC did not autoactivate and exhaust the stale startup window"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        println!("NODOMI_VM_OPENRC_AUTOACTIVATION_DRAINED");
    }

    let domain = ExecutionDomain::open_existing(Path::new(CONTROL), 0).unwrap();
    assert!(domain.matches_prepared(&prepared.directory, prepared.lock_id));
    let control = prepared.directory.try_clone().unwrap();
    let (send, receive) = mpsc::channel();
    let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
        let result = prepared.recover_service_after_fixture_reboot(
            &root,
            manager,
            &mut client,
            &archive,
            CA,
            fixture_now,
        );
        let _ = send.send(result);
        Ok(())
    })];
    assert_eq!(
        domain.start(&mut pending).unwrap().join().termination,
        Termination::Completed
    );
    let result = receive.recv().unwrap().unwrap();
    assert_eq!(result.exit_code(), 0);
    assert_eq!(result.operation_id(), checkpoint.control.operation_id);
    assert_eq!(
        lookup_install_operation(
            &checkpoint.control.operation_id,
            &checkpoint.control.target_id
        ),
        Ok(result)
    );
    let completed = read_record(&control).unwrap();
    assert_eq!(completed.control_domain_id(), checkpoint.control.domain_id);
    let window = completed.business().unwrap().startup_window().unwrap();
    assert_eq!(
        serde_json::to_value(window).unwrap()["bootId"],
        current_boot
    );
    assert_eq!(FixtureIdentity::read(), checkpoint.identity);
    assert_eq!(
        fs::symlink_metadata("/opt/nodomi-agent").unwrap().ino(),
        checkpoint.program_inode
    );
    assert_eq!(
        fs::symlink_metadata(service_path).unwrap().ino(),
        checkpoint.service_inode
    );
    if manager == ServiceManagerObservation::OpenRc {
        assert_eq!(
            Some(fs::symlink_metadata(enabled_path).unwrap().ino()),
            checkpoint.enabled_inode
        );
    }
    assert_eq!(
        fs::symlink_metadata(format!("{CONTROL}/supervisor.lock"))
            .unwrap()
            .ino(),
        checkpoint.supervisor_lock_inode
    );
    let events = read_events(&observations);
    assert_eq!(count_events(&events, "enrollment-target"), 1);
    assert_eq!(count_events(&events, "registration-attempt"), 1);
    assert_eq!(count_events(&events, "registration"), 1);
    assert!(count_events(&events, "held-metric") >= 1);
    assert!(
        events
            .iter()
            .filter(|row| row["kind"] == "held-metric")
            .all(|row| { row["body"]["samples"][0]["bootId"] == checkpoint.control.boot_id })
    );
    let accepted =
        &events.iter().find(|row| row["kind"] == "metric").unwrap()["body"]["samples"][0];
    assert_eq!(accepted["bootId"], current_boot);
    let accepted_epoch = accepted["collectorEpoch"].as_str().unwrap();
    assert_ne!(accepted_epoch, checkpoint.held_epoch);
    let mut second_boot_heartbeats = events
        .iter()
        .filter(|row| row["kind"] == "heartbeat" && row["body"]["bootId"] == current_boot);
    assert!(
        second_boot_heartbeats
            .next()
            .is_some_and(|row| row["body"]["collectorEpoch"] == accepted_epoch)
    );
    assert!(second_boot_heartbeats.all(|row| row["body"]["collectorEpoch"] == accepted_epoch));
    for kind in ["heartbeat", "receipt"] {
        assert!(
            events
                .iter()
                .any(|row| row["kind"] == kind && row["body"]["collectorEpoch"] == accepted_epoch)
        );
    }
    match manager {
        ServiceManagerObservation::Systemd => stop_vm_service(),
        ServiceManagerObservation::OpenRc => stop_vm_openrc_service(),
        _ => unreachable!("fixture requires a supported service manager"),
    }
    println!(
        "NODOMI_VM_RECOVERY_SUCCEEDED {current_boot} registration_posts=1 phase=SERVICE_START"
    );
}

fn fixture_service_enrollment(state: &Path) -> Enrollment {
    let token = state.join("service-start-enrollment");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&token)
        .unwrap();
    file.set_permissions(Permissions::from_mode(0o400)).unwrap();
    write!(file, "ndme_{}", "A".repeat(43)).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let enrollment = Enrollment::from_private_file(&token).unwrap();
    fs::remove_file(token).unwrap();
    enrollment
}

fn read_events(path: &Path) -> Vec<serde_json::Value> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap(),
        Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("fixture observations unavailable: {error}"),
    }
}

fn count_events(events: &[serde_json::Value], kind: &str) -> usize {
    events.iter().filter(|row| row["kind"] == kind).count()
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Checkpoint {
    plan_id: String,
    operation_id: String,
    target_id: String,
    domain_id: String,
    lock_inode: u64,
    boot_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationCheckpoint {
    control: Checkpoint,
    program_inode: u64,
    service_inode: u64,
    receipt_inode: u64,
}

#[test]
#[ignore = "requires two actual Linux VM boots on the dedicated fixture disk"]
fn publication_recovers_after_vm_reboot() {
    assert!(inside_reboot_fixture());
    assert_eq!(effective_uid(), 0);
    let host = inspect_host();
    let manager = ServiceManagerObservation::Systemd;
    assert_eq!(host.service_manager, manager);
    let requirements = fixture_requirements(&host).unwrap();
    let stage = std::env::var("NODOMI_INSTALL_REBOOT_STAGE").unwrap();
    let state = Path::new(STATE);
    let plans = state.join("plans");
    let management = state.join("management");
    let checkpoint_path = state.join("publication-checkpoint.json");
    let root = super::super::layout::open_root().unwrap();
    if stage == "before" {
        assert!(!checkpoint_path.exists());
        check_layout(&root, 0, LayoutEntry::Missing).unwrap();
        for directory in [&plans, &management] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, Permissions::from_mode(0o700)).unwrap();
        }
    }
    let _management = start_management(&management);
    let release_fixture =
        Fixture::with_artifact(requirements.platform, &fs::read(ARCHIVE).unwrap());
    let mut client = release_fixture.client(ReleaseReadOptions::default());
    let archive = File::open(ARCHIVE).unwrap();
    let store = InstallPlanStore::open(File::open(&plans).unwrap()).unwrap();
    if stage == "before" {
        let release = client
            .load_exact(GithubReleaseId::new(123).unwrap(), requirements)
            .unwrap();
        let plan = InstallPlan::inspect_formal_and_create(
            InstallPlanInput {
                management_origin: ORIGIN,
                expected_server_id: "server-1",
                release_id: release.target().release_id.as_str(),
                update_mode: Some(InstallUpdateMode::Manual),
            },
            &release,
            Some(CA),
            archive.try_clone().unwrap(),
        )
        .unwrap();
        store.save(&plan).unwrap();
        let intent =
            AuthorizedPreparationIntent::for_fixture(plan, "cc97d508-75c2-4453-8542-845a08613769")
                .unwrap();
        let prepared = prepare_control(&root, intent, fixture_now).unwrap();
        let domain = ExecutionDomain::open_existing(Path::new(CONTROL), 0).unwrap();
        assert!(domain.matches_prepared(&prepared.directory, prepared.lock_id));
        let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
            let result = prepared.publish_under_lease_with_hook(
                &root,
                manager,
                &mut client,
                &archive,
                fixture_now,
                || {
                    let record = read_record(&prepared.directory).unwrap();
                    assert_eq!(
                        record.business().unwrap().phase(),
                        BusinessPhase::LocalPublicationPossible
                    );
                    assert!(
                        record
                            .business()
                            .unwrap()
                            .pending_registration_id()
                            .is_none()
                    );
                    let claim = record.claim();
                    let prior_boot = boot_id().unwrap();
                    let stage_service = format!(
                        "/etc/systemd/system/.nodomi-install-{}.service",
                        claim.operation_id
                    );
                    let checkpoint = PublicationCheckpoint {
                        control: Checkpoint {
                            plan_id: claim.plan_id.clone(),
                            operation_id: claim.operation_id.clone(),
                            target_id: claim.installation_id.clone(),
                            domain_id: record.control_domain_id().to_owned(),
                            lock_inode: prepared.lock.metadata().unwrap().ino(),
                            boot_id: prior_boot.clone(),
                        },
                        program_inode: fs::symlink_metadata("/opt/nodomi-agent").unwrap().ino(),
                        service_inode: fs::symlink_metadata(stage_service).unwrap().ino(),
                        receipt_inode: fs::symlink_metadata(format!("{CONTROL}/publication.json"))
                            .unwrap()
                            .ino(),
                    };
                    assert!(!Path::new("/etc/systemd/system/nodomi-agent.service").exists());
                    assert!(!Path::new("/var/lib/nodomi-agent").exists());
                    let mut file = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(checkpoint_path)
                        .unwrap();
                    file.set_permissions(Permissions::from_mode(0o600)).unwrap();
                    serde_json::to_writer(&mut file, &checkpoint).unwrap();
                    file.sync_all().unwrap();
                    File::open(state).unwrap().sync_all().unwrap();
                    println!("NODOMI_VM_REBOOT_READY {prior_boot}");
                    thread_wait_for_power_cut();
                    unreachable!(
                        "the host harness must stop the VM while the original worker owns the lease"
                    );
                },
            );
            assert!(
                result.is_ok(),
                "publication fixture failed before its reboot checkpoint"
            );
            Ok(())
        })];
        let outcome = domain.start(&mut pending).unwrap().join();
        panic!("the first publication boot unexpectedly returned {outcome:?}");
    }

    assert_eq!(stage, "after");
    let checkpoint: PublicationCheckpoint =
        serde_json::from_slice(&fs::read(checkpoint_path).unwrap()).unwrap();
    let current_boot = boot_id().unwrap();
    assert_ne!(current_boot, checkpoint.control.boot_id);
    let plan = store.load(&checkpoint.control.plan_id).unwrap();
    let prepared =
        PreparedControl::open_fixture_control(&root, plan, &checkpoint.control.operation_id)
            .unwrap();
    assert_eq!(
        prepared.record.control_domain_id(),
        checkpoint.control.domain_id
    );
    assert_eq!(
        prepared.lock.metadata().unwrap().ino(),
        checkpoint.control.lock_inode
    );
    assert_eq!(
        prepared.record.business().unwrap().phase(),
        BusinessPhase::LocalPublicationPossible
    );
    assert_eq!(
        lookup_install_operation(
            &checkpoint.control.operation_id,
            &checkpoint.control.target_id
        )
        .unwrap()
        .exit_code(),
        6
    );
    let domain = ExecutionDomain::open_existing(Path::new(CONTROL), 0).unwrap();
    assert!(domain.matches_prepared(&prepared.directory, prepared.lock_id));
    let (send, receive) = mpsc::channel();
    let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
        let result = prepared
            .recover_publication_after_fixture_reboot(
                &root,
                manager,
                &mut client,
                &archive,
                fixture_now,
            )
            .map(|published| published.journal.phase());
        let _ = send.send(result);
        Ok(())
    })];
    assert_eq!(
        domain.start(&mut pending).unwrap().join().termination,
        Termination::Completed
    );
    assert_eq!(receive.recv().unwrap(), Ok(BusinessPhase::LocalPublished));
    assert_eq!(
        fs::symlink_metadata("/opt/nodomi-agent").unwrap().ino(),
        checkpoint.program_inode
    );
    assert_eq!(
        fs::symlink_metadata("/etc/systemd/system/nodomi-agent.service")
            .unwrap()
            .ino(),
        checkpoint.service_inode
    );
    assert_eq!(
        fs::symlink_metadata(format!("{CONTROL}/publication.json"))
            .unwrap()
            .ino(),
        checkpoint.receipt_inode
    );
    assert!(!Path::new("/var/lib/nodomi-agent").exists());
    assert!(!Path::new("/var/lib/nodomi-agent-control/supervisor.lock").exists());
    assert!(!management.join("service-observations.json").exists());
    assert!(
        !Path::new("/etc/systemd/system/multi-user.target.wants/nodomi-agent.service").exists()
    );
    println!(
        "NODOMI_VM_RECOVERY_SUCCEEDED {current_boot} registration_posts=0 phase=LOCAL_PUBLISHED"
    );
}

#[test]
#[ignore = "requires two actual Linux VM boots on the dedicated fixture disk"]
fn registration_recovers_after_vm_reboot() {
    assert!(inside_reboot_fixture());
    assert_eq!(effective_uid(), 0);
    let host = inspect_host();
    assert_eq!(host.service_manager, ServiceManagerObservation::Systemd);
    let requirements = fixture_requirements(&host).unwrap();
    let stage = std::env::var("NODOMI_INSTALL_REBOOT_STAGE").unwrap();
    let state = Path::new(STATE);
    let management_dir = state.join("management");
    let plans = state.join("plans");
    let checkpoint_path = state.join("checkpoint.json");
    let root = super::super::layout::open_root().unwrap();
    if stage == "before" {
        assert!(!checkpoint_path.exists());
        check_layout(&root, 0, LayoutEntry::Missing).unwrap();
        for directory in [&management_dir, &plans] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, Permissions::from_mode(0o700)).unwrap();
        }
    }
    let _management = start_management(&management_dir);
    let release_fixture =
        Fixture::with_artifact(requirements.platform, &fs::read(ARCHIVE).unwrap());
    let mut client = release_fixture.client(ReleaseReadOptions::default());
    let archive = File::open(ARCHIVE).unwrap();
    let store = InstallPlanStore::open(File::open(&plans).unwrap()).unwrap();
    if stage == "before" {
        let release = client
            .load_exact(GithubReleaseId::new(123).unwrap(), requirements)
            .unwrap();
        let plan = InstallPlan::inspect_formal_and_create(
            InstallPlanInput {
                management_origin: ORIGIN,
                expected_server_id: "server-1",
                release_id: release.target().release_id.as_str(),
                update_mode: Some(InstallUpdateMode::Manual),
            },
            &release,
            Some(CA),
            archive,
        )
        .unwrap();
        store.save(&plan).unwrap();
        let intent =
            AuthorizedPreparationIntent::for_fixture(plan, "bd97d508-75c2-4453-8542-845a08613769")
                .unwrap();
        let prepared = prepare_control(&root, intent, fixture_now).unwrap();
        let domain = ExecutionDomain::open_existing(Path::new(CONTROL), 0).unwrap();
        assert!(domain.matches_prepared(&prepared.directory, prepared.lock_id));
        let token = state.join("enrollment");
        let mut enrollment = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&token)
            .unwrap();
        enrollment
            .set_permissions(Permissions::from_mode(0o400))
            .unwrap();
        write!(enrollment, "ndme_{}", "A".repeat(43)).unwrap();
        enrollment.sync_all().unwrap();
        drop(enrollment);
        let claim = prepared.record.claim();
        let mut child = spawn_registration_worker(
            &claim.operation_id,
            &plans,
            &claim.plan_id,
            release_fixture.origin(),
            &token,
        );
        let pending = wait_registration_pending(
            &mut child,
            &domain,
            &prepared,
            &management_dir.join("service-observations.json"),
        );
        assert!(ReapedRegistrationWorker::after_fixture_reboot(&pending).is_err());
        let boot = boot_id().unwrap();
        assert_eq!(
            pending.business().unwrap().registration_boot_id(),
            Some(boot.as_str())
        );
        // SAFETY: the PID belongs to the live fixture child just checked by wait_registration_pending.
        assert_eq!(
            unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGSTOP) },
            0
        );
        let checkpoint = Checkpoint {
            plan_id: claim.plan_id.clone(),
            operation_id: claim.operation_id.clone(),
            target_id: claim.installation_id.clone(),
            domain_id: pending.control_domain_id().to_owned(),
            lock_inode: prepared.lock.metadata().unwrap().ino(),
            boot_id: boot.clone(),
        };
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(checkpoint_path)
            .unwrap();
        file.set_permissions(Permissions::from_mode(0o600)).unwrap();
        serde_json::to_writer(&mut file, &checkpoint).unwrap();
        file.sync_all().unwrap();
        File::open(state).unwrap().sync_all().unwrap();
        // SAFETY: sync has no memory preconditions. The marker follows the flush.
        unsafe { libc::sync() };
        println!("NODOMI_VM_REBOOT_READY {boot}");
        thread_wait_for_power_cut();
        unreachable!("the host harness must stop this VM at the durable marker");
    }
    assert_eq!(stage, "after");
    let checkpoint: Checkpoint =
        serde_json::from_slice(&fs::read(checkpoint_path).unwrap()).unwrap();
    let current_boot = boot_id().unwrap();
    assert_ne!(current_boot, checkpoint.boot_id);
    let plan = store.load(&checkpoint.plan_id).unwrap();
    let prepared =
        PreparedControl::open_fixture_control(&root, plan, &checkpoint.operation_id).unwrap();
    assert_eq!(prepared.record.control_domain_id(), checkpoint.domain_id);
    assert_eq!(
        prepared.lock.metadata().unwrap().ino(),
        checkpoint.lock_inode
    );
    assert_eq!(
        prepared.record.business().unwrap().registration_boot_id(),
        Some(checkpoint.boot_id.as_str())
    );
    assert_eq!(
        lookup_install_operation(&checkpoint.operation_id, &checkpoint.target_id)
            .unwrap()
            .exit_code(),
        6
    );
    let reaped = ReapedRegistrationWorker::after_fixture_reboot(&prepared.record).unwrap();
    let domain = ExecutionDomain::open_existing(Path::new(CONTROL), 0).unwrap();
    assert!(domain.matches_prepared(&prepared.directory, prepared.lock_id));
    let (send, receive) = mpsc::channel();
    let mut pending: Vec<WorkUnit> = vec![Box::new(move || {
        let result = prepared.recover_after_fixture_worker_exit(
            &root,
            ServiceManagerObservation::Systemd,
            &mut client,
            &archive,
            CA,
            reaped,
            fixture_now,
        );
        let _ = send.send(result);
        Ok(())
    })];
    assert_eq!(
        domain.start(&mut pending).unwrap().join().termination,
        Termination::Completed
    );
    let result = receive.recv().unwrap().unwrap();
    assert_eq!(result.exit_code(), 0);
    assert_eq!(
        lookup_install_operation(&checkpoint.operation_id, &checkpoint.target_id),
        Ok(result)
    );
    println!("NODOMI_VM_INSTALL_SETTLED");
    let observations = management_dir.join("service-observations.json");
    let ordinary_deadline = Instant::now() + Duration::from_secs(12);
    let events = loop {
        let events: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(&observations).unwrap()).unwrap();
        let mut metrics = events.iter().filter(|row| row["kind"] == "metric");
        if let (Some(first), Some(second)) = (metrics.next(), metrics.next())
            && fs::read_dir("/var/lib/nodomi-agent/ssh-queue")
                .is_ok_and(|mut entries| entries.next().is_some())
        {
            let first_epoch = first["body"]["samples"][0]["collectorEpoch"]
                .as_str()
                .unwrap();
            let second_epoch = second["body"]["samples"][0]["collectorEpoch"]
                .as_str()
                .unwrap();
            assert_eq!(first_epoch, second_epoch);
            assert_ne!(
                first["body"]["samples"][0]["sampleId"],
                second["body"]["samples"][0]["sampleId"]
            );
            break events;
        }
        assert!(
            Instant::now() < ordinary_deadline,
            "ordinary collection did not resume after settlement"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let count = |kind: &str| events.iter().filter(|row| row["kind"] == kind).count();
    assert_eq!(count("enrollment-target"), 1);
    assert_eq!(count("registration"), 1);
    assert!(count("identity") >= 2);
    assert!(count("heartbeat") > 0 && count("receipt") > 0 && count("metric") > 0);
    println!("NODOMI_VM_ORDINARY_COLLECTION_CONFIRMED");
    stop_vm_service();
    println!("NODOMI_VM_RECOVERY_SUCCEEDED {current_boot} registration_posts=1");
}

fn stop_vm_service() {
    assert!(
        Command::new("/usr/bin/timeout")
            .args([
                "3s",
                "/usr/bin/systemctl",
                "--no-block",
                "stop",
                "nodomi-agent.service"
            ])
            .status()
            .unwrap()
            .success()
    );
    let stop_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let output = Command::new("/usr/bin/timeout")
            .args([
                "2s",
                "/usr/bin/systemctl",
                "show",
                "--property=ActiveState,MainPID",
                "nodomi-agent.service",
            ])
            .output()
            .unwrap();
        if output.status.success()
            && output
                .stdout
                .split(|byte| *byte == b'\n')
                .any(|line| line == b"ActiveState=inactive")
            && output
                .stdout
                .split(|byte| *byte == b'\n')
                .any(|line| line == b"MainPID=0")
        {
            break;
        }
        assert!(
            Instant::now() < stop_deadline,
            "service stop did not drain the supervisor"
        );
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn stop_vm_openrc_service() {
    let status = Command::new("/usr/bin/timeout")
        .args([
            "-k",
            "2",
            "18",
            "/sbin/rc-service",
            "--nodeps",
            "/etc/init.d/nodomi-agent",
            "stop",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "OpenRC did not stop the service");
    let status = Command::new("/usr/bin/timeout")
        .args([
            "2",
            "/sbin/rc-service",
            "--nodeps",
            "/etc/init.d/nodomi-agent",
            "status",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3), "OpenRC service is not stopped");
    assert!(!Path::new("/run/supervise-nodomi-agent.pid").exists());
}

fn start_management(directory: &Path) -> FixtureProcess {
    start_management_scenario(directory, "reboot-registration")
}

fn start_management_scenario(directory: &Path, scenario: &str) -> FixtureProcess {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/https_service.py");
    let mut child = FixtureProcess(
        Command::new("/usr/bin/python3")
            .arg(fixture)
            .arg(directory)
            .args([MANAGER_PORT, scenario])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), MANAGER_PORT);
    child
}

fn thread_wait_for_power_cut() {
    std::thread::sleep(Duration::from_secs(90));
}
