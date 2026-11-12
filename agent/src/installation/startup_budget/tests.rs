use super::super::{AllocationFilesystem, DirectorySpace, DiskBudgetState, QuotaObservation};
use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
fn limits() -> StartupWorkloadLimits {
    StartupWorkloadLimits {
        max_duration_ms: 60_000,
        max_runtime_manifest_bytes: 1_000_000,
        max_sqlite_database_bytes: 1_000_000,
        max_sqlite_journal_bytes: 1_000_000,
    }
}
fn observation() -> AllocationObservation {
    AllocationObservation {
        space: DirectorySpace {
            device: 1,
            inode: 1,
            available_bytes: Some(1000),
            available_inodes: Some(1000),
            fragment_bytes: Some(4096),
            read_only: false,
        },
        filesystem: AllocationFilesystem::Ext,
        mount_id: Some(1),
        mount_verified: true,
        quotas: [QuotaObservation::Disabled; 3],
        ext_counters_unscoped: Some(true),
    }
}
fn complete_profile() -> StartupBudgetProfile {
    let mut profile = StartupBudgetProfile::unknown(1, limits()).unwrap();
    for stage in StartupStage::ALL {
        profile
            .record_phase(
                stage,
                StartupComponent::ALL
                    .into_iter()
                    .map(|component| StartupComponentBudget {
                        component,
                        evidence: StartupBudgetEvidence::Bounded,
                        charges: vec![AllocationCharge {
                            bytes: Some(10),
                            inodes: Some(1),
                        }],
                    })
                    .collect(),
            )
            .unwrap();
    }
    profile
}
#[test]
fn complete_profile_requires_enforcement_and_all_stage_components() {
    let profile = complete_profile();
    assert_eq!(
        assess_startup_budget(&[observation()], &profile, true)
            .unwrap()
            .state,
        DiskBudgetState::Sufficient
    );
    assert_eq!(
        assess_startup_budget(&[observation()], &profile, false)
            .unwrap()
            .state,
        DiskBudgetState::Unknown
    );
    let profile = StartupBudgetProfile::unknown(1, limits()).unwrap();
    assert_eq!(
        assess_startup_budget(&[observation()], &profile, true)
            .unwrap()
            .state,
        DiskBudgetState::Unknown
    );
}
#[test]
fn observed_snapshot_never_becomes_a_peak_or_definite_shortage() {
    let mut profile = complete_profile();
    let components = StartupComponent::ALL
        .into_iter()
        .map(|component| StartupComponentBudget {
            component,
            evidence: StartupBudgetEvidence::ObservedOnly,
            charges: vec![AllocationCharge {
                bytes: Some(u64::MAX),
                inodes: Some(u64::MAX),
            }],
        })
        .collect();
    profile
        .record_phase(StartupStage::FirstHealth, components)
        .unwrap();
    assert_eq!(
        assess_startup_budget(&[observation()], &profile, true)
            .unwrap()
            .state,
        DiskBudgetState::Unknown
    );
}
#[test]
fn phase_shared_peak_is_combined_but_not_summed_over_time() {
    let profile = complete_profile();
    let mut observation = observation();
    observation.space.available_bytes = Some(80);
    assert_eq!(
        assess_startup_budget(&[observation.clone()], &profile, true)
            .unwrap()
            .state,
        DiskBudgetState::Sufficient
    );
    observation.space.available_bytes = Some(79);
    assert_eq!(
        assess_startup_budget(&[observation], &profile, true)
            .unwrap()
            .state,
        DiskBudgetState::Insufficient
    );
}
#[test]
fn rejects_duplicate_or_missing_components_and_overflow() {
    let mut profile = complete_profile();
    assert_eq!(
        profile.record_phase(StartupStage::FirstHealth, vec![]),
        Err(StartupBudgetError::InvalidProfile)
    );
    let components = StartupComponent::ALL
        .into_iter()
        .map(|_| StartupComponentBudget {
            component: StartupComponent::Program,
            evidence: StartupBudgetEvidence::Bounded,
            charges: vec![AllocationCharge::ZERO],
        })
        .collect();
    assert_eq!(
        profile.record_phase(StartupStage::FirstHealth, components),
        Err(StartupBudgetError::InvalidProfile)
    );
    let components = StartupComponent::ALL
        .into_iter()
        .map(|component| StartupComponentBudget {
            component,
            evidence: StartupBudgetEvidence::Bounded,
            charges: vec![AllocationCharge {
                bytes: Some(u64::MAX),
                inodes: Some(0),
            }],
        })
        .collect();
    profile
        .record_phase(StartupStage::FirstHealth, components)
        .unwrap();
    assert_eq!(
        assess_startup_budget(&[observation()], &profile, true),
        Err(StartupBudgetError::ArithmeticOverflow)
    );
}
#[test]
fn bounded_tree_measurement_counts_allocated_objects_without_following_links() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("file"), vec![0x55; 8192]).unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    symlink("/outside-canary", dir.path().join("link")).unwrap();
    let held = File::open(dir.path()).unwrap();
    let snapshot = measure_startup_tree(&held).unwrap();
    assert_eq!(snapshot.inodes, 4);
    assert_eq!(snapshot.regular_files, 1);
    assert_eq!(snapshot.directories, 2);
    assert_eq!(snapshot.symlinks, 1);
    assert!(snapshot.allocated_bytes >= 8192);
    assert_eq!(snapshot, measure_startup_tree(&held).unwrap());
}
#[test]
#[ignore = "requires disposable ext4 volume at /startup-proof"]
fn real_ext4_identity_and_shared_buffer_snapshots_remain_observations() {
    use crate::{
        buffer::{QueueTime, SharedBuffer, SharedBufferPaths},
        identity::{Binding, IdentityStore, Target},
        protocol::AgentConfiguration,
    };
    let root = tempfile::tempdir_in("/startup-proof").unwrap();
    let private = |name: &str| {
        let path = root.path().join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    };
    let identity_path = private("identity");
    let host = private("runtime");
    let ssh = private("ssh-queue");
    let held = File::open(root.path()).unwrap();
    let empty = measure_startup_tree(&held).unwrap();
    let mut identity = IdentityStore::initialize(
        &identity_path,
        Target::new("https://startup.invalid", "server-startup").unwrap(),
    )
    .unwrap();
    let initialized = measure_startup_tree(&held).unwrap();
    identity
        .confirm(Binding {
            agent_id: "agent-startup".into(),
            server_id: "server-startup".into(),
            binding_revision: 1,
        })
        .unwrap();
    let registered = measure_startup_tree(&held).unwrap();
    let config=AgentConfiguration::decode(br#"{"agentId":"agent-startup","bindingRevision":1,"schemaVersion":1,"target":{"configId":"11111111-1111-4111-8111-111111111111","generation":1,"configuration":{"samplingIntervalSeconds":30,"bufferMaxAgeSeconds":3600,"bufferMaxBytes":100000000}}}"#).unwrap();
    let epoch = "22222222-2222-4222-8222-222222222222";
    let buffer = SharedBuffer::open(
        SharedBufferPaths {
            host: &host,
            ssh: &ssh,
        },
        &identity,
        epoch,
        &config,
        &QueueTime {
            boot_id: epoch.into(),
            monotonic_ns: 1,
            unix_seconds: 1794355200,
        },
    )
    .unwrap();
    let runtime = measure_startup_tree(&held).unwrap();
    let observed_buffer_peak = buffer.observed_peak_bytes().unwrap();
    let observed_journal_peak = buffer.observed_journal_peak_bytes().unwrap();
    assert!(observed_buffer_peak >= buffer.allocated_bytes().unwrap());
    assert!(runtime.allocated_bytes < 100_000_000);
    assert!(runtime.inodes > registered.inodes);
    assert!(initialized.inodes > empty.inodes);
    eprintln!(
        "ext4 startup snapshots (NOT peaks): empty={empty:?}; identity={initialized:?}; bound={registered:?}; shared_buffer={runtime:?}"
    );
    eprintln!(
        "SharedBuffer instrumentation observed peaks (NOT whole-startup bounds): allocation={observed_buffer_peak}; sqlite_journal={observed_journal_peak}"
    );
    let _ = buffer;
}

#[test]
#[ignore = "requires disposable ext4 volume at /startup-proof"]
fn actual_publication_state_and_control_snapshots_keep_metadata_separate() {
    use super::super::{
        InstallUpdateMode, ServiceManagerObservation,
        control_record::{ControlRecord, PreparationClaim, publish_claimed},
        inspect_formal_package,
        install_state::prepare_install_state,
        package::{fixture_formal_archive, package_file},
        staging::publish_formal_package,
    };
    use crate::{identity::Target, release::manifest::Platform};
    let root = tempfile::tempdir_in("/startup-proof").unwrap();
    for name in ["opt", "var", "var/lib", "service"] {
        let path = root.path().join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let control = root.path().join("var/lib/nodomi-agent-control");
    fs::create_dir(&control).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
    let control = File::open(control).unwrap();
    // SAFETY: control is a live private fixture directory descriptor.
    assert_eq!(
        unsafe { libc::flock(control.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let id = "11111111-1111-4111-8111-111111111111";
    let target = Target::new("https://startup.invalid", "server-startup").unwrap();
    let record = ControlRecord::claimed(
        id.into(),
        PreparationClaim {
            operation_id: id.into(),
            idempotency_key: id.into(),
            plan_id: id.into(),
            plan_digest: "a".repeat(64),
            installation_id: id.into(),
            target: target.clone(),
        },
    )
    .unwrap();
    publish_claimed(&control, &record).unwrap();
    use std::os::unix::fs::OpenOptionsExt;
    let execution_lock = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(
            root.path()
                .join("var/lib/nodomi-agent-control/execution.lock"),
        )
        .unwrap();
    execution_lock.sync_all().unwrap();
    control.sync_all().unwrap();
    let control_snapshot = measure_startup_tree(&control).unwrap();
    assert_eq!(control_snapshot.inodes, 3);
    let archive = fixture_formal_archive(Platform::LinuxAarch64, b"fixture text\n");
    let package = inspect_formal_package(package_file(&archive), Platform::LinuxAarch64).unwrap();
    let program = File::open(root.path().join("opt")).unwrap();
    let service = File::open(root.path().join("service")).unwrap();
    // SAFETY: geteuid has no preconditions.
    let publication_owner = unsafe { libc::geteuid() };
    publish_formal_package(
        &super::super::staging::PublicationContext {
            control: &control,
            program_parent: &program,
            service_parent: &service,
            owner: publication_owner,
            manager: ServiceManagerObservation::Systemd,
            operation_id: id,
            plan_digest: &"a".repeat(64),
            release_id: id,
        },
        &package_file(&archive),
        &package,
        id,
        || Ok(()),
    )
    .unwrap();
    let program_snapshot =
        measure_startup_tree(&File::open(root.path().join("opt/nodomi-agent")).unwrap()).unwrap();
    let service_snapshot = measure_startup_tree(&service).unwrap();
    assert_eq!(program_snapshot.inodes, 9);
    assert_eq!(service_snapshot.inodes, 2);
    let anchored = File::open(root.path()).unwrap();
    // SAFETY: geteuid has no preconditions.
    let owner = unsafe { libc::geteuid() };
    let state = prepare_install_state(
        &anchored,
        &control,
        owner,
        &target,
        InstallUpdateMode::Manual,
        None,
    )
    .unwrap();
    let state_snapshot = measure_startup_tree(state.directory()).unwrap();
    assert_eq!(state_snapshot.inodes, 7);
    eprintln!(
        "ext4 publication snapshots (fixture member bytes, NOT peaks): control={control_snapshot:?}; program={program_snapshot:?}; service={service_snapshot:?}; state={state_snapshot:?}"
    );
}

#[test]
fn tree_traversal_bounds_and_held_parent_are_enforced() {
    let outer = tempfile::tempdir().unwrap();
    let original = outer.path().join("source");
    fs::create_dir(&original).unwrap();
    fs::write(original.join("one"), b"one").unwrap();
    let held = File::open(&original).unwrap();
    let moved = outer.path().join("held");
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    fs::write(original.join("unrelated"), vec![1; 16384]).unwrap();
    assert_eq!(measure_startup_tree(&held).unwrap().regular_files, 1);
    let mut next = moved;
    for _ in 0..18 {
        next = next.join("d");
        fs::create_dir(&next).unwrap();
    }
    assert_eq!(
        measure_startup_tree(&held),
        Err(StartupBudgetError::TraversalLimit)
    );
}
