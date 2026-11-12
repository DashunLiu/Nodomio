use super::super::{AllocationCharge, DiskBudgetReason, DiskBudgetState};
use super::*;
fn observed(device: u64, mount: u64, available: u64) -> AllocationObservation {
    AllocationObservation {
        space: DirectorySpace {
            device,
            inode: 1,
            available_bytes: Some(available),
            available_inodes: Some(20),
            fragment_bytes: Some(4096),
            read_only: false,
        },
        filesystem: AllocationFilesystem::Ext,
        mount_id: Some(mount),
        mount_verified: true,
        quotas: [QuotaObservation::Disabled; 3],
        ext_counters_unscoped: Some(true),
    }
}
#[test]
fn bind_mounts_share_capacity_and_separate_filesystems_do_not() {
    let a = observed(1, 10, 10);
    let b = observed(1, 11, 10);
    let phase = PhaseBudget {
        charges: vec![
            AllocationCharge {
                bytes: Some(6),
                inodes: Some(1)
            };
            2
        ],
    };
    assert_eq!(
        assess_allocation(&[a.clone(), b], &[phase.clone()])
            .unwrap()
            .state,
        DiskBudgetState::Insufficient
    );
    let other = observed(2, 12, 10);
    assert_eq!(
        assess_allocation(&[a, other], &[phase]).unwrap().state,
        DiskBudgetState::Sufficient
    );
}

#[test]
fn ext_project_quota_counters_do_not_create_a_shared_shortage() {
    let mut program = observed(1, 10, 100);
    program.quotas[2] = QuotaObservation::Enabled;
    program.ext_counters_unscoped = Some(false);
    let mut state = program.clone();
    state.space.inode = 2;
    let phase = PhaseBudget {
        charges: vec![
            AllocationCharge {
                bytes: Some(60),
                inodes: Some(12),
            };
            2
        ],
    };

    let result = assess_allocation(&[program.clone(), state.clone()], &[phase.clone()]).unwrap();
    assert_eq!(result.state, DiskBudgetState::Unknown);
    assert!(result.pools.is_empty());

    // An unscoped observation of the same device still must not absorb a
    // quota-scoped destination or use its smaller per-project counter.
    state.ext_counters_unscoped = Some(true);
    state.space.available_bytes = Some(1000);
    state.space.available_inodes = Some(200);
    let result = assess_allocation(&[program.clone(), state.clone()], &[phase]).unwrap();
    assert_eq!(result.state, DiskBudgetState::Unknown);
    assert_eq!(result.pools.len(), 1);

    let result = assess_allocation(
        &[program, state],
        &[PhaseBudget {
            charges: vec![
                AllocationCharge {
                    bytes: Some(10),
                    inodes: Some(21),
                },
                AllocationCharge::ZERO,
            ],
        }],
    )
    .unwrap();
    assert_eq!(result.state, DiskBudgetState::Insufficient);
    assert!(
        result
            .reasons
            .contains(&DiskBudgetReason::InodesInsufficient)
    );
}

#[test]
fn legacy_ext_observation_reencodes_without_proving_shared_counters() {
    let mut recorded = serde_json::to_value(observed(1, 10, 100)).unwrap();
    recorded
        .as_object_mut()
        .unwrap()
        .remove("extCountersUnscoped");
    let legacy: AllocationObservation = serde_json::from_value(recorded.clone()).unwrap();
    assert!(legacy.proven_pool());
    assert!(!legacy.counters_share_pool());
    assert_eq!(serde_json::to_value(legacy).unwrap(), recorded);
}
#[test]
fn denial_and_unsupported_filesystems_cannot_prove_quota_absence() {
    for error in [libc::EPERM, libc::ENOSYS, libc::EINVAL, libc::EIO] {
        assert_eq!(quota_result(-1, Some(error)), QuotaObservation::Unknown);
    }
    assert_eq!(
        quota_result(-1, Some(libc::ESRCH)),
        QuotaObservation::Disabled
    );
    assert_eq!(quota_result(0, None), QuotaObservation::Enabled);
    let mut a = observed(1, 10, 100);
    a.quotas[2] = QuotaObservation::Unknown;
    let phase = PhaseBudget {
        charges: vec![AllocationCharge::ZERO],
    };
    assert_eq!(
        assess_allocation(&[a.clone()], &[phase.clone()])
            .unwrap()
            .state,
        DiskBudgetState::Unknown
    );
    a.quotas = [QuotaObservation::Disabled; 3];
    a.filesystem = AllocationFilesystem::Unsupported;
    assert_eq!(
        assess_allocation(&[a], &[phase]).unwrap().state,
        DiskBudgetState::Unknown
    );
}
#[test]
fn malformed_mount_information_never_identifies_a_pool() {
    assert_eq!(parse_mount_id("pos: 0\nmnt_id: 12\n"), Some(12));
    assert_eq!(parse_mount_id("mnt_id: 12\nmnt_id: 12\n"), None);
    let dev = libc::makedev(8, 1);
    assert!(verify_mount(
        "12 1 8:1 / / rw - ext4 /dev/a rw\n",
        12,
        dev,
        AllocationFilesystem::Ext
    ));
    assert!(!verify_mount(
        "12 1 8:2 / / rw - ext4 /dev/a rw\n",
        12,
        dev,
        AllocationFilesystem::Ext
    ));
    assert!(!verify_mount(
        "12 1 8:1 / / rw - overlay overlay rw\n",
        12,
        dev,
        AllocationFilesystem::Ext
    ));
    assert!(!verify_mount(
        "12 1 8:1 / / rw - ext4 /dev/a rw\n12 1 8:1 / / rw - ext4 /dev/a rw\n",
        12,
        dev,
        AllocationFilesystem::Ext
    ));
}
#[test]
fn real_member_lower_bound_detects_shortage_but_never_complete_readiness() {
    let package = PackageDiskInputs {
        program_files: [8192, 8192, 8192, 8192],
        service_file: 8192,
        archive_bytes: 1000,
    };
    let observations = [
        observed(1, 10, 20_479),
        observed(1, 10, 20_479),
        observed(1, 10, 20_479),
    ];
    let result = assess_publication_lower_bound(&observations, &package).unwrap();
    assert_eq!(result.state, DiskBudgetState::Insufficient);
    assert!(
        result
            .reasons
            .contains(&DiskBudgetReason::BytesInsufficient)
    );
    let observations = [
        observed(1, 10, 50_000),
        observed(1, 10, 50_000),
        observed(1, 10, 50_000),
    ];
    let result = assess_publication_lower_bound(&observations, &package).unwrap();
    assert_eq!(result.state, DiskBudgetState::Unknown);
    assert!(
        result
            .reasons
            .contains(&DiskBudgetReason::AllocationUnknown)
    );
}
#[test]
fn actual_directory_observation_is_read_only_and_keeps_unknown_honestly() {
    let directory = tempfile::tempdir().unwrap();
    let fd = File::open(directory.path()).unwrap();
    let before = std::fs::read_dir(directory.path()).unwrap().count();
    let observation = observe_allocation(&fd).unwrap();
    assert!(observation.mount_id.is_some());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), before);
    let result = assess_allocation(
        &[observation.clone()],
        &[PhaseBudget {
            charges: vec![AllocationCharge::ZERO],
        }],
    )
    .unwrap();
    if !observation.proven_pool() || observation.quotas != [QuotaObservation::Disabled; 3] {
        assert_eq!(result.state, DiskBudgetState::Unknown);
    }
}
#[test]
#[ignore = "requires dedicated disposable ext4 named volume mounted at /allocation-proof"]
fn actual_ext4_volume_reads_quota_state_and_computes_real_shortage() {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = File::options()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open("/allocation-proof")
        .unwrap();
    let observation = observe_allocation(&directory).unwrap();
    eprintln!("allocation evidence: {:?}", observation);
    assert_eq!(observation.filesystem, AllocationFilesystem::Ext);
    assert!(observation.proven_pool());
    assert!(observation.counters_share_pool());
    let alias = observe_allocation(&File::open("/allocation-alias").unwrap()).unwrap();
    assert_ne!(observation.mount_id, alias.mount_id);
    assert_eq!(observation.space.device, alias.space.device);
    let shared_available = observation
        .space
        .available_bytes
        .unwrap()
        .min(alias.space.available_bytes.unwrap());
    let shared = assess_allocation(
        &[observation.clone(), alias],
        &[PhaseBudget {
            charges: vec![
                AllocationCharge {
                    bytes: Some(shared_available / 2 + 1),
                    inodes: Some(1)
                };
                2
            ],
        }],
    )
    .unwrap();
    assert_eq!(shared.state, DiskBudgetState::Insufficient);
    assert_eq!(shared.pools.len(), 1);

    let available = observation.space.available_bytes.unwrap();
    let result = assess_allocation(
        &[observation.clone()],
        &[PhaseBudget {
            charges: vec![AllocationCharge {
                bytes: Some(available + 1),
                inodes: Some(1),
            }],
        }],
    )
    .unwrap();
    assert_eq!(result.state, DiskBudgetState::Insufficient);
    let result = assess_allocation(
        &[observation.clone()],
        &[PhaseBudget {
            charges: vec![AllocationCharge::ZERO],
        }],
    )
    .unwrap();
    if observation.quotas == [QuotaObservation::Disabled; 3] && !observation.space.read_only {
        assert_eq!(result.state, DiskBudgetState::Sufficient);
    } else {
        assert_eq!(result.state, DiskBudgetState::Unknown);
    }
}

#[test]
fn contradictory_pool_claims_do_not_produce_false_shortage() {
    let a = observed(1, 10, 0);
    let mut b = a.clone();
    b.filesystem = AllocationFilesystem::Xfs;
    let phase = PhaseBudget {
        charges: vec![
            AllocationCharge {
                bytes: Some(99),
                inodes: Some(99)
            };
            2
        ],
    };
    let result = assess_allocation(&[a.clone(), b], &[phase.clone()]).unwrap();
    assert_eq!(result.state, DiskBudgetState::Unknown);
    assert_eq!(
        result.reasons,
        vec![DiskBudgetReason::ConflictingPoolEvidence]
    );
    let b = observed(2, 10, 0);
    assert_eq!(
        assess_allocation(&[a, b], &[phase]).unwrap().state,
        DiskBudgetState::Unknown
    );
}

#[test]
fn small_inline_or_unknown_files_do_not_invent_allocated_byte_shortage() {
    let package = PackageDiskInputs {
        program_files: [4, 3, 2, 1],
        service_file: 2,
        archive_bytes: 1000,
    };
    let observations = [observed(1, 10, 0), observed(1, 10, 0), observed(1, 10, 0)];
    let result = assess_publication_lower_bound(&observations, &package).unwrap();
    assert_eq!(result.state, DiskBudgetState::Unknown);
    let mut observations = observations;
    observations[0].space.available_inodes = Some(8);
    assert_eq!(
        assess_publication_lower_bound(&observations, &package)
            .unwrap()
            .state,
        DiskBudgetState::Insufficient
    );
    for observation in &mut observations {
        observation.filesystem = AllocationFilesystem::Unsupported;
    }
    assert_eq!(
        assess_publication_lower_bound(&observations, &package)
            .unwrap()
            .state,
        DiskBudgetState::Unknown
    );
}

#[test]
fn tmpfs_pool_requires_verified_mount_and_retains_quota_uncertainty() {
    let mut a = observed(libc::makedev(0, 90), 100, 10);
    a.filesystem = AllocationFilesystem::Tmpfs;
    a.quotas = [QuotaObservation::Unknown; 3];
    let mut alias = a.clone();
    alias.mount_id = Some(101);
    let phase = PhaseBudget {
        charges: vec![
            AllocationCharge {
                bytes: Some(6),
                inodes: Some(1)
            };
            2
        ],
    };
    let shared = assess_allocation(&[a.clone(), alias.clone()], &[phase.clone()]).unwrap();
    assert_eq!(shared.state, DiskBudgetState::Insufficient);
    assert_eq!(shared.pools.len(), 1);
    alias.space.device = libc::makedev(0, 91);
    let independent = assess_allocation(&[a.clone(), alias], &[phase]).unwrap();
    assert_eq!(independent.state, DiskBudgetState::Unknown);
    assert_eq!(independent.pools.len(), 2);
    assert!(
        independent
            .reasons
            .contains(&DiskBudgetReason::QuotaUnknown)
    );
    a.mount_verified = false;
    assert!(!a.proven_pool());
    // Unknown grouping prevents a shared-pool conclusion. A separately proven
    // individual shortage would still be valid with a caller-supplied charge.
    assert_eq!(
        assess_allocation(
            &[a],
            &[PhaseBudget {
                charges: vec![AllocationCharge {
                    bytes: Some(1),
                    inodes: Some(1)
                }]
            }]
        )
        .unwrap()
        .state,
        DiskBudgetState::Unknown
    );
}

#[test]
fn tmpfs_mount_table_must_match_kernel_device_and_type() {
    let device = libc::makedev(0, 90);
    let table = "100 1 0:90 / /run rw,nosuid,nodev - tmpfs tmpfs rw,size=64k,usrquota,grpquota\n";
    assert!(verify_mount(
        table,
        100,
        device,
        AllocationFilesystem::Tmpfs
    ));
    assert!(!verify_mount(
        table,
        101,
        device,
        AllocationFilesystem::Tmpfs
    ));
    assert!(!verify_mount(
        table,
        100,
        libc::makedev(0, 91),
        AllocationFilesystem::Tmpfs
    ));
    assert!(!verify_mount(
        &table.replace("- tmpfs", "- ramfs"),
        100,
        device,
        AllocationFilesystem::Tmpfs
    ));
    assert!(!verify_mount(
        &(table.to_owned() + table),
        100,
        device,
        AllocationFilesystem::Tmpfs
    ));
}

#[test]
#[ignore = "requires isolated /tmpfs-pool-a, its /tmpfs-alias bind, independent /tmpfs-pool-b and unlimited /tmpfs-unlimited"]
fn actual_tmpfs_bind_independence_shortages_and_unlimited_are_observed() {
    let handles =
        ["/tmpfs-pool-a", "/tmpfs-alias", "/tmpfs-pool-b"].map(|path| File::open(path).unwrap());
    let observations = handles.each_ref().map(|fd| observe_allocation(fd).unwrap());
    for (fd, observation) in handles.iter().zip(&observations) {
        assert_eq!(observation.filesystem, AllocationFilesystem::Tmpfs);
        assert!(observation.proven_pool());
        assert_eq!(statx_mount_id(fd, &observation.space), observation.mount_id);
        let mut wrong = observation.space;
        wrong.inode += 1;
        assert_eq!(statx_mount_id(fd, &wrong), None);
    }
    let [a, alias, independent] = &observations;
    assert_eq!(a.space.device, alias.space.device);
    assert_ne!(a.mount_id, alias.mount_id);
    assert_ne!(a.space.device, independent.space.device);
    let available = a
        .space
        .available_bytes
        .unwrap()
        .min(alias.space.available_bytes.unwrap());
    let phase = PhaseBudget {
        charges: vec![
            AllocationCharge {
                bytes: Some(available / 2 + 1),
                inodes: Some(1)
            };
            2
        ],
    };
    let shared = assess_allocation(&[a.clone(), alias.clone()], &[phase.clone()]).unwrap();
    assert_eq!(shared.pools.len(), 1);
    assert_eq!(shared.state, DiskBudgetState::Insufficient);
    assert!(
        shared
            .reasons
            .contains(&DiskBudgetReason::BytesInsufficient)
    );
    let separate = assess_allocation(&[a.clone(), independent.clone()], &[phase]).unwrap();
    assert_eq!(separate.pools.len(), 2);
    assert_ne!(separate.state, DiskBudgetState::Insufficient);
    for observation in &observations {
        let result = assess_allocation(
            std::slice::from_ref(observation),
            &[PhaseBudget {
                charges: vec![AllocationCharge {
                    bytes: Some(0),
                    inodes: Some(observation.space.available_inodes.unwrap() + 1),
                }],
            }],
        )
        .unwrap();
        assert_eq!(result.state, DiskBudgetState::Insufficient);
        assert!(
            result
                .reasons
                .contains(&DiskBudgetReason::InodesInsufficient)
        );
    }
    let unlimited = observe_allocation(&File::open("/tmpfs-unlimited").unwrap()).unwrap();
    assert!(unlimited.proven_pool());
    assert_eq!(unlimited.space.available_bytes, None);
    assert_eq!(unlimited.space.available_inodes, None);
    assert_eq!(
        assess_allocation(
            &[unlimited],
            &[PhaseBudget {
                charges: vec![AllocationCharge {
                    bytes: Some(1),
                    inodes: Some(1)
                }]
            }]
        )
        .unwrap()
        .state,
        DiskBudgetState::Unknown
    );
    eprintln!(
        "tmpfs real evidence: a={a:?}; alias={alias:?}; independent={independent:?}; shared={:?}; separate={:?}",
        shared.state, separate.state
    );
}

#[test]
#[ignore = "requires isolated tmpfs mounted with usrquota,grpquota at /tmpfs-quota"]
fn actual_tmpfs_enabled_quotas_are_not_assumed_absent() {
    let observation = observe_allocation(&File::open("/tmpfs-quota").unwrap()).unwrap();
    assert_eq!(observation.filesystem, AllocationFilesystem::Tmpfs);
    assert!(observation.proven_pool());
    assert_eq!(
        observation.quotas,
        [
            QuotaObservation::Enabled,
            QuotaObservation::Enabled,
            QuotaObservation::Unknown,
        ]
    );
    assert_eq!(
        assess_allocation(
            &[observation.clone()],
            &[PhaseBudget {
                charges: vec![AllocationCharge::ZERO]
            }]
        )
        .unwrap()
        .state,
        DiskBudgetState::Unknown
    );
    eprintln!("tmpfs enabled quota evidence: {:?}", observation.quotas);
}
