use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
fn root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    root
}
fn directories(root: &std::path::Path, path: &str) {
    let mut at = root.to_path_buf();
    for part in path.split('/') {
        at.push(part);
        if !at.exists() {
            fs::create_dir(&at).unwrap();
            fs::set_permissions(&at, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}
fn inspect(root: &File, manager: ServiceManagerObservation) -> ManagerCapacityInventory {
    inspect_at(
        root,
        super::super::super::plan_store::effective_uid(),
        manager,
    )
}
#[test]
fn selected_managers_include_runtime_enablement_and_possible_logs() {
    let root = root();
    for path in [
        "run/systemd",
        "run/openrc",
        "etc/systemd/system/multi-user.target.wants",
        "etc/runlevels/default",
        "var/log/journal",
        "run/log/journal",
    ] {
        directories(root.path(), path);
    }
    for manager in [
        ServiceManagerObservation::Systemd,
        ServiceManagerObservation::OpenRc,
    ] {
        for spec in specs(manager) {
            directories(root.path(), spec.path.trim_start_matches('/'));
        }
    }
    let held = File::open(root.path()).unwrap();
    for manager in [
        ServiceManagerObservation::Systemd,
        ServiceManagerObservation::OpenRc,
    ] {
        let inventory = inspect(&held, manager);
        assert_eq!(
            inventory.destinations().len(),
            if manager == ServiceManagerObservation::Systemd {
                10
            } else {
                13
            }
        );
        assert!(inventory.destinations().len() + 3 <= 16);
        assert_eq!(
            inventory
                .destinations()
                .iter()
                .any(|entry| entry.role == ManagerDestinationRole::VolatileJournal),
            manager == ServiceManagerObservation::Systemd
        );
        assert!(
            inventory
                .destinations()
                .iter()
                .all(|destination| destination.status == ManagerDestinationStatus::Existing)
        );
        for role in [
            ManagerDestinationRole::RunRoot,
            ManagerDestinationRole::Runtime,
            ManagerDestinationRole::Enablement,
        ] {
            assert!(
                inventory
                    .destinations()
                    .iter()
                    .any(|destination| destination.role == role)
            );
        }
        assert!(
            inventory
                .unresolved()
                .contains(&ManagerCapacityUnknown::EffectiveLoggingRoute)
        );
        assert_eq!(
            inventory
                .assess(&[PhaseBudget {
                    charges: vec![AllocationCharge::ZERO; inventory.destinations().len()]
                }])
                .unwrap()
                .state,
            DiskBudgetState::Unknown
        );
    }
}
#[test]
fn missing_destinations_use_nearest_protected_parent_without_creating() {
    let root = root();
    for path in ["run", "etc/systemd/system", "var/log"] {
        directories(root.path(), path);
    }
    let inventory = inspect(
        &File::open(root.path()).unwrap(),
        ServiceManagerObservation::Systemd,
    );
    let volatile = inventory
        .destinations()
        .iter()
        .find(|destination| destination.role == ManagerDestinationRole::VolatileJournal)
        .unwrap();
    assert_eq!(
        volatile.status,
        ManagerDestinationStatus::MissingBelowProtectedParent {
            missing_components: 2
        }
    );
    assert!(volatile.allocation.is_some());
    assert_eq!(fs::read_dir(root.path().join("run")).unwrap().count(), 0);
    assert!(
        !root
            .path()
            .join("etc/systemd/system/multi-user.target.wants")
            .exists()
    );
}
#[test]
fn symlinks_and_writable_ancestors_are_not_capacity_authority() {
    let root = root();
    directories(root.path(), "run");
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("canary"), b"untouched").unwrap();
    symlink(outside.path(), root.path().join("run/log")).unwrap();
    directories(root.path(), "var/log");
    fs::set_permissions(
        root.path().join("var/log"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let inventory = inspect(
        &File::open(root.path()).unwrap(),
        ServiceManagerObservation::Systemd,
    );
    for role in [
        ManagerDestinationRole::VolatileJournal,
        ManagerDestinationRole::PersistentJournal,
    ] {
        let destination = inventory
            .destinations()
            .iter()
            .find(|destination| destination.role == role)
            .unwrap();
        assert_eq!(destination.status, ManagerDestinationStatus::Unsafe);
        assert!(destination.allocation.is_none());
    }
    assert!(inventory.allocation_observations().is_none());
    assert_eq!(
        fs::read(outside.path().join("canary")).unwrap(),
        b"untouched"
    );
}
#[test]
fn held_root_rename_does_not_redirect_observation() {
    let outer = tempfile::tempdir().unwrap();
    let initial = outer.path().join("initial");
    fs::create_dir(&initial).unwrap();
    directories(&initial, "run/systemd");
    let held = File::open(&initial).unwrap();
    let moved = outer.path().join("moved");
    fs::rename(&initial, &moved).unwrap();
    fs::create_dir(&initial).unwrap();
    symlink("/", initial.join("run")).unwrap();
    let inventory = inspect(&held, ServiceManagerObservation::Systemd);
    assert_eq!(
        inventory.destinations()[0].status,
        ManagerDestinationStatus::Existing
    );
    assert_eq!(
        inventory.destinations()[1].status,
        ManagerDestinationStatus::Existing
    );
}
#[test]
fn unavailable_or_unsupported_manager_never_becomes_ready() {
    let inventory = ManagerCapacityInventory::inspect(ServiceManagerObservation::Unknown);
    assert_eq!(
        inventory.unresolved(),
        &[ManagerCapacityUnknown::UnsupportedManager]
    );
    assert_eq!(
        inventory.assess(&[]).unwrap().state,
        DiskBudgetState::Unknown
    );
}
#[test]
fn live_linux_inventory_is_read_only_and_does_not_claim_effective_journal_policy() {
    let inventory = ManagerCapacityInventory::inspect(ServiceManagerObservation::Systemd);
    let run = inventory
        .destinations()
        .iter()
        .find(|destination| destination.role == ManagerDestinationRole::RunRoot)
        .unwrap();
    assert_eq!(run.status, ManagerDestinationStatus::Existing);
    assert!(run.allocation.is_some());
    assert!(
        inventory
            .unresolved()
            .contains(&ManagerCapacityUnknown::ManagerWriteBounds)
    );
    let component = inventory.unknown_component_budget();
    assert_eq!(component.evidence, StartupBudgetEvidence::Unknown);
    assert_eq!(component.charges.len(), inventory.destinations().len());
}

#[test]
#[ignore = "requires isolated tmpfs /manager-proof and separately mounted /manager-proof/run/openrc/options"]
fn separately_mounted_openrc_state_keeps_its_actual_pool_observation() {
    use super::super::super::AllocationFilesystem;

    let root = std::path::Path::new("/manager-proof");
    for spec in specs(ServiceManagerObservation::OpenRc) {
        directories(root, spec.path.trim_start_matches('/'));
    }
    let inventory = inspect(
        &File::open(root).unwrap(),
        ServiceManagerObservation::OpenRc,
    );
    let runtime = inventory
        .destinations()
        .iter()
        .find(|value| value.role == ManagerDestinationRole::Runtime)
        .unwrap();
    let options = inventory
        .destinations()
        .iter()
        .find(|value| value.role == ManagerDestinationRole::RuntimeSubdirectory("options"))
        .unwrap();
    let runtime_allocation = runtime.allocation.as_ref().unwrap();
    let options_allocation = options.allocation.as_ref().unwrap();
    for allocation in [runtime_allocation, options_allocation] {
        assert_eq!(allocation.filesystem, AllocationFilesystem::Tmpfs);
        assert!(allocation.proven_pool());
    }
    assert_ne!(
        runtime_allocation.space.device,
        options_allocation.space.device
    );
    assert_eq!(inventory.destinations().len(), 13);
    assert!(
        inventory
            .unresolved()
            .contains(&ManagerCapacityUnknown::ManagerWriteBounds)
    );
    assert!(
        inventory
            .destinations()
            .iter()
            .all(|entry| entry.anchor().is_some())
    );
    assert_eq!(inventory.manager(), ServiceManagerObservation::OpenRc);
    assert_eq!(options.path, "/run/openrc/options");
    assert_eq!(
        inventory
            .assess(&[PhaseBudget {
                charges: vec![AllocationCharge::ZERO; 13]
            }])
            .unwrap()
            .state,
        DiskBudgetState::Unknown
    );
}
