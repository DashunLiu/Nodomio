use super::*;
use crate::installation::{AllocationFilesystem, QuotaObservation};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn make_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    root
}
fn mkdir(root: &std::path::Path, path: &str) {
    let mut current = root.to_path_buf();
    for component in path.split('/') {
        current.push(component);
        if !current.exists() {
            fs::create_dir(&current).unwrap();
        }
        fs::set_permissions(&current, fs::Permissions::from_mode(0o755)).unwrap();
    }
}
fn inspect(
    root: &std::path::Path,
    manager: ServiceManagerObservation,
) -> ManagerEnablementEvidence {
    inspect_at(
        &File::open(root).unwrap(),
        super::super::super::super::plan_store::effective_uid(),
        manager,
    )
}

#[test]
fn missing_parent_and_link_counts_do_not_create_or_claim_byte_bounds() {
    for (manager, parent, name) in [
        (
            ServiceManagerObservation::Systemd,
            "etc/systemd/system/multi-user.target.wants",
            "nodomi-agent.service",
        ),
        (
            ServiceManagerObservation::OpenRc,
            "etc/runlevels/default",
            "nodomi-agent",
        ),
    ] {
        let root = make_root();
        let observed = inspect(root.path(), manager);
        assert_eq!(
            observed.status(),
            ManagerEnablementStatus::ParentDirectoriesAbsent
        );
        assert_eq!(observed.missing_directories(), parent.split('/').count());
        assert_eq!(
            observed.required_additional_inodes(),
            Some(parent.split('/').count() as u64 + 1)
        );
        assert!(!root.path().join("etc").exists());
        mkdir(root.path(), parent);
        let observed = inspect(root.path(), manager);
        assert_eq!(observed.status(), ManagerEnablementStatus::LinkAbsent);
        assert_eq!(observed.required_additional_inodes(), Some(1));
        assert_eq!(observed.allocated_byte_upper_bound(), None);
        assert_eq!(
            observed.assess_minimum().unwrap().state,
            DiskBudgetState::Unknown
        );
        assert!(!root.path().join(parent).join(name).exists());
    }
}

#[test]
fn exact_links_are_observations_but_conflicts_never_become_zero_cost() {
    let root = make_root();
    let parent = "etc/systemd/system/multi-user.target.wants";
    mkdir(root.path(), parent);
    let link = root.path().join(parent).join("nodomi-agent.service");
    for target in [
        "../nodomi-agent.service",
        "/etc/systemd/system/nodomi-agent.service",
    ] {
        symlink(target, &link).unwrap();
        let observed = inspect(root.path(), ServiceManagerObservation::Systemd);
        assert_eq!(
            observed.status(),
            ManagerEnablementStatus::ExpectedLinkPresent
        );
        assert_eq!(observed.required_additional_inodes(), Some(0));
        assert!(observed.existing_link_allocated_bytes().is_some());
        assert_eq!(observed.allocated_byte_upper_bound(), None);
        fs::remove_file(&link).unwrap();
    }
    symlink("/wrong-target", &link).unwrap();
    let conflict = inspect(root.path(), ServiceManagerObservation::Systemd);
    assert_eq!(
        conflict.status(),
        ManagerEnablementStatus::ConflictingObject
    );
    assert_eq!(conflict.required_additional_inodes(), None);
    assert_eq!(
        conflict.assess_minimum().unwrap().state,
        DiskBudgetState::Unknown
    );
    fs::remove_file(&link).unwrap();
    fs::write(&link, b"not a symlink").unwrap();
    assert_eq!(
        inspect(root.path(), ServiceManagerObservation::Systemd).status(),
        ManagerEnablementStatus::ConflictingObject
    );
}

#[test]
fn untrusted_parent_is_not_allocation_authority() {
    let root = make_root();
    mkdir(root.path(), "etc/runlevels/default");
    fs::set_permissions(
        root.path().join("etc/runlevels"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let observed = inspect(root.path(), ServiceManagerObservation::OpenRc);
    assert_eq!(observed.status(), ManagerEnablementStatus::UnsafeParent);
    assert_eq!(observed.required_additional_inodes(), None);
    fs::set_permissions(
        root.path().join("etc/runlevels"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::remove_dir(root.path().join("etc/runlevels/default")).unwrap();
    symlink(root.path(), root.path().join("etc/runlevels/default")).unwrap();
    assert_eq!(
        inspect(root.path(), ServiceManagerObservation::OpenRc).status(),
        ManagerEnablementStatus::UnsafeParent
    );
}

#[test]
fn only_proven_allocator_can_reject_known_inode_minimum() {
    let root = make_root();
    mkdir(root.path(), "etc/runlevels/default");
    let mut evidence = inspect(root.path(), ServiceManagerObservation::OpenRc);
    let allocation = evidence.allocation.as_mut().unwrap();
    // Synthetic arithmetic proof only; not fabricated production host evidence.
    allocation.filesystem = AllocationFilesystem::Ext;
    allocation.mount_verified = true;
    allocation.mount_id = Some(1);
    allocation.space.device = 1;
    allocation.space.available_inodes = Some(0);
    allocation.quotas = [QuotaObservation::Disabled; 3];
    assert_eq!(
        evidence.assess_minimum().unwrap().state,
        DiskBudgetState::Insufficient
    );
    evidence.allocation.as_mut().unwrap().space.available_inodes = Some(1);
    assert_eq!(
        evidence.assess_minimum().unwrap().state,
        DiskBudgetState::Unknown
    );
    let allocation = evidence.allocation.as_mut().unwrap();
    allocation.space.available_inodes = Some(0);
    allocation.filesystem = AllocationFilesystem::Unsupported;
    assert_eq!(
        evidence.assess_minimum().unwrap().state,
        DiskBudgetState::Unknown
    );
}

#[test]
#[ignore = "requires disposable ext4 volume at /enablement-proof"]
fn isolated_ext4_link_allocations_are_snapshots_not_upper_bounds() {
    let root = tempfile::tempdir_in("/enablement-proof").unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    for (manager, parent, name, target) in [
        (
            ServiceManagerObservation::Systemd,
            "etc/systemd/system/multi-user.target.wants",
            "nodomi-agent.service",
            "../nodomi-agent.service",
        ),
        (
            ServiceManagerObservation::OpenRc,
            "etc/runlevels/default",
            "nodomi-agent",
            "../../init.d/nodomi-agent",
        ),
    ] {
        mkdir(root.path(), parent);
        let before = inspect(root.path(), manager);
        assert!(before.allocation().unwrap().proven_pool());
        assert_eq!(before.required_additional_inodes(), Some(1));
        symlink(target, root.path().join(parent).join(name)).unwrap();
        let after = inspect(root.path(), manager);
        assert_eq!(after.status(), ManagerEnablementStatus::ExpectedLinkPresent);
        assert_eq!(after.required_additional_inodes(), Some(0));
        println!(
            "{manager:?}: exact link allocated snapshot {:?} bytes; upper bound {:?}; assessment {:?}",
            after.existing_link_allocated_bytes(),
            after.allocated_byte_upper_bound(),
            after.assess_minimum().unwrap().state
        );
        assert_eq!(
            after.assess_minimum().unwrap().state,
            DiskBudgetState::Unknown
        );
    }
}
