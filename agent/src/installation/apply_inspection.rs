//! Read-only preconditions for the official first-install apply path.

use super::{
    AdmittedOfficialArtifact, DiskBudgetState, EnrollmentTargetProof, InstallPlan,
    InstallPublicationReadiness, LayoutEntry, ManagerCapacityInventory, ManagerCapacityUnknown,
    ManagerEnablementEvidence, ManagerEnablementStatus, OfficialArtifactError, PlanError,
    ServiceObservation, TargetAdmissionError,
    host::inspect_host,
    layout::{CONTROL_NAME, inspect_layout, open_root, state_parent},
    plan_store::{check_directory, open_at},
    readiness::ControlCapacity,
    target_admission::inspect_target_admission,
};
use crate::{identity::Enrollment, release::manifest::PlatformCompatibility};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct FormalApplyConfirmation<'a> {
    pub plan_id: &'a str,
    pub target_id: &'a str,
    pub plan_digest: &'a str,
    /// Identity obtained independently from the intended management deployment.
    pub expected_deployment_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormalApplyInspectionError {
    Plan(PlanError),
    Artifact(OfficialArtifactError),
    Target(TargetAdmissionError),
}

#[derive(Debug, PartialEq, Eq)]
pub struct FormalApplyInspection {
    pub enrollment_target: EnrollmentTargetProof,
    pub startup_capacity: DiskBudgetState,
    pub manager_capacity_unresolved: Vec<ManagerCapacityUnknown>,
    pub manager_enablement: ManagerEnablementStatus,
    pub manager_enablement_required_inodes: Option<u64>,
}

/// Revalidate the confirmed plan, the held archive, this installer, and both
/// targets. The capacity finding remains unknown until the first-health
/// workload has an enforced bound. No installation effects are started here.
pub fn inspect_formal_apply(
    plan: &InstallPlan,
    confirmation: FormalApplyConfirmation<'_>,
    artifact: &AdmittedOfficialArtifact,
    enrollment: &Enrollment,
    explicit_ca: Option<&[u8]>,
) -> Result<FormalApplyInspection, FormalApplyInspectionError> {
    plan.check_confirmation(
        confirmation.plan_id,
        confirmation.target_id,
        confirmation.plan_digest,
        unix_ms().map_err(FormalApplyInspectionError::Plan)?,
    )
    .map_err(FormalApplyInspectionError::Plan)?;

    let package = plan
        .verify_apply_package(artifact.release(), artifact.archive())
        .map_err(FormalApplyInspectionError::Plan)?;
    artifact
        .verify_running_installer()
        .map_err(FormalApplyInspectionError::Artifact)?;
    let host = inspect_host();
    let compatibility = artifact.release().platform_compatibility(
        host.platform,
        host.kernel.as_ref().and_then(|kernel| kernel.version),
        host.libc,
    );
    match compatibility {
        PlatformCompatibility::Compatible => {}
        PlatformCompatibility::Incompatible => {
            return Err(FormalApplyInspectionError::Target(
                TargetAdmissionError::PlatformMismatch,
            ));
        }
        PlatformCompatibility::Unknown => {
            return Err(FormalApplyInspectionError::Target(
                TargetAdmissionError::HostUnavailable,
            ));
        }
    }
    let manager = plan.service_manager();
    let local = inspect_target_admission(plan, &host, manager, explicit_ca)
        .map_err(FormalApplyInspectionError::Target)?;
    let enrollment_target = local
        .prove_remote(enrollment, confirmation.expected_deployment_id)
        .map_err(FormalApplyInspectionError::Target)?;
    let publication = InstallPublicationReadiness::inspect(&package, manager);
    let manager_capacity = ManagerCapacityInventory::inspect(manager);
    let enablement = ManagerEnablementEvidence::inspect(manager);
    let layout = inspect_layout();
    let control_directory = if layout.control == LayoutEntry::Present {
        open_root()
            .ok()
            .and_then(|root| state_parent(&root, 0).ok())
            .and_then(|parent| {
                open_at(&parent, CONTROL_NAME, libc::O_RDONLY | libc::O_DIRECTORY).ok()
            })
            .filter(|directory| check_directory(directory, 0).is_ok())
    } else {
        None
    };
    let control = match (layout.control, control_directory.as_ref()) {
        (LayoutEntry::Missing, _) => ControlCapacity::Missing,
        (LayoutEntry::Present, Some(directory)) => ControlCapacity::Existing(directory),
        _ => ControlCapacity::Unavailable,
    };
    let fresh = layout.program == LayoutEntry::Missing
        && layout.state == LayoutEntry::Missing
        && publication.service == ServiceObservation::InterfaceObserved;
    let startup_capacity = if publication.definite_startup_shortage(
        &enablement,
        fresh.then_some((control, explicit_ca.is_some())),
    ) {
        DiskBudgetState::Insufficient
    } else {
        DiskBudgetState::Unknown
    };
    plan.check_validity(unix_ms().map_err(FormalApplyInspectionError::Plan)?)
        .map_err(FormalApplyInspectionError::Plan)?;
    Ok(FormalApplyInspection {
        enrollment_target,
        startup_capacity,
        manager_capacity_unresolved: manager_capacity.unresolved().to_vec(),
        manager_enablement: enablement.status(),
        manager_enablement_required_inodes: enablement.required_additional_inodes(),
    })
}

fn unix_ms() -> Result<u64, PlanError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(PlanError::InvalidTime)
}
