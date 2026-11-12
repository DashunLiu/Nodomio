//! First-install observations and protected plan and control records.

mod allocation_admission;
mod apply_inspection;
mod control;
mod control_record;
mod disk_budget;
mod executable;
mod filesystem_readiness;
mod health_confirmation;
mod host;
#[cfg(test)]
mod install_state;
mod layout;
mod official_artifact;
mod operation_journal;
mod package;
mod plan;
mod plan_store;
#[cfg(test)]
mod preparation;
mod readiness;
#[cfg(test)]
mod registration;
#[cfg(test)]
mod registration_recovery;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "only the read-only configuration check is used by apply inspection"
    )
)]
mod service_activation;
mod service_readiness;
#[cfg(test)]
mod staging;
mod startup_budget;
mod startup_window;
mod target_admission;

pub use allocation_admission::{
    AllocationFilesystem, AllocationObservation, QuotaObservation, assess_allocation,
    assess_publication_lower_bound, observe_allocation,
};
pub use apply_inspection::{
    FormalApplyConfirmation, FormalApplyInspection, FormalApplyInspectionError,
    inspect_formal_apply,
};
pub use control::{
    InstallControlObservation, InstallPreparationLookup, InstallStatusError,
    inspect_install_control, lookup_install_operation, lookup_install_preparation,
};
pub use disk_budget::{
    AllocationCharge, ArchiveStorage, DestinationBudget, DirectorySpace, DiskAssessment,
    DiskBudgetError, DiskBudgetReason, DiskBudgetState, FileAllocationProfile, PackageDiskInputs,
    PhaseBudget, PoolBudget, QuotaEvidence, assess_budget, file_charge, observe_directory,
};
pub use executable::{
    EXECUTABLE_PREFIX_BYTES, ElfKind, ExecutableError, ExecutableHeader, inspect_executable,
};
pub use filesystem_readiness::{
    FilesystemObservation, InstallFilesystemReadiness, inspect_filesystem_readiness,
};
pub use health_confirmation::{
    HealthConfirmationStore, HealthContext, HealthTracker, health_boottime_ns,
};
pub use host::{InstallHost, KernelObservation, ServiceManagerObservation};
pub use layout::{InstallLayout, LayoutEntry};
pub use official_artifact::{
    AdmittedOfficialArtifact, OfficialArtifactError, admit_official_artifact,
};
pub use operation_journal::InstallOperationResult;
pub use package::{
    FormalPackage, FormalPackageMember, PackageInspectionError, RehearsalPackage,
    inspect_formal_package, inspect_rehearsal_package, verify_formal_package,
};
pub use plan::{InstallPlan, InstallPlanInput, InstallPlanPreview, InstallUpdateMode, PlanError};
pub use plan_store::{InstallPlanStore, PlanStoreError};
pub use readiness::{InstallPublicationReadiness, ServiceObservation};
pub use startup_budget::{
    ConfiguredLogStream, ManagerCapacityDestination, ManagerCapacityInventory,
    ManagerCapacityUnknown, ManagerDestinationRole, ManagerDestinationStatus,
    ManagerEnablementEvidence, ManagerEnablementStatus, StartupBudgetError, StartupBudgetEvidence,
    StartupBudgetProfile, StartupComponent, StartupComponentBudget, StartupFootprintSnapshot,
    StartupStage, StartupWorkloadLimits, SystemdLoggingError, SystemdLoggingObservation,
    assess_startup_budget, measure_startup_tree,
};
pub use startup_window::{
    AWAITING_INSTALL_TAKEOVER_EXIT, StartupState, StartupWindow, read_startup_state,
};
pub use target_admission::{EnrollmentTargetProof, TargetAdmissionError};

#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallPreflight {
    pub host: InstallHost,
    pub layout: InstallLayout,
}

/// Observe the current Linux namespace and the fixed installation layout.
pub fn inspect_first_install() -> InstallPreflight {
    InstallPreflight {
        host: host::inspect_host(),
        layout: layout::inspect_layout(),
    }
}

/// Maximum serialized size of the local service settings file.
pub const MAX_SERVICE_SETTINGS_BYTES: usize = 4096;

/// Validate a bounded certificate-only bundle before persisting or using it.
pub fn validate_service_ca(bytes: &[u8]) -> crate::identity::Result<()> {
    if bytes.len() > 65_536 {
        return Err("INVALID_CA");
    }
    let mut inside = false;
    for line in bytes.split(|byte| *byte == b'\n') {
        match line.trim_ascii() {
            b"-----BEGIN CERTIFICATE-----" if !inside => inside = true,
            b"-----END CERTIFICATE-----" if inside => inside = false,
            b"" if !inside => {}
            line if inside
                && !line.is_empty()
                && line
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(b)) => {}
            _ => return Err("INVALID_CA"),
        }
    }
    if inside
        || reqwest::Certificate::from_pem_bundle(bytes)
            .map_err(|_| "INVALID_CA")?
            .is_empty()
    {
        return Err("INVALID_CA");
    }
    Ok(())
}
