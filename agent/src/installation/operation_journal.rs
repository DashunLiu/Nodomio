//! First-install admission and results within the protected control record.
//!
//! Read-only lookups never restart an admitted operation. Only the original
//! executor may advance a writer, while holding the matching execution lease.
use super::control_record::{ControlRecord, PreparationClaim};
use super::startup_window::{StartupState, StartupWindow};
#[cfg(test)]
use super::{
    control_record::{ControlPhase, ControlRecordError, read_record, replace_business_record},
    plan::valid_plan_id,
    registration_recovery::{RegistrationRecoveryError, recover_original_registration},
};
use crate::identity::{Binding, IdentityStore, public_id, uuid};
#[cfg(test)]
use crate::protocol::AgentIdentity;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::{fs::File, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(test)]
mod tests;

const LAST_RFC3339_MILLISECOND: u64 = 253_402_300_799_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JournalError {
    InvalidConfirmation,
    #[cfg(test)]
    IdempotencyConflict,
    #[cfg(test)]
    OtherIntent,
    #[cfg(test)]
    PreparationNotReady,
    InvalidTime,
    #[cfg(test)]
    InvalidTransition,
    #[cfg(test)]
    WriterFenced,
    #[cfg(test)]
    Storage(ControlRecordError),
}

#[cfg(test)]
pub(super) struct InstallIntent {
    plan_id: String,
    plan_digest: String,
    target_id: String,
    idempotency_key: String,
}

#[cfg(test)]
impl InstallIntent {
    pub(super) fn new(
        plan_id: &str,
        plan_digest: &str,
        target_id: &str,
        idempotency_key: &str,
    ) -> Result<Self, JournalError> {
        if !valid_plan_id(plan_id)
            || !valid_plan_id(target_id)
            || !uuid(idempotency_key)
            || plan_digest.len() != 64
            || !plan_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(JournalError::InvalidConfirmation);
        }
        Ok(Self {
            plan_id: plan_id.into(),
            plan_digest: plan_digest.into(),
            target_id: target_id.into(),
            idempotency_key: idempotency_key.to_ascii_lowercase(),
        })
    }

    fn check(&self, claim: &PreparationClaim) -> Result<(), JournalError> {
        if self.idempotency_key != claim.idempotency_key {
            return Err(JournalError::OtherIntent);
        }
        if self.plan_id != claim.plan_id
            || self.plan_digest != claim.plan_digest
            || self.target_id != claim.installation_id
        {
            return Err(JournalError::IdempotencyConflict);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum BusinessPhase {
    Accepted,
    LocalPublicationPossible,
    LocalPublished,
    SupervisorLockCreatePossible,
    SupervisorLockReady,
    RegistrationPossible,
    IdentityConfirmed,
    ServiceStartPossible,
    Verifying,
}

impl BusinessPhase {
    fn number(self) -> u64 {
        match self {
            Self::Accepted => 1,
            Self::LocalPublicationPossible => 2,
            Self::LocalPublished => 3,
            Self::SupervisorLockCreatePossible => 4,
            Self::SupervisorLockReady => 5,
            Self::RegistrationPossible => 6,
            Self::IdentityConfirmed => 7,
            Self::ServiceStartPossible => 8,
            Self::Verifying => 9,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum InstallFailureCode {
    ApplyFailed,
    DiskInsufficient,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum BusinessState {
    Pending,
    Unknown,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BusinessOperation {
    revision: u64,
    phase: BusinessPhase,
    state: BusinessState,
    error_code: Option<InstallFailureCode>,
    updated_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration: Option<RegistrationCheckpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    startup: Option<StartupWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistrationCheckpoint {
    identity_operation_id: String,
    binding: Option<Binding>,
    #[serde(default, skip_serializing_if = "is_false")]
    recovered_from_unknown: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worker_boot_id: Option<String>,
}

fn is_false(flag: &bool) -> bool {
    !*flag
}

impl BusinessOperation {
    pub(super) fn startup_window(&self) -> Option<&StartupWindow> {
        self.startup.as_ref()
    }

    pub(super) fn startup_state(
        &self,
        identity: &IdentityStore,
    ) -> crate::identity::Result<StartupState> {
        let window = self.startup.as_ref().ok_or("INVALID_INSTALL_STARTUP")?;
        let registration = self
            .registration
            .as_ref()
            .ok_or("INVALID_INSTALL_STARTUP")?;
        if registration.identity_operation_id != identity.operation_id()
            || registration.binding.as_ref() != identity.binding()
        {
            return Err("INVALID_INSTALL_STARTUP");
        }
        match self.state {
            BusinessState::Succeeded => Ok(StartupState::Settled),
            BusinessState::Pending => {
                if !window.current_boot()? {
                    return Ok(StartupState::AwaitingTakeover);
                }
                window.remaining()?;
                Ok(StartupState::Pending(window.clone()))
            }
            _ => Err("INVALID_INSTALL_STARTUP"),
        }
    }

    pub(super) fn is_valid(&self) -> bool {
        let terminal_or_unknown = self.state != BusinessState::Pending;
        let recovered_from_unknown = self
            .registration
            .as_ref()
            .is_some_and(|registration| registration.recovered_from_unknown);
        self.updated_at_unix_ms <= LAST_RFC3339_MILLISECOND
            && self.revision
                == self.phase.number()
                    + u64::from(terminal_or_unknown)
                    + u64::from(recovered_from_unknown)
                    + self.startup.as_ref().map_or(0, StartupWindow::renewals)
            && self.registration.as_ref().is_none_or(|registration| {
                uuid(&registration.identity_operation_id)
                    && registration.worker_boot_id.as_deref().is_none_or(uuid)
                    && self.phase.number() >= BusinessPhase::RegistrationPossible.number()
                    && (registration.binding.is_some()
                        == (self.phase.number() >= BusinessPhase::IdentityConfirmed.number()))
                    && (!registration.recovered_from_unknown || registration.binding.is_some())
                    && registration.binding.as_ref().is_none_or(|binding| {
                        public_id(&binding.agent_id)
                            && public_id(&binding.server_id)
                            && binding.binding_revision != 0
                    })
            })
            && self.startup.as_ref().is_none_or(|window| {
                window.valid()
                    && self.phase.number() >= BusinessPhase::ServiceStartPossible.number()
                    && self
                        .registration
                        .as_ref()
                        .is_some_and(|value| value.binding.is_some())
            })
            && match self.state {
                BusinessState::Pending | BusinessState::Unknown => self.error_code.is_none(),
                BusinessState::Succeeded => {
                    self.phase == BusinessPhase::Verifying && self.error_code.is_none()
                }
                BusinessState::Failed => {
                    self.phase == BusinessPhase::Accepted
                        && matches!(
                            self.error_code,
                            Some(
                                InstallFailureCode::ApplyFailed
                                    | InstallFailureCode::DiskInsufficient
                            )
                        )
                }
            }
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision
    }

    pub(super) fn matches_target(&self, target: &crate::identity::Target) -> bool {
        self.registration
            .as_ref()
            .and_then(|registration| registration.binding.as_ref())
            .is_none_or(|binding| binding.server_id == target.expected_server_id)
    }

    #[cfg(test)]
    pub(super) fn pending_registration_id(&self) -> Option<&str> {
        if self.phase != BusinessPhase::RegistrationPossible
            || !matches!(self.state, BusinessState::Pending | BusinessState::Unknown)
        {
            return None;
        }
        self.registration
            .as_ref()
            .map(|registration| registration.identity_operation_id.as_str())
    }

    #[cfg(test)]
    pub(super) fn registration_boot_id(&self) -> Option<&str> {
        self.registration.as_ref()?.worker_boot_id.as_deref()
    }

    #[cfg(test)]
    pub(super) fn phase(&self) -> BusinessPhase {
        self.phase
    }

    #[cfg(test)]
    pub(super) fn can_follow(&self, previous: Option<&Self>) -> bool {
        if !self.is_valid() {
            return false;
        }
        let Some(previous) = previous else {
            return self.phase == BusinessPhase::Accepted && self.state == BusinessState::Pending;
        };
        // UNKNOWN used one revision without advancing phase. The original
        // registration proof may consume one more revision to confirm it.
        let recovering_unknown = previous.state == BusinessState::Unknown
            && previous.phase == BusinessPhase::RegistrationPossible
            && self.state == BusinessState::Pending
            && self.phase == BusinessPhase::IdentityConfirmed;
        let rebooted = self.state == BusinessState::Pending
            && self.phase == previous.phase
            && self
                .startup
                .as_ref()
                .zip(previous.startup.as_ref())
                .is_some_and(|(next, old)| next.follows_reboot(old));
        (previous.state == BusinessState::Pending || recovering_unknown)
            && self.revision.checked_sub(1) == Some(previous.revision)
            && self.updated_at_unix_ms >= previous.updated_at_unix_ms
            && (self.startup == previous.startup
                || rebooted
                || (previous.startup.is_none()
                    && self
                        .startup
                        .as_ref()
                        .is_some_and(|window| window.renewals() == 0)
                    && self.phase == BusinessPhase::ServiceStartPossible
                    && self.state == BusinessState::Pending))
            && match (&previous.registration, &self.registration) {
                (None, Some(_)) => {
                    !recovering_unknown && self.phase == BusinessPhase::RegistrationPossible
                }
                (Some(before), Some(after)) if before != after => {
                    self.phase == BusinessPhase::IdentityConfirmed
                        && before.binding.is_none()
                        && after.binding.is_some()
                        && before.identity_operation_id == after.identity_operation_id
                        && before.worker_boot_id == after.worker_boot_id
                        && after.recovered_from_unknown == recovering_unknown
                }
                (Some(_), None) => false,
                _ => !recovering_unknown,
            }
            && if self.state == BusinessState::Pending && !rebooted {
                self.phase.number() == previous.phase.number() + 1
            } else {
                self.phase == previous.phase
            }
    }

    fn result(&self, claim: &PreparationClaim) -> Result<InstallOperationResult, JournalError> {
        let updated_at = OffsetDateTime::from_unix_timestamp_nanos(
            i128::from(self.updated_at_unix_ms) * 1_000_000,
        )
        .map_err(|_| JournalError::InvalidTime)?
        .format(&Rfc3339)
        .map_err(|_| JournalError::InvalidTime)?;
        let (operation_state, stage, exit_code, error_code) = match self.state {
            BusinessState::Pending | BusinessState::Unknown => (
                "UNKNOWN",
                "RECOVERY_REQUIRED",
                6,
                Some(InstallFailureCode::OutcomeUnknown),
            ),
            BusinessState::Succeeded => ("SUCCEEDED", "COMPLETE", 0, None),
            BusinessState::Failed => ("FAILED", "STOPPED", 5, self.error_code),
        };
        Ok(InstallOperationResult {
            operation_id: claim.operation_id.clone(),
            target_id: claim.installation_id.clone(),
            action: "AGENT_INSTALL",
            operation_state,
            stage,
            exit_code,
            error_code,
            updated_at,
        })
    }
}

/// Operation result projection, with a timestamp retained in the original record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallOperationResult {
    operation_id: String,
    target_id: String,
    action: &'static str,
    operation_state: &'static str,
    stage: &'static str,
    exit_code: u8,
    error_code: Option<InstallFailureCode>,
    updated_at: String,
}

impl InstallOperationResult {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

fn observed_result(record: &ControlRecord) -> Result<Option<InstallOperationResult>, JournalError> {
    // Visibility is not a parent fsync acknowledgement. The writer fences on
    // an unconfirmed publication. Even a visible terminal result cannot admit
    // another intent, and an earlier nonterminal record still fences reexecution.
    record
        .business()
        .map(|business| business.result(record.claim()))
        .transpose()
}

#[cfg(test)]
pub(super) fn lookup_apply(
    directory: &File,
    intent: &InstallIntent,
) -> Result<Option<InstallOperationResult>, JournalError> {
    let record = read_record(directory).map_err(JournalError::Storage)?;
    intent.check(record.claim())?;
    observed_result(&record)
}

#[cfg(test)]
pub(super) fn lookup_status(
    directory: &File,
    operation_id: &str,
    target_id: &str,
) -> Result<Option<InstallOperationResult>, JournalError> {
    let record = read_record(directory).map_err(JournalError::Storage)?;
    result_by_id(&record, operation_id, target_id)
}

pub(super) fn result_by_id(
    record: &ControlRecord,
    operation_id: &str,
    target_id: &str,
) -> Result<Option<InstallOperationResult>, JournalError> {
    if !uuid(operation_id) || !uuid(target_id) {
        return Err(JournalError::InvalidConfirmation);
    }
    let claim = record.claim();
    if !claim.operation_id.eq_ignore_ascii_case(operation_id)
        || !claim.installation_id.eq_ignore_ascii_case(target_id)
    {
        return Ok(None);
    }
    observed_result(record)
}

#[cfg(test)]
pub(super) enum Admission<'a> {
    New(OperationJournal<'a>),
    Replay(InstallOperationResult),
}

/// Retains the expected original record while the caller's existing lease is held.
/// No write capability can be reconstructed from a replay or an observed phase.
#[cfg(test)]
pub(super) struct OperationJournal<'a> {
    directory: &'a File,
    record: ControlRecord,
    fenced: bool,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RegistrationTakeoverError {
    Recovery(RegistrationRecoveryError),
    Journal(JournalError),
}

/// The original executor's replacement holds the verified matching lease and
/// has checked drainage and the exact installed release and target. No writer
/// is returned until the GET proof is checked and IdentityConfirmed is durable.
#[cfg(test)]
pub(super) fn confirm_recovered_registration<'a>(
    control: &'a File,
    expected: &ControlRecord,
    state: &File,
    explicit_ca: Option<&[u8]>,
    timeout: Duration,
    now_ms: impl FnOnce() -> u64,
) -> Result<(AgentIdentity, OperationJournal<'a>), RegistrationTakeoverError> {
    use RegistrationTakeoverError::{Journal, Recovery};
    let observed = recover_original_registration(control, expected, state, explicit_ca, timeout)
        .map_err(Recovery)?;
    let previous = expected
        .business()
        .ok_or(Journal(JournalError::InvalidTransition))?;
    let identity_operation_id = previous
        .pending_registration_id()
        .ok_or(Journal(JournalError::InvalidTransition))?;
    let now_ms = now_ms();
    if now_ms > LAST_RFC3339_MILLISECOND {
        return Err(Journal(JournalError::InvalidTime));
    }
    let next = BusinessOperation {
        revision: previous.revision() + 1,
        phase: BusinessPhase::IdentityConfirmed,
        state: BusinessState::Pending,
        error_code: None,
        updated_at_unix_ms: now_ms.max(previous.updated_at_unix_ms),
        registration: Some(RegistrationCheckpoint {
            identity_operation_id: identity_operation_id.to_owned(),
            binding: Some(observed.binding()),
            recovered_from_unknown: previous.state == BusinessState::Unknown,
            worker_boot_id: previous.registration_boot_id().map(str::to_owned),
        }),
        startup: None,
    };
    let record = replace_business_record(control, expected, next)
        .map_err(|error| Journal(JournalError::Storage(error)))?;
    Ok((
        observed,
        OperationJournal {
            directory: control,
            record,
            fenced: false,
        },
    ))
}

#[cfg(test)]
impl<'a> OperationJournal<'a> {
    /// Fresh plan, source, target and lease verification belong to the trusted
    /// executor before this call. Replay never consumes those authorizations.
    pub(super) fn begin(
        directory: &'a File,
        expected: &ControlRecord,
        intent: &InstallIntent,
        now_ms: u64,
    ) -> Result<Admission<'a>, JournalError> {
        let current = read_record(directory).map_err(JournalError::Storage)?;
        intent.check(current.claim())?;
        if current.claim() != expected.claim() {
            return Err(JournalError::Storage(ControlRecordError::Conflict));
        }
        if let Some(result) = observed_result(&current)? {
            return Ok(Admission::Replay(result));
        }
        if current.phase() != ControlPhase::Ready {
            return Err(JournalError::PreparationNotReady);
        }
        if current != *expected {
            return Err(JournalError::Storage(ControlRecordError::Conflict));
        }
        if now_ms > LAST_RFC3339_MILLISECOND {
            return Err(JournalError::InvalidTime);
        }
        let business = BusinessOperation {
            revision: 1,
            phase: BusinessPhase::Accepted,
            state: BusinessState::Pending,
            error_code: None,
            updated_at_unix_ms: now_ms,
            registration: None,
            startup: None,
        };
        let record = replace_business_record(directory, &current, business)
            .map_err(JournalError::Storage)?;
        Ok(Admission::New(Self {
            directory,
            record,
            fenced: false,
        }))
    }

    pub(super) fn phase(&self) -> BusinessPhase {
        self.business().phase()
    }

    pub(super) fn resume_local_publication(
        directory: &'a File,
        expected: &ControlRecord,
    ) -> Result<Self, JournalError> {
        let current = read_record(directory).map_err(JournalError::Storage)?;
        if current != *expected || current.phase() != ControlPhase::Ready {
            return Err(JournalError::Storage(ControlRecordError::Conflict));
        }
        if !current.business().is_some_and(|business| {
            business.phase == BusinessPhase::LocalPublicationPossible
                && business.state == BusinessState::Pending
                && business.registration.is_none()
        }) {
            return Err(JournalError::InvalidTransition);
        }
        Ok(Self {
            directory,
            record: current,
            fenced: false,
        })
    }

    /// Return only after the corresponding phase marker has been synchronized.
    pub(super) fn advance(
        &mut self,
        phase: BusinessPhase,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        self.replace(phase, BusinessState::Pending, None, now_ms)
    }

    pub(super) fn mark_service_start_possible(
        &mut self,
        window: StartupWindow,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        self.replace_checkpoint(
            BusinessPhase::ServiceStartPossible,
            BusinessState::Pending,
            None,
            self.business().registration.clone(),
            Some(window),
            now_ms,
        )
    }

    /// The original executor must hold both locks and verify the published
    /// program, the registered identity, and a quiescent exact service first.
    pub(super) fn reopen_pending_service(
        directory: &'a File,
        expected: &ControlRecord,
    ) -> Result<Self, JournalError> {
        let current = read_record(directory).map_err(JournalError::Storage)?;
        if current != *expected || current.phase() != ControlPhase::Ready {
            return Err(JournalError::Storage(ControlRecordError::Conflict));
        }
        let business = current.business().ok_or(JournalError::InvalidTransition)?;
        if business.state != BusinessState::Pending
            || !matches!(
                business.phase,
                BusinessPhase::ServiceStartPossible | BusinessPhase::Verifying
            )
            || !business
                .startup
                .as_ref()
                .is_some_and(|window| window.current_boot() == Ok(false))
        {
            return Err(JournalError::InvalidTransition);
        }
        Ok(Self {
            directory,
            record: current,
            fenced: false,
        })
    }

    pub(super) fn renew_service_window(
        &mut self,
        now_ms: u64,
    ) -> Result<StartupWindow, JournalError> {
        let next = self
            .business()
            .startup
            .as_ref()
            .ok_or(JournalError::InvalidTransition)?
            .renew_after_reboot()
            .map_err(|_| JournalError::InvalidTransition)?;
        self.replace_checkpoint(
            self.phase(),
            BusinessState::Pending,
            None,
            self.business().registration.clone(),
            Some(next.clone()),
            now_ms,
        )?;
        Ok(next)
    }

    pub(super) fn registration_binding(&self) -> Option<&Binding> {
        self.business().registration.as_ref()?.binding.as_ref()
    }

    pub(super) fn mark_registration_possible(
        &mut self,
        identity_operation_id: &str,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        self.mark_registration_possible_with_boot(identity_operation_id, None, now_ms)
    }

    pub(super) fn mark_registration_possible_with_boot(
        &mut self,
        identity_operation_id: &str,
        worker_boot_id: Option<&str>,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        self.replace_with_registration(
            BusinessPhase::RegistrationPossible,
            BusinessState::Pending,
            None,
            Some(RegistrationCheckpoint {
                identity_operation_id: identity_operation_id.to_owned(),
                binding: None,
                recovered_from_unknown: false,
                worker_boot_id: worker_boot_id.map(str::to_owned),
            }),
            now_ms,
        )
    }

    pub(super) fn registration_operation_id(&self) -> Option<&str> {
        self.business()
            .registration
            .as_ref()
            .map(|registration| registration.identity_operation_id.as_str())
    }

    pub(super) fn confirm_registration(
        &mut self,
        binding: Binding,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        let identity_operation_id = self
            .registration_operation_id()
            .ok_or(JournalError::InvalidTransition)?
            .to_owned();
        self.replace_with_registration(
            BusinessPhase::IdentityConfirmed,
            BusinessState::Pending,
            None,
            Some(RegistrationCheckpoint {
                identity_operation_id,
                binding: Some(binding),
                recovered_from_unknown: false,
                worker_boot_id: self.business().registration_boot_id().map(str::to_owned),
            }),
            now_ms,
        )
    }

    /// The trusted executor must have verified registration, heartbeat,
    /// configuration application, and real ingestion before settlement.
    pub(super) fn settle_success(
        &mut self,
        now_ms: u64,
    ) -> Result<InstallOperationResult, JournalError> {
        self.replace(self.phase(), BusinessState::Succeeded, None, now_ms)?;
        self.result()
    }

    /// Only the still-active executor before its first effect may settle here.
    pub(super) fn settle_failed_before_effects(
        &mut self,
        code: InstallFailureCode,
        now_ms: u64,
    ) -> Result<InstallOperationResult, JournalError> {
        self.replace(self.phase(), BusinessState::Failed, Some(code), now_ms)?;
        self.result()
    }

    /// Preserve the original pending phase. Ordinary apply will only replay it.
    pub(super) fn mark_unknown(
        &mut self,
        now_ms: u64,
    ) -> Result<InstallOperationResult, JournalError> {
        self.replace(self.phase(), BusinessState::Unknown, None, now_ms)?;
        self.result()
    }

    fn business(&self) -> &BusinessOperation {
        self.record
            .business()
            .expect("a journal is returned only after business admission")
    }

    fn result(&self) -> Result<InstallOperationResult, JournalError> {
        self.business().result(self.record.claim())
    }

    fn replace(
        &mut self,
        phase: BusinessPhase,
        state: BusinessState,
        error_code: Option<InstallFailureCode>,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        self.replace_with_registration(
            phase,
            state,
            error_code,
            self.business().registration.clone(),
            now_ms,
        )
    }

    fn replace_with_registration(
        &mut self,
        phase: BusinessPhase,
        state: BusinessState,
        error_code: Option<InstallFailureCode>,
        registration: Option<RegistrationCheckpoint>,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        self.replace_checkpoint(
            phase,
            state,
            error_code,
            registration,
            self.business().startup.clone(),
            now_ms,
        )
    }

    fn replace_checkpoint(
        &mut self,
        phase: BusinessPhase,
        state: BusinessState,
        error_code: Option<InstallFailureCode>,
        registration: Option<RegistrationCheckpoint>,
        startup: Option<StartupWindow>,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        if self.fenced {
            return Err(JournalError::WriterFenced);
        }
        if now_ms > LAST_RFC3339_MILLISECOND {
            return Err(JournalError::InvalidTime);
        }
        let previous = self.business();
        if previous.state != BusinessState::Pending {
            return Err(JournalError::InvalidTransition);
        }
        let next = BusinessOperation {
            revision: previous.revision() + 1,
            phase,
            state,
            error_code,
            // Wall-clock corrections never order journal transitions.
            updated_at_unix_ms: now_ms.max(previous.updated_at_unix_ms),
            registration,
            startup,
        };
        if !next.can_follow(Some(previous)) {
            return Err(JournalError::InvalidTransition);
        }
        match replace_business_record(self.directory, &self.record, next) {
            Ok(record) => {
                self.record = record;
                Ok(())
            }
            Err(error) => {
                self.fenced = true;
                Err(JournalError::Storage(error))
            }
        }
    }
}
