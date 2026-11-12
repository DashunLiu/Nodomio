//! One first-install registration attempt and recovery of its exact identity.
//!
//! The installer owns the execution lease and pins the protected identity
//! location. The identity directory and its parent entry must already be
//! durable. This layer holds the identity lock and uses the existing private
//! credential store and fixed-target HTTPS protocol.
use super::plan::valid_plan_id;
use crate::{
    client::ProtocolClient,
    identity::{Enrollment, IdentityStore, Status, Target},
    protocol::{AgentIdentity, RegistrationMetadata},
};
use std::{path::Path, time::Duration};

#[cfg(test)]
mod tests;

const MAX_BINDING_REVISION: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RegistrationError {
    InvalidOriginalIdentity,
    /// Local setup or recovery could not be performed. This does not settle a
    /// registration that was already possible.
    Local(&'static str),
    OutcomeUnknown(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RegistrationAttemptError<E> {
    Local(&'static str),
    /// The marker failed or its durability could not be confirmed. No POST
    /// was sent by this capability.
    Marker(E),
    OutcomeUnknown(&'static str),
}

/// Consuming capability issued only by fresh, durable identity initialization.
/// Recovery never reconstructs this capability from a saved credential.
pub(super) struct PreparedRegistration {
    state: IdentityStore,
    client: ProtocolClient,
}

impl PreparedRegistration {
    pub(super) fn initialize(
        identity_path: &Path,
        target: Target,
        explicit_ca: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Self, RegistrationError> {
        let client = ProtocolClient::new_for_service(target.clone(), explicit_ca, timeout)
            .map_err(RegistrationError::Local)?;
        let state =
            IdentityStore::initialize(identity_path, target).map_err(RegistrationError::Local)?;
        Ok(Self { state, client })
    }

    /// The marker must durably bind this original install to the supplied
    /// nonsecret identity operation ID before it returns success. The caller
    /// can also refuse the marker if it observes a stop before that boundary.
    pub(super) fn register_once<E>(
        mut self,
        enrollment: Enrollment,
        metadata: &RegistrationMetadata,
        expected_deployment_id: Option<&str>,
        mark_possible: impl FnOnce(&str) -> Result<(), E>,
    ) -> Result<AgentIdentity, RegistrationAttemptError<E>> {
        metadata
            .validate()
            .map_err(RegistrationAttemptError::Local)?;
        mark_possible(self.state.operation_id()).map_err(RegistrationAttemptError::Marker)?;
        // The protocol also syncs UNCERTAIN with the same credential before
        // sending. A returned error after this marker permits only recovery.
        let observed = match expected_deployment_id {
            Some(id) => {
                self.client
                    .register_for_deployment(&mut self.state, &enrollment, metadata, id)
            }
            None => self.client.register(&mut self.state, &enrollment, metadata),
        }
        .map_err(RegistrationAttemptError::OutcomeUnknown)?;
        confirmed_identity(&self.state, observed).map_err(RegistrationAttemptError::OutcomeUnknown)
    }
}

/// Recover only under the original operation's validated marker. The expected
/// identity operation ID comes from that marker, independently of this store.
pub(super) fn recover_registration(
    identity_path: &Path,
    target: &Target,
    expected_identity_operation_id: &str,
    explicit_ca: Option<&[u8]>,
    timeout: Duration,
) -> Result<AgentIdentity, RegistrationError> {
    if !valid_plan_id(expected_identity_operation_id) {
        return Err(RegistrationError::InvalidOriginalIdentity);
    }
    let mut state = IdentityStore::open(identity_path, target).map_err(RegistrationError::Local)?;
    if state.operation_id() != expected_identity_operation_id {
        return Err(RegistrationError::InvalidOriginalIdentity);
    }
    if state
        .binding()
        .is_some_and(|binding| !(1..=MAX_BINDING_REVISION).contains(&binding.binding_revision))
    {
        return Err(RegistrationError::InvalidOriginalIdentity);
    }
    let client = ProtocolClient::new_for_service(target.clone(), explicit_ca, timeout)
        .map_err(RegistrationError::Local)?;
    // Only the existing long-term credential can authorize this GET. A 401
    // alone cannot establish the result of the old registration request.
    let observed = client
        .query_identity(&mut state)
        .map_err(RegistrationError::OutcomeUnknown)?;
    confirmed_identity(&state, observed).map_err(RegistrationError::OutcomeUnknown)
}

fn confirmed_identity(
    state: &IdentityStore,
    observed: AgentIdentity,
) -> Result<AgentIdentity, &'static str> {
    if state.status() != Status::Bound
        || observed.server_id != state.target().expected_server_id
        || state.binding() != Some(&observed.binding())
        || !(1..=MAX_BINDING_REVISION).contains(&observed.binding_revision)
    {
        return Err("IDENTITY_MISMATCH");
    }
    Ok(observed)
}
