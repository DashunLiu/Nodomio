//! SSH delivery for a caller-owned identity and queue.
pub mod dispatcher;

use crate::{
    buffer::{QueueTime, RejectionProgress, SshQueue, SshRejection},
    client::{
        ProtocolClient, SecurityEventRejection, SecurityEventUpload, SecurityEventUploadCompletion,
        SecurityEventUploadOutcome,
    },
    identity::{Binding, IdentityStore, Result, Target},
};
use std::time::{Duration, Instant};

const RETRY_SECONDS: [u64; 4] = [5, 10, 20, 30];

/// Outcomes count server acknowledgements separately from local isolation.
#[derive(Debug, PartialEq, Eq)]
pub enum SecurityEventStep {
    /// No sendable events. Isolated originals may still occupy queue space.
    Empty {
        quarantined: u64,
    },
    MaintenancePending,
    Waiting {
        remaining: Duration,
    },
    Acknowledged {
        accepted: u64,
        duplicate: u64,
        expired: u64,
    },
    Split,
    Quarantined,
    RetryScheduled {
        code: &'static str,
        remaining: Duration,
    },
    Stopped {
        code: &'static str,
    },
}

pub enum SecurityEventPreparation {
    Ready(SecurityEventRequest),
    Progress(SecurityEventStep),
}

/// A single authorized upload that can move to a network worker.
#[must_use]
pub struct SecurityEventRequest {
    token: String,
    upload: Box<SecurityEventUpload>,
}

/// The owner must apply this result to the sender and queue that prepared it.
#[must_use]
pub struct SecurityEventCompletion {
    token: String,
    upload: SecurityEventUploadCompletion,
}

impl SecurityEventRequest {
    pub fn send(self) -> SecurityEventCompletion {
        SecurityEventCompletion {
            token: self.token,
            upload: self.upload.send(),
        }
    }
}

struct SenderOwner {
    target: Target,
    binding: Binding,
    operation_id: String,
}

/// Keeps retry deadlines and stop state for a single live identity operation.
/// SQLite remains the owner of frozen batches and quarantine across restart.
#[derive(Default)]
pub struct SecurityEventSender {
    owner: Option<SenderOwner>,
    in_flight: Option<String>,
    retry_at: Option<Instant>,
    retry_index: usize,
    stopped: Option<&'static str>,
}

impl SecurityEventSender {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run at most one synchronous request using the caller's scheduling clock.
    pub fn step(
        &mut self,
        client: &ProtocolClient,
        identity: &mut IdentityStore,
        queue: &mut SshQueue,
        now: &QueueTime,
        at: Instant,
    ) -> Result<SecurityEventStep> {
        let started = Instant::now();
        match self.prepare(client, identity, queue, now, at)? {
            SecurityEventPreparation::Ready(request) => {
                let completed = request.send();
                let finished_at = at.checked_add(started.elapsed());
                self.apply_completion(client, identity, queue, completed, finished_at)
            }
            SecurityEventPreparation::Progress(step) => Ok(step),
        }
    }

    /// Freeze at most one request using fresh queue residence evidence. A retry
    /// wait performs no queue preparation. Pair each request with a completion
    /// or cancel it before sending. After abandoning a sent request, reopen the
    /// sender and queue once the worker has stopped.
    pub fn prepare(
        &mut self,
        client: &ProtocolClient,
        identity: &IdentityStore,
        queue: &mut SshQueue,
        now: &QueueTime,
        at: Instant,
    ) -> Result<SecurityEventPreparation> {
        if let Some(owner) = &self.owner
            && (&owner.target != identity.target()
                || Some(&owner.binding) != identity.binding()
                || owner.operation_id != identity.operation_id())
        {
            return Err("IDENTITY_MISMATCH");
        }
        if self.in_flight.is_some() {
            return Err("SSH_ATTEMPT_ACTIVE");
        }
        if let Some(code) = self.stopped {
            return Ok(SecurityEventPreparation::Progress(
                SecurityEventStep::Stopped { code },
            ));
        }
        queue.check_identity(identity)?;
        if self.owner.is_none() {
            self.owner = Some(SenderOwner {
                target: identity.target().clone(),
                binding: identity.binding().ok_or("IDENTITY_NOT_CONFIRMED")?.clone(),
                operation_id: identity.operation_id().to_owned(),
            });
        }
        if let Some(deadline) = self.retry_at
            && deadline > at
        {
            return Ok(SecurityEventPreparation::Progress(
                SecurityEventStep::Waiting {
                    remaining: deadline - at,
                },
            ));
        }

        let attempt = match queue.prepare(now) {
            Ok(Some(attempt)) => attempt,
            Ok(None) => {
                return Ok(SecurityEventPreparation::Progress(
                    SecurityEventStep::Empty {
                        quarantined: queue.quarantined_count()?,
                    },
                ));
            }
            Err("SSH_QUEUE_EXPIRY_PENDING") => {
                return Ok(SecurityEventPreparation::Progress(
                    SecurityEventStep::MaintenancePending,
                ));
            }
            Err(code) => return Err(code),
        };
        let upload = match client.prepare_security_event_upload(
            identity,
            &attempt.body,
            attempt.event_count,
        ) {
            Ok(upload) => upload,
            Err(code) => {
                queue.finish(&attempt.token, None)?;
                return Err(code);
            }
        };
        self.in_flight = Some(attempt.token.clone());
        Ok(SecurityEventPreparation::Ready(SecurityEventRequest {
            token: attempt.token,
            upload: Box::new(upload),
        }))
    }

    /// Release an unsent request. Its original batch stays durable.
    pub fn cancel(&mut self, queue: &mut SshQueue, request: SecurityEventRequest) -> Result<()> {
        self.check_active(&request.token)?;
        queue.finish(&request.token, None)?;
        self.in_flight = None;
        Ok(())
    }

    /// Apply a worker result on the owner thread. `at` is when the worker
    /// finished the request and starts any subsequent retry delay.
    pub fn complete(
        &mut self,
        client: &ProtocolClient,
        identity: &mut IdentityStore,
        queue: &mut SshQueue,
        completion: SecurityEventCompletion,
        at: Instant,
    ) -> Result<SecurityEventStep> {
        self.apply_completion(client, identity, queue, completion, Some(at))
    }

    fn apply_completion(
        &mut self,
        client: &ProtocolClient,
        identity: &mut IdentityStore,
        queue: &mut SshQueue,
        completion: SecurityEventCompletion,
        finished_at: Option<Instant>,
    ) -> Result<SecurityEventStep> {
        let SecurityEventCompletion { token, upload } = completion;
        self.check_active(&token)?;
        queue.check_attempt(&token)?;
        self.in_flight = None;
        let outcome = match client.finish_security_event_upload(identity, upload) {
            Ok(outcome) => outcome,
            Err(code) => {
                queue.finish(&token, None)?;
                return Err(code);
            }
        };

        match outcome {
            SecurityEventUploadOutcome::Acknowledged(ack) => {
                if let Err(code) = queue.finish(&token, Some(&ack)) {
                    queue.finish(&token, None)?;
                    return Err(code);
                }
                self.reset_retry();
                Ok(SecurityEventStep::Acknowledged {
                    accepted: ack.accepted_count,
                    duplicate: ack.duplicate_count,
                    expired: ack.expired_count,
                })
            }
            SecurityEventUploadOutcome::Failed {
                rejection: Some(rejection),
                ..
            } => {
                let reason = match rejection {
                    SecurityEventRejection::TooLarge => SshRejection::TooLarge,
                    SecurityEventRejection::Invalid => SshRejection::Invalid,
                    SecurityEventRejection::Conflict => SshRejection::Conflict,
                };
                let progress = match queue.reject(&token, reason) {
                    Ok(progress) => progress,
                    Err(code) => {
                        queue.finish(&token, None)?;
                        return Err(code);
                    }
                };
                self.reset_retry();
                match progress {
                    RejectionProgress::Split => Ok(SecurityEventStep::Split),
                    RejectionProgress::Quarantined => Ok(SecurityEventStep::Quarantined),
                }
            }
            SecurityEventUploadOutcome::Failed {
                code,
                retry_after,
                terminal,
                rejection: None,
            } => {
                queue.finish(&token, None)?;
                if terminal {
                    return Ok(self.stop(code));
                }
                let mut random = [0; 2];
                let jitter_ms = if getrandom::fill(&mut random).is_ok() {
                    u64::from(u16::from_ne_bytes(random) % 251)
                } else {
                    0
                };
                let delay = (Duration::from_secs(RETRY_SECONDS[self.retry_index])
                    + Duration::from_millis(jitter_ms))
                .max(retry_after.unwrap_or_default());
                let Some(deadline) = finished_at.and_then(|done| done.checked_add(delay)) else {
                    return Ok(self.stop("INVALID_RETRY_AFTER"));
                };
                self.retry_at = Some(deadline);
                self.retry_index = (self.retry_index + 1).min(RETRY_SECONDS.len() - 1);
                Ok(SecurityEventStep::RetryScheduled {
                    code,
                    remaining: delay,
                })
            }
        }
    }

    fn check_active(&self, token: &str) -> Result<()> {
        if self.in_flight.as_deref() == Some(token) {
            Ok(())
        } else {
            Err("STALE_SSH_ATTEMPT")
        }
    }

    fn reset_retry(&mut self) {
        self.retry_at = None;
        self.retry_index = 0;
    }

    fn stop(&mut self, code: &'static str) -> SecurityEventStep {
        self.stopped = Some(code);
        SecurityEventStep::Stopped { code }
    }
}
