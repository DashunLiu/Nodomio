//! One worker for prepared uploads. The owner schedules queues and applies results.
use super::{SecurityEventCompletion, SecurityEventRequest};
use crate::{
    client::{MetricUpload, MetricUploadCompletion, ProtocolClient},
    identity::{IdentityStore, Result},
    runtime::StoredSample,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, sync_channel},
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryKind {
    Host,
    Ssh,
}

impl DeliveryKind {
    fn other(self) -> Self {
        match self {
            Self::Host => Self::Ssh,
            Self::Ssh => Self::Host,
        }
    }
}

pub enum DeliveryCompletion {
    Host {
        sample_id: String,
        finished_at: Instant,
        completion: MetricUploadCompletion,
    },
    Ssh {
        finished_at: Instant,
        completion: SecurityEventCompletion,
    },
}

enum Job {
    Host {
        sample_id: String,
        upload: Box<MetricUpload>,
    },
    Ssh(SecurityEventRequest),
}

impl Job {
    fn kind(&self) -> DeliveryKind {
        match self {
            Self::Host { .. } => DeliveryKind::Host,
            Self::Ssh(_) => DeliveryKind::Ssh,
        }
    }

    fn send(self) -> DeliveryCompletion {
        match self {
            Self::Host { sample_id, upload } => {
                let completion = upload.send();
                DeliveryCompletion::Host {
                    sample_id,
                    finished_at: Instant::now(),
                    completion,
                }
            }
            Self::Ssh(request) => {
                let completion = request.send();
                DeliveryCompletion::Ssh {
                    finished_at: Instant::now(),
                    completion,
                }
            }
        }
    }
}

/// At most one request may be submitted before its completion is taken.
pub struct DeliveryDispatcher {
    jobs: SyncSender<Job>,
    completed: Receiver<DeliveryCompletion>,
    active: Option<DeliveryKind>,
    preferred: DeliveryKind,
    stop: Arc<AtomicBool>,
}

impl Drop for DeliveryDispatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

impl DeliveryDispatcher {
    /// Probe the first ready queue in this order. Only a submission advances
    /// the preference, so an empty or backing-off queue can be skipped.
    pub fn preferred_order(&self) -> [DeliveryKind; 2] {
        [self.preferred, self.preferred.other()]
    }

    /// The kind submitted, including a completion the owner has yet to take.
    pub fn active_kind(&self) -> Option<DeliveryKind> {
        self.active
    }

    /// Prepare the request and its completion ID from the same durable sample
    /// on the owner thread before handing off to the worker.
    pub fn submit_host(
        &mut self,
        client: &ProtocolClient,
        identity: &IdentityStore,
        sample: StoredSample,
    ) -> Result<()> {
        self.ensure_idle()?;
        let upload = client.prepare_metric_upload(identity, &sample)?;
        self.submit(Job::Host {
            sample_id: sample.sample_id,
            upload: Box::new(upload),
        })
    }

    /// Prepare only while idle. A failed handoff consumes the request, so the
    /// owner must exit and reopen the queue to recover the durable batch.
    pub fn submit_ssh(&mut self, request: SecurityEventRequest) -> Result<()> {
        self.ensure_idle()?;
        self.submit(Job::Ssh(request))
    }

    fn ensure_idle(&self) -> Result<()> {
        if self.active.is_some() {
            return Err("DELIVERY_ATTEMPT_ACTIVE");
        }
        Ok(())
    }

    fn submit(&mut self, job: Job) -> Result<()> {
        let kind = job.kind();
        self.jobs
            .try_send(job)
            .map_err(|_| "DELIVERY_WORKER_UNAVAILABLE")?;
        self.active = Some(kind);
        self.preferred = kind.other();
        Ok(())
    }

    pub fn take_completion(&mut self) -> Result<Option<DeliveryCompletion>> {
        let completion = match self.completed.try_recv() {
            Ok(completion) => completion,
            Err(TryRecvError::Empty) => return Ok(None),
            Err(TryRecvError::Disconnected) => return Err("DELIVERY_WORKER_UNAVAILABLE"),
        };
        let kind = match &completion {
            DeliveryCompletion::Host { .. } => DeliveryKind::Host,
            DeliveryCompletion::Ssh { .. } => DeliveryKind::Ssh,
        };
        if self.active != Some(kind) {
            return Err("UNKNOWN_DELIVERY_ATTEMPT");
        }
        self.active = None;
        Ok(Some(completion))
    }
}

/// Close both channels on owner exit, then join the worker. The worker may
/// finish an already-started request, and only the owner can apply its result.
pub fn with_delivery_dispatcher<T>(
    run: impl FnOnce(&mut DeliveryDispatcher) -> Result<T>,
) -> Result<T> {
    std::thread::scope(|scope| {
        let (jobs, incoming) = sync_channel::<Job>(1);
        let (finished, completed) = sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::Builder::new()
            .name("nodomi-data-upload".into())
            .spawn_scoped(scope, move || {
                while let Ok(job) = incoming.recv() {
                    if worker_stop.load(Ordering::Acquire) || finished.send(job.send()).is_err() {
                        break;
                    }
                }
            })
            .map_err(|_| "DELIVERY_WORKER_UNAVAILABLE")?;
        let mut dispatcher = DeliveryDispatcher {
            jobs,
            completed,
            active: None,
            preferred: DeliveryKind::Host,
            stop,
        };
        let result = run(&mut dispatcher);
        drop(dispatcher);
        let joined = worker.join().map_err(|_| "DELIVERY_WORKER_UNAVAILABLE");
        result.and_then(|value| joined.map(|()| value))
    })
}
