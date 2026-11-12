//! Transactional SSH admission and bounded reuse of pages from old records.
use super::{
    Admission, BudgetGuard, MAX_BATCH, MAX_REQUEST, QueueTime, Result, SourcePosition, State,
    commit_write, parse_event,
    source_position::{PendingPosition, PositionOutcome},
    storage, write_storage, write_transaction,
};
use ring::digest::{Digest, SHA256, digest};
use rusqlite::{Connection, Transaction, params};

pub(super) struct PendingAdmission<'a> {
    position: PendingPosition<'a>,
    body: &'a [u8],
    now: &'a QueueTime,
    id: String,
    fingerprint: Digest,
    payload_limit: i64,
}

#[derive(Clone, Copy)]
struct Victim {
    id: i64,
    bytes: i64,
}

enum Staged {
    Stored,
    AlreadyCheckpointed,
    Full,
}

impl<'a> PendingAdmission<'a> {
    pub(super) fn new(
        position: &'a SourcePosition,
        body: &'a [u8],
        now: &'a QueueTime,
        payload_limit: i64,
    ) -> Result<Self> {
        Ok(Self {
            position: PendingPosition::new(position)?,
            body,
            now,
            id: parse_event(body)?.event_id.to_ascii_lowercase(),
            fingerprint: digest(&SHA256, body),
            payload_limit,
        })
    }

    pub(super) fn enqueue(
        &self,
        connection: &mut Connection,
        budget: Option<&BudgetGuard<'_>>,
        recovery_required: &mut bool,
    ) -> Result<Admission> {
        if let Some(admission) = self.attempt(connection, budget, recovery_required, &[])? {
            return Ok(admission);
        }
        // This limit is already installed by write_transaction. A body larger
        // than the entire allowed main file cannot fit even if all rows go away.
        let page_size: u32 = connection
            .pragma_query_one(None, "page_size")
            .map_err(storage)?;
        let max_pages: u32 = connection
            .pragma_query_one(None, "max_page_count")
            .map_err(storage)?;
        if self.body.len() as u64 > u64::from(page_size) * u64::from(max_pages) {
            return Err("SSH_QUEUE_RESOURCE_LIMIT");
        }
        let victims = oldest_victims(connection)?;
        if victims.is_empty() {
            return Err("SSH_QUEUE_RESOURCE_LIMIT");
        }

        // Deleting one short row may leave its page occupied. Probe increasing
        // FIFO prefixes, bounded by one batch of row metadata and body bytes.
        // Every failed probe rolls back before the next transaction starts.
        let mut count = 1;
        loop {
            if let Some(admission) =
                self.attempt(connection, budget, recovery_required, &victims[..count])?
            {
                return Ok(admission);
            }
            if count == victims.len() {
                return Err("SSH_QUEUE_RESOURCE_LIMIT");
            }
            count = (count * 2).min(victims.len());
        }
    }

    fn attempt(
        &self,
        connection: &mut Connection,
        budget: Option<&BudgetGuard<'_>>,
        recovery_required: &mut bool,
        victims: &[Victim],
    ) -> Result<Option<Admission>> {
        let transaction = write_transaction(connection, budget, false)?;
        let shared = budget.is_some();
        let result = match self.stage(&transaction, shared, victims) {
            Ok(Staged::Stored) => {
                #[cfg(test)]
                if !victims.is_empty() {
                    super::BEFORE_CAPACITY_COMMIT.with(|hook| {
                        if let Some(pause) = hook.take() {
                            pause();
                        }
                    });
                }
                commit_write(transaction, budget, recovery_required)?;
                return Ok(Some(Admission::Stored));
            }
            Ok(Staged::AlreadyCheckpointed) => Ok(Some(Admission::AlreadyCheckpointed)),
            Ok(Staged::Full) => Ok(None),
            Err(code) => Err(code),
        };
        if shared {
            // SQLite can roll back an entire transaction on SQLITE_FULL.
            // finish checks autocommit before issuing a rollback and reports
            // cleanup errors so no later attempt runs in an uncertain state.
            if transaction.finish().is_err() {
                *recovery_required = true;
                return Err("SSH_QUEUE_RECOVERY_REQUIRED");
            }
        }
        result
    }

    fn stage(
        &self,
        transaction: &Transaction<'_>,
        shared: bool,
        victims: &[Victim],
    ) -> Result<Staged> {
        if self.is_already_checkpointed(transaction)? {
            return Ok(Staged::AlreadyCheckpointed);
        }
        let mut state = State::read(transaction)?;
        let protected = protected_prefix(&state);
        let reclaimed: i64 = victims.iter().map(|victim| victim.bytes).sum();
        if victims.iter().any(|victim| victim.id <= protected) || reclaimed > state.payload_bytes {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        let remaining = state.payload_bytes - reclaimed;
        let bytes = self.body.len() as i64;
        if bytes > self.payload_limit.saturating_sub(remaining) {
            return Err("SSH_QUEUE_RESOURCE_LIMIT");
        }
        state.advance_clock(self.now)?;
        state.payload_bytes = remaining + bytes;
        state.capacity_discarded_count = state
            .capacity_discarded_count
            .checked_add(victims.len() as i64)
            .ok_or("SSH_QUEUE_RESOURCE_LIMIT")?;

        match self.write(transaction, state, shared, victims) {
            Ok(()) => Ok(Staged::Stored),
            Err("SSH_QUEUE_RESOURCE_LIMIT") if shared => Ok(Staged::Full),
            Err(code) => Err(code),
        }
    }

    fn is_already_checkpointed(&self, transaction: &Transaction<'_>) -> Result<bool> {
        if self
            .position
            .already_checkpointed(transaction, self.outcome())?
        {
            return Ok(true);
        }

        let occupied: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ssh_events WHERE event_id=?1)
                    OR EXISTS(SELECT 1 FROM source_checkpoints WHERE last_event_id=?1)",
                [&self.id],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if occupied {
            return Err("SSH_EVENT_CONFLICT");
        }
        Ok(false)
    }

    fn outcome(&self) -> PositionOutcome<'_> {
        PositionOutcome::Event {
            id: &self.id,
            fingerprint: self.fingerprint.as_ref(),
        }
    }

    fn write(
        &self,
        transaction: &Transaction<'_>,
        mut state: State,
        shared: bool,
        victims: &[Victim],
    ) -> Result<()> {
        let write_error = |error| write_storage(error, shared);
        if !victims.is_empty() {
            let mut delete = transaction
                .prepare(
                    "DELETE FROM ssh_events WHERE id=?1 AND quarantine_code IS NULL AND length(body)=?2",
                )
                .map_err(storage)?;
            for victim in victims {
                if delete
                    .execute(params![victim.id, victim.bytes])
                    .map_err(write_error)?
                    != 1
                {
                    return Err("INVALID_SSH_QUEUE_STATE");
                }
            }
        }
        transaction
            .execute(
                "INSERT INTO ssh_events(event_id,admitted_ns,body) VALUES (?1,?2,?3)",
                params![self.id, state.elapsed_ns, self.body],
            )
            .map_err(write_error)?;
        self.position.write(transaction, self.outcome(), shared)?;
        state.write(transaction, shared)
    }
}

fn protected_prefix(state: &State) -> i64 {
    state
        .flight
        .map_or(0, |flight| flight.last)
        .max(state.isolation_last.unwrap_or(0))
}

fn oldest_victims(connection: &Connection) -> Result<Vec<Victim>> {
    let state = State::read(connection)?;
    // The ready index gives the same FIFO as prepare. Only a suffix after the
    // durable flight and any in-progress isolation range can supply victims.
    let mut select = connection
        .prepare(
            "SELECT id,length(body) FROM ssh_events INDEXED BY ssh_events_ready
             WHERE id>?1 AND quarantine_code IS NULL ORDER BY id LIMIT ?2",
        )
        .map_err(storage)?;
    let mut rows = select
        .query(params![protected_prefix(&state), MAX_BATCH as i64])
        .map_err(storage)?;
    let mut victims = Vec::new();
    let mut bytes = 0;
    while let Some(row) = rows.next().map_err(storage)? {
        let victim = Victim {
            id: row.get(0).map_err(storage)?,
            bytes: row.get(1).map_err(storage)?,
        };
        if !(1..=MAX_REQUEST as i64).contains(&victim.bytes) {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        bytes += victim.bytes;
        if bytes > MAX_REQUEST as i64 {
            break;
        }
        victims.push(victim);
    }
    Ok(victims)
}
