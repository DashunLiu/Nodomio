//! Durable SSH source position and final record disposition.
use super::{
    Admission, MAX_CURSOR, MAX_STREAMS, Result, SourcePosition, SshQueue, commit_write, identity,
    lock_write, storage, write_storage, write_transaction,
};
#[cfg(any(target_os = "linux", test))]
use crate::protocol::SshGapReason;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceGap {
    pub(crate) reason: SshGapReason,
    pub(crate) detected_at: i64,
    pub(crate) recovered_at: Option<i64>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct SourceRecovery {
    pub(crate) witness: Option<Vec<u8>>,
    pub(crate) gap: Option<SourceGap>,
}

#[cfg(any(target_os = "linux", test))]
fn gap_reason_code(reason: SshGapReason) -> i64 {
    // These values are persisted by the queue schema.
    match reason {
        SshGapReason::SourceRetention => 1,
        SshGapReason::FileTruncation => 2,
        SshGapReason::SourceReset => 3,
        SshGapReason::SourceSwitch => 4,
    }
}

/// A complete source record that the reader has decided to skip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceDisposition {
    Ignored,
    UnknownFormat,
    Oversized,
}

impl SourceDisposition {
    fn code(self) -> [u8; 1] {
        // These values are persisted by the queue schema.
        match self {
            Self::Ignored => [1],
            Self::UnknownFormat => [2],
            Self::Oversized => [3],
        }
    }
}

/// The current collector epoch's durable source counts. A missing count
/// means overflow made that field unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshSourceCounters {
    pub unknown_format_records_total: Option<u64>,
    pub oversized_records_total: Option<u64>,
}

impl SshSourceCounters {
    pub fn is_complete(&self) -> bool {
        self.unknown_format_records_total.is_some() && self.oversized_records_total.is_some()
    }

    fn read(connection: &Connection, epoch: &str) -> Result<Self> {
        let (stored_epoch, counts) = connection
            .query_row(
                "SELECT source_counter_epoch,unknown_format_records_total,oversized_records_total
                 FROM queue_state WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        Self {
                            unknown_format_records_total: row
                                .get::<_, Option<[u8; 8]>>(1)?
                                .map(u64::from_be_bytes),
                            oversized_records_total: row
                                .get::<_, Option<[u8; 8]>>(2)?
                                .map(u64::from_be_bytes),
                        },
                    ))
                },
            )
            .map_err(storage)?;
        if stored_epoch.as_deref() == Some(epoch) {
            Ok(counts)
        } else {
            Ok(Self {
                unknown_format_records_total: Some(0),
                oversized_records_total: Some(0),
            })
        }
    }

    fn record(
        transaction: &Transaction<'_>,
        epoch: &str,
        disposition: SourceDisposition,
        shared: bool,
    ) -> Result<()> {
        if disposition == SourceDisposition::Ignored {
            return Ok(());
        }
        let mut counts = Self::read(transaction, epoch)?;
        let count = match disposition {
            SourceDisposition::Ignored => None,
            SourceDisposition::UnknownFormat => Some(&mut counts.unknown_format_records_total),
            SourceDisposition::Oversized => Some(&mut counts.oversized_records_total),
        };
        if let Some(count) = count {
            *count = count.and_then(|current| current.checked_add(1));
        }
        let updated = transaction
            .execute(
                "UPDATE queue_state SET source_counter_epoch=?1,
                     unknown_format_records_total=?2,oversized_records_total=?3 WHERE singleton=1",
                params![
                    epoch,
                    counts.unknown_format_records_total.map(u64::to_be_bytes),
                    counts.oversized_records_total.map(u64::to_be_bytes),
                ],
            )
            .map_err(|error| write_storage(error, shared))?;
        if updated != 1 {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        Ok(())
    }
}

pub(super) struct PendingPosition<'a> {
    position: &'a SourcePosition,
    sequence: i64,
}

#[derive(Clone, Copy)]
pub(super) enum PositionOutcome<'a> {
    Event { id: &'a str, fingerprint: &'a [u8] },
    Disposition(SourceDisposition),
}

impl<'a> PendingPosition<'a> {
    pub(super) fn new(position: &'a SourcePosition) -> Result<Self> {
        if !identity::public_id(&position.stream)
            || !(1..=MAX_CURSOR).contains(&position.cursor.len())
        {
            return Err("INVALID_SSH_SOURCE_POSITION");
        }
        Ok(Self {
            position,
            sequence: i64::try_from(position.sequence)
                .map_err(|_| "INVALID_SSH_SOURCE_POSITION")?,
        })
    }

    pub(super) fn already_checkpointed(
        &self,
        transaction: &Transaction<'_>,
        outcome: PositionOutcome<'_>,
    ) -> Result<bool> {
        let last = transaction
            .query_row(
                "SELECT sequence,cursor,last_event_id,last_outcome
                 FROM source_checkpoints WHERE stream=?1",
                [&self.position.stream],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        if let Some((previous, cursor, old_id, old_outcome)) = last {
            if self.sequence < previous {
                return Err("SSH_SOURCE_POSITION_STALE");
            }
            if self.sequence == previous {
                let same_outcome = match outcome {
                    PositionOutcome::Event { id, fingerprint } => {
                        old_id.as_deref() == Some(id) && old_outcome.as_slice() == fingerprint
                    }
                    PositionOutcome::Disposition(disposition) => {
                        old_outcome.as_slice() == disposition.code()
                    }
                };
                if cursor == self.position.cursor && same_outcome {
                    return Ok(true);
                }
                return Err("SSH_SOURCE_POSITION_CONFLICT");
            }
            if cursor == self.position.cursor {
                return Err("SSH_SOURCE_POSITION_CONFLICT");
            }
        } else {
            let streams: i64 = transaction
                .query_row("SELECT count(*) FROM source_checkpoints", [], |row| {
                    row.get(0)
                })
                .map_err(storage)?;
            if streams >= MAX_STREAMS {
                return Err("SSH_QUEUE_RESOURCE_LIMIT");
            }
        }

        Ok(false)
    }

    pub(super) fn write(
        &self,
        transaction: &Transaction<'_>,
        outcome: PositionOutcome<'_>,
        shared: bool,
    ) -> Result<()> {
        let code;
        let (id, proof) = match outcome {
            PositionOutcome::Event { id, fingerprint } => (Some(id), fingerprint),
            PositionOutcome::Disposition(disposition) => {
                code = disposition.code();
                (None, code.as_slice())
            }
        };
        // A disposition advances the cursor but retains the most recent real
        // event identity so it cannot be reused after the event is acknowledged.
        transaction
            .execute(
                "INSERT INTO source_checkpoints(
                     stream,sequence,cursor,last_event_id,last_outcome
                 ) VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(stream) DO UPDATE SET sequence=excluded.sequence,cursor=excluded.cursor,
                     last_event_id=coalesce(excluded.last_event_id,source_checkpoints.last_event_id),
                     last_outcome=excluded.last_outcome,last_read_at=NULL,source_witness=NULL",
                params![self.position.stream, self.sequence, self.position.cursor, id, proof],
            )
            .map_err(|error| write_storage(error, shared))?;
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    pub(super) static BEFORE_SOURCE_COMMIT: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
}

impl SshQueue {
    pub(super) fn commit_source_disposition(
        &mut self,
        epoch: &str,
        position: &SourcePosition,
        disposition: SourceDisposition,
    ) -> Result<Admission> {
        let position = PendingPosition::new(position)?;
        let mut budget = lock_write(self.budget.as_ref(), self.recovery_required)?;
        let shared = budget.is_some();
        let transaction = write_transaction(&mut self.connection, budget.as_ref(), false)?;
        let outcome = PositionOutcome::Disposition(disposition);
        let staged = (|| {
            if position.already_checkpointed(&transaction, outcome)? {
                return Ok(Admission::AlreadyCheckpointed);
            }
            position.write(&transaction, outcome, shared)?;
            SshSourceCounters::record(&transaction, epoch, disposition, shared)?;
            Ok(Admission::Stored)
        })();

        let result = match staged {
            Ok(Admission::Stored) => {
                #[cfg(test)]
                BEFORE_SOURCE_COMMIT.with(|hook| {
                    if let Some(before) = hook.take() {
                        before();
                    }
                });
                commit_write(transaction, budget.as_ref(), &mut self.recovery_required)
                    .map(|()| Admission::Stored)
            }
            result => {
                if transaction.finish().is_err() {
                    self.recovery_required = true;
                    Err("SSH_QUEUE_RECOVERY_REQUIRED")
                } else {
                    result
                }
            }
        };
        if self.recovery_required
            && let Some(budget) = budget.as_mut()
        {
            budget.mark_recovery_required();
        }
        result
    }

    pub(super) fn ssh_source_counters(&self, epoch: &str) -> Result<SshSourceCounters> {
        let _guard = lock_write(self.budget.as_ref(), self.recovery_required)?;
        SshSourceCounters::read(&self.connection, epoch)
    }

    /// Read observation metadata for the current position. Advancing the
    /// checkpoint clears this observation in the same transaction.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn source_read_at(&self, stream: &str) -> Result<Option<i64>> {
        self.connection
            .query_row(
                "SELECT last_read_at FROM source_checkpoints WHERE stream=?1",
                [stream],
                |row| row.get(0),
            )
            .map_err(storage)
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn source_recovery(&self, stream: &str) -> Result<SourceRecovery> {
        if !identity::public_id(stream) {
            return Err("INVALID_SSH_SOURCE_POSITION");
        }
        let _guard = lock_write(self.budget.as_ref(), self.recovery_required)?;
        let stored = self
            .connection
            .query_row(
                "SELECT source_witness,gap_reason,gap_detected_at,gap_recovered_at
                 FROM source_checkpoints WHERE stream=?1",
                [stream],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        let Some((witness, reason, detected_at, recovered_at)) = stored else {
            return Ok(SourceRecovery::default());
        };
        if witness
            .as_ref()
            .is_some_and(|bytes| !(1..=MAX_CURSOR).contains(&bytes.len()))
        {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        let gap = match (reason, detected_at, recovered_at) {
            (None, None, None) => None,
            (Some(reason), Some(detected_at), recovered_at)
                if (1..=253_402_300_799).contains(&detected_at)
                    && recovered_at.is_none_or(|time| (1..=253_402_300_799).contains(&time)) =>
            {
                let reason = match reason {
                    1 => SshGapReason::SourceRetention,
                    2 => SshGapReason::FileTruncation,
                    3 => SshGapReason::SourceReset,
                    4 => SshGapReason::SourceSwitch,
                    _ => return Err("INVALID_SSH_QUEUE_STATE"),
                };
                Some(SourceGap {
                    reason,
                    detected_at,
                    recovered_at,
                })
            }
            _ => return Err("INVALID_SSH_QUEUE_STATE"),
        };
        Ok(SourceRecovery { witness, gap })
    }

    /// Save an opaque observation of an unread record at this exact checkpoint.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn record_source_witness(
        &mut self,
        position: &SourcePosition,
        witness: &[u8],
    ) -> Result<()> {
        let position = PendingPosition::new(position)?;
        if !(1..=MAX_CURSOR).contains(&witness.len()) {
            return Err("INVALID_SSH_SOURCE_POSITION");
        }
        self.update_source_metadata(|transaction| {
            transaction.execute(
                "UPDATE source_checkpoints SET source_witness=?4
             WHERE stream=?1 AND sequence=?2 AND cursor=?3",
                params![
                    position.position.stream,
                    position.sequence,
                    position.position.cursor,
                    witness
                ],
            )
        })
    }

    /// Move the reader boundary after a lost position. Preserve the previous
    /// event identity, read time and gap unless a newer gap was confirmed.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn rebase_source(
        &mut self,
        previous: &SourcePosition,
        replacement: &SourcePosition,
        detected_at: i64,
        reason: Option<SshGapReason>,
    ) -> Result<()> {
        let previous = PendingPosition::new(previous)?;
        let replacement = PendingPosition::new(replacement)?;
        if previous.position.stream != replacement.position.stream
            || previous.sequence.checked_add(1) != Some(replacement.sequence)
            || previous.position.cursor == replacement.position.cursor
        {
            return Err("INVALID_SSH_SOURCE_POSITION");
        }
        if !(1..=253_402_300_799).contains(&detected_at) {
            return Err("INVALID_SSH_QUEUE_TIME");
        }
        let reason = reason.map(gap_reason_code);
        self.update_source_metadata(|transaction| {
            transaction.execute(
                "UPDATE source_checkpoints
             SET sequence=?4,cursor=?5,last_outcome=?6,source_witness=NULL,
                 gap_reason=coalesce(?7,gap_reason),
                 gap_detected_at=CASE WHEN ?7 IS NULL THEN gap_detected_at ELSE ?8 END,
                 gap_recovered_at=CASE WHEN ?7 IS NULL THEN gap_recovered_at END
             WHERE stream=?1 AND sequence=?2 AND cursor=?3",
                params![
                    previous.position.stream,
                    previous.sequence,
                    previous.position.cursor,
                    replacement.sequence,
                    replacement.position.cursor,
                    SourceDisposition::Ignored.code(),
                    reason,
                    detected_at,
                ],
            )
        })
    }

    /// Save a successful source read observation without advancing its cursor.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn record_source_read(
        &mut self,
        position: &SourcePosition,
        unix_seconds: i64,
    ) -> Result<()> {
        let position = PendingPosition::new(position)?;
        if !(1..=253_402_300_799).contains(&unix_seconds) {
            return Err("INVALID_SSH_QUEUE_TIME");
        }
        self.update_source_metadata(|transaction| {
            transaction.execute(
                "UPDATE source_checkpoints SET last_read_at=?4,
                     gap_recovered_at=CASE WHEN gap_reason IS NOT NULL
                                          THEN coalesce(gap_recovered_at,?4) END
                 WHERE stream=?1 AND sequence=?2 AND cursor=?3",
                params![
                    position.position.stream,
                    position.sequence,
                    position.position.cursor,
                    unix_seconds
                ],
            )
        })
    }

    #[cfg(any(target_os = "linux", test))]
    fn update_source_metadata(
        &mut self,
        update: impl FnOnce(&Transaction<'_>) -> rusqlite::Result<usize>,
    ) -> Result<()> {
        let mut budget = lock_write(self.budget.as_ref(), self.recovery_required)?;
        let transaction = write_transaction(&mut self.connection, budget.as_ref(), false)?;
        let result = update(&transaction).map_err(|error| write_storage(error, budget.is_some()));
        let result = match result {
            Ok(1) => commit_write(transaction, budget.as_ref(), &mut self.recovery_required),
            result => {
                if transaction.finish().is_err() {
                    self.recovery_required = true;
                    Err("SSH_QUEUE_RECOVERY_REQUIRED")
                } else {
                    result.and(Err("SSH_SOURCE_POSITION_CONFLICT"))
                }
            }
        };
        if self.recovery_required
            && let Some(budget) = budget.as_mut()
        {
            budget.mark_recovery_required();
        }
        result
    }
}
