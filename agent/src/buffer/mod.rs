//! Durable SSH queue and source checkpoint storage for one Agent binding.
mod admission;
pub(crate) mod budget;
mod compaction;
mod directory;
mod source_position;
#[cfg(test)]
mod tests;

use crate::{
    client::{MAX_SECURITY_EVENT_COUNT as MAX_BATCH, MAX_SECURITY_EVENT_REQUEST as MAX_REQUEST},
    identity::{self, IdentityStore, Result},
    protocol::IngestionResult,
};
use budget::{BudgetGuard, SharedBudget};
pub use budget::{SharedBuffer, SharedBufferPaths};
#[cfg(all(test, target_os = "linux"))]
pub(crate) use compaction::BEFORE_COMPACTION;
pub use compaction::SshCompaction;
use directory::{APPLICATION_ID, NewQueueFiles, QueueBinding, QueueDirectory, SCHEMA_VERSION};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Deserializer};
pub use source_position::{SourceDisposition, SshSourceCounters};
#[cfg(any(target_os = "linux", test))]
#[cfg(test)]
use source_position::{SourceGap, SourceRecovery};
use std::{net::IpAddr, path::Path, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const PREFIX: &[u8] = b"{\"events\":[";
const SUFFIX: &[u8] = b"]}";
const MAX_STREAMS: i64 = 64;
const MAX_CURSOR: usize = 4096;
const SHARED_PAGE_SIZE: u32 = 4096;
const MAX_PAYLOAD_BYTES: u64 = 1_000_000_000;
const SOURCE_SCHEMA: &str = include_str!("source_schema.sql");
const NS_PER_SECOND: i64 = 1_000_000_000;
const SQLITE_SOURCE_ID: &str =
    "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76";

#[cfg(test)]
thread_local! {
    static BEFORE_CAPACITY_COMMIT: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
}

/// One source/generation namespace and its next durable read position. Sequence
/// orders positions within a stream; cursor bytes are opaque to the queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourcePosition {
    pub stream: String,
    pub sequence: u64,
    pub cursor: Vec<u8>,
}

/// Local residence evidence supplied by the source/runner. Within one boot,
/// CLOCK_BOOTTIME controls elapsed time even if the wall clock changes.
pub struct QueueTime {
    pub boot_id: String,
    pub monotonic_ns: u64,
    pub unix_seconds: i64,
}

impl QueueTime {
    fn validated_monotonic_ns(&self) -> Result<i64> {
        if !identity::uuid(&self.boot_id) || !(1..=253_402_300_799).contains(&self.unix_seconds) {
            return Err("INVALID_SSH_QUEUE_TIME");
        }
        i64::try_from(self.monotonic_ns).map_err(|_| "INVALID_SSH_QUEUE_TIME")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Stored,
    AlreadyCheckpointed,
}

pub struct SshAttempt {
    pub token: String,
    pub event_count: usize,
    pub body: Vec<u8>,
}

/// An explicit whole-batch rejection by the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshRejection {
    TooLarge,
    Invalid,
    Conflict,
}

impl SshRejection {
    fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "TOO_LARGE",
            Self::Invalid => "INVALID",
            Self::Conflict => "CONFLICT",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionProgress {
    Split,
    Quarantined,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Flight {
    first: i64,
    last: i64,
    count: usize,
}

struct Active {
    token: String,
    flight: Flight,
}

pub struct SshQueue {
    // Close SQLite before releasing the held directory flock.
    connection: Connection,
    _directory: QueueDirectory,
    binding: QueueBinding,
    active: Option<Active>,
    age_limit_ns: i64,
    payload_limit: i64,
    budget: Option<SharedBudget>,
    recovery_required: bool,
}

struct State {
    payload_bytes: i64,
    last_boot: Option<String>,
    last_monotonic_ns: i64,
    last_wall_seconds: i64,
    wall_uncertain: bool,
    elapsed_ns: i64,
    flight: Option<Flight>,
    isolation_last: Option<i64>,
    batch_limit: i64,
    quarantined_count: i64,
    capacity_discarded_count: i64,
}

fn storage(_: rusqlite::Error) -> &'static str {
    "SSH_QUEUE_STORAGE_ERROR"
}

fn write_storage(error: rusqlite::Error, shared: bool) -> &'static str {
    if shared && error.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) {
        "SSH_QUEUE_RESOURCE_LIMIT"
    } else {
        storage(error)
    }
}

impl State {
    fn read(connection: &Connection) -> Result<Self> {
        let (mut state, first, last, count) = connection
            .query_row(
                "SELECT payload_bytes,last_boot,last_monotonic_ns,last_wall_seconds,wall_uncertain,elapsed_ns,
                    flight_first,flight_last,flight_count,isolation_last,batch_limit,quarantined_count,capacity_discarded_count
                 FROM queue_state WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        Self {
                            payload_bytes: row.get(0)?,
                            last_boot: row.get(1)?,
                            last_monotonic_ns: row.get(2)?,
                            last_wall_seconds: row.get(3)?,
                            wall_uncertain: row.get(4)?,
                            elapsed_ns: row.get(5)?,
                            flight: None,
                            isolation_last: row.get(9)?,
                            batch_limit: row.get(10)?,
                            quarantined_count: row.get(11)?,
                            capacity_discarded_count: row.get(12)?,
                        },
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                    ))
                },
            )
            .map_err(storage)?;
        if !(1..=MAX_BATCH as i64).contains(&state.batch_limit)
            || !(0..=state.payload_bytes).contains(&state.quarantined_count)
            || state.capacity_discarded_count < 0
            || state.isolation_last.is_some_and(|last| last <= 0)
            || (state.isolation_last.is_none() && state.batch_limit != MAX_BATCH as i64)
        {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        match (first, last, count) {
            (None, None, None) => {}
            (Some(first), Some(last), Some(count))
                if first > 0
                    && last >= first
                    && (1..=state.batch_limit).contains(&count)
                    && state.isolation_last.is_none_or(|end| last <= end) =>
            {
                state.flight = Some(Flight {
                    first,
                    last,
                    count: count as usize,
                });
            }
            _ => return Err("INVALID_SSH_QUEUE_STATE"),
        }
        Ok(state)
    }

    fn advance_clock(&mut self, now: &QueueTime) -> Result<()> {
        let monotonic = now.validated_monotonic_ns()?;
        let boot = now.boot_id.to_ascii_lowercase();
        if self.payload_bytes == 0 {
            self.reset_age();
        }
        let previous = self.last_boot.as_deref();
        let delta = if self.payload_bytes == 0 {
            Some(0)
        } else if previous == Some(boot.as_str()) {
            self.wall_uncertain |= now.unix_seconds < self.last_wall_seconds;
            monotonic.checked_sub(self.last_monotonic_ns)
        } else if previous.is_some() && !self.wall_uncertain {
            now.unix_seconds
                .checked_sub(self.last_wall_seconds)
                .and_then(|seconds| seconds.checked_mul(NS_PER_SECOND))
        } else {
            None
        };
        let Some(delta) = delta.filter(|delta| *delta >= 0) else {
            return Err("SSH_QUEUE_CLOCK_UNCERTAIN");
        };
        self.elapsed_ns = self
            .elapsed_ns
            .checked_add(delta)
            .ok_or("SSH_QUEUE_CLOCK_UNCERTAIN")?;
        self.last_boot = Some(boot);
        self.last_monotonic_ns = monotonic;
        self.last_wall_seconds = self.last_wall_seconds.max(now.unix_seconds);
        Ok(())
    }

    fn reset_age(&mut self) {
        self.last_boot = None;
        self.last_monotonic_ns = 0;
        self.last_wall_seconds = 0;
        self.wall_uncertain = false;
        self.elapsed_ns = 0;
    }

    fn write(&mut self, transaction: &Transaction<'_>, shared: bool) -> Result<()> {
        if self.payload_bytes == 0 {
            self.reset_age();
            self.clear_isolation();
        }
        transaction
            .execute(
                "UPDATE queue_state SET payload_bytes=?1,last_boot=?2,last_monotonic_ns=?3,
                   last_wall_seconds=?4,wall_uncertain=?5,elapsed_ns=?6,flight_first=?7,flight_last=?8,
                   flight_count=?9,isolation_last=?10,batch_limit=?11,quarantined_count=?12,
                   capacity_discarded_count=?13
                 WHERE singleton=1",
                params![
                    self.payload_bytes,
                    self.last_boot,
                    self.last_monotonic_ns,
                    self.last_wall_seconds,
                    self.wall_uncertain,
                    self.elapsed_ns,
                    self.flight.map(|f| f.first),
                    self.flight.map(|f| f.last),
                    self.flight.map(|f| f.count as i64),
                    self.isolation_last,
                    self.batch_limit,
                    self.quarantined_count,
                    self.capacity_discarded_count,
                ],
            )
            .map_err(|error| write_storage(error, shared))?;
        Ok(())
    }

    fn clear_isolation(&mut self) {
        self.isolation_last = None;
        self.batch_limit = MAX_BATCH as i64;
    }

    fn complete_isolation(&mut self, transaction: &Transaction<'_>) -> Result<()> {
        let Some(last) = self.isolation_last else {
            return Ok(());
        };
        let remaining: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ssh_events INDEXED BY ssh_events_ready
                               WHERE id<=?1 AND quarantine_code IS NULL)",
                [last],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if !remaining {
            // SQLite may reuse a deleted highest rowid during the next enqueue.
            self.clear_isolation();
        }
        Ok(())
    }
}

fn configure(connection: &Connection, initializing: bool, shared: bool) -> Result<()> {
    connection.busy_timeout(Duration::ZERO).map_err(storage)?;
    let (version, source_id): (String, String) = connection
        .query_row("SELECT sqlite_version(), sqlite_source_id()", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(storage)?;
    if version != "3.54.1" || source_id != SQLITE_SOURCE_ID {
        return Err("UNSUPPORTED_SSH_QUEUE_ENGINE");
    }
    // The schema-only initialization has no previously admitted data and must
    // not leave any unowned sidecar. Published queues use DELETE with EXTRA,
    // which provides FULL durability and directory sync after journal unlink.
    let (pragma, expected) = if initializing {
        ("PRAGMA journal_mode=MEMORY", "memory")
    } else {
        ("PRAGMA journal_mode=DELETE", "delete")
    };
    let journal: String = connection
        .query_row(pragma, [], |row| row.get(0))
        .map_err(storage)?;
    connection
        .execute_batch(
            "PRAGMA synchronous=EXTRA; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;",
        )
        .map_err(storage)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(storage)?;
    if journal != expected || synchronous != 3 {
        return Err("UNSUPPORTED_SSH_QUEUE_DURABILITY");
    }
    if shared {
        if initializing {
            connection
                .pragma_update(None, "page_size", SHARED_PAGE_SIZE)
                .map_err(storage)?;
        }
        // A single rollback header is reserved per transaction. Prevent
        // mid-transaction pager syncs and untracked mmap/temporary writes.
        connection
            .execute_batch("PRAGMA cache_spill=OFF; PRAGMA mmap_size=0;")
            .map_err(storage)?;
        for (pragma, required) in [
            ("cache_spill", 0),
            ("mmap_size", 0),
            ("auto_vacuum", 0),
            ("temp_store", 2),
        ] {
            let actual: i64 = connection.pragma_query_one(None, pragma).map_err(storage)?;
            if actual != required {
                return Err("UNSUPPORTED_SSH_QUEUE_STORAGE_LAYOUT");
            }
        }
    }
    Ok(())
}

fn connect(directory: &QueueDirectory) -> Result<Connection> {
    Connection::open_with_flags(
        directory.database_path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(storage)
}

fn write_transaction<'a>(
    connection: &'a mut Connection,
    budget: Option<&BudgetGuard<'_>>,
    creating_owner: bool,
) -> Result<Transaction<'a>> {
    if let Some(budget) = budget {
        let page_size: u32 = connection
            .pragma_query_one(None, "page_size")
            .map_err(storage)?;
        let pages = u32::try_from(budget.sqlite_max_pages(u64::from(page_size), creating_owner)?)
            .map_err(|_| "SSH_QUEUE_RESOURCE_LIMIT")?;
        if pages == 0 {
            return Err("SSH_QUEUE_RESOURCE_LIMIT");
        }
        let actual: u32 = connection
            .pragma_update_and_check(None, "max_page_count", pages, |row| row.get(0))
            .map_err(storage)?;
        if actual != pages {
            return Err("SSH_QUEUE_RESOURCE_LIMIT");
        }
    }
    connection.transaction().map_err(storage)
}

fn lock_write(
    budget: Option<&SharedBudget>,
    recovery_required: bool,
) -> Result<Option<BudgetGuard<'_>>> {
    if recovery_required {
        return Err("SSH_QUEUE_RECOVERY_REQUIRED");
    }
    budget.map(SharedBudget::lock).transpose()
}

fn commit_write(
    transaction: Transaction<'_>,
    budget: Option<&BudgetGuard<'_>>,
    recovery_required: &mut bool,
) -> Result<()> {
    // In DELETE mode the rollback journal is still present here. Main file
    // growth during COMMIT is bounded by the connection's page limit.
    if let Some(budget) = budget
        && let Err(code) = budget.verify_allocation()
    {
        if transaction.finish().is_err() {
            *recovery_required = true;
            return Err("SSH_QUEUE_RECOVERY_REQUIRED");
        }
        return Err(code);
    }
    if let Err(error) = transaction.commit() {
        let code = write_storage(error, budget.is_some());
        if budget.is_some() {
            *recovery_required = true;
            if code != "SSH_QUEUE_RESOURCE_LIMIT" {
                return Err("SSH_QUEUE_RECOVERY_REQUIRED");
            }
        }
        return Err(code);
    }
    if let Some(budget) = budget
        && budget.verify_allocation().is_err()
    {
        *recovery_required = true;
        return Err("SSH_QUEUE_RECOVERY_REQUIRED");
    }
    Ok(())
}

fn quarantine_singleton(
    transaction: &Transaction<'_>,
    id: i64,
    reason: SshRejection,
    shared: bool,
) -> Result<()> {
    let changed = if shared {
        let (event_id, admitted_ns, body): (String, i64, Vec<u8>) = transaction
            .query_row(
                "SELECT event_id, admitted_ns, body FROM ssh_events
                 WHERE id=?1 AND quarantine_code IS NULL",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or("INVALID_SSH_QUEUE_STATE")?;
        // A SQLite UPDATE can allocate a new BLOB overflow chain before it
        // frees the old one. Free the original pages first and write the
        // same record back with its rejection reason in this transaction.
        if transaction
            .execute("DELETE FROM ssh_events WHERE id=?1", [id])
            .map_err(|error| write_storage(error, true))?
            != 1
        {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        transaction
            .execute(
                "INSERT INTO ssh_events(id,event_id,admitted_ns,body,quarantine_code)
                 VALUES (?1,?2,?3,?4,?5)",
                params![id, event_id, admitted_ns, body, reason.code()],
            )
            .map_err(|error| write_storage(error, true))?
    } else {
        transaction
            .execute(
                "UPDATE ssh_events SET quarantine_code=?1
                 WHERE id=?2 AND quarantine_code IS NULL",
                params![reason.code(), id],
            )
            .map_err(storage)?
    };
    if changed != 1 {
        return Err("INVALID_SSH_QUEUE_STATE");
    }
    Ok(())
}

fn initialize(
    directory: &QueueDirectory,
    created: &mut NewQueueFiles<'_>,
    binding: &QueueBinding,
    owner: &str,
    budget: Option<&BudgetGuard<'_>>,
) -> Result<Connection> {
    let mut connection = connect(directory)?;
    let shared = budget.is_some();
    let write_error = |error| write_storage(error, shared);
    configure(&connection, true, shared)?;
    let transaction = write_transaction(&mut connection, budget, true)?;
    transaction
        .execute_batch(include_str!("schema.sql"))
        .map_err(write_error)?;
    transaction
        .execute_batch(SOURCE_SCHEMA)
        .map_err(write_error)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(write_error)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(write_error)?;
    transaction
        .execute(
            "INSERT INTO queue_state(singleton,owner) VALUES(1,?1)",
            [owner],
        )
        .map_err(write_error)?;
    commit_write(transaction, budget, &mut false)?;
    configure(&connection, false, shared)?;
    created.publish_owner(binding)?;
    if let Some(budget) = budget {
        budget.verify_allocation()?;
    }
    Ok(connection)
}

fn reopen(
    directory: &QueueDirectory,
    owner: &str,
    budget: Option<&BudgetGuard<'_>>,
) -> Result<Connection> {
    if let Some(budget) = budget {
        let (page_size, recovery_pages) = directory.shared_recovery_pages()?;
        if recovery_pages > budget.sqlite_max_pages(page_size, false)? {
            return Err("SSH_QUEUE_RESOURCE_LIMIT");
        }
    }
    let mut connection = connect(directory)?;
    let shared = budget.is_some();
    let write_error = |error| write_storage(error, shared);
    configure(&connection, false, shared)?;
    let stored: String = connection
        .query_row(
            "SELECT owner FROM queue_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if stored != owner {
        return Err("SSH_QUEUE_BINDING_MISMATCH");
    }
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(storage)?;
    match version {
        1..=4 => {
            let transaction = write_transaction(&mut connection, budget, false)?;
            if version == 1 {
                // v1 has incomplete wall-clock evidence for cross-boot aging.
                transaction.execute_batch(
                    "ALTER TABLE queue_state ADD COLUMN wall_uncertain INTEGER NOT NULL DEFAULT 0 CHECK (wall_uncertain IN (0,1));
                     UPDATE queue_state SET wall_uncertain=1 WHERE payload_bytes>0;",
                ).map_err(write_error)?;
            }
            if version <= 2 {
                transaction.execute_batch(
                    "ALTER TABLE queue_state ADD COLUMN isolation_last INTEGER CHECK (isolation_last > 0);
                     ALTER TABLE queue_state ADD COLUMN batch_limit INTEGER NOT NULL DEFAULT 1000 CHECK (batch_limit BETWEEN 1 AND 1000);
                     ALTER TABLE queue_state ADD COLUMN quarantined_count INTEGER NOT NULL DEFAULT 0 CHECK (quarantined_count >= 0);
                     ALTER TABLE ssh_events ADD COLUMN quarantine_code TEXT CHECK (quarantine_code IN ('TOO_LARGE', 'INVALID', 'CONFLICT'));
                     CREATE INDEX ssh_events_ready ON ssh_events (id) WHERE quarantine_code IS NULL;",
                ).map_err(write_error)?;
            }
            if version <= 3 {
                transaction
                    .execute_batch(
                        "ALTER TABLE queue_state ADD COLUMN capacity_discarded_count INTEGER NOT NULL
                         DEFAULT 0 CHECK (capacity_discarded_count >= 0);",
                    )
                    .map_err(write_error)?;
            }
            migrate_source_checkpoints(&transaction, shared)?;
            transaction
                .pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(write_error)?;
            commit_write(transaction, budget, &mut false)?;
        }
        5 | 6 => {
            let transaction = write_transaction(&mut connection, budget, false)?;
            if version == 5 {
                transaction
                    .execute_batch(
                        "ALTER TABLE source_checkpoints ADD COLUMN last_read_at INTEGER
                         CHECK (last_read_at BETWEEN 1 AND 253402300799);",
                    )
                    .map_err(write_error)?;
            }
            transaction
                .execute_batch(
                    "ALTER TABLE source_checkpoints ADD COLUMN source_witness BLOB
                         CHECK (length(source_witness) BETWEEN 1 AND 4096);
                     ALTER TABLE source_checkpoints ADD COLUMN gap_reason INTEGER
                         CHECK (gap_reason IN (1,2,3,4));
                     ALTER TABLE source_checkpoints ADD COLUMN gap_detected_at INTEGER CHECK (
                         (gap_reason IS NULL AND gap_detected_at IS NULL)
                         OR (gap_reason IS NOT NULL AND gap_detected_at IS NOT NULL
                             AND gap_detected_at BETWEEN 1 AND 253402300799));
                     ALTER TABLE source_checkpoints ADD COLUMN gap_recovered_at INTEGER CHECK (
                         gap_recovered_at IS NULL OR
                         (gap_detected_at IS NOT NULL AND gap_recovered_at BETWEEN 1 AND 253402300799));",
                )
                .map_err(write_error)?;
            transaction
                .pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(write_error)?;
            commit_write(transaction, budget, &mut false)?;
        }
        SCHEMA_VERSION => {}
        _ => return Err("INVALID_SSH_QUEUE_STATE"),
    }
    State::read(&connection)?;
    if let Some(budget) = budget {
        // A previous compaction can exit after truncation but before syncing.
        // Make the observed file size durable before sharing its freed space.
        compaction::sync_main(&mut connection)?;
        budget.verify_allocation()?;
    }
    Ok(connection)
}

fn migrate_source_checkpoints(transaction: &Transaction<'_>, shared: bool) -> Result<()> {
    // At most 64 bounded cursors fit here. Free the old table's pages before
    // rebuilding so the migration does not need space for two complete copies.
    let mut checkpoints = Vec::new();
    {
        let mut statement = transaction
            .prepare(
                "SELECT stream,sequence,cursor,last_event_id,last_body_sha256
                 FROM source_checkpoints ORDER BY stream LIMIT ?1",
            )
            .map_err(storage)?;
        let mut rows = statement.query([MAX_STREAMS + 1]).map_err(storage)?;
        while let Some(row) = rows.next().map_err(storage)? {
            let stream = row
                .get_ref(0)
                .map_err(storage)?
                .as_str()
                .map_err(|_| "INVALID_SSH_QUEUE_STATE")?;
            let sequence: i64 = row.get(1).map_err(storage)?;
            let cursor = row
                .get_ref(2)
                .map_err(storage)?
                .as_blob()
                .map_err(|_| "INVALID_SSH_QUEUE_STATE")?;
            let event_id = row
                .get_ref(3)
                .map_err(storage)?
                .as_str()
                .map_err(|_| "INVALID_SSH_QUEUE_STATE")?;
            let digest = row
                .get_ref(4)
                .map_err(storage)?
                .as_blob()
                .map_err(|_| "INVALID_SSH_QUEUE_STATE")?;
            if checkpoints.len() as i64 >= MAX_STREAMS
                || !identity::public_id(stream)
                || sequence < 0
                || !(1..=MAX_CURSOR).contains(&cursor.len())
                || !identity::uuid(event_id)
                || digest.len() != 32
            {
                return Err("INVALID_SSH_QUEUE_STATE");
            }
            checkpoints.push((
                stream.to_owned(),
                sequence,
                cursor.to_vec(),
                event_id.to_owned(),
                digest.to_vec(),
            ));
        }
    }
    let write_error = |error| write_storage(error, shared);
    // Keep counts in the existing singleton instead of allocating another
    // table for one row when the v4 queue may already be at its page cap.
    transaction.execute_batch(
        "ALTER TABLE queue_state ADD COLUMN source_counter_epoch TEXT CHECK (length(source_counter_epoch) = 36);
         ALTER TABLE queue_state ADD COLUMN unknown_format_records_total BLOB CHECK (length(unknown_format_records_total) = 8);
         ALTER TABLE queue_state ADD COLUMN oversized_records_total BLOB CHECK (length(oversized_records_total) = 8);",
    ).map_err(write_error)?;
    transaction
        .execute_batch("DROP TABLE source_checkpoints")
        .map_err(write_error)?;
    transaction
        .execute_batch(SOURCE_SCHEMA)
        .map_err(write_error)?;
    let mut insert = transaction
        .prepare(
            "INSERT INTO source_checkpoints(stream,sequence,cursor,last_event_id,last_outcome)
             VALUES (?1,?2,?3,?4,?5)",
        )
        .map_err(storage)?;
    for (stream, sequence, cursor, event_id, digest) in checkpoints {
        insert
            .execute(params![stream, sequence, cursor, event_id, digest])
            .map_err(write_error)?;
    }
    Ok(())
}

fn required_nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SshEvent {
    event_id: String,
    boot_id: String,
    occurred_at: String,
    event_type: String,
    #[serde(rename = "sourceIp", deserialize_with = "required_nullable")]
    _source_ip: Option<IpAddr>,
    #[serde(deserialize_with = "required_nullable")]
    username: Option<String>,
}

fn parse_event(body: &[u8]) -> Result<SshEvent> {
    if body.len() > MAX_REQUEST - PREFIX.len() - SUFFIX.len() {
        return Err("SSH_QUEUE_RESOURCE_LIMIT");
    }
    if body
        .iter()
        .copied()
        .find(|byte| !matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        != Some(b'{')
    {
        return Err("INVALID_SSH_EVENT");
    }
    let event: SshEvent = serde_json::from_slice(body).map_err(|_| "INVALID_SSH_EVENT")?;
    let timestamp = event.occurred_at.as_bytes();
    // `time` accepts any separator and represents leap seconds. The ingest
    // server uppercases RFC 3339 before parsing with Go, which requires T and
    // rejects second 60. Reject those forms before advancing the source.
    if !identity::uuid(&event.event_id)
        || !identity::uuid(&event.boot_id)
        || !matches!(
            event.event_type.as_str(),
            "SSH_LOGIN_SUCCEEDED" | "SSH_AUTH_FAILED"
        )
        || !matches!(timestamp.get(10), Some(b'T' | b't'))
        || timestamp.get(17..19) == Some(b"60")
        || OffsetDateTime::parse(&event.occurred_at, &Rfc3339).is_err()
        || event
            .username
            .as_ref()
            .is_some_and(|username| username.chars().count() > 128 || username.contains('\0'))
    {
        return Err("INVALID_SSH_EVENT");
    }
    Ok(event)
}

fn prune(
    transaction: &Transaction<'_>,
    state: &mut State,
    cutoff: i64,
    shared: bool,
) -> Result<bool> {
    let mut select = transaction
        .prepare(
            "SELECT id,length(body),quarantine_code IS NOT NULL FROM ssh_events
         WHERE admitted_ns < ?1 ORDER BY admitted_ns,id LIMIT ?2",
        )
        .map_err(storage)?;
    let mut rows = select
        .query(params![cutoff, MAX_BATCH as i64 + 1])
        .map_err(storage)?;
    let mut first = None;
    let mut last = 0;
    let mut count = 0;
    let mut bytes = 0i64;
    let mut quarantined = 0i64;
    let mut flight_expired = false;
    let mut more = false;
    while count < MAX_BATCH {
        let Some(row) = rows.next().map_err(storage)? else {
            break;
        };
        let length = row.get::<_, i64>(1).map_err(storage)?;
        // Keep the dirty-cache working set bounded when page spilling is
        // disabled in shared mode. One ordinary upload is already byte-bound.
        if shared && count > 0 && bytes.saturating_add(length) > MAX_REQUEST as i64 {
            more = true;
            break;
        }
        last = row.get(0).map_err(storage)?;
        first.get_or_insert(last);
        bytes += length;
        if row.get::<_, bool>(2).map_err(storage)? {
            quarantined += 1;
        } else if state
            .flight
            .is_some_and(|flight| (flight.first..=flight.last).contains(&last))
        {
            flight_expired = true;
        }
        count += 1;
    }
    let more = more || rows.next().map_err(storage)?.is_some();
    drop(rows);
    drop(select);
    if let Some(first) = first {
        let removed = transaction
            .execute(
                "DELETE FROM ssh_events WHERE id BETWEEN ?1 AND ?2 AND admitted_ns < ?3",
                params![first, last, cutoff],
            )
            .map_err(|error| write_storage(error, shared))?;
        if removed != count || bytes > state.payload_bytes || quarantined > state.quarantined_count
        {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        state.payload_bytes -= bytes;
        state.quarantined_count -= quarantined;
        if flight_expired {
            state.flight = None;
        }
        state.complete_isolation(transaction)?;
    }
    Ok(more)
}

fn batch(connection: &Connection, state: &State) -> Result<Option<(Flight, Vec<u8>)>> {
    let (begin, end) = state
        .flight
        .map_or((1, state.isolation_last.unwrap_or(i64::MAX)), |flight| {
            (flight.first, flight.last)
        });
    let mut statement = connection
        .prepare(
            "SELECT id,body FROM ssh_events INDEXED BY ssh_events_ready WHERE id BETWEEN ?1 AND ?2
             AND quarantine_code IS NULL ORDER BY id LIMIT ?3",
        )
        .map_err(storage)?;
    let mut rows = statement
        .query(params![begin, end, state.batch_limit])
        .map_err(storage)?;
    let mut first = None;
    let mut last = 0;
    let mut count = 0;
    let mut body = PREFIX.to_vec();
    while let Some(row) = rows.next().map_err(storage)? {
        let raw = row
            .get_ref(1)
            .map_err(storage)?
            .as_blob()
            .map_err(|_| "INVALID_SSH_QUEUE_STATE")?;
        if raw.is_empty() || raw.len() > MAX_REQUEST - PREFIX.len() - SUFFIX.len() {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        let comma = usize::from(count != 0);
        if body.len() + comma + raw.len() + SUFFIX.len() > MAX_REQUEST {
            break;
        }
        last = row.get(0).map_err(storage)?;
        first.get_or_insert(last);
        if comma != 0 {
            body.push(b',');
        }
        body.extend_from_slice(raw);
        count += 1;
    }
    let result = first.map(|first| Flight { first, last, count });
    if state.flight.is_some() && state.flight != result {
        return Err("INVALID_SSH_QUEUE_STATE");
    }
    body.extend_from_slice(SUFFIX);
    Ok(result.map(|flight| (flight, body)))
}

impl SshQueue {
    /// Check directory and ownership without SQLite recovery or creating files.
    pub fn preflight(path: &Path, identity: &IdentityStore) -> Result<()> {
        let binding = QueueBinding::new(identity)?;
        QueueDirectory::open(path, identity, &binding)?;
        Ok(())
    }

    /// Open one private queue. The byte limit governs queued event payloads.
    /// SQLite pages, journals, and other collector groups have separate budgets.
    pub fn open(
        path: &Path,
        identity: &IdentityStore,
        max_age_seconds: u64,
        max_payload_bytes: u64,
    ) -> Result<Self> {
        if !(1_000_000..=MAX_PAYLOAD_BYTES).contains(&max_payload_bytes) {
            return Err("INVALID_SSH_QUEUE_LIMITS");
        }
        Self::open_with_budget(path, identity, max_age_seconds, max_payload_bytes, None)
    }

    pub(crate) fn open_shared(
        path: &Path,
        identity: &IdentityStore,
        max_age_seconds: u64,
        budget: SharedBudget,
    ) -> Result<Self> {
        if max_age_seconds != u64::from(budget.lock()?.age_limit()) {
            return Err("INVALID_SSH_QUEUE_LIMITS");
        }
        Self::open_with_budget(
            path,
            identity,
            max_age_seconds,
            MAX_PAYLOAD_BYTES,
            Some(budget),
        )
    }

    fn open_with_budget(
        path: &Path,
        identity: &IdentityStore,
        max_age_seconds: u64,
        max_payload_bytes: u64,
        budget: Option<SharedBudget>,
    ) -> Result<Self> {
        if !(3600..=604800).contains(&max_age_seconds) {
            return Err("INVALID_SSH_QUEUE_LIMITS");
        }
        let binding = QueueBinding::new(identity)?;
        let directory = QueueDirectory::open(path, identity, &binding)?;
        if let Some(budget) = &budget {
            budget.check_ssh_directory(directory.descriptor())?;
        }
        let owner = serde_json::to_string(&binding).map_err(|_| "INVALID_SSH_QUEUE_STATE")?;
        let budget_guard = lock_write(budget.as_ref(), false)?;
        if let Some(guard) = &budget_guard {
            guard.verify_allocation()?;
        }
        let connection = if directory.is_existing() {
            reopen(&directory, &owner, budget_guard.as_ref())?
        } else {
            if let Some(guard) = budget_guard.as_ref() {
                guard.sqlite_max_pages(u64::from(SHARED_PAGE_SIZE), true)?;
            }
            let mut created = directory.begin_creation()?;
            match initialize(
                &directory,
                &mut created,
                &binding,
                &owner,
                budget_guard.as_ref(),
            ) {
                Ok(connection) => connection,
                Err(error) => {
                    // initialize has returned and its SQLite handle is closed.
                    created
                        .cleanup()
                        .map_err(|_| "SSH_QUEUE_RECOVERY_REQUIRED")?;
                    return Err(error);
                }
            }
        };
        drop(budget_guard);
        Ok(Self {
            connection,
            _directory: directory,
            binding,
            active: None,
            age_limit_ns: max_age_seconds as i64 * NS_PER_SECOND,
            payload_limit: max_payload_bytes as i64,
            budget,
            recovery_required: false,
        })
    }

    pub fn check_identity(&self, identity: &IdentityStore) -> Result<()> {
        if self.binding != QueueBinding::new(identity)? {
            return Err("SSH_QUEUE_BINDING_MISMATCH");
        }
        Ok(())
    }

    pub(super) fn safely_reportable(&self) -> bool {
        !self.recovery_required
    }

    pub fn checkpoint(&self, stream: &str) -> Result<Option<SourcePosition>> {
        if !identity::public_id(stream) {
            return Err("INVALID_SSH_SOURCE_POSITION");
        }
        let stored = self
            .connection
            .query_row(
                "SELECT sequence,cursor FROM source_checkpoints WHERE stream=?1",
                [stream],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(storage)?;
        stored
            .map(|(sequence, cursor)| {
                Ok(SourcePosition {
                    stream: stream.to_owned(),
                    sequence: u64::try_from(sequence).map_err(|_| "INVALID_SSH_QUEUE_STATE")?,
                    cursor,
                })
            })
            .transpose()
    }

    pub fn queued_payload_bytes(&self) -> Result<u64> {
        let bytes: i64 = self
            .connection
            .query_row(
                "SELECT payload_bytes FROM queue_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        u64::try_from(bytes).map_err(|_| "INVALID_SSH_QUEUE_STATE")
    }

    /// Rejected originals still retained under the same payload and age limits.
    pub fn quarantined_count(&self) -> Result<u64> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT quarantined_count FROM queue_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        u64::try_from(count).map_err(|_| "INVALID_SSH_QUEUE_STATE")
    }

    /// Durable local capacity discards over the lifetime of this queue.
    /// This total is independent of collector epochs and remote receipts.
    pub fn capacity_discarded_events_total(&self) -> Result<u64> {
        if self.recovery_required {
            return Err("SSH_QUEUE_RECOVERY_REQUIRED");
        }
        let count: i64 = self
            .connection
            .query_row(
                "SELECT capacity_discarded_count FROM queue_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        u64::try_from(count).map_err(|_| "INVALID_SSH_QUEUE_STATE")
    }

    /// Advance the source only when this event is durably admitted. A retried
    /// current position is a no-op if its cursor, original ID and bytes agree.
    pub fn enqueue(
        &mut self,
        position: &SourcePosition,
        original_event_json: &[u8],
        now: &QueueTime,
    ) -> Result<Admission> {
        let pending = admission::PendingAdmission::new(
            position,
            original_event_json,
            now,
            self.payload_limit,
        )?;
        let budget = lock_write(self.budget.as_ref(), self.recovery_required)?;
        pending.enqueue(
            &mut self.connection,
            budget.as_ref(),
            &mut self.recovery_required,
        )
    }

    /// Freeze one FIFO batch, or issue a new token for an unacknowledged batch.
    /// Bounded maintenance makes progress before an expiry backlog retry.
    pub fn prepare(&mut self, now: &QueueTime) -> Result<Option<SshAttempt>> {
        if self.active.is_some() {
            return Err("SSH_ATTEMPT_ACTIVE");
        }
        let budget = lock_write(self.budget.as_ref(), self.recovery_required)?;
        let shared = budget.is_some();
        let age_limit_ns = budget.as_ref().map_or(self.age_limit_ns, |guard| {
            i64::from(guard.age_limit()) * NS_PER_SECOND
        });
        let transaction = write_transaction(&mut self.connection, budget.as_ref(), false)?;
        let mut state = State::read(&transaction)?;
        state.advance_clock(now)?;
        let cutoff = state.elapsed_ns.saturating_sub(age_limit_ns);
        if prune(&transaction, &mut state, cutoff, shared)? {
            state.write(&transaction, shared)?;
            commit_write(transaction, budget.as_ref(), &mut self.recovery_required)?;
            return Err("SSH_QUEUE_EXPIRY_PENDING");
        }
        let prepared = batch(&transaction, &state)?;
        state.flight = prepared.as_ref().map(|(flight, _)| *flight);
        let token = prepared
            .as_ref()
            .map(|_| identity::new_collector_epoch())
            .transpose()?;
        state.write(&transaction, shared)?;
        commit_write(transaction, budget.as_ref(), &mut self.recovery_required)?;
        if let (Some((flight, body)), Some(token)) = (prepared, token) {
            self.active = Some(Active {
                token: token.clone(),
                flight,
            });
            return Ok(Some(SshAttempt {
                token,
                event_count: flight.count,
                body,
            }));
        }
        Ok(None)
    }

    fn active_flight(&self, token: &str) -> Result<Flight> {
        self.active
            .as_ref()
            .filter(|active| active.token == token)
            .map(|active| active.flight)
            .ok_or("STALE_SSH_ATTEMPT")
    }

    pub(crate) fn check_attempt(&self, token: &str) -> Result<()> {
        self.active_flight(token).map(|_| ())
    }

    /// Apply an explicit whole-batch rejection to the current attempt. A split
    /// limits the next prefix of the rejected range. A singleton stays durable
    /// with its reason and is excluded from future sends.
    pub fn reject(&mut self, token: &str, reason: SshRejection) -> Result<RejectionProgress> {
        let flight = self.active_flight(token)?;
        let budget = lock_write(self.budget.as_ref(), self.recovery_required)?;
        let shared = budget.is_some();
        let transaction = write_transaction(&mut self.connection, budget.as_ref(), false)?;
        let mut state = State::read(&transaction)?;
        if state.flight != Some(flight) {
            return Err("INVALID_SSH_QUEUE_STATE");
        }

        let progress = if flight.count > 1 {
            state.isolation_last = Some(state.isolation_last.unwrap_or(flight.last));
            state.batch_limit = flight.count.div_ceil(2) as i64;
            RejectionProgress::Split
        } else {
            if flight.first != flight.last {
                return Err("INVALID_SSH_QUEUE_STATE");
            }
            quarantine_singleton(&transaction, flight.first, reason, shared)?;
            state.quarantined_count = state
                .quarantined_count
                .checked_add(1)
                .filter(|count| *count <= state.payload_bytes)
                .ok_or("INVALID_SSH_QUEUE_STATE")?;
            state.complete_isolation(&transaction)?;
            RejectionProgress::Quarantined
        };
        state.flight = None;
        state.write(&transaction, shared)?;
        commit_write(transaction, budget.as_ref(), &mut self.recovery_required)?;
        self.active = None;
        Ok(progress)
    }

    /// End the active network attempt. Without a validated aggregate ACK the
    /// durable batch remains available with the original bytes and member IDs.
    pub fn finish(&mut self, token: &str, ack: Option<&IngestionResult>) -> Result<()> {
        let flight = self.active_flight(token)?;
        let Some(ack) = ack else {
            self.active = None;
            return Ok(());
        };
        let sum = ack
            .accepted_count
            .checked_add(ack.duplicate_count)
            .and_then(|n| n.checked_add(ack.expired_count));
        if sum != Some(flight.count as u64)
            || OffsetDateTime::parse(&ack.received_at, &Rfc3339).is_err()
        {
            return Err("INVALID_SSH_ACK");
        }
        let budget = lock_write(self.budget.as_ref(), self.recovery_required)?;
        let shared = budget.is_some();
        let transaction = write_transaction(&mut self.connection, budget.as_ref(), false)?;
        let mut state = State::read(&transaction)?;
        if state.flight != Some(flight) {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        let bytes: i64 = transaction
            .query_row(
                "SELECT coalesce(sum(length(body)),0) FROM ssh_events
                 WHERE id BETWEEN ?1 AND ?2 AND quarantine_code IS NULL",
                params![flight.first, flight.last],
                |row| row.get(0),
            )
            .map_err(storage)?;
        let removed = transaction
            .execute(
                "DELETE FROM ssh_events WHERE id BETWEEN ?1 AND ?2 AND quarantine_code IS NULL",
                params![flight.first, flight.last],
            )
            .map_err(|error| write_storage(error, shared))?;
        if removed != flight.count || bytes > state.payload_bytes {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        state.payload_bytes -= bytes;
        state.flight = None;
        state.complete_isolation(&transaction)?;
        state.write(&transaction, shared)?;
        commit_write(transaction, budget.as_ref(), &mut self.recovery_required)?;
        self.active = None;
        Ok(())
    }
}
