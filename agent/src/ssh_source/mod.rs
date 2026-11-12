//! Read one trusted local SSH source into the binding's durable queue.
mod auth_file;
#[cfg(test)]
mod file_tests;
mod journal;
mod parse;
#[cfg(test)]
mod tests;

use crate::{
    buffer::{QueueTime, SharedBuffer, SourceDisposition, SourcePosition},
    identity::Result,
    protocol::{
        Capability, SshContinuity, SshCounterCoverage, SshGapReason, SshParseCoverage, SshSource,
        SshSourceCounters, SshSourceDiagnostics, SshSourceGap,
    },
};
use auth_file::{AuthFile, FileCursor, FileError, FileRecord, FileStep, FileWitness};
use journal::{Journal, JournalError, JournalMessage, JournalRecord};
use parse::Classification;
use ring::digest::{Context, SHA256};
use serde::Deserialize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// This stream identifies the fixed local journal filter and cursor format.
pub const JOURNAL_STREAM: &str = "journald.ssh.v1";
pub const AUTH_FILE_STREAM: &str = "auth-file.ssh.v1";
const MAX_POLL_RECORDS: usize = 64;
const POLL_BUDGET: Duration = Duration::from_millis(50);
const MAX_SOURCE_CURSOR: usize = 4000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceRead {
    CaughtUp,
    More,
    Rebased,
    PendingLine,
    WaitingForRotation,
    Unavailable,
    PermissionDenied,
    CursorLost,
    ReadError,
}

#[derive(Default)]
pub struct SshSourceReader {
    journal: Option<Journal>,
    last_outcome: Option<SourceRead>,
    last_read_at: Option<i64>,
}

struct Checkpoint {
    initialized_at: i64,
    last_record_read_at: Option<i64>,
    cursor: Vec<u8>,
    resume_after_lost_journal: bool,
}

impl Checkpoint {
    fn encode(&self, source: SshSource, sequence: u64) -> SourcePosition {
        let mut cursor = Vec::with_capacity(17 + self.cursor.len());
        cursor.push(if self.resume_after_lost_journal { 3 } else { 2 });
        cursor.extend_from_slice(&self.initialized_at.to_be_bytes());
        cursor.extend_from_slice(&self.last_record_read_at.unwrap_or(0).to_be_bytes());
        cursor.extend_from_slice(&self.cursor);
        SourcePosition {
            stream: stream(source).into(),
            sequence,
            cursor,
        }
    }

    fn decode(position: &SourcePosition) -> Result<Self> {
        let Some((&version @ (1..=3), rest)) = position.cursor.split_first() else {
            return Err("INVALID_SSH_SOURCE_CHECKPOINT");
        };
        let Some((initialized_at, rest)) = rest.split_first_chunk::<8>() else {
            return Err("INVALID_SSH_SOURCE_CHECKPOINT");
        };
        let Some((last_read_at, cursor)) = rest.split_first_chunk::<8>() else {
            return Err("INVALID_SSH_SOURCE_CHECKPOINT");
        };
        let initialized_at = i64::from_be_bytes(*initialized_at);
        let last_read_at = i64::from_be_bytes(*last_read_at);
        if !(1..=253_402_300_799).contains(&initialized_at)
            || !(0..=253_402_300_799).contains(&last_read_at)
            || cursor.len() > MAX_SOURCE_CURSOR
            || (position.sequence == 0 && last_read_at != 0)
            || (version == 1 && position.sequence != 0 && (last_read_at == 0 || cursor.is_empty()))
            || (version == 3
                && (position.stream != JOURNAL_STREAM
                    || position.sequence == 0
                    || cursor.is_empty()))
        {
            return Err("INVALID_SSH_SOURCE_CHECKPOINT");
        }
        Ok(Self {
            initialized_at,
            last_record_read_at: (last_read_at != 0).then_some(last_read_at),
            cursor: cursor.to_vec(),
            resume_after_lost_journal: version == 3,
        })
    }
}

enum PollError {
    Source(SourceRead),
    Queue(&'static str),
}

impl From<JournalError> for PollError {
    fn from(error: JournalError) -> Self {
        Self::Source(match error {
            JournalError::Unavailable => SourceRead::Unavailable,
            JournalError::PermissionDenied => SourceRead::PermissionDenied,
            JournalError::CursorLost => SourceRead::CursorLost,
            JournalError::Read => SourceRead::ReadError,
        })
    }
}

impl From<FileError> for PollError {
    fn from(error: FileError) -> Self {
        Self::Source(match error {
            FileError::Unavailable => SourceRead::Unavailable,
            FileError::PermissionDenied => SourceRead::PermissionDenied,
            FileError::CursorLost => SourceRead::CursorLost,
            FileError::Read => SourceRead::ReadError,
        })
    }
}

impl From<&'static str> for PollError {
    fn from(error: &'static str) -> Self {
        Self::Queue(error)
    }
}

fn stream(source: SshSource) -> &'static str {
    match source {
        SshSource::Journald => JOURNAL_STREAM,
        SshSource::AuthLogFile => AUTH_FILE_STREAM,
    }
}

fn saved_position(buffer: &SharedBuffer) -> Result<Option<(SshSource, SourcePosition)>> {
    match (
        buffer.ssh.checkpoint(JOURNAL_STREAM)?,
        buffer.ssh.checkpoint(AUTH_FILE_STREAM)?,
    ) {
        (Some(position), None) => Ok(Some((SshSource::Journald, position))),
        (None, Some(position)) => Ok(Some((SshSource::AuthLogFile, position))),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err("CONFLICTING_SSH_SOURCE_CHECKPOINTS"),
    }
}

impl SshSourceReader {
    /// The durable checkpoint is authoritative after a failed admission or a
    /// process restart. An invalid anchor is retained for later recovery.
    pub fn poll(&mut self, buffer: &mut SharedBuffer, now: &QueueTime) -> Result<SourceRead> {
        self.poll_bounded(buffer, now, MAX_POLL_RECORDS)
    }

    fn poll_bounded(
        &mut self,
        buffer: &mut SharedBuffer,
        now: &QueueTime,
        limit: usize,
    ) -> Result<SourceRead> {
        if !(1..=253_402_300_799).contains(&now.unix_seconds) {
            return Err("INVALID_SSH_QUEUE_TIME");
        }
        let outcome = match self.read_selected(buffer, now, limit) {
            Ok(progress) => progress,
            Err(PollError::Queue(error)) => {
                self.last_outcome = Some(SourceRead::ReadError);
                return Err(error);
            }
            Err(PollError::Source(outcome)) => {
                self.journal = None;
                outcome
            }
        };
        self.last_outcome = Some(outcome);
        if outcome == SourceRead::CaughtUp {
            self.last_read_at = Some(now.unix_seconds);
        }
        if let Some(at) = self.last_read_at.filter(|at| *at == now.unix_seconds)
            && let Some((source, position)) = saved_position(buffer)?
            && buffer
                .ssh
                .source_recovery(stream(source))?
                .gap
                .is_some_and(|gap| gap.recovered_at.is_none())
            && let Err(error) = buffer.ssh.record_source_read(&position, at)
        {
            self.last_outcome = Some(SourceRead::ReadError);
            return Err(error);
        }
        Ok(outcome)
    }

    /// Report only facts supported by the latest read and the durable baseline.
    /// A missing cursor alone does not identify a lost range of unread records.
    pub fn heartbeat_report(
        &self,
        buffer: &mut SharedBuffer,
    ) -> Result<(Capability, Option<SshSourceDiagnostics>)> {
        let Some(outcome) = self.last_outcome else {
            return Ok((Capability::Unsupported, None));
        };
        let saved = saved_position(buffer)?;
        let checkpoint = saved
            .as_ref()
            .map(|(_, position)| Checkpoint::decode(position))
            .transpose()?;
        let initialized = checkpoint.is_some();
        let capability = match outcome {
            SourceRead::CaughtUp
            | SourceRead::More
            | SourceRead::Rebased
            | SourceRead::PendingLine
            | SourceRead::WaitingForRotation
                if initialized =>
            {
                Capability::Available
            }
            SourceRead::PermissionDenied => Capability::PermissionDenied,
            SourceRead::Unavailable if !initialized => Capability::Unsupported,
            _ => Capability::Error,
        };
        let counts = initialized
            .then(|| buffer.ssh_source_counters().ok())
            .flatten();
        let counters = SshSourceCounters {
            coverage: if counts.as_ref().is_some_and(|counts| counts.is_complete()) {
                SshCounterCoverage::Complete
            } else {
                SshCounterCoverage::Partial
            },
            unknown_format_records_total: counts
                .as_ref()
                .and_then(|counts| counts.unknown_format_records_total)
                .map(|count| count.to_string()),
            oversized_records_total: counts
                .as_ref()
                .and_then(|counts| counts.oversized_records_total)
                .map(|count| count.to_string()),
        };
        let initialized_at = checkpoint
            .as_ref()
            .map(|checkpoint| journal_timestamp(checkpoint.initialized_at as u64 * 1_000_000))
            .transpose()?;
        let mut gap = saved
            .as_ref()
            .map(|(source, _)| buffer.ssh.source_recovery(stream(*source)))
            .transpose()?
            .and_then(|recovery| recovery.gap);
        let mut durable_read_at =
            if let (Some((source, _)), Some(checkpoint)) = (&saved, &checkpoint) {
                buffer
                    .ssh
                    .source_read_at(stream(*source))?
                    .or(checkpoint.last_record_read_at)
            } else {
                None
            };
        if let (Some((_, position)), Some(at)) = (&saved, self.last_read_at)
            && (durable_read_at != Some(at)
                || gap.as_ref().is_some_and(|gap| gap.recovered_at.is_none()))
        {
            match buffer.ssh.record_source_read(position, at) {
                Ok(()) => {
                    durable_read_at = Some(at);
                    if let Some(gap) = &mut gap {
                        gap.recovered_at.get_or_insert(at);
                    }
                }
                Err("SSH_QUEUE_RESOURCE_LIMIT" | "RESOURCE_LIMIT")
                    if buffer.safely_reportable() => {}
                Err(code) => return Err(code),
            }
        }
        let last_read_at = durable_read_at.map(observation_timestamp).transpose()?;
        let recovered = gap.as_ref().is_none_or(|gap| gap.recovered_at.is_some());
        let last_gap = gap
            .map(|gap| -> Result<_> {
                Ok(SshSourceGap {
                    reason: gap.reason,
                    detected_at: observation_timestamp(gap.detected_at)?,
                    recovered_at: gap.recovered_at.map(observation_timestamp).transpose()?,
                })
            })
            .transpose()?;
        let diagnostics = SshSourceDiagnostics {
            source: saved.map(|(source, _)| source),
            initialized_at,
            last_read_at,
            is_caught_up: (outcome == SourceRead::CaughtUp
                && durable_read_at == self.last_read_at
                && recovered)
                .then_some(true),
            continuity: if last_gap.is_some() {
                SshContinuity::Gapped
            } else {
                SshContinuity::Unknown
            },
            continuous_since: None,
            last_gap,
            parse_coverage: if initialized {
                SshParseCoverage::Partial
            } else {
                SshParseCoverage::Unknown
            },
            counters,
        };
        Ok((capability, Some(diagnostics)))
    }

    fn read_selected(
        &mut self,
        buffer: &mut SharedBuffer,
        now: &QueueTime,
        limit: usize,
    ) -> std::result::Result<SourceRead, PollError> {
        match saved_position(buffer)? {
            Some((SshSource::Journald, position)) => {
                self.read_journal(buffer, now, Some(position), limit)
            }
            Some((SshSource::AuthLogFile, position)) => {
                self.read_file(buffer, now, Some(position), limit)
            }
            None => match self.read_journal(buffer, now, None, limit) {
                Err(PollError::Source(
                    outcome @ (SourceRead::Unavailable | SourceRead::PermissionDenied),
                )) if buffer.ssh.checkpoint(JOURNAL_STREAM)?.is_none() => {
                    self.journal = None;
                    match self.read_file(buffer, now, None, limit) {
                        Err(PollError::Source(SourceRead::Unavailable)) => {
                            Err(PollError::Source(outcome))
                        }
                        result => result,
                    }
                }
                result => result,
            },
        }
    }

    fn read_journal(
        &mut self,
        buffer: &mut SharedBuffer,
        now: &QueueTime,
        position: Option<SourcePosition>,
        limit: usize,
    ) -> std::result::Result<SourceRead, PollError> {
        if self.journal.is_none() {
            self.journal = Some(Journal::open()?);
        }
        let journal = self.journal.as_mut().expect("journal was opened");
        journal.refresh()?;
        let (mut position, mut checkpoint) = match position {
            Some(position) => {
                let checkpoint = Checkpoint::decode(&position)?;
                (position, checkpoint)
            }
            None => {
                let checkpoint = Checkpoint {
                    initialized_at: now.unix_seconds,
                    last_record_read_at: None,
                    cursor: journal.tail()?.unwrap_or_default(),
                    resume_after_lost_journal: false,
                };
                let position = checkpoint.encode(SshSource::Journald, 0);
                buffer.commit_source_disposition(&position, SourceDisposition::Ignored)?;
                (position, checkpoint)
            }
        };
        let resume = checkpoint.resume_after_lost_journal;
        if !resume {
            if checkpoint.cursor.is_empty() {
                journal.seek_head()?;
            } else {
                match journal.seek_after(&checkpoint.cursor) {
                    Ok(()) => {}
                    Err(JournalError::CursorLost) => {
                        return self.recover_journal(buffer, now, &position, checkpoint);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let started = Instant::now();
        for index in 0..=limit {
            // A restored exact anchor was already handled. Otherwise the
            // candidate positioned by libsystemd is the first record to read.
            let next = if resume && index == 0 {
                journal.next_after_lost(&checkpoint.cursor)?
            } else {
                journal.next()?
            };
            let Some(record) = next else {
                return Ok(SourceRead::CaughtUp);
            };
            if record.cursor == checkpoint.cursor {
                return Err(JournalError::Read.into());
            }
            if index == limit || (index > 0 && started.elapsed() >= POLL_BUDGET) {
                buffer
                    .ssh
                    .record_source_witness(&position, &journal_witness(&record))?;
                return Ok(SourceRead::More);
            }
            checkpoint.cursor.clone_from(&record.cursor);
            checkpoint.last_record_read_at = Some(now.unix_seconds);
            checkpoint.resume_after_lost_journal = false;
            position = checkpoint.encode(SshSource::Journald, next_sequence(&position)?);
            let classification = match record.message {
                JournalMessage::Bytes(bytes) => classify(&bytes),
                JournalMessage::Missing => {
                    RecordOutcome::Disposition(SourceDisposition::UnknownFormat)
                }
                JournalMessage::Oversized => {
                    RecordOutcome::Disposition(SourceDisposition::Oversized)
                }
            };
            commit_record(
                buffer,
                &position,
                now,
                SshSource::Journald,
                &record.cursor,
                classification,
                || Ok((record.boot_id, journal_timestamp(record.realtime_usec)?)),
            )?;
            self.last_read_at = Some(now.unix_seconds);
        }
        unreachable!("the lookahead exits at the record limit")
    }

    fn recover_journal(
        &mut self,
        buffer: &mut SharedBuffer,
        now: &QueueTime,
        position: &SourcePosition,
        mut checkpoint: Checkpoint,
    ) -> std::result::Result<SourceRead, PollError> {
        let mut verified = Journal::open_recovery_files()?;
        let mut fresh = Journal::open()?;
        if fresh.has_cursor(&checkpoint.cursor)? {
            self.journal = Some(fresh);
            return Ok(SourceRead::More);
        }
        if verified.has_cursor(&checkpoint.cursor)? {
            return Err(JournalError::CursorLost.into());
        }
        let witness = buffer.ssh.source_recovery(JOURNAL_STREAM)?.witness;
        let reason = if let Some(witness) = witness.as_deref() {
            let (boot, monotonic, cursor) = decode_journal_witness(witness)?;
            if verified.confirms_retention(cursor, boot, monotonic)? && !fresh.has_cursor(cursor)? {
                Some(SshGapReason::SourceRetention)
            } else {
                None
            }
        } else {
            None
        };
        fresh.refresh()?;
        if fresh.has_cursor(&checkpoint.cursor)? {
            self.journal = Some(fresh);
            return Ok(SourceRead::More);
        }
        checkpoint.resume_after_lost_journal = true;
        let replacement = checkpoint.encode(SshSource::Journald, next_sequence(position)?);
        let result = self.rebase(buffer, now, position, &replacement, reason)?;
        self.journal = Some(fresh);
        Ok(result)
    }

    fn read_file(
        &mut self,
        buffer: &mut SharedBuffer,
        now: &QueueTime,
        position: Option<SourcePosition>,
        limit: usize,
    ) -> std::result::Result<SourceRead, PollError> {
        let source = SshSource::AuthLogFile;
        let file = AuthFile::open()?;
        let (mut position, mut checkpoint, mut cursor) = match position {
            Some(position) => {
                let checkpoint = Checkpoint::decode(&position)?;
                let cursor = FileCursor::decode(&checkpoint.cursor)?;
                (position, checkpoint, cursor)
            }
            None => {
                let cursor = file.baseline()?;
                let checkpoint = Checkpoint {
                    initialized_at: now.unix_seconds,
                    last_record_read_at: None,
                    cursor: cursor.encode(),
                    resume_after_lost_journal: false,
                };
                let position = checkpoint.encode(source, 0);
                buffer.commit_source_disposition(&position, SourceDisposition::Ignored)?;
                (position, checkpoint, cursor)
            }
        };
        let started = Instant::now();
        for index in 0..limit {
            if index > 0 && started.elapsed() >= POLL_BUDGET {
                break;
            }
            let step = match file.next(&cursor) {
                Ok(step) => step,
                Err(FileError::CursorLost) => {
                    let witness = buffer
                        .ssh
                        .source_recovery(AUTH_FILE_STREAM)?
                        .witness
                        .as_deref()
                        .map(FileWitness::decode)
                        .transpose()?;
                    let Some(recovery) = file.recovery_plan(&cursor, witness.as_ref())? else {
                        return Ok(SourceRead::More);
                    };
                    let reason = if recovery.lost_unread {
                        Some(SshGapReason::FileTruncation)
                    } else if recovery.skipped_unread {
                        Some(SshGapReason::SourceReset)
                    } else {
                        None
                    };
                    checkpoint.cursor = recovery.cursor.encode();
                    let replacement = checkpoint.encode(source, next_sequence(&position)?);
                    return Ok(self.rebase(buffer, now, &position, &replacement, reason)?);
                }
                Err(error) => return Err(error.into()),
            };
            let record = match step {
                FileStep::CaughtUp => return Ok(SourceRead::CaughtUp),
                FileStep::PendingLine => return Ok(SourceRead::PendingLine),
                FileStep::WaitingForRotation => return Ok(SourceRead::WaitingForRotation),
                FileStep::Rotated(next) => {
                    cursor = next;
                    FileRecord::Ignored
                }
                FileStep::Record {
                    cursor: next,
                    record,
                } => {
                    cursor = next;
                    record
                }
            };
            checkpoint.cursor = cursor.encode();
            checkpoint.last_record_read_at = Some(now.unix_seconds);
            position = checkpoint.encode(source, next_sequence(&position)?);
            commit_file_record(buffer, &position, now, &checkpoint.cursor, record)?;
            self.last_read_at = Some(now.unix_seconds);
        }
        if let Some(witness) = file.observe_unread(&cursor)? {
            buffer
                .ssh
                .record_source_witness(&position, &witness.encode())?;
        }
        Ok(SourceRead::More)
    }

    fn rebase(
        &mut self,
        buffer: &mut SharedBuffer,
        now: &QueueTime,
        previous: &SourcePosition,
        replacement: &SourcePosition,
        reason: Option<SshGapReason>,
    ) -> Result<SourceRead> {
        if let Some(at) = self.last_read_at
            && (buffer.ssh.source_read_at(&previous.stream)? != Some(at)
                || buffer
                    .ssh
                    .source_recovery(&previous.stream)?
                    .gap
                    .is_some_and(|gap| gap.recovered_at.is_none()))
        {
            buffer.ssh.record_source_read(previous, at)?;
        }
        buffer
            .ssh
            .rebase_source(previous, replacement, now.unix_seconds, reason)?;
        // Reaching a safe restart position is not itself a successful read.
        self.last_read_at = None;
        Ok(SourceRead::Rebased)
    }
}

fn next_sequence(position: &SourcePosition) -> Result<u64> {
    position
        .sequence
        .checked_add(1)
        .ok_or("SSH_SOURCE_SEQUENCE_EXHAUSTED")
}

fn journal_witness(record: &JournalRecord) -> Vec<u8> {
    let mut witness = Vec::with_capacity(44 + record.cursor.len());
    witness.extend_from_slice(record.boot_id.as_bytes());
    witness.extend_from_slice(&record.monotonic_usec.to_be_bytes());
    witness.extend_from_slice(&record.cursor);
    witness
}

fn decode_journal_witness(witness: &[u8]) -> Result<(&str, u64, &[u8])> {
    let invalid = "INVALID_SSH_SOURCE_WITNESS";
    let (boot, rest) = witness.split_first_chunk::<36>().ok_or(invalid)?;
    let (monotonic, cursor) = rest.split_first_chunk::<8>().ok_or(invalid)?;
    let boot = std::str::from_utf8(boot).map_err(|_| invalid)?;
    if !crate::identity::uuid(boot) || cursor.is_empty() || cursor.len() > MAX_SOURCE_CURSOR {
        return Err(invalid);
    }
    Ok((boot, u64::from_be_bytes(*monotonic), cursor))
}

fn observation_timestamp(seconds: i64) -> Result<String> {
    journal_timestamp(seconds as u64 * 1_000_000)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileEnvelope {
    boot_id: String,
    at: String,
    message: String,
}

fn file_envelope(bytes: &[u8]) -> Option<FileEnvelope> {
    let envelope: FileEnvelope = serde_json::from_slice(bytes).ok()?;
    if crate::identity::uuid(&envelope.boot_id)
        && OffsetDateTime::parse(&envelope.at, &Rfc3339)
            .is_ok_and(|at| (1970..=9999).contains(&at.year()))
    {
        Some(envelope)
    } else {
        None
    }
}

fn commit_file_record(
    buffer: &mut SharedBuffer,
    position: &SourcePosition,
    now: &QueueTime,
    cursor: &[u8],
    record: FileRecord,
) -> Result<()> {
    let disposition = match record {
        FileRecord::Ignored => SourceDisposition::Ignored,
        FileRecord::Oversized => SourceDisposition::Oversized,
        FileRecord::Bytes(bytes) => {
            if let Some(envelope) = file_envelope(&bytes) {
                return commit_record(
                    buffer,
                    position,
                    now,
                    SshSource::AuthLogFile,
                    cursor,
                    classify(envelope.message.trim_ascii_start().as_bytes()),
                    || Ok((envelope.boot_id.to_ascii_lowercase(), envelope.at)),
                );
            }
            SourceDisposition::UnknownFormat
        }
    };
    buffer.commit_source_disposition(position, disposition)?;
    Ok(())
}

enum RecordOutcome {
    Disposition(SourceDisposition),
    Event {
        accepted: bool,
        source_ip: Option<std::net::IpAddr>,
        username: Option<String>,
    },
}

fn classify(bytes: &[u8]) -> RecordOutcome {
    match parse::classify(bytes) {
        Classification::Ignored => RecordOutcome::Disposition(SourceDisposition::Ignored),
        Classification::UnknownFormat => {
            RecordOutcome::Disposition(SourceDisposition::UnknownFormat)
        }
        Classification::Event {
            accepted,
            source_ip,
            username,
        } => RecordOutcome::Event {
            accepted,
            source_ip,
            username,
        },
    }
}

fn commit_record(
    buffer: &mut SharedBuffer,
    position: &SourcePosition,
    now: &QueueTime,
    source: SshSource,
    cursor: &[u8],
    outcome: RecordOutcome,
    origin: impl FnOnce() -> Result<(String, String)>,
) -> Result<()> {
    match outcome {
        RecordOutcome::Disposition(disposition) => {
            buffer.commit_source_disposition(position, disposition)?;
        }
        RecordOutcome::Event {
            accepted,
            source_ip,
            username,
        } => {
            let (boot_id, occurred_at) = origin()?;
            let body = serde_json::to_vec(&serde_json::json!({
                "eventId": source_event_id(source, cursor),
                "bootId": boot_id,
                "occurredAt": occurred_at,
                "eventType": if accepted { "SSH_LOGIN_SUCCEEDED" } else { "SSH_AUTH_FAILED" },
                "sourceIp": source_ip.map(|ip| ip.to_string()),
                "username": username,
            }))
            .map_err(|_| "INVALID_SSH_EVENT")?;
            buffer.ssh.enqueue(position, &body, now)?;
        }
    }
    Ok(())
}

fn journal_timestamp(micros: u64) -> Result<String> {
    let at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000)
        .map_err(|_| "INVALID_SSH_JOURNAL_TIMESTAMP")?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        micros % 1_000_000,
    ))
}

fn source_event_id(source: SshSource, cursor: &[u8]) -> String {
    let mut digest = Context::new(&SHA256);
    digest.update(match source {
        SshSource::Journald => b"nodomi ssh journal event v1\0",
        SshSource::AuthLogFile => b"nodomi ssh auth file event v1\0",
    });
    digest.update(cursor);
    let result = digest.finish();
    let mut uuid: [u8; 16] = result.as_ref()[..16].try_into().expect("SHA-256 size");
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    let hex: String = uuid.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Fresh residence evidence uses the current boot, never the journal entry's boot.
pub fn queue_time(boot_id: &str) -> Result<QueueTime> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the kernel receives a writable, aligned timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0
        || time.tv_sec < 0
        || !(0..1_000_000_000).contains(&time.tv_nsec)
    {
        return Err("LOCAL_RUNTIME_UNAVAILABLE");
    }
    let monotonic_ns = (time.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(time.tv_nsec as u64))
        .ok_or("LOCAL_RUNTIME_UNAVAILABLE")?;
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|wall| i64::try_from(wall.as_secs()).ok())
        .filter(|value| (1..=253_402_300_799).contains(value))
        .ok_or("LOCAL_RUNTIME_UNAVAILABLE")?;
    Ok(QueueTime {
        boot_id: boot_id.into(),
        monotonic_ns,
        unix_seconds,
    })
}
