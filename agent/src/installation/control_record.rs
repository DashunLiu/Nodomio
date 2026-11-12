//! The private, bounded journal record for control-domain preparation.
use super::{
    operation_journal::BusinessOperation,
    plan::{canonical_target, valid_plan_id},
    plan_store::{
        PlanStoreError, check_directory, check_file, effective_uid, open_at, same_snapshot, stat,
    },
};
use crate::identity::Target;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read},
};

#[cfg(test)]
use super::plan_store::TemporaryPlan;
#[cfg(test)]
use std::{io::Write, os::fd::AsRawFd};

const PURPOSE: &str = "NODOMI_AGENT_CONTROL_V1";
const SCHEMA_VERSION: u32 = 1;
const LAYOUT_ID: &str = "V1";
const TARGET_KEY: &str = "AGENT_INSTALL";
const MAX_CONTROL_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlRecordError {
    UnsafeDirectory,
    UnsafeEntry,
    InvalidRecord,
    TooLarge,
    NotFound,
    #[cfg(test)]
    Conflict,
    Io,
    #[cfg(test)]
    CommitOutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum ControlPhase {
    Claimed,
    LockCreatePossible,
    Ready,
}

impl ControlPhase {
    fn revision(self) -> u64 {
        match self {
            Self::Claimed => 1,
            Self::LockCreatePossible => 2,
            Self::Ready => 3,
        }
    }

    #[cfg(test)]
    fn next(self) -> Option<Self> {
        match self {
            Self::Claimed => Some(Self::LockCreatePossible),
            Self::LockCreatePossible => Some(Self::Ready),
            Self::Ready => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PreparationClaim {
    pub(super) operation_id: String,
    pub(super) idempotency_key: String,
    pub(super) plan_id: String,
    pub(super) plan_digest: String,
    pub(super) installation_id: String,
    pub(super) target: Target,
}

impl PreparationClaim {
    fn is_valid(&self) -> bool {
        [
            &self.operation_id,
            &self.idempotency_key,
            &self.plan_id,
            &self.installation_id,
        ]
        .into_iter()
        .all(|id| valid_plan_id(id))
            && self.plan_digest.len() == 64
            && self
                .plan_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && canonical_target(&self.target.origin, &self.target.expected_server_id)
                .is_ok_and(|target| target == self.target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ControlRecord {
    purpose: String,
    schema_version: u32,
    control_domain_id: String,
    layout_id: String,
    target_key: String,
    revision: u64,
    phase: ControlPhase,
    claim: PreparationClaim,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    business: Option<BusinessOperation>,
}

impl ControlRecord {
    #[cfg(test)]
    pub(super) fn claimed(
        control_domain_id: String,
        claim: PreparationClaim,
    ) -> Result<Self, ControlRecordError> {
        let record = Self {
            purpose: PURPOSE.into(),
            schema_version: SCHEMA_VERSION,
            control_domain_id,
            layout_id: LAYOUT_ID.into(),
            target_key: TARGET_KEY.into(),
            revision: ControlPhase::Claimed.revision(),
            phase: ControlPhase::Claimed,
            claim,
            business: None,
        };
        record.encode()?;
        Ok(record)
    }

    pub(super) fn control_domain_id(&self) -> &str {
        &self.control_domain_id
    }

    pub(super) fn claim(&self) -> &PreparationClaim {
        &self.claim
    }

    pub(super) fn phase(&self) -> ControlPhase {
        self.phase
    }

    pub(super) fn business(&self) -> Option<&BusinessOperation> {
        self.business.as_ref()
    }

    #[cfg(test)]
    pub(super) fn revision(&self) -> u64 {
        self.revision
    }

    fn encode(&self) -> Result<Vec<u8>, ControlRecordError> {
        let mut revision = self.phase.revision();
        if let Some(business) = &self.business {
            if self.phase != ControlPhase::Ready
                || !business.is_valid()
                || !business.matches_target(&self.claim.target)
            {
                return Err(ControlRecordError::InvalidRecord);
            }
            revision = revision
                .checked_add(business.revision())
                .ok_or(ControlRecordError::InvalidRecord)?;
        }
        if self.purpose != PURPOSE
            || self.schema_version != SCHEMA_VERSION
            || !valid_plan_id(&self.control_domain_id)
            || self.layout_id != LAYOUT_ID
            || self.target_key != TARGET_KEY
            || self.revision != revision
            || !self.claim.is_valid()
        {
            return Err(ControlRecordError::InvalidRecord);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ControlRecordError::InvalidRecord)?;
        if bytes.len() > MAX_CONTROL_BYTES {
            return Err(ControlRecordError::TooLarge);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ControlRecordError> {
        if bytes.len() > MAX_CONTROL_BYTES {
            return Err(ControlRecordError::TooLarge);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| ControlRecordError::InvalidRecord)?;
        // The journal is generated internally. Require exact canonical object
        // bytes so even a positional Serde struct representation is rejected.
        if record.encode()? != bytes {
            return Err(ControlRecordError::InvalidRecord);
        }
        Ok(record)
    }
}

fn storage_error(error: PlanStoreError) -> ControlRecordError {
    match error {
        PlanStoreError::UnsafeDirectory => ControlRecordError::UnsafeDirectory,
        PlanStoreError::UnsafeEntry => ControlRecordError::UnsafeEntry,
        PlanStoreError::TooLarge => ControlRecordError::TooLarge,
        _ => ControlRecordError::Io,
    }
}

fn checked_size(metadata: &libc::stat, owner: libc::uid_t) -> Result<usize, ControlRecordError> {
    let size = check_file(metadata, owner).map_err(storage_error)?;
    if size > MAX_CONTROL_BYTES {
        return Err(ControlRecordError::TooLarge);
    }
    Ok(size)
}

pub(super) fn read_record(directory: &File) -> Result<ControlRecord, ControlRecordError> {
    let owner = effective_uid();
    check_directory(directory, owner).map_err(storage_error)?;
    let listed = stat(directory, Some(c"control.json")).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ControlRecordError::NotFound
        } else {
            ControlRecordError::Io
        }
    })?;
    let size = checked_size(&listed, owner)?;
    let file = open_at(directory, c"control.json", libc::O_RDONLY)
        .map_err(|_| ControlRecordError::UnsafeEntry)?;
    let opened = stat(&file, None).map_err(|_| ControlRecordError::Io)?;
    if !same_snapshot(&opened, &listed) {
        return Err(ControlRecordError::UnsafeEntry);
    }
    let mut bytes = Vec::with_capacity(size);
    (&file)
        .take((MAX_CONTROL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ControlRecordError::Io)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(ControlRecordError::TooLarge);
    }
    let after = stat(&file, None).map_err(|_| ControlRecordError::Io)?;
    let named_after =
        stat(directory, Some(c"control.json")).map_err(|_| ControlRecordError::UnsafeEntry)?;
    if bytes.len() != size
        || !same_snapshot(&opened, &after)
        || !same_snapshot(&opened, &named_after)
    {
        return Err(ControlRecordError::UnsafeEntry);
    }
    check_directory(directory, owner).map_err(storage_error)?;
    ControlRecord::decode(&bytes)
}

/// Called only while the preparer holds its exclusive lock on this directory.
#[cfg(test)]
pub(super) fn publish_claimed(
    directory: &File,
    claimed: &ControlRecord,
) -> Result<(), ControlRecordError> {
    if claimed.phase != ControlPhase::Claimed {
        return Err(ControlRecordError::Conflict);
    }
    write_record(directory, claimed, true, File::sync_all)
}

/// Called only while the preparer holds its exclusive lock on this directory.
#[cfg(test)]
pub(super) fn advance_record(
    directory: &File,
    expected: &ControlRecord,
    next: ControlPhase,
) -> Result<ControlRecord, ControlRecordError> {
    if expected.phase.next() != Some(next) || read_record(directory)? != *expected {
        return Err(ControlRecordError::Conflict);
    }
    let mut updated = expected.clone();
    updated.phase = next;
    updated.revision = next.revision();
    write_record(directory, &updated, false, File::sync_all)?;
    Ok(updated)
}

#[cfg(test)]
fn write_record(
    directory: &File,
    record: &ControlRecord,
    first_publication: bool,
    sync_parent: impl FnOnce(&File) -> io::Result<()>,
) -> Result<(), ControlRecordError> {
    let bytes = record.encode()?;
    let owner = effective_uid();
    check_directory(directory, owner).map_err(storage_error)?;
    // A separate descriptor supports fsync even if the caller's anchor is O_PATH.
    // The caller's independent lock on the original descriptor remains held.
    let synced_directory = open_at(directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|_| ControlRecordError::Io)?;
    let mut temporary = TemporaryPlan::create(directory).map_err(storage_error)?;
    temporary
        .file
        .write_all(&bytes)
        .and_then(|()| temporary.file.sync_all())
        .map_err(|_| ControlRecordError::Io)?;
    let written = stat(&temporary.file, None).map_err(|_| ControlRecordError::Io)?;
    if checked_size(&written, owner)? != bytes.len() || !temporary.owns_name() {
        return Err(ControlRecordError::UnsafeEntry);
    }
    check_directory(directory, owner).map_err(storage_error)?;

    // SAFETY: both names are NUL-terminated single components in the live
    // directory. The first publication cannot overwrite; subsequent replacement
    // is serialized by the caller's directory lock and exact record comparison.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory.as_raw_fd(),
            temporary.name.as_ptr(),
            directory.as_raw_fd(),
            c"control.json".as_ptr(),
            if first_publication {
                libc::RENAME_NOREPLACE
            } else {
                0
            },
        )
    };
    if result != 0 {
        return Err(
            if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
                ControlRecordError::Conflict
            } else {
                ControlRecordError::Io
            },
        );
    }
    temporary.published = true;
    sync_parent(&synced_directory).map_err(|_| ControlRecordError::CommitOutcomeUnknown)
}

/// Compare and replace the active business state under the original execution lease.
#[cfg(test)]
pub(super) fn replace_business_record(
    directory: &File,
    expected: &ControlRecord,
    business: BusinessOperation,
) -> Result<ControlRecord, ControlRecordError> {
    if expected.phase != ControlPhase::Ready
        || !business.can_follow(expected.business())
        || read_record(directory)? != *expected
    {
        return Err(ControlRecordError::Conflict);
    }
    let revision = expected
        .revision
        .checked_add(1)
        .ok_or(ControlRecordError::InvalidRecord)?;
    if ControlPhase::Ready
        .revision()
        .checked_add(business.revision())
        != Some(revision)
    {
        return Err(ControlRecordError::Conflict);
    }
    let mut updated = expected.clone();
    updated.revision = revision;
    updated.business = Some(business);
    write_record(directory, &updated, false, File::sync_all)?;
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, Permissions},
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
    };

    const DOMAIN_ID: &str = "11111111-1111-4111-8111-111111111111";
    const OPERATION_ID: &str = "22222222-2222-4222-8222-222222222222";
    const KEY: &str = "33333333-3333-4333-8333-333333333333";
    const PLAN_ID: &str = "44444444-4444-4444-8444-444444444444";
    const INSTALLATION_ID: &str = "55555555-5555-4555-8555-555555555555";

    fn fixture() -> tempfile::TempDir {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), Permissions::from_mode(0o700)).unwrap();
        fixture
    }

    fn locked(directory: &Path) -> File {
        let descriptor = File::open(directory).unwrap();
        // SAFETY: the fixture owns a live, independently opened directory descriptor.
        assert_eq!(
            unsafe { libc::flock(descriptor.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        descriptor
    }

    fn claim() -> PreparationClaim {
        PreparationClaim {
            operation_id: OPERATION_ID.into(),
            idempotency_key: KEY.into(),
            plan_id: PLAN_ID.into(),
            plan_digest: "a".repeat(64),
            installation_id: INSTALLATION_ID.into(),
            target: Target::new("https://management.example", "server-1").unwrap(),
        }
    }

    fn claimed() -> ControlRecord {
        ControlRecord::claimed(DOMAIN_ID.into(), claim()).unwrap()
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn preserves_the_original_claim_and_advances_only_the_expected_revision() {
        let fixture = fixture();
        let directory = locked(fixture.path());
        let path = fixture.path().join("control.json");
        assert_eq!(read_record(&directory), Err(ControlRecordError::NotFound));

        let original = claimed();
        publish_claimed(&directory, &original).unwrap();
        assert_eq!(read_record(&directory).unwrap(), original);
        assert_eq!(original.control_domain_id(), DOMAIN_ID);
        assert_eq!(original.claim(), &claim());
        let original_bytes = fs::read(&path).unwrap();

        let competing = ControlRecord::claimed(
            DOMAIN_ID.into(),
            PreparationClaim {
                operation_id: PLAN_ID.into(),
                ..claim()
            },
        )
        .unwrap();
        assert_eq!(
            publish_claimed(&directory, &competing),
            Err(ControlRecordError::Conflict)
        );
        assert_eq!(
            advance_record(&directory, &competing, ControlPhase::LockCreatePossible),
            Err(ControlRecordError::Conflict)
        );
        assert_eq!(
            advance_record(&directory, &original, ControlPhase::Ready),
            Err(ControlRecordError::Conflict)
        );
        assert_eq!(fs::read(&path).unwrap(), original_bytes);

        let possible =
            advance_record(&directory, &original, ControlPhase::LockCreatePossible).unwrap();
        assert_eq!(possible.revision(), 2);
        assert_eq!(possible.phase(), ControlPhase::LockCreatePossible);
        assert_eq!(
            advance_record(&directory, &original, ControlPhase::LockCreatePossible),
            Err(ControlRecordError::Conflict)
        );
        let ready = advance_record(&directory, &possible, ControlPhase::Ready).unwrap();
        assert_eq!(ready.revision(), 3);
        assert_eq!(ready.phase(), ControlPhase::Ready);
        assert_eq!(ready.control_domain_id(), DOMAIN_ID);
        assert_eq!(ready.claim(), original.claim());
        assert_eq!(
            advance_record(&directory, &ready, ControlPhase::Claimed),
            Err(ControlRecordError::Conflict)
        );
        drop(directory);

        let reopened = File::open(fixture.path()).unwrap();
        assert_eq!(read_record(&reopened).unwrap(), ready);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 1);
    }

    #[test]
    fn rejects_noncanonical_records_and_invalid_claim_binding() {
        let record = claimed();
        let bytes = record.encode().unwrap();
        assert_eq!(ControlRecord::decode(&bytes).unwrap(), record);
        let mut padded = bytes.clone();
        padded.push(b'\n');
        assert_eq!(
            ControlRecord::decode(&padded),
            Err(ControlRecordError::InvalidRecord)
        );

        let mut invalid = record.clone();
        invalid.revision += 1;
        assert_eq!(
            ControlRecord::decode(&serde_json::to_vec(&invalid).unwrap()),
            Err(ControlRecordError::InvalidRecord)
        );
        for bad in [
            PreparationClaim {
                operation_id: "op-1".into(),
                ..claim()
            },
            PreparationClaim {
                idempotency_key: "opaque".into(),
                ..claim()
            },
            PreparationClaim {
                plan_digest: "A".repeat(64),
                ..claim()
            },
            PreparationClaim {
                target: Target {
                    origin: "https://MANAGEMENT.example".into(),
                    expected_server_id: "server-1".into(),
                },
                ..claim()
            },
        ] {
            assert_eq!(
                ControlRecord::claimed(DOMAIN_ID.into(), bad),
                Err(ControlRecordError::InvalidRecord)
            );
        }

        let mut extra = serde_json::to_value(&record).unwrap();
        extra["claim"]["credential"] = serde_json::json!("synthetic secret");
        assert_eq!(
            ControlRecord::decode(&serde_json::to_vec(&extra).unwrap()),
            Err(ControlRecordError::InvalidRecord)
        );

        let mut positional = serde_json::to_value(&record).unwrap();
        positional["claim"]["target"] =
            serde_json::json!(["https://management.example", "server-1"]);
        assert_eq!(
            ControlRecord::decode(&serde_json::to_vec(&positional).unwrap()),
            Err(ControlRecordError::InvalidRecord)
        );
    }

    #[test]
    fn protects_the_directory_and_bounds_reads_before_decoding() {
        let fixture = fixture();
        let directory = File::open(fixture.path()).unwrap();
        let path = fixture.path().join("control.json");
        let external = tempfile::tempdir().unwrap();
        let canary = external.path().join("canary");
        let record = claimed().encode().unwrap();
        private_file(&canary, &record);

        symlink(&canary, &path).unwrap();
        assert_eq!(
            read_record(&directory),
            Err(ControlRecordError::UnsafeEntry)
        );
        assert_eq!(fs::read_link(&path).unwrap(), canary);
        fs::remove_file(&path).unwrap();
        fs::hard_link(&canary, &path).unwrap();
        assert_eq!(
            read_record(&directory),
            Err(ControlRecordError::UnsafeEntry)
        );
        assert_eq!(fs::read(&canary).unwrap(), record);
        fs::remove_file(&path).unwrap();

        let oversized = vec![0; MAX_CONTROL_BYTES + 1];
        private_file(&path, &oversized);
        assert_eq!(read_record(&directory), Err(ControlRecordError::TooLarge));
        assert_eq!(fs::read(&path).unwrap(), oversized);

        private_file(&path, &record);
        fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            read_record(&directory),
            Err(ControlRecordError::UnsafeEntry)
        );
        fs::set_permissions(fixture.path(), Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            read_record(&directory),
            Err(ControlRecordError::UnsafeDirectory)
        );
        assert_eq!(fs::read(&path).unwrap(), record);
    }

    #[test]
    fn failed_directory_sync_preserves_published_claim() {
        let fixture = fixture();
        let directory = locked(fixture.path());
        let original = claimed();
        assert_eq!(
            write_record(&directory, &original, true, |_| Err(
                io::Error::from_raw_os_error(libc::EIO)
            )),
            Err(ControlRecordError::CommitOutcomeUnknown),
        );
        assert_eq!(read_record(&directory).unwrap(), original);
        assert_eq!(
            publish_claimed(&directory, &original),
            Err(ControlRecordError::Conflict)
        );
        assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 1);
    }
}
