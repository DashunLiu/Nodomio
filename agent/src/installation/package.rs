//! Read-only inspection of the formal and rehearsal package profiles.

use super::executable::{
    EXECUTABLE_PREFIX_BYTES, ExecutableError, ExecutableHeader, inspect_executable,
};
use crate::release::{
    github::VerifiedRelease,
    manifest::{MAX_ARTIFACT_BYTES, Platform, parse_agent_tag},
};
use flate2::bufread::GzDecoder;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
};

const TAR_BLOCK: usize = 512;
const TAR_RECORD_BLOCKS: usize = 20;
const MAX_DIAGNOSTIC_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 1024;
const MAX_FORMAL_CONTENT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FORMAL_SERVICE_BYTES: u64 = 64 * 1024;
const MAX_FORMAL_LICENSE_BYTES: u64 = 1024 * 1024;
pub(super) const FORMAL_MEMBER_COUNT: usize = 6;
const FORMAL_MEMBERS: [(&str, u32, bool); FORMAL_MEMBER_COUNT] = [
    ("bin/nodomi-agent", 0o755, true),
    ("bin/nodomi-agentctl", 0o755, true),
    ("bin/nodomi-agent-supervisor", 0o755, true),
    ("services/systemd/nodomi-agent.service", 0o644, false),
    ("services/openrc/nodomi-agent", 0o755, false),
    ("LICENSE", 0o644, false),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageInspectionError {
    Io,
    InvalidFile,
    InvalidGzip,
    InvalidArchive,
    UnsupportedLayout,
    InvalidRehearsalRecord,
    InvalidTextMember,
    DigestMismatch,
    StageWrite,
    StageSpace,
    Executable(ExecutableError),
}

/// Structural and byte-count observations for a diagnostic rehearsal package.
/// `commit` is the record's declaration. No source or install authority is issued.
#[derive(Debug, PartialEq, Eq)]
pub struct RehearsalPackage {
    pub tag: String,
    pub commit: String,
    pub compressed_bytes: u64,
    pub compressed_sha256: String,
    pub diagnostic_bytes: u64,
    pub record_bytes: u64,
    pub executable: ExecutableHeader,
}

/// Stream an already opened package from offset zero without extracting files.
/// This accepts only the two-member rehearsal profile, independent of filename.
pub fn inspect_rehearsal_package(file: File) -> Result<RehearsalPackage, PackageInspectionError> {
    let (archive, (record, diagnostic_bytes, record_bytes, executable)) =
        inspect_archive(file, read_rehearsal)?;
    Ok(RehearsalPackage {
        tag: record.tag,
        commit: record.commit,
        compressed_bytes: archive.bytes,
        compressed_sha256: archive.sha256,
        diagnostic_bytes,
        record_bytes,
        executable,
    })
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormalPackageMember {
    pub path: &'static str,
    pub mode: u32,
    pub length: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<ExecutableHeader>,
}

/// Observations bound to the exact compressed bytes scanned and the expected platform.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormalPackage {
    pub platform: Platform,
    pub archive_bytes: u64,
    pub archive_sha256: String,
    pub expanded_member_bytes: u64,
    pub members: Vec<FormalPackageMember>,
}

fn formal_text_limit(path: &str) -> u64 {
    if path == "LICENSE" {
        MAX_FORMAL_LICENSE_BYTES
    } else {
        MAX_FORMAL_SERVICE_BYTES
    }
}

pub(super) fn formal_member_lengths_valid(lengths: [u64; FORMAL_MEMBER_COUNT]) -> bool {
    let mut total = 0_u64;
    for (length, (path, _, binary)) in lengths.into_iter().zip(FORMAL_MEMBERS) {
        let allowed = if binary {
            64..=MAX_FORMAL_CONTENT_BYTES
        } else {
            1..=formal_text_limit(path)
        };
        if !allowed.contains(&length) {
            return false;
        }
        total += length;
    }
    total <= MAX_FORMAL_CONTENT_BYTES
}

/// Check the six ordered regular files in the formal package without extraction.
pub fn inspect_formal_package(
    file: File,
    platform: Platform,
) -> Result<FormalPackage, PackageInspectionError> {
    scan_formal(file, platform, None)
}

fn scan_formal(
    file: File,
    platform: Platform,
    staging: Option<FormalStaging<'_>>,
) -> Result<FormalPackage, PackageInspectionError> {
    let (archive, (members, expanded_member_bytes)) =
        inspect_archive(file, |reader| read_formal(reader, platform, staging))?;
    Ok(FormalPackage {
        platform,
        archive_bytes: archive.bytes,
        archive_sha256: archive.sha256,
        expanded_member_bytes,
        members,
    })
}

struct FormalStaging<'a> {
    expected: &'a FormalPackage,
    outputs: [Option<&'a mut File>; FORMAL_MEMBER_COUNT],
}

/// Copy only to private, newly created staging files held by the installer.
/// The caller publishes them only after success and synchronization.
#[cfg(test)]
pub(super) fn stage_formal_members<'a>(
    archive: &File,
    expected: &'a FormalPackage,
    outputs: [Option<&'a mut File>; FORMAL_MEMBER_COUNT],
) -> Result<(), PackageInspectionError> {
    let file = archive
        .try_clone()
        .map_err(|_| PackageInspectionError::Io)?;
    let actual = scan_formal(
        file,
        expected.platform,
        Some(FormalStaging { expected, outputs }),
    )?;
    if actual != *expected {
        return Err(PackageInspectionError::DigestMismatch);
    }
    Ok(())
}

/// Match a formal package to the archive bytes in an already verified release.
pub fn verify_formal_package(
    file: File,
    release: &VerifiedRelease,
) -> Result<FormalPackage, PackageInspectionError> {
    let target = release.target();
    let inspected = inspect_formal_package(file, target.platform)?;
    if inspected.archive_bytes != target.artifact.length
        || inspected.archive_sha256 != target.artifact.sha256
    {
        return Err(PackageInspectionError::DigestMismatch);
    }
    Ok(inspected)
}

struct ArchiveFacts {
    bytes: u64,
    sha256: String,
}

fn inspect_archive<T>(
    mut file: File,
    scan: impl FnOnce(&mut dyn Read) -> Result<T, PackageInspectionError>,
) -> Result<(ArchiveFacts, T), PackageInspectionError> {
    use PackageInspectionError::*;
    let before = file.metadata().map_err(|_| Io)?;
    let compressed_bytes = before.len();
    if !before.is_file() || !(1..=MAX_ARTIFACT_BYTES).contains(&compressed_bytes) {
        return Err(InvalidFile);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| Io)?;
    let mut hashed = HashingReader::new((&mut file).take(compressed_bytes + 1));
    let mut gzip_header = [0u8; 10];
    hashed
        .read_exact(&mut gzip_header)
        .map_err(|_| InvalidGzip)?;
    // The writers supply no optional header fields. Feed the same
    // bytes to the decoder to bound its header allocation even on mutable input.
    if gzip_header[..4] != [0x1f, 0x8b, 8, 0] {
        return Err(InvalidGzip);
    }
    let source = BufReader::new(Cursor::new(gzip_header).chain(&mut hashed));
    let mut decoder = GzDecoder::new(source);
    let observed = scan(&mut decoder)?;
    read_end(&mut decoder)?;
    // read_end drains through the gzip trailer. The bufread decoder leaves
    // a second member or trailing bytes available here instead of consuming them.
    if !decoder.into_inner().fill_buf().map_err(|_| Io)?.is_empty() {
        return Err(InvalidGzip);
    }
    if hashed.bytes_read != compressed_bytes {
        return Err(InvalidFile);
    }
    let sha256 = hashed.sha256();
    let after = file.metadata().map_err(|_| Io)?;
    if after.len() != compressed_bytes
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
    {
        return Err(InvalidFile);
    }
    Ok((
        ArchiveFacts {
            bytes: compressed_bytes,
            sha256,
        },
        observed,
    ))
}

struct HashingReader<R> {
    inner: R,
    digest: Context,
    bytes_read: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            digest: Context::new(&SHA256),
            bytes_read: 0,
        }
    }

    fn sha256(self) -> String {
        self.digest
            .finish()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes_read += read as u64;
        self.digest.update(&buffer[..read]);
        Ok(read)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RehearsalRecord {
    #[serde(rename = "mode")]
    _mode: RehearsalMode,
    tag: String,
    commit: String,
    platform: Platform,
}

#[derive(Deserialize)]
enum RehearsalMode {
    #[serde(rename = "REHEARSAL")]
    Rehearsal,
}

fn read_rehearsal(
    reader: &mut dyn Read,
) -> Result<(RehearsalRecord, u64, u64, ExecutableHeader), PackageInspectionError> {
    use PackageInspectionError::*;
    let diagnostic_bytes = entry_size(reader, b"bin/nodomi-agent-diagnostic", 0o755)?;
    if !(64..=MAX_DIAGNOSTIC_BYTES).contains(&diagnostic_bytes) {
        return Err(InvalidArchive);
    }
    let mut prefix = vec![0; diagnostic_bytes.min(EXECUTABLE_PREFIX_BYTES as u64) as usize];
    reader.read_exact(&mut prefix).map_err(|_| InvalidArchive)?;
    let remaining = diagnostic_bytes - prefix.len() as u64;
    let skipped = io::copy(&mut (&mut *reader).take(remaining), &mut io::sink())
        .map_err(|_| InvalidArchive)?;
    if skipped != remaining {
        return Err(InvalidArchive);
    }
    read_padding(reader, diagnostic_bytes)?;

    let record_bytes = entry_size(reader, b"REHEARSAL.json", 0o644)?;
    if !(1..=MAX_RECORD_BYTES).contains(&record_bytes) {
        return Err(InvalidRehearsalRecord);
    }
    let mut raw = vec![0; record_bytes as usize];
    reader.read_exact(&mut raw).map_err(|_| InvalidArchive)?;
    let record = parse_record(&raw)?;
    let executable =
        inspect_executable(&prefix, diagnostic_bytes, record.platform).map_err(Executable)?;
    read_padding(reader, record_bytes)?;
    Ok((record, diagnostic_bytes, record_bytes, executable))
}

fn read_formal(
    reader: &mut dyn Read,
    platform: Platform,
    mut staging: Option<FormalStaging<'_>>,
) -> Result<(Vec<FormalPackageMember>, u64), PackageInspectionError> {
    use PackageInspectionError::*;
    let mut members = Vec::with_capacity(FORMAL_MEMBERS.len());
    let mut remaining = MAX_FORMAL_CONTENT_BYTES;
    for (index, (path, mode, binary)) in FORMAL_MEMBERS.into_iter().enumerate() {
        let length = entry_size(reader, path.as_bytes(), u64::from(mode))?;
        remaining = remaining.checked_sub(length).ok_or(InvalidArchive)?;
        let (expected, output) = if let Some(staging) = staging.as_mut() {
            let expected = staging
                .expected
                .members
                .get(index)
                .filter(|member| member.path == path && member.length == length)
                .ok_or(DigestMismatch)?;
            (Some(expected), staging.outputs[index].take())
        } else {
            (None, None)
        };
        let mut member = HashingReader::new((&mut *reader).take(length));
        let mut output = output.map_or(Ok(None), |file| {
            if file.metadata().is_ok_and(|m| m.is_file() && m.len() == 0)
                && file.stream_position().is_ok_and(|position| position == 0)
            {
                Ok(Some(file))
            } else {
                Err(StageWrite)
            }
        })?;
        let executable = if binary {
            let mut prefix = vec![0; length.min(EXECUTABLE_PREFIX_BYTES as u64) as usize];
            member.read_exact(&mut prefix).map_err(|_| InvalidArchive)?;
            let executable = inspect_executable(&prefix, length, platform).map_err(Executable)?;
            if let Some(file) = output.as_deref_mut() {
                file.write_all(&prefix).map_err(stage_write_error)?;
                copy_member(&mut member, file)?;
            } else {
                io::copy(&mut member, &mut io::sink()).map_err(|_| InvalidArchive)?;
            }
            Some(executable)
        } else {
            if !(1..=formal_text_limit(path)).contains(&length) {
                return Err(InvalidTextMember);
            }
            let mut bytes = vec![0; length as usize];
            member.read_exact(&mut bytes).map_err(|_| InvalidArchive)?;
            if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
                return Err(InvalidTextMember);
            }
            if let Some(file) = output.as_deref_mut() {
                file.write_all(&bytes).map_err(stage_write_error)?;
            }
            None
        };
        if member.bytes_read != length {
            return Err(InvalidArchive);
        }
        let observed = FormalPackageMember {
            path,
            mode,
            length,
            sha256: member.sha256(),
            executable,
        };
        if expected.is_some_and(|expected| observed != *expected) {
            return Err(DigestMismatch);
        }
        members.push(observed);
        read_padding(reader, length)?;
    }
    Ok((members, MAX_FORMAL_CONTENT_BYTES - remaining))
}

fn copy_member(reader: &mut impl Read, output: &mut File) -> Result<(), PackageInspectionError> {
    let mut buffer = [0; 16 * 1024];
    loop {
        let size = reader
            .read(&mut buffer)
            .map_err(|_| PackageInspectionError::InvalidArchive)?;
        if size == 0 {
            return Ok(());
        }
        output
            .write_all(&buffer[..size])
            .map_err(stage_write_error)?;
    }
}

fn stage_write_error(error: io::Error) -> PackageInspectionError {
    match error.raw_os_error() {
        Some(libc::ENOSPC | libc::EDQUOT) => PackageInspectionError::StageSpace,
        _ => PackageInspectionError::StageWrite,
    }
}

fn parse_record(raw: &[u8]) -> Result<RehearsalRecord, PackageInspectionError> {
    use PackageInspectionError::InvalidRehearsalRecord;
    if raw.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err(InvalidRehearsalRecord);
    }
    let record: RehearsalRecord =
        serde_json::from_slice(raw).map_err(|_| InvalidRehearsalRecord)?;
    if parse_agent_tag(&record.tag).is_err()
        || record.commit.len() != 40
        || !record
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InvalidRehearsalRecord);
    }
    Ok(record)
}

fn entry_size(
    reader: &mut (impl Read + ?Sized),
    name: &[u8],
    mode: u64,
) -> Result<u64, PackageInspectionError> {
    use PackageInspectionError::*;
    let mut header = [0; TAR_BLOCK];
    reader.read_exact(&mut header).map_err(|_| InvalidArchive)?;
    if &header[257..265] != b"ustar\x0000" {
        return Err(UnsupportedLayout);
    }
    let checksum = octal(&header[148..156]).ok_or(InvalidArchive)?;
    header[148..156].fill(b' ');
    if header.iter().map(|byte| u64::from(*byte)).sum::<u64>() != checksum {
        return Err(InvalidArchive);
    }
    if !header[..100].starts_with(name)
        || header[name.len()..100].iter().any(|byte| *byte != 0)
        || header[156] != b'0'
        || header[157..257].iter().any(|byte| *byte != 0)
        || header[345..500].iter().any(|byte| *byte != 0)
        || octal(&header[100..108]) != Some(mode)
    {
        return Err(UnsupportedLayout);
    }
    octal(&header[124..136]).ok_or(InvalidArchive)
}

fn octal(field: &[u8]) -> Option<u64> {
    let count = field
        .iter()
        .take_while(|byte| (b'0'..=b'7').contains(byte))
        .count();
    if count == 0 || field[count..].iter().any(|byte| !matches!(*byte, 0 | b' ')) {
        return None;
    }
    Some(
        field[..count]
            .iter()
            .fold(0, |value, byte| value * 8 + u64::from(*byte - b'0')),
    )
}

fn read_padding(
    reader: &mut (impl Read + ?Sized),
    size: u64,
) -> Result<(), PackageInspectionError> {
    let length = (TAR_BLOCK - (size % TAR_BLOCK as u64) as usize) % TAR_BLOCK;
    let mut padding = [0; TAR_BLOCK];
    read_zeroes(reader, &mut padding[..length])
}

fn read_zeroes(
    reader: &mut (impl Read + ?Sized),
    buffer: &mut [u8],
) -> Result<(), PackageInspectionError> {
    use PackageInspectionError::InvalidArchive;
    reader.read_exact(buffer).map_err(|_| InvalidArchive)?;
    if buffer.iter().any(|byte| *byte != 0) {
        return Err(InvalidArchive);
    }
    Ok(())
}

fn read_end(reader: &mut impl Read) -> Result<(), PackageInspectionError> {
    use PackageInspectionError::InvalidArchive;
    let mut block = [0; TAR_BLOCK];
    read_zeroes(reader, &mut block)?;
    read_zeroes(reader, &mut block)?;
    // Python's USTAR writer pads to a 20-block record after the end markers.
    for _ in 0..TAR_RECORD_BLOCKS {
        if reader.read(&mut block[..1]).map_err(|_| InvalidArchive)? == 0 {
            return Ok(());
        }
        if block[0] != 0 {
            return Err(InvalidArchive);
        }
        read_zeroes(reader, &mut block[1..])?;
    }
    Err(InvalidArchive)
}

#[cfg(test)]
pub(super) use tests::{fixture_formal_archive, package_file};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation::executable::fixture_elf;
    use crate::release::{
        github::ReleaseReadOptions,
        github_tests::Fixture,
        manifest::{GithubReleaseId, HostRequirements},
    };
    use flate2::{Compression, write::GzEncoder};
    use ring::digest::digest;
    use std::io::Write;

    const DIAGNOSTIC: &[u8] = b"bin/nodomi-agent-diagnostic";
    const RECORD: &[u8] = br#"{"mode":"REHEARSAL","tag":"agent-v0.1.0","commit":"0123456789abcdef0123456789abcdef01234567","platform":"linux-aarch64"}"#;

    fn write_octal(field: &mut [u8], value: u64) {
        let text = format!("{value:0width$o}", width = field.len() - 1);
        field[..text.len()].copy_from_slice(text.as_bytes());
        field[text.len()] = 0;
    }

    fn checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let sum = header.iter().map(|byte| u64::from(*byte)).sum();
        write_octal(&mut header[148..156], sum);
    }

    fn entry(archive: &mut Vec<u8>, name: &[u8], mode: u64, bytes: &[u8]) {
        let mut header = [0; TAR_BLOCK];
        header[..name.len()].copy_from_slice(name);
        write_octal(&mut header[100..108], mode);
        write_octal(&mut header[124..136], bytes.len() as u64);
        header[156] = b'0';
        header[257..265].copy_from_slice(b"ustar\x0000");
        checksum(&mut header);
        archive.extend(header);
        archive.extend(bytes);
        archive.resize(archive.len().next_multiple_of(TAR_BLOCK), 0);
    }

    fn archive(elf: &[u8], record: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();
        entry(&mut archive, DIAGNOSTIC, 0o755, elf);
        entry(&mut archive, b"REHEARSAL.json", 0o644, record);
        archive.resize(archive.len() + TAR_BLOCK * 2, 0);
        archive
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn inspect(bytes: &[u8]) -> Result<RehearsalPackage, PackageInspectionError> {
        inspect_rehearsal_package(package_file(bytes))
    }

    pub(in crate::installation) fn package_file(bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn formal_archive(elf: &[u8], text: &[u8]) -> Vec<u8> {
        formal_archive_with_texts(elf, [text; 3])
    }

    fn formal_archive_with_texts(elf: &[u8], texts: [&[u8]; 3]) -> Vec<u8> {
        let mut archive = Vec::new();
        for (index, (name, mode, binary)) in FORMAL_MEMBERS.into_iter().enumerate() {
            entry(
                &mut archive,
                name.as_bytes(),
                u64::from(mode),
                if binary { elf } else { texts[index - 3] },
            );
        }
        archive.resize(archive.len() + TAR_BLOCK * 2, 0);
        archive
    }

    pub(in crate::installation) fn fixture_formal_archive(
        platform: Platform,
        text: &[u8],
    ) -> Vec<u8> {
        gzip(&formal_archive(&fixture_elf(platform, None), text))
    }

    #[test]
    fn formal_members_and_archive_have_independent_verified_hashes() {
        let platform = Platform::LinuxAarch64;
        let elf = fixture_elf(platform, None);
        let bytes = gzip(&formal_archive(&elf, b"fixture text\n"));
        let fixture = Fixture::with_artifact(platform, &bytes);
        let mut client = fixture.client(ReleaseReadOptions::default());
        let release = client
            .load_exact(
                GithubReleaseId::new(123).unwrap(),
                HostRequirements {
                    platform,
                    kernel: [6, 1, 0],
                    libc: None,
                    wire_protocol: 1,
                    supervisor_protocol: 1,
                    config_format: 1,
                    queue_format: 1,
                },
            )
            .unwrap();
        let mut downloaded = tempfile::tempfile().unwrap();
        let artifact = client.download(&release, &mut downloaded).unwrap();
        let inspected = verify_formal_package(downloaded, &release).unwrap();
        assert_eq!(inspected.archive_bytes, artifact.length);
        assert_eq!(inspected.archive_sha256, artifact.sha256);
        let elf_hash: String = digest(&SHA256, &elf)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(inspected.expanded_member_bytes, 3 * (elf.len() as u64 + 13));
        assert_eq!(inspected.members.len(), 6);
        for (member, (name, mode, binary)) in inspected.members.iter().zip(FORMAL_MEMBERS) {
            assert_eq!(member.path, name);
            assert_eq!(member.mode, mode);
            if binary {
                assert_eq!(member.sha256, elf_hash);
                assert_eq!(member.executable.as_ref().unwrap().platform(), platform);
            } else {
                assert!(member.executable.is_none());
            }
        }
        let substituted = gzip(&formal_archive(&elf, b"fixture TEXT\n"));
        assert_eq!(
            verify_formal_package(package_file(&substituted), &release),
            Err(PackageInspectionError::DigestMismatch)
        );
    }

    #[test]
    fn formal_reader_rejects_rehearsal_extra_members_and_invalid_text() {
        use PackageInspectionError::*;
        let platform = Platform::LinuxAarch64;
        let elf = fixture_elf(platform, None);
        let check = |plain: &[u8]| inspect_formal_package(package_file(&gzip(plain)), platform);
        assert_eq!(check(&archive(&elf, RECORD)), Err(UnsupportedLayout));
        assert_eq!(
            check(&formal_archive(&elf, b"foo\0bar")),
            Err(InvalidTextMember)
        );
        assert_eq!(
            check(&formal_archive(&elf, &[0xff])),
            Err(InvalidTextMember)
        );
        assert_eq!(check(&formal_archive(&elf, b"")), Err(InvalidTextMember));
        let mut extra = formal_archive(&elf, b"text");
        extra.truncate(extra.len() - TAR_BLOCK * 2);
        entry(&mut extra, b"LICENSE", 0o644, b"duplicate");
        extra.resize(extra.len() + TAR_BLOCK * 2, 0);
        assert_eq!(check(&extra), Err(InvalidArchive));
        let wrong = fixture_elf(Platform::LinuxX86_64, None);
        assert_eq!(
            check(&formal_archive(&wrong, b"text")),
            Err(Executable(ExecutableError::WrongPlatform))
        );
    }

    #[test]
    fn formal_package_has_distinct_license_and_service_limits() {
        const SERVICE_LIMIT: usize = 64 * 1024;
        const LICENSE_LIMIT: usize = 1024 * 1024;
        let platform = Platform::LinuxAarch64;
        let elf = fixture_elf(platform, None);
        let read = |texts| {
            let package = gzip(&formal_archive_with_texts(&elf, texts));
            inspect_formal_package(package_file(&package), platform)
        };
        let service = vec![b's'; SERVICE_LIMIT];
        let license = vec![b'l'; LICENSE_LIMIT];
        let package = read([&service, &service, &license]).unwrap();
        let lengths = std::array::from_fn(|index| package.members[index].length);
        assert_eq!(lengths[5], LICENSE_LIMIT as u64);
        assert!(formal_member_lengths_valid(lengths));

        let oversized_license = vec![b'l'; LICENSE_LIMIT + 1];
        let mut invalid = lengths;
        invalid[5] += 1;
        assert!(!formal_member_lengths_valid(invalid));
        assert_eq!(
            read([&service, &service, &oversized_license]),
            Err(PackageInspectionError::InvalidTextMember)
        );

        let oversized_service = vec![b's'; SERVICE_LIMIT + 1];
        for index in [0, 1] {
            let mut texts: [&[u8]; 3] = [&service, &service, &license];
            texts[index] = &oversized_service;
            let mut invalid = lengths;
            invalid[index + 3] += 1;
            assert!(!formal_member_lengths_valid(invalid));
            assert_eq!(read(texts), Err(PackageInspectionError::InvalidTextMember));
        }
    }

    #[test]
    fn streams_exact_hash_and_observed_member_sizes_from_offset_zero() {
        let interpreter = "/lib/ld-linux-aarch64.so.1";
        let elf = fixture_elf(Platform::LinuxAarch64, Some(interpreter));
        let bytes = gzip(&archive(&elf, RECORD));
        let package = inspect(&bytes).unwrap();
        assert_eq!(package.tag, "agent-v0.1.0");
        assert_eq!(package.commit, "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(package.compressed_bytes, bytes.len() as u64);
        assert_eq!(package.diagnostic_bytes, elf.len() as u64);
        assert_eq!(package.record_bytes, RECORD.len() as u64);
        let actual_hash: String = digest(&SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(package.compressed_sha256, actual_hash);
        assert_eq!(package.executable.platform(), Platform::LinuxAarch64);
        assert_eq!(package.executable.interpreter(), Some(interpreter));
    }

    #[test]
    fn rejects_unexpected_paths_types_permissions_and_extra_members() {
        use PackageInspectionError::*;
        let elf = fixture_elf(Platform::LinuxAarch64, None);
        let plain = archive(&elf, RECORD);
        for (offset, replacement) in [
            (0, b"../".as_slice()),
            (156, b"2"), // symlink
            (156, b"1"), // hard link
            (156, b"3"), // device
            (156, b"6"), // FIFO
            (156, b"x"), // PAX header
            (156, b"L"), // GNU long name
            (345, b"bin"),
            (157, b"link"),
            (100, b"0004755"),
        ] {
            let mut changed = plain.clone();
            changed[offset..offset + replacement.len()].copy_from_slice(replacement);
            checksum(&mut changed[..TAR_BLOCK]);
            assert_eq!(inspect(&gzip(&changed)), Err(UnsupportedLayout));
        }
        let mut duplicate = plain;
        duplicate.truncate(duplicate.len() - TAR_BLOCK * 2);
        entry(&mut duplicate, b"REHEARSAL.json", 0o644, RECORD);
        duplicate.resize(duplicate.len() + TAR_BLOCK * 2, 0);
        assert_eq!(inspect(&gzip(&duplicate)), Err(InvalidArchive));
    }

    #[test]
    fn rejects_corrupt_header_unbounded_members_and_bad_padding() {
        use PackageInspectionError::*;
        let mut elf = fixture_elf(Platform::LinuxAarch64, None);
        elf.push(0); // Give this fixture actual USTAR member padding.
        let plain = archive(&elf, RECORD);
        let mut bad_checksum = plain.clone();
        bad_checksum[200] = 1;
        assert_eq!(inspect(&gzip(&bad_checksum)), Err(InvalidArchive));

        let mut oversize = plain.clone();
        write_octal(&mut oversize[124..136], MAX_DIAGNOSTIC_BYTES + 1);
        checksum(&mut oversize[..TAR_BLOCK]);
        assert_eq!(inspect(&gzip(&oversize)), Err(InvalidArchive));

        let mut padding = plain.clone();
        padding[TAR_BLOCK + elf.len()] = 1;
        assert_eq!(inspect(&gzip(&padding)), Err(InvalidArchive));
        padding = plain;
        padding.resize(padding.len() + TAR_BLOCK * TAR_RECORD_BLOCKS, 0);
        assert_eq!(inspect(&gzip(&padding)), Err(InvalidArchive));

        let file = tempfile::tempfile().unwrap();
        file.set_len(MAX_ARTIFACT_BYTES + 1).unwrap();
        assert_eq!(inspect_rehearsal_package(file), Err(InvalidFile));
    }

    #[test]
    fn requires_complete_single_gzip_member_with_no_following_bytes() {
        use PackageInspectionError::*;
        let elf = fixture_elf(Platform::LinuxAarch64, None);
        let bytes = gzip(&archive(&elf, RECORD));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(inspect(&trailing), Err(InvalidGzip));
        let mut concatenated = bytes.clone();
        concatenated.extend(gzip(b""));
        assert_eq!(inspect(&concatenated), Err(InvalidGzip));
        let mut flags = bytes.clone();
        flags[3] = 8;
        assert_eq!(inspect(&flags), Err(InvalidGzip));

        let mut corrupt_crc = bytes.clone();
        corrupt_crc[bytes.len() - 8] ^= 1;
        assert_eq!(inspect(&corrupt_crc), Err(InvalidArchive));
        assert_eq!(inspect(&bytes[..bytes.len() - 1]), Err(InvalidArchive));
    }

    #[test]
    fn requires_unambiguous_rehearsal_record_and_matching_machine() {
        use PackageInspectionError::*;
        let arm = fixture_elf(Platform::LinuxAarch64, None);
        let record = std::str::from_utf8(RECORD).unwrap();
        for malformed in [
            record.replace("REHEARSAL", "PUBLISH"),
            record.replace("agent-v0.1.0", "agent-v0.01.0"),
            record.replace("\"tag\":", "\"tag\":\"agent-v0.1.0\",\"tag\":"),
            record.replace("\"tag\":", "\"extra\":true,\"tag\":"),
            record.replace("0123456789abcdef", "0123456789ABCDEF"),
            "[]".into(),
        ] {
            assert_eq!(
                inspect(&gzip(&archive(&arm, malformed.as_bytes()))),
                Err(InvalidRehearsalRecord)
            );
        }
        let x86 = fixture_elf(Platform::LinuxX86_64, None);
        assert_eq!(
            inspect(&gzip(&archive(&x86, RECORD))),
            Err(Executable(ExecutableError::WrongPlatform))
        );
    }
}
