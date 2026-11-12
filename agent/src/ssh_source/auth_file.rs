//! Read the fixed, local authentication file produced by the trusted writer.
use ring::digest::{Context, SHA256, digest};
use std::{
    ffi::CStr,
    fs::{File, OpenOptions},
    io::{self, ErrorKind},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
};

const ACTIVE: &CStr = c"ssh-auth.jsonl";
const ROTATED: &CStr = c"ssh-auth.jsonl.1";
const ANCHOR_BYTES: usize = 4096;
const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_LINE_BYTES: usize = 128 * 1024;
const OPEN_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileError {
    Unavailable,
    PermissionDenied,
    CursorLost,
    Read,
}

impl From<io::Error> for FileError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            ErrorKind::NotFound => Self::Unavailable,
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Read,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FileRecord {
    Bytes(Vec<u8>),
    Oversized,
    Ignored,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FileStep {
    Record {
        cursor: FileCursor,
        record: FileRecord,
    },
    Rotated(FileCursor),
    CaughtUp,
    PendingLine,
    WaitingForRotation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Generation {
    device: u64,
    inode: u64,
    birth_seconds: i64,
    birth_nanos: u32,
}

impl Generation {
    fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.device.to_be_bytes());
        bytes.extend_from_slice(&self.inode.to_be_bytes());
        bytes.extend_from_slice(&self.birth_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.birth_nanos.to_be_bytes());
    }

    fn decode(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (device, rest) = bytes.split_first_chunk::<8>()?;
        let (inode, rest) = rest.split_first_chunk::<8>()?;
        let (birth_seconds, rest) = rest.split_first_chunk::<8>()?;
        let (birth_nanos, rest) = rest.split_first_chunk::<4>()?;
        let birth_nanos = u32::from_be_bytes(*birth_nanos);
        (birth_nanos < 1_000_000_000).then_some((
            Self {
                device: u64::from_be_bytes(*device),
                inode: u64::from_be_bytes(*inode),
                birth_seconds: i64::from_be_bytes(*birth_seconds),
                birth_nanos,
            },
            rest,
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct FileCursor {
    generation: Generation,
    offset: u64,
    anchor: [u8; 32],
    skip_fragment: bool,
}

impl FileCursor {
    const ENCODED_LEN: usize = 70;

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::ENCODED_LEN);
        bytes.push(1);
        self.generation.encode(&mut bytes);
        bytes.extend_from_slice(&self.offset.to_be_bytes());
        bytes.push(u8::from(self.skip_fragment));
        bytes.extend_from_slice(&self.anchor);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, FileError> {
        let [1, encoded @ ..] = bytes else {
            return Err(FileError::CursorLost);
        };
        let Some((generation, rest)) = Generation::decode(encoded) else {
            return Err(FileError::CursorLost);
        };
        let Some((offset, rest)) = rest.split_first_chunk::<8>() else {
            return Err(FileError::CursorLost);
        };
        let Some((&skip_fragment, anchor)) = rest.split_first() else {
            return Err(FileError::CursorLost);
        };
        let offset = u64::from_be_bytes(*offset);
        if offset > i64::MAX as u64 || skip_fragment > 1 || (offset == 0 && skip_fragment == 1) {
            return Err(FileError::CursorLost);
        }
        Ok(Self {
            generation,
            offset,
            anchor: anchor.try_into().map_err(|_| FileError::CursorLost)?,
            skip_fragment: skip_fragment == 1,
        })
    }
}

/// A complete record observed strictly after the durable file position.
/// The digest covers only unread bytes, so a change to the prior cursor
/// window by itself is insufficient to establish the loss of this record.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct FileWitness {
    generation: Generation,
    start: u64,
    end: u64,
    digest: [u8; 32],
}

impl FileWitness {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(77);
        bytes.push(1);
        self.generation.encode(&mut bytes);
        bytes.extend_from_slice(&self.start.to_be_bytes());
        bytes.extend_from_slice(&self.end.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, FileError> {
        let [1, encoded @ ..] = bytes else {
            return Err(FileError::Read);
        };
        let (generation, rest) = Generation::decode(encoded).ok_or(FileError::Read)?;
        let (start, rest) = rest.split_first_chunk::<8>().ok_or(FileError::Read)?;
        let (end, digest) = rest.split_first_chunk::<8>().ok_or(FileError::Read)?;
        let start = u64::from_be_bytes(*start);
        let end = u64::from_be_bytes(*end);
        if end <= start || end > i64::MAX as u64 || end - start > MAX_LINE_BYTES as u64 {
            return Err(FileError::Read);
        }
        Ok(Self {
            generation,
            start,
            end,
            digest: digest.try_into().map_err(|_| FileError::Read)?,
        })
    }

    fn is_missing(&self, file: &OpenFile) -> Result<bool, FileError> {
        if file.file.metadata()?.len() < self.end {
            return Ok(true);
        }
        let mut bytes = [0; ANCHOR_BYTES];
        let mut offset = self.start;
        let mut observed = Context::new(&SHA256);
        while offset < self.end {
            let length = (self.end - offset).min(bytes.len() as u64) as usize;
            let chunk = &mut bytes[..length];
            match file.file.read_exact_at(chunk, offset) {
                Ok(()) => observed.update(chunk),
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(true),
                Err(error) => return Err(error.into()),
            }
            offset += length as u64;
        }
        Ok(observed.finish().as_ref() != self.digest)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct FileRecovery {
    pub(super) cursor: FileCursor,
    pub(super) lost_unread: bool,
    pub(super) skipped_unread: bool,
}

pub(super) struct AuthFile {
    directory: File,
    owner: u32,
}

impl AuthFile {
    pub(super) fn open() -> Result<Self, FileError> {
        let mut directory = OpenOptions::new()
            .read(true)
            .custom_flags(OPEN_FLAGS | libc::O_DIRECTORY)
            .open("/")?;
        validate_directory(&directory, 0)?;
        for component in [c"var", c"log", c"nodomi"] {
            directory = open_at(&directory, component, libc::O_DIRECTORY)?;
            validate_directory(&directory, 0)?;
        }
        Ok(Self {
            directory,
            owner: 0,
        })
    }

    #[cfg(test)]
    fn open_dir(path: &std::path::Path) -> Result<Self, FileError> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(OPEN_FLAGS | libc::O_DIRECTORY)
            .open(path)?;
        // SAFETY: geteuid has no preconditions.
        let owner = unsafe { libc::geteuid() };
        validate_directory(&directory, owner)?;
        Ok(Self { directory, owner })
    }

    pub(super) fn baseline(&self) -> Result<FileCursor, FileError> {
        let active = self.open_file(ACTIVE)?;
        tail_cursor(&active)
    }

    pub(super) fn observe_unread(
        &self,
        saved: &FileCursor,
    ) -> Result<Option<FileWitness>, FileError> {
        let Some(file) = self.find_generation(saved.generation)? else {
            return Err(FileError::CursorLost);
        };
        verify_anchor(&file, saved)?;
        let start = if saved.skip_fragment {
            // A partial deployment boundary was intentionally excluded.
            match read_line(&file.file, saved.offset)? {
                Line::Record { end, .. } => end,
                Line::Tail { .. } => return Ok(None),
            }
        } else {
            saved.offset
        };
        let line = read_line(&file.file, start)?;
        verify_anchor(&file, saved)?;
        Ok(match line {
            Line::Record { end, digest, .. } => Some(FileWitness {
                generation: saved.generation,
                start,
                end,
                digest,
            }),
            Line::Tail { .. } => None,
        })
    }

    pub(super) fn recovery_plan(
        &self,
        saved: &FileCursor,
        unread: Option<&FileWitness>,
    ) -> Result<Option<FileRecovery>, FileError> {
        let active = self.open_file(ACTIVE)?;
        let rotated;
        let old = if active.generation == saved.generation {
            Some(&active)
        } else {
            rotated = self.find_rotated(saved.generation)?;
            rotated.as_ref()
        };
        if let Some(old) = old {
            match verify_anchor(old, saved) {
                Ok(()) => return Ok(None),
                Err(FileError::CursorLost) => {}
                Err(error) => return Err(error),
            }
        }
        // A new tail is safe even after old events have been acknowledged.
        // Start after every currently visible byte instead of replaying
        // records whose generation or delivery status can no longer be proven.
        let cursor = match tail_cursor(&active) {
            Err(FileError::CursorLost) => return Ok(None),
            result => result?,
        };
        let (lost_unread, skipped_unread) = match (old, unread) {
            (Some(old), Some(witness))
                if witness.generation == saved.generation && witness.start >= saved.offset =>
            {
                let missing = witness.is_missing(old)?;
                let skipped = !missing
                    && (cursor.generation != saved.generation || cursor.offset >= witness.end);
                (missing, skipped)
            }
            _ => (false, false),
        };
        // A rotation or refill that made the saved cursor usable again
        // should follow the ordinary path instead of skipping the new tail.
        if let Some(old) = self.find_generation(saved.generation)? {
            match verify_anchor(&old, saved) {
                Ok(()) => return Ok(None),
                Err(FileError::CursorLost) => {}
                Err(error) => return Err(error),
            }
        }
        if !self.still_active(active.generation)? {
            return Ok(None);
        }
        match verify_anchor(&active, &cursor) {
            Ok(()) => {}
            Err(FileError::CursorLost) => return Ok(None),
            Err(error) => return Err(error),
        }
        Ok(Some(FileRecovery {
            cursor,
            lost_unread,
            skipped_unread,
        }))
    }

    fn find_generation(&self, generation: Generation) -> Result<Option<OpenFile>, FileError> {
        match self.open_file(ACTIVE) {
            Ok(active) if active.generation == generation => return Ok(Some(active)),
            Ok(_) | Err(FileError::Unavailable) => {}
            Err(error) => return Err(error),
        }
        self.find_rotated(generation)
    }

    fn find_rotated(&self, generation: Generation) -> Result<Option<OpenFile>, FileError> {
        match self.open_file(ROTATED) {
            Ok(old) if old.generation == generation => Ok(Some(old)),
            Ok(_) | Err(FileError::Unavailable) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn next(&self, cursor: &FileCursor) -> Result<FileStep, FileError> {
        let active = match self.open_file(ACTIVE) {
            Ok(file) => Some(file),
            Err(FileError::Unavailable) => None,
            Err(error) => return Err(error),
        };
        if let Some(active) = &active
            && active.generation == cursor.generation
        {
            return match read_current(active, cursor)? {
                Current::Step(step) => Ok(step),
                Current::Tail { partial: false, .. } if self.still_active(active.generation)? => {
                    Ok(FileStep::CaughtUp)
                }
                Current::Tail { partial: true, .. } => Ok(FileStep::PendingLine),
                Current::Tail { partial: false, .. } => Ok(FileStep::WaitingForRotation),
            };
        }

        let Some(old) = self.find_rotated(cursor.generation)? else {
            return Err(FileError::CursorLost);
        };
        let tail = match read_current(&old, cursor)? {
            Current::Step(step) => return Ok(step),
            Current::Tail { offset, .. } => offset,
        };
        let Some(active) = active else {
            return Ok(FileStep::WaitingForRotation);
        };
        // The configured single writer closes the old generation before it
        // starts writing the new one. A complete producer record in the
        // replacement is the handoff barrier.
        match read_line(&active.file, 0)? {
            Line::Record {
                record: FileRecord::Bytes(bytes),
                ..
            } if super::file_envelope(&bytes).is_some() => {}
            _ => return Ok(FileStep::WaitingForRotation),
        }
        // An old append may have completed after its EOF was observed.
        // Check again after seeing the new writer before leaving the old file.
        verify_anchor(&old, cursor)?;
        if old.file.metadata()?.len() != tail || !self.still_active(active.generation)? {
            return Ok(FileStep::WaitingForRotation);
        }
        Ok(FileStep::Rotated(FileCursor {
            generation: active.generation,
            offset: 0,
            anchor: read_anchor(&active.file, 0)?.0,
            skip_fragment: false,
        }))
    }

    fn still_active(&self, generation: Generation) -> Result<bool, FileError> {
        match self.open_file(ACTIVE) {
            Ok(active) => Ok(active.generation == generation),
            Err(FileError::Unavailable) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn open_file(&self, name: &CStr) -> Result<OpenFile, FileError> {
        let file = open_at(&self.directory, name, 0)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.owner
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            return Err(FileError::Read);
        }
        let (birth_seconds, birth_nanos) = birth_time(&file)?;
        Ok(OpenFile {
            generation: Generation {
                device: metadata.dev(),
                inode: metadata.ino(),
                birth_seconds,
                birth_nanos,
            },
            file,
        })
    }
}

struct OpenFile {
    file: File,
    generation: Generation,
}

fn tail_cursor(file: &OpenFile) -> Result<FileCursor, FileError> {
    let offset = file.file.metadata()?.len();
    let (anchor, last) = read_anchor(&file.file, offset)?;
    Ok(FileCursor {
        generation: file.generation,
        offset,
        anchor,
        skip_fragment: last.is_some_and(|last| last != b'\n'),
    })
}

fn open_at(directory: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: the directory and C string remain live for the openat call.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), OPEN_FLAGS | flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: success returned a fresh descriptor owned by this function.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn validate_directory(file: &File, owner: u32) -> Result<(), FileError> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(FileError::Read);
    }
    Ok(())
}

// The fixed Linux UAPI layout in include/uapi/linux/stat.h also works on
// musl, where the libc crate does not always expose the statx types.
#[repr(C, align(8))]
struct StatxBirthTime {
    mask: u32,
    before_birth: [u8; 76],
    birth_seconds: i64,
    birth_nanos: u32,
    after_birth: [u8; 164],
}

const _: () = {
    assert!(std::mem::size_of::<StatxBirthTime>() == 256);
    assert!(std::mem::offset_of!(StatxBirthTime, birth_seconds) == 0x50);
    assert!(std::mem::offset_of!(StatxBirthTime, birth_nanos) == 0x58);
};

fn birth_time(file: &File) -> Result<(i64, u32), FileError> {
    const STATX_BTIME: libc::c_uint = 0x0800;
    let mut info = MaybeUninit::<StatxBirthTime>::zeroed();
    // SAFETY: the file descriptor is live, the pathname is a NUL-terminated
    // empty string for AT_EMPTY_PATH, and info points to writable statx storage.
    let status = unsafe {
        libc::syscall(
            libc::SYS_statx,
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            STATX_BTIME,
            info.as_mut_ptr(),
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: success initialized the requested statx output.
    let info = unsafe { info.assume_init() };
    if info.mask & STATX_BTIME == 0 || info.birth_nanos >= 1_000_000_000 {
        return Err(FileError::Read);
    }
    Ok((info.birth_seconds, info.birth_nanos))
}

fn read_anchor(file: &File, offset: u64) -> Result<([u8; 32], Option<u8>), FileError> {
    let length = offset.min(ANCHOR_BYTES as u64) as usize;
    let mut buffer = [0; ANCHOR_BYTES];
    let bytes = &mut buffer[..length];
    file.read_exact_at(bytes, offset - length as u64)
        .map_err(|error| {
            if error.kind() == ErrorKind::UnexpectedEof {
                FileError::CursorLost
            } else {
                error.into()
            }
        })?;
    let hash = digest(&SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 size");
    Ok((hash, bytes.last().copied()))
}

fn verify_anchor(file: &OpenFile, cursor: &FileCursor) -> Result<(), FileError> {
    if file.generation != cursor.generation
        || file.file.metadata()?.len() < cursor.offset
        || read_anchor(&file.file, cursor.offset)?.0 != cursor.anchor
    {
        return Err(FileError::CursorLost);
    }
    Ok(())
}

enum Current {
    Step(FileStep),
    Tail { offset: u64, partial: bool },
}

fn read_current(file: &OpenFile, cursor: &FileCursor) -> Result<Current, FileError> {
    verify_anchor(file, cursor)?;
    let line = read_line(&file.file, cursor.offset)?;
    verify_anchor(file, cursor)?;
    match line {
        Line::Record { end, record, .. } => {
            let next = FileCursor {
                generation: cursor.generation,
                offset: end,
                anchor: read_anchor(&file.file, end)?.0,
                skip_fragment: false,
            };
            let record = if cursor.skip_fragment {
                FileRecord::Ignored
            } else {
                record
            };
            Ok(Current::Step(FileStep::Record {
                cursor: next,
                record,
            }))
        }
        Line::Tail { offset } => Ok(Current::Tail {
            offset,
            partial: offset != cursor.offset,
        }),
    }
}

enum Line {
    Record {
        end: u64,
        record: FileRecord,
        digest: [u8; 32],
    },
    Tail {
        offset: u64,
    },
}

fn read_line(file: &File, start: u64) -> Result<Line, FileError> {
    let mut buffer = [0; 4096];
    let mut bytes = Vec::new();
    let mut oversized = false;
    let mut read = 0;
    let mut observed = Context::new(&SHA256);
    while read < MAX_LINE_BYTES {
        let length = buffer.len().min(MAX_LINE_BYTES - read);
        let offset = start.checked_add(read as u64).ok_or(FileError::Read)?;
        let count = match file.read_at(&mut buffer[..length], offset) {
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            return Ok(Line::Tail { offset });
        }
        let chunk = &buffer[..count];
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(chunk.len(), |index| index + 1);
        observed.update(&chunk[..consumed]);
        let contents = &chunk[..newline.unwrap_or(chunk.len())];
        if !oversized {
            if bytes.len() + contents.len() > MAX_RECORD_BYTES {
                bytes.clear();
                oversized = true;
            } else {
                bytes.extend_from_slice(contents);
            }
        }
        if let Some(newline) = newline {
            let end = offset
                .checked_add((newline + 1) as u64)
                .ok_or(FileError::Read)?;
            return Ok(Line::Record {
                end,
                digest: observed.finish().as_ref().try_into().expect("SHA-256 size"),
                record: if oversized {
                    FileRecord::Oversized
                } else {
                    FileRecord::Bytes(bytes)
                },
            });
        }
        read += count;
    }
    // This exceeds the configured producer's complete-line limit. Stop
    // before losing the durable record boundary or allocating more memory.
    Err(FileError::Read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
    };

    fn paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let active = root.path().join(ACTIVE.to_str().unwrap());
        let rotated = root.path().join(ROTATED.to_str().unwrap());
        (root, active, rotated)
    }

    fn append(path: &Path, bytes: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    fn record(source: &AuthFile, at: &FileCursor, expected: FileRecord) -> FileCursor {
        let FileStep::Record { cursor, record } = source.next(at).unwrap() else {
            panic!("expected a complete record");
        };
        assert_eq!(record, expected);
        cursor
    }

    #[test]
    fn restart_keeps_tail_and_ignores_only_the_initial_fragment() {
        let (root, active, _) = paths();
        fs::write(&active, b"old\nfrag").unwrap();
        let source = AuthFile::open_dir(root.path()).unwrap();
        let baseline = source.baseline().unwrap();
        assert_eq!(source.next(&baseline), Ok(FileStep::CaughtUp));
        let encoded = baseline.encode();
        assert_eq!(encoded.len(), FileCursor::ENCODED_LEN);
        assert_eq!(FileCursor::decode(&encoded), Ok(baseline));
        let cursor = FileCursor::decode(&encoded).unwrap();
        assert_eq!(
            FileCursor::decode(&encoded[..69]),
            Err(FileError::CursorLost)
        );
        drop(source);

        append(&active, b"ment\nfull\npart");
        let source = AuthFile::open_dir(root.path()).unwrap();
        let cursor = record(&source, &cursor, FileRecord::Ignored);
        let cursor = record(&source, &cursor, FileRecord::Bytes(b"full".to_vec()));
        assert_eq!(source.next(&cursor), Ok(FileStep::PendingLine));
        append(&active, b"ial\n");
        let cursor = record(&source, &cursor, FileRecord::Bytes(b"partial".to_vec()));
        assert_eq!(source.next(&cursor), Ok(FileStep::CaughtUp));
    }

    #[test]
    fn drains_renamed_file_and_recovers_across_rotation() {
        let (root, active, rotated) = paths();
        fs::write(&active, b"historical\n").unwrap();
        let source = AuthFile::open_dir(root.path()).unwrap();
        let baseline = source.baseline().unwrap();
        fs::rename(&active, &rotated).unwrap();
        fs::write(&active, b"").unwrap();
        append(&rotated, b"late-old\nstranded-part");
        let old = record(&source, &baseline, FileRecord::Bytes(b"late-old".to_vec()));
        assert_eq!(source.next(&old), Ok(FileStep::WaitingForRotation));
        drop(source);

        append(&active, b"invalid envelope");
        let source = AuthFile::open_dir(root.path()).unwrap();
        let old = FileCursor::decode(&old.encode()).unwrap();
        assert_eq!(source.next(&old), Ok(FileStep::WaitingForRotation));
        append(&active, b"\n");
        assert_eq!(source.next(&old), Ok(FileStep::WaitingForRotation));
        let replacement = br#"{"bootId":"f82ee528-c48b-4bc4-942e-823655a39f5a","at":"2026-11-11T12:00:00Z","message":"test record"}"#;
        fs::write(&active, [replacement.as_slice(), b"\n"].concat()).unwrap();
        let FileStep::Rotated(new) = source.next(&old).unwrap() else {
            panic!("expected a verified rotation");
        };
        assert_ne!(new.generation, old.generation);
        assert_eq!(new.offset, 0);
        let new = record(&source, &new, FileRecord::Bytes(replacement.to_vec()));
        assert_eq!(source.next(&new), Ok(FileStep::CaughtUp));
        fs::remove_file(rotated).unwrap();
        assert_eq!(source.next(&old), Err(FileError::CursorLost));
    }

    #[test]
    fn refuses_shortening_or_changed_anchor_and_unsafe_paths() {
        let (root, active, rotated) = paths();
        fs::write(&active, b"original\n").unwrap();
        let source = AuthFile::open_dir(root.path()).unwrap();
        let cursor = source.baseline().unwrap();
        fs::write(&active, b"short").unwrap();
        assert_eq!(source.next(&cursor), Err(FileError::CursorLost));
        fs::write(&active, b"different\nnew\n").unwrap();
        assert_eq!(source.next(&cursor), Err(FileError::CursorLost));

        fs::set_permissions(&active, fs::Permissions::from_mode(0o622)).unwrap();
        assert_eq!(source.baseline(), Err(FileError::Read));
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&active, &rotated).unwrap();
        assert_eq!(source.baseline(), Err(FileError::Read));
        fs::remove_file(&active).unwrap();
        symlink(&rotated, &active).unwrap();
        assert_eq!(source.baseline(), Err(FileError::Read));
    }

    #[test]
    fn oversized_complete_records_advance_but_unframed_input_stops() {
        let (root, active, _) = paths();
        fs::write(&active, b"").unwrap();
        let source = AuthFile::open_dir(root.path()).unwrap();
        let baseline = source.baseline().unwrap();
        append(&active, &vec![b'x'; MAX_RECORD_BYTES + 1]);
        assert_eq!(source.next(&baseline), Ok(FileStep::PendingLine));
        append(&active, b"\n");
        let at = record(&source, &baseline, FileRecord::Oversized);
        assert_eq!(source.next(&at), Ok(FileStep::CaughtUp));
        append(&active, &vec![b'x'; MAX_LINE_BYTES]);
        assert_eq!(source.next(&at), Err(FileError::Read));
    }

    #[test]
    fn recovery_distinguishes_lost_or_skipped_unread_from_a_stale_anchor() {
        let (root, active, _) = paths();
        fs::write(&active, b"saved\n").unwrap();
        let source = AuthFile::open_dir(root.path()).unwrap();
        let saved = source.baseline().unwrap();
        assert_eq!(source.observe_unread(&saved), Ok(None));
        append(&active, b"unread");
        assert_eq!(source.observe_unread(&saved), Ok(None));
        append(&active, b"\n");
        let witness = source.observe_unread(&saved).unwrap().unwrap();
        let encoded = witness.encode();
        assert_eq!(FileWitness::decode(&encoded), Ok(witness));
        let witness = FileWitness::decode(&encoded).unwrap();
        assert_eq!(source.recovery_plan(&saved, Some(&witness)), Ok(None));

        // Change only the already committed prefix. The entire unread line
        // is still exact; the reset will pass it but it was not truncated.
        fs::write(&active, b"alter\nunread\n").unwrap();
        let plan = source
            .recovery_plan(&saved, Some(&witness))
            .unwrap()
            .unwrap();
        assert!(!plan.lost_unread);
        assert!(plan.skipped_unread);

        // Change both regions with the same inode and enough bytes to mask
        // simple size checks. The previously observed unread record is lost.
        fs::write(&active, b"alter\nreplacement-record\n").unwrap();
        let plan = source
            .recovery_plan(&saved, Some(&witness))
            .unwrap()
            .unwrap();
        assert!(plan.lost_unread);
        assert!(!plan.skipped_unread);
        assert_eq!(source.next(&plan.cursor), Ok(FileStep::CaughtUp));
        append(&active, b"after recovery\n");
        let next = record(
            &source,
            &plan.cursor,
            FileRecord::Bytes(b"after recovery".to_vec()),
        );
        assert_eq!(source.next(&next), Ok(FileStep::CaughtUp));

        let unknown = source.recovery_plan(&saved, None).unwrap().unwrap();
        assert!(!unknown.lost_unread && !unknown.skipped_unread);
    }
}
