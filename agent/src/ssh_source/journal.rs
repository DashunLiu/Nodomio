//! Local system journal access through the stable libsystemd C API.
use libc::{c_char, c_int, c_void};
use std::{
    ffi::{CStr, CString},
    fs::{self, OpenOptions},
    io::{ErrorKind, Read},
    os::unix::fs::OpenOptionsExt,
    ptr::{self, NonNull},
    slice,
};

// These are the public sd-journal.h open flags.
const LOCAL_ONLY: c_int = 1 << 0;
const SYSTEM: c_int = 1 << 2;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
pub(super) const MAX_CURSOR_BYTES: usize = 4000;
const MAX_RECOVERY_FILES: usize = 512;
const MAX_RECOVERY_DIRECTORY_ENTRIES: usize = 4096;
const JOURNAL_ROOTS: [&str; 2] = ["/run/log/journal", "/var/log/journal"];

// Match trusted fields assigned by journald from the sending process, in
// pairs. Root syslog datagrams provide credentials per message.
const SSH_PROCESSES: &[(&str, &str)] = &[
    ("/usr/sbin/sshd", "sshd"),
    ("/usr/bin/sshd", "sshd"),
    ("/usr/lib/openssh/sshd-session", "sshd-session"),
    ("/usr/lib/ssh/sshd-session", "sshd-session"),
    ("/usr/libexec/openssh/sshd-session", "sshd-session"),
    ("/usr/libexec/sshd-session", "sshd-session"),
    ("/usr/lib/openssh/sshd-auth", "sshd-auth"),
    ("/usr/lib/ssh/sshd-auth", "sshd-auth"),
    ("/usr/libexec/openssh/sshd-auth", "sshd-auth"),
    ("/usr/libexec/sshd-auth", "sshd-auth"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum JournalError {
    Unavailable,
    PermissionDenied,
    CursorLost,
    Read,
}

pub(super) enum JournalMessage {
    Bytes(Vec<u8>),
    Oversized,
    Missing,
}

pub(super) struct JournalRecord {
    pub(super) cursor: Vec<u8>,
    pub(super) boot_id: String,
    pub(super) realtime_usec: u64,
    pub(super) monotonic_usec: u64,
    pub(super) message: JournalMessage,
}

type Context = *mut c_void;
type Operation = unsafe extern "C" fn(Context) -> c_int;
type CursorOperation = unsafe extern "C" fn(Context, *const c_char) -> c_int;
type GetUint64 = unsafe extern "C" fn(Context, *mut u64) -> c_int;
type GetData =
    unsafe extern "C" fn(Context, *const c_char, *mut *const c_void, *mut usize) -> c_int;
type OpenFiles = unsafe extern "C" fn(*mut Context, *const *const c_char, c_int) -> c_int;
type GetMonotonic = unsafe extern "C" fn(Context, *mut u64, *mut Id128) -> c_int;
type GetMonotonicCutoff = unsafe extern "C" fn(Context, Id128, *mut u64, *mut u64) -> c_int;

// sd_id128_t is a C union of sixteen bytes and two uint64_t words.
#[repr(C)]
union Id128 {
    bytes: [u8; 16],
    words: [u64; 2],
}

struct Library(NonNull<c_void>);

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: This handle was returned by dlopen and is closed once.
        unsafe { libc::dlclose(self.0.as_ptr()) };
    }
}

struct Api {
    _library: Library,
    open: unsafe extern "C" fn(*mut Context, c_int) -> c_int,
    open_files: OpenFiles,
    close: unsafe extern "C" fn(Context),
    add_match: unsafe extern "C" fn(Context, *const c_void, usize) -> c_int,
    add_disjunction: Operation,
    get_fd: Operation,
    process: Operation,
    get_usage: GetUint64,
    seek_head: Operation,
    seek_tail: Operation,
    seek_cursor: CursorOperation,
    test_cursor: CursorOperation,
    get_cursor: unsafe extern "C" fn(Context, *mut *mut c_char) -> c_int,
    previous: Operation,
    next: Operation,
    set_data_threshold: unsafe extern "C" fn(Context, usize) -> c_int,
    get_data: GetData,
    get_realtime_usec: GetUint64,
    get_monotonic_usec: GetMonotonic,
    get_cutoff_monotonic_usec: GetMonotonicCutoff,
}

impl Api {
    fn load() -> Result<Self, JournalError> {
        // SAFETY: The library name is a static C string. The loaded handle is
        // owned below, including on an early return for a missing symbol.
        let handle = unsafe {
            libc::dlopen(
                c"libsystemd.so.0".as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            )
        };
        let library = Library(NonNull::new(handle).ok_or(JournalError::Unavailable)?);
        macro_rules! symbol {
            ($name:literal, $signature:ty) => {{
                // SAFETY: The library remains open. Each static name below
                // refers to its exact public C signature in sd-journal.h.
                let address = unsafe { libc::dlsym(handle, $name.as_ptr()) };
                if address.is_null() {
                    return Err(JournalError::Unavailable);
                }
                // SAFETY: POSIX dlsym returns the callable address of the
                // named function, with the signature specified above.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
            }};
        }
        Ok(Self {
            open: symbol!(
                c"sd_journal_open",
                unsafe extern "C" fn(*mut Context, c_int) -> c_int
            ),
            open_files: symbol!(c"sd_journal_open_files", OpenFiles),
            close: symbol!(c"sd_journal_close", unsafe extern "C" fn(Context)),
            add_match: symbol!(
                c"sd_journal_add_match",
                unsafe extern "C" fn(Context, *const c_void, usize) -> c_int
            ),
            add_disjunction: symbol!(c"sd_journal_add_disjunction", Operation),
            get_fd: symbol!(c"sd_journal_get_fd", Operation),
            process: symbol!(c"sd_journal_process", Operation),
            get_usage: symbol!(c"sd_journal_get_usage", GetUint64),
            seek_head: symbol!(c"sd_journal_seek_head", Operation),
            seek_tail: symbol!(c"sd_journal_seek_tail", Operation),
            seek_cursor: symbol!(c"sd_journal_seek_cursor", CursorOperation),
            test_cursor: symbol!(c"sd_journal_test_cursor", CursorOperation),
            get_cursor: symbol!(
                c"sd_journal_get_cursor",
                unsafe extern "C" fn(Context, *mut *mut c_char) -> c_int
            ),
            previous: symbol!(c"sd_journal_previous", Operation),
            next: symbol!(c"sd_journal_next", Operation),
            set_data_threshold: symbol!(
                c"sd_journal_set_data_threshold",
                unsafe extern "C" fn(Context, usize) -> c_int
            ),
            get_data: symbol!(c"sd_journal_get_data", GetData),
            get_realtime_usec: symbol!(c"sd_journal_get_realtime_usec", GetUint64),
            get_monotonic_usec: symbol!(c"sd_journal_get_monotonic_usec", GetMonotonic),
            get_cutoff_monotonic_usec: symbol!(
                c"sd_journal_get_cutoff_monotonic_usec",
                GetMonotonicCutoff
            ),
            _library: library,
        })
    }
}

pub(super) struct Journal {
    api: Api,
    context: NonNull<c_void>,
}

impl Drop for Journal {
    fn drop(&mut self) {
        // SAFETY: The context is live and owned by this Journal. Drop runs
        // before the Api's library handle is released.
        unsafe { (self.api.close)(self.context.as_ptr()) };
    }
}

fn checked(result: c_int) -> Result<c_int, JournalError> {
    match result {
        n if n >= 0 => Ok(n),
        n if n == -libc::EACCES || n == -libc::EPERM => Err(JournalError::PermissionDenied),
        _ => Err(JournalError::Read),
    }
}

impl Journal {
    pub(super) fn open() -> Result<Self, JournalError> {
        let api = Api::load()?;
        let mut context = ptr::null_mut();
        // SAFETY: The output pointer is valid and the flags are defined by
        // sd-journal.h. A successful open yields an owned context.
        checked(unsafe { (api.open)(&mut context, LOCAL_ONLY | SYSTEM) })?;
        let mut journal = Self {
            api,
            context: NonNull::new(context).ok_or(JournalError::Unavailable)?,
        };
        journal.match_ssh()?;
        // Initialize inotify before the first sd_journal_process. The fd
        // belongs to the journal context and must not be closed separately.
        journal.call(journal.api.get_fd)?;
        journal.refresh()?;
        Ok(journal)
    }

    fn match_ssh(&mut self) -> Result<(), JournalError> {
        let context = self.context.as_ptr();
        for (index, (executable, comm)) in SSH_PROCESSES.iter().enumerate() {
            if index != 0 {
                self.call(self.api.add_disjunction)?;
            }
            let executable = format!("_EXE={executable}");
            let comm = format!("_COMM={comm}");
            for filter in [
                executable.as_bytes(),
                comm.as_bytes(),
                b"_UID=0",
                b"_TRANSPORT=syslog",
            ] {
                // SAFETY: The context is live and the filter provides exactly
                // the supplied length. libsystemd copies the match.
                checked(unsafe {
                    (self.api.add_match)(context, filter.as_ptr().cast(), filter.len())
                })?;
            }
        }
        // SAFETY: The context is live. The threshold includes the field name,
        // '=' and an extra byte to distinguish a truncated oversized value.
        checked(unsafe {
            (self.api.set_data_threshold)(context, MAX_MESSAGE_BYTES + b"MESSAGE=".len() + 1)
        })?;
        Ok(())
    }

    fn call(&mut self, function: Operation) -> Result<c_int, JournalError> {
        // SAFETY: All callers use a function from this Api and the context is
        // uniquely borrowed for the duration of the call.
        checked(unsafe { function(self.context.as_ptr()) })
    }

    pub(super) fn refresh(&mut self) -> Result<(), JournalError> {
        self.call(self.api.process)?;
        let mut bytes = 0;
        // SAFETY: The context and writable output pointer are live.
        checked(unsafe { (self.api.get_usage)(self.context.as_ptr(), &mut bytes) })?;
        // libsystemd can open a context even when no system files are readable.
        if bytes == 0 {
            return Err(no_readable_journal());
        }
        Ok(())
    }

    pub(super) fn seek_head(&mut self) -> Result<(), JournalError> {
        self.call(self.api.seek_head)?;
        Ok(())
    }

    pub(super) fn tail(&mut self) -> Result<Option<Vec<u8>>, JournalError> {
        self.call(self.api.seek_tail)?;
        if self.call(self.api.previous)? == 0 {
            return Ok(None);
        }
        self.cursor().map(Some)
    }

    pub(super) fn seek_after(&mut self, cursor: &[u8]) -> Result<(), JournalError> {
        if self.has_cursor(cursor)? {
            Ok(())
        } else {
            Err(JournalError::CursorLost)
        }
    }

    /// Check the exact cursor, leaving the handle on the record when present.
    /// A syntactically invalid cursor or failed read is not proof of absence.
    pub(super) fn has_cursor(&mut self, cursor: &[u8]) -> Result<bool, JournalError> {
        Ok(self.seek_at_or_after(cursor)? == Some(true))
    }

    /// None is EOF, true is the exact entry, and false leaves the handle on
    /// the first following entry according to the native journal ordering.
    fn seek_at_or_after(&mut self, cursor: &[u8]) -> Result<Option<bool>, JournalError> {
        if !valid_cursor(cursor) {
            return Err(JournalError::Read);
        }
        let cursor = CString::new(cursor).map_err(|_| JournalError::Read)?;
        let context = self.context.as_ptr();
        // SAFETY: The context is live and the cursor is a valid C string.
        checked(unsafe { (self.api.seek_cursor)(context, cursor.as_ptr()) })?;
        if self.call(self.api.next)? == 0 {
            return Ok(None);
        }
        // A successful seek can land at the nearest surviving entry. Only
        // the exact cursor test allows the next call to advance past it.
        // SAFETY: The context and the cursor string are still live.
        Ok(Some(
            checked(unsafe { (self.api.test_cursor)(context, cursor.as_ptr()) })? != 0,
        ))
    }

    pub(super) fn next_after_lost(
        &mut self,
        cursor: &[u8],
    ) -> Result<Option<JournalRecord>, JournalError> {
        match self.seek_at_or_after(cursor)? {
            Some(false) => self.current().map(Some),
            Some(true) => self.next(),
            None => Err(JournalError::CursorLost),
        }
    }

    /// A witnessed unread entry is outside retention when it is missing and
    /// the oldest retained entry in its boot is strictly newer.
    pub(super) fn confirms_retention(
        &mut self,
        cursor: &[u8],
        boot_id: &str,
        monotonic_usec: u64,
    ) -> Result<bool, JournalError> {
        if self.has_cursor(cursor)? {
            return Ok(false);
        }
        let boot_id = parse_boot_uuid(boot_id).ok_or(JournalError::Read)?;
        let mut oldest = 0;
        // Iteration can silently drop a file that fails to read. Obtain the
        // bound from all the open files before attempting to seek a record.
        // SAFETY: the context is live, the ID uses the sd_id128_t C layout,
        // and one writable output is sufficient for the cutoff call.
        let found = checked(unsafe {
            (self.api.get_cutoff_monotonic_usec)(
                self.context.as_ptr(),
                boot_id,
                &mut oldest,
                ptr::null_mut(),
            )
        })?;
        Ok(found == 1 && oldest > monotonic_usec)
    }

    // The usual journal open silently skips inaccessible files. Use the same
    // explicitly opened set to verify both the original anchor and retention.
    pub(super) fn open_recovery_files() -> Result<Self, JournalError> {
        let names = local_journal_files()?;
        if names.is_empty() {
            return Err(JournalError::Unavailable);
        }
        let api = Api::load()?;
        let mut paths: Vec<_> = names.iter().map(|name| name.as_ptr()).collect();
        paths.push(ptr::null());
        let mut context = ptr::null_mut();
        // SAFETY: the array is null-terminated, its strings live through the
        // call, and a successful open returns an owned journal context.
        checked(unsafe { (api.open_files)(&mut context, paths.as_ptr(), 0) })?;
        Ok(Self {
            api,
            context: NonNull::new(context).ok_or(JournalError::Read)?,
        })
    }

    pub(super) fn next(&mut self) -> Result<Option<JournalRecord>, JournalError> {
        if self.call(self.api.next)? == 0 {
            return Ok(None);
        }
        self.current().map(Some)
    }

    fn current(&mut self) -> Result<JournalRecord, JournalError> {
        let cursor = self.cursor()?;
        let mut realtime_usec = 0;
        // SAFETY: The context is positioned at an entry and the writable
        // output pointer is valid.
        checked(unsafe {
            (self.api.get_realtime_usec)(self.context.as_ptr(), &mut realtime_usec)
        })?;
        let mut monotonic_usec = 0;
        let mut boot = Id128 { bytes: [0; 16] };
        // SAFETY: The context and both output pointers are valid. Providing
        // boot output lets this call read entries from a previous boot.
        checked(unsafe {
            (self.api.get_monotonic_usec)(self.context.as_ptr(), &mut monotonic_usec, &mut boot)
        })?;
        // SAFETY: sd_id128_t stores the ID in its byte array representation.
        let boot_id = boot_uuid(unsafe { boot.bytes });
        let message = self.field(c"MESSAGE", b"MESSAGE=", MAX_MESSAGE_BYTES)?;
        Ok(JournalRecord {
            cursor,
            boot_id,
            realtime_usec,
            monotonic_usec,
            message,
        })
    }

    fn cursor(&mut self) -> Result<Vec<u8>, JournalError> {
        let mut raw = ptr::null_mut();
        // SAFETY: A successful call writes a malloc-allocated C string to
        // this valid output pointer.
        checked(unsafe { (self.api.get_cursor)(self.context.as_ptr(), &mut raw) })?;
        let raw = NonNull::new(raw).ok_or(JournalError::Read)?;
        // SAFETY: libsystemd returned a NUL-terminated allocation, and
        // strnlen limits inspection to one byte beyond our limit.
        let length = unsafe { libc::strnlen(raw.as_ptr(), MAX_CURSOR_BYTES + 1) };
        // SAFETY: These bytes are inside the live allocation. Copy only
        // approved cursors, then free the allocation in both cases.
        let bytes = unsafe { slice::from_raw_parts(raw.as_ptr().cast::<u8>(), length) };
        let result = valid_cursor(bytes)
            .then(|| bytes.to_vec())
            .ok_or(JournalError::Read);
        // SAFETY: The pointer was allocated by libsystemd with malloc. The
        // borrowed bytes are no longer used.
        unsafe { libc::free(raw.as_ptr().cast()) };
        result
    }

    fn field(
        &mut self,
        name: &CStr,
        prefix: &[u8],
        limit: usize,
    ) -> Result<JournalMessage, JournalError> {
        let mut data = ptr::null();
        let mut length = 0;
        // SAFETY: The context is positioned at an entry, name is a C string,
        // and the two output pointers are writable.
        let result = unsafe {
            (self.api.get_data)(self.context.as_ptr(), name.as_ptr(), &mut data, &mut length)
        };
        if result == -libc::ENOENT {
            return Ok(JournalMessage::Missing);
        }
        if result == -libc::ENOBUFS || result == -libc::E2BIG {
            return Ok(JournalMessage::Oversized);
        }
        checked(result)?;
        if length > prefix.len() + limit {
            return Ok(JournalMessage::Oversized);
        }
        if data.is_null() || length < prefix.len() {
            return Err(JournalError::Read);
        }
        // SAFETY: The successful field lookup supplies length bytes valid
        // until the next journal operation. No operation precedes the copy.
        let bytes = unsafe { slice::from_raw_parts(data.cast::<u8>(), length) };
        let value = bytes.strip_prefix(prefix).ok_or(JournalError::Read)?;
        Ok(JournalMessage::Bytes(value.to_vec()))
    }
}

fn valid_cursor(bytes: &[u8]) -> bool {
    (1..=MAX_CURSOR_BYTES).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_graphic)
}

fn no_readable_journal() -> JournalError {
    if let Ok(id) = local_machine_id() {
        for directory in JOURNAL_ROOTS {
            let path = format!("{directory}/{id}/system.journal");
            let result = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path);
            if result.is_err_and(|error| error.kind() == ErrorKind::PermissionDenied) {
                return JournalError::PermissionDenied;
            }
        }
    }
    JournalError::Unavailable
}

fn local_machine_id() -> Result<String, JournalError> {
    let mut machine_id = String::new();
    let read = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/etc/machine-id")
        .and_then(|file| file.take(34).read_to_string(&mut machine_id));
    read.map_err(recovery_io)?;
    let id = machine_id.trim_end_matches('\n');
    if id.len() != 32 || !id.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(JournalError::Read);
    }
    Ok(id.to_ascii_lowercase())
}

fn recovery_io(error: std::io::Error) -> JournalError {
    match error.kind() {
        ErrorKind::PermissionDenied => JournalError::PermissionDenied,
        _ => JournalError::Read,
    }
}

fn local_journal_files() -> Result<Vec<CString>, JournalError> {
    let machine_id = local_machine_id()?;
    let mut files = Vec::new();
    let mut remaining = MAX_RECOVERY_DIRECTORY_ENTRIES;
    for (index, root) in JOURNAL_ROOTS.into_iter().enumerate() {
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(recovery_io(error)),
        };
        for entry in entries {
            let entry = entry.map_err(recovery_io)?;
            remaining = remaining.checked_sub(1).ok_or(JournalError::Read)?;
            let name = entry.file_name();
            let name = name.as_encoded_bytes();
            if system_journal_filename(name) {
                push_recovery_file(&entry, &mut files)?;
            } else if recovery_journal_dir(name, (index != 0).then_some(&machine_id)) {
                if !entry.file_type().map_err(recovery_io)?.is_dir() {
                    return Err(JournalError::Read);
                }
                for child in fs::read_dir(entry.path()).map_err(recovery_io)? {
                    let child = child.map_err(recovery_io)?;
                    remaining = remaining.checked_sub(1).ok_or(JournalError::Read)?;
                    if system_journal_filename(child.file_name().as_encoded_bytes()) {
                        push_recovery_file(&child, &mut files)?;
                    }
                }
            }
        }
    }
    Ok(files)
}

fn recovery_journal_dir(name: &[u8], machine_id: Option<&str>) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    let valid = (name.len() == 32 && name.as_bytes().iter().all(u8::is_ascii_hexdigit))
        || crate::identity::uuid(name);
    valid
        && machine_id.is_none_or(|id| {
            name.bytes()
                .filter(|byte| *byte != b'-')
                .map(|byte| byte.to_ascii_lowercase())
                .eq(id.bytes())
        })
}

fn system_journal_filename(name: &[u8]) -> bool {
    (name.ends_with(b".journal") || name.ends_with(b".journal~"))
        && (name == b"system.journal" || name == b"system.journal~" || name.starts_with(b"system@"))
}

fn push_recovery_file(entry: &fs::DirEntry, files: &mut Vec<CString>) -> Result<(), JournalError> {
    if files.len() >= MAX_RECOVERY_FILES || !entry.file_type().map_err(recovery_io)?.is_file() {
        return Err(JournalError::Read);
    }
    files.push(
        CString::new(entry.path().as_os_str().as_encoded_bytes())
            .map_err(|_| JournalError::Read)?,
    );
    Ok(())
}

fn boot_uuid(bytes: [u8; 16]) -> String {
    let raw: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..],
    )
}

fn parse_boot_uuid(boot_id: &str) -> Option<Id128> {
    if !crate::identity::uuid(boot_id) {
        return None;
    }
    let mut digits = boot_id.bytes().filter(|byte| *byte != b'-');
    let mut bytes = [0; 16];
    for byte in &mut bytes {
        let hi = char::from(digits.next()?).to_digit(16)?;
        let lo = char::from(digits.next()?).to_digit(16)?;
        *byte = ((hi << 4) | lo) as u8;
    }
    Some(Id128 { bytes })
}
