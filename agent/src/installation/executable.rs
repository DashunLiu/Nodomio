//! Bounded ELF header inspection of bytes supplied by the package reader.

use crate::release::manifest::Platform;
use serde::Serialize;

pub const EXECUTABLE_PREFIX_BYTES: usize = 64 * 1024;
const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const INTERPRETER_MAX_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ElfKind {
    Executable,
    /// ET_DYN, which includes position-independent executables and shared objects.
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutableHeader {
    pub(super) platform: Platform,
    pub(super) kind: ElfKind,
    /// The requested loader path, if the ELF has a PT_INTERP segment.
    /// This provides no evidence that the host loader or libraries can run it.
    pub(super) interpreter: Option<String>,
}

impl ExecutableHeader {
    pub fn platform(&self) -> Platform {
        self.platform
    }

    pub fn kind(&self) -> ElfKind {
        self.kind
    }

    pub fn interpreter(&self) -> Option<&str> {
        self.interpreter.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableError {
    InvalidElf,
    WrongPlatform,
    InvalidProgramTable,
    HeaderOutsidePrefix,
    InvalidInterpreter,
}

/// Check the prefix of a regular archive member of the given total length.
/// The package reader checks the member type and counts its actual bytes.
pub fn inspect_executable(
    prefix: &[u8],
    file_len: u64,
    expected: Platform,
) -> Result<ExecutableHeader, ExecutableError> {
    use ExecutableError::*;
    if file_len < ELF_HEADER_BYTES as u64
        || prefix.len() > EXECUTABLE_PREFIX_BYTES
        || prefix.len() as u64 > file_len
    {
        return Err(InvalidElf);
    }
    let header = prefix.get(..ELF_HEADER_BYTES).ok_or(HeaderOutsidePrefix)?;
    if !header.starts_with(b"\x7fELF\x02\x01\x01")
        || !matches!(header[7], 0 | 3) // ELFOSABI_SYSV or ELFOSABI_GNU
        || u32::from_le_bytes(field(header, 20)) != 1
        || u16::from_le_bytes(field(header, 52)) as usize != ELF_HEADER_BYTES
    {
        return Err(InvalidElf);
    }
    let kind = match u16::from_le_bytes(field(header, 16)) {
        2 => ElfKind::Executable,
        3 => ElfKind::Dynamic,
        _ => return Err(InvalidElf),
    };
    if u16::from_le_bytes(field(header, 18)) != elf_machine(expected) {
        return Err(WrongPlatform);
    }

    let table_offset = u64::from_le_bytes(field(header, 32));
    let count = u16::from_le_bytes(field(header, 56));
    let table_len = u64::from(count) * PROGRAM_HEADER_BYTES as u64;
    if table_offset < ELF_HEADER_BYTES as u64
        || count == 0
        || count == u16::MAX // PN_XNUM needs section-header data outside this profile.
        || u16::from_le_bytes(field(header, 54)) as usize != PROGRAM_HEADER_BYTES
        || !range_within(table_offset, table_len, file_len)
    {
        return Err(InvalidProgramTable);
    }
    let table = prefix_region(prefix, table_offset, table_len).ok_or(HeaderOutsidePrefix)?;
    let entry = u64::from_le_bytes(field(header, 24));
    let mut entry_is_file_backed = false;
    let mut interpreter = None;

    for segment in table.chunks_exact(PROGRAM_HEADER_BYTES) {
        let kind = u32::from_le_bytes(field(segment, 0));
        let flags = u32::from_le_bytes(field(segment, 4));
        let offset = u64::from_le_bytes(field(segment, 8));
        let address = u64::from_le_bytes(field(segment, 16));
        let size = u64::from_le_bytes(field(segment, 32));

        if kind != 0 && size != 0 && !range_within(offset, size, file_len) {
            return Err(if kind == PT_INTERP {
                InvalidInterpreter
            } else {
                InvalidProgramTable
            });
        }
        match kind {
            PT_LOAD => {
                let memory_size = u64::from_le_bytes(field(segment, 40));
                let alignment = u64::from_le_bytes(field(segment, 48));
                if size > memory_size
                    || address.checked_add(memory_size).is_none()
                    || (alignment > 1
                        && (!alignment.is_power_of_two()
                            || offset % alignment != address % alignment))
                {
                    return Err(InvalidProgramTable);
                }
                entry_is_file_backed |= flags & PF_X != 0
                    && entry
                        .checked_sub(address)
                        .is_some_and(|distance| distance < size);
            }
            PT_INTERP => {
                if interpreter.is_some() || !(2..=INTERPRETER_MAX_BYTES).contains(&size) {
                    return Err(InvalidInterpreter);
                }
                let raw = prefix_region(prefix, offset, size).ok_or(HeaderOutsidePrefix)?;
                interpreter = Some(interpreter_path(raw)?);
            }
            _ => {}
        }
    }
    if entry == 0 || !entry_is_file_backed {
        return Err(InvalidProgramTable);
    }
    Ok(ExecutableHeader {
        platform: expected,
        kind,
        interpreter,
    })
}

fn elf_machine(platform: Platform) -> u16 {
    match platform {
        Platform::LinuxX86_64 => 62,
        Platform::LinuxAarch64 => 183,
    }
}

// Callers have already checked the fixed-size ELF64 or program header.
fn field<const N: usize>(header: &[u8], offset: usize) -> [u8; N] {
    header[offset..offset + N].try_into().unwrap()
}

fn range_within(offset: u64, length: u64, end: u64) -> bool {
    offset.checked_add(length).is_some_and(|limit| limit <= end)
}

fn prefix_region(prefix: &[u8], offset: u64, length: u64) -> Option<&[u8]> {
    let offset = usize::try_from(offset).ok()?;
    let length = usize::try_from(length).ok()?;
    prefix.get(offset..offset.checked_add(length)?)
}

fn interpreter_path(raw: &[u8]) -> Result<String, ExecutableError> {
    let invalid = ExecutableError::InvalidInterpreter;
    let terminated = raw.strip_suffix(&[0]).ok_or(invalid)?;
    let path = std::str::from_utf8(terminated).map_err(|_| invalid)?;
    let relative = path.strip_prefix('/').ok_or(invalid)?;
    if !relative.bytes().all(|byte| byte.is_ascii_graphic())
        || relative
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
    {
        return Err(invalid);
    }
    Ok(path.into())
}

/// Small structural ELF bytes for archive parser tests. They are never executed.
#[cfg(test)]
pub(super) fn fixture_elf(platform: Platform, interpreter: Option<&str>) -> Vec<u8> {
    let mut bytes = vec![0u8; 512];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put(
        &mut bytes,
        16,
        if interpreter.is_some() { 3u16 } else { 2u16 }.to_le_bytes(),
    );
    put(&mut bytes, 18, elf_machine(platform).to_le_bytes());
    put(&mut bytes, 20, 1u32.to_le_bytes());
    put(&mut bytes, 24, 0x400180u64.to_le_bytes());
    put(&mut bytes, 32, (ELF_HEADER_BYTES as u64).to_le_bytes());
    put(&mut bytes, 52, (ELF_HEADER_BYTES as u16).to_le_bytes());
    put(&mut bytes, 54, (PROGRAM_HEADER_BYTES as u16).to_le_bytes());
    put(
        &mut bytes,
        56,
        (if interpreter.is_some() { 2u16 } else { 1u16 }).to_le_bytes(),
    );

    let mut load = ELF_HEADER_BYTES;
    if let Some(interpreter) = interpreter {
        const PATH_OFFSET: usize = 256;
        assert!(interpreter.len() < 128);
        put(&mut bytes, load, PT_INTERP.to_le_bytes());
        put(&mut bytes, load + 8, (PATH_OFFSET as u64).to_le_bytes());
        put(
            &mut bytes,
            load + 32,
            ((interpreter.len() + 1) as u64).to_le_bytes(),
        );
        bytes[PATH_OFFSET..PATH_OFFSET + interpreter.len()].copy_from_slice(interpreter.as_bytes());
        load += PROGRAM_HEADER_BYTES;
    }
    let total = bytes.len() as u64;
    put(&mut bytes, load, PT_LOAD.to_le_bytes());
    put(&mut bytes, load + 4, (4 | PF_X).to_le_bytes());
    put(&mut bytes, load + 16, 0x400000u64.to_le_bytes());
    put(&mut bytes, load + 32, total.to_le_bytes());
    put(&mut bytes, load + 40, total.to_le_bytes());
    put(&mut bytes, load + 48, 4096u64.to_le_bytes());
    bytes[384] = 1;
    bytes
}

#[cfg(test)]
fn put<const N: usize>(bytes: &mut [u8], offset: usize, value: [u8; N]) {
    bytes[offset..offset + N].copy_from_slice(&value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARM: Platform = Platform::LinuxAarch64;
    const X86: Platform = Platform::LinuxX86_64;
    const ARM_LOADER: &str = "/lib/ld-linux-aarch64.so.1";

    fn inspect(bytes: &[u8], platform: Platform) -> Result<ExecutableHeader, ExecutableError> {
        inspect_executable(bytes, bytes.len() as u64, platform)
    }

    #[test]
    fn requires_expected_elf_class_cpu_and_object_kind() {
        let arm = fixture_elf(ARM, Some(ARM_LOADER));
        let header = inspect(&arm, ARM).unwrap();
        assert_eq!(header.platform(), ARM);
        assert_eq!(header.kind(), ElfKind::Dynamic);
        assert_eq!(header.interpreter(), Some(ARM_LOADER));
        assert_eq!(inspect(&arm, X86), Err(ExecutableError::WrongPlatform));
        let static_like = inspect(&fixture_elf(X86, None), X86).unwrap();
        assert_eq!(static_like.kind(), ElfKind::Executable);
        assert_eq!(static_like.interpreter(), None);

        for (offset, wrong) in [
            (0, 0),  // Magic
            (4, 1),  // ELF32
            (5, 2),  // Big endian
            (6, 0),  // Identification version
            (7, 9),  // FreeBSD ABI
            (16, 1), // ET_REL
            (20, 2), // ELF header version
            (52, 0), // ELF header size
        ] {
            let mut changed = arm.clone();
            changed[offset] = wrong;
            assert_eq!(
                inspect(&changed, ARM),
                Err(ExecutableError::InvalidElf),
                "{offset}"
            );
        }
        assert_eq!(
            inspect(b"#!/bin/sh\n", ARM),
            Err(ExecutableError::InvalidElf)
        );
    }

    #[test]
    fn rejects_truncated_overflowing_and_out_of_prefix_program_tables() {
        let bytes = fixture_elf(ARM, None);
        let file_len = bytes.len() as u64;
        assert_eq!(
            inspect_executable(&bytes[..ELF_HEADER_BYTES], file_len, ARM),
            Err(ExecutableError::HeaderOutsidePrefix),
        );
        assert_eq!(
            inspect(&bytes[..ELF_HEADER_BYTES], ARM),
            Err(ExecutableError::InvalidProgramTable),
        );
        for invalid_offset in [0, file_len - 1, u64::MAX] {
            let mut changed = bytes.clone();
            put(&mut changed, 32, invalid_offset.to_le_bytes());
            assert_eq!(
                inspect(&changed, ARM),
                Err(ExecutableError::InvalidProgramTable)
            );
        }
        for invalid_count in [0, u16::MAX] {
            let mut changed = bytes.clone();
            put(&mut changed, 56, invalid_count.to_le_bytes());
            assert_eq!(
                inspect(&changed, ARM),
                Err(ExecutableError::InvalidProgramTable)
            );
        }
        let mut changed = bytes;
        put(&mut changed, 54, 64u16.to_le_bytes());
        assert_eq!(
            inspect(&changed, ARM),
            Err(ExecutableError::InvalidProgramTable)
        );
    }

    #[test]
    fn checks_load_ranges_alignment_and_file_backed_entry() {
        let bytes = fixture_elf(ARM, None);
        let load = ELF_HEADER_BYTES;
        for (offset, value) in [
            (load + 8, u64::MAX),  // Overflowing file range
            (load + 40, 1),        // p_memsz < p_filesz
            (load + 48, 3),        // Not power-of-two alignment
            (load + 16, 0x400001), // Virtual address not congruent with file offset
            (24, 0),               // Ordinary shared objects do not supply an entry
            (24, 0x401000),        // Entry outside the executable load segment
        ] {
            let mut changed = bytes.clone();
            put(&mut changed, offset, value.to_le_bytes());
            assert_eq!(
                inspect(&changed, ARM),
                Err(ExecutableError::InvalidProgramTable),
                "{offset}"
            );
        }
        let mut not_executable = bytes.clone();
        put(&mut not_executable, load + 4, 4u32.to_le_bytes());
        assert_eq!(
            inspect(&not_executable, ARM),
            Err(ExecutableError::InvalidProgramTable)
        );
        let mut bss_entry = bytes;
        put(&mut bss_entry, 24, 0x400200u64.to_le_bytes());
        put(&mut bss_entry, load + 40, 1024u64.to_le_bytes());
        assert_eq!(
            inspect(&bss_entry, ARM),
            Err(ExecutableError::InvalidProgramTable)
        );
    }

    #[test]
    fn validates_interpreter_content_and_never_reads_past_prefix() {
        let bytes = fixture_elf(ARM, Some(ARM_LOADER));
        assert_eq!(
            inspect_executable(&bytes[..256], bytes.len() as u64, ARM),
            Err(ExecutableError::HeaderOutsidePrefix),
        );
        for invalid in [
            "",
            "/",
            "lib/loader",
            "/lib/../loader",
            "/lib//loader",
            "/lib/loader\0other",
            "/lib/loader\n",
        ] {
            assert_eq!(
                inspect(&fixture_elf(ARM, Some(invalid)), ARM),
                Err(ExecutableError::InvalidInterpreter),
                "{invalid:?}",
            );
        }
        let mut missing_nul = bytes.clone();
        missing_nul[256 + ARM_LOADER.len()] = b'x';
        assert_eq!(
            inspect(&missing_nul, ARM),
            Err(ExecutableError::InvalidInterpreter)
        );
        let mut duplicate = bytes;
        put(&mut duplicate, 56, 3u16.to_le_bytes());
        duplicate.copy_within(
            ELF_HEADER_BYTES..ELF_HEADER_BYTES + PROGRAM_HEADER_BYTES,
            ELF_HEADER_BYTES + 2 * PROGRAM_HEADER_BYTES,
        );
        assert_eq!(
            inspect(&duplicate, ARM),
            Err(ExecutableError::InvalidInterpreter)
        );
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    #[test]
    fn accepts_an_actual_compiled_linux_executable_prefix() {
        use std::{fs::File, io::Read};

        let platform = if cfg!(target_arch = "aarch64") {
            ARM
        } else {
            X86
        };
        let file = File::open(std::env::current_exe().unwrap()).unwrap();
        let length = file.metadata().unwrap().len();
        let mut prefix = Vec::new();
        file.take(EXECUTABLE_PREFIX_BYTES as u64)
            .read_to_end(&mut prefix)
            .unwrap();
        let header = inspect_executable(&prefix, length, platform).unwrap();
        assert_eq!(header.platform(), platform);
    }
}
