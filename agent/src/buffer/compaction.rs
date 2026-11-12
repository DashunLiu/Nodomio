//! Explicit in-place compaction of the shared SQLite queue.
use super::{SshQueue, State, lock_write, storage};
use crate::identity::Result;
use rusqlite::{Connection, ffi};
use std::ptr;

/// Physical main-file allocation measured before and after maintenance.
#[derive(Debug, PartialEq, Eq)]
pub struct SshCompaction {
    pub allocated_bytes_before: u64,
    pub allocated_bytes_after: u64,
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    pub(crate) static BEFORE_COMPACTION: std::cell::Cell<Option<fn()>> =
        const { std::cell::Cell::new(None) };
}

impl SshQueue {
    pub(super) fn compact(&mut self) -> Result<Option<SshCompaction>> {
        let budget = self
            .budget
            .as_ref()
            .ok_or("SSH_QUEUE_SHARED_BUDGET_REQUIRED")?;
        let mut guard = lock_write(Some(budget), self.recovery_required)?
            .ok_or("SSH_QUEUE_SHARED_BUDGET_REQUIRED")?;
        let connection = &mut self.connection;
        verify_settings(connection)?;
        let page_size: u32 = connection
            .pragma_query_one(None, "page_size")
            .map_err(storage)?;
        let pages: u32 = connection
            .pragma_query_one(None, "page_count")
            .map_err(storage)?;
        let free_pages: u64 = u64::from(
            connection
                .pragma_query_one::<u32>(None, "freelist_count")
                .map_err(storage)?,
        );
        if !(512..=65_536).contains(&page_size)
            || !page_size.is_power_of_two()
            || pages == 0
            || free_pages > u64::from(pages)
        {
            return Err("INVALID_SSH_QUEUE_STATE");
        }
        let logical_bytes = u64::from(page_size) * u64::from(pages);
        let allocated_bytes_before = match guard.check_sqlite_compaction(logical_bytes, free_pages)
        {
            Ok(Some(allocated)) => allocated,
            Ok(None) => return Ok(None),
            Err("SSH_QUEUE_RECOVERY_REQUIRED") => {
                self.recovery_required = true;
                guard.mark_recovery_required();
                return Err("SSH_QUEUE_RECOVERY_REQUIRED");
            }
            Err(code) => return Err(code),
        };

        // A pending page-size change would enter a different SQLite copy and
        // truncation path. Retain the current layout and cap the destination
        // at its logical page count. SQLite may raise the cap to the physical
        // page count when opening a file with a tail left by an earlier crash.
        connection
            .pragma_update(None, "page_size", page_size)
            .map_err(storage)?;
        let cap: u32 = connection
            .pragma_update_and_check(None, "max_page_count", pages, |row| row.get(0))
            .map_err(storage)?;
        if cap != pages {
            return Err("SSH_QUEUE_RESOURCE_LIMIT");
        }

        #[cfg(all(test, target_os = "linux"))]
        BEFORE_COMPACTION.with(|hook| {
            if let Some(before) = hook.take() {
                before();
            }
        });

        let outcome: Result<SshCompaction> = (|| {
            connection.execute_batch("VACUUM main").map_err(storage)?;
            sync_main(connection)?;
            let after_size: u32 = connection
                .pragma_query_one(None, "page_size")
                .map_err(storage)?;
            let after_pages: u32 = connection
                .pragma_query_one(None, "page_count")
                .map_err(storage)?;
            if after_size != page_size || after_pages == 0 || after_pages > pages {
                return Err("INVALID_SSH_QUEUE_STATE");
            }
            State::read(connection)?;
            let allocated_bytes_after = guard.sqlite_main_allocation()?;
            Ok(SshCompaction {
                allocated_bytes_before,
                allocated_bytes_after,
            })
        })();
        match outcome {
            Ok(report) => Ok(Some(report)),
            Err(_) => {
                // SQLite may report an error during the truncate or durability
                // barrier after finalizing its journal. Reopen to verify what
                // committed before admitting more writes in either store.
                self.recovery_required = true;
                guard.mark_recovery_required();
                Err("SSH_QUEUE_RECOVERY_REQUIRED")
            }
        }
    }
}

fn verify_settings(connection: &Connection) -> Result<()> {
    if !connection.is_autocommit() {
        return Err("SSH_QUEUE_TRANSACTION_ACTIVE");
    }
    let mode: String = connection
        .pragma_query_one(None, "journal_mode")
        .map_err(storage)?;
    if mode != "delete" {
        return Err("UNSUPPORTED_SSH_QUEUE_DURABILITY");
    }
    // SQLite attaches a memory B-tree for the rebuild. TEMP_STORE=0 would
    // override the connection's MEMORY setting and use a temporary file.
    let memory_temp: bool = connection
        .query_row(
            "SELECT (sqlite_compileoption_used('TEMP_STORE=1')
                  OR sqlite_compileoption_used('TEMP_STORE=2')
                  OR sqlite_compileoption_used('TEMP_STORE=3'))
                AND sqlite_compileoption_used('OMIT_MEMORYDB') = 0",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if !memory_temp {
        return Err("UNSUPPORTED_SSH_QUEUE_STORAGE_LAYOUT");
    }
    for (pragma, expected) in [
        ("synchronous", 3),
        ("temp_store", 2),
        ("cache_spill", 0),
        ("mmap_size", 0),
        ("auto_vacuum", 0),
    ] {
        let value: i64 = connection.pragma_query_one(None, pragma).map_err(storage)?;
        if value != expected {
            return Err("UNSUPPORTED_SSH_QUEUE_STORAGE_LAYOUT");
        }
    }
    Ok(())
}

pub(super) fn sync_main(connection: &mut Connection) -> Result<()> {
    let mut file: *mut ffi::sqlite3_file = ptr::null_mut();
    // SAFETY: The exclusive borrow keeps the connection and its VFS file
    // alive and prevents simultaneous operations. FILE_POINTER writes a
    // sqlite3_file pointer to the supplied initialized output slot.
    let result = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_FILE_POINTER,
            ptr::from_mut(&mut file).cast(),
        )
    };
    if result != ffi::SQLITE_OK || file.is_null() {
        return Err("SSH_QUEUE_STORAGE_ERROR");
    }
    // SAFETY: A successful FILE_POINTER returned the main pager's live VFS
    // handle. Its immutable method table remains valid until the connection
    // changes or closes. No SQLite API is called between lookup and xSync.
    let sync = unsafe { (*file).pMethods.as_ref() }
        .and_then(|methods| methods.xSync)
        .ok_or("SSH_QUEUE_STORAGE_ERROR")?;
    // SAFETY: xSync receives its own live file handle. Calling the VFS on the
    // existing descriptor avoids releasing POSIX locks via an extra close.
    if unsafe { sync(file, ffi::SQLITE_SYNC_FULL) } != ffi::SQLITE_OK {
        return Err("SSH_QUEUE_STORAGE_ERROR");
    }
    Ok(())
}
