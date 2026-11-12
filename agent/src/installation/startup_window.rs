//! The installer-owned, persisted window for bounded service startup.

use super::{
    control_record::{ControlPhase, ControlRecordError, read_record},
    health_confirmation::{boot_id, health_boottime_ns},
};
use crate::identity::{IdentityStore, Result, uuid};
use serde::{Deserialize, Serialize};
use std::{fs::File, time::Duration};

/// Private handshake between a verified collector and its supervisor. A
/// parked old-boot install has drained cleanly and awaits its installer.
pub const AWAITING_INSTALL_TAKEOVER_EXIT: u8 = 75;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartupWindow {
    boot_id: String,
    started_ns: u64,
    deadline_ns: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    renewals: u32,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl StartupWindow {
    pub const DURATION: Duration = Duration::from_secs(45);
    const DURATION_NS: u64 = 45_000_000_000;

    #[cfg(test)]
    pub(super) fn start() -> Result<Self> {
        let started_ns = health_boottime_ns().map_err(|_| "INVALID_INSTALL_STARTUP")?;
        Ok(Self {
            boot_id: boot_id().map_err(|_| "INVALID_INSTALL_STARTUP")?,
            started_ns,
            deadline_ns: started_ns
                .checked_add(Self::DURATION_NS)
                .ok_or("INVALID_INSTALL_STARTUP")?,
            previous_boot_id: None,
            renewals: 0,
        })
    }

    pub(super) fn valid(&self) -> bool {
        uuid(&self.boot_id)
            && self.deadline_ns.checked_sub(self.started_ns) == Some(Self::DURATION_NS)
            && match &self.previous_boot_id {
                None => self.renewals == 0,
                Some(previous) => self.renewals != 0 && uuid(previous) && previous != &self.boot_id,
            }
    }

    pub(super) fn renewals(&self) -> u64 {
        u64::from(self.renewals)
    }

    pub(super) fn current_boot(&self) -> Result<bool> {
        Ok(boot_id().map_err(|_| "INVALID_INSTALL_STARTUP")? == self.boot_id)
    }

    #[cfg(test)]
    pub(super) fn renew_after_reboot(&self) -> Result<Self> {
        let mut next = Self::start()?;
        if !self.valid() || next.boot_id == self.boot_id {
            return Err("INVALID_INSTALL_STARTUP");
        }
        next.previous_boot_id = Some(self.boot_id.clone());
        next.renewals = self
            .renewals
            .checked_add(1)
            .ok_or("INVALID_INSTALL_STARTUP")?;
        Ok(next)
    }

    #[cfg(test)]
    pub(super) fn follows_reboot(&self, previous: &Self) -> bool {
        self.boot_id != previous.boot_id
            && self.previous_boot_id.as_ref() == Some(&previous.boot_id)
            && self.renewals.checked_sub(1) == Some(previous.renewals)
    }

    pub fn remaining(&self) -> Result<Duration> {
        let now = health_boottime_ns().map_err(|_| "INVALID_INSTALL_STARTUP")?;
        let boot = boot_id().map_err(|_| "INVALID_INSTALL_STARTUP")?;
        self.remaining_at(&boot, now)
    }

    fn remaining_at(&self, boot: &str, now: u64) -> Result<Duration> {
        if boot != self.boot_id || !(self.started_ns..self.deadline_ns).contains(&now) {
            return Err("INSTALL_STARTUP_EXPIRED");
        }
        Ok(Duration::from_nanos(self.deadline_ns - now))
    }

    #[cfg(test)]
    pub(super) fn started_ns(&self) -> u64 {
        self.started_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_does_not_renew_or_cross_a_startup_window() {
        let window = StartupWindow::start().unwrap();
        let restored: StartupWindow =
            serde_json::from_slice(&serde_json::to_vec(&window).unwrap()).unwrap();
        assert_eq!(restored, window);
        assert!(restored.valid());
        assert_eq!(
            restored.remaining_at(&window.boot_id, window.deadline_ns - 1),
            Ok(Duration::from_nanos(1))
        );
        assert_eq!(
            restored.remaining_at(&window.boot_id, window.deadline_ns),
            Err("INSTALL_STARTUP_EXPIRED")
        );
        assert_eq!(
            restored.remaining_at(&window.boot_id, window.started_ns.saturating_sub(1)),
            Err("INSTALL_STARTUP_EXPIRED")
        );
        assert_eq!(
            restored.remaining_at("another-boot", window.started_ns),
            Err("INSTALL_STARTUP_EXPIRED")
        );
        assert!(restored.renew_after_reboot().is_err());
    }

    #[test]
    fn cold_renewal_retains_previous_boot_and_counts_one_revision() {
        let mut old = StartupWindow::start().unwrap();
        old.boot_id = if old.boot_id == "00000000-0000-4000-8000-000000000001" {
            "00000000-0000-4000-8000-000000000002".into()
        } else {
            "00000000-0000-4000-8000-000000000001".into()
        };
        let current = old.renew_after_reboot().unwrap();
        assert!(current.valid());
        assert!(current.follows_reboot(&old));
        assert_eq!(current.renewals(), 1);
        assert!(current.renew_after_reboot().is_err());
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartupState {
    Legacy,
    Pending(StartupWindow),
    AwaitingTakeover,
    Settled,
}

/// Observe the same protected control directory that anchors the service lease.
/// A missing startup field preserves existing installed layouts. The service
/// sets `sync_pending` at admission before its first write, then polls without
/// syncing an unchanged pending window.
pub fn read_startup_state(
    control: &File,
    identity: &IdentityStore,
    sync_pending: bool,
) -> Result<StartupState> {
    let read = || {
        read_record(control).or_else(|error| match error {
            // Atomic journal replacement can change the named inode during one read.
            ControlRecordError::UnsafeEntry => read_record(control),
            _ => Err(error),
        })
    };
    let record = match read() {
        Ok(record) => record,
        Err(ControlRecordError::NotFound) => return Ok(StartupState::Legacy),
        Err(_) => return Err("INVALID_INSTALL_STARTUP"),
    };
    let Some(business) = record.business() else {
        return Ok(StartupState::Legacy);
    };
    if business.startup_window().is_none() {
        return Ok(StartupState::Legacy);
    }
    if record.phase() != ControlPhase::Ready || &record.claim().target != identity.target() {
        return Err("INVALID_INSTALL_STARTUP");
    }
    let state = business.startup_state(identity)?;
    if state == StartupState::Settled || (sync_pending && matches!(state, StartupState::Pending(_)))
    {
        // A rename is visible before the writer's directory fsync. Do not
        // start work or lift restrictions on a merely visible record.
        control.sync_all().map_err(|_| "INVALID_INSTALL_STARTUP")?;
        let synced = read().map_err(|_| "INVALID_INSTALL_STARTUP")?;
        if synced.phase() != ControlPhase::Ready
            || synced.control_domain_id() != record.control_domain_id()
            || synced.claim() != record.claim()
            || synced
                .business()
                .ok_or("INVALID_INSTALL_STARTUP")?
                .startup_state(identity)?
                != state
        {
            return Err("INVALID_INSTALL_STARTUP");
        }
    }
    Ok(state)
}
