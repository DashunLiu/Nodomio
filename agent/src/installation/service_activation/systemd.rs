use super::{ActivationError, command};
use std::{collections::BTreeMap, fs::File, time::Duration};

const MANAGER_ARGUMENTS: &[&str] = &["systemctl", "--system", "--no-pager", "--no-ask-password"];
const UNIT: &str = "nodomi-agent.service";
const UNIT_PATH: &str = "/etc/systemd/system/nodomi-agent.service";
const PROPERTIES: &[&str] = &[
    "Id",
    "Names",
    "LoadState",
    "FragmentPath",
    "SourcePath",
    "DropInPaths",
    "Transient",
    "NeedDaemonReload",
    "Type",
    "User",
    "Group",
    "KillMode",
    "SendSIGKILL",
    "StandardInput",
    "Restart",
    "CanStart",
    "UnitFileState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "InvocationID",
    "Job",
    "ExecStart",
    "ExecCondition",
    "ExecStartPre",
    "ExecStartPost",
    "ExecStop",
    "ExecStopPost",
];

pub(super) fn reload(tool: &File) -> Result<(), ActivationError> {
    mutate(tool, &["daemon-reload"])
}

pub(super) fn enable(tool: &File) -> Result<(), ActivationError> {
    mutate(tool, &["enable", UNIT_PATH])
}

pub(super) fn start(tool: &File) -> Result<(), ActivationError> {
    mutate(tool, &["--job-mode=fail", "start", UNIT])
}

fn mutate(tool: &File, operation: &[&str]) -> Result<(), ActivationError> {
    let argv = [MANAGER_ARGUMENTS, operation].concat();
    command::run(tool, &argv, Duration::from_secs(30))
        .map(|_| ())
        .map_err(|_| ActivationError::OutcomeUnknown)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ObservedInstance {
    pub(super) pid: u32,
    pub(super) invocation_id: u128,
}

pub(super) fn observe(
    tool: &File,
    enabled: bool,
) -> Result<Option<ObservedInstance>, ActivationError> {
    let property_argument = format!("--property={}", PROPERTIES.join(","));
    let argv = [
        MANAGER_ARGUMENTS,
        &["show", "--all", &property_argument, UNIT],
    ]
    .concat();
    let output = command::run(tool, &argv, Duration::from_secs(5))
        .map_err(|_| ActivationError::Unavailable)?;
    loaded_unit(&output, enabled)
}

fn loaded_unit(output: &[u8], enabled: bool) -> Result<Option<ObservedInstance>, ActivationError> {
    let text = std::str::from_utf8(output).map_err(|_| ActivationError::Unavailable)?;
    let mut properties = BTreeMap::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once('=').ok_or(ActivationError::Unavailable)?;
        if !PROPERTIES.contains(&name) || properties.insert(name, value).is_some() {
            return Err(ActivationError::Unavailable);
        }
    }
    let property = |name: &str| {
        properties
            .get(name)
            .copied()
            .ok_or(ActivationError::Unavailable)
    };
    for (name, expected) in [
        ("Id", UNIT),
        ("Names", UNIT),
        ("LoadState", "loaded"),
        ("FragmentPath", UNIT_PATH),
        ("SourcePath", ""),
        ("DropInPaths", ""),
        ("Transient", "no"),
        ("NeedDaemonReload", "no"),
        ("Type", "simple"),
        ("User", "root"),
        ("Group", "root"),
        ("KillMode", "control-group"),
        ("SendSIGKILL", "yes"),
        ("StandardInput", "null"),
        ("Restart", "on-failure"),
        ("CanStart", "yes"),
        ("ControlPID", "0"),
        ("Job", ""),
        (
            "UnitFileState",
            if enabled { "enabled" } else { "disabled" },
        ),
    ] {
        if property(name)? != expected {
            return Err(ActivationError::Blocked);
        }
    }
    // systemctl omits an empty array of commands even with --all on v252.
    for name in [
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecStop",
        "ExecStopPost",
    ] {
        if properties.get(name).is_some_and(|value| !value.is_empty()) {
            return Err(ActivationError::Blocked);
        }
    }
    let command = property("ExecStart")?;
    let arguments = concat!(
        "{ path=/opt/nodomi-agent/bin/nodomi-agent-supervisor ; ",
        "argv[]=/opt/nodomi-agent/bin/nodomi-agent-supervisor ; ignore_errors=no ; ",
    );
    if !command
        .strip_prefix(arguments)
        .and_then(|rest| rest.strip_suffix(" }"))
        .is_some_and(|rest| !rest.contains(['{', '}']))
    {
        return Err(ActivationError::Blocked);
    }
    let pid = property("MainPID")?
        .parse::<u32>()
        .map_err(|_| ActivationError::Unavailable)?;
    let invocation = property("InvocationID")?;
    let valid_invocation = invocation.len() == 32
        && invocation
            .bytes()
            .all(|digit| digit.is_ascii_digit() || (b'a'..=b'f').contains(&digit));
    match (property("ActiveState")?, property("SubState")?, pid) {
        ("inactive", "dead", 0) => Ok(None),
        ("active", "running", 2..=2_147_483_647) if valid_invocation => {
            let invocation_id =
                u128::from_str_radix(invocation, 16).map_err(|_| ActivationError::Unavailable)?;
            if invocation_id == 0 {
                return Err(ActivationError::Unavailable);
            }
            Ok(Some(ObservedInstance { pid, invocation_id }))
        }
        _ => Err(ActivationError::Blocked),
    }
}

pub(super) fn fixed_install_target(bytes: &[u8]) -> bool {
    let Ok(template) = std::str::from_utf8(bytes) else {
        return false;
    };
    if template.contains('\0') || template.lines().any(|line| line.trim_end().ends_with('\\')) {
        return false;
    }
    let directives = template
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(['#', ';']));
    let mut install = false;
    let mut wanted = false;
    for line in directives {
        if install {
            if wanted || line != "WantedBy=multi-user.target" {
                return false;
            }
            wanted = true;
        } else if line == "[Install]" {
            install = true;
        } else if line.starts_with('[') && !matches!(line, "[Unit]" | "[Service]") {
            return false;
        }
    }
    wanted
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOADED: &str = "Id=nodomi-agent.service\nNames=nodomi-agent.service\nLoadState=loaded\nFragmentPath=/etc/systemd/system/nodomi-agent.service\nSourcePath=\nDropInPaths=\nTransient=no\nNeedDaemonReload=no\nType=simple\nUser=root\nGroup=root\nKillMode=control-group\nSendSIGKILL=yes\nStandardInput=null\nRestart=on-failure\nCanStart=yes\nUnitFileState=enabled\nActiveState=active\nSubState=running\nMainPID=47\nControlPID=0\nInvocationID=0000000000000000000000000000002f\nJob=\nExecStart={ path=/opt/nodomi-agent/bin/nodomi-agent-supervisor ; argv[]=/opt/nodomi-agent/bin/nodomi-agent-supervisor ; ignore_errors=no ; start_time=[Mon 2026-11-09 10:00:00 UTC] ; stop_time=[n/a] ; pid=47 ; code=(null) ; status=0/0 }\n";

    #[test]
    fn exactly_loaded_running_unit_proves_only_manager_pid() {
        assert_eq!(
            loaded_unit(LOADED.as_bytes(), true),
            Ok(Some(ObservedInstance {
                pid: 47,
                invocation_id: 47
            }))
        );
        let inactive = LOADED
            .replace("ActiveState=active", "ActiveState=inactive")
            .replace("SubState=running", "SubState=dead")
            .replace("MainPID=47", "MainPID=0");
        assert_eq!(loaded_unit(inactive.as_bytes(), true), Ok(None));
    }

    #[test]
    fn overridden_stale_or_ambiguous_manager_output_fails_closed() {
        for (original, changed) in [
            (
                "DropInPaths=",
                "DropInPaths=/run/systemd/system/nodomi-agent.service.d/override.conf",
            ),
            ("NeedDaemonReload=no", "NeedDaemonReload=yes"),
            (
                "FragmentPath=/etc/systemd/system/nodomi-agent.service",
                "FragmentPath=/usr/lib/systemd/system/nodomi-agent.service",
            ),
            (
                "argv[]=/opt/nodomi-agent/bin/nodomi-agent-supervisor ;",
                "argv[]=/opt/nodomi-agent/bin/nodomi-agent-supervisor --other ;",
            ),
            (
                "SourcePath=",
                "ExecStartPre={ path=/bin/sh ; argv[]=/bin/sh }\nSourcePath=",
            ),
            ("ControlPID=0", "ControlPID=8"),
            ("Job=", "Job=42"),
            (
                "InvocationID=0000000000000000000000000000002f",
                "InvocationID=00000000000000000000000000000000",
            ),
            ("MainPID=47", "MainPID=47\nMainPID=0"),
        ] {
            assert!(
                loaded_unit(LOADED.replace(original, changed).as_bytes(), true).is_err(),
                "{changed}"
            );
        }
    }
}
