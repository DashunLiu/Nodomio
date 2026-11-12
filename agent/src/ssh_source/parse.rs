//! Classify the MESSAGE of a record whose OpenSSH origin was already verified.
use std::{net::IpAddr, str};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Classification {
    Ignored,
    UnknownFormat,
    Event {
        accepted: bool,
        source_ip: Option<IpAddr>,
        username: Option<String>,
    },
}

pub(super) fn classify(message: &[u8]) -> Classification {
    // OpenSSH also emits operational messages such as "Failed to ...".
    let status_end = message
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(message.len());
    let accepted = match &message[..status_end] {
        b"Accepted" => true,
        b"Failed" if !message.starts_with(b"Failed to ") => false,
        _ => return Classification::Ignored,
    };
    let Some((user, address)) = message[status_end..]
        .strip_prefix(b" ")
        .and_then(|result| fields(result, accepted))
    else {
        return Classification::UnknownFormat;
    };
    Classification::Event {
        accepted,
        source_ip: str::from_utf8(address)
            .ok()
            .and_then(|address| address.parse::<IpAddr>().ok())
            .map(|address| address.to_canonical()),
        username: username(user),
    }
}

fn fields(result: &[u8], accepted: bool) -> Option<(&[u8], &[u8])> {
    if result.iter().any(|byte| matches!(byte, b'\n' | b'\r' | 0)) {
        return None;
    }
    let mut fields = result.splitn(2, |&byte| byte == b' ');
    let method = fields.next()?;
    let remainder = fields.next()?;
    let mut parts = method.split(|&byte| byte == b'/');
    if !parts.next().is_some_and(method_token)
        || parts.next().is_some_and(|part| !method_token(part))
        || parts.next().is_some()
    {
        return None;
    }
    let remainder = remainder.strip_prefix(b"for ")?;
    let remainder = match remainder.strip_prefix(b"invalid user ") {
        Some(_) if accepted => return None,
        Some(user) => user,
        None => remainder,
    };

    let separator = b" from ";
    let mut matches = remainder
        .windows(separator.len())
        .enumerate()
        .filter(|(_, part)| *part == separator)
        .filter_map(|(end, _)| {
            let address = endpoint(&remainder[end + separator.len()..])?;
            Some((&remainder[..end], address))
        });
    let fields = matches.next()?;
    // A remote username or certificate comment can contain delimiters.
    // More than one possible endpoint leaves the fields ambiguous.
    matches.next().is_none().then_some(fields)
}

fn method_token(token: &[u8]) -> bool {
    (1..=64).contains(&token.len())
        && token[0].is_ascii_alphanumeric()
        && token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@-".contains(byte))
}

fn endpoint(input: &[u8]) -> Option<&[u8]> {
    // The OpenSSH producer bounds the address field to 200 bytes. Checking
    // the same window also bounds work for every candidate separator.
    let address_end = input.iter().take(201).position(u8::is_ascii_whitespace)?;
    if address_end == 0 {
        return None;
    }
    let rest = input[address_end..].strip_prefix(b" port ")?;
    let port_end = rest.iter().take(6).position(|&byte| byte == b' ')?;
    let port = &rest[..port_end];
    if !port
        .first()
        .is_some_and(|first| (b'1'..=b'9').contains(first))
        || !port.iter().all(u8::is_ascii_digit)
        || str::from_utf8(port).ok()?.parse::<u16>().is_err()
    {
        return None;
    }
    let suffix = rest[port_end..].strip_prefix(b" ssh2")?;
    let tail_valid = suffix.is_empty()
        || suffix
            .strip_prefix(b": ")
            .is_some_and(|tail| !tail.is_empty());
    tail_valid.then_some(&input[..address_end])
}

fn username(user: &[u8]) -> Option<String> {
    // auth_log can truncate the input at 100 bytes before escaping. An
    // escaped or truncated string may identify the wrong user.
    let user = str::from_utf8(user).ok()?;
    (!user.is_empty()
        && user.len() < 100
        && !user
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '\\'))
    .then(|| user.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(accepted: bool, source_ip: Option<&str>, username: Option<&str>) -> Classification {
        Classification::Event {
            accepted,
            source_ip: source_ip.map(|ip| ip.parse().unwrap()),
            username: username.map(str::to_owned),
        }
    }

    #[test]
    fn openssh_auth_result_cases() {
        // Representative OpenSSH authentication outcomes and excluded messages.
        const IP4: &str = "192.0.2.24";
        const IP6: &str = "2001:db8::24";
        let vectors = [
            (
                "Accepted password for demo from 192.0.2.24 port 40100 ssh2",
                event(true, Some(IP4), Some("demo")),
            ),
            (
                "Failed password for demo from 192.0.2.24 port 40100 ssh2",
                event(false, Some(IP4), Some("demo")),
            ),
            (
                "Failed password for invalid user sample from 192.0.2.24 port 40100 ssh2",
                event(false, Some(IP4), Some("sample")),
            ),
            (
                "Accepted publickey for demo from 2001:db8::24 port 40100 ssh2: ED25519 SHA256:synthetic",
                event(true, Some(IP6), Some("demo")),
            ),
            (
                "Failed publickey for demo from 192.0.2.24 port 40100 ssh2: ED25519 SHA256:synthetic",
                event(false, Some(IP4), Some("demo")),
            ),
            (
                "Accepted keyboard-interactive/pam for demo from 192.0.2.24 port 40100 ssh2",
                event(true, Some(IP4), Some("demo")),
            ),
            (
                "Failed keyboard-interactive/pam for demo from 192.0.2.24 port 40100 ssh2",
                event(false, Some(IP4), Some("demo")),
            ),
            (
                "Failed keyboard-interactive/pam for invalid user sample from 192.0.2.24 port 40100 ssh2",
                event(false, Some(IP4), Some("sample")),
            ),
            (
                "Partial publickey for demo from 192.0.2.24 port 40100 ssh2: ED25519 SHA256:synthetic",
                Classification::Ignored,
            ),
            (
                "Postponed keyboard-interactive/pam for demo from 192.0.2.24 port 40100 ssh2",
                Classification::Ignored,
            ),
            (
                "Invalid user sample from 192.0.2.24 port 40100",
                Classification::Ignored,
            ),
            (
                "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.24 user=demo",
                Classification::Ignored,
            ),
            (
                "PAM: password authentication accepted for demo",
                Classification::Ignored,
            ),
            (
                "Connection closed by authenticating user demo 192.0.2.24 port 40100 [preauth]",
                Classification::Ignored,
            ),
            (
                "Failed password for demo from 192.0.2.24 port 40100 ssh2",
                event(false, Some(IP4), Some("demo")),
            ),
            (
                "Failed password for demo from ::ffff:192.0.2.24 port 40100 ssh2",
                event(false, Some(IP4), Some("demo")),
            ),
            (
                "Failed password for demo from invalid-address port 40100 ssh2",
                event(false, None, Some("demo")),
            ),
            (
                "Failed future-method@example.test for demo from 192.0.2.24 port 40100 ssh2",
                event(false, Some(IP4), Some("demo")),
            ),
            (
                "Failed keyboard-interactive//pam for demo from 192.0.2.24 port 40100 ssh2",
                Classification::UnknownFormat,
            ),
            (
                "Accepted password for demo from 192.0.2.24 port 40100 ssh",
                Classification::UnknownFormat,
            ),
        ];
        for (index, (message, expected)) in vectors.into_iter().enumerate() {
            assert_eq!(
                classify(message.as_bytes()),
                expected,
                "OpenSSH case {index}"
            );
        }
    }

    #[test]
    fn ambiguous_endpoints_in_the_username_or_tail_are_not_guessed() {
        for message in [
            b"Failed password for invalid user demo from 198.51.100.2 port 22 ssh2: forged from 192.0.2.24 port 40100 ssh2".as_slice(),
            b"Accepted publickey for demo from 192.0.2.24 port 40100 ssh2: key text from 198.51.100.2 port 22 ssh2",
        ] {
            assert_eq!(classify(message), Classification::UnknownFormat);
        }
    }

    #[test]
    fn unclear_usernames_are_null_and_incomplete_results_are_unknown() {
        for message in [
            b"Failed password for invalid user \\001demo from 192.0.2.24 port 40100 ssh2"
                .as_slice(),
            b"Failed password for invalid user \xFFdemo from 192.0.2.24 port 40100 ssh2",
            b"Failed password for invalid user  from 192.0.2.24 port 40100 ssh2",
        ] {
            assert_eq!(classify(message), event(false, Some("192.0.2.24"), None));
        }
        let message = format!(
            "Failed password for {} from 192.0.2.24 port 40100 ssh2",
            "a".repeat(100)
        );
        assert_eq!(
            classify(message.as_bytes()),
            event(false, Some("192.0.2.24"), None)
        );
        for message in [
            b"Failed password for demo from 192.0.2.24 port 65536 ssh2".as_slice(),
            b"Failed password for demo from 192.0.2.24 port 40100 ssh2x",
            b"Failed password for demo from 192.0.2.24 port 40100 ssh2: ",
            b"Failed password for demo\nfrom 192.0.2.24 port 40100 ssh2",
            b"Accepted password for invalid user demo from 192.0.2.24 port 40100 ssh2",
        ] {
            assert_eq!(classify(message), Classification::UnknownFormat);
        }
        assert_eq!(
            classify(b"Failed to allocate a terminal"),
            Classification::Ignored
        );
    }
}
