//! Keep system DNS off the HTTP runtime, then connect only to vetted addresses.

use crate::dns::{LookupLimit, resolve_on_worker};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
};

static LOOKUPS: LookupLimit = LookupLimit::new();

pub(super) struct PublicDns;

impl Resolve for PublicDns {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        resolve_on_worker(&LOOKUPS, move || {
            let addresses = (host.as_str(), 443).to_socket_addrs()?.collect();
            checked_addresses(addresses)
        })
    }
}

fn checked_addresses(addresses: Vec<SocketAddr>) -> io::Result<Addrs> {
    if addresses.is_empty() || addresses.iter().any(|addr| !is_public(addr.ip())) {
        return Err(io::Error::other("non-public release address"));
    }
    Ok(Box::new(addresses.into_iter()))
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let [a, b, ..] = ip.segments();
            // Permit ordinary global unicast, excluding transition and reserved ranges.
            (0x2000..=0x3fff).contains(&a)
                && !(a == 0x2001 && (b < 0x0200 || b == 0x0db8))
                && a != 0x2002
                && !(a == 0x3fff && b < 0x1000)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        (0 | 10 | 127 | 224..=255, _, _)
            | (100, 64..=127, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0 | 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18 | 19, _)
            | (198, 51, 100)
            | (203, 0, 113)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_answer_invalidates_the_entire_dns_result() {
        let public: SocketAddr = "140.82.114.3:443".parse().unwrap();
        for private in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "169.254.169.254:443",
            "[::ffff:192.168.1.2]:443",
            "[fd00::1]:443",
            "[fe80::1]:443",
        ] {
            assert!(checked_addresses(vec![public, private.parse().unwrap()]).is_err());
        }
        assert!(checked_addresses(Vec::new()).is_err());
        let ipv6 = "[2606:50c0:8000::153]:443".parse().unwrap();
        assert_eq!(
            checked_addresses(vec![public, ipv6])
                .unwrap()
                .collect::<Vec<_>>(),
            vec![public, ipv6]
        );
    }
}
