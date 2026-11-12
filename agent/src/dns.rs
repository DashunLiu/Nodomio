//! Bound system DNS work without tying HTTP runtime shutdown to getaddrinfo.

use futures_channel::oneshot;
use reqwest::dns::{Addrs, Resolving};
#[cfg(any(target_os = "linux", test))]
use reqwest::dns::{Name, Resolve};
#[cfg(target_os = "linux")]
use std::net::ToSocketAddrs;
use std::{
    io,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};

const MAX_LOOKUPS: usize = 4;

/// Each caller domain owns its budget; canceled requests retain their slot
/// until the OS lookup actually finishes.
pub(crate) struct LookupLimit {
    active: AtomicUsize,
}

impl LookupLimit {
    pub(crate) const fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
        }
    }

    fn acquire(&self) -> io::Result<LookupSlot<'_>> {
        self.active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                (active < MAX_LOOKUPS).then_some(active + 1)
            })
            .map(|_| LookupSlot(self))
            .map_err(|_| io::Error::other("DNS lookup budget exhausted"))
    }
}

struct LookupSlot<'a>(&'a LookupLimit);

impl Drop for LookupSlot<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
static ORIGIN_LOOKUPS: LookupLimit = LookupLimit::new();

/// Management origins may legitimately resolve to private/self-hosted addresses.
/// HTTPS certificate and hostname validation remains the client's responsibility.
#[cfg(target_os = "linux")]
pub(crate) struct OriginDns;

#[cfg(target_os = "linux")]
impl Resolve for OriginDns {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        resolve_on_worker(&ORIGIN_LOOKUPS, move || {
            let addresses = (host.as_str(), 0).to_socket_addrs()?;
            Ok(Box::new(addresses) as Addrs)
        })
    }
}

/// Late results are dropped with the canceled receiver and cannot initiate HTTP.
pub(crate) fn resolve_on_worker(
    limit: &'static LookupLimit,
    lookup: impl FnOnce() -> io::Result<Addrs> + Send + 'static,
) -> Resolving {
    Box::pin(async move {
        let slot = limit.acquire()?;
        let (send, receive) = oneshot::channel();
        thread::Builder::new()
            .name("nodomi-dns".into())
            .spawn(move || {
                let result = lookup();
                drop(slot);
                let _ = send.send(result);
            })?;
        Ok(receive.await??)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::blocking::Client;
    use std::{
        sync::{Arc, Mutex, mpsc},
        time::{Duration, Instant},
    };

    #[test]
    fn lookup_budgets_are_independent_and_slots_are_reusable() {
        let first = LookupLimit::new();
        let second = LookupLimit::new();
        let mut held = (0..MAX_LOOKUPS)
            .map(|_| first.acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(first.acquire().is_err());
        let independent = second.acquire().unwrap();
        drop(held.pop());
        let replacement = first.acquire().unwrap();
        assert!(first.acquire().is_err());
        drop((held, replacement, independent));
        assert_eq!(first.active.load(Ordering::Relaxed), 0);
        assert_eq!(second.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn request_timeout_and_client_drop_do_not_wait_for_system_dns() {
        static LOOKUPS: LookupLimit = LookupLimit::new();

        struct StalledLookup {
            started: mpsc::Sender<()>,
            resume: Mutex<Option<mpsc::Receiver<()>>>,
        }

        impl Resolve for StalledLookup {
            fn resolve(&self, _: Name) -> Resolving {
                let started = self.started.clone();
                let resume = self.resume.lock().unwrap().take().unwrap();
                resolve_on_worker(&LOOKUPS, move || {
                    started.send(()).unwrap();
                    let _ = resume.recv_timeout(Duration::from_secs(4));
                    Err(io::Error::other("fixture returned no DNS address"))
                })
            }
        }

        let (started, observed) = mpsc::channel();
        let (resume, wait) = mpsc::channel();
        let client = Client::builder()
            .no_proxy()
            .dns_resolver(Arc::new(StalledLookup {
                started,
                resume: Mutex::new(Some(wait)),
            }))
            .build()
            .unwrap();
        let start = Instant::now();
        let error = client
            .get("https://fixture.invalid")
            .timeout(Duration::from_millis(400))
            .send()
            .unwrap_err();
        drop(client);
        assert!(error.is_timeout());
        assert!(observed.try_recv().is_ok());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(LOOKUPS.active.load(Ordering::Relaxed), 1);
        resume.send(()).unwrap();
    }
}
