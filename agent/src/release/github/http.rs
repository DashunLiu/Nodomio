use super::super::manifest::{ManifestArtifact, OFFICIAL_OWNER, OFFICIAL_REPO, ReleaseError};
use super::dns::PublicDns;
use reqwest::{
    StatusCode, Url,
    blocking::{Client, ClientBuilder, Response},
    header::{
        AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, HeaderMap, HeaderValue, LOCATION,
        RETRY_AFTER,
    },
};
use ring::digest::{Context, SHA256};
use serde::de::DeserializeOwned;
use std::{
    io::{self, Read, Write},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const API_HOST: &str = "api.github.com";
const API_VERSION: &str = "2022-11-28";
const MAX_JSON_BYTES: u64 = 2 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const USER_AGENT: &str = concat!("nodomi-agent/", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Copy)]
pub(super) struct Deadline(Instant);

impl Deadline {
    pub(super) fn new(timeout: Duration) -> Self {
        Self(Instant::now() + timeout)
    }

    pub(super) fn remaining(self) -> Result<Duration, ReleaseError> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(ReleaseError::Timeout)
    }

    fn transport_failure(self, is_timeout: bool) -> ReleaseError {
        if is_timeout || self.remaining().is_err() {
            ReleaseError::Timeout
        } else {
            ReleaseError::Transport
        }
    }
}

pub(super) struct ReleaseHttp {
    client: Client,
    max_redirects: usize,
    read_token: Option<Zeroizing<String>>,
    #[cfg(test)]
    fixture_origin: Option<Url>,
}

impl ReleaseHttp {
    pub(super) fn official(max_redirects: usize) -> Result<Self, ReleaseError> {
        let client = client_builder()
            .dns_resolver(Arc::new(PublicDns))
            .build()
            .map_err(|_| ReleaseError::Transport)?;
        Ok(Self {
            client,
            max_redirects,
            read_token: None,
            #[cfg(test)]
            fixture_origin: None,
        })
    }

    #[cfg(test)]
    pub(super) fn for_fixture(
        origin: &str,
        ca: &[u8],
        max_redirects: usize,
    ) -> Result<Self, ReleaseError> {
        let origin = Url::parse(origin).map_err(|_| ReleaseError::InvalidOptions)?;
        if origin.scheme() != "https" || origin.host_str() != Some("localhost") {
            return Err(ReleaseError::InvalidOptions);
        }
        let ca = reqwest::Certificate::from_pem(ca).map_err(|_| ReleaseError::InvalidOptions)?;
        let client = client_builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .build()
            .map_err(|_| ReleaseError::Transport)?;
        Ok(Self {
            client,
            max_redirects,
            read_token: None,
            fixture_origin: Some(origin),
        })
    }

    pub(super) fn with_read_token(
        mut self,
        token: Zeroizing<String>,
    ) -> Result<Self, ReleaseError> {
        if !(1..=512).contains(&token.len())
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte))
        {
            return Err(ReleaseError::InvalidOptions);
        }
        self.read_token = Some(token);
        Ok(self)
    }

    pub(super) fn json<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        deadline: Deadline,
    ) -> Result<(T, HeaderMap), ReleaseError> {
        let mut response = self.send(api_url(endpoint), false, deadline)?;
        if response
            .content_length()
            .is_some_and(|n| n > MAX_JSON_BYTES)
        {
            return Err(ReleaseError::InvalidResponse);
        }
        let headers = response.headers().clone();
        let mut bytes = Vec::new();
        let mut limited = (&mut response).take(MAX_JSON_BYTES + 1);
        limited
            .read_to_end(&mut bytes)
            .map_err(|error| read_failure(error, deadline))?;
        deadline.remaining()?;
        if bytes.len() as u64 > MAX_JSON_BYTES {
            return Err(ReleaseError::InvalidResponse);
        }
        let parsed = serde_json::from_slice(&bytes).map_err(|_| ReleaseError::InvalidResponse)?;
        deadline.remaining()?;
        Ok((parsed, headers))
    }

    pub(super) fn copy_asset(
        &self,
        asset: &ManifestArtifact,
        deadline: Deadline,
        output: &mut dyn Write,
    ) -> Result<(), ReleaseError> {
        let mut response = self.send(
            api_url(&format!("/releases/assets/{}", asset.id.get())),
            true,
            deadline,
        )?;
        if response.content_length().is_some_and(|n| n != asset.length) {
            return Err(ReleaseError::AssetMismatch);
        }

        let mut hash = Context::new(&SHA256);
        let mut bytes = [0; 32 * 1024];
        let mut total = 0;
        loop {
            deadline.remaining()?;
            let capacity = bytes.len().min((asset.length - total + 1) as usize);
            let count = response
                .read(&mut bytes[..capacity])
                .map_err(|error| read_failure(error, deadline))?;
            deadline.remaining()?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > asset.length {
                return Err(ReleaseError::AssetMismatch);
            }
            let chunk = &bytes[..count];
            hash.update(chunk);
            output
                .write_all(chunk)
                .map_err(|_| ReleaseError::WriteFailed)?;
        }
        let digest = hash.finish();
        let digest_matches = digest.as_ref().iter().enumerate().all(|(index, byte)| {
            let hex = b"0123456789abcdef";
            asset.sha256.as_bytes()[index * 2] == hex[usize::from(byte >> 4)]
                && asset.sha256.as_bytes()[index * 2 + 1] == hex[usize::from(byte & 15)]
        });
        if total != asset.length || !digest_matches {
            return Err(ReleaseError::AssetMismatch);
        }
        deadline.remaining()?;
        Ok(())
    }

    fn send(
        &self,
        mut url: Url,
        asset: bool,
        deadline: Deadline,
    ) -> Result<Response, ReleaseError> {
        for hop in 0..=self.max_redirects {
            let mut request = self
                .client
                .get(self.request_url(&url))
                .header(CACHE_CONTROL, "no-cache")
                .header("Accept-Encoding", "identity");
            if is_api_url(&url) {
                request = request.header("X-GitHub-Api-Version", API_VERSION);
                let repo_path = format!("/repos/{OFFICIAL_OWNER}/{OFFICIAL_REPO}/");
                if hop == 0
                    && url.path().starts_with(&repo_path)
                    && let Some(token) = &self.read_token
                {
                    let bearer = Zeroizing::new(format!("Bearer {}", token.as_str()));
                    let mut value =
                        HeaderValue::from_str(&bearer).map_err(|_| ReleaseError::InvalidOptions)?;
                    value.set_sensitive(true);
                    request = request.header(AUTHORIZATION, value);
                }
            }
            let accept = if asset {
                "application/octet-stream"
            } else {
                "application/vnd.github+json"
            };
            let response = request
                .header("Accept", accept)
                .timeout(deadline.remaining()?)
                .send()
                .map_err(|error| deadline.transport_failure(error.is_timeout()))?;
            deadline.remaining()?;
            let headers = response.headers();
            let header_bytes: usize = headers
                .iter()
                .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
                .sum();
            if header_bytes > MAX_HEADER_BYTES {
                return Err(ReleaseError::InvalidResponse);
            }

            let status = response.status();
            if status.is_redirection() {
                if !asset
                    || hop == self.max_redirects
                    || !matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
                {
                    return Err(ReleaseError::InvalidRedirect);
                }
                let mut locations = headers.get_all(LOCATION).iter();
                let location = locations
                    .next()
                    .and_then(|value| value.to_str().ok())
                    .ok_or(ReleaseError::InvalidRedirect)?;
                let next = url
                    .join(location)
                    .map_err(|_| ReleaseError::InvalidRedirect)?;
                if locations.next().is_some() || !is_download_url(&next) {
                    return Err(ReleaseError::InvalidRedirect);
                }
                url = next;
                continue;
            }
            if status != StatusCode::OK {
                return Err(status_error(status, headers));
            }
            if headers
                .get_all(CONTENT_ENCODING)
                .iter()
                .any(|value| value != "identity")
            {
                return Err(ReleaseError::InvalidResponse);
            }
            return Ok(response);
        }
        Err(ReleaseError::InvalidRedirect)
    }

    fn request_url(&self, canonical: &Url) -> Url {
        #[cfg(test)]
        if let Some(origin) = &self.fixture_origin {
            let mut url = origin.clone();
            url.set_path(canonical.path());
            url.set_query(canonical.query());
            return url;
        }
        canonical.clone()
    }
}

pub(super) fn api_url(endpoint: &str) -> Url {
    Url::parse(&format!(
        "https://{API_HOST}/repos/{OFFICIAL_OWNER}/{OFFICIAL_REPO}{endpoint}"
    ))
    .expect("static GitHub API origin and validated endpoint")
}

fn clean_https(url: &Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

pub(super) fn is_api_url(url: &Url) -> bool {
    clean_https(url) && url.host_str() == Some(API_HOST)
}

fn is_download_url(url: &Url) -> bool {
    clean_https(url)
        && match url.host_str() {
            Some("release-assets.githubusercontent.com" | "objects.githubusercontent.com") => true,
            Some("github.com") => url.path().starts_with(&format!(
                "/{OFFICIAL_OWNER}/{OFFICIAL_REPO}/releases/download/"
            )),
            _ => false,
        }
}

fn client_builder() -> ClientBuilder {
    Client::builder()
        .https_only(true)
        .http1_only()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .retry(reqwest::retry::never())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .timeout(None)
        .user_agent(USER_AGENT)
}

fn status_error(status: StatusCode, headers: &HeaderMap) -> ReleaseError {
    match status {
        StatusCode::NOT_FOUND => ReleaseError::NotFound,
        StatusCode::TOO_MANY_REQUESTS => ReleaseError::RateLimited,
        StatusCode::FORBIDDEN
            if headers.contains_key(RETRY_AFTER)
                || headers
                    .get("x-ratelimit-remaining")
                    .is_some_and(|n| n == "0") =>
        {
            ReleaseError::RateLimited
        }
        _ => ReleaseError::Unavailable,
    }
}

fn read_failure(error: io::Error, deadline: Deadline) -> ReleaseError {
    let timeout = error.kind() == io::ErrorKind::TimedOut
        || error
            .get_ref()
            .and_then(|source| source.downcast_ref::<reqwest::Error>())
            .is_some_and(reqwest::Error::is_timeout);
    deadline.transport_failure(timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::{github::ReleaseReadOptions, github_tests::Fixture, manifest::AssetId};
    use ring::digest::digest;

    #[test]
    fn read_token_is_used_only_on_initial_exact_api_request() {
        let fixture = Fixture::new("authenticated-redirect");
        let http = fixture
            .client(ReleaseReadOptions {
                max_redirects: 1,
                ..ReleaseReadOptions::default()
            })
            .http
            .with_read_token(Zeroizing::new("fixture-read-token".into()))
            .unwrap();
        let payload = b"nodomi arm64 release fixture\n";
        let expected = ManifestArtifact {
            id: AssetId::new(456).unwrap(),
            name: "nodomi-agent-0.1.0-linux-aarch64.tar.gz".into(),
            length: payload.len() as u64,
            sha256: digest(&SHA256, payload)
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        };
        let mut received = Vec::new();
        http.copy_asset(
            &expected,
            Deadline::new(Duration::from_secs(2)),
            &mut received,
        )
        .unwrap();
        assert_eq!(received, payload);
        assert_eq!(
            fixture.requests(),
            [
                serde_json::json!({
                    "method": "GET",
                    "path": "/repos/DashunLiu/Nodomio/releases/assets/456",
                    "credentials": ["authorization"],
                }),
                serde_json::json!({
                    "method": "GET",
                    "path": "/fixture/redirect/package?signature=fixture",
                    "credentials": [],
                }),
            ]
        );
    }

    #[test]
    fn read_token_rejects_empty_overlong_and_unsafe_header_bytes() {
        for token in ["".into(), "a".repeat(513), "fixture\r\nHost: other".into()] {
            assert!(matches!(
                ReleaseHttp::official(1)
                    .unwrap()
                    .with_read_token(Zeroizing::new(token)),
                Err(ReleaseError::InvalidOptions)
            ));
        }
    }
}
