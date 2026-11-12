//! One bounded HTTPS attempt per operation. No redirect, proxy, insecure TLS or token diagnostics.
use crate::{
    identity::{Binding, Enrollment, IdentityStore, Result, Status, Target, uuid},
    protocol::{self, *},
};
use reqwest::{
    Method,
    blocking::{Body, Client, ClientBuilder, Response},
    header::{
        AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, HeaderValue, RETRY_AFTER,
    },
};
use std::{
    io::{Cursor, Read},
    sync::Mutex,
    time::Duration,
};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "client_metric_upload_tests.rs"]
mod metric_upload_tests;
#[cfg(test)]
#[path = "client_registration_tests.rs"]
mod registration_tests;

#[cfg(test)]
#[path = "client_security_upload_tests.rs"]
mod security_upload_tests;

const SECURITY_EVENT_BATCH_PATH: &str = "/api/agent/v1/security-event-batches";
const METRIC_BATCH_PATH: &str = "/api/agent/v1/metric-batches";
pub const MAX_SECURITY_EVENT_REQUEST: usize = 1_048_576;
pub const MAX_SECURITY_EVENT_COUNT: usize = 1_000;

#[derive(Default)]
struct Session {
    epoch: Option<String>,
    heartbeat_confirmed: bool,
    configuration: Option<AgentConfiguration>,
    receipt: Option<(u64, Vec<u8>)>,
}
pub struct ProtocolClient {
    target: Target,
    transport: Transport,
    session: Mutex<Session>,
}

/// A local failure that can be reported after a safe configuration apply attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationFailure {
    ResourceLimit,
    LocalStorageError,
}

impl ConfigurationFailure {
    pub fn from_apply_error(code: &str) -> Option<Self> {
        match code {
            "RESOURCE_LIMIT" => Some(Self::ResourceLimit),
            "LOCAL_STORAGE_ERROR" => Some(Self::LocalStorageError),
            _ => None,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::LocalStorageError => "LOCAL_STORAGE_ERROR",
        }
    }
}

#[derive(Clone)]
struct Transport {
    http: Client,
    timeout: Duration,
}

impl Transport {
    fn request(
        &self,
        origin: &str,
        method: Method,
        path: &'static str,
        secret: &str,
        payload: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Response> {
        let mut request = self
            .http
            .request(method, format!("{origin}{path}"))
            // Request-level timeout reaches the asynchronous body deadline;
            // blocking ClientBuilder timeout alone restarts its wait per read.
            .timeout(self.timeout)
            .header(AUTHORIZATION, bearer_header(secret)?)
            .header(CACHE_CONTROL, "no-store")
            .header("Accept", "application/json, application/problem+json");
        if let Some(bytes) = payload {
            let request_limit = match path {
                METRIC_BATCH_PATH => crate::runtime::MAX_METRIC_REQUEST,
                SECURITY_EVENT_BATCH_PATH => MAX_SECURITY_EVENT_REQUEST,
                _ => MAX_BODY,
            };
            if bytes.len() > request_limit {
                return Err("REQUEST_TOO_LARGE");
            }
            let len = bytes.len() as u64;
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(Body::sized(Cursor::new(bytes), len));
        }
        request.send().map_err(|_| "NETWORK_OR_TLS_ERROR")
    }
}

fn bearer_header(secret: &str) -> Result<HeaderValue> {
    let bearer = Zeroizing::new(format!("Bearer {secret}"));
    let mut header = HeaderValue::from_str(&bearer).map_err(|_| "INVALID_CREDENTIAL")?;
    header.set_sensitive(true);
    Ok(header)
}

enum ResponseBody {
    Success(Vec<u8>),
    Problem { code: String, is_object: bool },
}

fn validate_response(response: Response, success: u16) -> Result<ResponseBody> {
    let status = response.status().as_u16();
    // Reject authority independently of an error document's shape; never use or log its bytes.
    if status == 401 || status == 403 {
        return Err("CREDENTIAL_REJECTED");
    }
    let header_bytes = response
        .headers()
        .iter()
        .try_fold(0usize, |n, (k, v)| {
            n.checked_add(k.as_str().len() + v.as_bytes().len())
        })
        .ok_or("RESPONSE_HEADERS_TOO_LARGE")?;
    if header_bytes > 16 * 1024 {
        return Err("RESPONSE_HEADERS_TOO_LARGE");
    }
    if (300..400).contains(&status) {
        return Err("REDIRECT_REFUSED");
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_BODY as u64)
    {
        return Err("RESPONSE_TOO_LARGE");
    }
    if response.headers().get(CONTENT_ENCODING).is_some() {
        return Err("INVALID_PROTOCOL");
    }
    let mime = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .unwrap_or("");
    if response.headers().get_all(CONTENT_TYPE).iter().count() != 1
        || mime
            != if status == success {
                "application/json"
            } else {
                "application/problem+json"
            }
    {
        if status == 204 && status == success {
        } else {
            return Err("INVALID_PROTOCOL");
        }
    }
    let mut bytes = Vec::new();
    response
        .take((MAX_BODY + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "NETWORK_OR_TLS_ERROR")?;
    if bytes.len() > MAX_BODY {
        return Err("RESPONSE_TOO_LARGE");
    }
    if status == success {
        if status == 204 && !bytes.is_empty() {
            return Err("INVALID_PROTOCOL");
        }
        return Ok(ResponseBody::Success(bytes));
    }
    if !(400..=599).contains(&status) {
        return Err("INVALID_PROTOCOL");
    }
    let problem = protocol::Problem::decode(&bytes, status)?;
    Ok(ResponseBody::Problem {
        code: problem.code,
        is_object: bytes.trim_ascii_start().first() == Some(&b'{'),
    })
}

struct UploadAuthority {
    target: Target,
    binding: Binding,
    operation_id: String,
}

/// One upload authorized by the current identity owner. The data worker gets
/// a credential snapshot and no access to the mutable identity store.
pub struct MetricUpload {
    authority: UploadAuthority,
    transport: Transport,
    credential: Zeroizing<String>,
    body: Zeroizing<Vec<u8>>,
}

pub struct MetricUploadCompletion {
    authority: UploadAuthority,
    outcome: MetricUploadOutcome,
}

pub enum MetricUploadOutcome {
    Acknowledged(IngestionResult),
    Failed {
        code: &'static str,
        retry_after: Option<Duration>,
        terminal: bool,
    },
}

pub struct SecurityEventUpload {
    authority: UploadAuthority,
    transport: Transport,
    credential: Zeroizing<String>,
    body: Zeroizing<Vec<u8>>,
    expected_count: usize,
}

pub struct SecurityEventUploadCompletion {
    authority: UploadAuthority,
    outcome: SecurityEventUploadOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityEventRejection {
    TooLarge,
    Invalid,
    Conflict,
}

pub enum SecurityEventUploadOutcome {
    Acknowledged(IngestionResult),
    Failed {
        code: &'static str,
        retry_after: Option<Duration>,
        terminal: bool,
        rejection: Option<SecurityEventRejection>,
    },
}

fn retry_after(response: &Response) -> Option<Duration> {
    if !matches!(response.status().as_u16(), 429 | 503) {
        return None;
    }
    let mut headers = response.headers().get_all(RETRY_AFTER).iter();
    let value = headers.next()?.to_str().ok()?.trim_ascii();
    if headers.next().is_some()
        || value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    // A decimal value too large to represent still forbids a short retry.
    // The owner can reject the unrepresentable monotonic deadline.
    Some(
        value
            .parse::<u64>()
            .map_or(Duration::MAX, Duration::from_secs),
    )
}

fn metric_ack(bytes: &[u8]) -> Result<IngestionResult> {
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return Err("INVALID_METRIC_ACK");
    }
    let ack = IngestionResult::decode(bytes)?;
    if ack
        .accepted_count
        .checked_add(ack.duplicate_count)
        .and_then(|n| n.checked_add(ack.expired_count))
        != Some(1)
    {
        return Err("INVALID_METRIC_ACK");
    }
    Ok(ack)
}

fn metric_outcome(response: Result<Response>) -> MetricUploadOutcome {
    let response = match response {
        Ok(response) => response,
        Err(code) => {
            return MetricUploadOutcome::Failed {
                code,
                retry_after: None,
                terminal: false,
            };
        }
    };
    let status = response.status().as_u16();
    let retry_after = retry_after(&response);
    let code = match validate_response(response, 200) {
        Ok(ResponseBody::Success(bytes)) => match metric_ack(&bytes) {
            Ok(ack) => return MetricUploadOutcome::Acknowledged(ack),
            Err(code) => code,
        },
        // The fixed metric endpoint has no resource selector other than the
        // authenticated binding. The router's NOT_FOUND is a different fact.
        Ok(ResponseBody::Problem { code, is_object })
            if status == 404 && is_object && code == "RESOURCE_NOT_FOUND" =>
        {
            "CREDENTIAL_REJECTED"
        }
        Ok(ResponseBody::Problem { .. }) => "REMOTE_REQUEST_REJECTED",
        Err(code) => code,
    };
    MetricUploadOutcome::Failed {
        code,
        retry_after,
        terminal: code == "CREDENTIAL_REJECTED" || matches!(status, 400 | 409 | 413 | 422),
    }
}

impl MetricUpload {
    /// Execute exactly one request. Only the identity owner applies the result.
    pub fn send(self) -> MetricUploadCompletion {
        let response = self.transport.request(
            &self.authority.target.origin,
            Method::POST,
            METRIC_BATCH_PATH,
            &self.credential,
            Some(self.body),
        );
        MetricUploadCompletion {
            authority: self.authority,
            outcome: metric_outcome(response),
        }
    }
}

fn security_event_ack(bytes: &[u8], expected_count: usize) -> Result<IngestionResult> {
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return Err("INVALID_SECURITY_EVENT_ACK");
    }
    let result = IngestionResult::decode(bytes).map_err(|_| "INVALID_SECURITY_EVENT_ACK")?;
    if result
        .accepted_count
        .checked_add(result.duplicate_count)
        .and_then(|n| n.checked_add(result.expired_count))
        != Some(expected_count as u64)
    {
        return Err("INVALID_SECURITY_EVENT_ACK");
    }
    Ok(result)
}

fn security_event_outcome(
    response: Result<Response>,
    expected_count: usize,
) -> SecurityEventUploadOutcome {
    let response = match response {
        Ok(response) => response,
        Err(code) => {
            return SecurityEventUploadOutcome::Failed {
                code,
                retry_after: None,
                terminal: false,
                rejection: None,
            };
        }
    };
    let status = response.status().as_u16();
    let retry_after = retry_after(&response);
    let (code, rejection) = match validate_response(response, 200) {
        Ok(ResponseBody::Success(bytes)) => match security_event_ack(&bytes, expected_count) {
            Ok(ack) => return SecurityEventUploadOutcome::Acknowledged(ack),
            Err(code) => (code, None),
        },
        Ok(ResponseBody::Problem {
            code,
            is_object: true,
        }) => match (status, code.as_str()) {
            // Other 400 responses can describe authentication or request metadata.
            // A record may be isolated only on a known rejection from this endpoint.
            (400, "JSON_INVALID") | (422, "INPUT_INVALID") => (
                "REMOTE_REQUEST_REJECTED",
                Some(SecurityEventRejection::Invalid),
            ),
            (413, "BODY_TOO_LARGE") => (
                "REMOTE_REQUEST_REJECTED",
                Some(SecurityEventRejection::TooLarge),
            ),
            (409, "SECURITY_EVENT_CONFLICT") => (
                "REMOTE_REQUEST_REJECTED",
                Some(SecurityEventRejection::Conflict),
            ),
            (404, "RESOURCE_NOT_FOUND") => ("CREDENTIAL_REJECTED", None),
            _ => ("REMOTE_REQUEST_REJECTED", None),
        },
        Ok(ResponseBody::Problem { .. }) => ("REMOTE_REQUEST_REJECTED", None),
        Err(code) => (code, None),
    };
    SecurityEventUploadOutcome::Failed {
        code,
        retry_after,
        terminal: code == "CREDENTIAL_REJECTED",
        rejection,
    }
}

impl SecurityEventUpload {
    /// Execute one immutable request. The owner classifies its queue effect.
    pub fn send(self) -> SecurityEventUploadCompletion {
        let response = self.transport.request(
            &self.authority.target.origin,
            Method::POST,
            SECURITY_EVENT_BATCH_PATH,
            &self.credential,
            Some(self.body),
        );
        SecurityEventUploadCompletion {
            authority: self.authority,
            outcome: security_event_outcome(response, self.expected_count),
        }
    }
}

impl ProtocolClient {
    pub fn new(target: Target, explicit_ca: Option<&[u8]>, timeout: Duration) -> Result<Self> {
        let builder = Self::http_builder(&target, explicit_ca, timeout)?;
        Self::build(target, timeout, builder)
    }

    /// The foreground service must be able to drain and drop its client even
    /// if an underlying system DNS lookup has not yet finished.
    #[cfg(target_os = "linux")]
    pub fn new_for_service(
        target: Target,
        explicit_ca: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Self> {
        let builder = Self::bounded_dns_builder(&target, explicit_ca, timeout)?;
        Self::build(target, timeout, builder)
    }

    fn build(target: Target, timeout: Duration, builder: ClientBuilder) -> Result<Self> {
        let http = builder
            .build()
            .map_err(|_| "CLIENT_INITIALIZATION_FAILED")?;
        Ok(Self {
            target,
            transport: Transport { http, timeout },
            session: Mutex::new(Session::default()),
        })
    }

    fn http_builder(
        target: &Target,
        explicit_ca: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<ClientBuilder> {
        if Target::new(&target.origin, &target.expected_server_id)? != *target
            || timeout < Duration::from_millis(50)
            || timeout > Duration::from_secs(30)
        {
            return Err("INVALID_CLIENT_OPTIONS");
        }
        let mut builder = Client::builder()
            .https_only(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(5)))
            .pool_max_idle_per_host(0);
        if let Some(pem) = explicit_ca {
            if pem.len() > 65536 {
                return Err("INVALID_CA");
            }
            let certificates =
                reqwest::Certificate::from_pem_bundle(pem).map_err(|_| "INVALID_CA")?;
            if certificates.is_empty() {
                return Err("INVALID_CA");
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        Ok(builder)
    }

    #[cfg(target_os = "linux")]
    fn bounded_dns_builder(
        target: &Target,
        explicit_ca: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<ClientBuilder> {
        Ok(Self::http_builder(target, explicit_ca, timeout)?
            .dns_resolver(std::sync::Arc::new(crate::dns::OriginDns)))
    }

    /// A credential-free probe of HTTPS to the exact origin. HTTP status and
    /// response content provide no proof of registration or target ownership.
    #[cfg(target_os = "linux")]
    pub(crate) fn verify_tls_origin(
        target: &Target,
        explicit_ca: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<bool> {
        let client = Self::bounded_dns_builder(target, explicit_ca, timeout)?
            .build()
            .map_err(|_| "CLIENT_INITIALIZATION_FAILED")?;
        Ok(client
            .head(format!("{}/", target.origin))
            .timeout(timeout)
            .header(CACHE_CONTROL, "no-store")
            .send()
            .is_ok())
    }

    /// Read the enrolled server and deployment with the same trust policy as
    /// registration. A supplied CA bundle augments the built-in root store.
    #[cfg(target_os = "linux")]
    pub(crate) fn read_enrollment_target(
        target: &Target,
        explicit_ca: Option<&[u8]>,
        enrollment: &Enrollment,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let client = Self::bounded_dns_builder(target, explicit_ca, timeout)?
            .build()
            .map_err(|_| "CLIENT_INITIALIZATION_FAILED")?;
        let response = client
            .get(format!("{}/api/agent/v1/enrollment-target", target.origin))
            .query(&[("expectedServerId", &target.expected_server_id)])
            .timeout(timeout)
            .header(AUTHORIZATION, bearer_header(enrollment.secret())?)
            .header(reqwest::header::ORIGIN, &target.origin)
            .header(CACHE_CONTROL, "no-store")
            .header("Accept", "application/json, application/problem+json")
            .send()
            .map_err(|_| "NETWORK_OR_TLS_ERROR")?;
        let status = response.status().as_u16();
        match validate_response(response, 200)? {
            ResponseBody::Success(bytes) => Ok(bytes),
            ResponseBody::Problem {
                code,
                is_object: true,
            } if status == 422 && code == "TARGET_MISMATCH" => Err("TARGET_MISMATCH"),
            ResponseBody::Problem { .. } if status == 429 => Err("RATE_LIMITED"),
            ResponseBody::Problem { .. } => Err("REMOTE_REQUEST_REJECTED"),
        }
    }

    fn checked<'a>(&self, state: &'a IdentityStore, bound: bool) -> Result<&'a str> {
        if state.target() != &self.target {
            return Err("IDENTITY_MISMATCH");
        }
        if state.status() == Status::NeedsReconnect {
            return Err("NEEDS_RECONNECT");
        }
        if bound && state.status() != Status::Bound {
            return Err("IDENTITY_NOT_CONFIRMED");
        }
        state.credential()
    }
    fn send(
        &self,
        method: Method,
        path: &'static str,
        secret: &str,
        payload: Option<Zeroizing<Vec<u8>>>,
        success: u16,
    ) -> Result<Vec<u8>> {
        let response =
            self.transport
                .request(&self.target.origin, method, path, secret, payload)?;
        match validate_response(response, success)? {
            ResponseBody::Success(bytes) => Ok(bytes),
            ResponseBody::Problem { .. } => Err("REMOTE_REQUEST_REJECTED"),
        }
    }
    fn authenticated(
        &self,
        state: &mut IdentityStore,
        method: Method,
        path: &'static str,
        payload: Option<Zeroizing<Vec<u8>>>,
        success: u16,
    ) -> Result<Vec<u8>> {
        let result = self.send(method, path, self.checked(state, true)?, payload, success);
        if result.as_ref().is_err_and(|e| *e == "CREDENTIAL_REJECTED") {
            state.rejected()?;
        }
        result
    }
    pub fn register(
        &self,
        state: &mut IdentityStore,
        enrollment: &Enrollment,
        metadata: &RegistrationMetadata,
    ) -> Result<AgentIdentity> {
        self.register_inner(state, enrollment, metadata, None)
    }

    /// Bind this registration attempt to the deployment observed during the
    /// enrollment-target proof. The backend compares it before its writes.
    pub fn register_for_deployment(
        &self,
        state: &mut IdentityStore,
        enrollment: &Enrollment,
        metadata: &RegistrationMetadata,
        expected_deployment_id: &str,
    ) -> Result<AgentIdentity> {
        if !protocol::canonical_deployment_id(expected_deployment_id) {
            return Err("INVALID_DEPLOYMENT_ID");
        }
        self.register_inner(state, enrollment, metadata, Some(expected_deployment_id))
    }

    fn register_inner(
        &self,
        state: &mut IdentityStore,
        enrollment: &Enrollment,
        metadata: &RegistrationMetadata,
        expected_deployment_id: Option<&str>,
    ) -> Result<AgentIdentity> {
        self.checked(state, false)?;
        metadata.validate()?;
        if state.status() != Status::Prepared {
            return Err("REGISTRATION_ALREADY_ATTEMPTED");
        }
        let payload = Zeroizing::new(
            serde_json::to_vec(&protocol::Registration {
                agent_credential: state.credential()?,
                metadata,
                expected_server_id: &self.target.expected_server_id,
                expected_deployment_id,
            })
            .map_err(|_| "INVALID_PROTOCOL")?,
        );
        state.uncertain()?; // File AND parent fsync finish before the first possible HTTP write.
        let bytes = self.send(
            Method::POST,
            "/api/agent/v1/registrations",
            enrollment.secret(),
            Some(payload),
            201,
        )?;
        let identity = AgentIdentity::decode(&bytes)?;
        state.confirm(identity.binding())?;
        Ok(identity)
    }
    pub fn query_identity(&self, state: &mut IdentityStore) -> Result<AgentIdentity> {
        let result = self.send(
            Method::GET,
            "/api/agent/v1/identity",
            self.checked(state, false)?,
            None,
            200,
        );
        if result.as_ref().is_err_and(|e| *e == "CREDENTIAL_REJECTED") {
            state.rejected()?;
        }
        let identity = AgentIdentity::decode(&result?)?;
        state.confirm(identity.binding())?;
        Ok(identity)
    }
    pub fn configuration(&self, state: &mut IdentityStore) -> Result<AgentConfiguration> {
        let bytes =
            self.authenticated(state, Method::GET, "/api/agent/v1/configuration", None, 200)?;
        let config = AgentConfiguration::decode(&bytes)?;
        let binding = state.binding().ok_or("IDENTITY_NOT_CONFIRMED")?;
        if config.agent_id != binding.agent_id
            || config.binding_revision != binding.binding_revision
        {
            return Err("CONFIGURATION_BINDING_MISMATCH");
        }
        let mut session = self
            .session
            .lock()
            .map_err(|_| "SESSION_RECOVERY_REQUIRED")?;
        if session.configuration.as_ref().is_some_and(|previous| {
            config.target.generation < previous.target.generation
                || (config.target.generation == previous.target.generation && config != *previous)
        }) {
            return Err("CONFIGURATION_REGRESSION");
        }
        session.configuration = Some(config.clone());
        Ok(config)
    }
    pub fn heartbeat(
        &self,
        state: &mut IdentityStore,
        heartbeat: &Heartbeat,
    ) -> Result<HeartbeatAck> {
        heartbeat.validate()?;
        let mut session = self
            .session
            .lock()
            .map_err(|_| "SESSION_RECOVERY_REQUIRED")?;
        if session
            .epoch
            .as_ref()
            .is_some_and(|epoch| epoch != &heartbeat.collector_epoch)
        {
            return Err("COLLECTOR_EPOCH_CHANGED");
        }
        // Lock this process epoch before a request whose response may be lost.
        session.epoch = Some(heartbeat.collector_epoch.clone());
        let payload =
            Zeroizing::new(serde_json::to_vec(heartbeat).map_err(|_| "INVALID_PROTOCOL")?);
        let ack = HeartbeatAck::decode(&self.authenticated(
            state,
            Method::POST,
            "/api/agent/v1/heartbeats",
            Some(payload),
            200,
        )?)?;
        session.heartbeat_confirmed = true;
        Ok(ack)
    }
    /// This slice has no applied configuration. Report a fetched target as unsupported,
    /// only after a live heartbeat confirmed this process epoch. Never emit APPLIED.
    pub fn report_unsupported_configuration(
        &self,
        state: &mut IdentityStore,
        config: &AgentConfiguration,
        epoch: &str,
        sequence: u64,
    ) -> Result<()> {
        if !uuid(epoch) || !(1..=9_007_199_254_740_991).contains(&sequence) {
            return Err("INVALID_RECEIPT");
        }
        let mut session = self
            .session
            .lock()
            .map_err(|_| "SESSION_RECOVERY_REQUIRED")?;
        if !session.heartbeat_confirmed
            || session.epoch.as_deref() != Some(epoch)
            || session.configuration.as_ref() != Some(config)
        {
            return Err("UNKNOWN_CONFIGURATION_OR_EPOCH");
        }
        let payload = serde_json::to_vec(&protocol::UnsupportedReceipt {
            config_id: &config.target.config_id,
            generation: config.target.generation,
            binding_revision: config.binding_revision,
            collector_epoch: epoch,
            sequence,
            result: "FAILED",
            applied_config_id: None,
            error_code: "UNSUPPORTED_CONFIGURATION",
        })
        .map_err(|_| "INVALID_PROTOCOL")?;
        if session.receipt.as_ref().is_some_and(|(last, bytes)| {
            sequence < *last || (sequence == *last && bytes != &payload)
        }) {
            return Err("RECEIPT_SEQUENCE_CONFLICT");
        }
        session.receipt = Some((sequence, payload.clone()));
        self.authenticated(
            state,
            Method::PUT,
            "/api/agent/v1/configuration-receipts",
            Some(Zeroizing::new(payload)),
            204,
        )?;
        Ok(())
    }
    /// Only a runtime with an activated durable complete target may call this.
    pub fn report_applied_configuration(
        &self,
        state: &mut IdentityStore,
        config: &AgentConfiguration,
        epoch: &str,
        sequence: u64,
    ) -> Result<()> {
        self.submit_applied_configuration(state, config, epoch, sequence, false)
    }

    /// Reassert a retained effective configuration after the manager's
    /// projection was reset or its earlier APPLIED acknowledgement was lost.
    /// The active runtime must agree with the manifest for this exact identity.
    pub fn report_retained_configuration(
        &self,
        state: &mut IdentityStore,
        runtime: &crate::runtime::RuntimeStore,
        runtime_path: &std::path::Path,
        epoch: &str,
        sequence: u64,
    ) -> Result<()> {
        let active = runtime
            .configuration()
            .filter(|_| runtime.safely_reportable())
            .ok_or("CONFIGURATION_NOT_APPLIED")?;
        let committed = crate::runtime::RuntimeStore::persisted_configuration(runtime_path, state)?;
        if committed.as_ref() != Some(active) {
            return Err("RUNTIME_CONFIGURATION_CHANGED");
        }
        self.submit_applied_configuration(state, active, epoch, sequence, true)
    }

    fn submit_applied_configuration(
        &self,
        state: &mut IdentityStore,
        config: &AgentConfiguration,
        epoch: &str,
        sequence: u64,
        allow_retained: bool,
    ) -> Result<()> {
        if !uuid(epoch) || !(1..=9_007_199_254_740_991).contains(&sequence) {
            return Err("INVALID_RECEIPT");
        }
        let mut session = self
            .session
            .lock()
            .map_err(|_| "SESSION_RECOVERY_REQUIRED")?;
        if !session.heartbeat_confirmed
            || session.epoch.as_deref() != Some(epoch)
            || session.configuration.as_ref().is_none_or(|desired| {
                desired != config
                    && !(allow_retained
                        && desired.agent_id == config.agent_id
                        && desired.binding_revision == config.binding_revision
                        && desired.target.generation > config.target.generation)
            })
        {
            return Err("UNKNOWN_CONFIGURATION_OR_EPOCH");
        }
        let payload=serde_json::to_vec(&serde_json::json!({"configId":config.target.config_id,"generation":config.target.generation,"bindingRevision":config.binding_revision,"collectorEpoch":epoch,"sequence":sequence,"result":"APPLIED","appliedConfigId":config.target.config_id,"errorCode":null})).map_err(|_|"INVALID_PROTOCOL")?;
        if session.receipt.as_ref().is_some_and(|(last, bytes)| {
            sequence < *last || (sequence == *last && bytes != &payload)
        }) {
            return Err("RECEIPT_SEQUENCE_CONFLICT");
        }
        session.receipt = Some((sequence, payload.clone()));
        self.authenticated(
            state,
            Method::PUT,
            "/api/agent/v1/configuration-receipts",
            Some(Zeroizing::new(payload)),
            204,
        )?;
        Ok(())
    }
    /// Snapshot the authority and serialize one immutable HOST sample for the data worker.
    pub fn prepare_metric_upload(
        &self,
        state: &IdentityStore,
        sample: &crate::runtime::StoredSample,
    ) -> Result<MetricUpload> {
        let credential = self.checked(state, true)?;
        let binding = state.binding().ok_or("IDENTITY_NOT_CONFIRMED")?;
        let body = crate::runtime::metric_body(sample)?;
        Ok(MetricUpload {
            authority: UploadAuthority {
                target: self.target.clone(),
                binding: binding.clone(),
                operation_id: state.operation_id().to_owned(),
            },
            transport: self.transport.clone(),
            credential: Zeroizing::new(credential.to_owned()),
            body: Zeroizing::new(body),
        })
    }

    /// Apply a worker response to the identity that authorized its request.
    pub fn finish_metric_upload(
        &self,
        state: &mut IdentityStore,
        completed: MetricUploadCompletion,
    ) -> Result<MetricUploadOutcome> {
        let authority = &completed.authority;
        if authority.target != self.target
            || state.operation_id() != authority.operation_id
            || state.binding() != Some(&authority.binding)
        {
            return Err("IDENTITY_MISMATCH");
        }
        self.checked(state, true)?;
        if matches!(
            &completed.outcome,
            MetricUploadOutcome::Failed {
                code: "CREDENTIAL_REJECTED",
                ..
            }
        ) {
            state.rejected()?;
        }
        Ok(completed.outcome)
    }

    /// Synchronous entry point for a caller that owns both the data and control paths.
    pub fn metrics(
        &self,
        state: &mut IdentityStore,
        sample: &crate::runtime::StoredSample,
    ) -> Result<()> {
        let completed = self.prepare_metric_upload(state, sample)?.send();
        match self.finish_metric_upload(state, completed)? {
            MetricUploadOutcome::Acknowledged(_) => Ok(()),
            MetricUploadOutcome::Failed { code, .. } => Err(code),
        }
    }
    /// Snapshot authority and copy one bounded immutable SSH request.
    pub fn prepare_security_event_upload(
        &self,
        state: &IdentityStore,
        body: &[u8],
        expected_count: usize,
    ) -> Result<SecurityEventUpload> {
        if body.len() > MAX_SECURITY_EVENT_REQUEST {
            return Err("REQUEST_TOO_LARGE");
        }
        if !(1..=MAX_SECURITY_EVENT_COUNT).contains(&expected_count)
            || body.trim_ascii_start().first() != Some(&b'{')
        {
            return Err("INVALID_SECURITY_EVENT_BATCH");
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BatchEnvelope {
            events: Vec<serde::de::IgnoredAny>,
        }
        let envelope: BatchEnvelope =
            serde_json::from_slice(body).map_err(|_| "INVALID_SECURITY_EVENT_BATCH")?;
        if envelope.events.len() != expected_count {
            return Err("INVALID_SECURITY_EVENT_BATCH");
        }
        let credential = self.checked(state, true)?;
        let binding = state.binding().ok_or("IDENTITY_NOT_CONFIRMED")?;
        Ok(SecurityEventUpload {
            authority: UploadAuthority {
                target: self.target.clone(),
                binding: binding.clone(),
                operation_id: state.operation_id().to_owned(),
            },
            transport: self.transport.clone(),
            credential: Zeroizing::new(credential.to_owned()),
            body: Zeroizing::new(body.to_vec()),
            expected_count,
        })
    }

    pub fn finish_security_event_upload(
        &self,
        state: &mut IdentityStore,
        completed: SecurityEventUploadCompletion,
    ) -> Result<SecurityEventUploadOutcome> {
        let authority = &completed.authority;
        if authority.target != self.target
            || state.operation_id() != authority.operation_id
            || state.binding() != Some(&authority.binding)
        {
            return Err("IDENTITY_MISMATCH");
        }
        self.checked(state, true)?;
        if matches!(
            &completed.outcome,
            SecurityEventUploadOutcome::Failed {
                code: "CREDENTIAL_REJECTED",
                ..
            }
        ) {
            state.rejected()?;
        }
        Ok(completed.outcome)
    }

    /// Send one prepared request containing already validated, immutable events.
    pub fn security_events(
        &self,
        state: &mut IdentityStore,
        body: &[u8],
        expected_count: usize,
    ) -> Result<IngestionResult> {
        let completed = self
            .prepare_security_event_upload(state, body, expected_count)?
            .send();
        match self.finish_security_event_upload(state, completed)? {
            SecurityEventUploadOutcome::Acknowledged(ack) => Ok(ack),
            SecurityEventUploadOutcome::Failed { code, .. } => Err(code),
        }
    }
    /// An application failure after safe runtime preflight; actual refers only to an
    /// already activated target in this process, never merely persisted JSON.
    pub fn report_configuration_storage_failure(
        &self,
        state: &mut IdentityStore,
        config: &AgentConfiguration,
        epoch: &str,
        sequence: u64,
        actual: Option<&AgentConfiguration>,
    ) -> Result<()> {
        self.report_configuration_failure(
            state,
            config,
            epoch,
            sequence,
            actual,
            ConfigurationFailure::LocalStorageError,
        )
    }

    /// A failed apply keeps the previously activated target, if any. Call only
    /// when local recovery checks confirm the actual configuration is known.
    pub fn report_configuration_failure(
        &self,
        state: &mut IdentityStore,
        config: &AgentConfiguration,
        epoch: &str,
        sequence: u64,
        actual: Option<&AgentConfiguration>,
        reason: ConfigurationFailure,
    ) -> Result<()> {
        if !uuid(epoch)
            || !(1..=9_007_199_254_740_991).contains(&sequence)
            || actual.is_some_and(|old| {
                old.agent_id != config.agent_id
                    || old.binding_revision != config.binding_revision
                    || old.target.generation > config.target.generation
            })
        {
            return Err("INVALID_RECEIPT");
        }
        let mut session = self
            .session
            .lock()
            .map_err(|_| "SESSION_RECOVERY_REQUIRED")?;
        if !session.heartbeat_confirmed
            || session.epoch.as_deref() != Some(epoch)
            || session.configuration.as_ref() != Some(config)
        {
            return Err("UNKNOWN_CONFIGURATION_OR_EPOCH");
        }
        let payload = serde_json::to_vec(&serde_json::json!({
            "configId": config.target.config_id,
            "generation": config.target.generation,
            "bindingRevision": config.binding_revision,
            "collectorEpoch": epoch,
            "sequence": sequence,
            "result": "FAILED",
            "appliedConfigId": actual.map(|old| old.target.config_id.as_str()),
            "errorCode": reason.code(),
        }))
        .map_err(|_| "INVALID_PROTOCOL")?;
        if session.receipt.as_ref().is_some_and(|(last, bytes)| {
            sequence < *last || (sequence == *last && bytes != &payload)
        }) {
            return Err("RECEIPT_SEQUENCE_CONFLICT");
        }
        session.receipt = Some((sequence, payload.clone()));
        self.authenticated(
            state,
            Method::PUT,
            "/api/agent/v1/configuration-receipts",
            Some(Zeroizing::new(payload)),
            204,
        )?;
        Ok(())
    }
}
