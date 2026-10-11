use super::{
    ClockOwner, CodeTokenStart, InitialBudget, InitialError, InitialParentBudget,
    InitialReplyWitness, OwnedCodeInput, OwnedInitialInput, OwnedInitialKind,
    OwnedRegistrationInput, OwnedTokenBinding, PreparedInitialOwner, SystemClock, check_budget,
    check_parent_budget,
};
use crate::gateway_account::GatewayDesktopMetadata;
use acosmi::{
    HttpClient, HttpPurpose, HttpRequest, HttpResponse, HttpResponseMode, HttpTransport,
    RegisterWebOAuthClientOptions, TransportError,
};
use async_trait::async_trait;
use futures_util::future::poll_fn;
use http::{Method, header::CONTENT_TYPE};
use std::{
    future::{Future, pending},
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

const REQUEST_BODY_LIMIT: usize = 65_536;
const REQUEST_URL_LIMIT: usize = 2_048;
const HTTP_BUDGET: Duration = Duration::from_secs(10);

pub(super) struct CapturedRequest {
    pub(super) request: HttpRequest,
    pub(super) budget: InitialBudget,
    pub(super) sdk_child: CancellationToken,
}

pub(super) struct CaptureState {
    pub(super) executions: usize,
    pub(super) captured: Option<CapturedRequest>,
    pub(super) error: Option<InitialError>,
}

pub(super) struct CaptureTransport {
    pub(super) state: Mutex<CaptureState>,
    clock: ClockOwner,
    parent: InitialParentBudget,
}

impl CaptureTransport {
    pub(super) fn new(clock: ClockOwner, parent: &InitialParentBudget) -> Self {
        Self {
            state: Mutex::new(CaptureState {
                executions: 0,
                captured: None,
                error: None,
            }),
            clock,
            parent: InitialParentBudget {
                original_parent: parent.original_parent.clone(),
                owner_deadline: parent.owner_deadline,
            },
        }
    }
}

#[async_trait]
impl HttpTransport for CaptureTransport {
    async fn execute(
        &self,
        request: HttpRequest,
        cancel: CancellationToken,
    ) -> Result<HttpResponse, TransportError> {
        // This runs on the first poll of execute, rather than when it is constructed.
        let entry = check_parent_budget(&self.parent, &self.clock).and_then(|sample| {
            let ten_seconds = sample
                .mono
                .checked_add(HTTP_BUDGET)
                .ok_or(InitialError::Deadline)?;
            Ok(InitialBudget {
                original_parent: self.parent.original_parent.clone(),
                owner_deadline: self.parent.owner_deadline,
                http_entered_at: sample.mono,
                deadline: self.parent.owner_deadline.min(ten_seconds),
            })
        });
        {
            match self.state.lock() {
                Ok(mut state) => {
                    if state.executions != 0 {
                        state.executions = 2;
                        state.error = Some(InitialError::RequestMismatch);
                        drop(request);
                    } else {
                        state.executions = 1;
                        match entry {
                            Ok(budget) => {
                                state.captured = Some(CapturedRequest {
                                    request,
                                    budget,
                                    sdk_child: cancel,
                                });
                            }
                            Err(error) => {
                                state.error = Some(error);
                                drop(request);
                            }
                        }
                    }
                }
                Err(_) => drop(request),
            }
        }
        // The SDK must never receive a synthetic response or decode these replies.
        pending().await
    }
}

struct RegistrationOptionsOwner {
    options: RegisterWebOAuthClientOptions,
}

impl RegistrationOptionsOwner {
    fn new(redirect: &str) -> Self {
        let mut owner = Self {
            options: RegisterWebOAuthClientOptions {
                client_name: String::new(),
                redirect_uris: vec![String::new()],
                scopes: None,
            },
        };
        owner.options.client_name.push_str("Wrok Bot");
        owner.options.redirect_uris[0].push_str(redirect);
        owner
    }
}

impl Drop for RegistrationOptionsOwner {
    fn drop(&mut self) {
        self.options.client_name.zeroize();
        for redirect in &mut self.options.redirect_uris {
            redirect.zeroize();
        }
        if let Some(scopes) = &mut self.options.scopes {
            for scope in scopes {
                scope.zeroize();
            }
        }
    }
}

pub(super) fn valid_client_id(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && !value.starts_with(' ')
        && !value.ends_with(' ')
        && !value
            .chars()
            .any(|ch| matches!(ch as u32, 0x00..=0x1f | 0x7f..=0x9f))
}

fn valid_redirect(value: &str) -> bool {
    !value.is_empty() && value.len() <= REQUEST_URL_LIMIT && url::Url::parse(value).is_ok()
}

pub(super) fn owned_registration_input(
    metadata: GatewayDesktopMetadata,
    original_redirect_uri: Zeroizing<String>,
) -> Result<OwnedInitialInput, InitialError> {
    if !valid_redirect(&original_redirect_uri) {
        return Err(InitialError::RequestMismatch);
    }
    Ok(OwnedInitialInput {
        kind: OwnedInitialKind::Registration(OwnedRegistrationInput {
            metadata,
            original_redirect_uri,
        }),
        clock: Arc::new(SystemClock),
    })
}

pub(super) fn owned_code_input(
    metadata: GatewayDesktopMetadata,
    client_id: Zeroizing<String>,
    code: Zeroizing<String>,
    original_redirect_uri: Zeroizing<String>,
    code_verifier: Zeroizing<String>,
) -> Result<OwnedInitialInput, InitialError> {
    if !valid_client_id(&client_id)
        || !(1..=16_377).contains(&code.len())
        || !code.bytes().all(|byte| byte.is_ascii_graphic())
        || !valid_redirect(&original_redirect_uri)
        || !(43..=128).contains(&code_verifier.len())
        || !code_verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(InitialError::RequestMismatch);
    }
    let mut server_url = Zeroizing::new(String::new());
    server_url.push_str(metadata.sdk_metadata().issuer.as_str());
    Ok(OwnedInitialInput {
        kind: OwnedInitialKind::Code(OwnedCodeInput {
            metadata,
            client_id,
            code,
            redirect_uri: original_redirect_uri,
            code_verifier,
            server_url,
        }),
        clock: Arc::new(SystemClock),
    })
}

async fn capture_helper<F: Future>(
    mut helper: Pin<Box<F>>,
    transport: &CaptureTransport,
    parent: &InitialParentBudget,
    clock: &ClockOwner,
) -> Result<CapturedRequest, InitialError> {
    let capture = poll_fn(|cx| {
        if let Err(error) = check_parent_budget(parent, clock) {
            return Poll::Ready(Err(error));
        }
        let producer = helper.as_mut().poll(cx);
        let mut state = match transport.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(InitialError::RequestMismatch)),
        };
        if let Some(error) = state.error {
            return Poll::Ready(Err(error));
        }
        if state.executions == 1
            && let Some(captured) = state.captured.take()
        {
            return Poll::Ready(Ok(captured));
        }
        if producer.is_ready() {
            Poll::Ready(Err(InitialError::ProducerEnded))
        } else {
            Poll::Pending
        }
    });
    let result = tokio::select! {
        biased;
        _ = parent.original_parent.cancelled() => Err(InitialError::Cancelled),
        _ = tokio::time::sleep_until(parent.owner_deadline) => {
            if parent.original_parent.is_cancelled() {
                Err(InitialError::Cancelled)
            } else {
                Err(InitialError::Deadline)
            }
        }
        result = capture => result,
    };
    // This drops the owning box and every SDK frame before original inputs move.
    drop(helper);
    let captured = result?;
    check_budget(&captured.budget, clock)?;
    if !captured.sdk_child.is_cancelled() {
        return Err(InitialError::ProducerEnded);
    }
    Ok(captured)
}

pub(super) async fn prepare_initial(
    input: OwnedInitialInput,
    parent: InitialParentBudget,
) -> Result<PreparedInitialOwner, InitialError> {
    let clock = Arc::clone(&input.clock);
    check_parent_budget(&parent, &clock)?;
    let transport = Arc::new(CaptureTransport::new(Arc::clone(&clock), &parent));
    let http =
        HttpClient::new(transport.clone()).with_cancellation(Some(parent.original_parent.clone()));
    let (captured, start) = match &input.kind {
        OwnedInitialKind::Registration(registration) => {
            let options = RegistrationOptionsOwner::new(&registration.original_redirect_uri);
            let helper = Box::pin(acosmi::auth::register_web_oauth_client_with_transport(
                &http,
                registration.metadata.sdk_metadata(),
                &options.options,
            ));
            let captured = capture_helper(helper, &transport, &parent, &clock).await?;
            // The future borrowing options has exited before this guard is wiped.
            drop(options);
            (captured, None)
        }
        OwnedInitialKind::Code(code) => {
            // Both clocks belong to this original owner, sampled before first poll.
            let start = CodeTokenStart {
                original: check_parent_budget(&parent, &clock)?,
            };
            let helper = Box::pin(acosmi::auth::exchange_code_with_transport(
                &http,
                code.metadata.sdk_metadata(),
                &code.client_id,
                &code.code,
                &code.redirect_uri,
                &code.code_verifier,
            ));
            (
                capture_helper(helper, &transport, &parent, &clock).await?,
                Some(start),
            )
        }
    };
    check_budget(&captured.budget, &clock)?;
    validate_request(&captured.request, &input.kind)?;
    let witness = match input.kind {
        OwnedInitialKind::Registration(registration) => InitialReplyWitness::Registration {
            metadata: registration.metadata,
            original_redirect_uri: registration.original_redirect_uri,
        },
        OwnedInitialKind::Code(code) => InitialReplyWitness::Code {
            metadata: code.metadata,
            binding: OwnedTokenBinding {
                client_id: code.client_id,
                server_url: code.server_url,
            },
            start: start.ok_or(InitialError::RequestMismatch)?,
        },
    };
    let CapturedRequest {
        request,
        mut budget,
        sdk_child,
    } = captured;
    // Retain the original parent handle itself; the captured child stays separate.
    budget.original_parent = parent.original_parent;
    check_budget(&budget, &clock)?;
    Ok(PreparedInitialOwner {
        request: Some(request),
        witness: Some(witness),
        budget: Some(budget),
        clock: input.clock,
        sdk_exit_child: sdk_child,
    })
}

pub(super) fn validate_request(
    request: &HttpRequest,
    input: &OwnedInitialKind,
) -> Result<(), InitialError> {
    let (endpoint, purpose, content_type) = match input {
        OwnedInitialKind::Registration(registration) => (
            registration
                .metadata
                .sdk_metadata()
                .registration_endpoint
                .as_str(),
            HttpPurpose::OAuthRegistration,
            "application/json",
        ),
        OwnedInitialKind::Code(code) => (
            code.metadata.sdk_metadata().token_endpoint.as_str(),
            HttpPurpose::OAuthToken,
            "application/x-www-form-urlencoded",
        ),
    };
    if request.method != Method::POST
        || request.url.as_str() != endpoint
        || request.url.as_str().len() > REQUEST_URL_LIMIT
        || request.body.len() > REQUEST_BODY_LIMIT
        || request.context.purpose != purpose
        || request.context.response_mode != HttpResponseMode::Buffered
        || request.context.timeout != Duration::from_secs(30)
        || request.headers.len() != 1
        || request.headers.get_all(CONTENT_TYPE).iter().count() != 1
        || request
            .headers
            .get(CONTENT_TYPE)
            .map(|value| value.as_bytes())
            != Some(content_type.as_bytes())
    {
        return Err(InitialError::RequestMismatch);
    }
    match input {
        OwnedInitialKind::Registration(registration) => {
            validate_registration_json(&request.body, &registration.original_redirect_uri)
        }
        OwnedInitialKind::Code(code) => validate_code_form(&request.body, code),
    }
}

fn validate_code_form(body: &[u8], code: &OwnedCodeInput) -> Result<(), InitialError> {
    let expected: [(&[u8], &[u8]); 5] = [
        (b"grant_type", b"authorization_code"),
        (b"client_id", code.client_id.as_bytes()),
        (b"code", code.code.as_bytes()),
        (b"redirect_uri", code.redirect_uri.as_bytes()),
        (b"code_verifier", code.code_verifier.as_bytes()),
    ];
    let mut seen = 0_u8;
    for pair in body.split(|byte| *byte == b'&') {
        let at = pair
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(InitialError::RequestMismatch)?;
        let index = expected
            .iter()
            .position(|(key, _)| *key == &pair[..at])
            .ok_or(InitialError::RequestMismatch)?;
        let bit = 1_u8 << index;
        if seen & bit != 0 || !form_value_equals(&pair[at + 1..], expected[index].1) {
            return Err(InitialError::RequestMismatch);
        }
        seen |= bit;
    }
    if seen != 0b1_1111 {
        return Err(InitialError::RequestMismatch);
    }
    Ok(())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn form_value_equals(encoded: &[u8], expected: &[u8]) -> bool {
    let mut at = 0;
    let mut decoded = 0;
    let mut scratch = Zeroizing::new([0_u8; 1]);
    while at < encoded.len() {
        scratch[0] = match encoded[at] {
            b'+' => b' ',
            b'%' => {
                if at + 2 >= encoded.len() {
                    return false;
                }
                let (Some(high), Some(low)) = (hex(encoded[at + 1]), hex(encoded[at + 2])) else {
                    return false;
                };
                at += 2;
                high * 16 + low
            }
            byte if byte.is_ascii_graphic() && !matches!(byte, b'&' | b'=') => byte,
            _ => return false,
        };
        if expected.get(decoded) != Some(&scratch[0]) {
            return false;
        }
        scratch.zeroize();
        decoded += 1;
        at += 1;
    }
    decoded == expected.len()
}

struct RequestJson<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl RequestJson<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.at += 1;
        }
    }

    fn punctuation(&mut self, byte: u8) -> Result<(), InitialError> {
        self.whitespace();
        if self.bytes.get(self.at) != Some(&byte) {
            return Err(InitialError::RequestMismatch);
        }
        self.at += 1;
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u16, InitialError> {
        let end = self
            .at
            .checked_add(4)
            .ok_or(InitialError::RequestMismatch)?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or(InitialError::RequestMismatch)?;
        let mut number = 0_u16;
        for byte in bytes {
            number = number * 16 + u16::from(hex(*byte).ok_or(InitialError::RequestMismatch)?);
        }
        self.at = end;
        Ok(number)
    }

    fn scalar(&mut self, scratch: &mut Zeroizing<[u8; 4]>) -> Result<usize, InitialError> {
        scratch.zeroize();
        let byte = *self
            .bytes
            .get(self.at)
            .ok_or(InitialError::RequestMismatch)?;
        self.at += 1;
        if byte == b'\\' {
            let escape = *self
                .bytes
                .get(self.at)
                .ok_or(InitialError::RequestMismatch)?;
            self.at += 1;
            scratch[0] = match escape {
                b'"' => b'"',
                b'\\' => b'\\',
                b'/' => b'/',
                b'b' => 8,
                b'f' => 12,
                b'n' => 10,
                b'r' => 13,
                b't' => 9,
                b'u' => {
                    let first = self.hex_quad()?;
                    let scalar = if (0xd800..=0xdbff).contains(&first) {
                        if self.bytes.get(self.at..self.at + 2) != Some(b"\\u") {
                            return Err(InitialError::RequestMismatch);
                        }
                        self.at += 2;
                        let second = self.hex_quad()?;
                        if !(0xdc00..=0xdfff).contains(&second) {
                            return Err(InitialError::RequestMismatch);
                        }
                        0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second) - 0xdc00
                    } else {
                        u32::from(first)
                    };
                    let ch = char::from_u32(scalar).ok_or(InitialError::RequestMismatch)?;
                    return Ok(ch.encode_utf8(&mut **scratch).len());
                }
                _ => return Err(InitialError::RequestMismatch),
            };
            return Ok(1);
        }
        if byte < 0x20 || byte == b'"' {
            return Err(InitialError::RequestMismatch);
        }
        let width = match byte {
            0x20..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(InitialError::RequestMismatch),
        };
        let start = self.at - 1;
        let end = start
            .checked_add(width)
            .ok_or(InitialError::RequestMismatch)?;
        let bytes = self
            .bytes
            .get(start..end)
            .ok_or(InitialError::RequestMismatch)?;
        std::str::from_utf8(bytes).map_err(|_| InitialError::RequestMismatch)?;
        scratch[..width].copy_from_slice(bytes);
        self.at = end;
        Ok(width)
    }

    fn key(&mut self) -> Result<Zeroizing<String>, InitialError> {
        self.punctuation(b'"')?;
        let mut key = Zeroizing::new(String::with_capacity(26));
        let mut scratch = Zeroizing::new([0_u8; 4]);
        while self.bytes.get(self.at) != Some(&b'"') {
            let width = self.scalar(&mut scratch)?;
            if key.len() + width > 26 {
                return Err(InitialError::RequestMismatch);
            }
            key.push_str(
                std::str::from_utf8(&scratch[..width])
                    .map_err(|_| InitialError::RequestMismatch)?,
            );
            scratch.zeroize();
        }
        self.at += 1;
        Ok(key)
    }

    fn string_equals(&mut self, expected: &str) -> Result<(), InitialError> {
        self.punctuation(b'"')?;
        let mut scratch = Zeroizing::new([0_u8; 4]);
        let mut decoded = 0_usize;
        while self.bytes.get(self.at) != Some(&b'"') {
            let width = self.scalar(&mut scratch)?;
            let end = decoded
                .checked_add(width)
                .ok_or(InitialError::RequestMismatch)?;
            if expected.as_bytes().get(decoded..end) != Some(&scratch[..width]) {
                return Err(InitialError::RequestMismatch);
            }
            decoded = end;
            scratch.zeroize();
        }
        self.at += 1;
        if decoded != expected.len() {
            return Err(InitialError::RequestMismatch);
        }
        Ok(())
    }

    fn array_equals(&mut self, expected: &[&str]) -> Result<(), InitialError> {
        self.punctuation(b'[')?;
        for (index, value) in expected.iter().enumerate() {
            if index != 0 {
                self.punctuation(b',')?;
            }
            self.string_equals(value)?;
        }
        self.punctuation(b']')
    }
}

fn validate_registration_json(body: &[u8], redirect: &str) -> Result<(), InitialError> {
    let mut json = RequestJson { bytes: body, at: 0 };
    json.punctuation(b'{')?;
    let mut seen = 0_u8;
    loop {
        let key = json.key()?;
        let index = match key.as_str() {
            "client_name" => 0,
            "token_endpoint_auth_method" => 1,
            "grant_types" => 2,
            "redirect_uris" => 3,
            "response_types" => 4,
            _ => return Err(InitialError::RequestMismatch),
        };
        let bit = 1_u8 << index;
        if seen & bit != 0 {
            return Err(InitialError::RequestMismatch);
        }
        seen |= bit;
        json.punctuation(b':')?;
        match index {
            0 => json.string_equals("Wrok Bot")?,
            1 => json.string_equals("none")?,
            2 => json.array_equals(&["authorization_code", "refresh_token"])?,
            3 => json.array_equals(&[redirect])?,
            4 => json.array_equals(&["code"])?,
            _ => return Err(InitialError::RequestMismatch),
        }
        json.whitespace();
        match json.bytes.get(json.at) {
            Some(b',') => json.at += 1,
            Some(b'}') => {
                json.at += 1;
                break;
            }
            _ => return Err(InitialError::RequestMismatch),
        }
    }
    json.whitespace();
    if seen != 0b1_1111 || json.at != body.len() {
        return Err(InitialError::RequestMismatch);
    }
    Ok(())
}
