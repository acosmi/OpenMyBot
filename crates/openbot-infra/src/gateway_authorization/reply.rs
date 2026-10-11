//! Closed initial OAuth reply decoding; every decoded allocation is armed first.

use std::{future::poll_fn, num::NonZeroI64, task::Poll};

use futures_util::StreamExt;

use zeroize::{Zeroize, Zeroizing};

use super::journal::SavedFlow;
use super::{
    ClockOwner, DispatchedInitialOwner, InitialBudget, InitialError, InitialReply,
    InitialReplyWitness, OwnedRegistrationReply, ParsedTokenFields, PreparedInitialOwner,
    RegistrationTransferWitness, ReplyInvalidReason, ReplyResources,
};

const BODY_LIMIT: usize = 65_536;
const TOKEN_LIMIT: usize = 16_377;
const CLIENT_LIMIT: usize = 256;
const REDIRECT_LIMIT: usize = 2_048;
const SCOPE_LIMIT: usize = 128;

fn invalid(reason: ReplyInvalidReason) -> InitialError {
    InitialError::ProtocolInvalid(reason)
}

pub(super) fn client_id_valid(value: &str) -> bool {
    super::initial::valid_client_id(value)
}

pub(super) fn graphic_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= TOKEN_LIMIT
        && value
            .as_bytes()
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte))
}

pub(super) fn scope_valid(value: &str) -> bool {
    if value.len() > SCOPE_LIMIT || !value.is_ascii() {
        return false;
    }
    let mut ai = false;
    let mut account = false;
    for word in value
        .split(['\t', '\n', '\u{000c}', '\r', ' '])
        .filter(|word| !word.is_empty())
    {
        match word {
            "ai" if !ai => ai = true,
            "account" if !account => account = true,
            _ => return false,
        }
    }
    ai && account
}

#[derive(Clone, Copy)]
enum ReplyKind {
    Registration,
    Tokens,
}

#[derive(Clone, Copy)]
enum Key {
    ClientId,
    ClientName,
    RedirectUris,
    GrantTypes,
    AuthMethod,
    AccessToken,
    TokenType,
    ExpiresIn,
    RefreshToken,
    Scope,
}

impl Key {
    fn bit(self) -> u16 {
        match self {
            Self::ClientId | Self::AccessToken => 1,
            Self::ClientName | Self::TokenType => 2,
            Self::RedirectUris | Self::ExpiresIn => 4,
            Self::GrantTypes | Self::RefreshToken => 8,
            Self::AuthMethod | Self::Scope => 16,
        }
    }
}

struct TokenFieldsBuilder {
    access_token: Zeroizing<String>,
    token_type: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    scope: Zeroizing<String>,
    expires_in: Option<NonZeroI64>,
}

impl TokenFieldsBuilder {
    fn new() -> Self {
        Self {
            access_token: Zeroizing::new(String::with_capacity(TOKEN_LIMIT)),
            token_type: Zeroizing::new(String::with_capacity(6)),
            refresh_token: Zeroizing::new(String::with_capacity(TOKEN_LIMIT)),
            scope: Zeroizing::new(String::with_capacity(SCOPE_LIMIT)),
            expires_in: None,
        }
    }

    #[cfg(test)]
    fn erase(&mut self) {
        self.access_token.zeroize();
        self.token_type.zeroize();
        self.refresh_token.zeroize();
        self.scope.zeroize();
        self.expires_in = None;
    }

    fn finish(self) -> Result<ParsedTokenFields, InitialError> {
        let expires_in = self
            .expires_in
            .ok_or_else(|| invalid(ReplyInvalidReason::FieldShape))?;
        Ok(ParsedTokenFields {
            access_token: self.access_token,
            token_type: self.token_type,
            refresh_token: self.refresh_token,
            scope: self.scope,
            expires_in,
        })
    }
}

/// The only UTF-8 checks are the current scalar, never the complete body.
struct Cursor<'a> {
    raw: &'a [u8],
    position: usize,
    key: Zeroizing<[u8; 26]>,
    scalar: Zeroizing<[u8; 4]>,
    seen: u16,
}

impl<'a> Cursor<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self {
            raw,
            position: 0,
            key: Zeroizing::new([0; 26]),
            scalar: Zeroizing::new([0; 4]),
            seen: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.raw.get(self.position).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn punctuation(&mut self, byte: u8) -> Result<(), InitialError> {
        if self.peek() != Some(byte) {
            return Err(invalid(ReplyInvalidReason::JsonSyntax));
        }
        self.position += 1;
        Ok(())
    }

    fn string_start(&mut self) -> Result<(), InitialError> {
        if self.peek() != Some(b'"') {
            return Err(invalid(ReplyInvalidReason::FieldShape));
        }
        self.position += 1;
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<Zeroizing<u32>, InitialError> {
        let mut value = Zeroizing::new(0_u32);
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(byte @ b'0'..=b'9') => u32::from(byte - b'0'),
                Some(byte @ b'a'..=b'f') => u32::from(byte - b'a' + 10),
                Some(byte @ b'A'..=b'F') => u32::from(byte - b'A' + 10),
                _ => return Err(invalid(ReplyInvalidReason::JsonSyntax)),
            };
            *value = (*value << 4) | digit;
            self.position += 1;
        }
        Ok(value)
    }

    fn unicode_scalar(&mut self) -> Result<usize, InitialError> {
        let mut code = self.hex_quad()?;
        if (0xd800..=0xdbff).contains(&*code) {
            self.punctuation(b'\\')?;
            self.punctuation(b'u')?;
            let low = self.hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&*low) {
                return Err(invalid(ReplyInvalidReason::JsonSyntax));
            }
            *code = 0x10000 + ((*code - 0xd800) << 10) + (*low - 0xdc00);
        } else if (0xdc00..=0xdfff).contains(&*code) {
            return Err(invalid(ReplyInvalidReason::JsonSyntax));
        }
        let count = if *code <= 0x7f {
            self.scalar[0] = *code as u8;
            1
        } else if *code <= 0x7ff {
            self.scalar[0] = 0xc0 | (*code >> 6) as u8;
            self.scalar[1] = 0x80 | (*code & 0x3f) as u8;
            2
        } else if *code <= 0xffff {
            self.scalar[0] = 0xe0 | (*code >> 12) as u8;
            self.scalar[1] = 0x80 | ((*code >> 6) & 0x3f) as u8;
            self.scalar[2] = 0x80 | (*code & 0x3f) as u8;
            3
        } else {
            self.scalar[0] = 0xf0 | (*code >> 18) as u8;
            self.scalar[1] = 0x80 | ((*code >> 12) & 0x3f) as u8;
            self.scalar[2] = 0x80 | ((*code >> 6) & 0x3f) as u8;
            self.scalar[3] = 0x80 | (*code & 0x3f) as u8;
            4
        };
        Ok(count)
    }

    fn scalar(&mut self) -> Result<usize, InitialError> {
        self.scalar.zeroize();
        let first = self
            .peek()
            .ok_or_else(|| invalid(ReplyInvalidReason::JsonSyntax))?;
        if first == b'\\' {
            self.position += 1;
            let escape = self
                .peek()
                .ok_or_else(|| invalid(ReplyInvalidReason::JsonSyntax))?;
            self.position += 1;
            match escape {
                b'"' | b'\\' | b'/' => self.scalar[0] = escape,
                b'b' => self.scalar[0] = 0x08,
                b'f' => self.scalar[0] = 0x0c,
                b'n' => self.scalar[0] = b'\n',
                b'r' => self.scalar[0] = b'\r',
                b't' => self.scalar[0] = b'\t',
                b'u' => return self.unicode_scalar(),
                _ => return Err(invalid(ReplyInvalidReason::JsonSyntax)),
            }
            return Ok(1);
        }
        let count = match first {
            0x20..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(invalid(ReplyInvalidReason::JsonSyntax)),
        };
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| invalid(ReplyInvalidReason::JsonSyntax))?;
        let bytes = self
            .raw
            .get(self.position..end)
            .ok_or_else(|| invalid(ReplyInvalidReason::JsonSyntax))?;
        self.scalar[..count].copy_from_slice(bytes);
        std::str::from_utf8(&self.scalar[..count])
            .map_err(|_| invalid(ReplyInvalidReason::JsonSyntax))?;
        self.position = end;
        Ok(count)
    }

    fn string(
        &mut self,
        output: &mut Zeroizing<String>,
        limit: usize,
        limit_reason: ReplyInvalidReason,
    ) -> Result<(), InitialError> {
        self.string_start()?;
        loop {
            if self.peek() == Some(b'"') {
                self.position += 1;
                return Ok(());
            }
            let count = self.scalar()?;
            let length = output
                .len()
                .checked_add(count)
                .ok_or_else(|| invalid(limit_reason))?;
            if length > limit {
                return Err(invalid(limit_reason));
            }
            let scalar = std::str::from_utf8(&self.scalar[..count])
                .map_err(|_| invalid(ReplyInvalidReason::JsonSyntax))?;
            output.push_str(scalar);
        }
    }

    fn decoded_key(&mut self, kind: ReplyKind) -> Result<Key, InitialError> {
        self.key.zeroize();
        self.punctuation(b'"')?;
        let mut length = 0_usize;
        while self.peek() != Some(b'"') {
            let count = self.scalar()?;
            let end = length
                .checked_add(count)
                .ok_or_else(|| invalid(ReplyInvalidReason::UnknownKey))?;
            if end > 26 {
                return Err(invalid(ReplyInvalidReason::UnknownKey));
            }
            self.key[length..end].copy_from_slice(&self.scalar[..count]);
            length = end;
        }
        self.position += 1;
        // These decisions happen before ':' or any value decoder is consumed.
        if &self.key[..length] == b"client_secret" {
            return Err(invalid(ReplyInvalidReason::ForbiddenSecretKey));
        }
        let key = match (kind, &self.key[..length]) {
            (ReplyKind::Registration, b"client_id") => Key::ClientId,
            (ReplyKind::Registration, b"client_name") => Key::ClientName,
            (ReplyKind::Registration, b"redirect_uris") => Key::RedirectUris,
            (ReplyKind::Registration, b"grant_types") => Key::GrantTypes,
            (ReplyKind::Registration, b"token_endpoint_auth_method") => Key::AuthMethod,
            (ReplyKind::Tokens, b"access_token") => Key::AccessToken,
            (ReplyKind::Tokens, b"token_type") => Key::TokenType,
            (ReplyKind::Tokens, b"expires_in") => Key::ExpiresIn,
            (ReplyKind::Tokens, b"refresh_token") => Key::RefreshToken,
            (ReplyKind::Tokens, b"scope") => Key::Scope,
            _ => return Err(invalid(ReplyInvalidReason::UnknownKey)),
        };
        if self.seen & key.bit() != 0 {
            return Err(invalid(ReplyInvalidReason::DuplicateKey));
        }
        self.seen |= key.bit();
        Ok(key)
    }

    fn exact_string(&mut self, expected: &str, limit: usize) -> Result<(), InitialError> {
        let mut value = Zeroizing::new(String::with_capacity(limit));
        self.string(&mut value, limit, ReplyInvalidReason::FieldLimit)?;
        if value.as_str() != expected {
            return Err(invalid(ReplyInvalidReason::ReplyBinding));
        }
        Ok(())
    }

    fn string_array_start(&mut self) -> Result<(), InitialError> {
        if self.peek() != Some(b'[') {
            return Err(invalid(ReplyInvalidReason::FieldShape));
        }
        self.position += 1;
        self.whitespace();
        Ok(())
    }

    fn exact_redirect(&mut self, redirect: &str) -> Result<(), InitialError> {
        self.string_array_start()?;
        self.exact_string(redirect, REDIRECT_LIMIT)?;
        self.whitespace();
        if self.peek() != Some(b']') {
            return Err(invalid(ReplyInvalidReason::FieldShape));
        }
        self.position += 1;
        Ok(())
    }

    fn exact_grants(&mut self) -> Result<(), InitialError> {
        self.string_array_start()?;
        self.exact_string("authorization_code", 18)?;
        self.whitespace();
        if self.peek() != Some(b',') {
            return Err(invalid(ReplyInvalidReason::FieldShape));
        }
        self.position += 1;
        self.whitespace();
        self.exact_string("refresh_token", 13)?;
        self.whitespace();
        if self.peek() != Some(b']') {
            return Err(invalid(ReplyInvalidReason::FieldShape));
        }
        self.position += 1;
        Ok(())
    }

    fn positive_integer(&mut self) -> Result<NonZeroI64, InitialError> {
        if !matches!(self.peek(), Some(b'1'..=b'9')) {
            return Err(invalid(ReplyInvalidReason::ExpiryInteger));
        }
        let mut number = 0_i64;
        while let Some(byte @ b'0'..=b'9') = self.peek() {
            number = number
                .checked_mul(10)
                .and_then(|value| value.checked_add(i64::from(byte - b'0')))
                .ok_or_else(|| invalid(ReplyInvalidReason::ExpiryInteger))?;
            self.position += 1;
        }
        if !matches!(
            self.peek(),
            None | Some(b' ' | b'\t' | b'\n' | b'\r' | b',' | b'}')
        ) {
            return Err(invalid(ReplyInvalidReason::ExpiryInteger));
        }
        NonZeroI64::new(number).ok_or_else(|| invalid(ReplyInvalidReason::ExpiryInteger))
    }

    fn object_start(&mut self) -> Result<bool, InitialError> {
        self.whitespace();
        self.punctuation(b'{')?;
        self.whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(false);
        }
        Ok(true)
    }

    fn value_start(&mut self) -> Result<(), InitialError> {
        self.whitespace();
        self.punctuation(b':')?;
        self.whitespace();
        Ok(())
    }

    fn next_field(&mut self) -> Result<bool, InitialError> {
        self.whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(false);
        }
        self.punctuation(b',')?;
        self.whitespace();
        if self.peek() == Some(b'}') {
            return Err(invalid(ReplyInvalidReason::JsonSyntax));
        }
        Ok(true)
    }

    fn eof(&mut self) -> Result<(), InitialError> {
        self.whitespace();
        if self.position != self.raw.len() {
            return Err(invalid(ReplyInvalidReason::JsonSyntax));
        }
        Ok(())
    }

    fn registration(
        &mut self,
        redirect: &str,
        client: &mut Zeroizing<String>,
    ) -> Result<(), InitialError> {
        if self.object_start()? {
            loop {
                let key = self.decoded_key(ReplyKind::Registration)?;
                self.value_start()?;
                match key {
                    Key::ClientId => {
                        self.string(client, CLIENT_LIMIT, ReplyInvalidReason::FieldLimit)?;
                        if !client_id_valid(client.as_str()) {
                            return Err(invalid(ReplyInvalidReason::FieldLimit));
                        }
                    }
                    Key::ClientName => self.exact_string("Wrok Bot", 8)?,
                    Key::RedirectUris => self.exact_redirect(redirect)?,
                    Key::GrantTypes => self.exact_grants()?,
                    Key::AuthMethod => self.exact_string("none", 4)?,
                    _ => return Err(invalid(ReplyInvalidReason::UnknownKey)),
                }
                if !self.next_field()? {
                    break;
                }
            }
        }
        self.eof()?;
        if self.seen & 1 == 0 {
            return Err(invalid(ReplyInvalidReason::FieldShape));
        }
        Ok(())
    }

    fn tokens(&mut self, fields: &mut TokenFieldsBuilder) -> Result<(), InitialError> {
        if self.object_start()? {
            loop {
                let key = self.decoded_key(ReplyKind::Tokens)?;
                self.value_start()?;
                match key {
                    Key::AccessToken => {
                        self.string(
                            &mut fields.access_token,
                            TOKEN_LIMIT,
                            ReplyInvalidReason::FieldLimit,
                        )?;
                        if !graphic_token(fields.access_token.as_str()) {
                            return Err(invalid(ReplyInvalidReason::FieldLimit));
                        }
                    }
                    Key::TokenType => {
                        self.string(&mut fields.token_type, 6, ReplyInvalidReason::TokenType)?;
                        if fields.token_type.as_str() != "Bearer" {
                            return Err(invalid(ReplyInvalidReason::TokenType));
                        }
                    }
                    Key::ExpiresIn => fields.expires_in = Some(self.positive_integer()?),
                    Key::RefreshToken => {
                        self.string(
                            &mut fields.refresh_token,
                            TOKEN_LIMIT,
                            ReplyInvalidReason::FieldLimit,
                        )?;
                        if !graphic_token(fields.refresh_token.as_str()) {
                            return Err(invalid(ReplyInvalidReason::FieldLimit));
                        }
                    }
                    Key::Scope => {
                        self.string(
                            &mut fields.scope,
                            SCOPE_LIMIT,
                            ReplyInvalidReason::FieldLimit,
                        )?;
                        if !scope_valid(fields.scope.as_str()) {
                            return Err(invalid(ReplyInvalidReason::ScopeShape));
                        }
                    }
                    _ => return Err(invalid(ReplyInvalidReason::UnknownKey)),
                }
                if !self.next_field()? {
                    break;
                }
            }
        }
        self.eof()?;
        if self.seen != 31 {
            return Err(invalid(ReplyInvalidReason::FieldShape));
        }
        Ok(())
    }
}

pub(super) fn parse_registration(
    raw: &[u8],
    original_redirect: &str,
) -> Result<Zeroizing<String>, InitialError> {
    let mut client = Zeroizing::new(String::with_capacity(CLIENT_LIMIT));
    Cursor::new(raw).registration(original_redirect, &mut client)?;
    Ok(client)
}

pub(super) fn parse_tokens(raw: &[u8]) -> Result<ParsedTokenFields, InitialError> {
    let mut fields = TokenFieldsBuilder::new();
    Cursor::new(raw).tokens(&mut fields)?;
    fields.finish()
}

fn trim_sp_ht(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while matches!(bytes.last(), Some(b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn json_media_type(value: &[u8]) -> bool {
    if value
        .iter()
        .any(|byte| matches!(byte, b',' | b'\r' | b'\n'))
    {
        return false;
    }
    let value = trim_sp_ht(value);
    let mut parts = value.split(|byte| *byte == b';');
    let Some(media) = parts.next() else {
        return false;
    };
    if !trim_sp_ht(media).eq_ignore_ascii_case(b"application/json") {
        return false;
    }
    let Some(parameter) = parts.next() else {
        return true;
    };
    if parts.next().is_some() {
        return false;
    }
    let mut pair = trim_sp_ht(parameter).split(|byte| *byte == b'=');
    let Some(name) = pair.next() else {
        return false;
    };
    let Some(value) = pair.next() else {
        return false;
    };
    if pair.next().is_some() || !trim_sp_ht(name).eq_ignore_ascii_case(b"charset") {
        return false;
    }
    let value = trim_sp_ht(value);
    value.eq_ignore_ascii_case(b"utf-8") || value.eq_ignore_ascii_case(b"\"utf-8\"")
}

pub(super) fn header_limits(response: &acosmi::HttpResponse) -> Result<(), InitialError> {
    let mut count = 0_usize;
    let mut total = 0_usize;
    for (name, value) in &response.headers {
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid(ReplyInvalidReason::HeaderLimit))?;
        total = total
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .ok_or_else(|| invalid(ReplyInvalidReason::HeaderLimit))?;
        if count > 64 || total > 65_536 || value.as_bytes().len() > 8_192 {
            return Err(invalid(ReplyInvalidReason::HeaderLimit));
        }
    }
    Ok(())
}

pub(super) fn success_media_type(response: &acosmi::HttpResponse) -> Result<(), InitialError> {
    let values = response.headers.get_all("content-type");
    let mut values = values.iter();
    let value = values
        .next()
        .ok_or_else(|| invalid(ReplyInvalidReason::MediaType))?;
    if values.next().is_some() || !json_media_type(value.as_bytes()) {
        return Err(invalid(ReplyInvalidReason::MediaType));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn test_token_cursor(raw: &[u8]) -> (Result<(), InitialError>, usize) {
    let mut cursor = Cursor::new(raw);
    let mut fields = TokenFieldsBuilder::new();
    let result = cursor.tokens(&mut fields);
    (result, cursor.position)
}

#[cfg(test)]
pub(super) fn test_registration_cursor(
    raw: &[u8],
    redirect: &str,
) -> (Result<(), InitialError>, usize) {
    let mut cursor = Cursor::new(raw);
    let mut client = Zeroizing::new(String::with_capacity(CLIENT_LIMIT));
    let result = cursor.registration(redirect, &mut client);
    (result, cursor.position)
}

#[cfg(test)]
pub(super) fn test_partial_erase(raw: &[u8]) -> (Result<(), InitialError>, bool) {
    let mut body = Zeroizing::new(Vec::with_capacity(BODY_LIMIT));
    if raw.len() > BODY_LIMIT {
        return (Err(invalid(ReplyInvalidReason::BodyLimit)), body.is_empty());
    }
    body.extend_from_slice(raw);
    let mut fields = TokenFieldsBuilder::new();
    let mut cursor = Cursor::new(body.as_slice());
    let result = cursor.tokens(&mut fields);
    cursor.key.zeroize();
    cursor.scalar.zeroize();
    let scratch_zero =
        cursor.key.iter().all(|byte| *byte == 0) && cursor.scalar.iter().all(|byte| *byte == 0);
    drop(cursor);
    fields.erase();
    body.zeroize();
    let erased = scratch_zero
        && body.is_empty()
        && fields.access_token.is_empty()
        && fields.token_type.is_empty()
        && fields.refresh_token.is_empty()
        && fields.scope.is_empty()
        && fields.expires_in.is_none();
    (result, erased)
}

async fn owned_body(
    response: &mut acosmi::HttpResponse,
    budget: &InitialBudget,
    clock: &ClockOwner,
) -> Result<Zeroizing<Vec<u8>>, InitialError> {
    let mut body = Zeroizing::new(Vec::with_capacity(BODY_LIMIT));
    let deadline = budget.deadline.min(budget.owner_deadline);
    loop {
        budget.check(clock)?;
        let next = tokio::select! {
            biased;
            _ = budget.original_parent.cancelled() => return Err(InitialError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(InitialError::Deadline),
            next = response.body.next() => next,
        };
        budget.check(clock)?;
        match next {
            Some(Ok(chunk)) => {
                let length = body
                    .len()
                    .checked_add(chunk.len())
                    .ok_or_else(|| invalid(ReplyInvalidReason::BodyLimit))?;
                if length > BODY_LIMIT {
                    return Err(invalid(ReplyInvalidReason::BodyLimit));
                }
                // Its fixed preallocation already accommodates every permitted byte.
                // The immutable incoming Bytes is an SDK/library erasure limitation.
                body.extend_from_slice(&chunk);
            }
            Some(Err(_)) => return Err(InitialError::BodyTransport),
            None => return Ok(body),
        }
    }
}

pub(super) async fn consume_initial(
    mut prepared: PreparedInitialOwner,
    mut response: acosmi::HttpResponse,
) -> Result<InitialReply, InitialError> {
    let budget = prepared
        .budget
        .as_ref()
        .ok_or_else(|| invalid(ReplyInvalidReason::ReplyBinding))?;
    budget.check(&prepared.clock)?;
    if prepared.request.is_none() || !prepared.sdk_exit_child.is_cancelled() {
        return Err(invalid(ReplyInvalidReason::ReplyBinding));
    }
    header_limits(&response)?;
    let registration = matches!(
        prepared.witness.as_ref(),
        Some(InitialReplyWitness::Registration { .. })
    );
    if prepared.witness.is_none() {
        return Err(invalid(ReplyInvalidReason::ReplyBinding));
    }
    let status = response.status.as_u16();
    if (registration && status != 200 && status != 201) || (!registration && status != 200) {
        // This early return never polls or decodes any vendor error body.
        return Err(InitialError::HttpStatus(status));
    }
    success_media_type(&response)?;
    let body = owned_body(&mut response, budget, &prepared.clock).await?;
    budget.check(&prepared.clock)?;
    let witness = prepared
        .witness
        .take()
        .ok_or_else(|| invalid(ReplyInvalidReason::ReplyBinding))?;
    match witness {
        InitialReplyWitness::Registration {
            metadata,
            original_redirect_uri,
        } => {
            let client_id = parse_registration(body.as_slice(), original_redirect_uri.as_str())?;
            budget.check(&prepared.clock)?;
            let budget = prepared
                .budget
                .take()
                .ok_or_else(|| invalid(ReplyInvalidReason::ReplyBinding))?;
            let reply = OwnedRegistrationReply {
                client_id,
                original_redirect_uri,
                resources: ReplyResources {
                    metadata,
                    budget,
                    clock: prepared.clock,
                },
            };
            reply.resources.budget.check(&reply.resources.clock)?;
            Ok(InitialReply::Registration(reply))
        }
        InitialReplyWitness::Code {
            metadata,
            binding,
            start,
            ..
        } => {
            let fields = parse_tokens(body.as_slice())?;
            budget.check(&prepared.clock)?;
            let budget = prepared
                .budget
                .take()
                .ok_or_else(|| invalid(ReplyInvalidReason::ReplyBinding))?;
            let resources = ReplyResources {
                metadata,
                budget,
                clock: prepared.clock,
            };
            let owner = super::tokens::assemble_tokens(fields, binding, start, resources)?;
            Ok(InitialReply::Tokens(owner))
        }
    }
}

// The dispatched reader uses both original budgets on every actual stream poll,
// including Pending. The captured reader above retains its original behavior.
async fn owned_dispatched_registration_body(
    response: &mut acosmi::HttpResponse,
    budget: &InitialBudget,
    clock: &ClockOwner,
    flow: &SavedFlow,
) -> Result<Zeroizing<Vec<u8>>, InitialError> {
    let mut body = Zeroizing::new(Vec::with_capacity(BODY_LIMIT));
    let deadline = flow.registration_reply_cap(budget);
    loop {
        flow.check_registration_reply(budget, clock)?;
        let next = tokio::select! {
            biased;
            _ = budget.original_parent.cancelled() => return Err(InitialError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(InitialError::Deadline),
            next = poll_fn(|cx| {
                if let Err(error) = flow.check_registration_reply(budget, clock) {
                    return Poll::Ready(Err(error));
                }
                let polled = response.body.as_mut().poll_next(cx);
                if let Err(error) = flow.check_registration_reply(budget, clock) {
                    return Poll::Ready(Err(error));
                }
                match polled {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(item) => Poll::Ready(Ok(item)),
                }
            }) => next?,
        };
        flow.check_registration_reply(budget, clock)?;
        match next {
            Some(Ok(chunk)) => {
                let length = body
                    .len()
                    .checked_add(chunk.len())
                    .ok_or_else(|| invalid(ReplyInvalidReason::BodyLimit))?;
                if length > BODY_LIMIT {
                    return Err(invalid(ReplyInvalidReason::BodyLimit));
                }
                // Immutable SDK Bytes remain outside the zeroizing body owner.
                body.extend_from_slice(&chunk);
            }
            Some(Err(_)) => return Err(InitialError::BodyTransport),
            None => return Ok(body),
        }
    }
}

pub(super) async fn consume_dispatched_registration(
    dispatched: DispatchedInitialOwner,
    mut response: acosmi::HttpResponse,
    flow: &SavedFlow,
) -> Result<OwnedRegistrationReply, InitialError> {
    flow.check_registration_reply(&dispatched.budget, &dispatched.clock)?;
    if !dispatched.sdk_exit_child.is_cancelled() {
        return Err(invalid(ReplyInvalidReason::ReplyBinding));
    }
    let DispatchedInitialOwner {
        witness,
        budget,
        clock,
        sdk_exit_child: _,
        transfer,
    } = dispatched;
    let RegistrationTransferWitness { _private: () } = transfer;
    let InitialReplyWitness::Registration {
        metadata,
        original_redirect_uri,
    } = witness
    else {
        return Err(invalid(ReplyInvalidReason::ReplyBinding));
    };
    header_limits(&response)?;
    let status = response.status.as_u16();
    if status != 200 && status != 201 {
        // Preserve only the numeric status; never poll the vendor error body.
        return Err(InitialError::HttpStatus(status));
    }
    success_media_type(&response)?;
    let body = owned_dispatched_registration_body(&mut response, &budget, &clock, flow).await?;
    flow.check_registration_reply(&budget, &clock)?;
    let parsed = parse_registration(body.as_slice(), original_redirect_uri.as_str());
    flow.check_registration_reply(&budget, &clock)?;
    let client_id = parsed?;
    let reply = OwnedRegistrationReply {
        client_id,
        original_redirect_uri,
        resources: ReplyResources {
            metadata,
            budget,
            clock,
        },
    };
    flow.check_registration_reply(&reply.resources.budget, &reply.resources.clock)?;
    Ok(reply)
}
