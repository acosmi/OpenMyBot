//! Public sender-key ingress (spec revision R485).
//!
//! This route has its own framing and never reads a cookie, sets a session or runs CSRF checks;
//! it still sits behind the shared trusted-transport gate. The body is parsed exactly once here,
//! canonicalized with RFC 8785 and handed to the application port as a verified source input.

use crate::error::HttpError;
use axum::{
    Json,
    body::Body,
    extract::{Path, RawQuery, State},
};
use futures_core::Stream as _;
use http::{
    HeaderMap, StatusCode,
    header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE},
};
use openbot_application::automation::AutomationDeliveryEntry;
use openbot_contracts::{automation::*, error::AppError};
use openbot_domain::vault::SecretBytes;
use serde::{Deserialize, de};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const MAX_INGRESS_BODY_BYTES: usize = 256 * 1024;
const MAX_NORMALIZED_DATA_BYTES: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 16;
const MAX_IN_FLIGHT: usize = 64;

#[derive(Clone)]
struct Ingress {
    entry: AutomationDeliveryEntry,
    in_flight: Arc<tokio::sync::Semaphore>,
}

/// Register the sole public source route with its five-second, no-store budget.
pub(crate) fn routes(entry: AutomationDeliveryEntry) -> axum::Router {
    axum::Router::new()
        .route(
            "/api/automation-ingress/{receiver_id}",
            axum::routing::post(deliver),
        )
        .with_state(Ingress {
            entry,
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)),
        })
        .layer(axum::middleware::from_fn(
            super::automations::bounded_request,
        ))
}

// Closed sender-key envelope. Serde rejects unknown and repeated top-level fields.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    event_id: AutomationOperationId,
    event_type: AutomationEventType,
    occurred_at: String,
    data: StrictJson,
}

// One decode of `data` that refuses repeated decoded object keys and decoded U+0000 anywhere.
struct StrictJson(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = serde_json::Value;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate keys or NUL")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(value.into())
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(value.into())
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(value.into())
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.contains('\0') {
                    return Err(E::custom("NUL"));
                }
                Ok(value.into())
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while let Some(StrictJson(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(items.into())
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let StrictJson(value) = map.next_value()?;
                    if key.contains('\0') || object.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate key or NUL"));
                    }
                }
                Ok(object.into())
            }
        }
        deserializer.deserialize_any(Visitor).map(Self)
    }
}

/// Authenticate, frame and normalize one sender-key delivery, then hand it to the sole port.
async fn deliver(
    State(ingress): State<Ingress>,
    Path(receiver): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<AutomationIngressReceipt>), HttpError> {
    let _permit = ingress
        .in_flight
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::AutomationRateLimited)?;
    // An ID that cannot exist and a missing, repeated or non-Bearer header all look unknown.
    let receiver = AutomationReceiverId::try_from(receiver)
        .map_err(|_| AppError::AutomationSourceUnauthorized)?;
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let presented = match (values.next(), values.next()) {
        (Some(value), None) => value
            .as_bytes()
            .strip_prefix(b"Bearer ")
            .map(|key| SecretBytes::new(key.to_vec()))
            .ok_or(AppError::AutomationSourceUnauthorized)?,
        _ => return Err(AppError::AutomationSourceUnauthorized.into()),
    };
    let entry = &ingress.entry;
    let key_revision = match entry.authenticate(&receiver, &presented).await {
        Ok(revision) => revision,
        Err(error) => return Err(refused(entry, &receiver, error).await),
    };
    let outcome = async {
        let malformed = || AppError::MalformedPayload { field: "body" };
        if query.is_some_and(|raw| !raw.is_empty()) {
            return Err(malformed());
        }
        let json = headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
        let compressed = headers
            .get_all(CONTENT_ENCODING)
            .iter()
            .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
        if !json || compressed {
            return Err(malformed());
        }
        // Count the stream itself so a missing Content-Length or chunked input cannot bypass it.
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        let mut chunks = std::pin::pin!(body.into_data_stream());
        while let Some(data) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx)).await {
            let data = data.map_err(|_| malformed())?;
            if data.len() > MAX_INGRESS_BODY_BYTES - bytes.len() {
                return Err(AppError::PayloadTooLarge);
            }
            bytes.extend_from_slice(&data);
        }
        // This byte scan enforces only the nesting budget; serde performs the sole parse.
        let mut depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        for byte in bytes.iter() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == b'"' {
                    quoted = false;
                }
            } else {
                match *byte {
                    b'"' => quoted = true,
                    b'{' | b'[' => {
                        depth += 1;
                        if depth > MAX_JSON_DEPTH {
                            return Err(malformed());
                        }
                    }
                    b'}' | b']' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
        }
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| malformed())?;
        let occurred_at = time::OffsetDateTime::parse(
            &envelope.occurred_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| malformed())?
        .to_offset(time::UtcOffset::UTC);
        let occurred = occurred_at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| malformed())?;
        let data = envelope.data.0;
        if serde_json_canonicalizer::to_vec(&data)
            .map_err(|_| malformed())?
            .len()
            > MAX_NORMALIZED_DATA_BYTES
        {
            return Err(AppError::PayloadTooLarge);
        }
        let canonical = serde_json_canonicalizer::to_vec(&serde_json::json!({
            "eventType": envelope.event_type,
            "occurredAt": occurred,
            "data": data,
        }))
        .map_err(|_| malformed())?;
        // Store and execute exactly the interpretation that was fingerprinted.
        let normalized = serde_json::from_slice(&canonical).map_err(|_| malformed())?;
        entry
            .accept(VerifiedAutomationDelivery::from_verified_source(
                receiver.clone(),
                key_revision,
                AutomationSourcePrincipal::SenderKey {
                    receiver_id: receiver.clone(),
                },
                envelope.event_id,
                AutomationReceiverAdapter::SenderKey,
                envelope.event_type,
                Some(occurred_at),
                normalized,
                Sha256::digest(&canonical).into(),
                None,
            ))
            .await
    }
    .await;
    match outcome {
        Ok(AutomationIngressOutcome::Accepted(receipt)) => {
            Ok((StatusCode::ACCEPTED, Json(receipt)))
        }
        Ok(AutomationIngressOutcome::Replayed(receipt)) => Ok((StatusCode::OK, Json(receipt))),
        Err(error) => Err(refused(entry, &receiver, error).await),
    }
}

// Count registered refusal reasons for a known receiver; the original refusal is returned
// even when the content-free counter cannot be written.
async fn refused(
    entry: &AutomationDeliveryEntry,
    receiver: &AutomationReceiverId,
    error: AppError,
) -> HttpError {
    let reason = match &error {
        AppError::AutomationSourceUnauthorized => Some(AutomationRefusalReason::SourceUnauthorized),
        AppError::AutomationNotAccepting => Some(AutomationRefusalReason::NotAccepting),
        AppError::EventNotAccepted => Some(AutomationRefusalReason::EventNotAccepted),
        AppError::EventOutsideWindow => Some(AutomationRefusalReason::EventOutsideWindow),
        AppError::MalformedPayload { .. } => Some(AutomationRefusalReason::MalformedPayload),
        AppError::PayloadTooLarge => Some(AutomationRefusalReason::PayloadTooLarge),
        AppError::AutomationRateLimited => Some(AutomationRefusalReason::RateLimited),
        _ => None,
    };
    if let Some(reason) = reason
        && let Err(failure) = entry.record_refusal(receiver, reason).await
    {
        tracing::warn!(code = %failure.code(), "automation refusal counter unavailable");
    }
    error.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use http::{Request, header::COOKIE};
    use openbot_application::automation::AutomationDeliveries;
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct Port {
        accepted: Mutex<Vec<(Value, [u8; 32], AutomationOperationId)>>,
        refusals: Mutex<Vec<AutomationRefusalReason>>,
        authenticated: std::sync::atomic::AtomicUsize,
        hold: Option<Arc<tokio::sync::Semaphore>>,
    }

    #[async_trait]
    impl AutomationDeliveries for Port {
        async fn authenticate(
            &self,
            _: &AutomationReceiverId,
            presented: &SecretBytes,
        ) -> Result<AutomationRevision, AppError> {
            self.authenticated
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(hold) = &self.hold {
                drop(hold.acquire().await);
            }
            if presented.expose() != KEY.as_bytes() {
                return Err(AppError::AutomationSourceUnauthorized);
            }
            Ok(AutomationRevision::try_from(1).unwrap())
        }
        async fn admit(
            &self,
            delivery: VerifiedAutomationDelivery,
        ) -> Result<AutomationIngressOutcome, AppError> {
            self.accepted.lock().unwrap().push((
                delivery.normalized_data().clone(),
                *delivery.fingerprint(),
                delivery.source_event_key().clone(),
            ));
            Ok(AutomationIngressOutcome::Accepted(
                AutomationIngressReceipt {
                    receipt_id: AutomationReceiptId::try_from("adel:one".to_owned()).unwrap(),
                    status: AutomationDeliveryStatus::Accepted,
                },
            ))
        }
        async fn record_refusal(
            &self,
            _: &AutomationReceiverId,
            reason: AutomationRefusalReason,
        ) -> Result<(), AppError> {
            self.refusals.lock().unwrap().push(reason);
            Ok(())
        }
    }

    fn router(port: Arc<Port>) -> axum::Router {
        routes(AutomationDeliveryEntry::new(port))
    }

    fn request() -> http::request::Builder {
        Request::post("/api/automation-ingress/receiver")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {KEY}"))
    }

    async fn send(
        router: &axum::Router,
        builder: http::request::Builder,
        body: Body,
    ) -> (u16, Value, HeaderMap) {
        let response = router
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            headers,
        )
    }

    fn envelope(data: &str) -> String {
        format!(
            r#"{{"eventId":"evt-1","eventType":"push","occurredAt":"2026-11-10T08:00:00Z","data":{data}}}"#
        )
    }

    #[tokio::test]
    async fn jcs_rfc8785_vectors_and_utc_normalization() {
        let port = Arc::new(Port::default());
        let router = router(port.clone());
        // RFC 8785 section 3.2.2 number and string vector, and the UTF-16 key-order vector.
        let data = r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],
            "string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false],
            "order":{"\u20ac":1,"\r":2,"\ufb33":3,"1":4,"\ud83d\ude00":5,"\u0080":6,"\u00f6":7}}"#;
        let (status, body, headers) = send(&router, request(), Body::from(envelope(data))).await;
        assert_eq!(status, 202);
        assert_eq!(body, json!({"receiptId":"adel:one","status":"accepted"}));
        assert_eq!(
            headers.get(http::header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let expected = "{\"data\":{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\
\"order\":{\"\\r\":2,\"1\":4,\"\u{80}\":6,\"\u{f6}\":7,\"\u{20ac}\":1,\"\u{1f600}\":5,\"\u{fb33}\":3},\
\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"},\"eventType\":\"push\",\"occurredAt\":\"2026-11-10T08:00:00Z\"}";
        let (normalized, fingerprint, _) = port.accepted.lock().unwrap()[0].clone();
        assert_eq!(
            fingerprint,
            <[u8; 32]>::from(Sha256::digest(expected.as_bytes()))
        );
        assert_eq!(normalized, serde_json::from_str::<Value>(expected).unwrap());

        // Key order, number spelling and offset/fraction spelling do not change the fingerprint.
        for (occurred, data) in [
            (
                "2026-11-10T08:00:00.500Z",
                r#"{"a":1,"b":[1.0,2],"c":9007199254740993}"#,
            ),
            (
                "2026-11-10T10:00:00.5+02:00",
                r#"{"c":9007199254740992,"b":[1,2.0],"a":1.00}"#,
            ),
            (
                "2026-11-10T08:00:00.50000-00:00",
                r#"{"b":[10e-1,2],"a":100e-2,"c":9.007199254740992e15}"#,
            ),
        ] {
            let body = format!(
                r#"{{"data":{data},"occurredAt":"{occurred}","eventType":"push","eventId":"evt-2"}}"#
            );
            assert_eq!(send(&router, request(), Body::from(body)).await.0, 202);
        }
        let accepted = port.accepted.lock().unwrap();
        let canonical = br#"{"data":{"a":1,"b":[1,2],"c":9007199254740992},"eventType":"push","occurredAt":"2026-11-10T08:00:00.5Z"}"#;
        for (normalized, fingerprint, _) in &accepted[1..] {
            assert_eq!(*fingerprint, <[u8; 32]>::from(Sha256::digest(canonical)));
            assert_eq!(
                normalized["data"],
                json!({"a":1,"b":[1,2],"c":9007199254740992_u64})
            );
        }
    }

    #[tokio::test]
    async fn envelope_is_closed_stream_bounded_and_uncompressed() {
        let port = Arc::new(Port::default());
        let router = router(port.clone());
        for (body, status) in [
            (
                envelope("{}").replace("\"data\"", "\"actorId\":\"x\",\"data\""),
                400,
            ),
            (
                r#"{"eventId":"e","eventType":"push","data":{}}"#.to_owned(),
                400,
            ),
            (
                envelope("{}").replace(
                    "\"eventId\":\"evt-1\"",
                    "\"eventId\":\"evt-1\",\"eventId\":\"evt-2\"",
                ),
                400,
            ),
            (envelope(r#"{"a":{"b":1,"\u0062":2}}"#), 400),
            (envelope(r#"{"\u0000":1}"#), 400),
            (envelope(r#"[{"a":"\u0000"}]"#), 400),
            (envelope(r#"{"a":"\\u0000"}"#), 202),
            (envelope(r#"1e400"#), 400),
            (
                envelope("{}").replace("2026-11-10T08:00:00Z", "yesterday"),
                400,
            ),
            (
                envelope(&format!("{}0{}", "[".repeat(15), "]".repeat(15))),
                202,
            ),
            (
                envelope(&format!("{}0{}", "[".repeat(16), "]".repeat(16))),
                400,
            ),
            (envelope(&format!("\"{}\"", "x".repeat(64 * 1024))), 413),
        ] {
            assert_eq!(
                send(&router, request(), Body::from(body.clone())).await.0,
                status,
                "{body:.80}"
            );
        }
        // Exactly 256 KiB streamed in chunks without Content-Length is admitted, one byte more is 413.
        let base = envelope("{}");
        for (extra, status) in [(0, 202), (1, 413)] {
            let mut bytes = base.clone().into_bytes();
            bytes.resize(MAX_INGRESS_BODY_BYTES + extra, b' ');
            let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
                bytes.chunks(1000).map(|c| Ok(c.to_vec())).collect();
            let body = Body::from_stream(futures_util::stream::iter(chunks));
            assert_eq!(send(&router, request(), body).await.0, status);
        }
        let gzip = request().header(CONTENT_ENCODING, "gzip");
        assert_eq!(send(&router, gzip, Body::from(envelope("{}"))).await.0, 400);
        let text = Request::post("/api/automation-ingress/receiver")
            .header(CONTENT_TYPE, "text/plain")
            .header(AUTHORIZATION, format!("Bearer {KEY}"));
        assert_eq!(send(&router, text, Body::from(envelope("{}"))).await.0, 400);
        let reasons = port.refusals.lock().unwrap().clone();
        assert!(reasons.contains(&AutomationRefusalReason::MalformedPayload));
        assert!(reasons.contains(&AutomationRefusalReason::PayloadTooLarge));
    }

    #[tokio::test]
    async fn cookie_is_not_authentication_and_query_key_rejected() {
        let port = Arc::new(Port::default());
        let router = router(port.clone());
        let cookie = Request::post("/api/automation-ingress/receiver")
            .header(CONTENT_TYPE, "application/json")
            .header(COOKIE, "wrok_session=valid-owner-session");
        let (status, body, headers) = send(&router, cookie, Body::from(envelope("{}"))).await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], "automation_source_unauthorized");
        assert!(headers.get(http::header::SET_COOKIE).is_none());
        let query = Request::post(format!("/api/automation-ingress/receiver?key={KEY}"))
            .header(CONTENT_TYPE, "application/json");
        assert_eq!(
            send(&router, query, Body::from(envelope("{}"))).await.0,
            401
        );
        let path = Request::post(format!("/api/automation-ingress/{KEY}"))
            .header(CONTENT_TYPE, "application/json");
        assert_eq!(send(&router, path, Body::from(envelope("{}"))).await.0, 401);
        let wrong = Request::post("/api/automation-ingress/receiver")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Bearer 00");
        let (status, body, _) = send(&router, wrong, Body::from(envelope("{}"))).await;
        assert_eq!(status, 401);
        assert!(!body.to_string().contains("evt-1"));
        // Even with a valid key, a query string is refused rather than ignored.
        let both = request().uri(format!("/api/automation-ingress/receiver?key={KEY}"));
        assert_eq!(send(&router, both, Body::from(envelope("{}"))).await.0, 400);
        assert_eq!(port.accepted.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn rate_limit_and_inflight_project_429_retry_after() {
        let hold = Arc::new(tokio::sync::Semaphore::new(0));
        let port = Arc::new(Port {
            hold: Some(hold.clone()),
            ..Port::default()
        });
        let router = router(port.clone());
        let mut waiting = Vec::new();
        for _ in 0..MAX_IN_FLIGHT {
            let router = router.clone();
            waiting.push(tokio::spawn(async move {
                send(&router, request(), Body::from(envelope("{}"))).await.0
            }));
        }
        while port.authenticated.load(std::sync::atomic::Ordering::SeqCst) < MAX_IN_FLIGHT {
            tokio::task::yield_now().await;
        }
        let (status, body, headers) = send(&router, request(), Body::from(envelope("{}"))).await;
        assert_eq!(status, 429);
        assert_eq!(body["code"], "automation_rate_limited");
        assert_eq!(headers.get(http::header::RETRY_AFTER).unwrap(), "1");
        hold.add_permits(MAX_IN_FLIGHT);
        for task in waiting {
            assert_eq!(task.await.unwrap(), 202);
        }
    }
}
