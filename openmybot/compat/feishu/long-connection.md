# Feishu long connection

The Feishu long-connection wire protocol as this project implements it, and how it differs from the official SDKs. This record is not a version claim: the real-channel recheck is pending with the owner. It holds no app id, ticket, tenant token, complete connection URL, absolute path or credential.

## Sources and check date

There is no official Rust SDK; the wire protocol follows the source of the two official SDKs at the commits below. Every source was read as a web page; nothing was downloaded or cloned.

| Source | Revision |
|---|---|
| Go SDK <https://github.com/larksuite/oapi-sdk-go> | branch `v3_main` head = tag `v3.12.2` = commit `db9f52d0a88e3f5e4ed81bb34d71a28e3f5608fa` (2026-10-15T08:18:30Z) |
| Go SDK `ws/` directory | last change in commit `acd08255f3e2fbd5268293d55fc0c0ce74093d43` (2026-10-15T07:10:33Z); files read: `ws/pbbp2.pb.go`, `ws/const.go`, `ws/model.go`, `ws/client.go`, `ws/client_message.go`, `ws/client_session.go`, `ws/client_transport.go`, `ws/connection_config.go` |
| Python SDK <https://github.com/larksuite/oapi-sdk-python> | branch `v2_main` head = commit `0d9749a4728446a0ffa2e8374b37b5e1ce1cfd9c` (2026-10-15T08:56:07Z); files read: `lark_oapi/ws/client.py`, `lark_oapi/core/json.py` |
| Receiving events over the long connection | <https://open.feishu.cn/document/server-docs/event-subscription-guide/event-subscription-configure-/request-url-configuration-case> |
| Event subscription overview | <https://open.feishu.cn/document/server-docs/event-subscription-guide/overview> |
| `im.message.receive_v1` | <https://open.feishu.cn/document/server-docs/im-v1/message/events/receive> |
| Self-built app `tenant_access_token` | <https://open.feishu.cn/document/server-docs/authentication-management/access-token/tenant_access_token_internal> |
| Send message | <https://open.feishu.cn/document/server-docs/im-v1/message/create> |
| Common error codes | <https://open.feishu.cn/document/ukTMukTMukTM/ugjM14COyUjL4ITN> |

Check date (UTC): 2026-10-29. The three commits above were rechecked on that date and were unchanged.

## Endpoint

| Item | SDKs | This project |
|---|---|---|
| Request | `POST <domain>/callback/ws/endpoint`. Go sends `locale: zh`, `Content-Type: application/json` (no charset) and its `User-Agent`; Go body `{"AppID","AppSecret","ClientAssertion"}` with `ClientAssertion` an empty string in secret mode; Python body `{"AppID","AppSecret"}` | Body has exactly the two keys `AppID` and `AppSecret`; headers are the closed set of the safe HTTP client (`Content-Type: application/json`, no `locale`, no custom `User-Agent`) |
| Response | `{"code","msg","data":{"URL","ClientConfig":{"ReconnectCount","ReconnectInterval","ReconnectNonce","PingInterval"}}}`; `URL`, `ClientConfig` and the four integers (seconds) may be absent | Same shape; only `PingInterval` is read |
| `code` 0 | Success | Connect to `data.URL` |
| HTTP status other than 200; `code` 1 (system busy) or 1000040343 (internal error); empty `data` or `URL` | Server error, retried | `connect_failed` gap, then backoff |
| Any other `code` | Client error, not retried | Receiver suspended with `credential_rejected`, no reconnect |
| Time limit | Go HTTP client 10 seconds | 15 seconds for the whole request (`HTTP_SEND_TIMEOUT`) |

## Connection

| Item | Rule |
|---|---|
| URL shape | `wss://<host>/<path>?device_id=<id>&service_id=<n>`; the complete URL is never logged or recorded |
| URL checks | Parseable, scheme `ws` or `wss`, non-empty host, no userinfo, no fragment; production accepts `wss` only; the shape is checked by the safe dialer and a failure is a `connect_failed` gap |
| `device_id` | Connection id, not used by this project |
| `service_id` | Decimal int32 from the first form-decoded query value, as the Go SDK reads it; empty or invalid gives 0; used as `service` of every ping frame |
| Message and frame size | WebSocket single message and single frame at most 1 MiB |
| Connect time limit | 15 seconds for TCP connect, TLS and upgrade together |
| Outbound path | Only through the safe dialer (resolution, address policy, TLS); the daemon never listens on TCP |

A refused upgrade (any status other than 101) is classified from its headers:

| Response | SDKs | This project |
|---|---|---|
| `Handshake-Status` (integer; missing, unparseable or 0 means the HTTP status), `Handshake-Msg`, `Handshake-Autherrcode` | Read for classification | Same |
| 403 | Client error, not retried | Receiver suspended with `credential_rejected` |
| 514 with `Handshake-Autherrcode` 1000040350 (connection limit exceeded) | Client error, not retried | `connect_failed` gap, then backoff |
| 514 otherwise, and any other status | Server error, retried | `connect_failed` gap, then backoff |

## Frames

Frames are protobuf proto2 messages of package `pbbp2`, carried in WebSocket Binary messages. Other WebSocket message types are ignored. The codec is hand-written; no protobuf crate is used.

| Message | Field | Name | Type | Wire type / tag byte | Encoding |
|---|---|---|---|---|---|
| Frame | 1 | `SeqID` | uint64, required | varint / `08` | Always written |
| Frame | 2 | `LogID` | uint64, required | varint / `10` | Always written |
| Frame | 3 | `service` | int32, required | varint / `18` | Always written; negative values sign-extend to 10 bytes |
| Frame | 4 | `method` | int32, required | varint / `20` | Always written; 0 = control, 1 = data |
| Frame | 5 | `headers` | repeated Header | length-delimited / `2a` | One per header, in order |
| Frame | 6 | `payload_encoding` | string, optional | length-delimited / `32` | Always written (empty as `32 00`) |
| Frame | 7 | `payload_type` | string, optional | length-delimited / `3a` | Always written (empty as `3a 00`) |
| Frame | 8 | `payload` | bytes, optional | length-delimited / `42` | Written only when present (empty as `42 00`) |
| Frame | 9 | `LogIDNew` | string, optional | length-delimited / `4a` | Always written (empty as `4a 00`) |
| Header | 1 | `key` | string, required | length-delimited / `0a` | Always written |
| Header | 2 | `value` | string, required | length-delimited / `12` | Always written |

Fields are written in ascending order. Decoding skips unknown fields of the varint, 64-bit, length-delimited and 32-bit wire types, and refuses truncation, out-of-range lengths, a known field with the wrong wire type, groups, varints longer than 10 bytes and non-UTF-8 strings.

| Header key | Use |
|---|---|
| `type` | `event`, `card`, `ping` or `pong` |
| `message_id`, `sum`, `seq` | Fragment identity, count and index |
| `trace_id`, `instance_id`, `timestamp` | Carried, not interpreted |
| `biz_rt` | Processing time in milliseconds, added to an acknowledgement |

Codes: OK 0, system busy 1, forbidden 403, authentication failed 514, connection limit exceeded 1000040350, internal error 1000040343.

Vectors (lower-case hex):

- V1, the ping frame for `service` 7 (28 bytes): `08001000180720002a0c0a0474797065120470696e6732003a004a00`
- V2, a platform data frame with `SeqID` 300, `LogID` 1, `service` 7, headers `type=event`, `message_id=m1`, `sum=1`, `seq=0`, `trace_id=t1` and payload `{}`, without fields 6, 7 and 9 (82 bytes): `08ac021001180720012a0d0a047479706512056576656e742a100a0a6d6573736167655f696412026d312a080a0373756d1201312a080a037365711201302a0e0a0874726163655f69641202743142027b7d`
- V3, the acknowledgement of V2 with `biz_rt=3` (138 bytes): `08ac021001180720012a0d0a047479706512056576656e742a100a0a6d6573736167655f696412026d312a080a0373756d1201312a080a037365711201302a0e0a0874726163655f6964120274312a0b0a0662697a5f727412013332003a0042277b22636f6465223a3230302c2268656164657273223a6e756c6c2c2264617461223a6e756c6c7d4a00`

## Heartbeat

| Item | SDKs | This project |
|---|---|---|
| Ping frame | `SeqID` 0, `LogID` 0, `service` = `service_id`, `method` 0, the single header `type=ping`, no payload | Same |
| First ping | Right after the connection opens | Same |
| Interval | `PingInterval` from `ClientConfig`; default 120 seconds | Same default; a `PingInterval` is adopted only when it is a positive integer |
| Pong | Control frame with `type=pong`; a non-empty payload is `ClientConfig` JSON, and all four fields are assigned (missing ones become 0) | Only a positive `PingInterval` is adopted from the endpoint reply or a pong |
| Server ping | Ignored | Ignored |
| Read timeout | After every successful read, 2 × `PingInterval` + 5 seconds | Same formula; expiry is a `stream_broken` gap |
| Write timeout | 10 seconds | 10 seconds; expiry is a `stream_broken` gap |

## Data frames and acknowledgement

| Item | Rule |
|---|---|
| Fragments | With `sum` > 1, fragments are buffered by `message_id` at index `seq`; the buffer lives 5 seconds, refreshed by each fragment; a complete set is joined in `seq` order. Intermediate fragments are not acknowledged |
| Size limit | This project caps the buffered total at 1 MiB; exceeding it closes the connection as `stream_broken` |
| Types | Only `type=event` is processed; `card` and unknown types are neither processed nor acknowledged |
| Acknowledgement frame | The inbound frame (for fragments, the one that completed the set) with its headers plus `biz_rt`, payload replaced by exactly `{"code":200,"headers":null,"data":null}` (39 bytes); every other field keeps its inbound value; written as a Binary message on the same connection |
| Budget | 2 seconds from the arrival of the last fragment on the monotonic clock (`FS_ACK_BUDGET`) |
| Acknowledged | A committed acceptance of any disposition, an unparseable payload and an event type other than `im.message.receive_v1` |
| Not acknowledged | An acceptance that did not commit, one that exceeded the budget, and a receiver that is no longer active; no failure-shaped reply is ever written |

## Reconnect

The SDKs retry every error except client errors, waiting a random first delay within `ReconnectNonce` (default 30 seconds), then `ReconnectInterval` (default 120 seconds), for `ReconnectCount` attempts (default unlimited), all three overwritten by any `ClientConfig`. This project ignores those parameters and uses its own backoff for every retried failure: from 1 second doubling to 60 seconds, full jitter (a uniform wait between zero and the bound). A client error (an endpoint `code` other than 0, 1 and 1000040343, or a 403 upgrade) suspends the receiver with `credential_rejected` and it does not reconnect. A successful upgrade closes the open `connect_failed` or `stream_broken` gap and resets the backoff.

## Events and sending

| Item | Rule |
|---|---|
| Envelope | `schema` `"2.0"`; event key `header.event_id` (printable ASCII, at most 128 bytes, otherwise unparseable); event type `header.event_type` must be `im.message.receive_v1`, otherwise unsupported |
| Fields read | `event.sender.sender_id.open_id`, `event.message.chat_id`, `event.message.message_id`, `event.message.message_type`, `event.message.content`, `event.message.chat_type`; `sender_type` is not read |
| Occurred at | `header.create_time` in milliseconds: a string of 1 to 19 ASCII digits or a non-negative JSON integer |
| Private chat | `chat_type` = `p2p` |
| Content | `message_type` `text` with JSON `content` holding a string `text` (without NUL) is a text; any other `message_type` is other content; anything else, or a missing fingerprint field, is malformed |
| Identities | `feishu:<open_id>` and `feishu:<chat_id>`, at most 128 bytes of printable ASCII |
| Fingerprint | SHA-256 of the canonical JSON `{"data":{"chatId","content","messageId","messageType","openId"},"eventType":"feishu.im.message.receive_v1","occurredAt":<RFC 3339 UTC, milliseconds>}` with sorted keys |
| Token | `POST <domain>/open-apis/auth/v3/tenant_access_token/internal` with `{"app_id","app_secret"}`; reads `code`, `tenant_access_token` and `expire` (seconds). The token is cached per receiver binding and revision on the wall clock and refreshed when less than 30 minutes remain |
| Token outcomes | Granted on HTTP 200, `code` 0, a non-empty token and a positive `expire`; unreachable, HTTP 429, HTTP 5xx and `code` 99991400 retry; anything else is rejected |
| Send | `POST <domain>/open-apis/im/v1/messages?receive_id_type=chat_id` with `Authorization: Bearer <tenant token>` and exactly four body keys: `receive_id` (the chat id), `msg_type` `"text"`, `content` the JSON string `{"text":<body>}`, `uuid` the lower-case hex of the first 16 bytes of the SHA-256 of the delivery's idempotency key (32 characters; the platform's one-hour deduplication window covers the delivery retry plan) |
| Send outcomes | `data.message_id` is recorded on success; HTTP 429, HTTP 5xx and the rate-limit codes 230020 and 99991400 (carried on HTTP 400) retry as rate limited or server error; a failure after the request left is unknown; other refusals fail as client errors |

## Platform limits

| Limit | Value |
|---|---|
| App type | Self-built enterprise apps only |
| Connections | At most 50 per app |
| Several connections | Cluster mode: each event goes to one connection at random |
| Processing time | An event must be handled within 3 seconds |
| Subscription | The long connection must be open before the event subscription mode can be saved in the developer console |

## Divergences and not covered

| Topic | Note |
|---|---|
| Deduplication key | The event page names `message_id`, the overview names `event_id`; this project keys on `event_id`. A redelivery of the same message under a new `event_id` would start one more run |
| Offline retention | None: events during a disconnection are lost. Platform redelivery of unacknowledged events (after 15 seconds, 5 minutes, 1 hour and 6 hours, at most 4 times) coexists and is absorbed by deduplication |
| Token interface | The legacy-version notice at the top of the token page and the newer `accounts.feishu.cn` interface are not implemented |
| Request headers | The safe HTTP client sends a closed header set: no `locale`, no custom `User-Agent`; `Content-Type: application/json` without charset, as both SDKs do. The owner's real-channel recheck covers this |
| `ClientConfig` values | The values the server actually sends are unknown and are to be recorded by the real-channel recheck |
| 514 with 1000040350 | Reconnects with backoff as a connect failure; the Go SDK does not retry |
| Missing `PingInterval` | The current interval is kept; the SDKs set 0 |
| `ClientAssertion` | Not written in the endpoint body, as in the Python SDK; the Go SDK writes an empty string |
| Acknowledgement payload | The Go form; the Python SDK writes `{"code": 200}` |
| Missing required frame fields | Decoded as zero values or empty strings; the Go SDK drops such a frame |

## Fake server

The in-repository fake open platform used by the tests implements each item of this record:

| Area | Behaviour |
|---|---|
| HTTP | Default replies on the token path (a fake token, `expire` 7200), the endpoint path (a loopback `ws` URL with `device_id` and `service_id`, optional `ClientConfig`) and the messages path (a fake `message_id`); scripted replies per path; any other method is refused with 405 |
| Upgrade | Scripted accept, refusal with a status and `Handshake-Status`, `Handshake-Msg` and `Handshake-Autherrcode` headers, or a hang without an answer |
| Events | Single-fragment and multi-fragment event frames whose `message_id` is the envelope's `event_id` |
| Acknowledgements | Each one checked field by field against the pushed frame, with its arrival time |
| Heartbeat | Pings recorded and answered with a pong, optionally carrying `ClientConfig`; a silent mode that answers nothing |
| Connection | Server-side close; a push without a connection is dropped and reported; after a reconnect the same `event_id` can be pushed again |
