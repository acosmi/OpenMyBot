//! The outbound sender: records run terminals from the engine's notices, then claims due Telegram
//! delivery rows and sends each through the receiver's endpoint. Nothing is logged: the request
//! URL carries the bot token.
use crate::{
    ChannelError, Connection, DELIVERY_BODY_MAX, OMB_RESULT_CANCELLED_V1, OMB_RESULT_FAILED_V1,
    OMB_RESULT_SUCCEEDED_V1, OMB_RESULT_UNKNOWN_V1, STORE_BUDGET, Task, TelegramEndpoint, Timings,
};
use omb_store::{
    Claimed, DeliveryContent, ErrorCode, Finish, RunResultFacts, TerminalKind, claim_delivery,
    finish_delivery, record_terminal, run_result_facts, send_target,
};
use openbot_application::{RunTerminalKind, RunTerminalNotice, RunTerminalSubscriber};
use openbot_contracts::ids::ActorId;
use openbot_domain::vault::{SecretKind, SecretPrincipal, ServiceId};
use openbot_infra::{
    net::safe_http::{SafeHttpBudget, SafeHttpError, SafeHttpRequest},
    vault::CredentialRecordVault,
};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{
        Notify,
        mpsc::{self, error::TryRecvError},
        oneshot,
    },
    time::Instant,
};

/// The engine's terminal subscriber: it only enqueues; a full or closed queue drops the notice,
/// which reconciliation recovers.
pub struct TerminalQueue(pub mpsc::Sender<RunTerminalNotice>);
impl RunTerminalSubscriber for TerminalQueue {
    fn on_run_terminal(&self, notice: RunTerminalNotice) {
        let _ = self.0.try_send(notice);
    }
}

#[derive(Clone)]
pub struct SenderContext {
    pub vault: CredentialRecordVault,
    pub owner: ActorId,
    pub endpoint: TelegramEndpoint,
    pub timings: Timings,
    /// The dispatcher's wake-up, signalled after a first terminal write.
    pub wake: Arc<Notify>,
}

/// Bytes read of one `sendMessage` response.
pub(crate) const SEND_RESPONSE_MAX: usize = 64 * 1024;

/// Starts the sender; a stop takes effect between two sends, never during one.
pub fn start_sender(
    connection: Connection,
    context: SenderContext,
    terminals: mpsc::Receiver<RunTerminalNotice>,
) -> Task {
    Task::spawn(connection, move |client, stop| {
        send(client, context, terminals, stop)
    })
}
async fn send(
    mut client: tokio_postgres::Client,
    context: SenderContext,
    mut terminals: mpsc::Receiver<RunTerminalNotice>,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), ChannelError> {
    let store = |_| ChannelError::StoreFailed;
    let mut queue_open = true;
    let mut received = None;
    while matches!(stop.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
        loop {
            let notice: RunTerminalNotice = match received.take() {
                Some(notice) => notice,
                None if queue_open => match terminals.try_recv() {
                    Ok(notice) => notice,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        queue_open = false;
                        break;
                    }
                },
                None => break,
            };
            let written = record_terminal(
                &mut client,
                notice.run_id.as_str(),
                terminal_kind(notice.terminal),
                Instant::now() + STORE_BUDGET,
            )
            .await
            .map_err(store)?;
            if written.is_some_and(|terminal| terminal.written) {
                context.wake.notify_one();
            }
        }
        if let Some(claimed) = claim_delivery(&client, Instant::now() + STORE_BUDGET)
            .await
            .map_err(store)?
        {
            deliver(&client, &context, claimed).await?;
            continue;
        }
        tokio::select! {
            _ = &mut stop => return Ok(()),
            notice = terminals.recv(), if queue_open => match notice {
                Some(notice) => received = Some(notice),
                None => queue_open = false,
            },
            () = tokio::time::sleep(context.timings.delivery_poll) => {}
        }
    }
    Ok(())
}
/// One attempt of a claimed row: the binding and receiver are read again, the token is opened
/// from the receiver's envelope for this attempt only, and the outcome ends the attempt.
async fn deliver(
    client: &tokio_postgres::Client,
    context: &SenderContext,
    claimed: Claimed,
) -> Result<(), ChannelError> {
    let store = |_| ChannelError::StoreFailed;
    let timings = &context.timings;
    let target = send_target(client, claimed.binding_id, Instant::now() + STORE_BUDGET)
        .await
        .map_err(store)?;
    let message_id;
    let finish = 'decide: {
        if !target.sender_active {
            break 'decide Finish::Failed {
                code: ErrorCode::BindingInactive,
            };
        }
        let secret = target.receiver.as_ref().and_then(|receiver| {
            context
                .vault
                .open(
                    &receiver.binding_id,
                    SecretKind::Connector,
                    SecretPrincipal::Actor(context.owner.clone()),
                    SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
                    &receiver.credential_envelope,
                )
                .ok()
                .map(|opened| opened.into_secret())
        });
        let token = secret
            .as_ref()
            .and_then(|secret| std::str::from_utf8(secret.expose()).ok())
            .filter(|token| {
                target.receiver.as_ref().is_some_and(|receiver| {
                    token
                        .split_once(':')
                        .is_some_and(|(bot_id, _)| bot_id == receiver.source_key)
                })
            });
        let Some(token) = token else {
            break 'decide after_failure(
                claimed.attempts,
                ErrorCode::ReceiverInactive,
                None,
                &timings.delivery_retry,
            );
        };
        let Some(chat) = chat_id(&claimed.chat_key) else {
            break 'decide Finish::Failed {
                code: ErrorCode::ClientError,
            };
        };
        let text = match &claimed.content {
            DeliveryContent::Text(text) => text.clone(),
            DeliveryContent::RunResult { run_id } => {
                let facts = run_result_facts(client, run_id, Instant::now() + STORE_BUDGET)
                    .await
                    .map_err(store)?;
                compose_result(run_id, &facts)
            }
        };
        let mut url = context.endpoint.api_base.clone();
        url.set_path(&format!("/bot{token}/sendMessage"));
        let response = async {
            let budget = SafeHttpBudget::new(SEND_RESPONSE_MAX, timings.http_send_timeout)?;
            context
                .endpoint
                .dialer
                .execute(SafeHttpRequest::post_json_with_scheme(
                    url,
                    context.endpoint.scheme,
                    request_body(chat, &text),
                    None,
                    budget,
                )?)
                .await
        }
        .await;
        match classify(
            response
                .as_ref()
                .map(|response| (response.status().as_u16(), response.body()))
                .map_err(|error| *error),
        ) {
            Verdict::Sent { message_id: sent } => {
                message_id = sent;
                Finish::Sent {
                    platform_message_id: &message_id,
                }
            }
            Verdict::Retry { code, retry_after } => {
                after_failure(claimed.attempts, code, retry_after, &timings.delivery_retry)
            }
            Verdict::Failed { code } => Finish::Failed { code },
            Verdict::Unknown => Finish::Unknown {
                code: ErrorCode::ResultUnknown,
            },
        }
    };
    finish_delivery(
        client,
        claimed.delivery_id,
        finish,
        Instant::now() + STORE_BUDGET,
    )
    .await
    .map_err(store)
}

/// `[OpenMyBot] <state> · run <first 8 of the run id>`, the summary, then the artifact paths; over
/// `DELIVERY_BODY_MAX` the paths are dropped from the end first, then the summary is cut on a
/// character boundary.
pub(crate) fn compose_result(run_id: &str, facts: &RunResultFacts) -> String {
    let state = match facts.terminal {
        TerminalKind::Succeeded => OMB_RESULT_SUCCEEDED_V1.to_owned(),
        TerminalKind::Failed => OMB_RESULT_FAILED_V1.to_owned(),
        TerminalKind::Cancelled => OMB_RESULT_CANCELLED_V1.to_owned(),
        TerminalKind::ReconciliationRequired => OMB_RESULT_UNKNOWN_V1.replace("{run_id}", run_id),
    };
    let short: String = run_id.chars().take(8).collect();
    let mut text = format!("[OpenMyBot] {state} · run {short}");
    let mut summary = facts.result_summary.as_deref().unwrap_or_default();
    let summary_len = |summary: &str| match summary.len() {
        0 => 0,
        len => 1 + len,
    };
    let mut paths = facts.artifact_paths.as_slice();
    let paths_len = |paths: &[String]| match paths.len() {
        0 => 0,
        count => "\n成果：".len() + paths.iter().map(String::len).sum::<usize>() + count - 1,
    };
    while !paths.is_empty()
        && text.len() + summary_len(summary) + paths_len(paths) > DELIVERY_BODY_MAX
    {
        paths = &paths[..paths.len() - 1];
    }
    if text.len() + summary_len(summary) > DELIVERY_BODY_MAX {
        let mut cut = DELIVERY_BODY_MAX.saturating_sub(text.len() + 1);
        while !summary.is_char_boundary(cut) {
            cut -= 1;
        }
        summary = &summary[..cut];
    }
    if !summary.is_empty() {
        text.push('\n');
        text.push_str(summary);
    }
    if !paths.is_empty() {
        text.push_str("\n成果：");
        text.push_str(&paths.join("\n"));
    }
    text
}
/// The decimal chat id after the `telegram:` prefix.
pub(crate) fn chat_id(chat_key: &str) -> Option<i64> {
    chat_key
        .strip_prefix("telegram:")
        .filter(|digits| !digits.starts_with('+'))?
        .parse()
        .ok()
}
/// `{"chat_id": <integer>, "text": <text>}` and no other key: the text is sent as plain text.
pub(crate) fn request_body(chat_id: i64, text: &str) -> Vec<u8> {
    serde_json::json!({"chat_id": chat_id, "text": text})
        .to_string()
        .into_bytes()
}

/// What one `sendMessage` outcome means for the row.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Sent {
        message_id: String,
    },
    /// A definite failure that takes a retry slot.
    Retry {
        code: ErrorCode,
        retry_after: Option<Duration>,
    },
    Failed {
        code: ErrorCode,
    },
    /// The request may have reached the platform; never resent.
    Unknown,
}
pub(crate) fn classify(result: Result<(u16, &[u8]), SafeHttpError>) -> Verdict {
    match result {
        Err(
            SafeHttpError::DnsUnavailable
            | SafeHttpError::DestinationDenied
            | SafeHttpError::ConnectFailed
            | SafeHttpError::PeerMismatch
            | SafeHttpError::TlsFailed
            | SafeHttpError::InvalidUrl
            | SafeHttpError::SchemeRejected
            | SafeHttpError::InvalidBudget
            | SafeHttpError::InvalidHeader
            | SafeHttpError::InvalidAllowlist,
        ) => Verdict::Retry {
            code: ErrorCode::Unreachable,
            retry_after: None,
        },
        Err(
            SafeHttpError::DeadlineExceeded
            | SafeHttpError::ProtocolFailed
            | SafeHttpError::ResponseTooLarge
            | SafeHttpError::StreamStalled
            | SafeHttpError::RedirectInvalid
            | SafeHttpError::RedirectLimit
            | SafeHttpError::RedirectMethodRejected
            | SafeHttpError::SensitiveRedirectRejected,
        ) => Verdict::Unknown,
        Ok((429, body)) => Verdict::Retry {
            code: ErrorCode::RateLimited,
            retry_after: serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|body| {
                    body.pointer("/parameters/retry_after")
                        .and_then(Value::as_u64)
                })
                .map(Duration::from_secs),
        },
        Ok((500..=599, _)) => Verdict::Retry {
            code: ErrorCode::ServerError,
            retry_after: None,
        },
        Ok((200..=299, body)) => serde_json::from_slice::<Value>(body)
            .ok()
            .filter(|body| body.get("ok") == Some(&Value::Bool(true)))
            .and_then(|body| body.pointer("/result/message_id").and_then(Value::as_i64))
            .map_or(Verdict::Unknown, |id| Verdict::Sent {
                message_id: id.to_string(),
            }),
        Ok(_) => Verdict::Failed {
            code: ErrorCode::ClientError,
        },
    }
}
/// A definite failure of the `attempts`-th claim: retried after the planned wait, or after the
/// platform's longer wait, until the sixth claim fails as exhausted.
pub(crate) fn after_failure(
    attempts: u32,
    code: ErrorCode,
    retry_after: Option<Duration>,
    schedule: &[Duration; 5],
) -> Finish<'static> {
    match attempts
        .checked_sub(1)
        .and_then(|index| schedule.get(index as usize))
    {
        Some(planned) => Finish::Retry {
            after: (*planned).max(retry_after.unwrap_or_default()),
            code,
        },
        None => Finish::Failed {
            code: ErrorCode::RetriesExhausted,
        },
    }
}
pub(crate) fn terminal_kind(kind: RunTerminalKind) -> TerminalKind {
    match kind {
        RunTerminalKind::Succeeded => TerminalKind::Succeeded,
        RunTerminalKind::Failed => TerminalKind::Failed,
        RunTerminalKind::Cancelled => TerminalKind::Cancelled,
        RunTerminalKind::ReconciliationRequired => TerminalKind::ReconciliationRequired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::ids::{DeploymentId, RunId, TenantId, ThreadId};

    const RUN: &str = "0192f1a2-3b4c-7d5e-8f60-718293a4b5c6";
    fn facts(terminal: TerminalKind, summary: Option<&str>, paths: &[&str]) -> RunResultFacts {
        RunResultFacts {
            terminal,
            result_summary: summary.map(str::to_owned),
            artifact_paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        }
    }
    fn retry(finish: Finish<'_>) -> (Duration, ErrorCode) {
        match finish {
            Finish::Retry { after, code } => (after, code),
            _ => panic!("not a retry"),
        }
    }
    fn notice(run: &str) -> RunTerminalNotice {
        RunTerminalNotice {
            deployment: DeploymentId::new("deployment"),
            tenant: TenantId::new("tenant"),
            thread_id: ThreadId::new("thread"),
            run_id: RunId::new(run),
            terminal: RunTerminalKind::Succeeded,
        }
    }

    #[test]
    fn first_line_uses_state_text_and_first_eight_of_run_id_for_each_kind() {
        for (kind, line) in [
            (TerminalKind::Succeeded, "[OpenMyBot] 已完成 · run 0192f1a2"),
            (TerminalKind::Failed, "[OpenMyBot] 失败 · run 0192f1a2"),
            (TerminalKind::Cancelled, "[OpenMyBot] 已取消 · run 0192f1a2"),
        ] {
            assert_eq!(compose_result(RUN, &facts(kind, None, &[])), line);
        }
        let unknown = compose_result(RUN, &facts(TerminalKind::ReconciliationRequired, None, &[]));
        assert_eq!(
            unknown,
            format!(
                "[OpenMyBot] 结果未知，在本机执行 openmybot status --run {RUN} 核对 · run 0192f1a2"
            )
        );
        assert!(unknown.contains(RUN));
        assert!(!unknown.contains('\n'));
    }
    #[test]
    fn body_is_first_line_summary_and_artifacts_line() {
        let text = compose_result(
            RUN,
            &facts(
                TerminalKind::Succeeded,
                Some("wrote /srv/project/out.txt"),
                &["out.txt", "docs/a.md"],
            ),
        );
        assert_eq!(
            text,
            "[OpenMyBot] 已完成 · run 0192f1a2\nwrote /srv/project/out.txt\n成果：out.txt\ndocs/a.md"
        );
    }
    #[test]
    fn body_without_summary_or_without_artifacts_omits_that_line() {
        for summary in [None, Some("")] {
            assert_eq!(
                compose_result(RUN, &facts(TerminalKind::Succeeded, summary, &["a.txt"])),
                "[OpenMyBot] 已完成 · run 0192f1a2\n成果：a.txt"
            );
        }
        assert_eq!(
            compose_result(RUN, &facts(TerminalKind::Succeeded, Some("done"), &[])),
            "[OpenMyBot] 已完成 · run 0192f1a2\ndone"
        );
    }
    #[test]
    fn oversized_body_drops_paths_from_the_end_before_touching_the_summary() {
        let summary = "s".repeat(2048);
        let paths: Vec<String> = (0..20)
            .map(|n| format!("{n:02}-{}", "p".repeat(60)))
            .collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let text = compose_result(RUN, &facts(TerminalKind::Succeeded, Some(&summary), &refs));
        assert!(text.len() <= DELIVERY_BODY_MAX);
        assert!(text.contains(&format!("\n{summary}\n成果：")));
        let kept = text.split("\n成果：").nth(1).unwrap().split('\n').count();
        assert!(kept < 20);
        assert_eq!(
            text.split("\n成果：")
                .nth(1)
                .unwrap()
                .split('\n')
                .collect::<Vec<_>>(),
            refs[..kept]
        );
        // One more path would not have fitted.
        assert!(text.len() + 1 + refs[kept].len() > DELIVERY_BODY_MAX);
        let huge = "q".repeat(DELIVERY_BODY_MAX);
        let alone = compose_result(
            RUN,
            &facts(TerminalKind::Succeeded, Some("done"), &[huge.as_str()]),
        );
        assert_eq!(alone, "[OpenMyBot] 已完成 · run 0192f1a2\ndone");
    }
    #[test]
    fn still_oversized_body_truncates_summary_on_a_char_boundary_without_ellipsis() {
        for unit in ["界", "ab", "é", "😀"] {
            let summary = unit.repeat(DELIVERY_BODY_MAX);
            let text = compose_result(
                RUN,
                &facts(TerminalKind::Failed, Some(&summary), &["a.txt"]),
            );
            assert!(text.len() <= DELIVERY_BODY_MAX, "{unit}");
            assert!(text.len() > DELIVERY_BODY_MAX - unit.len() - 1, "{unit}");
            assert!(!text.contains("成果："));
            assert!(!text.ends_with('…'));
            let body = text.split_once('\n').unwrap().1;
            assert!(summary.starts_with(body));
            assert!(std::str::from_utf8(text.as_bytes()).is_ok());
        }
    }
    #[test]
    fn chat_id_is_the_decimal_after_the_telegram_prefix() {
        assert_eq!(chat_id("telegram:42"), Some(42));
        assert_eq!(chat_id("telegram:-100123"), Some(-100_123));
        for key in [
            "42",
            "feishu:42",
            "telegram:",
            "telegram:4x2",
            "telegram:+42",
            "telegram:0x2a",
            "telegram:99999999999999999999",
        ] {
            assert_eq!(chat_id(key), None, "{key}");
        }
    }
    #[test]
    fn request_body_has_exactly_chat_id_and_text() {
        let body: Value = serde_json::from_slice(&request_body(-42, "你好 \"x\"\n")).unwrap();
        let object = body.as_object().unwrap();
        // Exactly these two keys: no formatting mode is ever requested.
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["chat_id", "text"]);
        assert_eq!(object["chat_id"], Value::from(-42));
        assert!(object["chat_id"].is_i64());
        assert_eq!(object["text"], "你好 \"x\"\n");
    }
    #[test]
    fn terminal_kind_maps_the_four_engine_kinds() {
        assert_eq!(
            [
                RunTerminalKind::Succeeded,
                RunTerminalKind::Failed,
                RunTerminalKind::Cancelled,
                RunTerminalKind::ReconciliationRequired,
            ]
            .map(terminal_kind),
            [
                TerminalKind::Succeeded,
                TerminalKind::Failed,
                TerminalKind::Cancelled,
                TerminalKind::ReconciliationRequired,
            ]
        );
    }
    #[test]
    fn classify_2xx_ok_true_is_sent_with_decimal_message_id() {
        assert_eq!(
            classify(Ok((
                200,
                br#"{"ok":true,"result":{"message_id":123,"text":"x"}}"#
            ))),
            Verdict::Sent {
                message_id: "123".into()
            }
        );
    }
    #[test]
    fn classify_2xx_ok_false_unparseable_or_without_message_id_is_unknown() {
        for body in [
            br#"{"ok":false,"result":{"message_id":1}}"#.as_slice(),
            b"not json",
            br#"{"ok":true,"result":{}}"#,
            br#"{"ok":true}"#,
        ] {
            assert_eq!(classify(Ok((200, body))), Verdict::Unknown);
        }
    }
    #[test]
    fn classify_429_is_rate_limited_and_reads_retry_after() {
        assert_eq!(
            classify(Ok((
                429,
                br#"{"ok":false,"error_code":429,"parameters":{"retry_after":7}}"#
            ))),
            Verdict::Retry {
                code: ErrorCode::RateLimited,
                retry_after: Some(Duration::from_secs(7)),
            }
        );
        assert_eq!(
            classify(Ok((429, br#"{"ok":false,"error_code":429}"#))),
            Verdict::Retry {
                code: ErrorCode::RateLimited,
                retry_after: None,
            }
        );
    }
    #[test]
    fn classify_5xx_is_server_error_retry() {
        for status in [500, 502, 503] {
            assert_eq!(
                classify(Ok((status, b"{}"))),
                Verdict::Retry {
                    code: ErrorCode::ServerError,
                    retry_after: None,
                }
            );
        }
    }
    #[test]
    fn classify_other_4xx_and_leftover_3xx_are_client_error_failed() {
        for status in [400, 401, 403, 404, 302] {
            assert_eq!(
                classify(Ok((status, b"{}"))),
                Verdict::Failed {
                    code: ErrorCode::ClientError
                },
                "{status}"
            );
        }
    }
    #[test]
    fn classify_errors_before_the_request_is_sent_are_unreachable_retry() {
        for error in [
            SafeHttpError::DnsUnavailable,
            SafeHttpError::DestinationDenied,
            SafeHttpError::ConnectFailed,
            SafeHttpError::PeerMismatch,
            SafeHttpError::TlsFailed,
            SafeHttpError::InvalidUrl,
            SafeHttpError::SchemeRejected,
            SafeHttpError::InvalidBudget,
            SafeHttpError::InvalidHeader,
            SafeHttpError::InvalidAllowlist,
        ] {
            assert_eq!(
                classify(Err(error)),
                Verdict::Retry {
                    code: ErrorCode::Unreachable,
                    retry_after: None,
                },
                "{error:?}"
            );
        }
    }
    #[test]
    fn classify_errors_after_the_request_is_sent_are_unknown() {
        for error in [
            SafeHttpError::DeadlineExceeded,
            SafeHttpError::ProtocolFailed,
            SafeHttpError::ResponseTooLarge,
            SafeHttpError::StreamStalled,
            SafeHttpError::RedirectInvalid,
            SafeHttpError::RedirectLimit,
            SafeHttpError::RedirectMethodRejected,
            SafeHttpError::SensitiveRedirectRejected,
        ] {
            assert_eq!(classify(Err(error)), Verdict::Unknown, "{error:?}");
        }
    }
    #[test]
    fn after_failure_schedules_retry_n_after_the_nth_planned_interval() {
        let schedule = crate::DELIVERY_RETRY;
        for attempts in 1..=5u32 {
            for code in [
                ErrorCode::Unreachable,
                ErrorCode::ServerError,
                ErrorCode::ReceiverInactive,
            ] {
                assert_eq!(
                    retry(after_failure(attempts, code, None, &schedule)),
                    (schedule[attempts as usize - 1], code)
                );
            }
        }
    }
    #[test]
    fn after_failure_429_waits_the_larger_of_retry_after_and_plan() {
        let schedule = crate::DELIVERY_RETRY;
        let code = ErrorCode::RateLimited;
        assert_eq!(
            retry(after_failure(
                1,
                code,
                Some(Duration::from_secs(300)),
                &schedule
            )),
            (Duration::from_secs(300), code)
        );
        assert_eq!(
            retry(after_failure(
                2,
                code,
                Some(Duration::from_secs(5)),
                &schedule
            )),
            (Duration::from_secs(120), code)
        );
        assert_eq!(
            retry(after_failure(3, code, None, &schedule)),
            (Duration::from_secs(240), code)
        );
    }
    #[test]
    fn after_failure_on_the_sixth_attempt_is_failed_retries_exhausted() {
        for code in [
            ErrorCode::Unreachable,
            ErrorCode::RateLimited,
            ErrorCode::ServerError,
            ErrorCode::ReceiverInactive,
        ] {
            assert!(matches!(
                after_failure(
                    6,
                    code,
                    Some(Duration::from_secs(1)),
                    &crate::DELIVERY_RETRY
                ),
                Finish::Failed {
                    code: ErrorCode::RetriesExhausted
                }
            ));
        }
    }
    #[test]
    fn terminal_queue_drops_when_full_without_blocking() {
        let (sender, mut receiver) = mpsc::channel(1);
        let queue = TerminalQueue(sender);
        queue.on_run_terminal(notice("first"));
        queue.on_run_terminal(notice("second"));
        assert_eq!(receiver.try_recv().unwrap().run_id.as_str(), "first");
        assert!(receiver.try_recv().is_err());
    }
    #[test]
    fn terminal_queue_drops_after_the_receiver_is_closed() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let queue = TerminalQueue(sender);
        queue.on_run_terminal(notice("first"));
        queue.on_run_terminal(notice("second"));
    }
}
