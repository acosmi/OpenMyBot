//! The outbound task: records run terminals from the engine's notices, then claims due delivery
//! rows and sends each through the plugin process of the row's channel. A stop takes effect between
//! two sends, never during one.
use crate::{
    ChannelError, Connection, DELIVERY_BODY_MAX, OMB_RESULT_CANCELLED_V1, OMB_RESULT_FAILED_V1,
    OMB_RESULT_SUCCEEDED_V1, OMB_RESULT_UNKNOWN_V1, STORE_BUDGET, Task, Timings,
    channels::Processes, supervisor::SendResult,
};
use omb_channel_sdk::{
    plugin::SendArgs,
    protocol::{FailureClass, SendErrorCode},
};
use omb_store::{
    Claimed, DeliveryContent, ErrorCode, Finish, RunResultFacts, TerminalKind, claim_delivery,
    finish_delivery, record_terminal, run_result_facts, send_target,
};
use openbot_application::{RunTerminalKind, RunTerminalNotice, RunTerminalSubscriber};
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
pub(crate) struct TerminalQueue(pub(crate) mpsc::Sender<RunTerminalNotice>);
impl RunTerminalSubscriber for TerminalQueue {
    fn on_run_terminal(&self, notice: RunTerminalNotice) {
        let _ = self.0.try_send(notice);
    }
}

/// What the outbound task sends through and wakes.
pub(crate) struct OutboundContext {
    pub(crate) processes: Processes,
    pub(crate) timings: Timings,
    /// The dispatcher's wake-up, signalled after a first terminal write.
    pub(crate) wake: Arc<Notify>,
}

pub(crate) fn start_outbound(
    connection: Connection,
    context: OutboundContext,
    terminals: mpsc::Receiver<RunTerminalNotice>,
) -> Task {
    Task::spawn(connection, move |client, stop| {
        send(client, context, terminals, stop)
    })
}
async fn send(
    mut client: tokio_postgres::Client,
    context: OutboundContext,
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
/// One attempt of a claimed row: the binding and receiver are read again, and the plugin of the
/// row's channel sends the text; no process or no reply within `plugin_send` ends the attempt.
async fn deliver(
    client: &tokio_postgres::Client,
    context: &OutboundContext,
    claimed: Claimed,
) -> Result<(), ChannelError> {
    let store = |_| ChannelError::StoreFailed;
    let schedule = &context.timings.delivery_retry;
    let target = send_target(
        client,
        claimed.binding_id,
        claimed.channel.clone(),
        Instant::now() + STORE_BUDGET,
    )
    .await
    .map_err(store)?;
    let message_id;
    let finish = 'decide: {
        if !target.sender_active {
            break 'decide Finish::Failed {
                code: ErrorCode::BindingInactive,
            };
        }
        if target.receiver.is_none() {
            break 'decide after_failure(
                claimed.attempts,
                ErrorCode::ReceiverInactive,
                None,
                schedule,
            );
        }
        let process = context
            .processes
            .lock()
            .unwrap()
            .get(&claimed.channel)
            .cloned();
        let Some(process) = process else {
            break 'decide after_failure(claimed.attempts, ErrorCode::Unreachable, None, schedule);
        };
        let body = match &claimed.content {
            DeliveryContent::Text(text) => text.clone(),
            DeliveryContent::RunResult { run_id } => {
                let facts = run_result_facts(client, run_id, Instant::now() + STORE_BUDGET)
                    .await
                    .map_err(store)?;
                compose_result(run_id, &facts)
            }
        };
        let sent = process
            .send(
                SendArgs {
                    delivery_id: claimed.delivery_id.to_string(),
                    chat_key: claimed.chat_key.clone(),
                    body,
                    idempotency_key: claimed.idempotency_key.clone(),
                },
                context.timings.plugin_send,
            )
            .await;
        let code = |code: SendErrorCode| match code {
            SendErrorCode::Unreachable => ErrorCode::Unreachable,
            SendErrorCode::RateLimited => ErrorCode::RateLimited,
            SendErrorCode::ServerError => ErrorCode::ServerError,
            SendErrorCode::ClientError => ErrorCode::ClientError,
            SendErrorCode::ReceiverInactive => ErrorCode::ReceiverInactive,
        };
        match sent {
            SendResult::Sent(id) => {
                message_id = id;
                Finish::Sent {
                    platform_message_id: &message_id,
                }
            }
            SendResult::Failed {
                class: FailureClass::Retryable,
                code: failed,
                retry_after,
            } => after_failure(claimed.attempts, code(failed), retry_after, schedule),
            SendResult::Failed {
                class: FailureClass::Final,
                code: failed,
                ..
            } => Finish::Failed { code: code(failed) },
            SendResult::Failed {
                class: FailureClass::Unknown,
                ..
            }
            | SendResult::Unknown => Finish::Unknown {
                code: ErrorCode::ResultUnknown,
            },
            SendResult::NotRunning => {
                after_failure(claimed.attempts, ErrorCode::Unreachable, None, schedule)
            }
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
