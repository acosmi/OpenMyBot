//! Fake Telegram and Feishu platforms for the daemon's end-to-end tests (testkit only). Starts both
//! loopback fakes in this process and prints their API bases as the first stdout line; then answers
//! each JSON command line on stdin with one JSON line on stdout until stdin ends.
use omb_channels::{fake_feishu::FakeFeishu, testkit::FakeTelegram};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    TelegramPushUpdate {
        update: Value,
    },
    TelegramSent,
    /// The `offset` parameter of every `getUpdates` call, in arrival order.
    TelegramOffsets,
    /// `ok` is false when no long connection was there to take the event.
    FeishuPushEvent {
        event: Value,
    },
    FeishuSent,
    /// Valid acknowledgements of pushed events.
    FeishuAcks,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let telegram = FakeTelegram::start().await;
    let feishu = FakeFeishu::start().await;
    let mut stdout = tokio::io::stdout();
    let mut write = async |line: Value| {
        stdout
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("stdout");
        stdout.flush().await.expect("stdout");
    };
    write(json!({
        "telegram_api_base": telegram.endpoint().api_base.as_str(),
        "feishu_api_base": feishu.endpoint().api_base.as_str(),
    }))
    .await;
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await.expect("stdin") {
        let reply = match serde_json::from_str::<Command>(&line).expect("command line") {
            Command::TelegramPushUpdate { update } => {
                telegram.push_update(update);
                json!({"ok": true})
            }
            Command::TelegramSent => {
                let sent: Vec<Value> = telegram
                    .sent_messages()
                    .into_iter()
                    .map(|sent| json!({"chat_id": sent.chat_id, "text": sent.text}))
                    .collect();
                json!({ "sent": sent })
            }
            Command::TelegramOffsets => {
                let offsets: Vec<Option<u64>> = telegram
                    .calls("getUpdates")
                    .iter()
                    .map(|call| call.param("offset").and_then(|offset| offset.parse().ok()))
                    .collect();
                json!({ "offsets": offsets })
            }
            Command::FeishuPushEvent { event } => json!({"ok": feishu.push_event(&event)}),
            Command::FeishuSent => {
                let sent: Vec<Value> = feishu
                    .sent_messages()
                    .into_iter()
                    .map(|sent| {
                        let content: Value = serde_json::from_str(&sent.content).expect("content");
                        json!({"receive_id": sent.receive_id, "text": content["text"], "uuid": sent.uuid})
                    })
                    .collect();
                json!({ "sent": sent })
            }
            Command::FeishuAcks => {
                json!({"acks": feishu.acks().iter().filter(|ack| ack.valid).count()})
            }
        };
        write(reply).await;
    }
}
