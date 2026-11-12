//! A loopback PostgreSQL wire proxy drops one COMMIT acknowledgement after PostgreSQL committed.
//! This tests an actual connection-loss boundary; no production fault hook is involved.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct CommitAckProxy {
    port: u16,
    drop_next: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CommitAckProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CommitAckProxy {
    async fn start(host: String, port: u16) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let drop_next = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let next = drop_next.clone();
        let count = dropped.clone();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let Ok(server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                    break;
                };
                let next = next.clone();
                let count = count.clone();
                children.spawn(async move {
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    // NoTls means the backend stream contains normal PG frames, including SCRAM.
                    let forward_backend = async {
                        loop {
                            let kind = server_read.read_u8().await?;
                            let length = server_read.read_u32().await?;
                            if !(4..=16 * 1024 * 1024).contains(&length) {
                                return Err(std::io::Error::other("invalid test proxy frame"));
                            }
                            let mut payload = vec![0; (length - 4) as usize];
                            server_read.read_exact(&mut payload).await?;
                            if kind == b'C'
                                && payload == b"COMMIT\0"
                                && next.swap(false, Ordering::SeqCst)
                            {
                                count.fetch_add(1, Ordering::SeqCst);
                                // A COMMIT CommandComplete proves PostgreSQL committed. Close before
                                // the caller receives it or ReadyForQuery, so commit() returns error.
                                return Ok::<(), std::io::Error>(());
                            }
                            client_write.write_u8(kind).await?;
                            client_write.write_u32(length).await?;
                            client_write.write_all(&payload).await?;
                        }
                    };
                    tokio::select! {
                        _ = tokio::io::copy(&mut client_read, &mut server_write) => {},
                        _ = forward_backend => {},
                    }
                });
            }
        });
        Self {
            port: proxy_port,
            drop_next,
            dropped,
            task,
        }
    }
}

struct ArmCommitLoss {
    arm: Arc<AtomicBool>,
    calls: AtomicUsize,
    rotate: bool,
}

#[async_trait]
impl RotatingOAuthTokenExchanger for ArmCommitLoss {
    fn requires_refresh_rotation(&self) -> bool {
        self.rotate
    }

    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        request.admit_token_send().await?;
        // Even a copied request cannot acquire send admission twice.
        assert_eq!(
            request.admit_token_send().await,
            Err(OAuthTokenExchangeError::Unavailable)
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.arm.store(true, Ordering::SeqCst);
        Ok(RotatingOAuthGrant::new(
            SecretBytes::new(b"access-only-after-committed-readback".to_vec()),
            self.rotate
                .then(|| SecretBytes::new(b"rotated-before-ack-loss".to_vec())),
            None,
        ))
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and local sockets; set OPENBOT_TEST_DATABASE_URL"]
async fn actual_commit_ack_loss_reads_receipt_without_a_second_exchange() {
    with_fixture("commit_ack_loss", "refresh_ack_loss", |fixture| async move {
        register_client(&fixture, DRIVE).await?;
        let db: String = fixture.pool.get().await.map_err(|e| e.to_string())?.query_one("SELECT current_database()", &[]).await.map_err(|e| e.to_string())?.get(0);
        let mut config = admin_config("commit_ack_loss").with_dbname(&db);
        let proxy = CommitAckProxy::start(config.host.clone(), config.port).await;
        config.host = "127.0.0.1".to_owned();
        config.port = proxy.port;
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let store = PluginUserCredentialStore::new(pool.clone(), fixture.vault.clone(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside"))).with_rotation_audit_key(AUDIT_KEY.to_vec()).unwrap();
        for rotate in [false, true] {
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            let exchanger = ArmCommitLoss { arm: proxy.drop_next.clone(), calls: AtomicUsize::new(0), rotate };
            let token = tokio::time::timeout(std::time::Duration::from_secs(15), store.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &exchanger)).await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
            assert_eq!(token.expose_for_vendor(), b"access-only-after-committed-readback");
            assert_eq!(exchanger.calls.load(Ordering::SeqCst), 1);
            let state: String = fixture.pool.get().await.map_err(|e| e.to_string())?.query_one("SELECT state FROM public.oauth_refresh_operations ORDER BY created_at DESC LIMIT 1", &[]).await.map_err(|e| e.to_string())?.get(0);
            assert_eq!(state, "committed");
        }
        assert_eq!(proxy.dropped.load(Ordering::SeqCst), 2);
        drop(store);
        pool.close();
        Ok(())
    }).await;
}
