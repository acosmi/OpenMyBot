//! Owner-initiated pairing: verified workspace, minted thread and a pending sender binding.
use crate::{DaemonError, engine::Engine, pg::Postgres};
use openbot_contracts::command::{AppCommand, AppReply};
use std::path::PathBuf;

pub struct PairRequest {
    pub channel: omb_store::Channel,
    pub workspace: PathBuf,
    pub run_deadline: Option<omb_store::RunDeadline>,
}

/// Starts pairing for one channel. The workspace's real path must be one of the configured
/// roots or inside one; the thread is minted under the owner's local context.
pub async fn pair(
    engine: &Engine,
    pg: &mut Postgres,
    workspace_roots: &[PathBuf],
    request: PairRequest,
) -> Result<omb_store::PairStarted, DaemonError> {
    let workspace =
        std::fs::canonicalize(&request.workspace).map_err(|_| DaemonError::WorkspaceInvalid)?;
    let inside = workspace_roots
        .iter()
        .any(|root| std::fs::canonicalize(root).is_ok_and(|root| workspace.starts_with(root)));
    if !inside || !workspace.is_dir() {
        return Err(DaemonError::WorkspaceInvalid);
    }
    let workspace_dir = workspace.to_str().ok_or(DaemonError::WorkspaceInvalid)?;
    let auth = engine
        .resolver
        .local_context()
        .map_err(|_| DaemonError::InternalError)?;
    let granted_generation = auth.auth_generation().get();
    let AppReply::ThreadMinted(minted) = engine
        .assembly
        .application
        .execute(auth, AppCommand::MintThreadId)
        .await
        .map_err(|_| DaemonError::InternalError)?
    else {
        return Err(DaemonError::InternalError);
    };
    pg.pair_start(omb_store::PairStart {
        channel: request.channel,
        workspace_dir,
        thread_id: minted.thread_id.as_str(),
        granted_generation,
        run_deadline: request.run_deadline,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config, delegation::fixture};
    use openbot_contracts::ids::{ThreadId, thread::ThreadIdentity};
    use sha2::{Digest, Sha256};
    use std::path::Path;

    fn workspace(root: &Path, name: &str) -> PathBuf {
        let path = root.join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }
    async fn senders(client: &tokio_postgres::Client) -> i64 {
        client
            .query_one(
                "SELECT count(*) FROM openmybot.channel_bindings WHERE binding_kind='sender'",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
    fn request(workspace: PathBuf) -> PairRequest {
        PairRequest {
            channel: omb_store::Channel::Telegram,
            workspace,
            run_deadline: omb_store::RunDeadline::parse(300),
        }
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn pair_mints_thread_under_local_context_and_records_current_generation() {
        let mut fixture = fixture::Fixture::start().await;
        let client = fixture.client().await;
        fixture::receiver(&client, "telegram").await;
        let roots = config::test_dir();
        let project = workspace(&roots, "project");
        let started = pair(
            fixture.engine.as_ref().unwrap(),
            &mut fixture.pg,
            std::slice::from_ref(&roots),
            request(project.clone()),
        )
        .await
        .unwrap();
        let row = client.query_one("SELECT thread_id,granted_generation,workspace_dir,run_deadline_seconds,pairing_code_hash,status,row_to_json(b)::text FROM openmybot.channel_bindings b WHERE binding_id=$1", &[&started.binding_id]).await.unwrap();
        let thread: String = row.get(0);
        assert!(ThreadIdentity::is_plausible(&ThreadId::new(&thread)));
        let generation = fixture
            .engine()
            .resolver
            .local_context()
            .unwrap()
            .auth_generation()
            .get();
        assert_eq!(u64::try_from(row.get::<_, i64>(1)).unwrap(), generation);
        assert_eq!(
            Path::new(&row.get::<_, String>(2)),
            std::fs::canonicalize(&project).unwrap()
        );
        assert_eq!(row.get::<_, i32>(3), 300);
        let code = started.code.display().replace('-', "");
        let mut digest = Sha256::new();
        digest.update(started.binding_id.as_bytes());
        digest.update(code.as_bytes());
        assert_eq!(row.get::<_, Vec<u8>>(4), digest.finalize().to_vec());
        assert_eq!(row.get::<_, String>(5), "pending");
        assert!(!row.get::<_, String>(6).contains(&code));
        std::fs::remove_dir_all(roots).unwrap();
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn pair_refuses_workspace_outside_roots() {
        let mut fixture = fixture::Fixture::start().await;
        let client = fixture.client().await;
        fixture::receiver(&client, "telegram").await;
        let roots = config::test_dir();
        let outside = config::test_dir();
        for candidate in [
            workspace(&outside, "project"),
            roots.join("missing"),
            roots.join("project/../../escape"),
        ] {
            assert_eq!(
                pair(
                    fixture.engine.as_ref().unwrap(),
                    &mut fixture.pg,
                    std::slice::from_ref(&roots),
                    request(candidate),
                )
                .await
                .unwrap_err(),
                DaemonError::WorkspaceInvalid
            );
        }
        assert_eq!(senders(&client).await, 0);
        std::fs::remove_dir_all(roots).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn pair_refuses_symlink_escaping_roots() {
        let mut fixture = fixture::Fixture::start().await;
        let client = fixture.client().await;
        fixture::receiver(&client, "telegram").await;
        let roots = config::test_dir();
        let outside = config::test_dir();
        let target = workspace(&outside, "project");
        let link = roots.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            pair(
                fixture.engine.as_ref().unwrap(),
                &mut fixture.pg,
                std::slice::from_ref(&roots),
                request(link),
            )
            .await
            .unwrap_err(),
            DaemonError::WorkspaceInvalid
        );
        assert_eq!(senders(&client).await, 0);
        std::fs::remove_dir_all(roots).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
        fixture.stop().await;
    }
}
