//! R409: real isolated PostgreSQL migration and storage boundary evidence.

mod harness;

use std::future::Future;
use std::time::Duration;

use openbot_infra::db::{baseline, desktop_vault_canary, fresh, native, pool, schema_facts};
use openbot_infra::repo::run::RunRepo;
use tokio_postgres::Client;

async fn fixture<F, Fut>(name: &str, body: F)
where
    F: FnOnce(openbot_infra::db::pool::DatabasePool) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(name), name, |config| async move {
        let p = pool::connect(&config.with_max_pool_size(6))
            .await
            .map_err(|e| e.to_string())?;
        let result = body(p.clone()).await;
        p.close();
        result
    })
    .await;
}

async fn through35(p: &openbot_infra::db::pool::DatabasePool) {
    let mut c = p.get().await.unwrap();
    baseline::apply(&c).await.unwrap();
    native::apply_through(&mut c, native::NATIVE_0035_VERSION)
        .await
        .unwrap();
}

async fn seed(c: &Client, id: &str, state: &str, foreground: bool) {
    c.execute("INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id) VALUES($1,'tenant','deployment','actor','direct_bot','bot')", &[&id]).await.unwrap();
    // A terminal Run carries its exactly-once terminal event in the same statement (§4.3).
    c.execute("WITH r AS (INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,terminal_event_seq,error_code,created_at,started_at,finished_at) VALUES($1,$1,'bot','actor',$2,$3,1,CASE WHEN $3 IN ('queued','running') THEN NULL ELSE 1 END,CASE WHEN $3 IN ('failed','reconciliation_required') THEN 'fixture_failure' ELSE NULL END,'2026-09-01 00:00:00+00'::timestamptz,CASE WHEN $3='queued' THEN NULL ELSE '2026-09-01 00:00:00+00'::timestamptz END,CASE WHEN $3 IN ('queued','running') THEN NULL ELSE '2026-09-01 00:00:00+00'::timestamptz END) RETURNING run_id,thread_id,status,terminal_event_seq) INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal) SELECT run_id,terminal_event_seq,thread_id,0,status,'{}'::jsonb,true FROM r WHERE terminal_event_seq IS NOT NULL", &[&id,&foreground,&state]).await.unwrap();
}

async fn pairs(c: &Client) -> Vec<(String, String)> {
    c.query(
        "SELECT thread_id,run_id FROM public.thread_run_occupancy ORDER BY thread_id",
        &[],
    )
    .await
    .unwrap()
    .into_iter()
    .map(|r| (r.get(0), r.get(1)))
    .collect()
}

async fn terminal(c: &Client, run: &str, status: &str) {
    // Settle like the real finish: the terminal event and Run terminal state commit together.
    c.execute("WITH r AS (UPDATE public.runs SET status=$2,terminal_event_seq=1,finished_at=now(),error_code=CASE WHEN $2='failed' THEN 'fixture_failure' ELSE NULL END WHERE run_id=$1 RETURNING run_id,thread_id,status,terminal_event_seq) INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal) SELECT r.run_id,r.terminal_event_seq,r.thread_id,(SELECT coalesce(max(e.event_seq)+1,0) FROM public.run_events e WHERE e.thread_id=r.thread_id),r.status,'{}'::jsonb,true FROM r", &[&run,&status]).await.unwrap();
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn upgrade_backfills_every_state_at_0036_and_latest_fresh_matches_registered_schema() {
    fixture("occupancy36schema", |p| async move {
        through35(&p).await;
        let mut c = p.get().await.unwrap();
        let before = schema_facts::fetch(&c).await.unwrap();
        let old =
            serde_json::from_str(include_str!("../../../fixtures/db/schema-0035.json")).unwrap();
        assert_eq!(before, old);
        for state in [
            "queued",
            "running",
            "completed",
            "failed",
            "cancelled",
            "reconciliation_required",
        ] {
            seed(&c, state, state, true).await;
            seed(&c, &format!("background-{state}"), state, false).await;
        }
        assert_eq!(
            native::apply_through(&mut c, native::NATIVE_0036_VERSION)
                .await
                .unwrap(),
            native::ApplyOutcome::Applied
        );
        assert_eq!(
            pairs(&c).await,
            ["queued", "reconciliation_required", "running"].map(|s| (s.to_owned(), s.to_owned()))
        );
        let actual = schema_facts::fetch(&c).await.unwrap();
        let expected =
            serde_json::from_str(include_str!("../../../fixtures/db/schema-0036.json")).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.tables.len(), before.tables.len() + 1);
        for table in &before.tables {
            if table.name != "runs" {
                assert_eq!(actual.table(&table.name), Some(table));
            }
        }
        assert_eq!(actual.enums, before.enums);
        assert_eq!(actual.extensions, before.extensions);
        let old_runs = before.table("runs").unwrap();
        let new_runs = actual.table("runs").unwrap();
        assert_eq!(old_runs.columns, new_runs.columns);
        for index in &old_runs.indexes {
            assert!(new_runs.indexes.contains(index));
        }
        let before_pairs = pairs(&c).await;
        assert_eq!(
            native::apply_through(&mut c, native::NATIVE_0036_VERSION)
                .await
                .unwrap(),
            native::ApplyOutcome::AlreadyApplied
        );
        assert_eq!(pairs(&c).await, before_pairs);
        drop(c);
        desktop_vault_canary::verify_pre_upgrade_layout(&p)
            .await
            .unwrap();
        Ok(())
    })
    .await;
    fixture("occupancy36fresh", |p| async move {
        let mut c=p.get().await.unwrap();
        c.batch_execute("SET default_transaction_isolation='repeatable read'").await.unwrap();
        // Owned observation hook: a default-RR implementation must fail at its first DDL.
        c.batch_execute("CREATE FUNCTION public.require_fresh_rc() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF current_setting('transaction_isolation') <> 'read committed' THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='fresh must use read committed'; END IF; END $$; CREATE EVENT TRIGGER require_fresh_rc ON ddl_command_start EXECUTE FUNCTION public.require_fresh_rc()").await.unwrap();
        let probe=c.batch_execute("CREATE TABLE public.rr_probe(n integer)").await.unwrap_err();
        assert_eq!(probe.code(),Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION));
        assert_eq!(fresh::apply(&mut c).await.unwrap(),fresh::FreshApplyOutcome::Applied(native::ApplyOutcome::Applied));
        c.batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED; DROP EVENT TRIGGER require_fresh_rc; DROP FUNCTION public.require_fresh_rc(); COMMIT").await.unwrap();
        let actual=schema_facts::fetch(&c).await.unwrap();
        let expected=serde_json::from_str(include_str!("../../../fixtures/db/schema-0051.json")).unwrap();
        assert_eq!(actual,expected);
        assert_eq!(fresh::apply(&mut c).await.unwrap(),fresh::FreshApplyOutcome::AlreadyInitialized);
        assert!(pairs(&c).await.is_empty());
        drop(c);
        desktop_vault_canary::verify_current_layout(&p).await.unwrap();
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn migration_waits_for_old_writer_then_reads_its_commit_even_on_default_rr_session() {
    fixture("occupancy36barrier", |p| async move {
        through35(&p).await;
        let writer = p.get().await.unwrap();
        seed(&writer, "old-running", "running", true).await;
        writer.batch_execute("BEGIN").await.unwrap();
        terminal(&writer, "old-running", "completed").await;
        seed(&writer, "new-unknown", "reconciliation_required", true).await;
        let writer_pid: i32 = writer
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let mut migrator = p.get().await.unwrap();
        migrator
            .batch_execute("SET default_transaction_isolation='repeatable read'")
            .await
            .unwrap();
        let migrator_pid: i32 = migrator
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let pending = tokio::spawn(async move { native::apply(&mut migrator).await });
        let observer = p.get().await.unwrap();
        let observed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let blocked: bool = observer
                    .query_one(
                        "SELECT $1=ANY(pg_blocking_pids($2))",
                        &[&writer_pid, &migrator_pid],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if blocked {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        writer.batch_execute("COMMIT").await.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(10), pending)
            .await
            .unwrap()
            .unwrap();
        assert!(observed.is_ok(), "must observe the real old-writer barrier");
        assert_eq!(outcome.unwrap(), native::ApplyOutcome::Applied);
        assert_eq!(
            pairs(&observer).await,
            vec![("new-unknown".to_owned(), "new-unknown".to_owned())]
        );
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn migration_failure_rolls_back_every_new_object_and_ledger_entry() {
    fixture("occupancy36rollback", |p| async move {
        through35(&p).await;
        let mut c = p.get().await.unwrap();
        // Explicit incompatible-schema injection in this disposable negative database only.
        c.batch_execute("CREATE TABLE public.thread_run_occupancy(unrelated integer)")
            .await
            .unwrap();
        let before = schema_facts::fetch(&c).await.unwrap();
        assert!(native::apply(&mut c).await.is_err());
        assert_eq!(schema_facts::fetch(&c).await.unwrap(), before);
        let version: i32 = c
            .query_one(
                "SELECT max(version) FROM openbot_internal.schema_migrations",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(version, 35);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn repeated_apply_rejects_missing_slot_without_repair() {
    fixture("occupancy36missing", |p| async move {
        let mut c=p.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        seed(&c,"unknown","reconciliation_required",true).await;
        // Corruption fixture only: bypass user triggers solely while deleting this owned slot.
        c.batch_execute("ALTER TABLE public.thread_run_occupancy DISABLE TRIGGER USER; DELETE FROM public.thread_run_occupancy; ALTER TABLE public.thread_run_occupancy ENABLE TRIGGER USER;").await.unwrap();
        assert!(native::apply(&mut c).await.is_err());
        assert!(pairs(&c).await.is_empty());
        assert!(c.batch_execute("UPDATE public.runs SET next_event_seq=next_event_seq+1 WHERE run_id='unknown'").await.is_err());
        assert!(c.batch_execute("UPDATE public.runs SET status='completed',error_code=NULL WHERE run_id='unknown'").await.is_err());
        assert!(pairs(&c).await.is_empty());
        let state:String=c.query_one("SELECT status FROM public.runs WHERE run_id='unknown'",&[]).await.unwrap().get(0);
        assert_eq!(state,"reconciliation_required");
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn run_writes_preserve_exact_ownership_and_prohibit_unknown_release_shortcuts() {
    fixture("occupancy36writes", |p| async move {
        let mut c=p.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        seed(&c,"unknown","reconciliation_required",true).await;
        seed(&c,"background-unknown","reconciliation_required",false).await;
        seed(&c,"other","completed",true).await;
        let before=pairs(&c).await;
        for sql in [
            "UPDATE public.runs SET foreground=false WHERE run_id='unknown'",
            "UPDATE public.runs SET thread_id='other' WHERE run_id='unknown'",
            // Its exactly-once terminal event would refuse the rename first through
            // run_events_run_id_fkey; drop it inside the probe so occupancy is what refuses.
            "BEGIN; DELETE FROM public.run_events WHERE run_id='unknown'; UPDATE public.runs SET run_id='renamed' WHERE run_id='unknown'",
            "UPDATE public.runs SET status='completed',error_code=NULL WHERE run_id='unknown'",
            "DELETE FROM public.runs WHERE run_id='unknown'",
            "DELETE FROM public.runs WHERE run_id='background-unknown'",
            "DELETE FROM public.threads WHERE thread_id='unknown'",
            "TRUNCATE public.runs CASCADE",
            "UPDATE public.thread_run_occupancy SET run_id=run_id",
            "DELETE FROM public.thread_run_occupancy",
            "INSERT INTO public.thread_run_occupancy VALUES('other','other')",
            "TRUNCATE public.thread_run_occupancy",
            "UPDATE public.runs SET status='running',terminal_event_seq=NULL,finished_at=NULL WHERE run_id='other'",
        ] {
            let error=c.batch_execute(sql).await.unwrap_err();
            if sql.starts_with("BEGIN;") { c.batch_execute("ROLLBACK").await.unwrap(); }
            let db=error.as_db_error().expect("server rejection");
            if sql=="TRUNCATE public.runs CASCADE" {
                // At 0051 the writer TRUNCATE guard explicitly refuses runs first (§4.2 item 11).
                assert_eq!((db.code().code(),db.message()),("55000","thread_history_writer_truncate_refused"),"{sql}: {error}");
                assert_eq!(pairs(&c).await,before,"{sql}");
                continue;
            }
            assert!(matches!(error.code(),Some(code) if code==&tokio_postgres::error::SqlState::CHECK_VIOLATION || code==&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION),"{sql}: {error}");
            assert!(db.constraint().is_some_and(|name| name.starts_with("thread_run_occupancy_")),"{sql}: {error}");
            assert_eq!(pairs(&c).await,before,"{sql}");
        }
        assert!(RunRepo::new(p.clone()).delete("unknown").await.is_err());
        c.batch_execute("UPDATE public.runs SET next_tool_call_seq=next_tool_call_seq+1 WHERE run_id='unknown'; UPDATE public.threads SET status='deleted',deleted_at=now() WHERE thread_id='unknown'").await.unwrap();
        assert_eq!(pairs(&c).await,before);
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn terminal_release_bulk_updates_and_public_repo_insert_are_atomic() {
    fixture("occupancy36terminal", |p| async move {
        let mut c=p.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        for state in ["completed","failed","cancelled"] {
            seed(&c,state,"running",true).await;
        }
        for state in ["completed","failed","cancelled"] { terminal(&c,state,state).await; }
        assert!(pairs(&c).await.is_empty());
        let repo=RunRepo::new(p.clone());
        let mut new=repo.find_by_id("completed").await.unwrap().unwrap();
        new.run_id="next-run".into(); new.status="running".into(); new.finished_at=None; new.terminal_event_seq=None;
        repo.insert(&new).await.unwrap();
        assert_eq!(repo.active_foreground_for_thread("completed").await.unwrap().unwrap().run_id,"next-run");
        // Deleting the old terminal must neither refuse nor remove its successor's slot.
        assert!(repo.delete("completed").await.unwrap());
        assert_eq!(pairs(&c).await,vec![("completed".to_owned(),"next-run".to_owned())]);
        seed(&c,"bulk-a","queued",true).await;
        seed(&c,"bulk-b","queued",true).await;
        c.batch_execute("UPDATE public.runs SET status='running',started_at=now() WHERE run_id IN ('bulk-a','bulk-b'); WITH r AS (UPDATE public.runs SET status='completed',terminal_event_seq=1,finished_at=now() WHERE run_id IN ('bulk-a','bulk-b') RETURNING run_id,thread_id,status,terminal_event_seq) INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal) SELECT run_id,terminal_event_seq,thread_id,0,status,'{}'::jsonb,true FROM r").await.unwrap();
        assert_eq!(pairs(&c).await,vec![("completed".to_owned(),"next-run".to_owned())]);
        let rows=c.query("SELECT run_id,status FROM public.runs WHERE run_id IN ('bulk-a','bulk-b') ORDER BY run_id",&[]).await.unwrap();
        let states:Vec<(String,String)>=rows.iter().map(|r|(r.get(0),r.get(1))).collect();
        assert_eq!(states,vec![("bulk-a".into(),"completed".into()),("bulk-b".into(),"completed".into())]);
        seed(&c,"bulk-reject-a","running",true).await;
        seed(&c,"bulk-reject-b","reconciliation_required",true).await;
        let before=pairs(&c).await;
        let error=c.batch_execute("UPDATE public.runs SET status='completed',terminal_event_seq=1,finished_at=now(),error_code=NULL WHERE run_id IN ('bulk-reject-a','bulk-reject-b')").await.unwrap_err();
        assert_eq!(error.as_db_error().and_then(|e|e.constraint()),Some("thread_run_occupancy_rr_immutable"));
        assert_eq!(pairs(&c).await,before);
        assert_eq!(repo.find_by_id("bulk-reject-a").await.unwrap().unwrap().status,"running");
        assert_eq!(repo.find_by_id("bulk-reject-b").await.unwrap().unwrap().status,"reconciliation_required");
        c.batch_execute("BEGIN").await.unwrap();
        terminal(&c,"next-run","completed").await;
        assert_eq!(pairs(&c).await.len(),2);
        c.batch_execute("ROLLBACK").await.unwrap();
        assert_eq!(pairs(&c).await,before);
        assert_eq!(repo.find_by_id("next-run").await.unwrap().unwrap().status,"running");
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn locked_slot_fails_without_partial_terminal_and_restores_caller_timeout() {
    fixture("occupancy36lock", |p| async move {
        let mut c=p.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        seed(&c,"running","running",true).await;
        let locker=p.get().await.unwrap();
        locker.batch_execute("BEGIN; SELECT * FROM public.thread_run_occupancy FOR UPDATE").await.unwrap();
        c.batch_execute("SET lock_timeout='700ms'").await.unwrap();
        let failed=tokio::time::timeout(Duration::from_secs(3),c.batch_execute("UPDATE public.runs SET status='completed',terminal_event_seq=1,finished_at=now() WHERE run_id='running'")).await.unwrap();
        // The refusal must be the occupancy row lock itself; at 0051 the deferred terminal
        // guard would also reject this event-less terminal UPDATE, so is_err() alone is vacuous.
        assert_eq!(failed.unwrap_err().code(),Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE));
        locker.batch_execute("ROLLBACK").await.unwrap();
        assert_eq!(RunRepo::new(p.clone()).find_by_id("running").await.unwrap().unwrap().status,"running");
        assert_eq!(pairs(&c).await.len(),1);
        terminal(&c,"running","completed").await;
        assert!(pairs(&c).await.is_empty());
        let setting:String=c.query_one("SHOW lock_timeout",&[]).await.unwrap().get(0);
        assert_eq!(setting,"700ms");
        Ok(())
    }).await;
}
