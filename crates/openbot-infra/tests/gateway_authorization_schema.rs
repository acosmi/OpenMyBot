//! Directed journal-foundation tests on explicitly owned synthetic PostgreSQL17.11.
//! The independently authored oracle is an input; this suite never generates it.

mod harness;

use std::future::Future;
use std::time::{Duration, Instant};

use openbot_infra::db::{
    InfraError, baseline, desktop_vault_canary, gateway_authorization_schema as journal, native,
    pool, schema_facts,
    tables::{TableRow, gateway_authorization_attempts as attempts},
};
use serde_json::Value;
use tokio_postgres::Client;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, String>;
const OWNER: &str = "journal-owned-user";

fn require(value: bool, message: &'static str) -> TestResult {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

async fn close_pool(p: pool::DatabasePool) -> TestResult {
    let observations = p.connection_observations();
    p.close();
    let deadline = Instant::now() + Duration::from_secs(10);
    for observation in observations {
        require(
            observation
                .wait_for_destruction_before(deadline)
                .await
                .map_err(|e| e.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "owned business pool connection destruction was not observed",
        )?;
    }
    Ok(())
}

async fn owned<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(pool::DatabasePool) -> Fut,
    Fut: Future<Output = TestResult>,
{
    let admin = harness::admin_config(tag);
    require(
        matches!(admin.host.as_str(), "127.0.0.1" | "::1"),
        "literal loopback required",
    )
    .expect("owned invocation prerequisite");
    harness::with_temp_database(&admin, tag, |config| async move {
        require(
            config.dbname.starts_with("openbot_it_"),
            "owned database identity missing",
        )?;
        let p = pool::connect(&config.with_max_pool_size(4))
            .await
            .map_err(|e| e.to_string())?;
        let prerequisites = async {
            let c = p.get().await.map_err(|e| e.to_string())?;
            let version: i32 = c
                .query_one("SELECT current_setting('server_version_num')::integer", &[])
                .await
                .map_err(|e| e.to_string())?
                .try_get(0)
                .map_err(|e| e.to_string())?;
            require(
                version == 170_011,
                "this frozen suite requires genuine PostgreSQL17.11",
            )
        }
        .await;
        let result = match prerequisites {
            Ok(()) => body(p.clone()).await,
            Err(error) => Err(error),
        };
        result.and(close_pool(p).await)
    })
    .await;
}

async fn initialize(p: &pool::DatabasePool, version: i32) -> TestResult {
    let mut c = p.get().await.map_err(|e| e.to_string())?;
    if version == 47 {
        baseline::apply(&c).await.map_err(|e| e.to_string())?;
        require(
            native::apply_through(&mut c, 47)
                .await
                .map_err(|e| e.to_string())?
                == native::ApplyOutcome::Applied,
            "original47 path did not apply",
        )?;
    } else {
        require(version == 48, "unregistered test target")?;
        baseline::apply(&c).await.map_err(|e| e.to_string())?;
        require(
            native::apply_through(&mut c, 48)
                .await
                .map_err(|e| e.to_string())?
                == native::ApplyOutcome::Applied,
            "explicit historical path did not apply48",
        )?;
    }
    c.execute(
        "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,0)",
        &[&OWNER, &"journal-owned-user@example.test"],
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn row(number: u16) -> attempts::Row {
    let created =
        time::OffsetDateTime::from_unix_timestamp(1_791_547_200).expect("finite fixture time");
    attempts::Row {
        attempt_id: Uuid::parse_str(&format!("01912345-6789-7abc-8def-{number:012x}")).unwrap(),
        journal_schema: 1,
        deployment_id: "journal-owned-deployment".to_owned(),
        tenant_id: "journal-owned-tenant".to_owned(),
        owner_user_id: OWNER.to_owned(),
        auth_generation: 0,
        installation_id: "a".repeat(64),
        runtime_epoch: "b".repeat(64),
        issuer: "https://issuer.example.test".to_owned(),
        redirect_uri: "http://127.0.0.1:49152/callback".to_owned(),
        phase: "created".to_owned(),
        client_id: None,
        enrollment_id: None,
        registration_admitted_at: None,
        code_admitted_at: None,
        created_at: created,
        expires_at: created + time::Duration::seconds(180),
        updated_at: created,
        finished_at: None,
        outcome_code: None,
    }
}

fn advance(r: &mut attempts::Row, phase: &str, number: u16) {
    r.phase = phase.to_owned();
    if phase != "created" {
        r.registration_admitted_at = Some(r.created_at + time::Duration::seconds(10));
    }
    if !matches!(phase, "created" | "registration_admitted") {
        r.client_id = Some("opaque-client:not-a-uuid".to_owned());
        r.enrollment_id =
            Some(Uuid::parse_str(&format!("01912345-6789-7abc-9def-{number:012x}")).unwrap());
    }
    if matches!(phase, "code_admitted" | "enrolled" | "closed") {
        r.code_admitted_at = Some(r.created_at + time::Duration::seconds(20));
    }
    if matches!(phase, "enrolled" | "closed") {
        r.finished_at = Some(r.created_at + time::Duration::seconds(30));
        r.updated_at = r.finished_at.unwrap();
        r.outcome_code = Some(
            if phase == "enrolled" {
                "enrolled"
            } else {
                "cancelled"
            }
            .to_owned(),
        );
    }
}

async fn insert(c: &Client, r: &attempts::Row) -> Result<attempts::Row, tokio_postgres::Error> {
    let columns = attempts::COLUMNS.join(",");
    let placeholders = (1..=attempts::COLUMNS.len())
        .map(|n| format!("${n}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "INSERT INTO {} ({columns}) VALUES ({placeholders}) RETURNING {columns}",
        attempts::TABLE_NAME
    );
    let observed = c.query_one(&sql, &r.as_sql_params()).await?;
    Ok(attempts::Row::try_from_pg(&observed).expect("genuine20-column typed row decode"))
}

fn structurally_invalid(error: &InfraError) -> bool {
    matches!(
        error,
        InfraError::RepositoryInvariant {
            code: "gateway_authorization_schema_invalid"
        }
    )
}

fn whole_schema_for_oracle(observation: &Value) -> TestResult<Value> {
    // This independent test comparison changes only the three frozen HOT positions.
    let mut schema = observation["schema"].clone();
    let indexes = schema["indexes"]
        .as_array_mut()
        .ok_or("capture indexes missing")?;
    require(indexes.len() == 3, "capture has extra/missing indexes")?;
    let mut seen = std::collections::BTreeSet::new();
    for index in indexes.iter_mut() {
        let schema = index["identity"]["schema"]
            .as_str()
            .ok_or("index schema missing")?;
        let name = index["identity"]["name"]
            .as_str()
            .ok_or("index name missing")?;
        let identity = (schema.to_owned(), name.to_owned());
        require(
            matches!(
                (schema, name),
                (
                    "openbot_internal",
                    "ga_attempts_pkey" | "ga_attempts_enrollment_key"
                ) | ("public", "users_pkey")
            ),
            "unknown index cannot use HOT predicate",
        )?;
        require(
            seen.insert(identity),
            "duplicate index cannot use HOT predicate",
        )?;
        require(
            index["checkXmin"].is_boolean(),
            "raw HOT flag not actual boolean",
        )?;
        index["checkXmin"] = serde_json::json!({"predicate":"pg17_hot_runtime_boolean_v1"});
    }
    // These are unordered index facts; HOT values can change their original sort order.
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut pairs = object.iter().collect::<Vec<_>>();
                pairs.sort_by_key(|(key, _)| *key);
                let mut sorted = serde_json::Map::new();
                for (key, value) in pairs {
                    sorted.insert(key.clone(), canonical(value));
                }
                Value::Object(sorted)
            }
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            _ => value.clone(),
        }
    }
    let mut keyed = std::mem::take(indexes)
        .into_iter()
        .map(|value| {
            serde_json::to_vec(&canonical(&value))
                .map(|key| (key, value))
                .map_err(|e| e.to_string())
        })
        .collect::<TestResult<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    *indexes = keyed.into_iter().map(|(_, value)| value).collect();
    Ok(schema)
}

async fn reject_schema_mutation(c: &Client, sql: &str) -> TestResult {
    c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
    let result = async {
        // A failed fixture DDL is not a successful refusal test.
        c.batch_execute(sql).await.map_err(|e| e.to_string())?;
        let refusal = journal::verify(c).await;
        require(
            matches!(&refusal, Err(error) if structurally_invalid(error)),
            "catalogue drift was not a definite journal-shape refusal",
        )
    }
    .await;
    let rolled_back = c.batch_execute("ROLLBACK").await.map_err(|e| e.to_string());
    result.and(rolled_back)?;
    journal::verify(c).await.map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn original47_upgrade48_replay_and_current_canary() {
    owned("journal48upgrade", |p| async move {
        initialize(&p, 47).await?;
        let mut c = p.get().await.map_err(|e| e.to_string())?;
        let before = schema_facts::fetch(&c).await.map_err(|e| e.to_string())?;
        let legacy = desktop_vault_canary::verify_pre_upgrade_layout(&p).await.map_err(|e| e.to_string())?;
        require(legacy.native_version() == 47, "genuine47 prefix not recognized")?;
        require(desktop_vault_canary::verify_current_layout(&p).await.is_err(), "47 incorrectly current")?;
        require(native::apply_through(&mut c, 47).await.map_err(|e| e.to_string())?
            == native::ApplyOutcome::AlreadyApplied, "explicit47 replay failed")?;
        let absent: bool = c.query_one("SELECT to_regclass('openbot_internal.gateway_authorization_attempts') IS NULL", &[])
            .await.map_err(|e| e.to_string())?.try_get(0).map_err(|e| e.to_string())?;
        require(absent, "47 replay created unregistered journal")?;
        require(native::apply_through(&mut c, 48).await.map_err(|e| e.to_string())? == native::ApplyOutcome::Applied,
            "real47->48 did not apply exactly once")?;
        let counts: (i64, i32) = {
            let r = c.query_one("SELECT count(*),max(version) FROM openbot_internal.schema_migrations", &[])
                .await.map_err(|e| e.to_string())?;
            (r.try_get(0).map_err(|e| e.to_string())?, r.try_get(1).map_err(|e| e.to_string())?)
        };
        require(counts == (36,48), "not complete13..48")?;
        let after=schema_facts::fetch(&c).await.map_err(|e|e.to_string())?;
        println!("JOURNAL48_PUBLIC46 before {}",serde_json::to_string(&before).map_err(|e|e.to_string())?);
        println!("JOURNAL48_PUBLIC46 after {}",serde_json::to_string(&after).map_err(|e|e.to_string())?);
        require(before == after, "public typed shape changed")?;
        let public46: schema_facts::SchemaFacts = serde_json::from_str(include_str!("../../../fixtures/db/schema-0046.json"))
            .map_err(|e| e.to_string())?;
        require(before == public46, "prior public facts not independentPUBLIC46")?;
        journal::verify(&c).await.map_err(|e| e.to_string())?;
        require(desktop_vault_canary::verify_pre_upgrade_layout(&p).await.map_err(|e| e.to_string())?.native_version()==48, "actual48 preupgrade canary rejected")?;
        require(desktop_vault_canary::verify_current_layout(&p).await.is_err(), "historical48 incorrectly current49")?;
        c.batch_execute("CREATE TABLE openbot_internal.owned_journal_ddl_observations(tag text);
            CREATE FUNCTION openbot_internal.owned_journal_ddl_probe() RETURNS event_trigger LANGUAGE plpgsql AS
            $$BEGIN INSERT INTO openbot_internal.owned_journal_ddl_observations SELECT command_tag FROM pg_event_trigger_ddl_commands(); END$$;
            CREATE EVENT TRIGGER owned_journal_ddl_probe ON ddl_command_end EXECUTE FUNCTION openbot_internal.owned_journal_ddl_probe();
            TRUNCATE openbot_internal.owned_journal_ddl_observations;")
            .await.map_err(|e| e.to_string())?;
        require(native::apply_through(&mut c, 48).await.map_err(|e| e.to_string())? == native::ApplyOutcome::AlreadyApplied,
            "48 replay was not AlreadyApplied")?;
        let ddl_count: i64 = c.query_one("SELECT count(*) FROM openbot_internal.owned_journal_ddl_observations", &[])
            .await.map_err(|e| e.to_string())?.try_get(0).map_err(|e| e.to_string())?;
        require(ddl_count == 0, "AlreadyApplied issued actual object DDL")
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn fresh48_whole_independent_oracle_and_two_raw_acl_states() {
    owned("journal48oracle", |p| async move {
        initialize(&p, 48).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        let expected: Value = serde_json::from_str(include_str!("../../../fixtures/db/gateway-authorization-attempts-0048.json"))
            .map_err(|e| e.to_string())?;
        let first = journal::capture(&c).await.map_err(|e| e.to_string())?;
        println!("JOURNAL48_CAPTURE null {}",serde_json::to_string(&first).map_err(|e|e.to_string())?);
        require(whole_schema_for_oracle(&first)? == expected["schema"], "whole independently authored oracle differs")?;
        require(first["tableAclState"]["aclIsNull"] == true, "fresh table ACL not rawNULL")?;
        require(first["rawFacts"]["format"] == "gateway-authorization-attempts-raw-v1", "full rawFacts missing")?;
        for function in first["schema"]["functions"].as_array().ok_or("functions missing")? {
            require(function["ownerRef"]=="original_pg17_bootstrap_owner"
                && function["aclIsNull"]==true && function["rawAcl"].is_null(),"systemowner/ACL facts erased")?;
        }
        journal::verify(&c).await.map_err(|e| e.to_string())?;
        c.batch_execute("GRANT ALL PRIVILEGES ON openbot_internal.gateway_authorization_attempts TO CURRENT_USER")
            .await.map_err(|e| e.to_string())?;
        let second = journal::capture(&c).await.map_err(|e| e.to_string())?;
        println!("JOURNAL48_CAPTURE explicit_owner8 {}",serde_json::to_string(&second).map_err(|e|e.to_string())?);
        require(second["tableAclState"]["aclIsNull"] == false, "explicitownerACL not actually materialized")?;
        require(second["schema"] == first["schema"], "allowed rawACL state changed portable schema")?;
        require(whole_schema_for_oracle(&second)? == expected["schema"], "explicitACL whole oracle differs")?;
        journal::verify(&c).await.map_err(|e| e.to_string())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn six_phases_typed_rows_checks_nulls_and_owner_fk() {
    owned("journal48rows", |p| async move {
        initialize(&p, 48).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        for (index, phase) in [
            "created",
            "registration_admitted",
            "registered",
            "code_admitted",
            "enrolled",
            "closed",
        ]
        .iter()
        .enumerate()
        {
            let mut r = row(index as u16 + 1);
            advance(&mut r, phase, index as u16 + 1);
            let decoded = insert(&c, &r).await.map_err(|e| e.to_string())?;
            require(decoded == r, "actual typed20-field roundtrip differs")?;
            let debug = format!("{decoded:?}");
            require(
                debug == "GatewayAuthorizationAttemptRow(<redacted>)",
                "row Debug exposes storage values",
            )?;
        }
        for (index, outcome) in [
            "cancelled",
            "expired",
            "host_revoked",
            "dependency_unknown",
            "registration_unknown",
            "code_unknown",
            "enrollment_unknown",
            "restart_denied",
            "refused",
        ]
        .iter()
        .enumerate()
        {
            let mut r = row(index as u16 + 100);
            r.phase = "closed".to_owned();
            r.finished_at = Some(r.created_at);
            r.outcome_code = Some((*outcome).to_owned());
            insert(&c, &r).await.map_err(|e| e.to_string())?;
        }
        let mut bad = Vec::new();
        let base = row(1000);
        let mut r = base.clone();
        r.journal_schema = 2;
        bad.push(r);
        let mut r = base.clone();
        r.deployment_id = " padded ".to_owned();
        bad.push(r);
        let mut r = base.clone();
        r.tenant_id = "bad\u{007f}".to_owned();
        bad.push(r);
        let mut r = base.clone();
        r.auth_generation = -1;
        bad.push(r);
        let mut r = base.clone();
        r.installation_id = "A".repeat(64);
        bad.push(r);
        let mut r = base.clone();
        r.runtime_epoch = "b".repeat(63);
        bad.push(r);
        let mut r = base.clone();
        r.issuer = "http://issuer.example.test".to_owned();
        bad.push(r);
        for uri in [
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:65536/callback",
            "http://localhost:1234/callback",
            "http://127.0.0.1:01234/callback",
        ] {
            let mut r = base.clone();
            r.redirect_uri = uri.to_owned();
            bad.push(r);
        }
        let mut r = base.clone();
        r.phase = "unknown".to_owned();
        bad.push(r);
        let mut r = base.clone();
        r.attempt_id = Uuid::nil();
        bad.push(r);
        let mut r = base.clone();
        r.expires_at = r.created_at;
        bad.push(r);
        let mut r = base.clone();
        r.updated_at = r.created_at - time::Duration::seconds(1);
        bad.push(r);
        let mut r = base.clone();
        r.client_id = Some("unpaired-client".to_owned());
        bad.push(r);
        let mut r = base.clone();
        r.code_admitted_at = Some(r.created_at);
        bad.push(r);
        let mut r = base.clone();
        r.phase = "registered".to_owned();
        bad.push(r);
        let mut r = base.clone();
        r.finished_at = Some(r.created_at);
        bad.push(r);
        let mut r = base.clone();
        r.outcome_code = Some("cancelled".to_owned());
        bad.push(r);
        let mut r = base.clone();
        advance(&mut r, "enrolled", 2000);
        r.finished_at = Some(r.expires_at + time::Duration::seconds(1));
        r.updated_at = r.finished_at.unwrap();
        bad.push(r);
        let mut r = base.clone();
        advance(&mut r, "registered", 2001);
        r.enrollment_id = Some(Uuid::nil());
        bad.push(r);
        let mut r = base.clone();
        advance(&mut r, "registered", 2002);
        r.client_id = Some(" ".to_owned());
        bad.push(r);
        let mut r = base.clone();
        advance(&mut r, "closed", 2003);
        r.outcome_code = Some("not-a-frozen-outcome".to_owned());
        bad.push(r);
        for r in bad {
            c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
            let error = insert(&c, &r).await.err();
            c.batch_execute("ROLLBACK")
                .await
                .map_err(|e| e.to_string())?;
            require(
                matches!(
                    error
                        .as_ref()
                        .and_then(|e| e.as_db_error())
                        .map(|e| e.code().code()),
                    Some("23514")
                ),
                "invalid row was not rejected by an actual CHECK",
            )?;
        }
        let duplicate_attempt = insert(&c, &row(1)).await.err();
        require(
            matches!(
                duplicate_attempt
                    .as_ref()
                    .and_then(|e| e.as_db_error())
                    .map(|e| e.code().code()),
                Some("23505")
            ),
            "attempt primary key accepted duplicate",
        )?;
        let mut enrolled = row(30_000);
        advance(&mut enrolled, "registered", 30_000);
        insert(&c, &enrolled).await.map_err(|e| e.to_string())?;
        let mut duplicate_enrollment = enrolled.clone();
        duplicate_enrollment.attempt_id = row(30_001).attempt_id;
        let duplicate = insert(&c, &duplicate_enrollment).await.err();
        require(
            matches!(
                duplicate
                    .as_ref()
                    .and_then(|e| e.as_db_error())
                    .map(|e| e.code().code()),
                Some("23505")
            ),
            "planned enrollment unique key accepted duplicate",
        )?;
        let mut foreign = row(30_002);
        foreign.owner_user_id = "journal-missing-user".to_owned();
        let missing_owner = insert(&c, &foreign).await.err();
        require(
            matches!(
                missing_owner
                    .as_ref()
                    .and_then(|e| e.as_db_error())
                    .map(|e| e.code().code()),
                Some("23503")
            ),
            "owner FK accepted missing user",
        )?;
        for column in ["created_at", "expires_at", "updated_at"] {
            c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
            let sql = format!(
                "UPDATE {} SET {}='infinity' WHERE attempt_id=$1",
                attempts::TABLE_NAME,
                column
            );
            let error = c.execute(&sql, &[&row(1).attempt_id]).await.err();
            c.batch_execute("ROLLBACK")
                .await
                .map_err(|e| e.to_string())?;
            require(
                matches!(
                    error
                        .as_ref()
                        .and_then(|e| e.as_db_error())
                        .map(|e| e.code().code()),
                    Some("23514")
                ),
                "infinite timestamp passed actual CHECK",
            )?;
        }
        for column in attempts::COLUMN_SPECS
            .iter()
            .filter(|column| column.not_null)
        {
            c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
            let sql = format!(
                "UPDATE {} SET {}=NULL WHERE attempt_id=$1",
                attempts::TABLE_NAME,
                column.name
            );
            let error = c.execute(&sql, &[&row(1).attempt_id]).await.err();
            c.batch_execute("ROLLBACK")
                .await
                .map_err(|e| e.to_string())?;
            require(
                matches!(
                    error
                        .as_ref()
                        .and_then(|e| e.as_db_error())
                        .map(|e| e.code().code()),
                    Some("23502")
                ),
                "registered NOTNULL column accepted NULL",
            )?;
        }
        c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
        let restriction = c
            .execute(
                "UPDATE public.users SET id='journal-replaced-owner' WHERE id=$1",
                &[&OWNER],
            )
            .await
            .err();
        c.batch_execute("ROLLBACK")
            .await
            .map_err(|e| e.to_string())?;
        require(
            matches!(
                restriction
                    .as_ref()
                    .and_then(|e| e.as_db_error())
                    .map(|e| e.code().code()),
                Some("23503")
            ),
            "actual ownerFK did not immediately RESTRICT update",
        )?;
        c.execute("DELETE FROM public.users WHERE id=$1", &[&OWNER])
            .await
            .map_err(|e| e.to_string())?;
        let remaining: i64 = c
            .query_one(
                "SELECT count(*) FROM openbot_internal.gateway_authorization_attempts",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .try_get(0)
            .map_err(|e| e.to_string())?;
        require(remaining == 0, "actual ownerFK did not CASCADE delete")
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn full_catalogue_and_acl_drift_are_definite_refusals() {
    owned("journal48drift", |p| async move {
        initialize(&p,48).await?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        let mutations=[
            "GRANT SELECT ON openbot_internal.gateway_authorization_attempts TO PUBLIC",
            "GRANT SELECT(client_id) ON openbot_internal.gateway_authorization_attempts TO PUBLIC",
            "GRANT SELECT ON openbot_internal.gateway_authorization_attempts TO CURRENT_USER WITH GRANT OPTION",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts OWNER TO pg_database_owner",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts ADD COLUMN extra text",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts ALTER COLUMN journal_schema TYPE integer",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts ALTER COLUMN phase SET DEFAULT 'created'",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts ALTER COLUMN phase DROP NOT NULL",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts ALTER COLUMN client_id TYPE text COLLATE pg_catalog.\"default\"",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts SET(fillfactor=80)",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts DROP CONSTRAINT ga_attempts_scope_check",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts ADD CONSTRAINT extra_check CHECK(auth_generation<9000)",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts DROP CONSTRAINT ga_attempts_owner_fkey; ALTER TABLE openbot_internal.gateway_authorization_attempts ADD CONSTRAINT ga_attempts_owner_fkey FOREIGN KEY(owner_user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts DROP CONSTRAINT ga_attempts_owner_fkey; ALTER TABLE openbot_internal.gateway_authorization_attempts ADD CONSTRAINT ga_attempts_owner_fkey FOREIGN KEY(owner_user_id) REFERENCES public.users(id) ON UPDATE RESTRICT ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts DROP CONSTRAINT ga_attempts_enrollment_key; ALTER TABLE openbot_internal.gateway_authorization_attempts ADD CONSTRAINT ga_attempts_enrollment_key UNIQUE NULLS NOT DISTINCT(enrollment_id)",
            "CREATE INDEX owned_journal_extra ON openbot_internal.gateway_authorization_attempts(auth_generation)",
            "ALTER INDEX openbot_internal.ga_attempts_enrollment_key SET(fillfactor=80)",
            "ALTER TABLE openbot_internal.gateway_authorization_attempts DISABLE TRIGGER ALL",
            "ALTER FUNCTION pg_catalog.\"RI_FKey_check_ins\"() SECURITY DEFINER",
            "ALTER FUNCTION pg_catalog.\"RI_FKey_check_ins\"() OWNER TO pg_database_owner",
            "ALTER FUNCTION pg_catalog.\"RI_FKey_check_ins\"() RENAME TO owned_journal_wrong_identity",
            "GRANT EXECUTE ON FUNCTION pg_catalog.\"RI_FKey_check_ins\"() TO CURRENT_USER WITH GRANT OPTION",
            // Deliberate catalogue corruption controls are confined to this owned database
            // and original transaction; they are never production repair operations.
            "UPDATE pg_catalog.pg_trigger SET tgfoid=1645 WHERE tgconstraint=(SELECT oid FROM pg_catalog.pg_constraint WHERE conname='ga_attempts_owner_fkey' AND conrelid='openbot_internal.gateway_authorization_attempts'::regclass) AND tgfoid=1644",
            "UPDATE pg_catalog.pg_class SET relowner='pg_database_owner'::regrole WHERE oid='public.users_pkey'::regclass",
            "GRANT ALL PRIVILEGES ON openbot_internal.gateway_authorization_attempts TO CURRENT_USER;UPDATE pg_catalog.pg_class SET relacl=(SELECT relacl FROM pg_catalog.pg_class WHERE oid='openbot_internal.gateway_authorization_attempts'::regclass) WHERE oid='public.users_pkey'::regclass",
            "UPDATE pg_catalog.pg_trigger SET tgname='wrong_generated_identifier' WHERE tgconstraint=(SELECT oid FROM pg_catalog.pg_constraint WHERE conname='ga_attempts_owner_fkey' AND conrelid='openbot_internal.gateway_authorization_attempts'::regclass) AND tgfoid=1644",
            "CREATE FUNCTION openbot_internal.owned_journal_noop() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$; CREATE TRIGGER owned_journal_extra BEFORE INSERT ON openbot_internal.gateway_authorization_attempts FOR EACH ROW EXECUTE FUNCTION openbot_internal.owned_journal_noop()",
            "CREATE TABLE openbot_internal.owned_journal_reference(id uuid REFERENCES openbot_internal.gateway_authorization_attempts(attempt_id))",
        ];
        for sql in mutations { reject_schema_mutation(&c,sql).await?; }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn original48_v2_transaction_replay_requires_whole_journal() {
    owned("journal48v2txn", |p| async move {
        initialize(&p,48).await?;
        let mut c=p.get().await.map_err(|e|e.to_string())?;
        // Normal native replay calls the original current V2 transaction observer.
        require(native::apply_through(&mut c, 48).await.map_err(|e|e.to_string())?==native::ApplyOutcome::AlreadyApplied,
            "current48 original transaction failed")?;
        c.batch_execute("ALTER TABLE openbot_internal.gateway_authorization_attempts ADD COLUMN damaged text")
            .await.map_err(|e|e.to_string())?;
        let refusal=native::apply_through(&mut c, 48).await;
        require(matches!(refusal,Err(ref error) if structurally_invalid(error)),
            "current48 V2 transaction accepted damaged journal")?;
        let still_damaged:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='openbot_internal.gateway_authorization_attempts'::regclass AND attname='damaged')",&[])
            .await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
        require(still_damaged,"rejected observer repaired fixture")
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn native_holes_names_checksums_unknown49_and_extra_rows_refuse() {
    owned("journal48ledger", |p| async move {
        initialize(&p,48).await?;
        let c=p.get().await.map_err(|e|e.to_string())?;
        let mutations=[
            "DELETE FROM openbot_internal.schema_migrations WHERE version=47",
            "UPDATE openbot_internal.schema_migrations SET name='wrong_name' WHERE version=48",
            "UPDATE openbot_internal.schema_migrations SET checksum=repeat('a',64) WHERE version=48",
            "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES(50,'unknown50',repeat('b',64))",
            "INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES(12,'unexpected12',repeat('c',64))",
        ];
        for sql in mutations {
            c.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
            c.batch_execute(sql).await.map_err(|e|e.to_string())?;
            let refusal=journal::verify(&c).await;
            c.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;
            require(refusal.is_err(),"invalid exact native ledger accepted")?;
            journal::verify(&c).await.map_err(|e|e.to_string())?;
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn default_privilege_and_original_owner_refusal_roll_back_new_migration() {
    for (tag, mutation) in [
        (
            "journal48defaultacl",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA openbot_internal GRANT SELECT ON TABLES TO PUBLIC",
        ),
        (
            "journal48owner",
            "ALTER TABLE public.sdk_gateway_connections OWNER TO pg_database_owner",
        ),
    ] {
        owned(tag,|p|async move{
            initialize(&p,47).await?;
            let mut c=p.get().await.map_err(|e|e.to_string())?;
            c.batch_execute(mutation).await.map_err(|e|e.to_string())?;
            require(native::apply_through(&mut c, 48).await.is_err(),"migration accepted forbidden owner/defaultACL")?;
            let r=c.query_one("SELECT to_regclass('openbot_internal.gateway_authorization_attempts') IS NULL,NOT EXISTS(SELECT 1 FROM openbot_internal.schema_migrations WHERE version=48)",&[])
                .await.map_err(|e|e.to_string())?;
            require(r.try_get::<_,bool>(0).map_err(|e|e.to_string())? && r.try_get::<_,bool>(1).map_err(|e|e.to_string())?,
                "original refused transaction left table/ledger48")
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn actual_query_failure_keeps_query_error_classification() {
    owned("journal48query", |p| async move {
        initialize(&p, 48).await?;
        let c = p.get().await.map_err(|e| e.to_string())?;
        c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
        // A server-side aborted transaction is a genuine query failure, not shape evidence.
        let broken = c.batch_execute("SELECT 1/0").await;
        require(broken.is_err(), "owned query failure control did not fail")?;
        let classified = journal::capture(&c).await;
        c.batch_execute("ROLLBACK")
            .await
            .map_err(|e| e.to_string())?;
        require(
            matches!(classified, Err(InfraError::Query { .. })),
            "query failure relabeled schema_invalid",
        )
    })
    .await;
}

#[test]
fn row_metadata_has_twenty_ordered_columns_and_six_options() {
    assert_eq!(attempts::COLUMNS.len(), 20);
    assert_eq!(
        attempts::COLUMN_SPECS.iter().filter(|c| c.not_null).count(),
        14
    );
    assert_eq!(
        attempts::COLUMN_SPECS
            .iter()
            .filter(|c| !c.not_null)
            .count(),
        6
    );
    assert_eq!(row(1).as_sql_params().len(), 20);
    assert_eq!(
        format!("{:?}", row(1)),
        "GatewayAuthorizationAttemptRow(<redacted>)"
    );
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn distinct_and_colliding_owner_o_u_s_keep_object_specific_mapping() {
    owned("journal48owners", |p| async move {
        let mut c = p.get().await.map_err(|e| e.to_string())?;
        let name = format!("openbot_it_journal_{}", Uuid::new_v4().simple());
        require(
            name.len() < 63
                && name
                    .chars()
                    .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == '_'),
            "owned role identity invalid",
        )?;
        let database: String = c
            .query_one("SELECT current_database()", &[])
            .await
            .map_err(|e| e.to_string())?
            .try_get(0)
            .map_err(|e| e.to_string())?;
        require(
            database.starts_with("openbot_it_")
                && database
                    .chars()
                    .all(|v| v.is_ascii_alphanumeric() || v == '_'),
            "role test escaped owned database",
        )?;
        // This temporary NOLOGIN role has no production account or connection.
        c.batch_execute(&format!(
            "CREATE ROLE \"{name}\" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
            GRANT CREATE ON DATABASE \"{database}\" TO \"{name}\";
            GRANT USAGE,CREATE ON SCHEMA public TO \"{name}\";SET ROLE \"{name}\";"
        ))
        .await
        .map_err(|e| e.to_string())?;
        let result = async {
            baseline::apply(&c).await.map_err(|e| e.to_string())?;
            native::apply_through(&mut c, 47)
                .await
                .map_err(|e| e.to_string())?;
            c.batch_execute(&format!(
                "RESET ROLE;ALTER TABLE public.users OWNER TO pg_database_owner;
                GRANT REFERENCES ON public.users TO \"{name}\";SET ROLE \"{name}\";"
            ))
            .await
            .map_err(|e| e.to_string())?;
            require(
                native::apply_through(&mut c, 48)
                    .await
                    .map_err(|e| e.to_string())?
                    == native::ApplyOutcome::Applied,
                "different owner fixture could not apply original48",
            )?;
            let actual = journal::capture(&c).await.map_err(|e| e.to_string())?;
            println!(
                "JOURNAL48_CAPTURE distinct_ous {}",
                serde_json::to_string(&actual).map_err(|e| e.to_string())?
            );
            let o = &actual["rawFacts"]["ownerAnchorRaw"]["ownerOidRaw"];
            let u = &actual["rawFacts"]["referencedOwnerRaw"]["ownerOidRaw"];
            let s = &actual["rawFacts"]["systemOwnerRaw"]["ownerOidRaw"];
            require(
                o != u && o != s && u != s && s == "10",
                "genuine owner identities not distinguishable",
            )?;
            journal::verify(&c).await.map_err(|e| e.to_string())?;
            let expected: Value = serde_json::from_str(include_str!(
                "../../../fixtures/db/gateway-authorization-attempts-0048.json"
            ))
            .map_err(|e| e.to_string())?;
            require(
                whole_schema_for_oracle(&actual)? == expected["schema"],
                "different-owner whole oracle mismatch",
            )?;
            // Make U collide with S; O remains separate. Identity-specific markers must survive.
            c.batch_execute(&format!(
                "RESET ROLE;ALTER TABLE public.users OWNER TO CURRENT_USER;
                GRANT REFERENCES ON public.users TO \"{name}\";SET ROLE \"{name}\";"
            ))
            .await
            .map_err(|e| e.to_string())?;
            let collision = journal::capture(&c).await.map_err(|e| e.to_string())?;
            println!(
                "JOURNAL48_CAPTURE colliding_us {}",
                serde_json::to_string(&collision).map_err(|e| e.to_string())?
            );
            require(
                collision["rawFacts"]["referencedOwnerRaw"]["ownerOidRaw"]
                    == collision["rawFacts"]["systemOwnerRaw"]["ownerOidRaw"],
                "U/S collision control not actual",
            )?;
            require(
                whole_schema_for_oracle(&collision)? == expected["schema"],
                "colliding-owner whole oracle mismatch",
            )?;
            journal::verify(&c).await.map_err(|e| e.to_string())
        }
        .await;
        // Always attempt explicit owned-role teardown after the body, retaining failures.
        let reset = c
            .batch_execute("RESET ROLE")
            .await
            .map_err(|e| e.to_string());
        let cleanup = if reset.is_ok() {
            c.batch_execute(&format!(
                "DROP OWNED BY \"{name}\" CASCADE;DROP ROLE \"{name}\";"
            ))
            .await
            .map_err(|e| e.to_string())
        } else {
            reset
        };
        result.and(cleanup)
    })
    .await;
}
