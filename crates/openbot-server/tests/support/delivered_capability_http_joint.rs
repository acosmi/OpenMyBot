//! New C7 HTTP observations reuse the actual collector, resolver and owned PG fixture.
//! Router dispatch is a real HTTP request, not a TCP or browser wire observation.

use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode};
use openbot_contracts::runtime_capabilities::{
    RuntimeCapabilitiesResponse, RuntimeCapabilityId, RuntimeCapabilityReasonCode,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tower::ServiceExt as _;

use super::{
    A_ID, COOKIE_A, COOKIE_B, FINGERPRINT_SQL, FinalizeGate, Fixture, HttpFacts, Mode, PATH,
    actual_blocked_pid, admin_config, entry, require, with_temp_database,
};

fn start_http(router: axum::Router, cookie: &'static str) -> JoinHandle<Result<HttpFacts, String>> {
    tokio::spawn(async move {
        let request = Request::builder()
            .method(Method::GET)
            .uri(PATH)
            .header("cookie", format!("openbot_session={cookie}"))
            .body(Body::empty())
            .map_err(|_| "C7 original HTTP request build failed".to_owned())?;
        let response = router
            .oneshot(request)
            .await
            .map_err(|_| "C7 original Router dispatch failed".to_owned())?;
        require(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                == Some("no-store"),
            "C7 original HTTP response must be no-store",
        )?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024)
            .await
            .map_err(|_| "C7 bounded original HTTP body failed".to_owned())?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|_| "C7 original HTTP JSON failed".to_owned())?;
        Ok(HttpFacts { status, value })
    })
}

async fn join_http(
    pending: &mut Option<JoinHandle<Result<HttpFacts, String>>>,
    limit: Duration,
) -> Result<HttpFacts, String> {
    let task = pending
        .as_mut()
        .ok_or("C7 original request handle missing")?;
    let joined = tokio::time::timeout(limit, task)
        .await
        .map_err(|_| "C7 original HTTP request exceeded outer observation bound".to_owned())?;
    *pending = None;
    joined.map_err(|_| "C7 original HTTP request task failed".to_owned())?
}

async fn close_pending(pending: Option<JoinHandle<Result<HttpFacts, String>>>) {
    if let Some(task) = pending {
        task.abort();
        let _ = task.await;
    }
}

#[derive(Clone, Copy)]
enum JointChange {
    SessionAndPolicy,
    ConfigurationAndKey,
}

async fn final_http_joint(tag: &str, change: JointChange) {
    let case_id = match change {
        JointChange::SessionAndPolicy => "C7.http-final-session-policy-joint",
        JointChange::ConfigurationAndKey => "C7.http-final-config-key-joint",
    };
    with_temp_database(&admin_config(tag), tag, |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        let gate = FinalizeGate::new();
        fixture.install_actual(Mode::Sessions, Some(gate.clone())).await?;
        let setup_auth = fixture.auth(COOKIE_A).await?;
        if matches!(change, JointChange::ConfigurationAndKey) {
            // A configured policy keeps the late key visible: an unconfigured policy would hide
            // the provider level and make the stale and fresh results equal.
            fixture.pool.get().await.map_err(|_| "C7 policy setup acquire")?
                .batch_execute("INSERT INTO public.action_policy(id,mode,deny,allow) VALUES('current','enforce',ARRAY['true'],'{}')")
                .await.map_err(|_| "C7 policy setup")?;
        }
        let mut pending = Some(start_http(fixture.router.clone(), COOKIE_A));
        let result = async {
            gate.entered().await?;
            let mut controller = fixture.pool.get().await.map_err(|_| "C7 controller acquire")?;
            let controller_pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[])
                .await.map_err(|_| "C7 controller PID")?.get(0);
            let tx = controller.transaction().await.map_err(|_| "C7 controller transaction")?;
            tx.batch_execute("SET LOCAL lock_timeout='1500ms'; LOCK TABLE public.action_policy IN ACCESS EXCLUSIVE MODE")
                .await.map_err(|_| "C7 original source relation lock")?;
            let observer = fixture.pool.get().await.map_err(|_| "C7 independent observer acquire")?;
            gate.release();
            let producer = actual_blocked_pid(&observer, controller_pid, "%WITH policy_scan AS MATERIALIZED%").await?;
            require(producer != controller_pid, "C7 actual producer/controller identity conflated")?;
            match change {
                JointChange::SessionAndPolicy => {
                    tx.execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID]).await
                        .map_err(|_| "C7 original session A deletion")?;
                    tx.batch_execute("INSERT INTO public.action_policy(id,mode,deny,allow) VALUES('current','enforce',ARRAY['true'],'{}')")
                        .await.map_err(|_| "C7 current policy insertion")?;
                }
                JointChange::ConfigurationAndKey => {
                    fixture.seed_default_key().await?;
                    fixture.seed_custom(&setup_auth).await?;
                }
            }
            let changed: Value = tx.query_one(FINGERPRINT_SQL, &[]).await
                .map_err(|_| "C7 controller-only changed fingerprint")?.get(0);
            let expected: [u8; 32] = Sha256::digest(serde_json::to_vec(&changed)
                .map_err(|_| "C7 changed fingerprint encoding")?).into();
            tx.commit().await.map_err(|_| "C7 actual source relation release")?;
            let actual = join_http(&mut pending, Duration::from_secs(3)).await?;
            require(fixture.port.as_ref().ok_or("C7 actual collector missing")?.calls() == (1, 1, 1),
                "C7 original HTTP bypassed collector/finalizer/tail")?;
            match change {
                JointChange::SessionAndPolicy => {
                    require(actual.value.get("capabilities").is_none(), "C7 stale whole projection leaked")?;
                    require(actual.status == StatusCode::UNAUTHORIZED,
                        "C7 original A authority deletion must reject the whole HTTP result")?;
                    gate.release();
                    let sibling = fixture.http(Method::GET, PATH, Some(COOKIE_B), &[]).await?;
                    require(sibling.status == StatusCode::OK, "C7 original A deletion invalidated sibling B")?;
                    let dto: RuntimeCapabilitiesResponse = serde_json::from_value(sibling.value)
                        .map_err(|_| "C7 sibling exact capability DTO")?;
                    require(entry(&dto, RuntimeCapabilityId::AgentTools).reason_code()
                        == RuntimeCapabilityReasonCode::ModelKeyMissing,
                        "C7 sibling HTTP reused policy absence instead of the actual changed source")?;
                    require(fixture.auth(COOKIE_B).await?.auth_generation().get() == 0,
                        "C7 original A deletion advanced actor generation")?;
                }
                JointChange::ConfigurationAndKey => {
                    require(actual.status == StatusCode::OK, "C7 late configured/key sources refused the query")?;
                    let dto: RuntimeCapabilitiesResponse = serde_json::from_value(actual.value)
                        .map_err(|_| "C7 late source exact capability DTO")?;
                    for id in [RuntimeCapabilityId::AgentTools, RuntimeCapabilityId::ModelCustomV1] {
                        require(entry(&dto, id).reason_code() == RuntimeCapabilityReasonCode::ProviderUnproven,
                            "C7 late configured/key sources reused the stale missing-key projection")?;
                    }
                }
            }
            require(fixture.fingerprint().await? == expected,
                "C7 capability HTTP wrote beyond controller-only changes")?;
            eprintln!("{}", json!({"caseId":case_id,"httpStatus":actual.status.as_u16(),"noStore":true,
                "staleWholeProjectionAbsent":true,"originalProducerWaitObserved":true,"effectFreeAfterController":true}));
            Ok::<(), String>(())
        }.await;
        gate.release();
        close_pending(pending).await;
        fixture.finish().await;
        result
    }).await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_c7_http_final_session_policy_joint_preserves_sibling() {
    final_http_joint("cap7sessionpolicy", JointChange::SessionAndPolicy).await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_c7_http_final_configuration_key_joint_observes_late_sources() {
    final_http_joint("cap7configkey", JointChange::ConfigurationAndKey).await;
}

#[tokio::test]
#[ignore = "requires root-owned isolated PostgreSQL"]
async fn actual_c7_http_whole_deadline_and_separate_worker_quiescence() {
    with_temp_database(&admin_config("cap7deadline"), "cap7deadline", |config| async move {
        let mut fixture = Fixture::new(config, Mode::Sessions).await?;
        let gate = FinalizeGate::new();
        fixture.install_actual(Mode::Sessions, Some(gate.clone())).await?;
        let before = fixture.fingerprint().await?;
        let began = Instant::now();
        let mut pending = Some(start_http(fixture.router.clone(), COOKIE_A));
        let result = async {
            gate.entered().await?;
            let mut controller = fixture.pool.get().await.map_err(|_| "C7 deadline controller acquire")?;
            let pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await
                .map_err(|_| "C7 deadline controller PID")?.get(0);
            let tx = controller.transaction().await.map_err(|_| "C7 deadline controller transaction")?;
            tx.batch_execute("LOCK TABLE public.action_policy IN ACCESS EXCLUSIVE MODE").await
                .map_err(|_| "C7 deadline actual source relation lock")?;
            let observer = fixture.pool.get().await.map_err(|_| "C7 deadline observer acquire")?;
            gate.release();
            let producer = actual_blocked_pid(&observer, pid, "%WITH policy_scan AS MATERIALIZED%").await?;
            let actual = join_http(&mut pending, Duration::from_millis(6500)).await?;
            require(actual.status == StatusCode::SERVICE_UNAVAILABLE && actual.value.get("capabilities").is_none(),
                "C7 whole HTTP deadline returned stale success")?;
            let elapsed = began.elapsed();
            require(elapsed >= Duration::from_secs(4) && elapsed < Duration::from_millis(6500),
                "C7 original five-second deadline was reset")?;
            tx.rollback().await.map_err(|_| "C7 deadline source relation rollback")?;
            let mut quiescent = false;
            for _ in 0..200 {
                let row = observer.query_opt("SELECT state,xact_start FROM pg_stat_activity WHERE pid=$1", &[&producer])
                    .await.map_err(|_| "C7 actual worker observation")?;
                quiescent = row.is_none_or(|row| row.get::<_,String>(0) != "active"
                    && row.get::<_,Option<OffsetDateTime>>(1).is_none());
                if quiescent { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            require(quiescent, "C7 timeout alone did not close the actual SQL producer")?;
            require(fixture.fingerprint().await? == before, "C7 timed-out HTTP query wrote facts")?;
            eprintln!("{}",json!({"caseId":"C7.http-original-whole-deadline","httpStatus":503,
                "noStore":true,"elapsedMs":elapsed.as_millis(),"workerSeparatelyQuiescent":quiescent,"effectFree":true}));
            Ok::<(),String>(())
        }.await;
        gate.release();
        close_pending(pending).await;
        fixture.finish().await;
        result
    }).await;
}
