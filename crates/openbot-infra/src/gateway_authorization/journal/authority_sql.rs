//! Fixed journal SQL and original guarded readback closure.

use super::{
    Ack, Error, GatewayAuthorizationJournal, JournalWrite, Kind, OperationGate, Row, admitted_row,
    closed_row, current, observation_error,
};
use crate::db::{InfraError, native, tables::TableRow};
use openbot_contracts::{auth::AuthContext, request_binding::HostRequestBindingIdentity};
use openbot_domain::audit::{
    event::{AuditEvent, AuditEventType},
    payload::{
        AuditFact, AuditGatewayAuthorizationAttemptId, AuditGatewayAuthorizationOutcome,
        AuditGatewayAuthorizationPhase, AuditIdentifier, AuditLabel, AuditPayload,
    },
};
use openbot_domain::vault::SecretBytes;
use tokio_postgres::Transaction;
use uuid::Uuid;

const INSERT: &str = r"/* gateway_authorization_attempt_created */
 INSERT INTO openbot_internal.gateway_authorization_attempts
 (attempt_id,journal_schema,deployment_id,tenant_id,owner_user_id,auth_generation,
 installation_id,runtime_epoch,issuer,redirect_uri,phase,client_id,enrollment_id,
 registration_admitted_at,code_admitted_at,created_at,expires_at,updated_at,finished_at,outcome_code)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)";
const SELECT: &str = r"/* gateway_authorization_exact_readback */
 SELECT attempt_id,journal_schema,deployment_id,tenant_id,owner_user_id,auth_generation,
 installation_id,runtime_epoch,issuer,redirect_uri,phase,client_id,enrollment_id,
 registration_admitted_at,code_admitted_at,created_at,expires_at,updated_at,finished_at,outcome_code
 FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1";
const SELECT_FOR_UPDATE: &str = r"/* gateway_authorization_attempt_lock */
 SELECT attempt_id,journal_schema,deployment_id,tenant_id,owner_user_id,auth_generation,
 installation_id,runtime_epoch,issuer,redirect_uri,phase,client_id,enrollment_id,
 registration_admitted_at,code_admitted_at,created_at,expires_at,updated_at,finished_at,outcome_code
 FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1 FOR UPDATE";
const CAS_ADMIT: &str = r"/* gateway_authorization_registration_admitted */
 UPDATE openbot_internal.gateway_authorization_attempts
 SET phase='registration_admitted',registration_admitted_at=$21,updated_at=$21
 WHERE attempt_id=$1 AND journal_schema=$2 AND deployment_id=$3 AND tenant_id=$4
 AND owner_user_id=$5 AND auth_generation=$6 AND installation_id=$7 AND runtime_epoch=$8
 AND issuer=$9 AND redirect_uri=$10 AND phase=$11
 AND client_id IS NOT DISTINCT FROM $12 AND enrollment_id IS NOT DISTINCT FROM $13
 AND registration_admitted_at IS NOT DISTINCT FROM $14 AND code_admitted_at IS NOT DISTINCT FROM $15
 AND created_at=$16 AND expires_at=$17 AND updated_at=$18
 AND finished_at IS NOT DISTINCT FROM $19 AND outcome_code IS NOT DISTINCT FROM $20";
const CAS_CLOSE: &str = r"/* gateway_authorization_attempt_closed */
 UPDATE openbot_internal.gateway_authorization_attempts
 SET phase='closed',updated_at=$21,finished_at=$21,outcome_code=$22
 WHERE attempt_id=$1 AND journal_schema=$2 AND deployment_id=$3 AND tenant_id=$4
 AND owner_user_id=$5 AND auth_generation=$6 AND installation_id=$7 AND runtime_epoch=$8
 AND issuer=$9 AND redirect_uri=$10 AND phase=$11
 AND client_id IS NOT DISTINCT FROM $12 AND enrollment_id IS NOT DISTINCT FROM $13
 AND registration_admitted_at IS NOT DISTINCT FROM $14 AND code_admitted_at IS NOT DISTINCT FROM $15
 AND created_at=$16 AND expires_at=$17 AND updated_at=$18
 AND finished_at IS NOT DISTINCT FROM $19 AND outcome_code IS NOT DISTINCT FROM $20";

const CAS_REGISTERED: &str = r"/* gateway_authorization_registered */
 UPDATE openbot_internal.gateway_authorization_attempts
 SET phase='registered',client_id=$21,enrollment_id=$22,updated_at=$23
 WHERE attempt_id=$1 AND journal_schema=$2 AND deployment_id=$3 AND tenant_id=$4
 AND owner_user_id=$5 AND auth_generation=$6 AND installation_id=$7 AND runtime_epoch=$8
 AND issuer=$9 AND redirect_uri=$10 AND phase=$11
 AND client_id IS NOT DISTINCT FROM $12 AND enrollment_id IS NOT DISTINCT FROM $13
 AND registration_admitted_at IS NOT DISTINCT FROM $14 AND code_admitted_at IS NOT DISTINCT FROM $15
 AND created_at=$16 AND expires_at=$17 AND updated_at=$18
 AND finished_at IS NOT DISTINCT FROM $19 AND outcome_code IS NOT DISTINCT FROM $20";

const CAS_CODE_ADMITTED: &str = r"/* gateway_authorization_code_admitted */
 UPDATE openbot_internal.gateway_authorization_attempts
 SET phase='code_admitted',code_admitted_at=$21,updated_at=$21
 WHERE attempt_id=$1 AND journal_schema=$2 AND deployment_id=$3 AND tenant_id=$4
 AND owner_user_id=$5 AND auth_generation=$6 AND installation_id=$7 AND runtime_epoch=$8
 AND issuer=$9 AND redirect_uri=$10 AND phase=$11
 AND client_id IS NOT DISTINCT FROM $12 AND enrollment_id IS NOT DISTINCT FROM $13
 AND registration_admitted_at IS NOT DISTINCT FROM $14 AND code_admitted_at IS NOT DISTINCT FROM $15
 AND created_at=$16 AND expires_at=$17 AND updated_at=$18
 AND finished_at IS NOT DISTINCT FROM $19 AND outcome_code IS NOT DISTINCT FROM $20";

pub(super) async fn cas_code_admitted(
    tx: &Transaction<'_>,
    old: &Row,
    next: &Row,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    if *next != super::code_admitted_row(old, next.updated_at)? {
        return Err(Error::new(Kind::Refused));
    }
    let mut params = old.as_sql_params();
    params.push(&next.updated_at);
    let count = gate
        .io(tx.execute(CAS_CODE_ADMITTED, &params), observation_error)
        .await?;
    if count != 1 {
        return Err(Error::new(Kind::Refused));
    }
    Ok(())
}

pub(super) async fn append_code_admitted_audit(
    tx: &Transaction<'_>,
    auth: &AuthContext,
    next: &Row,
    key: &SecretBytes,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    if next.phase != "code_admitted"
        || next.code_admitted_at != Some(next.updated_at)
        || next
            .registration_admitted_at
            .is_none_or(|t| t > next.updated_at)
        || next.outcome_code.is_some()
        || next.finished_at.is_some()
    {
        return Err(Error::new(Kind::Refused));
    }
    let attempt = next.attempt_id.to_string();
    let payload = AuditPayload::from_facts([
        AuditFact::GatewayAuthorizationJournalSchema,
        AuditFact::GatewayAuthorizationAttemptId(
            AuditGatewayAuthorizationAttemptId::new(attempt.clone()).map_err(observation_error)?,
        ),
        AuditFact::GatewayAuthorizationPhase(AuditGatewayAuthorizationPhase::CodeAdmitted),
        AuditFact::GatewayAuthorizationOutcome(None),
    ])
    .map_err(observation_error)?;
    let (id, created_at) = gate
        .io(
            crate::repo::audit::next_event_coordinates(tx),
            observation_error,
        )
        .await?;
    let event = AuditEvent {
        id,
        actor: Some(auth.actor().clone()),
        event_type: AuditEventType::GATEWAY_AUTHORIZATION_CODE_ADMITTED,
        target_kind: AuditLabel::new("gateway_authorization_attempt"),
        target_id: Some(AuditIdentifier::new(attempt).map_err(observation_error)?),
        payload,
        created_at,
    };
    gate.io(
        crate::repo::audit::append_event_in_transaction(tx, &event, key.expose()),
        observation_error,
    )
    .await?;
    Ok(())
}

pub(super) async fn cas_registered(
    tx: &Transaction<'_>,
    old: &Row,
    next: &Row,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    let client = next
        .client_id
        .as_deref()
        .ok_or_else(|| Error::new(Kind::Refused))?;
    let enrollment = next
        .enrollment_id
        .ok_or_else(|| Error::new(Kind::Refused))?;
    if *next != super::registered_row(old, client, enrollment, next.updated_at)? {
        return Err(Error::new(Kind::Refused));
    }
    let mut params = old.as_sql_params();
    params.push(&next.client_id);
    params.push(&next.enrollment_id);
    params.push(&next.updated_at);
    let count = gate
        .io(tx.execute(CAS_REGISTERED, &params), observation_error)
        .await?;
    if count != 1 {
        return Err(Error::new(Kind::Refused));
    }
    Ok(())
}

pub(super) async fn append_registered_audit(
    tx: &Transaction<'_>,
    auth: &AuthContext,
    next: &Row,
    key: &SecretBytes,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    if next.phase != "registered" || next.outcome_code.is_some() {
        return Err(Error::new(Kind::Refused));
    }
    let attempt = next.attempt_id.to_string();
    let payload = AuditPayload::from_facts([
        AuditFact::GatewayAuthorizationJournalSchema,
        AuditFact::GatewayAuthorizationAttemptId(
            AuditGatewayAuthorizationAttemptId::new(attempt.clone()).map_err(observation_error)?,
        ),
        AuditFact::GatewayAuthorizationPhase(AuditGatewayAuthorizationPhase::Registered),
        AuditFact::GatewayAuthorizationOutcome(None),
    ])
    .map_err(observation_error)?;
    let (id, created_at) = gate
        .io(
            crate::repo::audit::next_event_coordinates(tx),
            observation_error,
        )
        .await?;
    let event = AuditEvent {
        id,
        actor: Some(auth.actor().clone()),
        event_type: AuditEventType::GATEWAY_AUTHORIZATION_REGISTERED,
        target_kind: AuditLabel::new("gateway_authorization_attempt"),
        target_id: Some(AuditIdentifier::new(attempt).map_err(observation_error)?),
        payload,
        created_at,
    };
    gate.io(
        crate::repo::audit::append_event_in_transaction(tx, &event, key.expose()),
        observation_error,
    )
    .await?;
    Ok(())
}

pub(super) fn native_error(error: InfraError) -> Error {
    Error::new(match error {
        InfraError::RepositoryInvariant {
            code: "gateway_authorization_journal_native_prefix_invalid",
        } => Kind::LedgerInvalid,
        InfraError::RepositoryInvariant {
            code: "gateway_authorization_schema_invalid",
        } => Kind::SchemaInvalid,
        _ => Kind::ObservationUnknown,
    })
}
pub(super) async fn create(
    tx: &Transaction<'_>,
    row: &Row,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    let params = row.as_sql_params();
    let count = gate
        .io(tx.execute(INSERT, &params), observation_error)
        .await?;
    if count != 1 {
        return Err(Error::new(Kind::Refused));
    }
    Ok(())
}
pub(super) async fn lock_attempt(
    tx: &Transaction<'_>,
    id: Uuid,
    gate: &OperationGate<'_>,
) -> Result<Row, Error> {
    let raw = gate
        .io(tx.query_opt(SELECT_FOR_UPDATE, &[&id]), observation_error)
        .await?
        .ok_or_else(|| Error::new(Kind::Refused))?;
    Row::try_from(&raw).map_err(observation_error)
}
pub(super) async fn cas_admit(
    tx: &Transaction<'_>,
    old: &Row,
    next: &Row,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    if *next != admitted_row(old, next.updated_at)? {
        return Err(Error::new(Kind::Refused));
    }
    let mut params = old.as_sql_params();
    params.push(&next.updated_at);
    let count = gate
        .io(tx.execute(CAS_ADMIT, &params), observation_error)
        .await?;
    if count != 1 {
        return Err(Error::new(Kind::Refused));
    }
    Ok(())
}
pub(super) async fn cas_close(
    tx: &Transaction<'_>,
    old: &Row,
    next: &Row,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    if *next != closed_row(old, next, next.updated_at)? {
        return Err(Error::new(Kind::Refused));
    }
    let mut params = old.as_sql_params();
    params.push(&next.updated_at);
    params.push(&next.outcome_code);
    let count = gate
        .io(tx.execute(CAS_CLOSE, &params), observation_error)
        .await?;
    if count != 1 {
        return Err(Error::new(Kind::Refused));
    }
    Ok(())
}
pub(super) async fn append_audit(
    tx: &Transaction<'_>,
    auth: &AuthContext,
    next: &Row,
    action: JournalWrite,
    key: &SecretBytes,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    let (event_type, phase) = match action {
        JournalWrite::Create => (
            AuditEventType::GATEWAY_AUTHORIZATION_ATTEMPT_CREATED,
            AuditGatewayAuthorizationPhase::Created,
        ),
        JournalWrite::Admit => (
            AuditEventType::GATEWAY_AUTHORIZATION_REGISTRATION_ADMITTED,
            AuditGatewayAuthorizationPhase::RegistrationAdmitted,
        ),
        JournalWrite::Close => (
            AuditEventType::GATEWAY_AUTHORIZATION_ATTEMPT_CLOSED,
            AuditGatewayAuthorizationPhase::Closed,
        ),
    };
    if phase.as_str() != next.phase {
        return Err(Error::new(Kind::Refused));
    }
    let outcome = match next.outcome_code.as_deref() {
        None => None,
        Some("refused") => Some(AuditGatewayAuthorizationOutcome::Refused),
        Some("dependency_unknown") => Some(AuditGatewayAuthorizationOutcome::DependencyUnknown),
        _ => return Err(Error::new(Kind::Refused)),
    };
    if matches!(action, JournalWrite::Close) != outcome.is_some() {
        return Err(Error::new(Kind::Refused));
    }
    let attempt = next.attempt_id.to_string();
    let payload = AuditPayload::from_facts([
        AuditFact::GatewayAuthorizationJournalSchema,
        AuditFact::GatewayAuthorizationAttemptId(
            AuditGatewayAuthorizationAttemptId::new(attempt.clone()).map_err(observation_error)?,
        ),
        AuditFact::GatewayAuthorizationPhase(phase),
        AuditFact::GatewayAuthorizationOutcome(outcome),
    ])
    .map_err(observation_error)?;
    let (id, created_at) = gate
        .io(
            crate::repo::audit::next_event_coordinates(tx),
            observation_error,
        )
        .await?;
    let event = AuditEvent {
        id,
        actor: Some(auth.actor().clone()),
        event_type,
        target_kind: AuditLabel::new("gateway_authorization_attempt"),
        target_id: Some(AuditIdentifier::new(attempt).map_err(observation_error)?),
        payload,
        created_at,
    };
    gate.io(
        crate::repo::audit::append_event_in_transaction(tx, &event, key.expose()),
        observation_error,
    )
    .await?;
    Ok(())
}

pub(super) async fn readback_exact(
    journal: &GatewayAuthorizationJournal,
    auth: &AuthContext,
    identity: &HostRequestBindingIdentity,
    expected: &Row,
    gate: &OperationGate<'_>,
) -> Result<(), Error> {
    let observation = current::borrow_current(journal, auth, gate)
        .await
        .map_err(|e| e.with_acks(Ack::Timely, Ack::NotAttempted))?;
    if !observation.identity().same_binding(identity) {
        return Err(Error::new(Kind::Refused).with_acks(Ack::Timely, Ack::NotAttempted));
    }
    let mut client = gate
        .io(journal.pool.get_guarded(gate.deadline().into_std()), |_| {
            Error::new(Kind::ReadbackUnproven)
        })
        .await
        .map_err(|e| e.with_acks(Ack::Timely, Ack::NotAttempted))?;
    let tx = gate
        .io(client.begin_read_committed_read_only(), |_| {
            Error::new(Kind::ReadbackUnproven)
        })
        .await
        .map_err(|e| e.with_acks(Ack::Timely, Ack::Unknown))?;
    let observation_result = async {
        gate.io(
            native::validate_gateway_authorization_journal_in_transaction(tx.as_transaction()),
            native_error,
        )
        .await?;
        let tail = current::observe_actor(tx.as_transaction(), auth, &observation, gate).await?;
        let raw = gate
            .io(
                tx.as_transaction()
                    .query_opt(SELECT, &[&expected.attempt_id]),
                |_| Error::new(Kind::ReadbackUnproven),
            )
            .await?
            .ok_or_else(|| Error::new(Kind::ReadbackUnproven))?;
        let actual = Row::try_from(&raw).map_err(|_| Error::new(Kind::ReadbackUnproven))?;
        if actual != *expected {
            return Err(Error::new(Kind::ReadbackUnproven));
        }
        current::verify_tail(tail.as_ref(), auth, gate)?;
        Ok::<_, Error>(tail)
    }
    .await;
    let ack = match gate.terminal(tx.rollback(), false).await {
        Ok(ack) => ack,
        Err((error, ack)) => return Err(error.with_acks(Ack::Timely, ack)),
    };
    drop(client);
    let tail = observation_result.map_err(|e| e.with_acks(Ack::Timely, ack))?;
    current::verify_tail(tail.as_ref(), auth, gate).map_err(|e| e.with_acks(Ack::Timely, ack))?;
    Ok(())
}
