-- Automation definitions, durable inputs and cumulative budgets (spec revision R485).
-- Core Thread/Run references retain their original keys. Their authority and scope
-- are checked together in the original admission/begin/budget transaction.

CREATE TABLE openbot_internal.automation_definitions (
    automation_id text PRIMARY KEY CHECK (automation_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    owner_id text NOT NULL,
    bot_id text NOT NULL,
    thread_id text NOT NULL UNIQUE REFERENCES public.threads(thread_id),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    state text NOT NULL CHECK (state IN ('paused', 'enabled', 'tombstoned')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    tombstoned_at timestamptz,
    pending_count bigint NOT NULL DEFAULT 0 CHECK (pending_count BETWEEN 0 AND 100),
    active_count bigint NOT NULL DEFAULT 0 CHECK (active_count BETWEEN 0 AND 1),
    UNIQUE (deployment_id, tenant_id, automation_id),
    CHECK ((state = 'tombstoned') = (tombstoned_at IS NOT NULL))
);

CREATE TABLE openbot_internal.automation_delegations (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    automation_id text NOT NULL,
    delegation_revision bigint NOT NULL CHECK (delegation_revision > 0),
    owner_id text NOT NULL,
    bot_id text NOT NULL,
    thread_id text NOT NULL REFERENCES public.threads(thread_id),
    granted_auth_generation bigint NOT NULL CHECK (granted_auth_generation >= 0),
    grant_snapshot jsonb NOT NULL CHECK (jsonb_typeof(grant_snapshot) = 'object'),
    validity text NOT NULL CHECK (validity IN ('until_revoked', 'expires')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz,
    revoked_at timestamptz,
    PRIMARY KEY (deployment_id, tenant_id, automation_id, delegation_revision),
    FOREIGN KEY (deployment_id, tenant_id, automation_id)
        REFERENCES openbot_internal.automation_definitions(deployment_id, tenant_id, automation_id),
    CHECK ((validity = 'expires') = (expires_at IS NOT NULL))
);

CREATE TABLE openbot_internal.automation_definition_revisions (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    automation_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    config_snapshot jsonb NOT NULL CHECK (jsonb_typeof(config_snapshot) = 'object'),
    delegation_revision bigint,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (deployment_id, tenant_id, automation_id, revision),
    FOREIGN KEY (deployment_id, tenant_id, automation_id)
        REFERENCES openbot_internal.automation_definitions(deployment_id, tenant_id, automation_id),
    FOREIGN KEY (deployment_id, tenant_id, automation_id, delegation_revision)
        REFERENCES openbot_internal.automation_delegations(deployment_id, tenant_id, automation_id, delegation_revision)
);

ALTER TABLE openbot_internal.automation_definitions
    ADD CONSTRAINT automation_definitions_current_revision_fkey
    FOREIGN KEY (deployment_id, tenant_id, automation_id, current_revision)
    REFERENCES openbot_internal.automation_definition_revisions(deployment_id, tenant_id, automation_id, revision)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE openbot_internal.automation_receivers (
    receiver_id text PRIMARY KEY CHECK (receiver_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    automation_id text NOT NULL,
    adapter text NOT NULL CHECK (adapter IN ('sender_key', 'github')),
    source_principal jsonb NOT NULL CHECK (jsonb_typeof(source_principal) = 'object'),
    event_filter jsonb NOT NULL CHECK (jsonb_typeof(event_filter) = 'object'),
    current_key_revision bigint NOT NULL CHECK (current_key_revision > 0),
    vault_record_ref text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    revoked_at timestamptz,
    dedup_count bigint NOT NULL DEFAULT 0 CHECK (dedup_count >= 0),
    UNIQUE (deployment_id, tenant_id, receiver_id),
    UNIQUE (deployment_id, tenant_id, automation_id, receiver_id),
    FOREIGN KEY (deployment_id, tenant_id, automation_id)
        REFERENCES openbot_internal.automation_definitions(deployment_id, tenant_id, automation_id)
);

CREATE TABLE openbot_internal.automation_deliveries (
    receipt_id text PRIMARY KEY CHECK (receipt_id ~ '^[A-Za-z0-9._:-]{1,128}$' AND receipt_id LIKE 'adel:%'),
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    automation_id text NOT NULL,
    receiver_id text NOT NULL,
    source_event_key text NOT NULL,
    key_revision bigint NOT NULL CHECK (key_revision > 0),
    definition_revision bigint NOT NULL,
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    verified_body_digest bytea CHECK (octet_length(verified_body_digest) = 32),
    status text NOT NULL CHECK (status IN ('accepted', 'verification_only', 'alias')),
    alias_of text,
    normalized_data jsonb,
    received_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    terminal_at timestamptz,
    data_cleared_at timestamptz,
    UNIQUE (deployment_id, tenant_id, receiver_id, source_event_key),
    UNIQUE (deployment_id, tenant_id, receiver_id, receipt_id),
    UNIQUE (deployment_id, tenant_id, automation_id, receipt_id),
    FOREIGN KEY (deployment_id, tenant_id, automation_id, receiver_id)
        REFERENCES openbot_internal.automation_receivers(deployment_id, tenant_id, automation_id, receiver_id),
    FOREIGN KEY (deployment_id, tenant_id, automation_id, definition_revision)
        REFERENCES openbot_internal.automation_definition_revisions(deployment_id, tenant_id, automation_id, revision),
    FOREIGN KEY (deployment_id, tenant_id, receiver_id, alias_of)
        REFERENCES openbot_internal.automation_deliveries(deployment_id, tenant_id, receiver_id, receipt_id),
    CHECK ((status = 'alias') = (alias_of IS NOT NULL))
);

CREATE UNIQUE INDEX automation_deliveries_github_canonical_idx
    ON openbot_internal.automation_deliveries(deployment_id, tenant_id, receiver_id, verified_body_digest)
    WHERE verified_body_digest IS NOT NULL AND status <> 'alias';

CREATE TABLE openbot_internal.automation_occurrences (
    occurrence_id text PRIMARY KEY CHECK (occurrence_id ~ '^[A-Za-z0-9._:-]{1,128}$' AND occurrence_id LIKE 'aocc:%'),
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    automation_id text NOT NULL,
    definition_revision bigint NOT NULL,
    trigger_kind text NOT NULL CHECK (trigger_kind IN ('manual', 'cron', 'event')),
    delivery_receipt_id text,
    manual_operation_id text CHECK (manual_operation_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    planned_at timestamptz,
    intent_snapshot jsonb NOT NULL CHECK (jsonb_typeof(intent_snapshot) = 'object'),
    run_id text UNIQUE REFERENCES public.runs(run_id),
    state text NOT NULL CHECK (state IN ('pending', 'blocked_budget', 'blocked_model', 'run_created', 'superseded', 'terminated_by_pause', 'expired')),
    reason_code text,
    accepted_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT statement_timestamp() + interval '24 hours',
    terminal_at timestamptz,
    UNIQUE (deployment_id, tenant_id, automation_id, manual_operation_id),
    UNIQUE (deployment_id, tenant_id, automation_id, planned_at),
    UNIQUE (deployment_id, tenant_id, delivery_receipt_id),
    FOREIGN KEY (deployment_id, tenant_id, automation_id, definition_revision)
        REFERENCES openbot_internal.automation_definition_revisions(deployment_id, tenant_id, automation_id, revision),
    FOREIGN KEY (deployment_id, tenant_id, automation_id, delivery_receipt_id)
        REFERENCES openbot_internal.automation_deliveries(deployment_id, tenant_id, automation_id, receipt_id),
    CHECK ((trigger_kind = 'manual' AND manual_operation_id IS NOT NULL AND delivery_receipt_id IS NULL AND planned_at IS NULL)
        OR (trigger_kind = 'cron' AND planned_at IS NOT NULL AND manual_operation_id IS NULL AND delivery_receipt_id IS NULL)
        OR (trigger_kind = 'event' AND delivery_receipt_id IS NOT NULL AND manual_operation_id IS NULL AND planned_at IS NULL)),
    CHECK ((state = 'run_created') = (run_id IS NOT NULL)),
    CHECK (expires_at = accepted_at + interval '24 hours')
);

CREATE TABLE openbot_internal.automation_cron_progress (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    automation_id text NOT NULL,
    timezone_id text NOT NULL,
    tzdb_version text NOT NULL,
    last_observed_pg_at timestamptz,
    last_processed_slot timestamptz,
    skipped_first timestamptz,
    skipped_last timestamptz,
    skipped_count bigint NOT NULL DEFAULT 0 CHECK (skipped_count >= 0),
    skip_reasons jsonb NOT NULL CHECK (jsonb_typeof(skip_reasons) = 'object'),
    skipped_total bigint NOT NULL DEFAULT 0 CHECK (skipped_total >= 0),
    unavailable_reason text CHECK (unavailable_reason = 'timezone_unavailable'),
    PRIMARY KEY (deployment_id, tenant_id, automation_id),
    FOREIGN KEY (deployment_id, tenant_id, automation_id)
        REFERENCES openbot_internal.automation_definitions(deployment_id, tenant_id, automation_id),
    CHECK ((skipped_count = 0 AND skipped_first IS NULL AND skipped_last IS NULL)
        OR (skipped_count > 0 AND skipped_first IS NOT NULL AND skipped_last IS NOT NULL AND skipped_first <= skipped_last))
);

CREATE TABLE openbot_internal.automation_workspace_capacity (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    pending_count bigint NOT NULL DEFAULT 0 CHECK (pending_count BETWEEN 0 AND 1000),
    active_count bigint NOT NULL DEFAULT 0 CHECK (active_count BETWEEN 0 AND 4),
    PRIMARY KEY (deployment_id, tenant_id)
);

CREATE TABLE openbot_internal.automation_budget_policies (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    scope_kind text NOT NULL CHECK (scope_kind IN ('owner', 'workspace', 'automation')),
    scope_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    metric text NOT NULL CHECK (metric IN ('tokens', 'sampling_calls', 'tool_calls', 'compute_millis', 'money_microunits')),
    window_origin timestamptz,
    window_seconds bigint,
    window_limit bigint CHECK (window_limit >= 0),
    total_limit bigint CHECK (total_limit >= 0),
    currency text,
    current bool NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (deployment_id, tenant_id, scope_kind, scope_id, revision, metric),
    CHECK (scope_kind <> 'workspace' OR scope_id = 'workspace'),
    CHECK (window_limit IS NOT NULL OR total_limit IS NOT NULL),
    CHECK ((window_origin IS NULL AND window_seconds IS NULL AND window_limit IS NULL)
        OR (window_origin IS NOT NULL AND window_seconds IS NOT NULL AND window_seconds > 0 AND window_limit IS NOT NULL)),
    CHECK ((metric = 'money_microunits') = (currency IS NOT NULL))
);

CREATE UNIQUE INDEX automation_budget_policies_current_idx
    ON openbot_internal.automation_budget_policies(deployment_id, tenant_id, scope_kind, scope_id, metric)
    WHERE current;

CREATE TABLE openbot_internal.automation_budget_balances (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    policy_revision bigint NOT NULL,
    metric text NOT NULL,
    bucket_start timestamptz NOT NULL,
    is_total bool NOT NULL,
    used bigint NOT NULL DEFAULT 0 CHECK (used >= 0),
    reserved bigint NOT NULL DEFAULT 0 CHECK (reserved >= 0),
    PRIMARY KEY (deployment_id, tenant_id, scope_kind, scope_id, policy_revision, metric, bucket_start, is_total),
    FOREIGN KEY (deployment_id, tenant_id, scope_kind, scope_id, policy_revision, metric)
        REFERENCES openbot_internal.automation_budget_policies(deployment_id, tenant_id, scope_kind, scope_id, revision, metric),
    CHECK (NOT is_total OR bucket_start = timestamptz '1970-01-01T00:00:00Z')
);

CREATE TABLE openbot_internal.automation_budget_attempts (
    attempt_id text PRIMARY KEY CHECK (attempt_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    automation_id text NOT NULL,
    root_run_id text NOT NULL REFERENCES public.runs(run_id),
    run_id text NOT NULL REFERENCES public.runs(run_id),
    usage_kind text NOT NULL CHECK (usage_kind IN ('sampling', 'tool', 'compute')),
    source_attempt_ref text NOT NULL,
    state text NOT NULL CHECK (state IN ('reserved', 'unknown', 'settled')),
    reserved_bound jsonb NOT NULL CHECK (jsonb_typeof(reserved_bound) = 'object'),
    actual_usage jsonb CHECK (jsonb_typeof(actual_usage) = 'object'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    settled_at timestamptz,
    UNIQUE (deployment_id, tenant_id, attempt_id),
    UNIQUE (deployment_id, tenant_id, run_id, usage_kind, source_attempt_ref),
    FOREIGN KEY (deployment_id, tenant_id, automation_id)
        REFERENCES openbot_internal.automation_definitions(deployment_id, tenant_id, automation_id)
);

CREATE TABLE openbot_internal.automation_budget_reservations (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    attempt_id text NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    policy_revision bigint NOT NULL,
    metric text NOT NULL,
    bucket_start timestamptz NOT NULL,
    is_total bool NOT NULL,
    reserved bigint NOT NULL CHECK (reserved >= 0),
    settled bigint NOT NULL DEFAULT 0 CHECK (settled >= 0),
    released bigint NOT NULL DEFAULT 0 CHECK (released >= 0),
    PRIMARY KEY (deployment_id, tenant_id, attempt_id, scope_kind, scope_id, policy_revision, metric, bucket_start, is_total),
    FOREIGN KEY (deployment_id, tenant_id, attempt_id)
        REFERENCES openbot_internal.automation_budget_attempts(deployment_id, tenant_id, attempt_id),
    FOREIGN KEY (deployment_id, tenant_id, scope_kind, scope_id, policy_revision, metric, bucket_start, is_total)
        REFERENCES openbot_internal.automation_budget_balances(deployment_id, tenant_id, scope_kind, scope_id, policy_revision, metric, bucket_start, is_total),
    CHECK (settled <= reserved AND released <= reserved - settled)
);

CREATE TABLE openbot_internal.automation_receiver_refusals (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    receiver_id text NOT NULL,
    reason_code text NOT NULL CHECK (reason_code IN ('automation_source_unauthorized', 'automation_not_accepting', 'event_not_accepted', 'event_outside_window', 'malformed_payload', 'payload_too_large', 'automation_rate_limited')),
    count bigint NOT NULL CHECK (count >= 0),
    first_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    last_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (deployment_id, tenant_id, receiver_id, reason_code),
    FOREIGN KEY (deployment_id, tenant_id, receiver_id)
        REFERENCES openbot_internal.automation_receivers(deployment_id, tenant_id, receiver_id),
    CHECK (first_at <= last_at)
);

CREATE INDEX automation_definitions_owner_idx
    ON openbot_internal.automation_definitions(deployment_id, tenant_id, owner_id, updated_at DESC, automation_id DESC);
CREATE INDEX automation_occurrences_pending_idx
    ON openbot_internal.automation_occurrences(deployment_id, tenant_id, automation_id, accepted_at, occurrence_id)
    WHERE state IN ('pending', 'blocked_budget', 'blocked_model');
CREATE INDEX automation_occurrences_list_idx
    ON openbot_internal.automation_occurrences(automation_id, accepted_at DESC, occurrence_id DESC);
CREATE INDEX automation_deliveries_list_idx
    ON openbot_internal.automation_deliveries(automation_id, received_at DESC, receipt_id DESC);
CREATE INDEX automation_deliveries_clear_data_idx
    ON openbot_internal.automation_deliveries(terminal_at)
    WHERE normalized_data IS NOT NULL;
CREATE INDEX automation_delegations_expiry_idx
    ON openbot_internal.automation_delegations(deployment_id, tenant_id, expires_at, automation_id)
    WHERE revoked_at IS NULL;

-- FIX-036-1: Rust owns the closed error-code set. The final writer guard still
-- requires the event errorCode to match the terminal Run's actual error_code.
CREATE OR REPLACE FUNCTION openbot_internal.thread_history_terminal_payload(p_type text,p_payload jsonb)
 RETURNS boolean LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE
 SECURITY INVOKER COST 100 SET search_path=pg_catalog,openbot_internal AS $$
BEGIN
 IF p_type IN('completed','cancelled') THEN
  RETURN p_payload IS NOT DISTINCT FROM pg_catalog.jsonb_build_object('status',p_type);
 ELSIF p_type IN('failed','reconciliation_required') THEN
  RETURN COALESCE(p_payload->>'errorCode' ~ '^[a-z][a-z0-9_]{1,63}$',false)
   AND p_payload IS NOT DISTINCT FROM
    pg_catalog.jsonb_build_object('status',p_type,'errorCode',p_payload->>'errorCode');
 END IF;
 RETURN false;
END;
$$;
