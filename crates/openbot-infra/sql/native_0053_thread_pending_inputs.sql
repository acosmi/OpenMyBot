CREATE TABLE openbot_internal.thread_pending_inputs (
    run_id text PRIMARY KEY,
    thread_id text NOT NULL REFERENCES public.threads(thread_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    actor_id text NOT NULL,
    auth_generation bigint NOT NULL,
    bot_id text NOT NULL,
    anchor_kind text NOT NULL CHECK (anchor_kind = 'direct_bot'),
    message text NOT NULL,
    selected_skill_slugs text[] NOT NULL DEFAULT '{}',
    model_selection jsonb NOT NULL,
    artifact_refs text[] NOT NULL DEFAULT '{}',
    state text NOT NULL CHECK (state IN ('pending', 'held', 'dispatched', 'withdrawn')),
    held_reason text CHECK (held_reason IN ('stopped_by_user', 'authority_stale', 'authority_unavailable', 'dispatch_rejected')),
    last_error text,
    submitted_at timestamptz NOT NULL,
    queued_at timestamptz NOT NULL,
    state_changed_at timestamptz NOT NULL,
    CHECK ((state = 'held') = (held_reason IS NOT NULL))
);

CREATE INDEX thread_pending_inputs_fifo_idx
    ON openbot_internal.thread_pending_inputs(thread_id, state, queued_at, run_id);
