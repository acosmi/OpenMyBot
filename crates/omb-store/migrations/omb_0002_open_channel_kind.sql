ALTER TABLE openmybot.channel_bindings
    DROP CONSTRAINT channel_bindings_check_2,
    ADD CONSTRAINT channel_bindings_check_2 CHECK (binding_kind <> 'receiver' OR (channel_kind ~ '^[a-z][a-z0-9_]{0,31}$' AND channel_kind <> 'host' AND credential_envelope IS NOT NULL AND sender_key IS NULL AND chat_key IS NULL AND workspace_dir IS NULL AND thread_id IS NULL AND status <> 'pending')),
    DROP CONSTRAINT channel_bindings_check_3,
    ADD CONSTRAINT channel_bindings_check_3 CHECK (binding_kind <> 'sender' OR (channel_kind ~ '^[a-z][a-z0-9_]{0,31}$' AND channel_kind <> 'host' AND (status <> 'pending' OR (pairing_code_hash IS NOT NULL AND pairing_expires_at IS NOT NULL AND workspace_dir IS NOT NULL AND thread_id IS NOT NULL AND granted_generation IS NOT NULL AND sender_key IS NULL)) AND (status NOT IN ('active','suspended') OR (sender_key IS NOT NULL AND chat_key IS NOT NULL AND workspace_dir IS NOT NULL AND thread_id IS NOT NULL AND granted_generation IS NOT NULL AND pairing_code_hash IS NULL)))),
    DROP CONSTRAINT channel_bindings_check_11,
    ADD CONSTRAINT channel_bindings_check_11 CHECK (channel_kind ~ '^[a-z][a-z0-9_]{0,31}$');

ALTER TABLE openmybot.channel_events
    DROP CONSTRAINT channel_events_check_16,
    ADD CONSTRAINT channel_events_check_16 CHECK (channel_kind ~ '^[a-z][a-z0-9_]{0,31}$'),
    DROP CONSTRAINT channel_events_check_21,
    ADD CONSTRAINT channel_events_check_21 CHECK (gap_reason IN ('daemon_down','daemon_suspended','connect_failed','stream_broken','receiver_suspended','plugin_missing'));

ALTER TABLE openmybot.deliveries
    DROP CONSTRAINT deliveries_check_5,
    ADD CONSTRAINT deliveries_check_5 CHECK (channel_kind ~ '^[a-z][a-z0-9_]{0,31}$' AND channel_kind <> 'host');
