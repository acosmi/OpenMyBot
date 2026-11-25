ALTER TABLE openmybot.channel_bindings ADD COLUMN host_kind text;
UPDATE openmybot.channel_bindings SET host_kind=CASE WHEN binding_kind='host' THEN source_key ELSE 'crabcode' END WHERE binding_kind <> 'receiver';

ALTER TABLE openmybot.channel_bindings
    DROP CONSTRAINT channel_bindings_check_4,
    ADD CONSTRAINT channel_bindings_check_4 CHECK (binding_kind <> 'host' OR (channel_kind='host' AND source_key IN ('crabcode','claude','dsh','pi') AND sender_key IS NOT NULL AND sender_key='host:' || source_key AND workspace_dir IS NOT NULL AND granted_generation IS NOT NULL AND status <> 'pending')),
    ADD CONSTRAINT channel_bindings_check_14 CHECK (host_kind IN ('crabcode','claude','dsh','pi')),
    ADD CONSTRAINT channel_bindings_check_15 CHECK ((binding_kind = 'receiver') = (host_kind IS NULL) AND (binding_kind <> 'host' OR host_kind = source_key));

DROP INDEX openmybot.binding_live_kind;
CREATE UNIQUE INDEX binding_live_kind ON openmybot.channel_bindings(binding_kind,channel_kind) WHERE status IN ('pending','active','suspended') AND binding_kind <> 'host';
CREATE UNIQUE INDEX host_live_kind ON openmybot.channel_bindings(source_key) WHERE status IN ('pending','active','suspended') AND binding_kind = 'host';

ALTER TABLE openmybot.host_driver_sessions
    DROP CONSTRAINT host_driver_sessions_check_11,
    ADD CONSTRAINT host_driver_sessions_check_11 CHECK (host_kind IN ('crabcode','claude','dsh','pi'));
