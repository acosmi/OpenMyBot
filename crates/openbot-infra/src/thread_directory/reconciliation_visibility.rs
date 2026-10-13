//! One static authority CTE, composed into each single-statement Unknown read.

pub(crate) const VISIBLE_RUN: &str = r"
WITH visible_run AS (
  SELECT r.run_id,r.thread_id,r.status,r.foreground,r.terminal_event_seq,r.actor_id,r.bot_id
  FROM public.runs r
  JOIN public.threads t ON t.thread_id=r.thread_id
  JOIN public.users u ON u.id=r.actor_id
  JOIN public.agents b ON b.id=r.bot_id
  JOIN public.agent_profiles p ON p.agent_id=b.id
  LEFT JOIN public.deployment_packages bp ON bp.id=b.package_id
  WHERE r.thread_id=$1 AND r.run_id=$2 AND r.actor_id=$3
    AND t.deployment_id=$4 AND t.tenant_id=$5 AND t.status<>'deleted'
    AND NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_completions hc
                   WHERE hc.thread_id=t.thread_id AND hc.deployment_id=t.deployment_id
                     AND hc.tenant_id=t.tenant_id)
    AND coalesce(u.auth_generation,0)=$6
    AND EXISTS(SELECT 1 FROM public.user_roles ur
               WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
    AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email))
    AND p.deleted_at IS NULL AND (p.visibility='public' OR p.owner_user_id=$3)
    AND (b.package_id IS NULL OR bp.tenant_id=$5)
    AND (
      (t.anchor_kind='direct_bot' AND t.anchor_id=b.id AND EXISTS(
        SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=$3))
      OR (t.anchor_kind='channel' AND EXISTS(
        SELECT 1 FROM public.channels ch
        JOIN public.channel_memberships cm ON cm.channel_id=ch.id AND cm.user_id=$3
        JOIN public.channel_agents ca ON ca.channel_id=ch.id AND ca.agent_id=b.id
        LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id
        WHERE ch.id=t.anchor_id AND (ch.package_id IS NULL OR cp.tenant_id=$5)))
    )
)
";
