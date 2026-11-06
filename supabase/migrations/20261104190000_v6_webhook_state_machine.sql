-- =========================================================================
-- InstaAuto v6 Pre-staging Webhook State Machine
-- Additive migration. Creates webhook_event_ledger and webhook_action_ledger
-- tables plus RPC functions for idempotent, lease-based event processing.
-- No historical migrations are modified.
-- =========================================================================

-- ---------------------------------------------------------------------------
-- Event ledger: one row per stable inbound webhook event key.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.webhook_event_ledger (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_key TEXT NOT NULL,
  event_type TEXT NOT NULL,
  user_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  data JSONB,
  status TEXT NOT NULL DEFAULT 'claimed',
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  retry_at TIMESTAMPTZ,
  lease_token UUID,
  lease_expires_at TIMESTAMPTZ,
  error_category TEXT,
  error_code TEXT,
  action_plan_sealed BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  CONSTRAINT ck_event_ledger_status
    CHECK (status IN ('claimed','completed','released','manual_review','dead_letter')),
  CONSTRAINT ck_event_ledger_event_type
    CHECK (event_type IN ('comment','message','story','follow_gate','quarantine')),
  CONSTRAINT ck_event_ledger_attempts
    CHECK (attempt_count >= 0 AND attempt_count <= max_attempts),
  CONSTRAINT ck_event_ledger_max_attempts
    CHECK (max_attempts > 0 AND max_attempts <= 10),
  CONSTRAINT ck_event_ledger_error_code_len
    CHECK (error_code IS NULL OR length(error_code) <= 20),
  CONSTRAINT ck_event_ledger_data_size
    CHECK (data IS NULL OR pg_column_size(data) <= 65536),
  CONSTRAINT ck_event_ledger_key_len
    CHECK (length(trim(event_key)) > 0 AND length(event_key) <= 500),
  CONSTRAINT ck_event_ledger_lease_pair
    CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
  CONSTRAINT ck_event_ledger_lease_status
    CHECK (
      (status = 'claimed' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
      OR (status <> 'claimed' AND lease_token IS NULL AND lease_expires_at IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_event_ledger_event_key
  ON public.webhook_event_ledger(event_key);
CREATE INDEX IF NOT EXISTS idx_event_ledger_retry
  ON public.webhook_event_ledger(retry_at)
  WHERE status IN ('claimed','released') AND retry_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_event_ledger_user_status
  ON public.webhook_event_ledger(user_id, status);
CREATE INDEX IF NOT EXISTS idx_event_ledger_lease
  ON public.webhook_event_ledger(lease_expires_at)
  WHERE lease_expires_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Action ledger: one row per required action within an event.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.webhook_action_ledger (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID NOT NULL REFERENCES public.webhook_event_ledger(id) ON DELETE CASCADE,
  action_key TEXT NOT NULL,
  action_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  retry_at TIMESTAMPTZ,
  lease_token UUID,
  lease_expires_at TIMESTAMPTZ,
  error_category TEXT,
  error_code TEXT,
  provider_message_id TEXT,
  provider_status TEXT,
  provider_payload_hash TEXT,
  side_effect BOOLEAN NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  CONSTRAINT ck_action_ledger_status
    CHECK (status IN ('pending','processing','completed','retryable','unknown','permanently_failed')),
  CONSTRAINT ck_action_ledger_attempts
    CHECK (attempt_count >= 0 AND attempt_count <= max_attempts),
  CONSTRAINT ck_action_ledger_max_attempts
    CHECK (max_attempts > 0 AND max_attempts <= 5),
  CONSTRAINT ck_action_ledger_error_code_len
    CHECK (error_code IS NULL OR length(error_code) <= 20),
  CONSTRAINT ck_action_side_effect_mapping
    CHECK (
      (action_type IN ('public_reply','dm_send','mark_seen','typing_on','follow_gate_card') AND side_effect = TRUE)
      OR
      (action_type IN ('inbox_persist','outbox_persist','verify_follow_status') AND side_effect = FALSE)
    ),
  CONSTRAINT ck_action_key_len
    CHECK (length(trim(action_key)) > 0 AND length(action_key) <= 500),
  CONSTRAINT ck_action_lease_pair
    CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
  CONSTRAINT ck_action_lease_status
    CHECK (
      (status = 'processing' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
      OR (status <> 'processing' AND lease_token IS NULL AND lease_expires_at IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_action_ledger_event_action
  ON public.webhook_action_ledger(event_id, action_key);
CREATE INDEX IF NOT EXISTS idx_action_ledger_event_status
  ON public.webhook_action_ledger(event_id, status);
CREATE INDEX IF NOT EXISTS idx_action_ledger_lease
  ON public.webhook_action_ledger(lease_expires_at)
  WHERE lease_expires_at IS NOT NULL;

ALTER TABLE public.webhook_event_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_action_ledger ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_claim_event
-- Claim or reclaim an event ledger row. Attempt count increments only on
-- successful lease acquisition. Enforces retry_at and max_attempts.
--
-- Locking/clock discipline (Corrections B & D):
-- 1. Attempt insertion with the idempotency key.
-- 2. On conflict, lock the existing row with SELECT ... FOR UPDATE.
-- 3. Refresh clock_timestamp() AFTER acquiring the row lock.
-- 4. Re-evaluate status, retry eligibility, expiry, terminal and manual-review
--    state against the fresh clock.
-- 5. An unknown external side-effect child action blocks reclaim (manual_review).
-- 6. The reclaim UPDATE is guarded by expected-state predicates.
-- 7. attempt_count increments only when a genuine new lease is acquired (F).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_claim_event(
  p_event_key TEXT,
  p_event_type TEXT,
  p_user_id BIGINT,
  p_data JSONB,
  p_lease_ttl_seconds INTEGER DEFAULT 300,
  OUT outcome TEXT,
  OUT event_id UUID,
  OUT lease_token UUID,
  OUT lease_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event_id UUID := gen_random_uuid();
  v_new_token UUID := gen_random_uuid();
  v_row public.webhook_event_ledger%ROWTYPE;
  v_now TIMESTAMPTZ := clock_timestamp();
  v_unknown_side_effect_child INTEGER := 0;
BEGIN
  IF p_lease_ttl_seconds <= 0 OR p_lease_ttl_seconds > 86400 THEN
    outcome := 'invalid_ttl';
    event_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF p_event_type IS NULL OR p_event_type NOT IN ('comment','message','story','follow_gate','quarantine') THEN
    outcome := 'invalid_event_type';
    event_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF p_event_key IS NULL OR length(trim(p_event_key)) = 0 OR length(p_event_key) > 500 THEN
    outcome := 'invalid_event_key';
    event_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  INSERT INTO public.webhook_event_ledger (
    id, event_key, event_type, user_id, data, status, attempt_count,
    max_attempts, lease_token, lease_expires_at, created_at, updated_at
  )
  VALUES (
    v_event_id, p_event_key, p_event_type, p_user_id, p_data, 'claimed', 1, 5,
    v_new_token, v_now + (p_lease_ttl_seconds || ' seconds')::interval,
    v_now, v_now
  )
  ON CONFLICT (event_key) DO NOTHING
  RETURNING id, webhook_event_ledger.lease_token, webhook_event_ledger.lease_expires_at, user_id, event_type
  INTO v_row.id, v_row.lease_token, v_row.lease_expires_at, v_row.user_id, v_row.event_type;

  IF FOUND THEN
    outcome := 'created';
    event_id := v_row.id;
    lease_token := v_row.lease_token;
    lease_expires_at := v_row.lease_expires_at;
    RETURN;
  END IF;

  -- Lock the existing row before re-evaluating its state (B: row serialization).
  SELECT *
  INTO v_row
  FROM public.webhook_event_ledger
  WHERE event_key = p_event_key
  FOR UPDATE;

  -- Refresh clock after acquiring the row lock (D: never validate against a
  -- time value captured before a lock wait).
  v_now := clock_timestamp();

  IF v_row.user_id <> p_user_id OR v_row.event_type <> p_event_type THEN
    outcome := 'identity_mismatch';
    event_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_row.status = 'completed' THEN
    outcome := 'duplicate_completed';
    event_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_row.status = 'dead_letter' THEN
    outcome := 'dead_letter';
    event_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_row.status = 'manual_review' THEN
    outcome := 'manual_review';
    event_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_row.status = 'released' THEN
    IF v_row.retry_at IS NOT NULL AND v_row.retry_at > v_now THEN
      outcome := 'retry_not_due';
      event_id := v_row.id;
      lease_token := NULL;
      lease_expires_at := NULL;
      RETURN;
    END IF;
  END IF;

  IF v_row.status = 'claimed' AND v_row.lease_expires_at IS NOT NULL AND v_row.lease_expires_at > v_now THEN
    outcome := 'active_lease';
    event_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  -- B #5: an unknown external side-effect child action blocks reclaim. The
  -- event must be resolved through manual review before it can be reclaimed.
  SELECT COUNT(*)
  INTO v_unknown_side_effect_child
  FROM public.webhook_action_ledger
  WHERE webhook_action_ledger.event_id = v_row.id
    AND side_effect = TRUE
    AND status = 'unknown';

  IF v_unknown_side_effect_child > 0 THEN
    UPDATE public.webhook_event_ledger
    SET status = 'manual_review',
        lease_token = NULL,
        lease_expires_at = NULL,
        error_category = 'unknown',
        error_code = 'unknown_side_effect',
        updated_at = v_now
    WHERE id = v_row.id
      AND status <> 'manual_review';
    outcome := 'manual_review';
    event_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_row.attempt_count >= v_row.max_attempts THEN
    UPDATE public.webhook_event_ledger
    SET status = 'dead_letter',
        lease_token = NULL,
        lease_expires_at = NULL,
        updated_at = v_now
    WHERE id = v_row.id AND status <> 'dead_letter';
    outcome := 'dead_letter';
    event_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  -- F #8: a genuine new lease acquisition increments attempt_count exactly
  -- once. Guarded by expected-state predicates so a concurrent holder wins.
  UPDATE public.webhook_event_ledger
  SET status = 'claimed',
      attempt_count = v_row.attempt_count + 1,
      lease_token = v_new_token,
      lease_expires_at = v_now + (p_lease_ttl_seconds || ' seconds')::interval,
      updated_at = v_now
  WHERE id = v_row.id
    AND status IN ('released', 'claimed')
    AND (webhook_event_ledger.lease_token IS NULL
         OR webhook_event_ledger.lease_expires_at IS NULL
         OR webhook_event_ledger.lease_expires_at <= v_now)
  RETURNING id, webhook_event_ledger.lease_token, webhook_event_ledger.lease_expires_at
  INTO v_row.id, v_row.lease_token, v_row.lease_expires_at;

  IF NOT FOUND THEN
    outcome := 'active_lease';
    event_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  outcome := 'reclaimed';
  event_id := v_row.id;
  lease_token := v_row.lease_token;
  lease_expires_at := v_row.lease_expires_at;
  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_register_action_plan
-- Register and seal all required actions for an event in one transaction.
-- Rejects conflicting pre-existing unsealed action plans.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_register_action_plan(
  p_event_id UUID,
  p_event_lease_token UUID,
  p_actions JSONB,
  OUT outcome TEXT,
  OUT plan_sealed BOOLEAN,
  OUT action_count INTEGER
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event public.webhook_event_ledger%ROWTYPE;
  v_elem JSONB;
  v_action_key TEXT;
  v_action_type TEXT;
  v_side_effect BOOLEAN;
  v_action_keys TEXT[] := ARRAY[]::TEXT[];
  v_action_count INTEGER := 0;
  v_zero_action_event_types TEXT[] := ARRAY['follow_gate'];
  v_valid_types TEXT[] := ARRAY[
    'public_reply','dm_send','mark_seen','typing_on','follow_gate_card',
    'inbox_persist','outbox_persist','verify_follow_status'
  ];
  v_arr_len INTEGER;
  v_i INTEGER;
  v_existing_actions INTEGER;
  v_now TIMESTAMPTZ;
BEGIN
  IF p_actions IS NULL OR jsonb_typeof(p_actions) <> 'array' THEN
    outcome := 'invalid_actions_spec';
    plan_sealed := FALSE;
    action_count := 0;
    RETURN;
  END IF;

  SELECT *
  INTO v_event
  FROM public.webhook_event_ledger
  WHERE id = p_event_id
  FOR UPDATE;

  -- Refresh the clock immediately after acquiring the parent event lock, and
  -- before any lease-expiry validation, so a clock read taken while waiting
  -- for the lock cannot let an expired lease slip through.
  v_now := clock_timestamp();

  IF NOT FOUND THEN
    outcome := 'event_not_found';
    plan_sealed := FALSE;
    action_count := 0;
    RETURN;
  END IF;

  IF v_event.status <> 'claimed' THEN
    outcome := 'event_not_claimable';
    plan_sealed := v_event.action_plan_sealed;
    action_count := 0;
    RETURN;
  END IF;

  IF v_event.lease_token IS DISTINCT FROM p_event_lease_token THEN
    outcome := 'event_lease_mismatch';
    plan_sealed := v_event.action_plan_sealed;
    action_count := 0;
    RETURN;
  END IF;

  IF v_event.lease_expires_at IS NOT NULL AND v_event.lease_expires_at <= v_now THEN
    outcome := 'event_lease_expired';
    plan_sealed := v_event.action_plan_sealed;
    action_count := 0;
    RETURN;
  END IF;

  IF v_event.action_plan_sealed THEN
    outcome := 'plan_sealed';
    plan_sealed := TRUE;
    action_count := 0;
    RETURN;
  END IF;

  v_arr_len := jsonb_array_length(p_actions);
  IF v_arr_len > 50 THEN
    outcome := 'too_many_actions';
    plan_sealed := FALSE;
    action_count := 0;
    RETURN;
  END IF;

  FOR v_i IN 0 .. (v_arr_len - 1) LOOP
    v_elem := p_actions -> v_i;
    IF jsonb_typeof(v_elem) <> 'object' THEN
      outcome := 'action_element_not_object';
      plan_sealed := FALSE;
      action_count := 0;
      RETURN;
    END IF;

    IF NOT (jsonb_typeof(v_elem->'action_key') = 'string') THEN
      outcome := 'action_key_not_string';
      plan_sealed := FALSE;
      action_count := 0;
      RETURN;
    END IF;

    IF NOT (jsonb_typeof(v_elem->'action_type') = 'string') THEN
      outcome := 'action_type_not_string';
      plan_sealed := FALSE;
      action_count := 0;
      RETURN;
    END IF;

    IF NOT (jsonb_typeof(v_elem->'side_effect') = 'boolean') THEN
      outcome := 'side_effect_not_boolean';
      plan_sealed := FALSE;
      action_count := 0;
      RETURN;
    END IF;

    v_action_key := v_elem->>'action_key';
    v_action_type := v_elem->>'action_type';
    v_side_effect := (v_elem->>'side_effect')::BOOLEAN;

    IF length(trim(v_action_key)) = 0 OR length(v_action_key) > 500 THEN
      outcome := 'missing_action_key';
      plan_sealed := FALSE;
      action_count := 0;
      RETURN;
    END IF;

    IF length(trim(v_action_type)) = 0 THEN
      outcome := 'missing_action_type';
      plan_sealed := FALSE;
      action_count := 0;
      RETURN;
    END IF;

    IF NOT (v_action_type = ANY(v_valid_types)) THEN
      outcome := 'invalid_action_type:' || v_action_type;
      plan_sealed := FALSE;
      action_count := 0;
      RETURN;
    END IF;

    IF v_action_type IN ('public_reply','dm_send','mark_seen','typing_on','follow_gate_card') THEN
      IF v_side_effect <> TRUE THEN
        outcome := 'side_effect_mismatch:' || v_action_type;
        plan_sealed := FALSE;
        action_count := 0;
        RETURN;
      END IF;
    ELSIF v_action_type IN ('inbox_persist','outbox_persist','verify_follow_status') THEN
      IF v_side_effect <> FALSE THEN
        outcome := 'side_effect_mismatch:' || v_action_type;
        plan_sealed := FALSE;
        action_count := 0;
        RETURN;
      END IF;
    ELSE
      outcome := 'unsupported_action_type:' || v_action_type;
      plan_sealed := FALSE;
      action_count := 0;
      RETURN;
    END IF;

    IF v_action_key = ANY(v_action_keys) THEN
      outcome := 'duplicate_action_key:' || v_action_key;
      plan_sealed := FALSE;
      action_count := 0;
      RETURN;
    END IF;

    v_action_keys := v_action_keys || v_action_key;
  END LOOP;

  SELECT COUNT(*) INTO v_existing_actions
  FROM public.webhook_action_ledger
  WHERE event_id = p_event_id;

  IF v_existing_actions > 0 AND NOT v_event.action_plan_sealed THEN
    outcome := 'conflicting_action_plan';
    plan_sealed := FALSE;
    action_count := 0;
    RETURN;
  END IF;

  FOR v_i IN 0 .. (v_arr_len - 1) LOOP
    v_elem := p_actions -> v_i;
    INSERT INTO public.webhook_action_ledger (
      event_id, action_key, action_type, status, attempt_count,
      max_attempts, side_effect, created_at, updated_at
    )
    VALUES (
      p_event_id,
      v_elem->>'action_key',
      v_elem->>'action_type',
      'pending', 0, 3,
      (v_elem->>'side_effect')::BOOLEAN,
      v_now, v_now
    )
    ON CONFLICT (event_id, action_key) DO NOTHING;
  END LOOP;

  SELECT COUNT(*) INTO action_count
  FROM public.webhook_action_ledger
  WHERE event_id = p_event_id;

  IF action_count = 0 AND NOT (v_event.event_type = ANY(v_zero_action_event_types)) THEN
    outcome := 'zero_action_not_allowed';
    plan_sealed := FALSE;
    action_count := 0;
    RETURN;
  END IF;

  UPDATE public.webhook_event_ledger
  SET action_plan_sealed = TRUE, updated_at = v_now
  WHERE id = p_event_id;

  outcome := 'plan_registered';
  plan_sealed := TRUE;
  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_claim_action
-- Claim an action: pending or eligible retryable -> processing.
-- Expired external side-effect actions become unknown (never blindly resent).
-- Parent-first lock: event row first, then action row.
--
-- Locking/clock discipline (Corrections C & D):
-- 1. Lock parent event.
-- 2. Validate parent token/status.
-- 3. Lock child action.
-- 4. Obtain fresh clock_timestamp() after both locks are held.
-- 5. Revalidate parent lease expiry AFTER child lock acquisition; a parent
--    lease that expired while waiting for the child lock is rejected.
-- 6. Validate child action status/token/expiry against the fresh clock.
-- 7. Apply the action claim transition (attempt_count increments only here).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_claim_action(
  p_event_id UUID,
  p_event_lease_token UUID,
  p_action_key TEXT,
  p_lease_ttl_seconds INTEGER DEFAULT 300,
  OUT outcome TEXT,
  OUT action_id UUID,
  OUT lease_token UUID,
  OUT lease_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event public.webhook_event_ledger%ROWTYPE;
  v_row public.webhook_action_ledger%ROWTYPE;
  v_new_token UUID := gen_random_uuid();
  v_now TIMESTAMPTZ := clock_timestamp();
BEGIN
  IF p_lease_ttl_seconds <= 0 OR p_lease_ttl_seconds > 86400 THEN
    outcome := 'invalid_ttl';
    action_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  -- 1. Lock parent event row FIRST.
  SELECT *
  INTO v_event
  FROM public.webhook_event_ledger
  WHERE id = p_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    outcome := 'event_not_found';
    action_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_event.status <> 'claimed' THEN
    outcome := 'event_not_claimable';
    action_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_event.lease_token IS DISTINCT FROM p_event_lease_token THEN
    outcome := 'event_lease_mismatch';
    action_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF NOT v_event.action_plan_sealed THEN
    outcome := 'plan_not_sealed';
    action_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  -- 3. Lock child action row SECOND.
  SELECT *
  INTO v_row
  FROM public.webhook_action_ledger
  WHERE event_id = p_event_id AND action_key = p_action_key
  FOR UPDATE;

  IF NOT FOUND THEN
    outcome := 'action_not_registered';
    action_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  -- 4. Fresh clock after both locks are held.
  v_now := clock_timestamp();

  -- 5. Revalidate parent lease expiry AFTER child lock acquisition. A parent
  --    lease that expired while waiting for the child lock must be rejected.
  IF v_event.lease_expires_at IS NOT NULL AND v_event.lease_expires_at <= v_now THEN
    outcome := 'event_lease_expired';
    action_id := NULL;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  -- 6. Validate child action status/token/expiry against the fresh clock.
  IF v_row.status IN ('unknown', 'permanently_failed') THEN
    outcome := 'action_terminal';
    action_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_row.status = 'completed' THEN
    outcome := 'action_completed';
    action_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_row.status = 'retryable' THEN
    IF v_row.retry_at IS NOT NULL AND v_row.retry_at > v_now THEN
      outcome := 'retry_not_due';
      action_id := v_row.id;
      lease_token := NULL;
      lease_expires_at := NULL;
      RETURN;
    END IF;
    IF v_row.attempt_count >= v_row.max_attempts THEN
      UPDATE public.webhook_action_ledger
      SET status = 'permanently_failed', lease_token = NULL, lease_expires_at = NULL,
          updated_at = v_now
      WHERE id = v_row.id;
      outcome := 'action_max_attempts';
      action_id := v_row.id;
      lease_token := NULL;
      lease_expires_at := NULL;
      RETURN;
    END IF;
  END IF;

  IF v_row.status = 'processing' AND v_row.lease_expires_at > v_now THEN
    outcome := 'action_active_lease';
    action_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_row.status = 'processing' AND v_row.lease_expires_at <= v_now AND v_row.side_effect THEN
    UPDATE public.webhook_action_ledger
    SET status = 'unknown', lease_token = NULL, lease_expires_at = NULL,
        updated_at = v_now
    WHERE id = v_row.id
    RETURNING id INTO v_row.id;
    outcome := 'action_expired_unknown';
    action_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  IF v_row.attempt_count >= v_row.max_attempts THEN
    UPDATE public.webhook_action_ledger
    SET status = 'permanently_failed', lease_token = NULL, lease_expires_at = NULL,
        updated_at = v_now
    WHERE id = v_row.id;
    outcome := 'action_max_attempts';
    action_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  -- 7. Apply the action claim transition. attempt_count increments only on a
  --    genuine new action-lease acquisition (F).
  UPDATE public.webhook_action_ledger AS a
  SET status = 'processing',
      attempt_count = v_row.attempt_count + 1,
      lease_token = v_new_token,
      lease_expires_at = v_now + (p_lease_ttl_seconds || ' seconds')::interval,
      updated_at = v_now
  WHERE id = v_row.id
    AND status IN ('pending', 'retryable', 'processing')
    AND (a.lease_token IS NULL OR a.lease_expires_at IS NULL OR a.lease_expires_at <= v_now)
  RETURNING id, a.lease_token, a.lease_expires_at
  INTO v_row.id, v_row.lease_token, v_row.lease_expires_at;

  IF NOT FOUND THEN
    outcome := 'action_active_lease';
    action_id := v_row.id;
    lease_token := NULL;
    lease_expires_at := NULL;
    RETURN;
  END IF;

  outcome := 'claimed';
  action_id := v_row.id;
  lease_token := v_row.lease_token;
  lease_expires_at := v_row.lease_expires_at;
  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_mark_action_complete
-- Only a currently-owned processing action can be completed.
-- Parent-first fencing: lock event, verify event lease, lock action, verify action.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_mark_action_complete(
  p_action_id UUID,
  p_event_lease_token UUID,
  p_action_lease_token UUID,
  p_provider_message_id TEXT DEFAULT NULL,
  p_provider_status TEXT DEFAULT NULL,
  p_payload_hash TEXT DEFAULT NULL,
  OUT result BOOLEAN
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event_id UUID;
  v_event_lease UUID;
  v_event_status TEXT;
  v_event_lease_expires TIMESTAMPTZ;
  v_action_lease_expires TIMESTAMPTZ;
  v_now TIMESTAMPTZ;
BEGIN
  -- Read parent event reference from action
  SELECT event_id INTO v_event_id
  FROM public.webhook_action_ledger
  WHERE id = p_action_id;

  IF NOT FOUND OR v_event_id IS NULL THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 1. Lock parent event row FIRST
  SELECT lease_token, status, lease_expires_at
  INTO v_event_lease, v_event_status, v_event_lease_expires
  FROM public.webhook_event_ledger
  WHERE id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  IF v_event_status <> 'claimed' THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_event_lease IS DISTINCT FROM p_event_lease_token THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 2. Lock child action row SECOND
  SELECT lease_expires_at
  INTO v_action_lease_expires
  FROM public.webhook_action_ledger
  WHERE id = p_action_id AND event_id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 3. Refresh clock timestamp after acquiring row locks
  v_now := clock_timestamp();

  IF v_event_lease_expires IS NOT NULL AND v_event_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_action_lease_expires IS NOT NULL AND v_action_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;

  UPDATE public.webhook_action_ledger
  SET status = 'completed',
      lease_token = NULL,
      lease_expires_at = NULL,
      provider_message_id = p_provider_message_id,
      provider_status = p_provider_status,
      provider_payload_hash = p_payload_hash,
      completed_at = v_now,
      updated_at = v_now
  WHERE id = p_action_id
    AND lease_token = p_action_lease_token
    AND status = 'processing';

  result := FOUND;
  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_mark_action_retryable
-- Attempt count is NOT incremented here (only on lease acquisition).
-- Uses declared backoff parameters.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_mark_action_retryable(
  p_action_id UUID,
  p_event_lease_token UUID,
  p_action_lease_token UUID,
  p_error_category TEXT,
  p_error_code TEXT DEFAULT NULL,
  p_backoff_base_seconds INTEGER DEFAULT 60,
  p_backoff_cap_seconds INTEGER DEFAULT 3600,
  OUT result BOOLEAN
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event_id UUID;
  v_event_lease UUID;
  v_event_status TEXT;
  v_event_lease_expires TIMESTAMPTZ;
  v_attempt_count INTEGER;
  v_max_attempts INTEGER;
  v_next_retry TIMESTAMPTZ;
  v_action_lease_expires TIMESTAMPTZ;
  v_now TIMESTAMPTZ;
BEGIN
  -- Read parent event reference from action
  SELECT event_id INTO v_event_id
  FROM public.webhook_action_ledger
  WHERE id = p_action_id;

  IF NOT FOUND OR v_event_id IS NULL THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 1. Lock parent event row FIRST
  SELECT lease_token, status, lease_expires_at
  INTO v_event_lease, v_event_status, v_event_lease_expires
  FROM public.webhook_event_ledger
  WHERE id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  IF v_event_status <> 'claimed' THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_event_lease IS DISTINCT FROM p_event_lease_token THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 2. Lock child action row SECOND
  SELECT attempt_count, max_attempts, lease_expires_at
  INTO v_attempt_count, v_max_attempts, v_action_lease_expires
  FROM public.webhook_action_ledger
  WHERE id = p_action_id AND event_id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 3. Refresh clock timestamp after acquiring row locks
  v_now := clock_timestamp();

  IF v_event_lease_expires IS NOT NULL AND v_event_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_action_lease_expires IS NOT NULL AND v_action_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;

  IF p_backoff_base_seconds <= 0 OR p_backoff_cap_seconds <= 0 OR p_backoff_cap_seconds < p_backoff_base_seconds THEN
    result := FALSE;
    RETURN;
  END IF;

  IF v_attempt_count >= v_max_attempts THEN
    UPDATE public.webhook_action_ledger
    SET status = 'permanently_failed', lease_token = NULL, lease_expires_at = NULL,
        error_category = p_error_category, error_code = p_error_code,
        updated_at = v_now
    WHERE id = p_action_id AND lease_token = p_action_lease_token AND status = 'processing';
    result := FOUND;
    RETURN;
  END IF;

  v_next_retry := v_now +
    (LEAST(p_backoff_base_seconds * (2 ^ (v_attempt_count - 1)), p_backoff_cap_seconds) || ' seconds')::interval;

  UPDATE public.webhook_action_ledger
  SET status = 'retryable', lease_token = NULL, lease_expires_at = NULL,
      error_category = p_error_category, error_code = p_error_code,
      retry_at = v_next_retry, updated_at = v_now
  WHERE id = p_action_id AND lease_token = p_action_lease_token AND status = 'processing';

  result := FOUND;
  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_mark_action_unknown
-- External side-effect delivery uncertainty: mark unknown, never auto-resend.
-- No attempt-count increment.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_mark_action_unknown(
  p_action_id UUID,
  p_event_lease_token UUID,
  p_action_lease_token UUID,
  p_provider_status TEXT DEFAULT NULL,
  OUT result BOOLEAN
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event_id UUID;
  v_event_lease UUID;
  v_event_status TEXT;
  v_event_lease_expires TIMESTAMPTZ;
  v_action_lease_expires TIMESTAMPTZ;
  v_now TIMESTAMPTZ;
BEGIN
  -- Read parent event reference from action
  SELECT event_id INTO v_event_id
  FROM public.webhook_action_ledger
  WHERE id = p_action_id;

  IF NOT FOUND OR v_event_id IS NULL THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 1. Lock parent event row FIRST
  SELECT lease_token, status, lease_expires_at
  INTO v_event_lease, v_event_status, v_event_lease_expires
  FROM public.webhook_event_ledger
  WHERE id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  IF v_event_status <> 'claimed' THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_event_lease IS DISTINCT FROM p_event_lease_token THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 2. Lock child action row SECOND
  SELECT lease_expires_at
  INTO v_action_lease_expires
  FROM public.webhook_action_ledger
  WHERE id = p_action_id AND event_id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 3. Refresh clock timestamp after acquiring row locks
  v_now := clock_timestamp();

  IF v_event_lease_expires IS NOT NULL AND v_event_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_action_lease_expires IS NOT NULL AND v_action_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;

  UPDATE public.webhook_action_ledger
  SET status = 'unknown', lease_token = NULL, lease_expires_at = NULL,
      provider_status = p_provider_status, updated_at = v_now
  WHERE id = p_action_id
    AND lease_token = p_action_lease_token
    AND status = 'processing';

  result := FOUND;
  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_mark_action_permanently_failed
-- No attempt-count increment. Terminal state.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_mark_action_permanently_failed(
  p_action_id UUID,
  p_event_lease_token UUID,
  p_action_lease_token UUID,
  p_error_category TEXT,
  p_error_code TEXT DEFAULT NULL,
  OUT result BOOLEAN
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event_id UUID;
  v_event_lease UUID;
  v_event_status TEXT;
  v_event_lease_expires TIMESTAMPTZ;
  v_action_lease_expires TIMESTAMPTZ;
  v_now TIMESTAMPTZ;
BEGIN
  -- Read parent event reference from action
  SELECT event_id INTO v_event_id
  FROM public.webhook_action_ledger
  WHERE id = p_action_id;

  IF NOT FOUND OR v_event_id IS NULL THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 1. Lock parent event row FIRST
  SELECT lease_token, status, lease_expires_at
  INTO v_event_lease, v_event_status, v_event_lease_expires
  FROM public.webhook_event_ledger
  WHERE id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  IF v_event_status <> 'claimed' THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_event_lease IS DISTINCT FROM p_event_lease_token THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 2. Lock child action row SECOND
  SELECT lease_expires_at
  INTO v_action_lease_expires
  FROM public.webhook_action_ledger
  WHERE id = p_action_id AND event_id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 3. Refresh clock timestamp after acquiring row locks
  v_now := clock_timestamp();

  IF v_event_lease_expires IS NOT NULL AND v_event_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_action_lease_expires IS NOT NULL AND v_action_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;

  UPDATE public.webhook_action_ledger
  SET status = 'permanently_failed', lease_token = NULL, lease_expires_at = NULL,
      error_category = p_error_category, error_code = p_error_code,
      updated_at = v_now
  WHERE id = p_action_id
    AND lease_token = p_action_lease_token
    AND status = 'processing';

  result := FOUND;
  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_transition_event
-- Rejects target 'claimed'. Completion requires sealed plan + all actions complete.
-- Exponential backoff with declared parameters.
--
-- Locking/clock discipline (Corrections D & F):
-- Lock the event row, then refresh clock_timestamp() before any lease/expiry
-- validation. attempt_count is NOT incremented on transitions (only on genuine
-- lease acquisition in fn_webhook_claim_event).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_transition_event(
  p_event_id UUID,
  p_lease_token UUID,
  p_target_status TEXT,
  p_error_category TEXT DEFAULT NULL,
  p_error_code TEXT DEFAULT NULL,
  p_backoff_base_seconds INTEGER DEFAULT 60,
  p_backoff_cap_seconds INTEGER DEFAULT 3600,
  OUT result BOOLEAN
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event public.webhook_event_ledger%ROWTYPE;
  v_incomplete_actions INTEGER;
  v_unknown_or_permanent INTEGER;
  v_next_retry TIMESTAMPTZ;
  v_action_lease_expires TIMESTAMPTZ;
  v_now TIMESTAMPTZ;
BEGIN
  SELECT *
  INTO v_event
  FROM public.webhook_event_ledger
  WHERE id = p_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  -- Refresh clock after acquiring the row lock (D).
  v_now := clock_timestamp();

  IF v_event.lease_token IS DISTINCT FROM p_lease_token THEN
    result := FALSE;
    RETURN;
  END IF;

  IF v_event.lease_expires_at IS NOT NULL AND v_event.lease_expires_at <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;

  IF p_target_status = 'claimed' THEN
    result := FALSE;
    RETURN;
  END IF;

  IF p_target_status NOT IN ('completed','released','manual_review','dead_letter') THEN
    result := FALSE;
    RETURN;
  END IF;

  IF p_target_status = 'completed' THEN
    IF NOT v_event.action_plan_sealed THEN
      result := FALSE;
      RETURN;
    END IF;

    SELECT COUNT(*) INTO v_incomplete_actions
    FROM public.webhook_action_ledger
    WHERE event_id = p_event_id AND status NOT IN ('completed');

    IF v_incomplete_actions > 0 THEN
      result := FALSE;
      RETURN;
    END IF;
  END IF;

  IF p_target_status = 'released' THEN
    SELECT COUNT(*) INTO v_unknown_or_permanent
    FROM public.webhook_action_ledger
    WHERE event_id = p_event_id AND status IN ('unknown','permanently_failed');

    IF v_unknown_or_permanent > 0 THEN
      p_target_status := 'manual_review';
    END IF;
  END IF;

  IF p_backoff_base_seconds <= 0 OR p_backoff_cap_seconds <= 0 OR p_backoff_cap_seconds < p_backoff_base_seconds THEN
    result := FALSE;
    RETURN;
  END IF;

  IF p_target_status = 'released' AND p_backoff_base_seconds > 0 THEN
    v_next_retry := v_now +
      (LEAST(p_backoff_base_seconds * (2 ^ (v_event.attempt_count - 1)), p_backoff_cap_seconds) || ' seconds')::interval;
  ELSE
    v_next_retry := NULL;
  END IF;

  IF p_target_status = 'released' AND v_event.attempt_count >= v_event.max_attempts THEN
    p_target_status := 'dead_letter';
    v_next_retry := NULL;
  END IF;

  UPDATE public.webhook_event_ledger
  SET status = p_target_status,
      lease_token = NULL,
      lease_expires_at = NULL,
      error_category = p_error_category,
      error_code = p_error_code,
      retry_at = v_next_retry,
      completed_at = CASE WHEN p_target_status = 'completed' THEN v_now ELSE v_event.completed_at END,
      updated_at = v_now
  WHERE id = p_event_id AND lease_token = p_lease_token;

  result := FOUND;
    RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_transition_to_manual_review
-- Terminal-ish state for events with unknown/permanently_failed actions.
-- Excluded from automatic retries.
--
-- Locking/clock discipline (Correction D): lock the event row, then refresh
-- clock_timestamp() before validating the lease.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_transition_to_manual_review(
  p_event_id UUID,
  p_lease_token UUID,
  p_error_category TEXT DEFAULT 'unknown',
  p_error_code TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event public.webhook_event_ledger%ROWTYPE;
  v_now TIMESTAMPTZ;
BEGIN
  SELECT *
  INTO v_event
  FROM public.webhook_event_ledger
  WHERE id = p_event_id
  FOR UPDATE;

  IF NOT FOUND OR v_event.lease_token IS DISTINCT FROM p_lease_token THEN
    RETURN FALSE;
  END IF;

  -- Refresh clock after acquiring the row lock (D).
  v_now := clock_timestamp();

  IF v_event.lease_expires_at IS NOT NULL AND v_event.lease_expires_at <= v_now THEN
    RETURN FALSE;
  END IF;

  UPDATE public.webhook_event_ledger
  SET status = 'manual_review', lease_token = NULL, lease_expires_at = NULL,
      error_category = p_error_category, error_code = p_error_code,
      updated_at = v_now
  WHERE id = p_event_id AND lease_token = p_lease_token;

  RETURN FOUND;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_renew_event_lease
-- Extend event lease.
--
-- Locking/clock discipline (Correction D): lock the event row, refresh the
-- clock after acquiring the lock, validate the parent lease, then mutate.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_renew_event_lease(
  p_event_id UUID,
  p_lease_token UUID,
  p_lease_ttl_seconds INTEGER DEFAULT 300,
  OUT result BOOLEAN
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event_lease UUID;
  v_event_status TEXT;
  v_event_lease_expires TIMESTAMPTZ;
  v_now TIMESTAMPTZ;
BEGIN
  IF p_lease_ttl_seconds <= 0 OR p_lease_ttl_seconds > 86400 THEN
    result := FALSE;
    RETURN;
  END IF;

  -- Lock the event row FIRST.
  SELECT lease_token, status, lease_expires_at
  INTO v_event_lease, v_event_status, v_event_lease_expires
  FROM public.webhook_event_ledger
  WHERE id = p_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  IF v_event_status <> 'claimed' THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_event_lease IS DISTINCT FROM p_lease_token THEN
    result := FALSE;
    RETURN;
  END IF;

  -- Refresh clock after acquiring the row lock (D).
  v_now := clock_timestamp();

  IF v_event_lease_expires IS NOT NULL AND v_event_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;

  UPDATE public.webhook_event_ledger
  SET lease_expires_at = v_now + (p_lease_ttl_seconds || ' seconds')::interval,
      updated_at = v_now
  WHERE id = p_event_id
    AND lease_token = p_lease_token
    AND status = 'claimed'
    AND lease_expires_at > v_now;

  result := FOUND;
  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_renew_action_lease
-- Extend action lease.
-- Parent-first lock: event row first, then action row; clock refreshed after
-- both locks are held (Correction D).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_renew_action_lease(
  p_action_id UUID,
  p_event_lease_token UUID,
  p_action_lease_token UUID,
  p_lease_ttl_seconds INTEGER DEFAULT 300,
  OUT result BOOLEAN
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event_id UUID;
  v_event_lease UUID;
  v_event_status TEXT;
  v_event_lease_expires TIMESTAMPTZ;
  v_action_lease_expires TIMESTAMPTZ;
  v_now TIMESTAMPTZ := clock_timestamp();
BEGIN
  IF p_lease_ttl_seconds <= 0 OR p_lease_ttl_seconds > 86400 THEN
    result := FALSE;
    RETURN;
  END IF;

  -- Read parent event reference from action
  SELECT event_id INTO v_event_id
  FROM public.webhook_action_ledger
  WHERE id = p_action_id;

  IF NOT FOUND OR v_event_id IS NULL THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 1. Lock parent event row FIRST
  SELECT lease_token, status, lease_expires_at
  INTO v_event_lease, v_event_status, v_event_lease_expires
  FROM public.webhook_event_ledger
  WHERE id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  IF v_event_status <> 'claimed' THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_event_lease IS DISTINCT FROM p_event_lease_token THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 2. Lock child action row SECOND
  SELECT lease_expires_at
  INTO v_action_lease_expires
  FROM public.webhook_action_ledger
  WHERE id = p_action_id AND event_id = v_event_id
  FOR UPDATE;

  IF NOT FOUND THEN
    result := FALSE;
    RETURN;
  END IF;

  -- 3. Refresh clock timestamp after acquiring row locks
  v_now := clock_timestamp();

  IF v_event_lease_expires IS NOT NULL AND v_event_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;
  IF v_action_lease_expires IS NOT NULL AND v_action_lease_expires <= v_now THEN
    result := FALSE;
    RETURN;
  END IF;

  UPDATE public.webhook_action_ledger
  SET lease_expires_at = v_now + (p_lease_ttl_seconds || ' seconds')::interval,
      updated_at = v_now
  WHERE id = p_action_id
    AND lease_token = p_action_lease_token
    AND status = 'processing';

  result := FOUND;
  RETURN;
END;
$$;

-- ---------------------------------------------------------------------------
-- RPC: fn_webhook_recover_expired_leases
-- Bounded reaper. Expired events -> released (schedulable), NOT claimed.
-- Expired external side-effect actions -> unknown (never auto-resend).
-- Expired internal actions -> retryable (idempotent).
-- Parents with unknown external actions -> manual_review.
-- SKIP LOCKED for concurrency safety. Parent-first lock hierarchy.
--
-- Locking/clock discipline (Corrections D & E):
-- - Recovery work respects the configured batch size.
-- - Only expired records are recovered.
-- - Parent rows are locked before child rows; no child-only FOR UPDATE OF
--   SKIP LOCKED path violates the hierarchy.
-- - clock_timestamp() is refreshed after each lock acquisition.
-- - attempt_count is NOT incremented by recovery (F).
-- - Unknown side-effect actions block event reclaim and drive manual_review.
-- - Never automatically clear or retry ambiguous external sends.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_webhook_recover_expired_leases(
  p_batch_size INTEGER DEFAULT 100,
  OUT event_recoveries INTEGER,
  OUT action_recoveries INTEGER,
  OUT action_unknown_count INTEGER
)
LANGUAGE plpgsql
SET search_path = 'public, pg_temp'
AS $$
DECLARE
  v_event_recoveries INTEGER := 0;
  v_action_recoveries INTEGER := 0;
  v_action_unknown_count INTEGER := 0;
  v_now TIMESTAMPTZ := clock_timestamp();
  v_event_rec RECORD;
  v_action_rec RECORD;
  v_parent_id UUID;
  v_parent_status TEXT;
  v_have_unknown_child BOOLEAN;
  v_created_unknown BOOLEAN;
BEGIN
  IF p_batch_size <= 0 OR p_batch_size > 1000 THEN
    event_recoveries := 0;
    action_recoveries := 0;
    action_unknown_count := 0;
    RETURN;
  END IF;

  -- ------------------------------------------------------------------
  -- Phase A: Expired events (parents first). Lock each event row, then
  -- recover that event's own expired child actions under the parent lock.
  -- ------------------------------------------------------------------
  FOR v_event_rec IN
    SELECT id, attempt_count, max_attempts, lease_expires_at
    FROM public.webhook_event_ledger
    WHERE status = 'claimed'
      AND lease_expires_at IS NOT NULL
      AND lease_expires_at <= v_now
    ORDER BY lease_expires_at ASC
    LIMIT p_batch_size
    FOR UPDATE SKIP LOCKED
  LOOP
    -- Refresh clock after acquiring the event row lock (D).
    v_now := clock_timestamp();

    -- Re-verify the row is still an expired, claimed event under the lock.
    IF v_event_rec.lease_expires_at IS NULL OR v_event_rec.lease_expires_at > v_now THEN
      CONTINUE;
    END IF;

    -- E #8: an expired event with an unknown external side-effect child must
    -- enter manual_review, including when first encountered by recovery.
    SELECT EXISTS (
      SELECT 1
      FROM public.webhook_action_ledger
      WHERE event_id = v_event_rec.id
        AND side_effect = TRUE
        AND status = 'unknown'
    ) INTO v_have_unknown_child;

    IF v_have_unknown_child THEN
      UPDATE public.webhook_event_ledger
      SET status = 'manual_review',
          lease_token = NULL,
          lease_expires_at = NULL,
          error_category = 'unknown',
          updated_at = v_now
      WHERE id = v_event_rec.id;
      v_event_recoveries := v_event_recoveries + 1;
      CONTINUE;
    END IF;

    -- Recover this event's expired processing actions. Parent is already
    -- locked (parent-first hierarchy); lock each child under it.
    v_created_unknown := FALSE;
    FOR v_action_rec IN
      SELECT id, side_effect, attempt_count, max_attempts
      FROM public.webhook_action_ledger
      WHERE event_id = v_event_rec.id
        AND status = 'processing'
        AND lease_expires_at IS NOT NULL
        AND lease_expires_at <= v_now
      ORDER BY lease_expires_at ASC
      FOR UPDATE SKIP LOCKED
    LOOP
      v_now := clock_timestamp();
      IF v_action_rec.side_effect THEN
        -- E #4: ambiguous external side-effect -> unknown, never auto-resend.
        UPDATE public.webhook_action_ledger
        SET status = 'unknown',
            lease_token = NULL,
            lease_expires_at = NULL,
            updated_at = v_now
        WHERE id = v_action_rec.id;
        v_action_unknown_count := v_action_unknown_count + 1;
        v_created_unknown := TRUE;
      ELSE
        -- E #3: only known-safe non-side-effect actions may be made retryable.
        -- F: recovery alone does NOT increment attempt_count.
        UPDATE public.webhook_action_ledger
        SET status = 'retryable',
            lease_token = NULL,
            lease_expires_at = NULL,
            retry_at = v_now +
              (LEAST(60 * (2 ^ (GREATEST(1, v_action_rec.attempt_count - 1))), 3600) || ' seconds')::interval,
            updated_at = v_now
        WHERE id = v_action_rec.id;
        v_action_recoveries := v_action_recoveries + 1;
      END IF;
    END LOOP;

    -- E #8 / E #10: if recovery created an unknown side-effect action, the
    -- event enters manual_review; never automatically retry ambiguous sends.
    IF v_created_unknown THEN
      UPDATE public.webhook_event_ledger
      SET status = 'manual_review',
          lease_token = NULL,
          lease_expires_at = NULL,
          error_category = 'unknown',
          updated_at = v_now
      WHERE id = v_event_rec.id;
    ELSIF v_event_rec.attempt_count >= v_event_rec.max_attempts THEN
      UPDATE public.webhook_event_ledger
      SET status = 'dead_letter',
          lease_token = NULL,
          lease_expires_at = NULL,
          updated_at = v_now
      WHERE id = v_event_rec.id;
    ELSE
      -- Release the event (schedulable) WITHOUT incrementing attempt_count (F).
      UPDATE public.webhook_event_ledger
      SET status = 'released',
          lease_token = NULL,
          lease_expires_at = NULL,
          retry_at = v_now +
            (LEAST(60 * (2 ^ (GREATEST(1, v_event_rec.attempt_count - 1))), 3600) || ' seconds')::interval,
          updated_at = v_now
      WHERE id = v_event_rec.id;
    END IF;
    v_event_recoveries := v_event_recoveries + 1;
  END LOOP;

  -- ------------------------------------------------------------------
  -- Phase B: Expired processing actions whose parent event was not handled
  -- in Phase A (e.g. parent already released/manual_review/dead_letter, or a
  -- claimed-but-not-expired parent). Parent-first: lock parent first, then
  -- child. SKIP LOCKED so the reaper never blocks on a held lock (E #6).
  -- ------------------------------------------------------------------
  FOR v_action_rec IN
    SELECT al.id, al.event_id, al.side_effect, al.attempt_count, al.max_attempts
    FROM public.webhook_action_ledger al
    WHERE al.status = 'processing'
      AND al.lease_expires_at IS NOT NULL
      AND al.lease_expires_at <= v_now
    ORDER BY al.lease_expires_at ASC
    LIMIT p_batch_size
  LOOP
    -- Lock parent event row FIRST (E #5). SKIP LOCKED: skip events held by
    -- an active worker rather than waiting.
    SELECT id, status
    INTO v_parent_id, v_parent_status
    FROM public.webhook_event_ledger
    WHERE id = v_action_rec.event_id
    FOR UPDATE SKIP LOCKED;

    IF NOT FOUND THEN
      CONTINUE;
    END IF;

    -- Re-read the child under the parent lock; only act if it is still an
    -- expired processing action (it may have been resolved by Phase A).
    SELECT id, side_effect, attempt_count, max_attempts
    INTO v_action_rec.id, v_action_rec.side_effect, v_action_rec.attempt_count, v_action_rec.max_attempts
    FROM public.webhook_action_ledger
    WHERE id = v_action_rec.id
      AND status = 'processing'
      AND lease_expires_at IS NOT NULL
      AND lease_expires_at <= v_now
    FOR UPDATE SKIP LOCKED;

    IF NOT FOUND THEN
      CONTINUE;
    END IF;

    v_now := clock_timestamp();

    IF v_action_rec.side_effect THEN
      UPDATE public.webhook_action_ledger
      SET status = 'unknown',
          lease_token = NULL,
          lease_expires_at = NULL,
          updated_at = v_now
      WHERE id = v_action_rec.id;
      v_action_unknown_count := v_action_unknown_count + 1;
    ELSE
      UPDATE public.webhook_action_ledger
      SET status = 'retryable',
          lease_token = NULL,
          lease_expires_at = NULL,
          retry_at = v_now +
            (LEAST(60 * (2 ^ (GREATEST(1, v_action_rec.attempt_count - 1))), 3600) || ' seconds')::interval,
          updated_at = v_now
      WHERE id = v_action_rec.id;
      v_action_recoveries := v_action_recoveries + 1;
    END IF;
  END LOOP;

  -- ------------------------------------------------------------------
  -- Final: any claimed event that now has an unknown external side-effect
  -- child enters manual_review. Unknown side-effect actions block reclaim.
  -- Repeated execution preserves unknown/manual_review states (E #7, E #9).
  -- ------------------------------------------------------------------
  UPDATE public.webhook_event_ledger el
  SET status = 'manual_review',
      lease_token = NULL,
      lease_expires_at = NULL,
      error_category = 'unknown',
      updated_at = v_now
  FROM public.webhook_action_ledger al
  WHERE al.event_id = el.id
    AND el.status = 'claimed'
    AND al.status = 'unknown'
    AND al.side_effect = TRUE;

  event_recoveries := v_event_recoveries;
  action_recoveries := v_action_recoveries;
  action_unknown_count := v_action_unknown_count;
  RETURN;
END;
$$;
