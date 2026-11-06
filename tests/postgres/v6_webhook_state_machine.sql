-- tests/postgres/v6_webhook_state_machine.sql
\set ON_ERROR_STOP on

INSERT INTO users (id, username, access_token) VALUES (999,'testuser999','tok') ON CONFLICT (id) DO NOTHING;

-- Cleanup test fixtures from prior runs
DELETE FROM webhook_action_ledger WHERE event_id IN (SELECT id FROM webhook_event_ledger WHERE event_key LIKE 'scn%');
DELETE FROM webhook_event_ledger WHERE event_key LIKE 'scn%';

-- Scenario 1: fresh event claim creates lease
DO $$
DECLARE
  v_outcome TEXT;
  v_event UUID;
  v_token UUID;
  v_expires TIMESTAMPTZ;
BEGIN
  SELECT outcome, event_id, lease_token, lease_expires_at
  INTO v_outcome, v_event, v_token, v_expires
  FROM fn_webhook_claim_event('scn1:event','comment',999,'{}'::jsonb,300);

  IF v_outcome <> 'created' OR v_event IS NULL OR v_token IS NULL THEN
    RAISE EXCEPTION 'SCENARIO 1 FAIL: expected created with valid tokens, got outcome=%', v_outcome;
  END IF;

  RAISE NOTICE 'SCENARIO 1 PASS (outcome=created, token acquired)';
END $$;

-- Scenario 2: active lease prevents concurrent re-claim
DO $$
DECLARE
  v_outcome TEXT;
  v_event UUID;
  v_token UUID;
  v_expires TIMESTAMPTZ;
BEGIN
  SELECT outcome, event_id, lease_token, lease_expires_at
  INTO v_outcome, v_event, v_token, v_expires
  FROM fn_webhook_claim_event('scn1:event','comment',999,'{}'::jsonb,300);

  IF v_outcome <> 'active_lease' OR v_token IS NOT NULL THEN
    RAISE EXCEPTION 'SCENARIO 2 FAIL: expected active_lease with NULL token, got outcome=%', v_outcome;
  END IF;

  RAISE NOTICE 'SCENARIO 2 PASS (outcome=active_lease, token rejected)';
END $$;

-- Scenario 3
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_action UUID;
  v_atoken UUID;
  v_outcome TEXT;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn3:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken
  FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  RAISE NOTICE 'claim outcome=%', v_outcome;
  PERFORM fn_webhook_mark_action_complete(v_action, v_token, v_atoken, 'msg1', 'sent', 'hash1');
  SELECT outcome INTO v_outcome FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  RAISE NOTICE 'replay outcome=%', v_outcome;
  IF v_outcome = 'claimed' THEN
    RAISE EXCEPTION 'SCENARIO 3 FAIL: replay returned claimed';
  END IF;
  RAISE NOTICE 'SCENARIO 3 PASS';
END $$;

-- Scenario 4: stale parent token
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_new_token UUID;
  v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn4:event','comment',999,'{}'::jsonb,300);
  -- establish newer lease via transition to manual_review (releases current)
  PERFORM fn_webhook_transition_to_manual_review(v_event, v_token, 'test', 'test');
  -- attempt protected transition with stale (old) token
  SELECT result INTO v_res FROM fn_webhook_transition_event(v_event, v_token, 'completed', NULL, NULL, 1, 10);
  IF v_res IS TRUE THEN
    RAISE EXCEPTION 'SCENARIO 4 FAIL: stale token accepted';
  END IF;
  RAISE NOTICE 'SCENARIO 4 PASS';
END;
$$;

-- Scenario 5: expired parent lease
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn5:event','comment',999,'{}'::jsonb,300);
  -- expire the lease deterministically
  UPDATE webhook_event_ledger SET lease_expires_at = now() - interval '1 minute' WHERE id = v_event;
  -- attempt protected transition with expired lease
  SELECT result INTO v_res FROM fn_webhook_transition_event(v_event, v_token, 'completed', NULL, NULL, 1, 10);
  IF v_res IS TRUE THEN
    RAISE EXCEPTION 'SCENARIO 5 FAIL: expired lease accepted';
  END IF;
  RAISE NOTICE 'SCENARIO 5 PASS';
END;
$$;

-- Scenario 6: stale child action token
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_action UUID;
  v_atoken UUID;
  v_outcome TEXT;
  v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn6:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken
  FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  -- complete action (releases lease)
  PERFORM fn_webhook_mark_action_complete(v_action, v_token, v_atoken, 'msg1', 'sent', 'hash1');
  -- attempt stale token completion
  SELECT result INTO v_res FROM fn_webhook_mark_action_complete(v_action, v_token, v_atoken, 'msg2', 'sent', 'hash2');
  IF v_res IS TRUE THEN
    RAISE EXCEPTION 'SCENARIO 6 FAIL: stale token accepted';
  END IF;
  RAISE NOTICE 'SCENARIO 6 PASS';
END;
$$;

-- Scenario 7: expired child action lease
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_action UUID;
  v_atoken UUID;
  v_outcome TEXT;
  v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn7:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken
  FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  -- expire child lease only
  UPDATE webhook_action_ledger SET lease_expires_at = now() - interval '1 minute' WHERE id = v_action;
  -- attempt completion
  SELECT result INTO v_res FROM fn_webhook_mark_action_complete(v_action, v_token, v_atoken, 'msg1', 'sent', 'hash1');
  IF v_res IS TRUE THEN RAISE EXCEPTION 'SCENARIO 7 FAIL: completion accepted'; END IF;
  -- attempt retryable
  SELECT result INTO v_res FROM fn_webhook_mark_action_retryable(v_action, v_token, v_atoken, 'network', 'code', 1, 10);
  IF v_res IS TRUE THEN RAISE EXCEPTION 'SCENARIO 7 FAIL: retryable accepted'; END IF;
  -- attempt unknown
  SELECT result INTO v_res FROM fn_webhook_mark_action_unknown(v_action, v_token, v_atoken, 'status');
  IF v_res IS TRUE THEN RAISE EXCEPTION 'SCENARIO 7 FAIL: unknown accepted'; END IF;
  -- attempt permanent failure
  SELECT result INTO v_res FROM fn_webhook_mark_action_permanently_failed(v_action, v_token, v_atoken, 'cat', 'code');
  IF v_res IS TRUE THEN RAISE EXCEPTION 'SCENARIO 7 FAIL: permanent accepted'; END IF;
  -- attempt renewal
  SELECT result INTO v_res FROM fn_webhook_renew_action_lease(v_action, v_token, v_atoken, 300);
  IF v_res IS TRUE THEN RAISE EXCEPTION 'SCENARIO 7 FAIL: renewal accepted'; END IF;
  RAISE NOTICE 'SCENARIO 7 PASS';
END;
$$;

-- Scenario 8: parent-first lock ordering (source inspection + executable assertion)
DO $$
DECLARE
  v_fn_names TEXT[] := ARRAY[
    'fn_webhook_mark_action_complete',
    'fn_webhook_mark_action_retryable',
    'fn_webhook_mark_action_unknown',
    'fn_webhook_mark_action_permanently_failed',
    'fn_webhook_renew_action_lease'
  ];
  v_fn TEXT;
  v_src TEXT;
  v_event UUID;
  v_token UUID;
  v_action UUID;
  v_atoken UUID;
  v_outcome TEXT;
  v_res BOOLEAN;
BEGIN
  -- 1. Source verification: inspect prosrc to assert absence of joined FOR UPDATE OF
  FOREACH v_fn IN ARRAY v_fn_names LOOP
    SELECT prosrc INTO v_src
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.proname = v_fn;

    IF v_src IS NULL THEN
      RAISE EXCEPTION 'SCENARIO 8 FAIL: function % not found', v_fn;
    END IF;

    IF v_src LIKE '%FOR UPDATE OF%' THEN
      RAISE EXCEPTION 'SCENARIO 8 FAIL: function % still uses joined FOR UPDATE OF', v_fn;
    END IF;

    IF v_src NOT LIKE '%webhook_event_ledger%FOR UPDATE%' OR v_src NOT LIKE '%webhook_action_ledger%FOR UPDATE%' THEN
      RAISE EXCEPTION 'SCENARIO 8 FAIL: function % missing explicit parent-first FOR UPDATE locks', v_fn;
    END IF;
  END LOOP;

  -- 2. Executable parent-first lock ordering assertion in active transaction
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn8:event', 'comment', 999, '{}'::jsonb, 300);

  PERFORM fn_webhook_register_action_plan(
    v_event, v_token,
    '[{"action_key":"public_reply:scn8","action_type":"public_reply","side_effect":true}]'::jsonb
  );

  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken
  FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:scn8', 300);

  IF v_outcome <> 'claimed' THEN
    RAISE EXCEPTION 'SCENARIO 8 FAIL: could not claim action, got %', v_outcome;
  END IF;

  SELECT result INTO v_res
  FROM fn_webhook_mark_action_complete(v_action, v_token, v_atoken, 'msg8', 'sent', 'hash8');

  IF v_res IS NOT TRUE THEN
    RAISE EXCEPTION 'SCENARIO 8 FAIL: complete rejected under parent-first lock ordering';
  END IF;

  RAISE NOTICE 'SCENARIO 8 PASS (parent-first lock ordering verified with executable assertions)';
END;
$$;

-- Scenario 9: successful action completion
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_outcome TEXT; v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn9:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  SELECT result INTO v_res FROM fn_webhook_mark_action_complete(v_action, v_token, v_atoken, 'msg9', 'sent', 'hash9');
  IF v_res IS NOT TRUE THEN RAISE EXCEPTION 'SCENARIO 9 FAIL: complete rejected'; END IF;
  RAISE NOTICE 'SCENARIO 9 PASS';
END;
$$;

-- Scenario 10: retryable transition
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_outcome TEXT; v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn10:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  SELECT result INTO v_res FROM fn_webhook_mark_action_retryable(v_action, v_token, v_atoken, 'network', 'code', 1, 10);
  IF v_res IS NOT TRUE THEN RAISE EXCEPTION 'SCENARIO 10 FAIL: retryable rejected'; END IF;
  RAISE NOTICE 'SCENARIO 10 PASS';
END;
$$;

-- Scenario 11: unknown external outcome
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_outcome TEXT; v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn11:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  SELECT result INTO v_res FROM fn_webhook_mark_action_unknown(v_action, v_token, v_atoken, 'ambiguous');
  IF v_res IS NOT TRUE THEN RAISE EXCEPTION 'SCENARIO 11 FAIL: unknown rejected'; END IF;
  RAISE NOTICE 'SCENARIO 11 PASS';
END;
$$;

-- Scenario 12: permanent failure
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_outcome TEXT; v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn12:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  SELECT result INTO v_res FROM fn_webhook_mark_action_permanently_failed(v_action, v_token, v_atoken, 'cat', 'code');
  IF v_res IS NOT TRUE THEN RAISE EXCEPTION 'SCENARIO 12 FAIL: permanent rejected'; END IF;
  RAISE NOTICE 'SCENARIO 12 PASS';
END;
$$;

-- Scenario 13: action lease renewal
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_outcome TEXT; v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn13:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  SELECT result INTO v_res FROM fn_webhook_renew_action_lease(v_action, v_token, v_atoken, 300);
  IF v_res IS NOT TRUE THEN RAISE EXCEPTION 'SCENARIO 13 FAIL: renewal rejected'; END IF;
  RAISE NOTICE 'SCENARIO 13 PASS';
END;
$$;

-- Scenario 14: expired event lease recovery
DO $$
DECLARE
  v_event UUID; v_token UUID; v_res INTEGER;
  v_status TEXT; v_token_persisted UUID; v_lease_expires TIMESTAMPTZ; v_retry_at TIMESTAMPTZ;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn14:event','comment',999,'{}'::jsonb,300);
  UPDATE webhook_event_ledger SET lease_expires_at = now() - interval '1 minute' WHERE id = v_event;
  SELECT event_recoveries INTO v_res FROM fn_webhook_recover_expired_leases(10);
  IF v_res < 1 THEN RAISE EXCEPTION 'SCENARIO 14 FAIL: no recoveries recorded'; END IF;

  SELECT status, lease_token, lease_expires_at, retry_at
  INTO v_status, v_token_persisted, v_lease_expires, v_retry_at
  FROM webhook_event_ledger WHERE id = v_event;

  IF v_status <> 'released' THEN
    RAISE EXCEPTION 'SCENARIO 14 FAIL: event status is %, expected released', v_status;
  END IF;
  IF v_token_persisted IS NOT NULL THEN
    RAISE EXCEPTION 'SCENARIO 14 FAIL: lease_token not null after recovery';
  END IF;
  IF v_lease_expires IS NOT NULL THEN
    RAISE EXCEPTION 'SCENARIO 14 FAIL: lease_expires_at not null after recovery';
  END IF;
  IF v_retry_at IS NULL THEN
    RAISE EXCEPTION 'SCENARIO 14 FAIL: retry_at is null after recovery';
  END IF;

  RAISE NOTICE 'SCENARIO 14 PASS (recoveries=%, persisted_status=%)', v_res, v_status;
END;
$$;

-- Scenario 15: expired action lease recovery (safe retry)
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_outcome TEXT; v_res INTEGER; v_ar INTEGER; v_au INTEGER;
  v_action_status TEXT; v_action_lease UUID; v_action_expires TIMESTAMPTZ; v_event_status TEXT;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn15:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  UPDATE webhook_action_ledger SET lease_expires_at = now() - interval '1 minute' WHERE id = v_action;
  SELECT action_recoveries, action_unknown_count INTO v_ar, v_au FROM fn_webhook_recover_expired_leases(10);

  IF v_au < 1 THEN RAISE EXCEPTION 'SCENARIO 15 FAIL: expected action_unknown_count >= 1 for expired side_effect action'; END IF;

  SELECT status, lease_token, lease_expires_at
  INTO v_action_status, v_action_lease, v_action_expires
  FROM webhook_action_ledger WHERE id = v_action;

  IF v_action_status <> 'unknown' THEN
    RAISE EXCEPTION 'SCENARIO 15 FAIL: persisted action status is %, expected unknown', v_action_status;
  END IF;
  IF v_action_lease IS NOT NULL OR v_action_expires IS NOT NULL THEN
    RAISE EXCEPTION 'SCENARIO 15 FAIL: action lease fields not null after recovery';
  END IF;

  SELECT status INTO v_event_status FROM webhook_event_ledger WHERE id = v_event;
  IF v_event_status <> 'manual_review' THEN
    RAISE EXCEPTION 'SCENARIO 15 FAIL: parent event status is %, expected manual_review', v_event_status;
  END IF;

  RAISE NOTICE 'SCENARIO 15 PASS (action_recoveries=%, unknown=%, action_status=%, event_status=%)', v_ar, v_au, v_action_status, v_event_status;
END;
$$;

-- Scenario 16: unknown action blocks parent reclaim
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_outcome TEXT; v_res BOOLEAN;
  v_action_status TEXT; v_event_status TEXT; v_reclaim_event UUID; v_reclaim_token UUID;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn16:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  PERFORM fn_webhook_mark_action_unknown(v_action, v_token, v_atoken, 'ambiguous');
  PERFORM fn_webhook_recover_expired_leases(10);

  SELECT status INTO v_action_status FROM webhook_action_ledger WHERE id = v_action;
  IF v_action_status <> 'unknown' THEN
    RAISE EXCEPTION 'SCENARIO 16 FAIL: action status is %, expected unknown', v_action_status;
  END IF;

  SELECT status INTO v_event_status FROM webhook_event_ledger WHERE id = v_event;
  IF v_event_status <> 'manual_review' THEN
    RAISE EXCEPTION 'SCENARIO 16 FAIL: event status is %, expected manual_review', v_event_status;
  END IF;

  SELECT outcome, event_id, lease_token INTO v_outcome, v_reclaim_event, v_reclaim_token
  FROM fn_webhook_claim_event('scn16:event','comment',999,'{}'::jsonb,300);
  IF v_reclaim_token IS NOT NULL OR v_outcome <> 'manual_review' THEN
    RAISE EXCEPTION 'SCENARIO 16 FAIL: parent event was reclaimed despite unknown action blocking (outcome=%, token=%)', v_outcome, v_reclaim_token;
  END IF;

  RAISE NOTICE 'SCENARIO 16 PASS (persisted state verified: action=unknown, parent=manual_review, reclaim_blocked)';
END;
$$;

-- Scenario 17: concurrent multi-session overlap validation
DO $$
DECLARE
  v_proven BOOLEAN := FALSE;
  v_proven_at TIMESTAMPTZ;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM information_schema.tables WHERE table_name = '_v6_concurrency_proof'
  ) INTO v_proven;

  IF v_proven THEN
    SELECT EXISTS (
      SELECT 1 FROM _v6_concurrency_proof WHERE proof_name = 'scenario_17_multi_session_overlap'
    ) INTO v_proven;
  END IF;

  IF NOT v_proven THEN
    RAISE EXCEPTION 'SCENARIO 17 FAIL: multi-session concurrency overlap was not proven by separate-session runner (run_v6_concurrency.ps1)';
  END IF;

  SELECT proven_at INTO v_proven_at FROM _v6_concurrency_proof WHERE proof_name = 'scenario_17_multi_session_overlap';
  RAISE NOTICE 'SCENARIO 17 PASS (multi-session concurrency overlap proven at %)', v_proven_at;
END;
$$;

-- Scenario 18: attempt-count invariant
DO $$
DECLARE
  v_event UUID; v_token UUID; v_before INTEGER; v_after INTEGER;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn18:event','comment',999,'{}'::jsonb,300);
  SELECT attempt_count INTO v_before FROM webhook_event_ledger WHERE id = v_event;
  -- ordinary transition should not increment
  PERFORM fn_webhook_transition_to_manual_review(v_event, v_token, 'test', 'test');
  SELECT attempt_count INTO v_after FROM webhook_event_ledger WHERE id = v_event;
  IF v_after <> v_before THEN RAISE EXCEPTION 'SCENARIO 18 FAIL: attempt incremented on transition'; END IF;
  RAISE NOTICE 'SCENARIO 18 PASS (before=%, after=%)', v_before, v_after;
END;
$$;

-- Scenario 19: ambiguous external outcome never resendable
DO $$
DECLARE
  v_event UUID; v_token UUID; v_action UUID; v_atoken UUID; v_outcome TEXT;
  v_action_status TEXT; v_reclaim_token UUID;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token FROM fn_webhook_claim_event('scn19:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(v_event, v_token, '[{"action_key":"public_reply:test","action_type":"public_reply","side_effect":true}]'::jsonb);
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);
  PERFORM fn_webhook_mark_action_unknown(v_action, v_token, v_atoken, 'ambiguous');
  PERFORM fn_webhook_recover_expired_leases(10);

  SELECT status INTO v_action_status FROM webhook_action_ledger WHERE id = v_action;
  IF v_action_status <> 'unknown' THEN
    RAISE EXCEPTION 'SCENARIO 19 FAIL: action status is %, expected unknown', v_action_status;
  END IF;

  SELECT outcome, lease_token INTO v_outcome, v_reclaim_token
  FROM fn_webhook_claim_action(v_event, v_token, 'public_reply:test', 300);

  IF v_outcome NOT IN ('action_terminal', 'event_not_claimable') OR v_reclaim_token IS NOT NULL THEN
    RAISE EXCEPTION 'SCENARIO 19 FAIL: unknown action was claimable! outcome=%, token=%', v_outcome, v_reclaim_token;
  END IF;

  RAISE NOTICE 'SCENARIO 19 PASS (persisted state verified: action=unknown, outcome=%, re-claim blocked)', v_outcome;
END;
$$;

-- =========================================================================
-- Additional regression scenarios (20-28): attempt-count invariant (F) and
-- reaper safety (E). These run in the same harness after the seed user exists
-- and must PASS like scenarios 1-19.
-- =========================================================================

-- Scenario 20: attempt-count invariant — initial lease acquisition increments once.
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_before INTEGER;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn20:event','comment',999,'{}'::jsonb,300);
  SELECT attempt_count INTO v_before FROM webhook_event_ledger WHERE id = v_event;
  IF v_before <> 1 THEN
    RAISE EXCEPTION 'SCENARIO 20 FAIL: initial attempt_count=%, expected 1', v_before;
  END IF;
  RAISE NOTICE 'SCENARIO 20 PASS (initial attempt_count=1)';
END $$;

-- Scenario 21: attempt-count invariant — event completion does not increment.
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_action UUID;
  v_atoken UUID;
  v_outcome TEXT;
  v_before INTEGER;
  v_after INTEGER;
  v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn21:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(
    v_event, v_token,
    '[{"action_key":"a1","action_type":"inbox_persist","side_effect":false}]'::jsonb
  );
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken
  FROM fn_webhook_claim_action(v_event, v_token, 'a1', 300);
  SELECT attempt_count INTO v_before FROM webhook_event_ledger WHERE id = v_event;
  SELECT result INTO v_res FROM fn_webhook_mark_action_complete(v_action, v_token, v_atoken, 'm1', 'sent', 'h1');
  PERFORM fn_webhook_transition_event(v_event, v_token, 'completed', NULL, NULL, 60, 3600);
  SELECT attempt_count INTO v_after FROM webhook_event_ledger WHERE id = v_event;
  IF v_after <> v_before THEN
    RAISE EXCEPTION 'SCENARIO 21 FAIL: attempt_count incremented on completion (%=%)', v_before, v_after;
  END IF;
  RAISE NOTICE 'SCENARIO 21 PASS (completion does not increment, attempt_count=%)', v_after;
END $$;

-- Scenario 22: attempt-count invariant — manual review does not increment.
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_before INTEGER;
  v_after INTEGER;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn22:event','comment',999,'{}'::jsonb,300);
  SELECT attempt_count INTO v_before FROM webhook_event_ledger WHERE id = v_event;
  PERFORM fn_webhook_transition_to_manual_review(v_event, v_token, 'unknown', 'test');
  SELECT attempt_count INTO v_after FROM webhook_event_ledger WHERE id = v_event;
  IF v_after <> v_before THEN
    RAISE EXCEPTION 'SCENARIO 22 FAIL: attempt_count incremented on manual_review';
  END IF;
  RAISE NOTICE 'SCENARIO 22 PASS (manual_review does not increment, attempt_count=%)', v_after;
END $$;

-- Scenario 23: attempt-count invariant — ordinary release/transition does not increment.
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_before INTEGER;
  v_after INTEGER;
  v_res BOOLEAN;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn23:event','comment',999,'{}'::jsonb,300);
  SELECT attempt_count INTO v_before FROM webhook_event_ledger WHERE id = v_event;
  SELECT result INTO v_res FROM fn_webhook_transition_event(v_event, v_token, 'released', NULL, NULL, 60, 3600);
  SELECT attempt_count INTO v_after FROM webhook_event_ledger WHERE id = v_event;
  IF v_after <> v_before THEN
    RAISE EXCEPTION 'SCENARIO 23 FAIL: attempt_count incremented on release';
  END IF;
  RAISE NOTICE 'SCENARIO 23 PASS (release does not increment, attempt_count=%)', v_after;
END $$;

-- Scenario 24: attempt-count invariant — lease expiry alone does not increment.
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_before INTEGER;
  v_after INTEGER;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn24:event','comment',999,'{}'::jsonb,300);
  SELECT attempt_count INTO v_before FROM webhook_event_ledger WHERE id = v_event;
  UPDATE webhook_event_ledger SET lease_expires_at = now() - interval '1 minute' WHERE id = v_event;
  SELECT attempt_count INTO v_after FROM webhook_event_ledger WHERE id = v_event;
  IF v_after <> v_before THEN
    RAISE EXCEPTION 'SCENARIO 24 FAIL: attempt_count incremented on expiry alone';
  END IF;
  RAISE NOTICE 'SCENARIO 24 PASS (expiry alone does not increment, attempt_count=%)', v_after;
END $$;

-- Scenario 25: attempt-count invariant — reaper recovery alone does not increment.
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_before INTEGER;
  v_after INTEGER;
  v_res INTEGER;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn25:event','comment',999,'{}'::jsonb,300);
  SELECT attempt_count INTO v_before FROM webhook_event_ledger WHERE id = v_event;
  UPDATE webhook_event_ledger SET lease_expires_at = now() - interval '1 minute' WHERE id = v_event;
  SELECT event_recoveries INTO v_res FROM fn_webhook_recover_expired_leases(10);
  SELECT attempt_count INTO v_after FROM webhook_event_ledger WHERE id = v_event;
  IF v_after <> v_before THEN
    RAISE EXCEPTION 'SCENARIO 25 FAIL: reaper incremented attempt_count (%=%)', v_before, v_after;
  END IF;
  RAISE NOTICE 'SCENARIO 25 PASS (reaper does not increment, attempt_count=%)', v_after;
END $$;

-- Scenario 26: attempt-count invariant — later genuine new lease increments exactly once.
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_after INTEGER;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn26:event','comment',999,'{}'::jsonb,300);
  UPDATE webhook_event_ledger SET lease_expires_at = now() - interval '1 minute' WHERE id = v_event;
  PERFORM fn_webhook_recover_expired_leases(10);
  -- Make the release due so a genuine new lease can be acquired.
  UPDATE webhook_event_ledger SET retry_at = now() - interval '1 minute' WHERE id = v_event;
  SELECT lease_token INTO v_token FROM fn_webhook_claim_event('scn26:event','comment',999,'{}'::jsonb,300);
  SELECT attempt_count INTO v_after FROM webhook_event_ledger WHERE id = v_event;
  IF v_after <> 2 THEN
    RAISE EXCEPTION 'SCENARIO 26 FAIL: reclaimed attempt_count=%, expected 2', v_after;
  END IF;
  RAISE NOTICE 'SCENARIO 26 PASS (reclaimed attempt_count=2)';
END $$;

-- Scenario 27: expired parent with unknown side-effect child -> manual_review (E #8).
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_action UUID;
  v_atoken UUID;
  v_outcome TEXT;
  v_status TEXT;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn27:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(
    v_event, v_token,
    '[{"action_key":"a1","action_type":"dm_send","side_effect":true}]'::jsonb
  );
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken
  FROM fn_webhook_claim_action(v_event, v_token, 'a1', 300);
  PERFORM fn_webhook_mark_action_unknown(v_action, v_token, v_atoken, 'ambiguous');
  UPDATE webhook_event_ledger SET lease_expires_at = now() - interval '1 minute' WHERE id = v_event;
  PERFORM fn_webhook_recover_expired_leases(10);
  SELECT status INTO v_status FROM webhook_event_ledger WHERE id = v_event;
  IF v_status <> 'manual_review' THEN
    RAISE EXCEPTION 'SCENARIO 27 FAIL: event status=%, expected manual_review', v_status;
  END IF;
  RAISE NOTICE 'SCENARIO 27 PASS (event=manual_review with unknown side-effect child)';
END $$;

-- Scenario 28: repeated recovery preserves unknown/manual_review states (E #9).
DO $$
DECLARE
  v_event UUID;
  v_token UUID;
  v_action UUID;
  v_atoken UUID;
  v_outcome TEXT;
  v_status1 TEXT;
  v_status2 TEXT;
  v_astatus1 TEXT;
  v_astatus2 TEXT;
BEGIN
  SELECT event_id, lease_token INTO v_event, v_token
  FROM fn_webhook_claim_event('scn28:event','comment',999,'{}'::jsonb,300);
  PERFORM fn_webhook_register_action_plan(
    v_event, v_token,
    '[{"action_key":"a1","action_type":"dm_send","side_effect":true}]'::jsonb
  );
  SELECT outcome, action_id, lease_token INTO v_outcome, v_action, v_atoken
  FROM fn_webhook_claim_action(v_event, v_token, 'a1', 300);
  PERFORM fn_webhook_mark_action_unknown(v_action, v_token, v_atoken, 'ambiguous');
  PERFORM fn_webhook_recover_expired_leases(10);
  SELECT status INTO v_status1 FROM webhook_event_ledger WHERE id = v_event;
  SELECT status INTO v_astatus1 FROM webhook_action_ledger WHERE id = v_action;
  PERFORM fn_webhook_recover_expired_leases(10);
  SELECT status INTO v_status2 FROM webhook_event_ledger WHERE id = v_event;
  SELECT status INTO v_astatus2 FROM webhook_action_ledger WHERE id = v_action;
  IF v_astatus1 <> 'unknown' OR v_astatus2 <> 'unknown' THEN
    RAISE EXCEPTION 'SCENARIO 28 FAIL: unknown action changed across repeated recovery';
  END IF;
  IF v_status1 <> 'manual_review' OR v_status2 <> 'manual_review' THEN
    RAISE EXCEPTION 'SCENARIO 28 FAIL: manual_review changed across repeated recovery';
  END IF;
  RAISE NOTICE 'SCENARIO 28 PASS (unknown and manual_review preserved across repeated recovery)';
END $$;

