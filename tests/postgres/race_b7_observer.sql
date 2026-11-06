-- Race B7 Independent Observer SQL
-- Samples pg_stat_activity and pg_locks for the locker_b7 / waiter_b7 pair.
-- Intended to be run via: docker exec -i <container> psql -U postgres -d insta_test -f /tmp/race_b7_observer.sql

-- 1. Activity snapshot: confirm both sessions active and waiter blocked on Lock/transactionid.
SELECT
  pid,
  application_name,
  state,
  wait_event_type,
  wait_event,
  pg_blocking_pids(pid) AS blocked_by
FROM pg_stat_activity
WHERE application_name IN ('locker_b7', 'waiter_b7')
ORDER BY application_name;

-- 2. Lock snapshot: confirm locker holds the row lock and waiter is waiting (granted = f).
SELECT
  pid,
  locktype,
  relation::regclass AS relation,
  mode,
  granted
FROM pg_locks
WHERE pid IN (
  SELECT pid FROM pg_stat_activity WHERE application_name IN ('locker_b7', 'waiter_b7')
)
ORDER BY pid, mode;
