SET application_name = 'locker_b7'; BEGIN; SELECT pg_backend_pid() AS pid_locker_b7; SELECT * FROM webhook_event_ledger WHERE event_key = 'race_b7:expiry' FOR UPDATE; SELECT pg_sleep(8); COMMIT;
