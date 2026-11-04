-- InstaAuto V6 — Privilege Reduction Remediation
-- Revokes dangerous DDL-adjacent table privileges from anon/authenticated
-- while preserving SELECT, INSERT, UPDATE, DELETE and all service-role/owner privileges.
--
-- Scope:
--   - REVOKE TRUNCATE, REFERENCES, TRIGGER on all public application tables from anon/authenticated
--   - REVOKE MAINTAIN on the same tables, only when server_version_num >= 170000
--   - Default privileges: none present in baseline migration; no default-privilege change needed
--   - Service-role and postgres owner privileges are preserved
--
-- Idempotency: REVOKE is a no-op when the privilege is not held.
-- Safety: No table data is deleted or rewritten. No RLS policies are changed.

-- =========================================================================
-- A. Revoke TRUNCATE, REFERENCES, TRIGGER from anon/authenticated
--    These privilege names exist in all supported PostgreSQL versions,
--    so the revoke is unconditional.
--    Idempotent: REVOKE is a no-op when the privilege is not held.
-- =========================================================================

REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."automations" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."content_pool" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."conversations" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."dm_queue" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."ice_breakers" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."media_cache" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."messages" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."reels_posts" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."scheduler_config" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."unlock_attempts" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."users" FROM "anon", "authenticated";
REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE "public"."webhook_events" FROM "anon", "authenticated";

-- =========================================================================
-- B. Revoke MAINTAIN from anon/authenticated (PostgreSQL 17+ only)
--    MAINTAIN privilege was introduced in PostgreSQL 17. On PG 14/15/16
--    the keyword is unknown and the statement would fail to parse.
--    Dynamic SQL inside a version-guarded DO block ensures older servers
--    never encounter the unsupported syntax.
-- =========================================================================

DO $$
BEGIN
  IF (SELECT current_setting('server_version_num')::int) >= 170000 THEN
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."automations" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."content_pool" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."conversations" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."dm_queue" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."ice_breakers" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."media_cache" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."messages" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."reels_posts" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."scheduler_config" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."unlock_attempts" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."users" FROM "anon", "authenticated"';
    EXECUTE 'REVOKE MAINTAIN ON TABLE "public"."webhook_events" FROM "anon", "authenticated"';
  END IF;
END $$;

-- =========================================================================
-- C. Default privileges
--    The baseline migration (20261031140902_remote_schema.sql) contains no
--    ALTER DEFAULT PRIVILEGES statement. No default-grant remediation is
--    necessary for future tables.
-- =========================================================================
