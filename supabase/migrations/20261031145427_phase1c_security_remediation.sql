-- InstaAuto Phase 1C — security remediation
-- STATUS: APPLIED. Applied to production (eszvufkbremlqyhxxpzq) as version 20261031145427.
-- Production catalog state verified on 2026-11-01.
--
-- Scope:
--   1) Ensure the 'reels' Storage bucket exists and is private.
--   2) Remove the known public read policy for reels objects.
--   3) Harden bump_unlock_attempt(text) without changing its function body,
--      SECURITY INVOKER mode, counter behavior, or postgres ownership.
--
-- Intentionally OUT OF SCOPE:
--   - ALTER DEFAULT PRIVILEGES: the earlier live dump showed 12 broad default
--     grants to anon/authenticated/service_role. Recreating those defaults
--     would automatically grant broad rights on FUTURE public objects. That is
--     not a security fix. Keep this as a separately reviewed privilege task.
--   - Revoking existing table/sequence grants: deferred in the Phase 1A plan.
--   - Rewriting application-table RLS policies.
--   - Adding the four optional FK indexes.
--
-- Safety:
--   - No table data is deleted or rewritten.
--   - No RLS policy on public application tables is changed.
--   - No broad existing table grants are revoked in this migration.
--   - No objects are moved or deleted from Storage.

-- ---------------------------------------------------------------------------
-- A. Make the reels bucket private.
--    The UPSERT handles both an existing remote bucket and a fresh local DB.
--    Only the 'public' flag is changed on conflict; other bucket settings are
--    left intact. The earlier live audit found zero objects in this bucket.
-- ---------------------------------------------------------------------------

INSERT INTO "storage"."buckets" ("id", "name", "public")
VALUES ('reels', 'reels', false)
ON CONFLICT ("id") DO UPDATE
SET "public" = EXCLUDED."public";

-- Remove the known public read policy on storage.objects for this bucket.
DROP POLICY IF EXISTS "Public Viewing" ON "storage"."objects";

-- ---------------------------------------------------------------------------
-- B. Harden bump_unlock_attempt(text).
--    Preserve its current function body and SECURITY INVOKER semantics.
--    An empty search_path prevents objects in writable schemas from shadowing
--    unqualified names. The body schema-qualifies public.unlock_attempts;
--    NOW() resolves from pg_catalog.
-- ---------------------------------------------------------------------------

ALTER FUNCTION "public"."bump_unlock_attempt"("text")
  SET search_path = '';

REVOKE EXECUTE ON FUNCTION "public"."bump_unlock_attempt"("text")
  FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION "public"."bump_unlock_attempt"("text")
  FROM "anon";
REVOKE EXECUTE ON FUNCTION "public"."bump_unlock_attempt"("text")
  FROM "authenticated";

-- Retain the service backend's explicit execute permission. The postgres
-- owner retains owner privileges; no ownership transfer is performed.
GRANT EXECUTE ON FUNCTION "public"."bump_unlock_attempt"("text")
  TO "service_role";

-- END OF MIGRATION
