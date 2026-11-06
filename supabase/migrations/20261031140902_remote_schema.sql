SET local check_function_bodies = off;

CREATE SEQUENCE "public"."content_pool_sequence_index_seq" AS integer INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1 NO CYCLE;

CREATE TABLE "public"."automations" (
  "id"                uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "user_id"           bigint                   NOT NULL,
  "name"              text                     NOT NULL,
  "trigger_type"      text                     NOT NULL,
  "trigger_value"     text                     NOT NULL,
  "response_type"     text                     DEFAULT 'text'::text,
  "response_content"  jsonb,
  "media_selection"   jsonb,
  "selected_reel_id"  text,
  "specific_media_id" text,
  "trigger_source"    text                     NOT NULL DEFAULT 'comment'::text,
  "follow_up_steps"   jsonb,
  "is_active"         boolean                  DEFAULT true,
  "created_at"        timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  "updated_at"        timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "automations_pkey" PRIMARY KEY (id),
  CONSTRAINT "automations_trigger_source_check" CHECK ((trigger_source = ANY (ARRAY['comment'::text, 'dm'::text, 'story'::text])))
);

ALTER TABLE "public"."automations"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."content_pool" (
  "id"                  uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "user_id"             bigint                   NOT NULL,
  "video_url"           text                     NOT NULL,
  "caption"             text,
  "cover_url"           text,
  "sequence_index"      integer                  NOT NULL DEFAULT nextval('public.content_pool_sequence_index_seq'::regclass),
  "thumbnail_url"       text,
  "is_active"           boolean                  DEFAULT true,
  "created_at"          timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  "automation_template" jsonb,
  CONSTRAINT "content_pool_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."content_pool"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."conversations" (
  "id"                 uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "user_id"            bigint                   NOT NULL,
  "recipient_id"       text                     NOT NULL,
  "recipient_username" text                     NOT NULL,
  "last_message_at"    timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  "created_at"         timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  "updated_at"         timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "conversations_pkey" PRIMARY KEY (id),
  CONSTRAINT "conversations_user_id_recipient_id_key" UNIQUE (user_id, recipient_id)
);

ALTER TABLE "public"."conversations"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."dm_queue" (
  "id"           uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "user_id"      text                     NOT NULL,
  "recipient_id" text                     NOT NULL,
  "access_token" text                     NOT NULL,
  "message"      text                     NOT NULL,
  "send_at"      timestamp with time zone NOT NULL,
  "status"       text                     NOT NULL DEFAULT 'pending'::text,
  "attempts"     integer                  NOT NULL DEFAULT 0,
  "created_at"   timestamp with time zone DEFAULT now(),
  CONSTRAINT "dm_queue_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."dm_queue"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."ice_breakers" (
  "id"         uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "user_id"    bigint                   NOT NULL,
  "question"   text                     NOT NULL,
  "response"   text                     NOT NULL,
  "is_active"  boolean                  DEFAULT true,
  "created_at" timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ice_breakers_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."ice_breakers"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."media_cache" (
  "id"                 uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "user_id"            bigint                   NOT NULL,
  "media_id"           text                     NOT NULL,
  "media_type"         text                     NOT NULL,
  "caption"            text,
  "image_url"          text,
  "video_url"          text,
  "permalink"          text,
  "media_product_type" text,
  "timestamp"          timestamp with time zone,
  "cached_at"          timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "media_cache_pkey" PRIMARY KEY (id),
  CONSTRAINT "media_cache_user_id_media_id_key" UNIQUE (user_id, media_id)
);

ALTER TABLE "public"."media_cache"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."messages" (
  "id"                text                     NOT NULL,
  "conversation_id"   uuid                     NOT NULL,
  "user_id"           bigint                   NOT NULL,
  "sender_id"         text                     NOT NULL,
  "sender_username"   text                     NOT NULL,
  "content"           text                     NOT NULL,
  "is_from_instagram" boolean                  DEFAULT true,
  "created_at"        timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "messages_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."messages"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."reels_posts" (
  "id"              uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "user_id"         bigint                   NOT NULL,
  "content_pool_id" uuid,
  "video_url"       text                     NOT NULL,
  "caption"         text,
  "ig_container_id" text,
  "ig_media_id"     text,
  "status"          text                     DEFAULT 'PENDING'::text,
  "error_message"   text,
  "published_at"    timestamp with time zone,
  "created_at"      timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "reels_posts_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."reels_posts"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."scheduler_config" (
  "user_id"                bigint                   NOT NULL,
  "interval_minutes"       integer                  NOT NULL DEFAULT 240,
  "start_time"             time without time zone   DEFAULT '09:00:00'::time WITHOUT time zone,
  "end_time"               time without time zone   DEFAULT '21:00:00'::time WITHOUT time zone,
  "last_run_at"            timestamp with time zone,
  "next_run_at"            timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  "current_sequence_index" integer                  DEFAULT 1,
  "is_running"             boolean                  DEFAULT false,
  "created_at"             timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  "updated_at"             timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "scheduler_config_pkey" PRIMARY KEY (user_id)
);

ALTER TABLE "public"."scheduler_config"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."unlock_attempts" (
  "key"        text                     NOT NULL,
  "count"      integer                  NOT NULL DEFAULT 0,
  "updated_at" timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "unlock_attempts_pkey" PRIMARY KEY (key)
);

ALTER TABLE "public"."unlock_attempts"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."users" (
  "id"                      bigint                   NOT NULL,
  "username"                text                     NOT NULL,
  "access_token"            text                     NOT NULL,
  "token_expires_at"        timestamp with time zone,
  "business_account_id"     bigint,
  "page_id"                 text,
  "groq_auto_reply_enabled" boolean                  DEFAULT false,
  "ai_context"              text,
  "groq_api_key"            text,
  "ai_base_url"             text,
  "ai_model"                text,
  "created_at"              timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  "updated_at"              timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "users_pkey" PRIMARY KEY (id),
  CONSTRAINT "users_username_key" UNIQUE (username)
);

ALTER TABLE "public"."users"
  ENABLE ROW LEVEL SECURITY;

CREATE TABLE "public"."webhook_events" (
  "id"           uuid                     NOT NULL DEFAULT gen_random_uuid(),
  "event_type"   text                     NOT NULL,
  "user_id"      bigint,
  "data"         jsonb,
  "processed_at" timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "webhook_events_pkey" PRIMARY KEY (id)
);

ALTER TABLE "public"."webhook_events"
  ENABLE ROW LEVEL SECURITY;

ALTER SEQUENCE "public"."content_pool_sequence_index_seq" OWNED BY "public"."content_pool"."sequence_index";

CREATE OR REPLACE FUNCTION public.bump_unlock_attempt (
  p_key text
)
  RETURNS integer
  LANGUAGE plpgsql
  AS $function$
DECLARE
  v_count INTEGER;
BEGIN
  INSERT INTO public.unlock_attempts (key, count, updated_at)
  VALUES (p_key, 1, NOW())
  ON CONFLICT (key) DO UPDATE
    SET count = public.unlock_attempts.count + 1,
        updated_at = NOW()
  RETURNING count INTO v_count;

  RETURN v_count;
END;
$function$;

ALTER TABLE "public"."messages"
  ADD CONSTRAINT "messages_conversation_id_fkey" FOREIGN KEY (conversation_id) REFERENCES public.conversations(id) ON DELETE CASCADE;

ALTER TABLE "public"."reels_posts"
  ADD CONSTRAINT "reels_posts_content_pool_id_fkey" FOREIGN KEY (content_pool_id) REFERENCES public.content_pool(id) ON DELETE SET NULL;

ALTER TABLE "public"."automations"
  ADD CONSTRAINT "automations_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."content_pool"
  ADD CONSTRAINT "content_pool_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."conversations"
  ADD CONSTRAINT "conversations_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."ice_breakers"
  ADD CONSTRAINT "ice_breakers_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."media_cache"
  ADD CONSTRAINT "media_cache_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."messages"
  ADD CONSTRAINT "messages_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."reels_posts"
  ADD CONSTRAINT "reels_posts_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE "public"."scheduler_config"
  ADD CONSTRAINT "scheduler_config_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

CREATE INDEX idx_automations_trigger_source ON public.automations USING btree (trigger_source);

CREATE INDEX idx_automations_user_source ON public.automations USING btree (user_id, trigger_source);

CREATE INDEX idx_content_pool_user_sequence ON public.content_pool USING btree (user_id, sequence_index);

CREATE INDEX idx_reels_posts_user_status ON public.reels_posts USING btree (user_id, status);

CREATE INDEX idx_scheduler_next_run ON public.scheduler_config USING btree (next_run_at);

CREATE INDEX idx_unlock_attempts_updated ON public.unlock_attempts USING btree (updated_at);

CREATE POLICY "automations_delete_own" ON "public"."automations"
  FOR DELETE
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "automations_insert_own" ON "public"."automations"
  FOR INSERT
  TO "anon", "authenticated"
  WITH CHECK ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "automations_select_own" ON "public"."automations"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "automations_update_own" ON "public"."automations"
  FOR UPDATE
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "content_pool_delete_own" ON "public"."content_pool"
  FOR DELETE
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "content_pool_insert_own" ON "public"."content_pool"
  FOR INSERT
  TO "anon", "authenticated"
  WITH CHECK ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "content_pool_select_own" ON "public"."content_pool"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "content_pool_update_own" ON "public"."content_pool"
  FOR UPDATE
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "conversations_insert_own" ON "public"."conversations"
  FOR INSERT
  TO "anon", "authenticated"
  WITH CHECK ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "conversations_select_own" ON "public"."conversations"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "conversations_update_own" ON "public"."conversations"
  FOR UPDATE
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "dm_queue_select_own" ON "public"."dm_queue"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((user_id = ((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text)));

CREATE POLICY "ice_breakers_delete_own" ON "public"."ice_breakers"
  FOR DELETE
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "ice_breakers_insert_own" ON "public"."ice_breakers"
  FOR INSERT
  TO "anon", "authenticated"
  WITH CHECK ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "ice_breakers_select_own" ON "public"."ice_breakers"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "ice_breakers_update_own" ON "public"."ice_breakers"
  FOR UPDATE
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "media_cache_select_own" ON "public"."media_cache"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "messages_insert_own" ON "public"."messages"
  FOR INSERT
  TO "anon", "authenticated"
  WITH CHECK ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "messages_select_own" ON "public"."messages"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "reels_posts_insert_own" ON "public"."reels_posts"
  FOR INSERT
  TO "anon", "authenticated"
  WITH CHECK ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "reels_posts_select_own" ON "public"."reels_posts"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "reels_posts_update_own" ON "public"."reels_posts"
  FOR UPDATE
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "scheduler_config_select_own" ON "public"."scheduler_config"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "scheduler_config_upsert_own" ON "public"."scheduler_config"
  FOR ALL
  TO "anon", "authenticated"
  USING ((user_id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "users_select_own" ON "public"."users"
  FOR SELECT
  TO "anon", "authenticated"
  USING ((id = (((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text))::bigint));

CREATE POLICY "Public Viewing" ON "storage"."objects"
  FOR SELECT
  TO PUBLIC
  USING ((bucket_id = 'reels'::text));

GRANT EXECUTE ON FUNCTION "public"."bump_unlock_attempt"(text) TO PUBLIC, "anon", "authenticated";

REVOKE ALL ON FUNCTION "public"."bump_unlock_attempt"(text) FROM "postgres";

GRANT EXECUTE ON FUNCTION "public"."bump_unlock_attempt"(text) TO "postgres";

GRANT EXECUTE ON FUNCTION "public"."bump_unlock_attempt"(text) TO "service_role";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."content_pool_sequence_index_seq" TO "anon", "authenticated";

REVOKE ALL ON SEQUENCE "public"."content_pool_sequence_index_seq" FROM "postgres";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."content_pool_sequence_index_seq" TO "postgres";

GRANT SELECT, UPDATE, USAGE ON SEQUENCE "public"."content_pool_sequence_index_seq" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."automations" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."automations" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."automations" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."automations" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."content_pool" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."content_pool" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."content_pool" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."content_pool" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."conversations" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."conversations" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."conversations" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."conversations" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."dm_queue" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."dm_queue" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."dm_queue" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."dm_queue" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."ice_breakers" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."ice_breakers" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."ice_breakers" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."ice_breakers" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."media_cache" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."media_cache" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."media_cache" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."media_cache" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."messages" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."messages" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."messages" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."messages" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."reels_posts" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."reels_posts" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."reels_posts" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."reels_posts" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."scheduler_config" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."scheduler_config" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."scheduler_config" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."scheduler_config" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."unlock_attempts" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."unlock_attempts" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."unlock_attempts" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."unlock_attempts" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."users" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."users" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."users" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."users" TO "service_role";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."webhook_events" TO "anon", "authenticated";

REVOKE ALL ON TABLE "public"."webhook_events" FROM "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."webhook_events" TO "postgres";

GRANT DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON TABLE "public"."webhook_events" TO "service_role";

