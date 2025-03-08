-- Table: public.refresh_tokens

-- DROP TABLE IF EXISTS public.refresh_tokens;

CREATE TABLE IF NOT EXISTS public.refresh_tokens
(
    id bigint NOT NULL DEFAULT nextval('refresh_tokens_id_seq'::regclass),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    user_id bigint,
    token text COLLATE pg_catalog."default",
    expires_at timestamp with time zone,
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.refresh_tokens
    OWNER to db_user_dtt;
-- Index: idx_refresh_tokens_deleted_at

-- DROP INDEX IF EXISTS public.idx_refresh_tokens_deleted_at;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_deleted_at
    ON public.refresh_tokens USING btree
    (deleted_at ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_refresh_tokens_expires_at

-- DROP INDEX IF EXISTS public.idx_refresh_tokens_expires_at;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON public.refresh_tokens USING btree
    (expires_at ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_refresh_tokens_token

-- DROP INDEX IF EXISTS public.idx_refresh_tokens_token;

CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token
    ON public.refresh_tokens USING btree
    (token COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_refresh_tokens_user_id

-- DROP INDEX IF EXISTS public.idx_refresh_tokens_user_id;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id
    ON public.refresh_tokens USING btree
    (user_id ASC NULLS LAST)
    TABLESPACE pg_default;