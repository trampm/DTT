-- Table: public.password_resets

-- DROP TABLE IF EXISTS public.password_resets;

CREATE TABLE IF NOT EXISTS public.password_resets
(
    id bigint NOT NULL DEFAULT nextval('password_resets_id_seq'::regclass),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    user_id bigint NOT NULL,
    token text COLLATE pg_catalog."default" NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used boolean DEFAULT false,
    CONSTRAINT password_resets_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.password_resets
    OWNER to db_user_dtt;
-- Index: idx_password_resets_deleted_at

-- DROP INDEX IF EXISTS public.idx_password_resets_deleted_at;

CREATE INDEX IF NOT EXISTS idx_password_resets_deleted_at
    ON public.password_resets USING btree
    (deleted_at ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_password_resets_token

-- DROP INDEX IF EXISTS public.idx_password_resets_token;

CREATE UNIQUE INDEX IF NOT EXISTS idx_password_resets_token
    ON public.password_resets USING btree
    (token COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;