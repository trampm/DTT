-- Table: public.permissions

-- DROP TABLE IF EXISTS public.permissions;

CREATE TABLE IF NOT EXISTS public.permissions
(
    id bigint NOT NULL DEFAULT nextval('permissions_id_seq'::regclass),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name text COLLATE pg_catalog."default" NOT NULL,
    description text COLLATE pg_catalog."default",
    CONSTRAINT permissions_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.permissions
    OWNER to db_user_dtt;
-- Index: idx_permissions_deleted_at

-- DROP INDEX IF EXISTS public.idx_permissions_deleted_at;

CREATE INDEX IF NOT EXISTS idx_permissions_deleted_at
    ON public.permissions USING btree
    (deleted_at ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_permissions_name

-- DROP INDEX IF EXISTS public.idx_permissions_name;

CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_name
    ON public.permissions USING btree
    (name COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;