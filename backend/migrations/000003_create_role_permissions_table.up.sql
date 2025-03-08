-- Table: public.role_permissions

-- DROP TABLE IF EXISTS public.role_permissions;

CREATE TABLE IF NOT EXISTS public.role_permissions
(
    id bigint NOT NULL DEFAULT nextval('role_permissions_id_seq'::regclass),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    role_id bigint,
    permission_id bigint,
    CONSTRAINT role_permissions_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.role_permissions
    OWNER to db_user_dtt;
-- Index: idx_role_permission

-- DROP INDEX IF EXISTS public.idx_role_permission;

CREATE UNIQUE INDEX IF NOT EXISTS idx_role_permission
    ON public.role_permissions USING btree
    (role_id ASC NULLS LAST, permission_id ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_role_permissions_deleted_at

-- DROP INDEX IF EXISTS public.idx_role_permissions_deleted_at;

CREATE INDEX IF NOT EXISTS idx_role_permissions_deleted_at
    ON public.role_permissions USING btree
    (deleted_at ASC NULLS LAST)
    TABLESPACE pg_default;