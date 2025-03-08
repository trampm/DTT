-- Table: public.roles

-- DROP TABLE IF EXISTS public.roles;

CREATE TABLE IF NOT EXISTS public.roles
(
    id bigint NOT NULL DEFAULT nextval('roles_id_seq'::regclass),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name text COLLATE pg_catalog."default" NOT NULL,
    description text COLLATE pg_catalog."default",
    parent_id bigint,
    CONSTRAINT roles_pkey PRIMARY KEY (id),
    CONSTRAINT fk_roles_parent FOREIGN KEY (parent_id)
        REFERENCES public.roles (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.roles
    OWNER to db_user_dtt;
-- Index: idx_roles_deleted_at

-- DROP INDEX IF EXISTS public.idx_roles_deleted_at;

CREATE INDEX IF NOT EXISTS idx_roles_deleted_at
    ON public.roles USING btree
    (deleted_at ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_roles_name

-- DROP INDEX IF EXISTS public.idx_roles_name;

CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_name
    ON public.roles USING btree
    (name COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;