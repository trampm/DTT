-- Table: public.profiles

-- DROP TABLE IF EXISTS public.profiles;

CREATE TABLE IF NOT EXISTS public.profiles
(
    id bigint NOT NULL DEFAULT nextval('profiles_id_seq'::regclass),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    user_id bigint NOT NULL,
    first_name text COLLATE pg_catalog."default",
    last_name text COLLATE pg_catalog."default",
    avatar text COLLATE pg_catalog."default",
    phone_number text COLLATE pg_catalog."default",
    bio text COLLATE pg_catalog."default",
    CONSTRAINT profiles_pkey PRIMARY KEY (id),
    CONSTRAINT fk_users_profile FOREIGN KEY (user_id)
        REFERENCES public.users (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.profiles
    OWNER to db_user_dtt;
-- Index: idx_profiles_deleted_at

-- DROP INDEX IF EXISTS public.idx_profiles_deleted_at;

CREATE INDEX IF NOT EXISTS idx_profiles_deleted_at
    ON public.profiles USING btree
    (deleted_at ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_profiles_user_id

-- DROP INDEX IF EXISTS public.idx_profiles_user_id;

CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_user_id
    ON public.profiles USING btree
    (user_id ASC NULLS LAST)
    TABLESPACE pg_default;