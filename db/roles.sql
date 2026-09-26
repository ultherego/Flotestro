-- The database roles of an installation, and what each of them may do.
--
-- Run once, as a superuser, against the database the panel will use:
--
--   psql "$SUPERUSER_DSN" -v ON_ERROR_STOP=1 \
--        -v owner_password=... -v migrator_password=... \
--        -v runtime_password=... -v backup_password=... -f db/roles.sql
--
-- The point is that the process which serves the fleet cannot change the
-- schema. A serving process that may run DDL is one that an injected statement
-- or a mistaken deployment can reshape the database with, and a panel that
-- migrates on its own start does exactly that on every restart.
--
-- owner     holds the schema and cannot log in. Nothing connects as it.
-- migrator  logs in only to migrate, and does so by taking on the owner.
-- runtime   is what the panel serves as: reads and writes rows, no DDL.
-- backup    reads everything and writes nothing.
--
-- The migrator must not be a superuser: a superuser may take on any role at
-- all, so the separation would exist on paper only, and the migrator refuses
-- to start when it finds itself one.

\set ON_ERROR_STOP on

-- The owner of every object. NOLOGIN, because an owner nobody connects as is
-- an owner no leaked password reaches.
do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'flotestro_owner') then
        create role flotestro_owner nologin;
    end if;
end $$;

do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'flotestro_migrator') then
        execute format('create role flotestro_migrator login password %L', :'migrator_password');
    else
        execute format('alter role flotestro_migrator login password %L', :'migrator_password');
    end if;
end $$;

do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'flotestro_runtime') then
        execute format('create role flotestro_runtime login password %L', :'runtime_password');
    else
        execute format('alter role flotestro_runtime login password %L', :'runtime_password');
    end if;
end $$;

do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'flotestro_backup') then
        execute format('create role flotestro_backup login password %L', :'backup_password');
    else
        execute format('alter role flotestro_backup login password %L', :'backup_password');
    end if;
end $$;

-- The migrator works as the owner and is not the owner: what it creates belongs
-- to the owner, so revoking the migrator's login changes nothing about the
-- objects.
grant flotestro_owner to flotestro_migrator;

alter schema public owner to flotestro_owner;
grant usage on schema public to flotestro_runtime, flotestro_backup;

-- What exists now.
grant select, insert, update, delete on all tables in schema public to flotestro_runtime;
grant usage, select on all sequences in schema public to flotestro_runtime;
grant execute on all functions in schema public to flotestro_runtime;
grant select on all tables in schema public to flotestro_backup;

-- And what the next migration creates: the defaults are recorded for the owner,
-- because the owner is who the migrator creates as.
alter default privileges for role flotestro_owner in schema public
    grant select, insert, update, delete on tables to flotestro_runtime;
alter default privileges for role flotestro_owner in schema public
    grant usage, select on sequences to flotestro_runtime;
alter default privileges for role flotestro_owner in schema public
    grant execute on functions to flotestro_runtime;
alter default privileges for role flotestro_owner in schema public
    grant select on tables to flotestro_backup;

-- Nothing else creates anything here.
revoke create on schema public from public;
