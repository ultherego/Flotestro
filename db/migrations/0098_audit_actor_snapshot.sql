-- The actor of an audit event, as it was when the event happened.
--
-- actor_id carries a subject or a host identifier as text, and the panel
-- named the actor by joining that text with the live tables. A person
-- renamed, a token reissued under another description or a host
-- decommissioned later then changed the history under the reviewer, and a
-- machine identifier - thirty-two hex digits, which a uuid column accepts -
-- could be read as a host it never was. The columns below are the actor
-- snapshotted at the moment of writing: the immutable identifier, the
-- name as it was, the kind that says which table the identifier belongs
-- to, and the credential the request came with. They are written once
-- with the row and never joined. actor_id stays for the readers that know
-- it. Everything is nullable: a campaign has no principal, a person has no
-- resource, and the trail written so far stays readable as it is.

alter table audit_events
    add column if not exists actor_principal_id  uuid,
    add column if not exists actor_subject       text,
    add column if not exists actor_display_name  text,
    add column if not exists actor_kind          text,
    add column if not exists actor_resource_type text,
    add column if not exists actor_resource_id   uuid,
    add column if not exists actor_resource_name text,
    add column if not exists credential_id       uuid;

comment on column audit_events.actor_principal_id is
    'The immutable identifier of the identity that acted; null for an agent, a relay, a machine or the panel.';
comment on column audit_events.actor_subject is
    'The subject of the identity, or the identifier of the host, relay, machine or panel part, as it was.';
comment on column audit_events.actor_display_name is
    'What the identity was called when the event was written.';
comment on column audit_events.actor_kind is
    'user, service, anonymous, agent, relay, machine or system: which table actor_subject belongs to.';
comment on column audit_events.actor_resource_type is
    'For a non-person: host, relay, machine, campaign, policy, remediation_plan, campaign_schedule or directory_change.';
comment on column audit_events.actor_resource_id is
    'The row of the resource that acted; null for a machine identifier, which is not a row of anything.';
comment on column audit_events.actor_resource_name is
    'What the resource was called when the event was written.';
comment on column audit_events.credential_id is
    'The row of the browser session or the API token the request came with; never the credential itself.';

-- A review groups the trail by who acted, by the immutable identifier
-- rather than by the text of the name.
create index if not exists audit_events_actor_principal_idx
    on audit_events (actor_kind, actor_principal_id, occurred_at desc)
    where actor_principal_id is not null;
create index if not exists audit_events_actor_resource_idx
    on audit_events (actor_kind, actor_resource_id, occurred_at desc)
    where actor_resource_id is not null;

-- The events written before the snapshot get what can still be derived
-- from actor_id: the subject as it is, the kind from the type of actor and
-- the spelling of the identifier, the immutable identifier where the row
-- still exists under that subject or identifier. The names are not
-- backfilled: a name read now is the name now, not the name then, and a
-- snapshot that pretends otherwise is worse than an empty one. The
-- interface falls back to the subject where the name is empty.
--
-- The trail is append-only and the trigger refuses an update. The one
-- update here fills columns that did not exist when the rows were written
-- and touches nothing the rows already said; the trigger is switched off
-- for this statement alone, inside the migration's transaction, and back
-- on before it commits.
alter table audit_events disable trigger audit_events_no_update;

update audit_events
set actor_subject = actor_id,
    actor_kind = case
        when actor_type = 'system' then 'system'
        when actor_type = 'user' and actor_id = 'anonymous' then 'anonymous'
        when actor_type = 'user' then coalesce(
            (select p.kind from principals p where p.subject = audit_events.actor_id), 'user')
        when actor_id ~ '^[0-9a-f]{32}$' then 'machine'
        when actor_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
             and exists (select 1 from relays r where r.id = audit_events.actor_id::uuid) then 'relay'
        when exists (select 1 from relays r where r.name = audit_events.actor_id) then 'relay'
        else 'agent'
    end,
    actor_principal_id = case
        when actor_type = 'user' then
            (select p.id from principals p where p.subject = audit_events.actor_id)
    end,
    actor_resource_type = case
        when actor_type = 'system' and actor_id like 'campaign:%' then 'campaign'
        when actor_type = 'system' and actor_id like 'policy:%' then 'policy'
        when actor_type = 'system' and actor_id like 'remediation:%' then 'remediation_plan'
        when actor_type = 'system' and actor_id like 'schedule:%' then 'campaign_schedule'
        when actor_type = 'system' and actor_id like 'directory-change:%' then 'directory_change'
        when actor_type = 'agent' and actor_id ~ '^[0-9a-f]{32}$' then 'machine'
        when actor_type = 'agent' and actor_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
             and exists (select 1 from relays r where r.id = audit_events.actor_id::uuid) then 'relay'
        when actor_type = 'agent' and actor_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then 'host'
        when actor_type = 'agent' and exists (select 1 from relays r where r.name = audit_events.actor_id) then 'relay'
    end,
    actor_resource_id = case
        when actor_type = 'system' and split_part(actor_id, ':', 2)
             ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
             and split_part(actor_id, ':', 1) in ('campaign', 'policy', 'remediation', 'schedule', 'directory-change')
             then split_part(actor_id, ':', 2)::uuid
        when actor_type = 'agent' and actor_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
             then actor_id::uuid
        when actor_type = 'agent' then
            (select r.id from relays r where r.name = audit_events.actor_id)
    end,
    actor_resource_name = case
        when actor_type = 'agent' and actor_id ~ '^[0-9a-f]{32}$' then actor_id
    end
where actor_kind is null;

alter table audit_events enable trigger audit_events_no_update;
