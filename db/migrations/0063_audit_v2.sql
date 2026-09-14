-- The second shape of the audit trail, and role bindings with a validity.
--
-- An event so far said who did what to which target and how it ended. The
-- document asks for more around it: which session the actor held and how
-- it was authenticated, which request the event belongs to, what the host
-- was called and where it stood at the moment - a host renamed or
-- decommissioned later must not rewrite its own history - and, for a
-- change, what it looked like before and after. Everything is nullable:
-- an agent or the system has no session, a refusal has no before and
-- after, and the trail written so far stays readable as it is. The
-- append-only trigger is untouched; the new columns are written once with
-- the row and never after.

alter table audit_events
    add column session_id      text,
    add column acr             text,
    add column amr             text[],
    add column auth_time       timestamptz,
    add column target_hostname text,
    add column target_address  text,
    add column approval_chain  jsonb,
    add column before          jsonb,
    add column after           jsonb;

comment on column audit_events.session_id is
    'The digest of the browser session the actor held; null for an API token, an agent or the system.';
comment on column audit_events.acr is
    'The authentication level the identity provider reported for the session.';
comment on column audit_events.amr is
    'The authentication methods the identity provider reported for the session.';
comment on column audit_events.auth_time is
    'When the identity provider authenticated the session.';
comment on column audit_events.target_hostname is
    'The name of the target host as the panel knew it when the event was written.';
comment on column audit_events.target_address is
    'The management address of the target host when the event was written.';
comment on column audit_events.approval_chain is
    'For an approval: who ordered the change and who approved it, in order.';
comment on column audit_events.before is
    'For a change: the state before it, where the handler had it at hand.';
comment on column audit_events.after is
    'For a change: the state after it.';

-- The session digest lets an incident review pull everything one session
-- did, whichever identity and target the events name.
create index audit_events_session_idx on audit_events (session_id, occurred_at desc)
    where session_id is not null;

-- A role binding may end by itself. An access granted for a rotation or an
-- audit engagement then does not depend on somebody remembering to take
-- it back. The panel ignores an expired binding at once; the sweep notes
-- the expiry on the trail exactly once, which is what the flag is for.
alter table role_bindings
    add column valid_until  timestamptz,
    add column expiry_noted boolean not null default false;

comment on column role_bindings.valid_until is
    'The moment the binding stops granting anything; null means until revoked.';
comment on column role_bindings.expiry_noted is
    'Whether the expiry has already been written to the audit trail.';

create index role_bindings_expiry_idx on role_bindings (valid_until)
    where valid_until is not null and not expiry_noted;
