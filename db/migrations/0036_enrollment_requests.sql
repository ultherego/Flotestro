-- Enrollment stops being a bare token.
--
-- The token is a secret authorising one attempt, but the panel needs a
-- durable record of the pending installation: who ordered it, for what
-- purpose, how it ended and whether it may still be used. The token digest
-- alone answers none of those questions.
do $$
begin
    if exists (select 1 from information_schema.tables
               where table_name = 'enrollment_tokens') then
        alter table enrollment_tokens rename to enrollment_requests;
    end if;
end $$;

alter table enrollment_requests
    -- The purpose blocks a quiet re-enrollment: "new host" and "identity
    -- replacement of an existing host" are two different decisions and need
    -- two different orders.
    add column if not exists purpose             text,
    -- Binding to a specific machine and a specific host. In automation and in
    -- identity recovery the token must not match just anything.
    add column if not exists expected_machine_id text,
    -- An order without the host it concerns makes no sense: it is deleted
    -- together with the host. The record of which host was created stays -
    -- that is history, not a dependency.
    add column if not exists expected_host_id    uuid references hosts (id) on delete cascade,
    -- The status is for the operator and the audit, never a basis of authorisation.
    add column if not exists status              text,
    add column if not exists enrolled_host_id    uuid references hosts (id) on delete set null,
    add column if not exists updated_at          timestamptz not null default now();

update enrollment_requests set purpose = case when kind = 'relay' then 'relay' else 'new' end
    where purpose is null;
update enrollment_requests set status = case
        when revoked_at is not null then 'revoked'
        when uses >= max_uses       then 'enrolled'
        when expires_at < now()     then 'expired'
        else 'pending'
    end
    where status is null;

alter table enrollment_requests alter column purpose set not null;
alter table enrollment_requests alter column purpose set default 'new';
alter table enrollment_requests alter column status set not null;
alter table enrollment_requests alter column status set default 'pending';

do $$
begin
    if not exists (select 1 from pg_constraint where conname = 'enrollment_requests_purpose_check') then
        alter table enrollment_requests add constraint enrollment_requests_purpose_check
            check (purpose in ('new', 'replace_identity', 'relay'));
    end if;
    if not exists (select 1 from pg_constraint where conname = 'enrollment_requests_status_check') then
        alter table enrollment_requests add constraint enrollment_requests_status_check
            check (status in ('pending', 'enrolled', 'expired', 'revoked', 'failed'));
    end if;
    -- An identity replacement without naming the host would be a token that
    -- matches anyone - and that is exactly what the purpose is to protect against.
    if not exists (select 1 from pg_constraint where conname = 'enrollment_requests_recovery_check') then
        alter table enrollment_requests add constraint enrollment_requests_recovery_check
            check ((purpose = 'replace_identity') = (expected_host_id is not null));
    end if;
    -- The kind of identity and the purpose must agree: a relay does not enroll
    -- with a host order nor the other way round.
    if not exists (select 1 from pg_constraint where conname = 'enrollment_requests_kind_check') then
        alter table enrollment_requests add constraint enrollment_requests_kind_check
            check ((kind = 'relay') = (purpose = 'relay'));
    end if;
end $$;

-- An enrollment attempt is the record of what was already issued.
--
-- Without it a lost response in the network ends with a host without an
-- identity and a token that is already spent: the server recorded the host
-- and issued a certificate, and the agent never saw it. A repeated attempt
-- with the same identifier and the same CSR is to get the same certificate.
create table if not exists enrollment_attempts (
    request_id         uuid        not null references enrollment_requests (id) on delete cascade,
    client_request_id  uuid        not null,
    csr_sha256         bytea       not null check (octet_length(csr_sha256) = 32),
    machine_id         text        not null,
    host_id            uuid        references hosts (id) on delete set null,
    certificate_pem    bytea,
    ca_bundle_pem      bytea,
    certificate_serial text,
    completed_at       timestamptz,
    created_at         timestamptz not null default now(),
    primary key (request_id, client_request_id)
);

create unique index if not exists enrollment_attempts_csr_idx
    on enrollment_attempts (request_id, csr_sha256);
