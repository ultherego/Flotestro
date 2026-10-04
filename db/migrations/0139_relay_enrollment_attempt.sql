-- An enrollment attempt may belong to a relay, not only to a host.
--
-- The attempt is what makes an enrollment idempotent: the token is spent in the
-- prologue both branches share, so an answer lost in the network leaves the
-- certificate recorded in the panel and absent from the machine, and the retry
-- has to find the attempt and be given the same certificate again. The relay
-- branch records its attempt as of today - and the only column for the subject
-- was host_id, with a foreign key to hosts, so writing a relay's identifier
-- into it was refused by the database (23503) and every relay enrollment
-- answered 500.
--
-- Two columns rather than one without a constraint: a host attempt keeps the
-- key that says the host is real, and a relay attempt gets one of its own.
alter table enrollment_attempts
    add column if not exists relay_id uuid references relays (id) on delete set null;

alter table enrollment_requests
    add column if not exists enrolled_relay_id uuid references relays (id) on delete set null;

do $$
begin
    -- An attempt is of one kind or of neither (an attempt recorded before
    -- anything was issued); it is never of both.
    if not exists (select 1 from pg_constraint where conname = 'enrollment_attempts_subject_check') then
        alter table enrollment_attempts add constraint enrollment_attempts_subject_check
            check (host_id is null or relay_id is null);
    end if;
end $$;
