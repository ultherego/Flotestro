-- The certificates of the authorities withdrawn from signing, for an
-- installation that keeps its keys in the database.
--
-- They do not belong in crypto_wrapped_keys: a row there is a private key
-- wrapped with the key encryption key the deployment mounts, and a withdrawn
-- authority has no private key any more. It has nothing left to sign, so the
-- key is destroyed at the handover and only the certificate stays - the fleet
-- still has to recognise the hosts that authority issued for, until the last
-- of them has renewed.
--
-- Public material, therefore, and a table that says so: this is what used to
-- lie in ca-retired/<serial>.pem of one machine's state directory, where no
-- second replica could read it.
create table crypto_retired_authorities (
    -- The serial of the certificate, which is what the state directory named
    -- the file by.
    serial      text primary key,
    -- The certificate in PEM, as it goes into the trust bundle the agents get.
    certificate text        not null,
    retired_at  timestamptz not null default now()
);

comment on table crypto_retired_authorities is
    'The certificates of the fleet authorities withdrawn from signing. Public material with no key: the key is destroyed at the handover, and the certificate stays only so the hosts it issued for are still recognised.';
