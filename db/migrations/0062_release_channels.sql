-- The release channel of a host.
--
-- A fleet does not take every agent release at once: a few hosts follow the
-- beta channel and see a release first, the rest follow stable and see it
-- once the beta hosts have run it. The channel is a policy of the panel
-- recorded on the host - the host itself is not asked and nothing runs on
-- it - and a campaign selector may name it, so an agent upgrade in waves
-- targets "channel=beta" before "channel=stable".
--
-- A host is assigned explicitly and defaults to stable. There is no implicit
-- "latest": a host on no channel would follow nothing.
alter table hosts add column if not exists release_channel text not null default 'stable'
    check (release_channel in ('stable', 'beta'));

comment on column hosts.release_channel is
    'Which agent releases the host follows: stable or beta. Set by operators; a campaign selector may name it.';
