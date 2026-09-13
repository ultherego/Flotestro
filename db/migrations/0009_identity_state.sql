-- The state of the host's domain integration. The fields serve filtering and
-- detecting hosts that need attention, so they are normalised; the full report
-- stays in the JSONB of the inventory revision.
--
-- NULL values mean an undetermined state, not a missing integration: a host
-- that could not be queried is something other than a host deliberately outside the domain.
alter table hosts add column identity_enrolled    boolean not null default false;
alter table hosts add column identity_domain      text;
alter table hosts add column identity_realm       text;
alter table hosts add column identity_sssd_online boolean;
alter table hosts add column identity_checked_at  timestamptz;

create index hosts_identity_idx on hosts (identity_enrolled, identity_domain);
-- Hosts in the domain that lost contact with the directory need attention.
create index hosts_identity_offline_idx on hosts (identity_sssd_online)
    where identity_enrolled and identity_sssd_online is not true;
