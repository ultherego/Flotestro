-- The campaign approval fingerprint.
--
-- The approval is to concern exactly what the operator saw: the same
-- operation, the same payload, the same host list and the same rollout
-- policy. Without the fingerprint the consent referred to the campaign
-- identifier, and thus also to everything somebody changed along the way.
alter table campaigns
    add column if not exists approval_fingerprint text not null default '';

comment on column campaigns.approval_fingerprint is
    'The fingerprint of the operation, the payload, the host snapshot and the rollout policy. The approval must give it.';
