-- The preview of a campaign becomes a token the order is checked against.
--
-- A campaign was ordered by describing the selector twice: once to the
-- preview, which counted the hosts and qualified them, and once to the
-- creation, which resolved them again. Between the two answers the fleet
-- moves and the operator's own rights move: a host enrols, a role binding
-- is withdrawn, a machine leaves the site. The order then carried a set of
-- hosts nobody had approved - the operator read one number on the screen
-- and authorised another - and nothing in the record said the two had ever
-- differed.
--
-- The preview now leaves a record of what it showed: who asked, with which
-- permission, for which selector, the scopes that answered it, the hash of
-- the hosts it qualified and how many there were. The order names that
-- record. The creation resolves the fleet itself, as it always did, and
-- compares: a different principal, a different permission, a different
-- selector, changed scopes, a changed set of hosts or an expired preview
-- refuse the order with a reason and the operator previews again.
--
-- A preview is consumed by the order that used it, so one approved picture
-- of the fleet creates one campaign. The targets themselves are not stored
-- here: a snapshot of ten thousand hosts belongs to the campaign, and the
-- token needs only their fingerprint.

create table campaign_previews (
    id            uuid        primary key,
    -- The principal is the identity that previewed, not the display name:
    -- a preview is not transferable between people.
    principal_id  text        not null,
    principal     text        not null default '',
    -- The permission the preview counted by. An operation is previewed with
    -- the permission its order will ask for, so a preview taken for a
    -- service restart does not authorise a package upgrade.
    permission    text        not null,
    action        text        not null default '',
    selector_hash text        not null,
    -- The fingerprint of the scopes that answered the preview. A role
    -- binding withdrawn or granted between the preview and the order
    -- changes it, which invalidates the preview: the count the operator
    -- read was computed with rights they no longer have, or without rights
    -- they have gained.
    scope_hash    text        not null,
    -- The fingerprint of the qualified hosts, sorted by identifier.
    snapshot_hash text        not null,
    target_count  integer     not null,
    created_at    timestamptz not null default now(),
    expires_at    timestamptz not null,
    consumed_at   timestamptz,
    -- The campaign that used this preview, once there is one. A preview is
    -- consumed before the campaign exists - the order may still be refused
    -- for its own reasons - so the column is filled in afterwards and stays
    -- empty for an order that got no further.
    campaign_id   uuid
);

create index campaign_previews_expiry_idx on campaign_previews (expires_at);
create index campaign_previews_principal_idx on campaign_previews (principal_id, created_at desc);

comment on table campaign_previews is
    'What a campaign preview showed, so the order can be checked against it instead of resolving the fleet a second time and hoping it did not move.';
