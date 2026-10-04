-- The explicit link between a panel identity and a directory account.
--
-- Group membership that authorizes background work is read from the directory
-- itself, and an identity's own issuer is the only system that answers for it.
-- A FreeIPA account is not the same account as a Keycloak user with a similar
-- name, and the groups of the two systems are not equivalent: a mapping of one
-- issuer must never be satisfied with the groups of the other. So a principal
-- is asked at FreeIPA only where somebody wrote down which account it is.
--
-- Null means "no link": such a principal gets no FreeIPA groups at all, which
-- is the narrow side. A guess from the subject would have been the wide one.
alter table principals
    add column if not exists directory_uid text;

comment on column principals.directory_uid is
    'The directory account (FreeIPA uid) this identity is explicitly linked to. Null means the directory is not asked about this identity.';
