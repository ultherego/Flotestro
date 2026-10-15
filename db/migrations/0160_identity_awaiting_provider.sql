-- An identity can be written down before its person has ever signed in.
--
-- An administrator looking at "who may sign in" sees the directory's people,
-- and some of them the panel has never met: the record is made at the first
-- sign-in. Granting one of them a role of their own means creating that
-- record early - and the record would have been the wrong one. An identity
-- arriving from the provider deliberately never takes over a principal that
-- exists under the same subject with another origin (internal/authz/
-- sessions.go says so in as many words), so the person would have signed in,
-- been given a second record named subject@provider-host, and the role
-- granted in advance would have sat on a record nobody used: a button that
-- looks like it worked.
--
-- So a record made in advance says what it is. awaiting_issuer holds the
-- issuer this identity expects, and the first sign-in from exactly that
-- issuer adopts the record instead of making another. Nothing else adopts
-- it - a local identity, a service principal and an ordinary record are
-- untouched - which is the rule that comment was protecting.
alter table principals
    add column if not exists awaiting_issuer text;

comment on column principals.awaiting_issuer is
    'The issuer whose first sign-in may adopt this record, for an identity written down before its person ever arrived. Null for every record made the ordinary way.';

-- Two records waiting for the same person under the same issuer would be two
-- answers to the question the adoption asks.
create unique index if not exists principals_awaiting_idx
    on principals (awaiting_issuer, lower(subject))
    where awaiting_issuer is not null;
