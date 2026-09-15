-- When a host was last moved between sites or environments.
--
-- The site and the environment come with the host at enrollment and stay
-- there for years - until an operator corrects a wrong token, or a
-- machine is physically carried to another site. The move is not a fact
-- like the owner: the site keys the site:* budgets, the scope of every
-- role binding and the site leaf of the group selectors, and the
-- environment decides whether a change needs a second person. Nothing
-- re-evaluates on its own after a move, so the moment of the move is kept
-- on the host: the host page shows it next to the placement, and a reader
-- of the trail can tell a host that stood in a site all along from one
-- that arrived yesterday. Null for a host never moved.
alter table hosts
    add column if not exists placement_changed_at timestamptz;

comment on column hosts.placement_changed_at is
    'When an operator last changed the site or the environment of the host. Null when the host stands where it enrolled.';
