-- The network names of a relay are part of its identity, not of the request body.
--
-- The relay certificate is the only fleet certificate with a server role: the
-- site agents verify against it the name they connected to. If the names came
-- from the renewal request, the relay could at every renewal take the name of
-- somebody else's service and become for the agents something other than it was.
--
-- The record in the registry makes a name change an operator decision: the
-- renewal issues what the panel has recorded, and nothing beyond that.
alter table relays add column advertised_names text[] not null default '{}';

-- The last renewal says whether the relay keeps up its identity at all.
-- A relay certificate lives seven days; a relay that has not renewed for a
-- week is one step from cutting off the whole site.
alter table relays add column renewed_at timestamptz;
