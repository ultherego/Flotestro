-- What the operator knows about a host before it exists.
--
-- An installation order is placed by somebody who already knows whose
-- machine it is and what it is for. Until now those facts had to be typed
-- a second time, on the host, once it appeared - and a host that appears
-- at night appears as nobody's and untagged, outside every campaign that
-- selects by tag. The order carries them and the enrollment writes them
-- onto the host in the same transaction as the row itself.
alter table enrollment_requests
    add column if not exists owner text,
    add column if not exists tags  text[] not null default '{}';
