-- Free-form notes on a host.
--
-- The owner, the tags and the placement are facts with a shape the panel
-- keys on; the notes are what does not fit any of them - the ticket that
-- brought the machine, the quirk of its RAID controller, the person to
-- call before rebooting it. They are the panel's knowledge about the
-- host, like the owner, so they are written under the same permission,
-- and every write goes to the audit trail with both texts: a note
-- silently rewritten is a warning nobody read. Empty for a host nobody
-- has written about.
alter table hosts
    add column if not exists notes text not null default '';

comment on column hosts.notes is
    'Free-form notes an operator keeps about the host; empty when nobody wrote any.';
