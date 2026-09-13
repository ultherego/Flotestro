-- Restricting an enrollment order to one relay.
--
-- In an isolated site the host does not see the centre and enrolls through
-- a relay. The relay is then the TLS terminator, so it sees the token - and it
-- attests to the centre that the request came from its site.
--
-- Without this restriction a token carried out of one site would work in any
-- other. A set relay_id means: this order may be fulfilled only through this
-- relay. Empty means "no route restriction" and stays so for installations
-- without relays.
alter table enrollment_requests add column relay_id uuid references relays (id);

create index enrollment_requests_relay_idx on enrollment_requests (relay_id)
    where relay_id is not null;
