-- The management address of a host.
--
-- A host may have many addresses, connect from behind NAT or through a site
-- relay. The first address of the interface list is not the management
-- address and must not be presented as one - an operator confirming an
-- operation must see the address that really describes this host.
--
-- The source is part of the fact, because two addresses of different origin
-- mean different things: 'session' is what the panel sees at its end of the
-- connection, 'agent' is what the host declares (the only way with a relay in
-- between), 'manual' is set by the operator. A missing address stays empty.
alter table hosts
    add column management_address             text,
    add column management_address_source      text,
    add column management_address_observed_at timestamptz;

alter table hosts add constraint hosts_management_address_source_check
    check (management_address_source is null
           or management_address_source in ('session', 'agent', 'manual'));

-- An address without a source and a source without an address are an incomplete record.
alter table hosts add constraint hosts_management_address_complete_check
    check ((management_address is null and management_address_source is null)
           or (management_address is not null and management_address_source is not null));
