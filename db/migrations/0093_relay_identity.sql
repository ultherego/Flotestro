-- How the newest session of a host was identified when it came through a
-- relay. A relay that names the certificate of the host lets the gateway
-- check that certificate as it would in a direct handshake ("attested");
-- a relay from before that attestation names the host alone, and the
-- gateway takes its word ("weak"). The operator is to see the second kind
-- on the host, because it is the relay's word rather than the host's key
-- that opened the session. Null is a direct connection.
alter table hosts add column relay_identity text
    check (relay_identity in ('attested', 'weak'));
