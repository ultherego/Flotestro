-- The failure domain of a host and the topology budgets.
--
-- A site says where a host stands; a failure domain says what it goes down
-- with, or what must not go down with it: a rack, an availability zone, a
-- cluster whose members keep a service alive. The campaigns document (ch.
-- 13, appendix A-06) keys a budget on it - one unavailable member of a
-- cluster at a time - and the architecture document names the gateway next
-- to it: the pipe the changes of its hosts go through. The domain is free
-- text an operator records, the way the owner is; null means nobody placed
-- the host, and a host nobody placed loads no domain budget rather than a
-- budget shared by the unplaced.
alter table hosts
    add column if not exists failure_domain text;

comment on column hosts.failure_domain is
    'What the host goes down with: a rack, a zone, a cluster. Null when nobody placed it; keyed on by the domain:* budgets.';

-- The starting values. The patterns apply to every domain and every gateway
-- nobody described separately; an installation may override them with an
-- exact row, the way it does for a site.
--
-- The failure domain follows the document: one unavailable member at a
-- time, for the families that take a member off - a reboot, a unit
-- restart, a network or a storage change. A package transaction and a
-- backup leave the member serving, so those get the room of a site.
--
-- The gateway follows the document's "20 tasks" per gateway, taken per
-- family: the document names one number for the gateway as a whole and the
-- keys are per family, so each family gets it - a gateway on a thin link
-- is described separately with an exact row.
insert into budget_limits (key, capacity, note) values
    ('domain:*:reboot',   1,  'reboots in one failure domain'),
    ('domain:*:units',    1,  'unit changes in one failure domain'),
    ('domain:*:network',  1,  'network changes in one failure domain'),
    ('domain:*:storage',  1,  'storage changes in one failure domain'),
    ('domain:*:packages', 5,  'package transactions in one failure domain'),
    ('domain:*:backup',   2,  'backup operations in one failure domain'),
    ('gateway:*:packages', 20, 'package transactions through one gateway'),
    ('gateway:*:reboot',   20, 'reboots through one gateway'),
    ('gateway:*:network',  20, 'network changes through one gateway'),
    ('gateway:*:storage',  20, 'storage changes through one gateway'),
    ('gateway:*:backup',   20, 'backup operations through one gateway'),
    ('gateway:*:units',    20, 'unit changes through one gateway')
on conflict (key) do nothing;
