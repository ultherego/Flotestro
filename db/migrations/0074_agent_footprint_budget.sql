-- The footprint budget follows the architecture document: 30 MiB of
-- resident memory and 0.2 % of a core for the agent. The release gate
-- asserts those numbers; the default rules fire at roughly twice them,
-- so a package transaction or an inventory run does not alarm while a
-- leak does. Only the rules seeded with the old defaults are moved -
-- an installation that set its own thresholds keeps them.
update alert_rules set threshold = 67108864::double precision
where metric = 'agent_rss_bytes' and created_by = 'system'
  and threshold = 268435456::double precision;

update alert_rules set threshold = 2::double precision
where metric = 'agent_cpu_percent' and created_by = 'system'
  and threshold = 25::double precision;
