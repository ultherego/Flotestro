-- A host's trail is more than the events aimed at the host: the events of
-- its jobs name the host in their detail, and the host's audit tab reads
-- them by that name. The expression index keeps that read off a scan.
create index if not exists audit_events_detail_host_idx
    on audit_events ((detail->>'host_id'), occurred_at desc, id desc)
    where detail ? 'host_id';
