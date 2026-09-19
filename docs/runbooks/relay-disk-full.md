# Relay buffer full and relay disk full

## Purpose

Handle a site relay that has run out of room and put it back into service. Two resources
are involved:

- The **message buffer** is the spool: append-only segments under `spool/` in the state
  directory, bounded by `buffer_max_bytes` in `relay.yaml` (1 GiB by default). It holds what
  the site's agents send while the link to the centre is down, and it survives a restart of
  `flotestro-relay` - the index is rebuilt from the segments and a record damaged at the end of
  the last one is cut off without touching the records before it.
- The **state directory** (`state_dir`, default `/var/lib/flotestro-relay`, the only writable
  path of the unit) holds that spool, the identity (`identity/current -> generations/<serial>/`
  with `agent.key`, `agent.pem`, `trust-bundle.pem`), `status.json` and the renewal throttle
  file. A full filesystem there stops certificate renewal and the spool alike: nothing is
  appended below `min_free_bytes` (256 MiB by default), whatever the class.

## Signals

- The relay's own health listener (`health_listen`, `127.0.0.1:8454` by default):
  `GET /healthz` is liveness - the process serves and its listener accepts - and stays `200`
  through an outage of the centre, because a relay whose link is down is the one process that
  must not be restarted. `GET /readyz` is readiness and answers `503` with the reason:
  `relay_upstream_unreachable`, `relay_spool_critical`, `relay_spool_unwritable`,
  `relay_certificate_expired`, `relay_certificate_unknown`. Its body also carries
  `safe_to_restart`, which is true only when nothing is waiting in the spool.

- Dashboard: "Relay buffers high" (`relays_buffer_high` in `GET /api/v1/fleet/summary`): relays
  whose last heartbeat shows the buffer at 70 % or more; absent until a relay has reported
  since the panel started. `degraded_relays`: relays silent for 10 minutes.
- `GET /metrics`: `flotestro_relay_buffer_bytes{relay}`, `flotestro_relay_buffer_max_bytes{relay}`,
  `flotestro_relay_buffer_dropped_total{relay}` (since the relay started). The panel computes
  them from the relay's heartbeats; the relay itself serves no `/metrics`.
- `GET /api/v1/relays/{id}` and the Relays page (`/relays`, `/relays/:id`): `state` (`active`,
  `silent`, `never_seen`, `revoked`), `hosts_attested`, `buffer` with `buffer_bytes`,
  `buffer_max_bytes`, `buffered_items`, `buffer_dropped`, `sessions`, `reported_at`. That is the
  last heartbeat only - what is true now, not what happened.
- **The history** - `GET /api/v1/relays/{id}/buffer-history?range=3h|24h|7d|30d|90d` and the
  "Buffer history" card on `/relays/:id`, read with the same right as the relay list
  (`host.enroll.read` over the relay's site). This is where an incident is read the morning
  after, and it answers five things the last heartbeat cannot:
  - `bytes_used` against `bytes_limit` over the window, with `bytes_used_max` per step on the
    rolled-up windows, so a spike a mean would have hidden is still there. An unknown limit is
    not zero: a relay that reported none has no fill share at all, and the card says so.
  - `item_count`: how many results were waiting.
  - `dropped_delta`: how many results were lost **between two reports**. It is empty across a
    restart, because the relay's drop counter starts again with the process; the window total on
    the card is the sum of the deltas, never the difference of the counters at the ends.
  - `disconnected` and `upstream_state` (`connected`, `buffering`, `reconnecting`): the stretches
    when the relay had nothing upstream to send to, drawn as a band across the chart. An empty
    `upstream_state` is a relay that did not say, and is not counted as connected.
  - `restarted` and `instance_id`: the relay was restarted between two points. That is the only
    thing that explains `dropped_total` falling back to zero, and it is marked on the chart.
  `latest` is the newest raw report whatever the window, and `raw_retention_hours` /
  `rollup_retention_days` say how far back the history reaches at all - a window that shows
  nothing beyond them shows nothing because nothing is kept, not because the relay was quiet.
  The raw reports come minute by minute for `3h` and `24h`; `7d`, `30d` and `90d` are read from
  quarter-hour rollups (`rollup: true`). Retention is set with
  `FLOTESTRO_RELAY_BUFFER_RETENTION_RAW` and `FLOTESTRO_RELAY_BUFFER_RETENTION_ROLLUP`.
- Built-in alert rules over the history, in `relay_buffer_alert_rules`: "Relay buffer filling"
  (over 70 % for 15 minutes, warning), "Relay buffer nearly full" (over 85 % for 5 minutes,
  warning), "Relay buffer critical" (over 95 %, critical, no holding window) and "Relay is
  dropping results" (any growth of `dropped_total` within one process, critical). A firing
  episode is on `GET /api/v1/relays/{id}/buffer-history` under `alerts` and on the card, and it
  reaches the notification channels subscribed to `alert.fired` and `alert.resolved`. A relay
  that says nothing advances no episode in either direction: silence is a matter for the relay
  state above, not for its buffer.
- On the relay: `journalctl -u flotestro-relay` logs "the state of the relay" every 30 seconds
  (`buffer_bytes`, `dropped`, `connectivity_with_the_centre`) and each drop as "the buffer of
  the relay is full, the result was dropped". `flotestro-relayctl status` prints
  `Buffer: <used> of <max>, N items[; DROPPED N results]` and exits 1 after a drop. `flotestro-relayctl diagnose [--json]` reports
  `relay_buffer_high` (over 70 %), `relay_buffer_dropping`, `relay_upstream_unreached`,
  `relay_upstream_stale`, `state_dir_low_space` (under 64 MiB free), `state_dir_unwritable`.
- Jobs on the site's hosts stay `dispatched` or `running` until their 5-minute lease is
  reclaimed (attempt status `lease_expired`): the result never reached the panel.

## Preconditions

- Shell on the relay host as root or the `flotestro-relay` user; `relay.enroll.create` and
  `relay.manage` in the panel for a re-enrollment, both under step-up authentication. The
  buffer only fills while `Centre:` in `flotestro-relayctl status` reads unreachable.

## Procedure

### What is kept and what is dropped

Every message carries a class, and the class decides what happens when the room runs out:

| Class | Priority | When the spool is full |
| --- | --- | --- |
| identity, control | 0 | keeps the reserve; new sessions are refused before an existing record is lost |
| job result, acknowledgement | 1 | keeps the reserve; `relay_spool_critical` |
| inventory, security | 2 | coalesced to the newest full revision |
| metrics | 3 | oldest dropped first, counted in `dropped_total` |
| interactive logs | 4 | the stream is cut with `resource_exhausted` |

Which class is written **ahead** of the send is a separate question from which class is kept
during an outage. While the link is up, control messages, job results and inventories go to
the disk before the socket, and metrics and log lines do not - a sample about to be
acknowledged would be written twice for nothing. While the link is down every class goes to
the disk, so a site cut off keeps its samples too, within the metric quota and oldest-dropped
first once that quota is spent.

The last `critical_reserve_bytes` of the quota (128 MiB by default) are for classes 0 and 1
alone, so a site streaming metrics cannot starve the acknowledgement of a job. A message of a
light class is refused with `resource_exhausted` and one of a durable class with
`relay_spool_critical`; both are counted and both are named in the log.

Delivery is priority first, then sequence, per host, once that host's session to the centre is
open again, and at most `max_inflight_per_host` records (64) are out at a time. **A record
leaves the spool when the panel says it consumed the message, never on a successful send**: the
panel names the record in its acknowledgement - by the sequence of the agent's signed envelope,
or by the identifier the relay gave it for an agent that signs none - and a record nobody
acknowledges within `ack_timeout` (30 s) is sent again. A panel of a release older than 0.58.0
cannot name a record that has no sequence; the relay waits four delivery attempts for it and
then lets the record go on its delivery alone, saying so in the log ("the centre does not
acknowledge a message by its record identifier").

Agents keep no spool of their own: what the relay drops is gone. The panel returns the job to
`queued` when its lease expires and dispatches it again once the host is back; the agent
answers from its idempotency journal (24 hours), so a dropped result is usually recovered. A
job whose time to live passes first ends `expired`; a campaign target ends `unknown` with the
code `lease_expired`.

### Buffer full (link to the centre down)

1. Confirm: `sudo -u flotestro-relay flotestro-relayctl status` (`Centre:`, `Buffer:`), then
   `flotestro-relayctl diagnose` for the `dns.*`, `tls.*` and `upstream` checks of `upstream.gateway_urls`.
2. Restore the link. Restarting the relay frees nothing - the spool is on disk and comes back
   with the process - and it costs the site every open session, so restart only for a reason of
   its own.
3. Once `Centre:` shows a last contact, watch `buffer_bytes` fall and `buffered_items` reach 0
   on `GET /api/v1/relays/{id}`; a host's buffered messages go out with its new session. The
   history over the same window says how long the site was cut off and whether anything was lost
   while it was: `GET /api/v1/relays/{id}/buffer-history?range=24h`, or the card on `/relays/:id`.
4. Read what the outage cost: `GET /api/v1/jobs?state=expired&since=<start>` and, per campaign,
   targets in `unknown` with `error_code` `lease_expired` (`GET /api/v1/campaigns/{id}/targets`);
   follow the guide before repeating a destructive step.
5. If drops occurred, raise `buffer_max_bytes` (bytes, at most `4294967296`; `0` buffers nothing)
   in `/etc/flotestro/relay.yaml`, check with `flotestro-relay config validate` and
   `flotestro-relay config show`, then `systemctl restart flotestro-relay` while the buffer is
   empty. The unit runs under `MemoryHigh=512M` and `MemoryMax=768M`; a larger buffer needs the
   unit changed too.

### State directory full

1. `df /var/lib/flotestro-relay`; `flotestro-relayctl diagnose` reports `state_dir_low_space` or
   `state_dir_unwritable`. The relay writes nothing large there; something else took the space.
2. Free the filesystem without touching `identity/` (`generations/` keeps two entries by itself).
3. `flotestro-relayctl renew` if the certificate has under a day left (`identity_expiring`); once
   per 10 minutes, and the running relay switches only at `systemctl restart flotestro-relay`.

### Re-enrollment (identity lost or compromised)

1. In the panel revoke the relay: `POST /api/v1/relays/{id}/revoke` with `{"reason": "..."}`.
   Every host session it attested ends with `relay.revoke`; the agents reconnect through the
   next address in their `gateway_urls`.
2. Order a token: `POST /api/v1/enrollment-requests` with `"kind": "relay"` and the site; the
   token appears once in the response.
3. On the relay host, with the token in a file readable by the service user:
   `sudo -u flotestro-relay flotestro-relayctl enroll --token-file /run/relay-token`, then
   `systemctl start flotestro-relay`. `enroll` refuses while a valid identity exists
   (`machine_already_enrolled`); the revocation in step 1 is what makes the old one invalid on the
   panel side, and a lost state directory passes the local check by itself. The relay `name`
   in `relay.yaml` is the natural key: the same name refreshes the existing record and clears
   its revocation instead of creating a second relay.
4. Upgrade order for the host identity envelope (`relay.identity` v2): the panel first, the relay
   second, the agents last - a panel that does not know the envelope refuses a signing agent
   as `relay_body_hash_mismatch`, and a relay from before v2 forwards neither the challenge nor the
   certificate the gateway takes an older host key from. Set `FLOTESTRO_RELAY_IDENTITY=enforce`
   only once `flotestro_relay_session_identity_total{strength="weak"}` stops growing and no open
   session on `agent_sessions` carries `auth_strength = 'relay_only'`; after that a relayed host
   that still does not sign shows `blocked_upgrade_required` and needs its agent upgraded.

## Verification

- `GET /api/v1/relays/{id}`: `state: "active"`, `buffer_dropped: 0` after the restart,
  `hosts_attested` back to the site's count; "Relay buffers high" no longer counts the relay.
- `GET /api/v1/relays/{id}/buffer-history?range=24h`: the newest points have `disconnected: false`,
  `dropped_delta: 0` and a falling `bytes_used`, and `alerts` is empty. A restart shows as
  `restarted: true` with the drop counter starting again - the history keeps what the earlier
  process lost, which the counter itself no longer does. The spool is not emptied by the
  restart, so `bytes_used` carries on from where it stood.
- `flotestro-relayctl status` exits 0; `flotestro-relayctl diagnose` shows no `fail`.
- The site's hosts show sessions on their host pages; new jobs to them complete.

## Rollback/Recovery

- `flotestro-relay config validate` before a restart avoids a relay that will not start on a
  bad `relay.yaml`.
- A wrong re-enrollment: revoke and enroll again; there is no delete route, and a revoked
  relay stays listed as `revoked`.
- Hosts whose results were dropped: the panel re-dispatches and the agent replays from its
  journal; an attempt closed after the replay carries `superseded_by_result`.

## Related codes

The error guide has no relay entries; a relay incident shows on jobs as `lease_expired`,
`superseded_by_result` (reconcile) and `expired` (dispatch). Relay-side codes come from
`flotestro-relayctl diagnose` (`relay_buffer_high`, `relay_buffer_dropping`,
`relay_upstream_unreached`, `relay_upstream_stale`, `state_dir_low_space`, `state_dir_unwritable`,
`identity_missing`, `identity_expired`, `identity_expiring`, `listener_unavailable`) and the
configuration loader (`relay_config_buffer_out_of_range`, `relay_config_state_dir_invalid`,
`relay_config_gateway_missing`, `relay_config_health_listen_invalid`). The spool refuses a
message of a light class with `resource_exhausted` and one of a durable class with
`relay_spool_critical`. The health answers of
the relay carry their own codes, and those are in the guide: `relay_listener_unavailable`,
`relay_upstream_unreachable`, `relay_spool_critical`, `relay_spool_unwritable`,
`relay_certificate_expired`, `relay_certificate_unknown`.
