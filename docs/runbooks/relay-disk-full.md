# Relay buffer full and relay disk full

## Purpose

Handle a site relay that has run out of room and put it back into service. Two resources
are involved:

- The **message buffer** holds what the site's agents send while the link to the centre is
  down. It lives in the relay's memory, bounded by `buffer_max_bytes` in `relay.yaml`; nothing
  of it is written to disk, and a restart of `flotestro-relay` empties it.
- The **state directory** (`state_dir`, default `/var/lib/flotestro-relay`, the only writable
  path of the unit) holds the identity (`identity/current -> generations/<serial>/` with
  `agent.key`, `agent.pem`, `trust-bundle.pem`), `status.json` and the renewal throttle file.
  A full filesystem there breaks certificate renewal, not the buffer.

## Signals

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

A new message is refused once `bytes + len(payload) > buffer_max_bytes`; the older ones stay,
because an old result usually belongs to a finished job and is closest to delivery. Every kind
of agent message is treated alike (results, progress, log lines, inventory, metrics samples,
heartbeats); there is no priority by kind. Delivery is oldest first, per host, once that host's
session to the centre is open again, and a message leaves the buffer only after a confirmed
send. Agents keep no spool of their own: what the relay drops is gone. The panel returns the
job to `queued` when its lease expires and dispatches it again once the host is back; the
agent answers from its idempotency journal (24 hours), so a dropped result is usually
recovered. A job whose time to live passes first ends `expired`; a campaign target ends
`unknown` with the code `lease_expired`.

### Buffer full (link to the centre down)

1. Confirm: `sudo -u flotestro-relay flotestro-relayctl status` (`Centre:`, `Buffer:`), then
   `flotestro-relayctl diagnose` for the `dns.*`, `tls.*` and `upstream` checks of `upstream.gateway_urls`.
2. Restore the link. Do not restart the relay to "free" the buffer: the restart discards it.
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
  `dropped_delta: 0` and a falling `bytes_used`, and `alerts` is empty. A restart to free the
  spool shows as `restarted: true` with the drop counter starting again - the history keeps what
  the earlier process lost, which the counter itself no longer does.
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
`relay_config_gateway_missing`).
