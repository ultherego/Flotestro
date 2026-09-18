# A host stops sending samples, or its charts have a hole

## Purpose

Tell apart the five reasons a host's resource chart stops or shows a gap - the host is
away, the agent cannot spool, the panel refuses the samples as too late, the rollup has
stopped, or the alert evaluator is not running anywhere - and relieve the one that
applies. The panel is the only alerting channel of this product: a host whose samples stop
arriving is a host whose alert rules cannot fire, so a gap is never only a cosmetic
problem with a chart.

## What the machinery does, in one paragraph

The agent reads the kernel counters once a minute, gives the reading an identity (the boot
it runs on and a sequence within that boot), writes it to a small spool under its state
directory, and only then sends it. The panel stores it, marks its quarter-hour as owing a
recomputation, and answers the agent after the transaction committed. The agent deletes
its copy on that answer and on no other event; on reconnect it sends what was never
answered, oldest first. The raw readings live in one table partition per day and the
retention drops whole partitions. The rollup recomputes exactly the quarters that are
marked, and keeps a progress mark per host so that one host's progress never speaks for
another's. One control-plane instance at a time evaluates the alert rules, under a lease.

## Signals

On `GET /api/v1/status` (permission `settings.read`), block `monitoring`:

- `raw_partitioned`: false means the raw samples are still one table and the retention is
  deleting rows. The migration has not run.
- `raw_partitions`, `oldest_raw_day`, `newest_raw_day`: there must be at least one day
  ahead of today. None means tomorrow's samples have nowhere to go.
- `dirty_buckets` and `oldest_dirty_bucket_at`: quarters waiting to be recomputed. The
  number rises between rollups and comes back down. One that only rises is a rollup that
  has stopped, and the long charts are standing still while the short ones look healthy.
  It also explains a database that stops shrinking: a partition that still owes a
  recomputation is kept past its retention.
- `evaluator_holder` and `evaluator_lease_until`: who is judging the rules. Empty on every
  instance, for longer than the lease term, means nobody is.
- `raw_retention`, `max_lateness`, `raw_query_window`: the settings the rest has to be read
  against.

In the API and the panel:

- `GET /api/v1/hosts/{id}/metrics`: `last_sample_at` and the points. A host with no sample
  for more than three minutes counts as silent on the fleet view.
- `GET /api/v1/fleet/monitoring`: `hosts_reporting` against `hosts_silent`.
- `GET /api/v1/errors`: `metric_sample_too_old`, `metric_sample_not_kept`,
  `alert_evaluator_lease_lost`, `metrics_retention_too_short`.

On the host, in the agent's journal (`journalctl -u flotestro-agent`):

- `the resource samples the panel has not confirmed are sent again` with a count: the
  agent had a backlog and is draining it. Normal after a reconnect.
- `the resource sample was not kept for a resend`: the spool cannot be written. The host's
  disk or the permissions of the state directory.
- `the resource samples are not kept for a resend; a broken session loses them`: the spool
  could not be opened at all at start. The agent still reports; it just cannot survive a
  broken session.
- `the oldest sample left the spool because it is full`: the panel has been unreachable for
  longer than four hours. The gap this leaves is the outage.

In the panel's journal:

- `a resource sample reached the panel too late to be stored` with the age: see below.
- `a partition of the raw samples is past the retention but still owes a rollup; it is kept`.
- `the samples were not rolled up` / `the partitions of the raw samples were not prepared`.

## Procedure

1. **Is the host connected at all?** `GET /api/v1/hosts/{id}` - `connection_state` and
   `last_heartbeat_at`. A host that sends no heartbeat sends no samples either, and this is
   not a monitoring problem: go to the quarantine and decommission runbook, or to the relay
   runbook if the host is behind one.

2. **The host is connected and the chart still stops.** Read the agent's journal on the
   host for the lines above. A spool that cannot be written is a full disk or a state
   directory the agent may not write to; fix that and the next sample is kept again. The
   readings from the time it could not write are gone - they were never on disk anywhere.

3. **The chart has a hole that ends at the moment the link came back.** Look in the panel's
   journal for `a resource sample reached the panel too late to be stored`. The age in that
   line is how far the delivery was behind, and it was longer than
   `FLOTESTRO_METRICS_MAX_LATENESS`. This is the outage, not a fault: the panel refused to
   draw readings into a window its retention drops in the same pass, and the host has
   dropped its copies. If such an outage has to be recoverable in future, raise
   `FLOTESTRO_METRICS_MAX_LATENESS` **and** `FLOTESTRO_METRICS_RETENTION_RAW` together -
   the panel refuses to start on a retention shorter than the query window plus the
   lateness - and remember that the agent's own spool holds four hours whatever the panel
   allows.

4. **The short charts are fine and the long ones stand still.** `dirty_buckets` is rising.
   The rollup runs every fifteen minutes inside the control plane; a run that fails logs
   `the samples were not rolled up`. The usual cause is a database that cannot take the
   write - check the `database` block of the status for the connection count and the oldest
   open transaction. Nothing is lost while this lasts: the marks are the queue, the raw
   readings are still there, and the retention will not drop a partition that owes one.
   Once the rollup runs again it recomputes exactly the marked quarters, including the ones
   from days ago.

5. **No alerts are firing anywhere although a rule clearly holds.** `evaluator_holder` is
   empty on every instance. Either every instance is failing to take the lease - look for
   database errors - or an instance took it and died without giving it back, in which case
   it frees itself within `FLOTESTRO_METRICS_EVALUATOR_LEASE` (45 seconds by default) and
   the next pass takes it. A stream of `alert_evaluator_lease_lost` from one instance means
   that instance cannot renew in time: look at the database latency and at its clock.

6. **`raw_partitioned` is false.** The migration that converts the raw samples has not run
   on this database. Check the `migrations` block of the status; the panel applies them at
   start, so this is a panel that did not finish starting or a database it could not
   migrate. Until it runs the retention deletes rows, which works but is the behaviour the
   partitions replaced.

## Verification

- The host's chart has points at the sampling interval again:
  `GET /api/v1/hosts/{id}/metrics?range=3h`.
- `dirty_buckets` comes back down within two rollup intervals.
- `hosts_silent` on `GET /api/v1/fleet/monitoring` no longer counts the host.
- On the host, the agent's journal stops logging a backlog to resend.

## What this runbook does not do

There is no request that makes the panel accept a sample it refused as too old, and none
that makes a host produce a reading for a moment that has passed: a counter cannot be read
backwards. The gap stays, with its reason. There is also no way to order a rollup by hand;
it runs every fifteen minutes and recomputes what is marked.

## Codes

`metric_sample_too_old`, `metric_sample_not_kept`, `alert_evaluator_lease_lost`,
`metrics_retention_too_short`.
