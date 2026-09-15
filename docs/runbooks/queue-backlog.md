# Queue backlog

## Purpose

Tell apart the four reasons a queued task does not start (a saturated budget, the dispatch
rate, a resource lock on the host, an offline host) and relieve the one that applies. A
campaign stop never interrupts a host; the remedies here change what starts next.

## Signals

On `GET /metrics` (permission `metrics.read`):

- `flotestro_budget_tokens{budget,status}` with `status` in `capacity`, `used`, `waiting`.
- `flotestro_jobs_awaiting_budget{budget}`: single-host jobs in `queued` with
  `wait_reason` `awaiting_budget:<key>`; campaign hosts show instead as
  `flotestro_campaign_targets{state="awaiting_budget",reason_code}`.
- `flotestro_budget_wait_seconds_max{budget,class}`: the longest current wait.
- `flotestro_dispatch_throttled_total{gateway}`: candidates a scheduler pass left in the queue
  because the rate bucket was empty.
- `flotestro_job_queue_age_seconds` (oldest `queued` job), `flotestro_jobs{state}`,
  `flotestro_campaign_targets{state,reason_code}` for `awaiting_lock`, `queued_offline`,
  `dispatched`; `flotestro_resource_lock_wait_seconds{action}` for lock waits the agents reported.

In the API and the panel:

- `GET /api/v1/jobs/{id}`: `wait_reason` is `awaiting_budget:<key>` or `awaiting_lock:<blocker>`
  (the agent's text: the resource and the task holding it). `GET /api/v1/jobs` filters by
  `state`, `host_id`, `action`, `campaign_id`, `error_code`, `since`, `until`; it has no
  `wait_reason` filter, so list `state=queued` and read the field.
- `GET /api/v1/budgets` (permission `budget.read`) and the Budgets page (`/budgets`): per key
  `capacity`, `used`, `claimants`, `waiting_jobs`, `waiting_targets`, `holders` (owner, claimant,
  class, tokens, since) and `by_class`.
- `GET /api/v1/campaigns/{id}/targets`: targets in `awaiting_budget`, `awaiting_lock`,
  `queued_offline`, with `reason_code` (`budget_capacity`, `budget_fair_share`, `offline`).
- The dashboard has no queue counter; use the Budgets page and the metrics above.

## Preconditions

- `budget.read` to see, `budget.write` in the site's scope (`site:<name>:<family>` keys) or the
  global scope (every other key) to change; `campaign.control` to pause, resume or cancel;
  `job.cancel` on the host for a single job.
- Know the gateway's `FLOTESTRO_DISPATCH_RATE` (envelopes per second per gateway process,
  default `100`; `0` sends every leased task at once and logs a warning at start).

## Procedure

1. Name the wait. For a job: `GET /api/v1/jobs/{id}` and read `wait_reason` and `state`. For a
   campaign: `GET /api/v1/campaigns/{id}/targets` and count the states. For the fleet: the
   three gauges above. Then follow the matching branch.
2. Budget saturated (`awaiting_budget:<key>`, `budget_capacity`, `budget_fair_share`):
   1. `GET /api/v1/budgets` shows who holds the tokens. Budget keys are `global:mutations`,
      `global:reads`, `site:<site>:<family>`, `domain:<failure-domain>:<family>`,
      `gateway:<gateway>:<family>`, `backend:<repository>:backup`; a key nobody configured is
      not enforced, and a pattern `<kind>:*:<family>` applies to every key of that shape.
   2. Tokens are leases of 2 minutes renewed by the work that holds them; a task whose lease
      expired hands them back through `ReclaimExpiredLeases` every 30 seconds. A campaign that
      does nothing anymore holds none: `cancel` returns them at once (`canceled`) or when the
      last host settles (`canceling`).
   3. To raise a budget, read it first: `GET /api/v1/budgets/{key}` returns an `ETag`
      (`404 budget_not_found` for a key nobody configured; then write without `If-Match`). Then
      `PUT /api/v1/budgets/{key}` with header `If-Match: <etag>` and body
      `{"capacity": <n>, "note": "<why>"}`. A stale tag is refused with `412 precondition_failed`
      and the current tag; read again and repeat. `capacity` below 1 is refused with
      `400 invalid_request` ("to stop work, pause the campaign").
   4. `budget_fair_share` needs no action: the claimant is promoted by age (`interactive` 15s,
      `maintenance` 2m, `background` 5m; `incident` at once).
3. Dispatch rate (`flotestro_dispatch_throttled_total` climbing, tasks `queued` with an empty
   `wait_reason`, hosts connected): each scheduler pass admits at most the tokens in a bucket
   of `FLOTESTRO_DISPATCH_RATE` per second (burst one second's worth), oldest first. Raise the
   value in `/etc/flotestro/control-plane.env` and `systemctl restart flotestro-control-plane`;
   there is no runtime setting.
4. Lock wait (`awaiting_lock:<blocker>`, target `awaiting_lock`): the agent waits on its host
   for the resource another task holds (one lock class per operation). There is no lock-wait
   setting; the task waits until its own time limit (`job_timeout_seconds` of the campaign) and
   then ends with `resource_busy`. Let the blocker finish. `POST /api/v1/jobs/{id}/cancel`
   (`{"reason": "..."}`) marks a job `canceled` in any non-final state, but no message
   interrupts a task already on the host; a result that arrives after the cancellation is
   kept for diagnostics and not applied.
5. Offline hosts (target `queued_offline`, `reason_code` `offline`): under
   `wait_until_deadline` or `replan_on_reconnect` the host starts by itself when it reconnects
   before `deadline_minutes` (default one day), then ends as `offline_deadline`. Under
   `require_online` or `skip_if_offline` it was already skipped (`offline`, `skipped_offline`).
   Bring the host back (`flotestro-agentctl diagnose` on it) or order again later.
6. To stop a campaign from taking more capacity: `POST /api/v1/campaigns/{id}/pause` with
   `{"reason": "..."}` (allowed from `planned`, `canary`, `manual_gate`, `running`; otherwise
   `409 invalid_state`). Its hosts under way finish; paused hosts stay `awaiting_budget` but ask
   for nothing. `POST /api/v1/campaigns/{id}/resume` puts it back to `planned`, from where the
   orchestrator continues.
7. To end it: `POST /api/v1/campaigns/{id}/cancel`. Targets in `pending`, `awaiting_budget`,
   `queued_offline`, `planning` become `canceled` at once. Targets in `dispatched`,
   `awaiting_lock`, `running`, `rebooting`, `verifying` are left to finish; the campaign is
   `canceling` until the last of them settles, then `canceled`, and its tokens are released.
   A cancel does not pretend to be a rollback.

## Verification

- `flotestro_jobs_awaiting_budget` and `flotestro_budget_tokens{status="waiting"}` fall;
  `flotestro_budget_wait_seconds_max` stops growing.
- `flotestro_job_queue_age_seconds` falls; `flotestro_dispatch_throttled_total` stops climbing.
- The campaign's targets move from `awaiting_budget`/`awaiting_lock` to `dispatched` and
  `running` (`GET /api/v1/campaigns/{id}/targets`, `GET /api/v1/campaigns/{id}/report`).
- The audit shows the change: actions `campaign.pause`, `campaign.resume`, `campaign.cancel`
  and `budget.write` under `GET /api/v1/audit?action=<name>`.

## Rollback/Recovery

- A raised budget is lowered the same way (`PUT` with the current `ETag`); running holders keep
  their tokens until their leases end, so the new capacity applies gradually.
- A paused campaign resumes with `resume`; a cancelled one cannot; order it again. Hosts that
  finished under `canceling` are not undone.
- A lowered `FLOTESTRO_DISPATCH_RATE` takes effect at the next restart.

## Related codes

`budget_capacity`, `budget_fair_share` (admission, automatic retry); `resource_busy`,
`precondition_changed` (agent); `conflict` (preflight, automatic); `offline`, `skipped_offline`,
`offline_deadline`, `maintenance`, `host_unavailable`, `expired`, `lease_expired`, `canceled`
(dispatch/reconcile); `offline_policy_loosened`, `plan_changed_offline` (planning). Outside the
guide: `precondition_failed` (412, If-Match), `invalid_state` (409, campaign control),
`invalid_request` (400, budget body), `budgets_disabled` (501).
