package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	backupmodule "github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/modules/storage"
	"github.com/ultherego/flotestro/internal/opspec"
)

// plan runs the planning phase of a campaign.
//
// Every host computes its own plan, because two hosts picked by the same
// request almost never have the same diff. The phase ends with the digest of
// the whole set of plans: that digest enters the approval fingerprint, so the
// consent concerns those plans rather than the request alone.
//
// A plan is a read and changes nothing, so the phase has neither waves nor a
// campaign concurrency limit: the hosts compute in parallel, and the resource
// locks on the agent's side will not let a plan enter a package transaction
// that is under way anyway.
func (o *Orchestrator) plan(ctx context.Context, campaign Campaign, targets []Target) error {
	change := opspec.ActionType(campaign.ActionType)
	// A plan that comes with the order needs no host: the panel splits the
	// order and records every host's part as its plan.
	if opspec.PanelPlanned(change) {
		return o.planFromOrder(ctx, campaign, targets)
	}
	action := opspec.PlanningAction(change)
	if action == "" {
		// The campaign should never have come into being; ending it is the
		// only honest answer, because there is nothing to compute the plan
		// with, and nothing a resume could start.
		return o.failPlanning(ctx, campaign, targets,
			"the operation cannot be planned on the hosts")
	}

	var payload opspec.Payload
	if len(campaign.Payload) > 0 {
		if err := json.Unmarshal(campaign.Payload, &payload); err != nil {
			return err
		}
	}

	settled := 0
	for i := range targets {
		target := &targets[i]
		if target.State.Finished() {
			settled++
			continue
		}
		switch target.State {
		case TargetPending:
			if err := o.orderPlan(ctx, campaign, target, action,
				opspec.ActionType(campaign.ActionType), payload); err != nil {
				return err
			}
		case TargetPlanning:
			done, err := o.collectPlan(ctx, campaign, target)
			if err != nil {
				return err
			}
			if done {
				settled++
			}
		case TargetQueuedOffline:
			// A host that was offline when its plan was ordered: back to the
			// queue when it returns, closed when the deadline passes. The
			// planning phase must not wait without end either.
			returned, err := o.recheckOfflinePlanning(ctx, campaign, target)
			if err != nil {
				return err
			}
			if returned {
				if err := o.orderPlan(ctx, campaign, target, action,
					opspec.ActionType(campaign.ActionType), payload); err != nil {
					return err
				}
			}
		}
	}

	if settled < len(targets) {
		return nil
	}
	return o.finishPlanning(ctx, campaign, targets)
}

// planFromOrder runs the planning phase of a campaign whose per-host plans
// come with the order: a rename carries a mapping of host to new name, and
// the plan of a host is its own entry.
//
// No task reaches a host here, and an offline host is planned all the same:
// its name is in the order, not on the machine, and the offline policy
// takes over at execution. A host the mapping does not name ends here as
// ineligible with a reason - silence in the mapping is not consent to a
// default. Every plan is recorded with its own digest and enters the plan
// set, so the consent covers the split the operator will read, host by
// host, rather than the mapping as one blob.
func (o *Orchestrator) planFromOrder(ctx context.Context, campaign Campaign, targets []Target) error {
	mapping, err := opspec.ParseHostnameMapping(campaign.Payload)
	if err != nil {
		// The order was validated when the campaign came into being, so this
		// is a payload that changed underneath it; there is nothing to split.
		return o.failPlanning(ctx, campaign, targets,
			"the order carries no usable mapping: "+err.Error())
	}
	var shared opspec.Payload
	if len(campaign.Payload) > 0 {
		if err := json.Unmarshal(campaign.Payload, &shared); err != nil {
			return err
		}
	}

	settled := 0
	for i := range targets {
		target := &targets[i]
		if target.State.Finished() {
			settled++
			continue
		}
		switch target.State {
		case TargetPending, TargetQueuedOffline:
		default:
			continue
		}
		own, reason := mapping.PayloadFor(target.HostID, shared)
		if reason != "" {
			o.finishTarget(ctx, campaign, target, TargetIneligible, reason,
				"the order names no new hostname for this host")
			settled++
			continue
		}
		plan, err := json.Marshal(map[string]any{
			"plan": map[string]any{"hostname": own.Hostname.Hostname, "source": "order"},
		})
		if err != nil {
			return err
		}
		// The plan step is opened and closed here without a task: the strip
		// shows a plan, and the plan says where the name came from.
		if err := o.startStep(ctx, target, stepStart{
			Key: StepPlan, State: TargetPlanning,
			Note: "the name comes with the order",
		}); err != nil {
			return err
		}
		if err := o.acceptPlan(ctx, campaign, target, ContentFingerprint(plan), plan,
			"named "+own.Hostname.Hostname+" by the order"); err != nil {
			return err
		}
		settled++
	}

	if settled < len(targets) {
		return nil
	}
	return o.finishPlanning(ctx, campaign, targets)
}

// orderPlan starts the planning operation on a host.
func (o *Orchestrator) orderPlan(ctx context.Context, campaign Campaign, target *Target,
	action, change opspec.ActionType, payload opspec.Payload) error {
	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetSkipped, "host_unavailable", err.Error())
		return nil
	}
	// A disconnected host is not a planning failure. The offline policy
	// says whether the plan waits for it, and until when.
	if host.ConnectionState != "online" {
		return o.holdOffline(ctx, campaign, target, host)
	}

	// The plan task and the host's transition commit together under the
	// campaign's lock: a cancel that closed the planning phase a moment
	// earlier is seen, and no plan task is left queued for a campaign
	// that is gone.
	jobID, err := o.launch(ctx, &campaign, target,
		func(tx pgx.Tx) (string, error) {
			return o.submitJobTx(ctx, tx, campaign, host, action, planPayload(action, change, payload),
				"campaign:"+campaign.ID+":plan:"+target.HostID)
		},
		func(jobID string) stepStart {
			return stepStart{Key: StepPlan, JobID: jobID, Column: "plan_job_id", State: TargetPlanning}
		})
	var refused *createRefusal
	if errors.As(err, &refused) {
		o.finishTarget(ctx, campaign, target, TargetFailed, "plan_create_failed", err.Error())
		return nil
	}
	if err != nil {
		return err
	}
	o.log.Info("the campaign is planning a host",
		"campaign_id", campaign.ID, "host_id", target.HostID, "job_id", jobID)
	return nil
}

// recheckOfflinePlanning looks at a host that was offline when its plan was
// ordered. It returns true when the host is back and may be planned now.
func (o *Orchestrator) recheckOfflinePlanning(ctx context.Context, campaign Campaign,
	target *Target) (bool, error) {
	host, err := o.hosts.Get(ctx, target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetSkipped, "host_unavailable", err.Error())
		return false, nil
	}
	if host.ConnectionState != "online" {
		if pastDeadline(campaign, time.Now()) {
			o.finishTarget(ctx, campaign, target, TargetSkipped, "offline_deadline",
				"the host is "+host.ConnectionState+" and the campaign's deadline "+
					campaign.DeadlineAt.UTC().Format(time.RFC3339)+" has passed")
		}
		return false, nil
	}
	if err := o.store.UpdateTarget(ctx, target, TargetPending, "",
		"the host came back; its plan is ordered"); err != nil {
		return false, err
	}
	return true, nil
}

// collectPlan records the result of planning on a host. It returns true once
// the host's plan is settled - either its own or an absence that ends its
// participation.
func (o *Orchestrator) collectPlan(ctx context.Context, campaign Campaign,
	target *Target) (bool, error) {
	if target.PlanJobID == nil {
		return false, nil
	}
	job, err := o.jobs.Get(ctx, *target.PlanJobID)
	if err != nil {
		return false, err
	}
	if !jobs.State(job.State).Terminal() {
		return false, nil
	}
	if job.FinishedAt != nil {
		// The planner duration is the whole round trip: from ordering the
		// plan to having its result, queue and host included.
		metrics.PlannerDuration.Observe(job.FinishedAt.Sub(job.CreatedAt).Seconds(),
			campaign.ActionType, string(job.State))
	}
	if job.State != jobs.StateSucceeded {
		o.finishTarget(ctx, campaign, target, TargetFailed,
			orDefault(job.ResultErrorCode, "plan_failed"), job.ResultMessage)
		return true, nil
	}

	hash, plan, err := o.planFingerprint(ctx, *target.PlanJobID)
	if err != nil {
		return false, err
	}
	if hash == "" {
		// A plan without a digest is not a plan: it cannot be bound to a
		// consent.
		o.finishTarget(ctx, campaign, target, TargetFailed, "plan_hash_missing",
			"the host gave no plan digest")
		return true, nil
	}
	if reason := planRefusal(plan); reason != "" {
		// A plan that says "this change will not enter this host" is an
		// answer rather than a failure of the read. The host ends its
		// participation here, before anyone approves anything - and not
		// halfway through the fleet, when the change bounces off a host
		// during execution.
		o.finishTarget(ctx, campaign, target, TargetIneligible, "plan_refused", reason)
		return true, nil
	}
	if planNoChange(plan) {
		// A plan that found nothing to do is the host's report that it
		// already has the desired state. Nothing is approved for it and
		// nothing runs on it: a change ordered on such a host would write
		// the same file again for the sake of a step record. The plan is
		// kept all the same, so the screen of plans shows what the host
		// found, and the host ends here as a success without a mutation.
		// The plan is written first and on its own: a pass repeated after
		// a crash between the two finds the host still planning with its
		// task ended, and writes the same plan again.
		if err := o.store.SavePlan(ctx, campaign.ID, target.HostID, hash, plan); err != nil {
			return false, err
		}
		o.settleNoChange(ctx, campaign, target, hash)
		return true, nil
	}
	// The host goes back to the queue: the plan is computed, the change will
	// start once the consent is given.
	if err := o.acceptPlan(ctx, campaign, target, hash, plan, ""); err != nil {
		return false, err
	}
	return true, nil
}

// settleNoChange ends a host whose plan found nothing to do as no_change:
// the plan step succeeded with that answer, and the change step is
// recorded skipped so the strip says why the host never ran rather than
// showing a change it never reached.
func (o *Orchestrator) settleNoChange(ctx context.Context, campaign Campaign, target *Target, hash string) {
	why := "the host already has the desired state; the plan found nothing to change"
	o.finishTargetSteps(ctx, campaign, target, TargetNoChange, "", why,
		stepOutcome{Key: StepPlan, State: StepSucceeded, Reason: "plan " + shortHash(hash) + ": nothing to change"},
		stepOutcome{Key: StepExecute, State: StepSkipped, Reason: why})
}

// planNoChange reads off a plan whether it found nothing to do.
//
// Every planner says it in its own way: a file, a rule, a module or a
// clock plan names its action, and no_change - or remove_absent, the
// removal of a file that is not there - is nothing to do; a package plan
// lists its changes, and an empty list with nothing blocked is nothing to
// do. A plan of a shape the campaign does not know is taken as a change:
// a host started for nothing is a wasted step, a host settled as done
// while a change waited is a lie in the report.
func planNoChange(plan json.RawMessage) bool {
	if len(plan) == 0 {
		return false
	}
	var parsed struct {
		Kind string `json:"kind"`
		Plan struct {
			Action string `json:"action"`
		} `json:"plan"`
		Changes json.RawMessage `json:"changes"`
		Blocked json.RawMessage `json:"blocked"`
	}
	if err := json.Unmarshal(plan, &parsed); err != nil {
		return false
	}
	switch parsed.Plan.Action {
	case "no_change", "remove_absent":
		return true
	}
	if parsed.Kind == "package_plan" {
		return jsonListEmpty(parsed.Changes) && jsonListEmpty(parsed.Blocked)
	}
	return false
}

// jsonListEmpty says whether a JSON value is an absent, null or empty list.
// Anything that is not a list is not empty: unknown is not zero.
func jsonListEmpty(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return false
	}
	return len(list) == 0
}

// acceptPlan records a host's plan, closes its plan step and returns the
// host to the queue - in one transaction, because a plan on record with
// the host still planning, or a host queued without its plan, is a state
// the next pass cannot read.
func (o *Orchestrator) acceptPlan(ctx context.Context, campaign Campaign, target *Target,
	hash string, plan json.RawMessage, message string) error {
	tx, err := o.store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := o.store.SavePlanTx(ctx, tx, campaign.ID, target.HostID, hash, plan); err != nil {
		return err
	}
	revision, err := o.store.UpdateTargetTx(ctx, tx, target, TargetPending, "", message)
	if err != nil {
		return err
	}
	if _, err := o.store.FinishStep(ctx, tx, target.ID, StepPlan, StepSucceeded, "plan "+shortHash(hash)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	target.Revision = revision
	target.State = TargetPending
	target.ErrorCode = ""
	target.Message = message
	return nil
}

// planFingerprint takes the plan digest out of the result of the planning
// task.
//
// The digest can come from two places, and those are not the same thing. A
// digest computed by the host also binds the execution: a package transaction
// and a Compose deployment carry it back, and the host refuses once it stops
// matching the state it has now. A digest computed in the panel binds the
// consent only: it says the operator approved exactly the diff the host
// reported.
//
// We prefer the host's digest wherever it exists. A silent substitute on the
// panel's side would promise more than it really guards.
func (o *Orchestrator) planFingerprint(ctx context.Context, jobID string) (string, json.RawMessage, error) {
	attempts, err := o.jobs.Attempts(ctx, jobID)
	if err != nil {
		return "", nil, err
	}
	for i := len(attempts) - 1; i >= 0; i-- {
		detail := attempts[i].Detail
		if len(detail) == 0 {
			continue
		}
		if fingerprint := hostFingerprint(detail); fingerprint != "" {
			return fingerprint, detail, nil
		}
		// A plan without a digest of its own is still a plan: it is the
		// description of the diff the host has just computed. We compute the
		// digest from its content, so that the consent concerns that
		// description rather than the mere fact that a plan came into being.
		if fingerprint := ContentFingerprint(detail); fingerprint != "" {
			return fingerprint, detail, nil
		}
	}
	return "", nil, nil
}

// hostFingerprint reads the digest computed on the host.
//
// Every family names it differently, because every one computes it from
// something else: a package plan from the list of changes, a Compose plan
// from the manifest and the image digests.
func hostFingerprint(detail json.RawMessage) string {
	var parsed struct {
		PlanHash string `json:"plan_hash"`
		Kind     string `json:"kind"`
		Payload  struct {
			Digest string `json:"digest"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(detail, &parsed); err != nil {
		return ""
	}
	if parsed.PlanHash != "" {
		return parsed.PlanHash
	}
	if parsed.Kind == "compose" {
		return parsed.Payload.Digest
	}
	return ""
}

// ContentFingerprint computes the digest of a plan from its description.
func ContentFingerprint(detail json.RawMessage) string {
	if len(detail) == 0 {
		return ""
	}
	// We canonicalise by encoding again: the order of the keys in the JSON
	// from the host is not a decision and must not change the digest.
	var value any
	if err := json.Unmarshal(detail, &value); err != nil {
		return ""
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return textFingerprint([]string{string(canonical)})
}

// finishPlanning computes the digest of the set of plans and moves the
// campaign to the operator's decision.
func (o *Orchestrator) finishPlanning(ctx context.Context, campaign Campaign,
	targets []Target) error {
	// Every host settled while planning - already in the desired state,
	// refused by its plan, failed to plan - leaves nothing to approve and
	// nothing to run. The campaign ends here: completed when hosts were
	// found in the desired state, plan_failed when no host got that far.
	if allFinished(targets) {
		if tallyTargets(targets).Succeeded == 0 {
			return o.failPlanning(ctx, campaign, targets,
				"no host computed a plan of the change")
		}
		return o.complete(ctx, campaign, targets)
	}
	plans, err := o.store.Plans(ctx, campaign.ID)
	if err != nil {
		return err
	}
	if len(plans) == 0 {
		// Hosts still in the queue without a plan on record: a plan set
		// nobody can approve. The guard is for a row somebody changed by
		// hand; the engine queues no host without its plan.
		return o.failPlanning(ctx, campaign, targets,
			"no host computed a plan of the change")
	}

	set := PlanSetFingerprint(plans)
	fingerprint, err := FingerprintWithPlans(campaign, set)
	if err != nil {
		return err
	}
	next := StatePlanned
	if campaign.RequiresApproval {
		next = StateAwaitingApproval
	}
	if err := o.store.FinishPlanning(ctx, campaign.ID, set, fingerprint, next); err != nil {
		return err
	}
	o.log.Info("the campaign finished planning",
		"campaign_id", campaign.ID, "plans", len(plans), "plan_set_hash", set)
	return nil
}

// planPayload trims the payload of a change down to what the plan needs.
//
// A plan asks about the same target state but with a different operation
// type. For most families the payload is the same - the plan of a file or of
// a Compose manifest needs exactly what the change needs - and only a package
// transaction has a separate shape: an upgrade carries the digest of the
// approved plan, and the plan is what computes it.
func planPayload(action opspec.ActionType, change opspec.ActionType,
	payload opspec.Payload) opspec.Payload {
	// A device plan is given the name of its kind: the path /dev/... alone
	// does not say whether the operator is checking or extending.
	// A copy plan is given the name of its kind too: the same order serves
	// reading the repository and planning a copy.
	if change == opspec.ActionBackupRun || change == opspec.ActionBackupVerify {
		if payload.Backup != nil {
			copyPayload := *payload.Backup
			copyPayload.Plan = backupmodule.PlanRun
			if change == opspec.ActionBackupVerify {
				copyPayload.Plan = backupmodule.PlanVerify
			}
			payload.Backup = &copyPayload
		}
		return payload
	}
	if kind := devicePlanKind(change); kind != "" && payload.Storage != nil {
		storagePayload := *payload.Storage
		storagePayload.Plan = kind
		payload.Storage = &storagePayload
		return payload
	}
	if action != opspec.ActionPackagePlan {
		return payload
	}
	plan := &opspec.PackagePlanPayload{Mode: planMode(change)}
	switch {
	case payload.PackageUpgrade != nil:
		plan.OnlyPackages = payload.PackageUpgrade.Packages
		plan.SecurityOnly = payload.PackageUpgrade.SecurityOnly
	case payload.PackageChange != nil:
		plan.OnlyPackages = payload.PackageChange.Packages
	}
	return opspec.Payload{PackagePlan: plan}
}

// devicePlanKind says which device plan we are asking for.
func devicePlanKind(change opspec.ActionType) string {
	switch change {
	case opspec.ActionFilesystemCheck:
		return storage.PlanCheck
	case opspec.ActionFilesystemResize:
		return storage.PlanFSResize
	case opspec.ActionLVMExtend:
		return storage.PlanLVExtend
	}
	return ""
}

// planMode says what we are asking the package planner about.
func planMode(change opspec.ActionType) string {
	switch change {
	case opspec.ActionPackageInstall:
		return "install"
	case opspec.ActionPackageRemove:
		return "remove"
	default:
		return "upgrade"
	}
}

// withPlan adds to the payload of a change the digest of the plan computed on
// this host.
//
// Without it the campaign would send a change without a plan, and the host
// would have nothing to compare with the state it has now.
func withPlan(action opspec.ActionType, payload opspec.Payload, hash string,
	plan json.RawMessage) opspec.Payload {
	switch action {
	case opspec.ActionPackageInstall:
		install := &opspec.PackageChangePayload{PlanHash: hash}
		if payload.PackageChange != nil {
			install.Packages = payload.PackageChange.Packages
		}
		payload.PackageChange = install

	case opspec.ActionPackageUpgrade:
		upgrade := &opspec.PackageUpgradePayload{PlanHash: hash}
		if payload.PackageUpgrade != nil {
			upgrade.Packages = payload.PackageUpgrade.Packages
			upgrade.SecurityOnly = payload.PackageUpgrade.SecurityOnly
		}
		payload.PackageUpgrade = upgrade

	case opspec.ActionFileEnsure, opspec.ActionFileRemove, opspec.ActionFileRollback:
		// A file binds to its plan differently from packages: the host does
		// not compare the plan digest but the digest of the content it found.
		// That is the same mechanism that protects a single write from
		// overwriting somebody else's change - and here it gives every host
		// its own precondition.
		if fingerprint := foundContentFingerprint(plan); fingerprint != "" && payload.File != nil {
			file := *payload.File
			file.ExpectedSHA256 = fingerprint
			payload.File = &file
		}

	case opspec.ActionFirewallRuleEnsure, opspec.ActionFirewallRuleRemove,
		opspec.ActionFirewallZonePort, opspec.ActionFirewallZoneService:
		// The firewall binds by the digest of the whole ruleset the host had
		// while planning: the change is to enter the neighbourhood the
		// operator reviewed rather than another one.
		if fingerprint := rulesetFingerprint(plan); fingerprint != "" && payload.Firewall != nil {
			rule := *payload.Firewall
			rule.ExpectedHash = fingerprint
			payload.Firewall = &rule
		}

	case opspec.ActionNetworkProfileApply, opspec.ActionNetworkRouteEnsure,
		opspec.ActionNetworkMTUSet:
		// The network binds by the plan digest: the host computes the plan
		// once more before the change, and a profile changed since planning
		// stops it.
		if payload.Network != nil {
			network := *payload.Network
			network.PlanHash = hash
			payload.Network = &network
		}

	case opspec.ActionBackupRun, opspec.ActionBackupVerify:
		// A copy binds by the plan digest: a scope or a repository changed
		// since planning stops the operation.
		if payload.Backup != nil {
			backup := *payload.Backup
			backup.PlanHash = hash
			payload.Backup = &backup
		}

	case opspec.ActionCertificateTrustEnsure, opspec.ActionCertificateTrustRemove:
		// An anchor binds by the plan digest: a trust store changed since
		// planning stops the rotation step.
		if payload.Certificate != nil {
			certificate := *payload.Certificate
			certificate.PlanHash = hash
			payload.Certificate = &certificate
		}

	case opspec.ActionCertificateRenew:
		// A renewal binds by the plan digest: a different certmonger request
		// at that path since planning stops the change.
		if payload.Certificate != nil {
			certificate := *payload.Certificate
			certificate.PlanHash = hash
			payload.Certificate = &certificate
		}

	case opspec.ActionCertificateDeploy:
		// A certificate binds by the plan digest: a file at that path changed
		// since planning stops the deployment instead of overwriting somebody
		// else's material.
		if payload.Certificate != nil {
			certificate := *payload.Certificate
			certificate.PlanHash = hash
			payload.Certificate = &certificate
		}

	case opspec.ActionTimeConfigApply:
		// The time sources bind by the plan digest: the panel's file or the
		// daemon changed since planning stops the change.
		if payload.Time != nil {
			clock := *payload.Time
			clock.PlanHash = hash
			payload.Time = &clock
		}

	case opspec.ActionKernelModuleBlacklist:
		// A module blacklist binds by the plan digest: the blacklist file or
		// the module's state changed since planning stops the change.
		if payload.Kernel != nil {
			kernel := *payload.Kernel
			kernel.PlanHash = hash
			payload.Kernel = &kernel
		}

	case opspec.ActionSSHConfigApply:
		// sshd binds by the plan digest: the host computes the plan once more
		// before writing, and the server or the panel's file changed since
		// planning stops the change.
		if payload.SSH != nil {
			server := *payload.SSH
			server.PlanHash = hash
			payload.SSH = &server
		}

	case opspec.ActionDNSHostApply:
		// The resolver binds by the plan digest just like the rest of the
		// network.
		if payload.DNS != nil {
			resolver := *payload.DNS
			resolver.PlanHash = hash
			payload.DNS = &resolver
		}

	case opspec.ActionFilesystemCheck, opspec.ActionFilesystemResize, opspec.ActionLVMExtend:
		// A device binds by the plan digest: the disk, the group or the mount
		// changed since planning stops the operation.
		if payload.Storage != nil {
			storagePayload := *payload.Storage
			storagePayload.PlanHash = hash
			payload.Storage = &storagePayload
		}

	case opspec.ActionMountEnsure:
		// A mount binds by the source resolved to a UUID on this host: mount
		// by UUID finds the same filesystem or none, and never somebody
		// else's disk that got the same path after a reboot.
		if source := resolvedSource(plan); source != "" && payload.Storage != nil {
			mount := *payload.Storage
			mount.Source = source
			payload.Storage = &mount
		}

	case opspec.ActionComposeDeploy:
		// The digest of a Compose plan comes from the manifest and from the
		// image digests. A deployment without it has no basis, and one with
		// somebody else's would reach a host that never saw that plan.
		if payload.Compose != nil {
			manifest := *payload.Compose
			manifest.PlanDigest = hash
			payload.Compose = &manifest
		}

	case opspec.ActionSystemHostnameSet:
		// A rename binds to the name recorded in this host's plan: the
		// shared payload carries no name, and the one the approver read for
		// this host is the only one that may reach it. A plan without a
		// name gives the host no name at all, and the host refuses the
		// empty order rather than keeping a placeholder.
		own := opspec.HostnamePayload{Hostname: orderedHostname(plan)}
		if payload.Hostname != nil {
			own.Pretty = payload.Hostname.Pretty
		}
		payload.Hostname = &own
	}
	return payload
}

// orderedHostname takes the name the order gave this host out of its plan.
func orderedHostname(plan json.RawMessage) string {
	if len(plan) == 0 {
		return ""
	}
	var parsed struct {
		Plan struct {
			Hostname string `json:"hostname"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(plan, &parsed); err != nil {
		return ""
	}
	return parsed.Plan.Hostname
}

// foundContentFingerprint takes from the plan the digest of the file the host
// had at the moment of planning.
//
// An empty result is a valid answer here: the file may not exist, and then
// the write has nothing to expect and the host checks for itself that it is
// still not there.
func foundContentFingerprint(plan json.RawMessage) string {
	if len(plan) == 0 {
		return ""
	}
	var parsed struct {
		Plan struct {
			SHA256 string `json:"sha256"`
			Exists bool   `json:"exists"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(plan, &parsed); err != nil {
		return ""
	}
	if !parsed.Plan.Exists {
		return ""
	}
	return parsed.Plan.SHA256
}

// planRefusal reads from the plan the reason the change will not enter the
// host.
//
// Every planner may give one: a rule cutting off the management channel, a
// validator rejecting the content of a file. An empty result means a workable
// plan.
func planRefusal(plan json.RawMessage) string {
	if len(plan) == 0 {
		return ""
	}
	var parsed struct {
		Plan struct {
			Refusal         string `json:"refusal"`
			ValidatorFailed bool   `json:"validator_failed"`
			ValidatorOutput string `json:"validator_output"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(plan, &parsed); err != nil {
		return ""
	}
	if parsed.Plan.Refusal != "" {
		return parsed.Plan.Refusal
	}
	if parsed.Plan.ValidatorFailed {
		return "the validator rejected the target content: " + parsed.Plan.ValidatorOutput
	}
	return ""
}

// resolvedSource takes the UUID-resolved source out of a mount plan.
func resolvedSource(plan json.RawMessage) string {
	if len(plan) == 0 {
		return ""
	}
	var parsed struct {
		Plan struct {
			ResolvedSource string `json:"resolved_source"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(plan, &parsed); err != nil {
		return ""
	}
	return parsed.Plan.ResolvedSource
}

// rulesetFingerprint takes the digest of the host's ruleset out of a firewall
// plan.
func rulesetFingerprint(plan json.RawMessage) string {
	if len(plan) == 0 {
		return ""
	}
	var parsed struct {
		Plan struct {
			RulesetHash string `json:"ruleset_hash"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(plan, &parsed); err != nil {
		return ""
	}
	return parsed.Plan.RulesetHash
}

// PlanSetFingerprint computes the digest of the whole set of plans.
//
// The host:plan pairs are sorted, because the order they are read from the
// database in is not a decision.
func PlanSetFingerprint(plans map[string]string) string {
	pairs := make([]string, 0, len(plans))
	for host, hash := range plans {
		pairs = append(pairs, host+":"+hash)
	}
	sort.Strings(pairs)
	return textFingerprint(pairs)
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// failPlanning ends a campaign whose planning phase left no host to run
// on. Until now such a campaign stood paused with the reason, and a
// resume would have started nothing: there was no plan to start. The
// hosts still open are closed - their plan never came - and the campaign
// ends plan_failed, with its report.
func (o *Orchestrator) failPlanning(ctx context.Context, campaign Campaign,
	targets []Target, reason string) error {
	counts := tallyTargets(targets)
	why := fmt.Sprintf("%s: %d hosts cannot run the change, %d failed to plan, %d were skipped, %d never planned",
		reason, ineligibleCount(targets), counts.Failed, counts.Skipped, counts.Total-counts.Finished)
	for i := range targets {
		if targets[i].State.Finished() {
			continue
		}
		o.finishTarget(ctx, campaign, &targets[i], TargetSkipped, "plan_failed", reason)
	}
	if err := o.store.SetState(ctx, &campaign, StatePlanFailed, why); err != nil {
		return err
	}
	if o.budgets != nil {
		if err := o.budgets.ReleaseClaimant(ctx, "campaign:"+campaign.ID); err != nil {
			o.log.Error("the capacity of a campaign that failed to plan was not released",
				"campaign_id", campaign.ID, "err", err)
		}
	}
	o.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "campaign:" + campaign.ID,
		Action: "campaign.plan_failed", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: campaign.RequestID, Outcome: audit.OutcomeFailure,
		Detail: map[string]any{"reason": why, "hosts": len(targets)},
	})
	o.log.Warn("the campaign ended in planning with no host to run on",
		"campaign_id", campaign.ID, "reason", why)
	return nil
}

// ineligibleCount counts the hosts that answered the plan with a refusal
// or never qualified; they are the usual reason a planning phase leaves
// nothing to run.
func ineligibleCount(targets []Target) int {
	count := 0
	for _, target := range targets {
		if target.State == TargetIneligible || target.State == TargetExcluded {
			count++
		}
	}
	return count
}
