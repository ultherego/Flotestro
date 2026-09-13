package campaigns

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/ultherego/flotestro/internal/jobs"
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
	action := opspec.PlanningAction(opspec.ActionType(campaign.ActionType))
	if action == "" {
		// The campaign should never have come into being; stopping is the
		// only honest answer, because there is nothing to compute the plan
		// with.
		return o.pauseOnThreshold(ctx, campaign,
			"the operation cannot be planned on the hosts", 0, 0)
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
		}
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
	// A disconnected host is not a planning failure: the plan waits for it to come back.
	if host.ConnectionState != "online" {
		return nil
	}

	jobID, err := o.submitJob(ctx, campaign, host, action, planPayload(action, change, payload),
		"campaign:"+campaign.ID+":plan:"+target.HostID)
	if err != nil {
		o.finishTarget(ctx, campaign, target, TargetFailed, "plan_create_failed", err.Error())
		return nil
	}
	if err := o.store.AttachJob(ctx, target.ID, "plan_job_id", jobID); err != nil {
		return err
	}
	if err := o.store.UpdateTarget(ctx, target.ID, TargetPlanning, "", ""); err != nil {
		return err
	}
	target.State = TargetPlanning
	target.PlanJobID = &jobID
	o.log.Info("the campaign is planning a host",
		"campaign_id", campaign.ID, "host_id", target.HostID, "job_id", jobID)
	return nil
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
	if err := o.store.SavePlan(ctx, campaign.ID, target.HostID, hash, plan); err != nil {
		return false, err
	}
	// The host goes back to the queue: the plan is computed, the change will
	// start once the consent is given.
	if err := o.store.UpdateTarget(ctx, target.ID, TargetPending, "", ""); err != nil {
		return false, err
	}
	target.State = TargetPending
	return true, nil
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
	plans, err := o.store.Plans(ctx, campaign.ID)
	if err != nil {
		return err
	}
	if len(plans) == 0 {
		// No host computed a plan: there is nothing to approve.
		return o.pauseOnThreshold(ctx, campaign,
			"no host computed a plan of the change", len(targets), len(targets))
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
	}
	return payload
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
