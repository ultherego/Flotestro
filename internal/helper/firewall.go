package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/firewall"
)

// firewallPlanExtension marks the file that holds the rule registry from
// before a change.
const firewallPlanExtension = ".firewall.json"

// applyFirewall handles the operations on the host firewall.
//
// The panel changes only its own nftables table or a firewalld zone. Chains
// owned by others - docker, firewalld, iptables-nft - are rewritten without its
// participation, so a rule in them would disappear without a trace at the first
// container start or service reload.
func (s *Server) applyFirewall(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.FirewallRequest) *helperv1.HelperResponse {
	release, busy := s.hold(firewallGuard(action.GetOperation()), request)
	if busy != nil {
		return busy
	}
	defer release()

	actionCtx, cancel := deadline(ctx, request, 5*time.Minute, 30*time.Minute)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.FirewallRequest_OPERATION_READ:
		return firewallResponse(s.readFirewall(actionCtx), "", nil)
	case helperv1.FirewallRequest_OPERATION_CONFIRM:
		return s.confirmFirewall(actionCtx, action.GetRollbackId())
	case helperv1.FirewallRequest_OPERATION_RESTORE:
		return s.restoreFirewall(actionCtx, action.GetRollbackId())
	case helperv1.FirewallRequest_OPERATION_ZONE_PORT,
		helperv1.FirewallRequest_OPERATION_ZONE_SERVICE:
		return s.changeZone(actionCtx, action)
	case helperv1.FirewallRequest_OPERATION_RULE_ENSURE,
		helperv1.FirewallRequest_OPERATION_RULE_REMOVE:
		return s.changeRules(actionCtx, action)
	case helperv1.FirewallRequest_OPERATION_PLAN:
		return s.planRule(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "unknown firewall operation")
}

// firewallGuard names the guard of a firewall operation. The table is part of
// the network of the host and shares its guard; a read and a plan take none.
func firewallGuard(operation helperv1.FirewallRequest_Operation) string {
	switch operation {
	case helperv1.FirewallRequest_OPERATION_READ, helperv1.FirewallRequest_OPERATION_PLAN:
		return ""
	}
	return GuardNetwork
}

// planRule computes the difference between the rule found and the one
// requested.
//
// It changes nothing. The checks are the same as during a change - a rule that
// is invalid or that cuts off the management channel has to fall out here, at
// the plan stage, and not on half the fleet during execution. A refusal is then
// the content of the plan, not a failure: the operator sees it before giving
// consent.
//
// The plan carries the digest of the whole rule set the host has now. The
// change comes back with that digest and the host refuses when the set changed
// in the meantime.
func (s *Server) planRule(ctx context.Context, action *helperv1.FirewallRequest) *helperv1.HelperResponse {
	state := s.readFirewall(ctx)
	if state.UnavailableReason != "" {
		return reject(ErrorUnsupported, state.UnavailableReason)
	}
	// A plan with a zone concerns firewalld: a zone is a set of entries, not a
	// panel rule, and it is computed differently.
	if action.GetZone() != "" {
		return s.planZone(state, action)
	}
	registry, err := loadRuleRegistry(state.Adapter)
	if err != nil {
		return reject(ErrorExecFailed, "reading the rule registry: "+err.Error())
	}

	// A plan without a chain and an action is a removal plan: creating a rule
	// always carries them, removing one never does. The result names this
	// directly.
	removal := action.GetChain() == "" && action.GetAction() == ""

	var plan firewall.Plan
	var after firewall.Registry
	if removal {
		plan = firewall.ComputeRemoval(registry, action.GetRuleId(), state.Hash, state.Adapter)
		after, _ = registry.Remove(action.GetRuleId())
	} else {
		rule := firewall.RuleSpec{
			ID: action.GetRuleId(), Chain: action.GetChain(), Action: action.GetAction(),
			Protocol: action.GetProtocol(), Ports: action.GetPorts(),
			Sources: action.GetSources(), Interface: action.GetInterface(),
			Comment: action.GetComment(),
		}
		if err := rule.Validate(); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		plan = firewall.ComputeRule(registry, rule, state.Hash, state.Adapter)
		if !action.GetBreakGlass() {
			if err := firewall.ProtectsManagementChannel(rule,
				action.GetManagementAddress(), int(action.GetManagementPort())); err != nil {
				plan.Refuse(err.Error())
			}
		}
		after = registry.Set(rule)
	}
	if state.Adapter == firewall.AdapterUFW && plan.Refusal == "" {
		// ufw is driven by its command line, so the plan is the list of
		// commands - and what ufw cannot express falls out here, not on the
		// host.
		steps, err := firewall.UFWTransition(registry, after)
		if err != nil {
			plan.Refuse(err.Error())
		} else {
			plan.Describe(firewall.CommandLines(steps))
		}
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	response := firewallResponse(state, describeFirewallPlan(plan), nil)
	if response.GetFirewallResult() != nil {
		response.FirewallResult.Plan = encoded
	}
	return response
}

// planZone computes the difference for an entry in a firewalld zone. The checks
// are the same as during a change, including the protection of the management
// channel: a refusal is the content of the plan, not a failure.
func (s *Server) planZone(state firewall.Snapshot, action *helperv1.FirewallRequest) *helperv1.HelperResponse {
	var plan firewall.ZonePlan
	switch {
	case !exists(firewall.FirewallCmdPath):
		plan = firewall.ZonePlan{Zone: action.GetZone(), RulesetHash: state.Hash, Adapter: state.Adapter}
		plan.Refuse("this host has no firewalld")
	case action.GetService() != "":
		plan = firewall.ComputeService(state.Zones, action.GetZone(), action.GetService(),
			action.GetEnable(), state.Hash, state.Adapter)
	case len(action.GetPorts()) != 1:
		plan = firewall.ZonePlan{Zone: action.GetZone(), Kind: firewall.EntryPort,
			RulesetHash: state.Hash, Adapter: state.Adapter}
		plan.Refuse("the operation concerns exactly one port")
	default:
		plan = firewall.ComputePort(state.Zones, action.GetZone(), action.GetPorts()[0],
			action.GetProtocol(), action.GetEnable(), state.Hash, state.Adapter)
		if plan.Refusal == "" && !action.GetEnable() && !action.GetBreakGlass() &&
			action.GetPorts()[0] == strconv.Itoa(int(action.GetManagementPort())) {
			plan.Refuse("the port " + action.GetPorts()[0] + " is the management channel; " +
				"closing it deliberately needs explicit operator consent")
		}
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the change will not enter this host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == firewall.PlanNoChange:
		message = "the zone " + plan.Zone + " is already in the desired state"
	default:
		message = strings.Join(plan.Changes, "; ")
	}
	response := firewallResponse(state, message, nil)
	if response.GetFirewallResult() != nil {
		response.FirewallResult.Plan = encoded
	}
	return response
}

// describeFirewallPlan sums the plan up in one sentence for the operation
// journal.
func describeFirewallPlan(plan firewall.Plan) string {
	if plan.Refusal != "" {
		return "the change will not enter this host: " + plan.Refusal
	}
	switch plan.Action {
	case firewall.PlanNoChange:
		return "the rule is already in the desired state"
	case firewall.PlanCreate:
		return "the rule will be created"
	case firewall.PlanRemoveAbsent:
		return "the rule does not exist, so there is nothing to remove"
	case firewall.PlanRemove:
		return "the rule will be removed"
	default:
		return "what will change: " + strings.Join(plan.Changes, ", ")
	}
}

// changeRules creates or removes a panel rule and rebuilds the table - or,
// on a host where ufw holds the rules, runs the ufw commands that carry the
// registry from the state before to the state after.
func (s *Server) changeRules(ctx context.Context, action *helperv1.FirewallRequest) *helperv1.HelperResponse {
	state := s.readFirewall(ctx)
	if state.UnavailableReason != "" {
		return reject(ErrorUnsupported, state.UnavailableReason)
	}
	if !state.Writable {
		return reject(ErrorUnsupported, state.ReadOnlyReason)
	}
	// A change ordered against a different rule set is not the same change the
	// operator looked at in the plan.
	if expected := action.GetExpectedHash(); expected != "" && expected != state.Hash {
		return reject(ErrorPreconditionFailed, fmt.Sprintf(
			"the rule set changed since the plan (%s instead of %s)", state.Hash, expected))
	}

	registry, err := loadRuleRegistry(state.Adapter)
	if err != nil {
		return reject(ErrorExecFailed, "reading the rule registry: "+err.Error())
	}
	previous := registry

	if action.GetOperation() == helperv1.FirewallRequest_OPERATION_RULE_ENSURE {
		rule := firewall.RuleSpec{
			ID: action.GetRuleId(), Chain: action.GetChain(), Action: action.GetAction(),
			Protocol: action.GetProtocol(), Ports: action.GetPorts(),
			Sources: action.GetSources(), Interface: action.GetInterface(),
			Comment: action.GetComment(),
		}
		if err := rule.Validate(); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		// The management channel is the one thing that must not be lost: without
		// it the host stops answering and there is nothing left to undo the
		// change with.
		if !action.GetBreakGlass() {
			if err := firewall.ProtectsManagementChannel(rule,
				action.GetManagementAddress(), int(action.GetManagementPort())); err != nil {
				return reject(ErrorUnsupported, err.Error()+
					"; breaking it deliberately needs explicit operator consent")
			}
		}
		registry = registry.Set(rule)
	} else {
		updated, found := registry.Remove(action.GetRuleId())
		if !found {
			return reject(ErrorUnsupported, "the rule "+action.GetRuleId()+" does not belong to the panel")
		}
		registry = updated
	}
	registry.UpdatedAt = time.Now().UTC()

	// The ufw commands are assembled before anything is armed: a rule ufw
	// cannot express is a flaw of the order, not a failure of the execution.
	var ufwSteps [][]string
	if state.Adapter == firewall.AdapterUFW {
		if ufwSteps, err = firewall.UFWTransition(previous, registry); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
	}

	plan, response := s.armFirewallRollback(ctx, state.Adapter, previous, action.GetRollbackSeconds())
	if response != nil {
		return response
	}
	if state.Adapter == firewall.AdapterUFW {
		// ufw is changed rule by rule, so the registry is written before the
		// first step: a change that stops halfway is then rolled back from
		// the registry it was heading to - deleting what landed and adding
		// back what was removed - rather than from one that says nothing
		// changed.
		if err := saveRuleRegistry(state.Adapter, registry); err != nil {
			return reject(ErrorExecFailed, "writing the rule registry: "+err.Error())
		}
	}
	if err := s.applyRegistry(ctx, state.Adapter, registry, ufwSteps); err != nil {
		// The rollback stays armed: it will bring the rules to the state from
		// before the change also when the change stopped halfway.
		response := reject(ErrorExecFailed, err.Error())
		response.FirewallResult = &helperv1.FirewallResult{
			Message:          err.Error(),
			RollbackId:       plan.ID,
			RollbackDeadline: plan.Deadline.Format(time.RFC3339),
		}
		return response
	}
	if err := saveRuleRegistry(state.Adapter, registry); err != nil {
		return reject(ErrorExecFailed, "writing the rule registry: "+err.Error())
	}

	applied := "the rules were rebuilt"
	if state.Adapter == firewall.AdapterUFW {
		applied = "the ufw rules were changed"
	}
	return firewallResponse(s.readFirewall(ctx),
		fmt.Sprintf("%s; rollback at %s unless the agent confirms connectivity",
			applied, plan.Deadline.Format(time.RFC3339)), &plan)
}

// changeZone opens or closes a port or a service in a firewalld zone.
func (s *Server) changeZone(ctx context.Context, action *helperv1.FirewallRequest) *helperv1.HelperResponse {
	if !exists(firewall.FirewallCmdPath) {
		return reject(ErrorUnsupported, "this host has no firewalld")
	}
	// A change ordered against a different rule set is not the same change the
	// operator looked at in the plan: firewalld rewrites nftables at every zone
	// change, so the digest of the set detects somebody else's change.
	if expected := action.GetExpectedHash(); expected != "" {
		if state := s.readFirewall(ctx); expected != state.Hash {
			return reject(ErrorPreconditionFailed, fmt.Sprintf(
				"the rule set changed since the plan (%s instead of %s)", state.Hash, expected))
		}
	}

	var steps [][]string
	var err error
	if action.GetOperation() == helperv1.FirewallRequest_OPERATION_ZONE_PORT {
		if len(action.GetPorts()) != 1 {
			return reject(ErrorMalformed, "the operation concerns exactly one port")
		}
		// Closing the port the host talks to the panel through cuts the panel
		// off.
		if !action.GetEnable() && !action.GetBreakGlass() &&
			action.GetPorts()[0] == strconv.Itoa(int(action.GetManagementPort())) {
			return reject(ErrorUnsupported,
				"the port "+action.GetPorts()[0]+" is the management channel; "+
					"closing it deliberately needs explicit operator consent")
		}
		steps, err = firewall.PortArguments(action.GetZone(), action.GetPorts()[0],
			action.GetProtocol(), action.GetEnable())
	} else {
		steps, err = firewall.ServiceArguments(action.GetZone(), action.GetService(), action.GetEnable())
	}
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	for _, step := range steps {
		if output, err := runTool(ctx, step); err != nil {
			return reject(ErrorExecFailed, err.Error()+": "+output)
		}
	}
	return firewallResponse(s.readFirewall(ctx), "the zone was changed", nil)
}

// applyRegistry brings the host to the given registry: nftables by
// rebuilding the panel table, ufw by the commands of the transition.
func (s *Server) applyRegistry(ctx context.Context, adapter string, registry firewall.Registry,
	ufwSteps [][]string) error {
	if adapter != firewall.AdapterUFW {
		return s.rebuildTable(ctx, registry)
	}
	for _, step := range ufwSteps {
		output, err := runTool(ctx, step)
		if err != nil && firewall.UFWDeletionOfAbsentRule(step, output) {
			// A rule already gone is the state the step wanted. It happens on
			// a rollback of a change that stopped halfway, and on a host where
			// somebody removed the panel's rule by hand.
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(step, " "), err, output)
		}
	}
	return nil
}

// restoreRegistry returns to the registry of a rollback plan. For ufw the
// transition is computed from the registry the host has now to the one from
// before the change: the same function as the change, the other way round.
func (s *Server) restoreRegistry(ctx context.Context, plan firewallPlan) error {
	var steps [][]string
	if plan.Adapter == firewall.AdapterUFW {
		current, err := loadRuleRegistry(plan.Adapter)
		if err != nil {
			return fmt.Errorf("reading the rule registry: %w", err)
		}
		if steps, err = firewall.UFWTransition(current, plan.Registry); err != nil {
			return err
		}
	}
	if err := s.applyRegistry(ctx, plan.Adapter, plan.Registry, steps); err != nil {
		return err
	}
	return saveRuleRegistry(plan.Adapter, plan.Registry)
}

// loadRuleRegistry reads the registry of the mechanism that holds the rules.
// Each mechanism has one of its own: the same rule is written differently
// by each, and a host switching between them must not rebuild one's rules
// through the other.
func loadRuleRegistry(adapter string) (firewall.Registry, error) {
	if adapter == firewall.AdapterUFW {
		return firewall.LoadNamedRegistry(firewall.RegistryDir, firewall.UFWRegistryFile)
	}
	return firewall.LoadRegistry(firewall.RegistryDir)
}

func saveRuleRegistry(adapter string, registry firewall.Registry) error {
	if adapter == firewall.AdapterUFW {
		return firewall.SaveNamedRegistry(firewall.RegistryDir, firewall.UFWRegistryFile, registry)
	}
	return firewall.SaveRegistry(firewall.RegistryDir, registry)
}

// rebuildTable recreates the panel table from the registry.
func (s *Server) rebuildTable(ctx context.Context, registry firewall.Registry) error {
	if len(registry.Rules) == 0 {
		// An empty table with hooked chains filters nothing but leaves an object
		// nobody needs.
		_, _ = runTool(ctx, firewall.TableRemovalArguments())
		return nil
	}
	steps, err := firewall.RebuildArguments(registry)
	if err != nil {
		return err
	}
	for _, step := range steps {
		if output, err := runTool(ctx, step); err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(step, " "), err, output)
		}
	}
	return nil
}

// armFirewallRollback writes the registry from before the change and starts the
// timer.
func (s *Server) armFirewallRollback(ctx context.Context, adapter string, previous firewall.Registry,
	seconds uint32) (firewallPlan, *helperv1.HelperResponse) {
	plan := firewallPlan{
		ID:        rollbackIdentifier(),
		Adapter:   adapter,
		Registry:  previous,
		CreatedAt: time.Now().UTC(),
	}
	window := rollbackWindow(seconds)
	plan.Deadline = plan.CreatedAt.Add(window)

	if err := writeFirewallPlan(plan); err != nil {
		return plan, reject(ErrorExecFailed, "writing the rollback plan: "+err.Error())
	}
	if err := s.armTimer(ctx, firewallRollbackUnit+plan.ID, window, "-rollback-firewall", plan.ID); err != nil {
		_ = removeFirewallPlan(plan.ID)
		return plan, reject(ErrorExecFailed, "arming the rollback: "+err.Error())
	}
	return plan, nil
}

// confirmFirewall disarms the timer after connectivity is confirmed.
func (s *Server) confirmFirewall(ctx context.Context, id string) *helperv1.HelperResponse {
	if _, err := readFirewallPlan(id); err != nil {
		return firewallResponse(s.readFirewall(ctx),
			"there is nothing to disarm: the rollback "+id+" no longer exists", nil)
	}
	_ = s.disarmTimer(ctx, firewallRollbackUnit+id)
	if err := removeFirewallPlan(id); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	response := firewallResponse(s.readFirewall(ctx), "the firewall change was confirmed", nil)
	response.FirewallResult.Confirmed = true
	return response
}

// restoreFirewall goes back to the registry from before the change at the
// request of the operator.
func (s *Server) restoreFirewall(ctx context.Context, id string) *helperv1.HelperResponse {
	plan, err := readFirewallPlan(id)
	if err != nil {
		return reject(ErrorUnsupported, "there is no rollback plan "+id)
	}
	if err := s.restoreRegistry(ctx, plan); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	_ = s.disarmTimer(ctx, firewallRollbackUnit+id)
	_ = removeFirewallPlan(id)
	return firewallResponse(s.readFirewall(ctx), "the rules were restored on request", nil)
}

// readFirewall assembles the picture of the host firewall.
func (s *Server) readFirewall(ctx context.Context) firewall.Snapshot {
	snapshot := firewall.Snapshot{ObservedAt: time.Now().UTC()}

	nft := exists(firewall.NftPath)
	ufw := exists(firewall.UFWPath)
	if !nft && !ufw {
		snapshot.UnavailableReason = "this host has no nftables (nft) binary"
		return snapshot
	}
	var ruleset string
	if nft {
		// nft writes the warnings about tables belonging to other programs to
		// the error stream, not to the output. Without them the panel would
		// take the docker tables for ordinary host tables - and would allow
		// touching them.
		output, warnings, err := outputWithWarnings(ctx, firewall.NftPath, "-a", "list", "ruleset")
		if err != nil {
			snapshot.UnavailableReason = "nft list ruleset: " + err.Error()
			return snapshot
		}
		ruleset = warnings + output
		snapshot = firewall.ParseRuleset(ruleset)
		snapshot.ObservedAt = time.Now().UTC()
		snapshot.Writable = true
	}

	// ufw loads its rules into the tables underneath through iptables-nft,
	// which nft reports as foreign: the rules the operator knows are the ufw
	// ones, read in the form ufw takes them back in. An installed but
	// inactive ufw holds nothing, and the panel's own nftables table works as
	// on any other host.
	if ufw {
		if response := s.readUFW(ctx, &snapshot, ruleset); response != "" {
			snapshot.ReadOnlyReason = response
		}
	}

	// Firewalld keeps its own tables and rewrites them on a reload, so on such
	// a host we speak of zones and not of panel rules.
	if exists(firewall.FirewallCmdPath) {
		defaultZone, _ := toolOutput(ctx, firewall.FirewallCmdPath, "--get-default-zone")
		if zones, err := toolOutput(ctx, firewall.FirewallCmdPath, "--list-all-zones"); err == nil {
			snapshot.Zones = firewall.ParseZones(zones, strings.TrimSpace(defaultZone))
			snapshot.Adapter = firewall.AdapterFirewalld
		}
	}
	return snapshot
}

// readUFW adds the ufw state to the snapshot. It returns the reason the
// panel cannot write here, or an empty string.
func (s *Server) readUFW(ctx context.Context, snapshot *firewall.Snapshot, ruleset string) string {
	arguments := firewall.UFWStatusArguments()
	output, err := toolOutput(ctx, arguments[0], arguments[1:]...)
	if err != nil {
		if !snapshot.Writable {
			return "ufw status: " + err.Error()
		}
		return ""
	}
	status := firewall.ParseUFWStatus(output)
	if !status.Active {
		// An inactive ufw is an answer the operator is to see next to the
		// adapter: where the rules go instead, or why nowhere.
		status.Reason = firewall.UFWInactiveWithNftables
		if !snapshot.Writable {
			status.Reason = firewall.UFWInactiveReadOnly
		}
		snapshot.UFW = &status
		if !snapshot.Writable {
			return status.Reason
		}
		return ""
	}
	snapshot.UFW = &status
	arguments = firewall.UFWAddedArguments()
	added, err := toolOutput(ctx, arguments[0], arguments[1:]...)
	if err != nil {
		snapshot.Writable = false
		return "ufw show added: " + err.Error()
	}
	// The rules the kernel filters with now are the ones nft listed; the
	// ufw rules are appended after, in the form ufw takes them back in.
	loaded := firewall.UFWLoadedRules(snapshot.Rules)
	snapshot.Rules = append(snapshot.Rules, firewall.ParseUFWAdded(added)...)
	snapshot.Adapter = firewall.AdapterUFW
	// What ufw keeps in its files and what the kernel filters with now are
	// two pictures, and the panel used to see only the tool's account of
	// itself. A rule written into user.rules and never loaded does nothing
	// while looking enforced; a rule in the kernel no file keeps vanishes
	// at the next reload.
	snapshot.Drift = ufwDrift(ruleset, loaded)
	// The fingerprint covers the ufw rules together with the tables: a rule
	// added with ufw since the plan is a changed rule set even when the
	// operator's nft listing looks the same at a glance.
	snapshot.Hash = firewall.Fingerprint(ruleset + "\n" + added)
	snapshot.Writable = true
	return ""
}

// firewallRollbackUnit is the prefix of the transient unit that carries out a
// firewall rollback.
const firewallRollbackUnit = "flotestro-firewall-"

// firewallPlan is the rule registry from before a change together with the
// deadline of the return.
type firewallPlan struct {
	ID string `json:"id"`
	// Adapter names the mechanism the registry belongs to. Empty means
	// nftables: plans written before the field existed are its plans.
	Adapter   string            `json:"adapter,omitempty"`
	Registry  firewall.Registry `json:"registry"`
	CreatedAt time.Time         `json:"created_at"`
	Deadline  time.Time         `json:"deadline"`
}

func firewallPlanPath(id string) (string, error) {
	if !validPlanIdentifier(id) {
		return "", fmt.Errorf("invalid plan identifier %q", id)
	}
	return filepath.Join(firewall.RegistryDir, id+firewallPlanExtension), nil
}

func writeFirewallPlan(plan firewallPlan) error {
	if err := os.MkdirAll(firewall.RegistryDir, 0o700); err != nil {
		return err
	}
	path, err := firewallPlanPath(plan.ID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func readFirewallPlan(id string) (firewallPlan, error) {
	path, err := firewallPlanPath(id)
	if err != nil {
		return firewallPlan{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return firewallPlan{}, err
	}
	var plan firewallPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return firewallPlan{}, err
	}
	return plan, nil
}

func removeFirewallPlan(id string) error {
	path, err := firewallPlanPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RollbackFirewall restores the panel rules from before a change.
//
// Called by the transient systemd unit when nobody confirmed connectivity after
// a firewall change. It works without the agent and without the panel.
func RollbackFirewall(ctx context.Context, id string) error {
	plan, err := readFirewallPlan(id)
	if err != nil {
		return fmt.Errorf("the rollback plan %s: %w", id, err)
	}
	// The unit that calls this has no clock of its own.
	ctx, cancel := context.WithTimeout(ctx, rollbackToolLimit)
	defer cancel()
	server := &Server{}
	if err := server.restoreRegistry(ctx, plan); err != nil {
		return err
	}
	return removeFirewallPlan(id)
}

func firewallResponse(snapshot firewall.Snapshot, message string, plan *firewallPlan) *helperv1.HelperResponse {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	result := &helperv1.FirewallResult{Snapshot: encoded, Message: message}
	if plan != nil {
		result.RollbackId = plan.ID
		result.RollbackDeadline = plan.Deadline.Format(time.RFC3339)
	}
	return &helperv1.HelperResponse{Accepted: true, FirewallResult: result}
}

func runTool(ctx context.Context, arguments []string) (string, error) {
	cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	cmd.Env = toolEnvironment()
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// toolOutput runs a tool and attaches its error message.
//
// The exit code alone says nothing: "exit status 3" from nft can mean a missing
// netlink socket, a missing table or a syntax error, and the operator is to read
// which of them it was.
func toolOutput(ctx context.Context, path string, arguments ...string) (string, error) {
	output, _, err := outputWithWarnings(ctx, path, arguments...)
	return output, err
}

// outputWithWarnings returns both streams separately.
//
// The error stream is sometimes the content of the answer and not noise: nft
// writes there the warnings about tables owned by others, and on a failure -
// the reason. The exit code alone says nothing: "exit status 3" can mean a
// missing netlink socket, a missing table or a syntax error.
func outputWithWarnings(ctx context.Context, path string, arguments ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, path, arguments...)
	cmd.Env = toolEnvironment()
	var errorStream strings.Builder
	cmd.Stderr = &errorStream
	output, err := cmd.Output()
	message := errorStream.String()
	if err != nil {
		if content := strings.TrimSpace(message); content != "" {
			return "", message, fmt.Errorf("%w: %s", err, content)
		}
		return "", message, err
	}
	return string(output), message, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ufwDrift compares what ufw keeps in its files with what the kernel filters
// with now. Without a listing from the kernel, or with a file that cannot be
// read, there is no comparison at all: an empty side would call every rule of
// the other one a drift.
func ufwDrift(ruleset string, loaded []firewall.Rule) []firewall.Drift {
	if ruleset == "" {
		return nil
	}
	var filed []firewall.Rule
	for _, source := range []struct{ family, path string }{
		{"ip", firewall.UFWUserRulesFile},
		{"ip6", firewall.UFWUser6RulesFile},
	} {
		content, err := os.ReadFile(source.path)
		if err != nil {
			if os.IsNotExist(err) {
				// ufw writes user6.rules only where IPv6 is on; a file that
				// is not there holds no rules, which is an answer.
				continue
			}
			return nil
		}
		filed = append(filed, firewall.UFWFileRules(source.family, string(content))...)
	}
	return firewall.UFWDrift(filed, loaded)
}
