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
	if !s.unitMutex.TryLock() {
		return reject(ErrorLocked, "another unit operation is in flight")
	}
	defer s.unitMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
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
	registry, err := firewall.LoadRegistry(firewall.RegistryDir)
	if err != nil {
		return reject(ErrorExecFailed, "reading the rule registry: "+err.Error())
	}

	// A plan without a chain and an action is a removal plan: creating a rule
	// always carries them, removing one never does. The result names this
	// directly.
	removal := action.GetChain() == "" && action.GetAction() == ""

	var plan firewall.Plan
	if removal {
		plan = firewall.ComputeRemoval(registry, action.GetRuleId(), state.Hash, state.Adapter)
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

// changeRules creates or removes a panel rule and rebuilds the table.
func (s *Server) changeRules(ctx context.Context, action *helperv1.FirewallRequest) *helperv1.HelperResponse {
	if !exists(firewall.NftPath) {
		return reject(ErrorUnsupported, "this host has no nftables")
	}

	state := s.readFirewall(ctx)
	// A change ordered against a different rule set is not the same change the
	// operator looked at in the plan.
	if expected := action.GetExpectedHash(); expected != "" && expected != state.Hash {
		return reject(ErrorPreconditionFailed, fmt.Sprintf(
			"the rule set changed since the plan (%s instead of %s)", state.Hash, expected))
	}

	registry, err := firewall.LoadRegistry(firewall.RegistryDir)
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

	plan, response := s.armFirewallRollback(ctx, previous, action.GetRollbackSeconds())
	if response != nil {
		return response
	}
	if err := s.rebuildTable(ctx, registry); err != nil {
		// The rollback stays armed: it will bring the table to the state from
		// before the change also when the rebuild stopped halfway.
		response := reject(ErrorExecFailed, err.Error())
		response.FirewallResult = &helperv1.FirewallResult{
			Message:          err.Error(),
			RollbackId:       plan.ID,
			RollbackDeadline: plan.Deadline.Format(time.RFC3339),
		}
		return response
	}
	if err := firewall.SaveRegistry(firewall.RegistryDir, registry); err != nil {
		return reject(ErrorExecFailed, "writing the rule registry: "+err.Error())
	}

	return firewallResponse(s.readFirewall(ctx),
		fmt.Sprintf("the rules were rebuilt; rollback at %s unless the agent confirms connectivity",
			plan.Deadline.Format(time.RFC3339)), &plan)
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
func (s *Server) armFirewallRollback(ctx context.Context, previous firewall.Registry,
	seconds uint32) (firewallPlan, *helperv1.HelperResponse) {
	plan := firewallPlan{
		ID:        rollbackIdentifier(),
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
	if err := s.rebuildTable(ctx, plan.Registry); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if err := firewall.SaveRegistry(firewall.RegistryDir, plan.Registry); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	_ = s.disarmTimer(ctx, firewallRollbackUnit+id)
	_ = removeFirewallPlan(id)
	return firewallResponse(s.readFirewall(ctx), "the rules were restored on request", nil)
}

// readFirewall assembles the picture of the host firewall.
func (s *Server) readFirewall(ctx context.Context) firewall.Snapshot {
	snapshot := firewall.Snapshot{ObservedAt: time.Now().UTC()}

	if !exists(firewall.NftPath) {
		snapshot.UnavailableReason = "this host has no nftables (nft) binary"
		return snapshot
	}
	// nft writes the warnings about tables belonging to other programs to the
	// error stream, not to the output. Without them the panel would take the
	// docker tables for ordinary host tables - and would allow touching them.
	output, warnings, err := outputWithWarnings(ctx, firewall.NftPath, "-a", "list", "ruleset")
	if err != nil {
		snapshot.UnavailableReason = "nft list ruleset: " + err.Error()
		return snapshot
	}
	snapshot = firewall.ParseRuleset(warnings + output)
	snapshot.ObservedAt = time.Now().UTC()
	snapshot.Writable = true

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

// firewallRollbackUnit is the prefix of the transient unit that carries out a
// firewall rollback.
const firewallRollbackUnit = "flotestro-firewall-"

// firewallPlan is the rule registry from before a change together with the
// deadline of the return.
type firewallPlan struct {
	ID        string            `json:"id"`
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
	server := &Server{}
	if err := server.rebuildTable(ctx, plan.Registry); err != nil {
		return err
	}
	if err := firewall.SaveRegistry(firewall.RegistryDir, plan.Registry); err != nil {
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
