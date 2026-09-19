package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/network"
)

// The range of the rollback clock.
const (
	rollbackDefault = 120 * time.Second
	rollbackMin     = 30 * time.Second
	rollbackMax     = 15 * time.Minute
)

// rollbackToolLimit bounds the tools a rollback runs when the transient unit
// calls the helper directly: that call carries no deadline of its own.
const rollbackToolLimit = 5 * time.Minute

// applyNetwork handles changes of the network configuration.
func (s *Server) applyNetwork(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.NetworkRequest) *helperv1.HelperResponse {
	release, busy := s.hold(networkGuard(action.GetOperation()), request)
	if busy != nil {
		return busy
	}
	defer release()

	actionCtx, cancel := deadline(ctx, request, 5*time.Minute, 30*time.Minute)
	defer cancel()

	// The mechanism is detected the same way the agent detects it for the
	// inventory: the host answers with the adapter it reported, not with one
	// picked here.
	adapter := network.DetectAdapter(network.Exists)
	if adapter == "" {
		reason := network.ReadOnlyReason(adapter)
		if action.GetOperation() == helperv1.NetworkRequest_OPERATION_PLAN {
			// A missing mechanism is an answer of the plan, not a read error:
			// the campaign is to see this host as a refusal.
			return networkPlanResponse(nil, network.RefusedPlan(action.GetInterface(),
				networkChangeKind(action), reason))
		}
		return reject(ErrorUnsupported, reason)
	}

	switch action.GetOperation() {
	case helperv1.NetworkRequest_OPERATION_READ:
		return networkResponse(s.adapterProfiles(actionCtx, adapter), "", nil)

	case helperv1.NetworkRequest_OPERATION_PLAN:
		return s.planNetwork(actionCtx, adapter, action)

	case helperv1.NetworkRequest_OPERATION_CONFIRM:
		return s.confirmChange(actionCtx, action.GetRollbackId())

	case helperv1.NetworkRequest_OPERATION_ROLLBACK:
		return s.rollbackNow(actionCtx, action.GetRollbackId())

	case helperv1.NetworkRequest_OPERATION_SET_MTU,
		helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES,
		helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		return s.changeNetwork(actionCtx, adapter, action)

	case helperv1.NetworkRequest_OPERATION_APPLY_LINK,
		helperv1.NetworkRequest_OPERATION_REMOVE_LINK:
		return s.changeNetworkLink(actionCtx, adapter, action)
	}
	return reject(ErrorUnknownAction, "unknown network operation")
}

// networkGuard names the guard of a network operation.
func networkGuard(operation helperv1.NetworkRequest_Operation) string {
	switch operation {
	case helperv1.NetworkRequest_OPERATION_READ, helperv1.NetworkRequest_OPERATION_PLAN:
		return ""
	}
	return GuardNetwork
}

// planNetwork computes the difference between the profile found and the one
// requested, without touching the host.
func (s *Server) planNetwork(ctx context.Context, adapter string,
	action *helperv1.NetworkRequest) *helperv1.HelperResponse {
	profiles := s.adapterProfiles(ctx, adapter)
	// A layered plan is computed against the whole host and not against one
	// profile: every one of its refusals is about a relation to something else -
	// a member another layer owns, a parent that is not there, the interface the.
	if kind := networkChangeKind(action); kind == network.PlanLink || kind == network.PlanLinkRemove {
		snapshot, err := s.networkSnapshot(ctx, action.GetManagementAddress())
		if err != nil {
			return networkPlanResponse(profiles, network.RefusedPlan(action.GetInterface(), kind, err.Error()))
		}
		return networkPlanResponse(profiles, s.adapterLinkPlan(ctx, adapter, action, snapshot))
	}
	_, profile, err := s.adapterProfile(ctx, adapter, action.GetInterface())
	if err != nil {
		return networkPlanResponse(profiles, network.RefusedPlan(action.GetInterface(),
			networkChangeKind(action), err.Error()))
	}
	return networkPlanResponse(profiles, s.adapterPlan(ctx, adapter, action, profile))
}

// adapterPlan computes the plan and attaches to it what the mechanism will
// apply: nothing for NetworkManager, which takes arguments, the nmstate
// document of the touched interface, or the panel's netplan file after the.
func (s *Server) adapterPlan(ctx context.Context, adapter string, action *helperv1.NetworkRequest,
	profile network.Profile) network.Plan {
	// The second family's switches come from the kernel, not from the profile: a
	// mechanism will happily write an IPv6 address onto an interface whose
	// disable_ipv6 is set, and the address then exists nowhere the verifier can.
	ipv6 := network.CombineIPv6(
		network.ReadIPv6Settings(network.IPv6ConfDir, "all"),
		network.ReadIPv6Settings(network.IPv6ConfDir, action.GetInterface()))
	plan := networkPlan(action, profile, ipv6)
	if plan.Refusal != "" || plan.Desired == nil {
		plan.Attach(adapter, "")
		return plan
	}
	var document string
	var err error
	switch adapter {
	case network.AdapterNetworkManager:
		// NetworkManager takes arguments rather than a document, so there is nothing
		// to show; what it cannot express is still its answer, and the operator is
		// to read it in the plan rather than in a failed job.
		if plan.Operation == network.PlanProfile {
			_, err = network.ProfileArguments(*plan.Desired)
		}
	case network.AdapterNmstate:
		document, err = network.NmstateDocument(plan.Operation, *plan.Current, *plan.Desired)
	case network.AdapterNetplan:
		config, readErr := s.readNetplanConfig(ctx)
		if readErr != nil {
			plan.Refuse(readErr.Error())
			plan.Attach(adapter, "")
			return plan
		}
		managed, _ := network.LoadState(network.NetplanManagedFile)
		document, err = network.NetplanManagedDocument(managed, config, action.GetInterface(),
			plan.Operation, *plan.Current, *plan.Desired)
	}
	if err != nil {
		// A configuration the mechanism cannot express is a refusal the
		// operator sees in the plan, not a failure on half the fleet.
		plan.Refuse(err.Error())
	}
	plan.Attach(adapter, document)
	return plan
}

// networkPlan computes the plan for the change described by the order against
// the profile found.
func networkPlan(action *helperv1.NetworkRequest, profile network.Profile,
	ipv6 network.IPv6Settings) network.Plan {
	switch networkChangeKind(action) {
	case network.PlanProfile:
		return network.ComputeProfile(action.GetInterface(), profile, network.ProfileRequest{
			Method:     action.GetMethod(),
			Addresses:  action.GetAddresses(),
			Gateway:    action.GetGateway(),
			DNS:        action.GetDns(),
			Method6:    action.GetMethod6(),
			Addresses6: action.GetAddresses6(),
			Gateway6:   action.GetGateway6(),
			AcceptRA:   action.GetAcceptRa(),
			Privacy:    action.GetPrivacy(),
		}, ipv6)
	case network.PlanRoutes:
		return network.ComputeRoutes(action.GetInterface(), profile, action.GetRoutes())
	default:
		return network.ComputeMTU(action.GetInterface(), profile, action.GetMtu())
	}
}

// linkSpecOf turns the layered order into the description the module plans
// against.
func linkSpecOf(link *helperv1.NetworkLink) network.LinkSpec {
	return network.LinkSpec{
		Name: link.GetName(), Kind: link.GetKind(), Members: link.GetMembers(),
		Mode: link.GetMode(), MIIMonMS: int(link.GetMiimonMs()),
		Primary: link.GetPrimary(), LACPRate: link.GetLacpRate(),
		STP: link.GetStp(), VLANFiltering: link.GetVlanFiltering(),
		Parent: link.GetParent(), VLANID: int(link.GetVlanId()),
		Protocol: link.GetProtocol(), MTU: link.GetMtu(),
	}
}

// networkChangeKind says which change the order describes.
func networkChangeKind(action *helperv1.NetworkRequest) string {
	switch action.GetOperation() {
	case helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		return network.PlanProfile
	case helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES:
		return network.PlanRoutes
	case helperv1.NetworkRequest_OPERATION_SET_MTU:
		return network.PlanMTU
	case helperv1.NetworkRequest_OPERATION_APPLY_LINK:
		return network.PlanLink
	case helperv1.NetworkRequest_OPERATION_REMOVE_LINK:
		return network.PlanLinkRemove
	}
	switch {
	case action.GetLink() != nil:
		return network.PlanLink
	case action.GetLinkRemove():
		return network.PlanLinkRemove
	case action.GetMethod() != "" || action.GetMethod6() != "" ||
		action.GetAcceptRa() != "" || action.GetPrivacy() != "":
		return network.PlanProfile
	case action.Routes != nil:
		return network.PlanRoutes
	default:
		return network.PlanMTU
	}
}

func networkPlanResponse(profiles []network.Profile, plan network.Plan) *helperv1.HelperResponse {
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	// A layered plan speaks about an interface, not about a profile: there
	// may be no profile at all behind a bond that does not exist yet.
	subject := "the profile " + plan.Connection
	if plan.CurrentLink != nil {
		subject = "the interface " + plan.Interface
	}
	message := "the change will not enter this host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == network.PlanNoChange:
		message = subject + " is already in the desired state"
	default:
		message = subject + ": " + strings.Join(plan.Changes, "; ")
	}
	response := networkResponse(profiles, message, nil)
	if response.GetNetworkResult() != nil {
		response.NetworkResult.Plan = encoded
	}
	return response
}

// changeNetwork assembles the change, arms the rollback and only then touches
// the host.
func (s *Server) changeNetwork(ctx context.Context, adapter string,
	action *helperv1.NetworkRequest) *helperv1.HelperResponse {
	connection, profile, err := s.adapterProfile(ctx, adapter, action.GetInterface())
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}

	// A change approved on the basis of a plan is to enter the state the operator
	// looked at.
	now := s.adapterPlan(ctx, adapter, action, profile)
	if expected := action.GetPlanHash(); expected != "" && now.PlanHash != expected {
		return reject(ErrorPreconditionFailed,
			"the profile "+connection+" changed since the planning; the change needs a new plan")
	}
	if now.Refusal != "" {
		return reject(ErrorMalformed, now.Refusal)
	}

	switch adapter {
	case network.AdapterNmstate:
		return s.changeNmstate(ctx, action, now)
	case network.AdapterNetplan:
		return s.changeNetplan(ctx, action, now)
	}

	steps, err := changeSteps(action, connection, profile)
	if err != nil {
		// A configuration the host will not accept is a flaw of the order, not
		// a failure of the execution.
		return reject(ErrorMalformed, err.Error())
	}

	// The rollback plan is built from the state read before the change.
	plan := network.RollbackPlan{
		ID:         rollbackIdentifier(),
		Profile:    profile,
		Interface:  action.GetInterface(),
		Management: false,
		CreatedAt:  time.Now().UTC(),
		Reason:     action.GetReason(),
		Adapter:    network.AdapterNetworkManager,
	}
	window := rollbackWindow(action.GetRollbackSeconds())
	plan.Deadline = plan.CreatedAt.Add(window)

	if _, err := network.RollbackSteps(plan); err != nil {
		// Without a verified way back the change is not made at all.
		return reject(ErrorUnsupported, "the rollback cannot be assembled: "+err.Error())
	}
	if err := network.SavePlan(network.RollbackDir, plan); err != nil {
		return reject(ErrorExecFailed, "writing the rollback plan: "+err.Error())
	}
	if err := s.armRollback(ctx, plan, window); err != nil {
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, "arming the rollback: "+err.Error())
	}

	for _, step := range steps {
		if output, err := runNmcli(ctx, step); err != nil {
			// A change that failed leaves the host in an intermediate state. The
			// rollback stays armed and will carry it to the end.
			return networkErrorResponse(plan, fmt.Sprintf("%s: %s", err, output))
		}
	}

	return networkResponse(s.readProfiles(ctx),
		fmt.Sprintf("the change was applied; rollback at %s unless the agent confirms connectivity",
			plan.Deadline.Format(time.RFC3339)), &plan)
}

// changeSteps assembles the commands for one concrete operation.
func changeSteps(action *helperv1.NetworkRequest, connection string,
	current network.Profile) ([][]string, error) {
	switch action.GetOperation() {
	case helperv1.NetworkRequest_OPERATION_SET_MTU:
		return network.MTUArguments(connection, action.GetMtu())
	case helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES:
		// The order carries one list and the two families are written into two
		// settings: NetworkManager drops an IPv6 route put into ipv4.
		routes, routes6 := network.SplitRouteFamilies(action.GetRoutes())
		return network.RouteArguments(connection, routes, routes6)
	case helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		// Routes, MTU and the rest of the resolver stay as they were: the address
		// profile is a separate operation and must not silently erase settings the
		// operator was never asked about.
		desired := network.Profile{
			Connection:    connection,
			Method:        current.Method,
			Addresses:     current.Addresses,
			Gateway:       current.Gateway,
			DNS:           current.DNS,
			DNSSearch:     current.DNSSearch,
			IgnoreAutoDNS: current.IgnoreAutoDNS,
			Routes:        current.Routes,
			MTU:           current.MTU,
			Method6:       current.Method6,
			Addresses6:    current.Addresses6,
			Gateway6:      current.Gateway6,
			Routes6:       current.Routes6,
			AcceptRA:      current.AcceptRA,
			Privacy:       current.Privacy,
		}
		if action.GetMethod() != "" {
			desired.Method = action.GetMethod()
			desired.Addresses = action.GetAddresses()
			desired.Gateway = action.GetGateway()
			desired.DNS = action.GetDns()
		}
		if action.GetMethod6() != "" {
			desired.Method6 = action.GetMethod6()
			desired.Addresses6 = action.GetAddresses6()
			desired.Gateway6 = action.GetGateway6()
		}
		if action.GetAcceptRa() != "" {
			desired.AcceptRA = action.GetAcceptRa()
		}
		if action.GetPrivacy() != "" {
			desired.Privacy = action.GetPrivacy()
		}
		return network.ProfileArguments(desired)
	}
	return nil, fmt.Errorf("unknown network operation")
}

// confirmChange disarms the rollback after the agent confirmed connectivity.
func (s *Server) confirmChange(ctx context.Context, id string) *helperv1.HelperResponse {
	plan, err := network.LoadPlan(network.RollbackDir, id)
	if err != nil {
		// A missing plan means the rollback was already performed or already
		// disarmed.
		if trial := netplanTrials.get(id); trial != nil && trial.wasReverted() {
			return reject(ErrorExecFailed,
				"the change was reverted by netplan before the confirmation arrived")
		}
		return networkResponse(s.adapterProfiles(ctx, network.DetectAdapter(network.Exists)),
			"there is nothing to disarm: the rollback "+id+" no longer exists", nil)
	}
	switch plan.Adapter {
	case network.AdapterNmstate:
		if response := s.commitNmstate(ctx, plan); response != nil {
			return response
		}
	case network.AdapterNetplan:
		if response := s.confirmNetplan(ctx, plan); response != nil {
			return response
		}
	default:
		if err := s.disarmRollback(ctx, plan.ID); err != nil {
			return reject(ErrorExecFailed, "disarming the rollback: "+err.Error())
		}
	}
	if err := network.RemovePlan(network.RollbackDir, plan.ID); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	response := networkResponse(s.adapterProfiles(ctx, plan.Adapter), "the change was confirmed", nil)
	response.NetworkResult.Confirmed = true
	return response
}

// rollbackNow restores the state from before the change at the request of the
// operator.
func (s *Server) rollbackNow(ctx context.Context, id string) *helperv1.HelperResponse {
	plan, err := network.LoadPlan(network.RollbackDir, id)
	if err != nil {
		return reject(ErrorUnsupported, "there is no rollback plan "+id)
	}
	switch plan.Adapter {
	case network.AdapterNmstate:
		if err := rollbackNmstate(ctx, plan); err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
	case network.AdapterNetplan:
		if err := s.rollbackNetplan(ctx, plan); err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
	default:
		steps, err := network.RollbackSteps(plan)
		if err != nil {
			return reject(ErrorUnsupported, err.Error())
		}
		for _, step := range steps {
			if output, err := runNmcli(ctx, step); err != nil {
				return reject(ErrorExecFailed, fmt.Sprintf("%s: %s", err, output))
			}
		}
	}
	_ = s.disarmRollback(ctx, plan.ID)
	_ = network.RemovePlan(network.RollbackDir, plan.ID)
	return networkResponse(s.adapterProfiles(ctx, plan.Adapter), "the change was rolled back on request", nil)
}

// armRollback starts a transient systemd timer.
func (s *Server) armRollback(ctx context.Context, plan network.RollbackPlan, window time.Duration) error {
	return s.armTimer(ctx, network.RollbackUnitName(plan.ID), window, "-rollback", plan.ID)
}

// armTimer starts a transient unit that, after the given time, calls the
// helper in rollback mode.
func (s *Server) armTimer(ctx context.Context, unit string, window time.Duration,
	flag, id string) error {
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return fmt.Errorf("a host without systemd-run cannot arm a rollback")
	}
	binary, err := helperPath()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, systemdRun,
		"--collect", "--quiet",
		"--unit="+unit,
		"--description=Flotestro: rollback of a change",
		"--on-active="+strconv.Itoa(int(window.Seconds())),
		"--timer-property=AccuracySec=1s",
		"--", binary, flag, id)
	cmd.Env = toolEnvironment()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// disarmRollback stops the rollback timer of a network change.
func (s *Server) disarmRollback(ctx context.Context, id string) error {
	return s.disarmTimer(ctx, network.RollbackUnitName(id))
}

// disarmTimer stops the transient rollback unit.
func (s *Server) disarmTimer(ctx context.Context, unit string) error {
	for _, name := range []string{unit + ".timer", unit + ".service"} {
		cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", name)
		cmd.Env = toolEnvironment()
		_ = cmd.Run()
	}
	return nil
}

// validPlanIdentifier allows only characters that cannot lead a path outside
// the plan directory.
func validPlanIdentifier(id string) bool {
	return network.ValidPlanID(id)
}

// adapterProfiles collects the profiles the given mechanism describes.
func (s *Server) adapterProfiles(ctx context.Context, adapter string) []network.Profile {
	switch adapter {
	case network.AdapterNmstate:
		state, err := s.readNmstate(ctx)
		if err != nil {
			return nil
		}
		return state.Profiles()
	case network.AdapterNetplan:
		config, err := s.readNetplanConfig(ctx)
		if err != nil {
			return nil
		}
		return config.Profiles()
	}
	return s.readProfiles(ctx)
}

// adapterProfile finds the profile of an interface in the given mechanism.
func (s *Server) adapterProfile(ctx context.Context, adapter, iface string) (string, network.Profile, error) {
	if iface == "" {
		return "", network.Profile{}, fmt.Errorf("the operation needs an interface name")
	}
	// The name goes into the documents the mechanisms read; a name the
	// kernel would not accept is a flaw of the order, whatever it looks like.
	if err := network.ValidateInterfaceName(iface); err != nil {
		return "", network.Profile{}, err
	}
	switch adapter {
	case network.AdapterNmstate:
		state, err := s.readNmstate(ctx)
		if err != nil {
			return "", network.Profile{}, err
		}
		profile, err := state.Profile(iface)
		return iface, profile, err
	case network.AdapterNetplan:
		config, err := s.readNetplanConfig(ctx)
		if err != nil {
			return "", network.Profile{}, err
		}
		profile, err := config.Profile(iface)
		return iface, profile, err
	}
	return s.interfaceProfile(ctx, iface)
}

// readProfiles collects the NetworkManager profiles together with their
// settings.
func (s *Server) readProfiles(ctx context.Context) []network.Profile {
	output, err := nmcliOutput(ctx, "-t", "-f", "NAME,UUID,DEVICE,TYPE,STATE", "connection", "show")
	if err != nil {
		return nil
	}
	var profiles []network.Profile
	for _, connection := range network.ParseConnections(output) {
		settings, err := nmcliOutput(ctx, "-t", "-f",
			strings.Join(network.ProfileFields, ","), "connection", "show", connection.Name)
		if err != nil {
			continue
		}
		profile := network.ParseProfile(settings)
		if profile.Connection == "" {
			profile.Connection = connection.Name
		}
		if profile.Interface == "" {
			profile.Interface = connection.Device
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

// interfaceProfile finds the profile active on an interface.
func (s *Server) interfaceProfile(ctx context.Context, iface string) (string, network.Profile, error) {
	if iface == "" {
		return "", network.Profile{}, fmt.Errorf("the operation needs an interface name")
	}
	output, err := nmcliOutput(ctx, "-t", "-f", "NAME,UUID,DEVICE,TYPE,STATE", "connection", "show")
	if err != nil {
		return "", network.Profile{}, fmt.Errorf("reading the connections: %w", err)
	}
	connection := network.DeviceConnection(network.ParseConnections(output), iface)
	if connection == nil {
		return "", network.Profile{}, fmt.Errorf(
			"the interface %s has no NetworkManager profile; the panel does not create new profiles here", iface)
	}
	settings, err := nmcliOutput(ctx, "-t", "-f",
		strings.Join(network.ProfileFields, ","), "connection", "show", connection.Name)
	if err != nil {
		return "", network.Profile{}, fmt.Errorf("reading the profile %s: %w", connection.Name, err)
	}
	profile := network.ParseProfile(settings)
	if profile.Connection == "" {
		profile.Connection = connection.Name
	}
	return connection.Name, profile, nil
}

func rollbackWindow(seconds uint32) time.Duration {
	if seconds == 0 {
		return rollbackDefault
	}
	window := time.Duration(seconds) * time.Second
	if window < rollbackMin {
		return rollbackMin
	}
	if window > rollbackMax {
		return rollbackMax
	}
	return window
}

// rollbackIdentifier builds the name of a plan from the moment it was created.
func rollbackIdentifier() string {
	return "w" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
}

func runNmcli(ctx context.Context, arguments []string) (string, error) {
	cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	cmd.Env = toolEnvironment()
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func nmcliOutput(ctx context.Context, arguments ...string) (string, error) {
	cmd := exec.CommandContext(ctx, network.NmcliPath, arguments...)
	cmd.Env = toolEnvironment()
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func toolEnvironment() []string {
	return []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
}

// encodeProfiles turns the profiles into the body of the answer.
func encodeProfiles(profiles []network.Profile) ([]byte, error) {
	return json.Marshal(struct {
		Profiles []network.Profile `json:"profiles"`
	}{profiles})
}

func networkResponse(profiles []network.Profile, message string,
	plan *network.RollbackPlan) *helperv1.HelperResponse {
	encoded, err := encodeProfiles(profiles)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	result := &helperv1.NetworkResult{Profiles: encoded, Message: message}
	if plan != nil {
		result.RollbackId = plan.ID
		result.RollbackDeadline = plan.Deadline.Format(time.RFC3339)
	}
	return &helperv1.HelperResponse{Accepted: true, NetworkResult: result}
}

// networkErrorResponse describes a change that failed but left the rollback
// armed. The operator is to know that the host will come back on its own.
func networkErrorResponse(plan network.RollbackPlan, message string) *helperv1.HelperResponse {
	response := reject(ErrorExecFailed, message)
	response.NetworkResult = &helperv1.NetworkResult{
		Message:          message,
		RollbackId:       plan.ID,
		RollbackDeadline: plan.Deadline.Format(time.RFC3339),
	}
	return response
}

// helperPath returns the path of the helper's own binary.
func helperPath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("the helper path was not determined: %w", err)
	}
	return filepath.EvalSymlinks(path)
}

// RollbackFromPlan restores the state from before a network change.
func RollbackFromPlan(ctx context.Context, id string) error {
	plan, err := network.LoadPlan(network.RollbackDir, id)
	if err != nil {
		return fmt.Errorf("the rollback plan %s: %w", id, err)
	}
	// The unit that calls this has no clock of its own; a tool that hangs here
	// would leave a rollback that neither finished nor failed.
	ctx, cancel := context.WithTimeout(ctx, rollbackToolLimit)
	defer cancel()
	switch plan.Adapter {
	case network.AdapterNmstate:
		if err := rollbackNmstate(ctx, plan); err != nil {
			_ = network.SetAsideFailedPlan(network.RollbackDir, id)
			return err
		}
		return network.RemovePlan(network.RollbackDir, id)
	case network.AdapterNetplan:
		// The trial, if it still runs, is not held by this process: the file is
		// restored and the configuration on disk applied, which is the state
		// netplan's own revert also returns to.
		if err := restoreNetplanFile(ctx, plan, true); err != nil {
			_ = network.SetAsideFailedPlan(network.RollbackDir, id)
			return err
		}
		return network.RemovePlan(network.RollbackDir, id)
	}
	steps, err := network.RollbackSteps(plan)
	if err != nil {
		_ = network.SetAsideFailedPlan(network.RollbackDir, id)
		return err
	}
	for _, step := range steps {
		if output, err := runNmcli(ctx, step); err != nil {
			// A plan whose timer has already fired is dead also when the rollback
			// failed.
			_ = network.SetAsideFailedPlan(network.RollbackDir, id)
			return fmt.Errorf("%s: %w: %s", strings.Join(step, " "), err, output)
		}
	}
	return network.RemovePlan(network.RollbackDir, id)
}

// The nmstate path.

// readNmstate reads the whole nmstate state.
func (s *Server) readNmstate(ctx context.Context) (network.NmstateState, error) {
	binary := network.NmstatectlBinary(network.Exists)
	if binary == "" {
		return network.NmstateState{}, fmt.Errorf("this host has no nmstatectl")
	}
	arguments := network.NmstateShowArguments(binary)
	output, err := toolOutput(ctx, arguments[0], arguments[1:]...)
	if err != nil {
		return network.NmstateState{}, fmt.Errorf("nmstatectl show: %w", err)
	}
	return network.ParseNmstateState([]byte(output))
}

// changeNmstate applies the document of the plan under nmstate's checkpoint.
func (s *Server) changeNmstate(ctx context.Context, action *helperv1.NetworkRequest,
	change network.Plan) *helperv1.HelperResponse {
	binary := network.NmstatectlBinary(network.Exists)
	if binary == "" {
		return reject(ErrorUnsupported, "this host has no nmstatectl")
	}
	// The way back is the same function the other way round: the document
	// carrying the interface from the desired state to the current one.
	previous, err := nmstatePreviousDocument(change)
	if err != nil {
		return reject(ErrorUnsupported, "the rollback cannot be assembled: "+err.Error())
	}

	plan := network.RollbackPlan{
		ID:        rollbackIdentifier(),
		Profile:   rollbackProfile(change),
		Interface: changedInterface(action, change),
		CreatedAt: time.Now().UTC(),
		Reason:    action.GetReason(),
		Adapter:   network.AdapterNmstate,
		Kind:      change.Operation,
	}
	window := rollbackWindow(action.GetRollbackSeconds())
	plan.Deadline = plan.CreatedAt.Add(window)

	if err := network.SavePlan(network.RollbackDir, plan); err != nil {
		return reject(ErrorExecFailed, "writing the rollback plan: "+err.Error())
	}
	previousPath, _ := network.PreviousStatePath(network.RollbackDir, plan.ID)
	desiredPath, _ := network.DesiredStatePath(network.RollbackDir, plan.ID)
	if err := network.SaveState(previousPath, previous); err != nil {
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, "writing the state from before the change: "+err.Error())
	}
	if err := network.SaveState(desiredPath, change.Document); err != nil {
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, "writing the desired state: "+err.Error())
	}

	arguments := network.NmstateApplyArguments(binary, desiredPath, int(window.Seconds()))
	if output, err := runTool(ctx, arguments); err != nil {
		// nmstate rolls a failed apply back on its own before returning;
		// there is no armed change left to keep a plan for.
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, fmt.Sprintf("nmstatectl apply: %s: %s", err, output))
	}
	return networkResponse(s.adapterProfiles(ctx, network.AdapterNmstate),
		fmt.Sprintf("the change was applied; nmstate rolls it back at %s unless the agent confirms connectivity",
			plan.Deadline.Format(time.RFC3339)), &plan)
}

// commitNmstate keeps the change after the connectivity confirmation. A nil
// answer means the commit went through.
func (s *Server) commitNmstate(ctx context.Context, plan network.RollbackPlan) *helperv1.HelperResponse {
	binary := network.NmstatectlBinary(network.Exists)
	if binary == "" {
		return reject(ErrorUnsupported, "this host has no nmstatectl")
	}
	if output, err := runTool(ctx, network.NmstateCommitArguments(binary)); err != nil {
		// A commit that finds no checkpoint arrives after nmstate rolled the change
		// back: the host is in the state from before, and the plan has nothing left
		// to guard.
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, fmt.Sprintf(
			"nmstatectl commit: %s: %s; the change was rolled back by nmstate's checkpoint", err, output))
	}
	return nil
}

// rollbackNmstate returns to the state from before the change: through the
// checkpoint while it is open, through the kept document once it is gone.
func rollbackNmstate(ctx context.Context, plan network.RollbackPlan) error {
	binary := network.NmstatectlBinary(network.Exists)
	if binary == "" {
		return fmt.Errorf("this host has no nmstatectl")
	}
	if _, err := runTool(ctx, network.NmstateRollbackArguments(binary)); err == nil {
		return nil
	}
	previousPath, err := network.PreviousStatePath(network.RollbackDir, plan.ID)
	if err != nil {
		return err
	}
	if !network.Exists(previousPath) {
		return fmt.Errorf("the checkpoint is gone and the plan %s has no state from before the change", plan.ID)
	}
	if output, err := runTool(ctx, network.NmstateRestoreArguments(binary, previousPath)); err != nil {
		return fmt.Errorf("nmstatectl apply of the previous state: %w: %s", err, output)
	}
	return nil
}

// The netplan path.

// netplanRevertMargin is how much later than netplan's own revert the
// transient timer restores the file: the timer is the second line, not a race
// with the first.
const netplanRevertMargin = 30 * time.Second

// netplanPromptWait bounds the wait for the confirmation prompt: the change is
// on the host when it appears, and the connectivity check makes sense only
// from then.
const netplanPromptWait = 45 * time.Second

// netplanTrial is a running "netplan try" together with what the helper
// knows about it.
type netplanTrial struct {
	id  string
	cmd *exec.Cmd
	// terminal is the helper's end of the trial's terminal: the prompt is read
	// from it and the confirmation written to it.
	terminal *os.File
	started  time.Time
	// prompt is closed when netplan asks for the confirmation, or when its
	// output ends without asking.
	prompt chan struct{}
	// done is closed when the process exits; settled when the exit handler
	// finished its work after that - the file restored or the confirmation
	// recorded.
	done    chan struct{}
	settled chan struct{}

	mu         sync.Mutex
	confirmed  bool
	reverted   bool
	killed     bool
	exitErr    error
	restoreErr error
}

func (t *netplanTrial) wasReverted() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reverted
}

// netplanTrialSet holds the trials of this process.
type netplanTrialSet struct {
	sync.Mutex
	byID map[string]*netplanTrial
}

var netplanTrials = netplanTrialSet{byID: map[string]*netplanTrial{}}

func (r *netplanTrialSet) get(id string) *netplanTrial {
	r.Lock()
	defer r.Unlock()
	return r.byID[id]
}

func (r *netplanTrialSet) put(trial *netplanTrial) {
	r.Lock()
	defer r.Unlock()
	// Trials that ended long ago are only a memory of an answer; an hour is
	// more than any confirmation can be late by.
	for id, old := range r.byID {
		if time.Since(old.started) > time.Hour {
			delete(r.byID, id)
		}
	}
	r.byID[trial.id] = trial
}

// readNetplanConfig reads the merged configuration: through "netplan get"
// where netplan has it, otherwise by merging the files the way netplan does.
func (s *Server) readNetplanConfig(ctx context.Context) (network.NetplanConfig, error) {
	if !network.Exists(network.NetplanPath) {
		return network.NetplanConfig{}, fmt.Errorf("this host has no netplan")
	}
	arguments := network.NetplanGetArguments()
	if output, err := toolOutput(ctx, arguments[0], arguments[1:]...); err == nil {
		return network.ParseNetplan(output)
	}
	entries, err := os.ReadDir(network.NetplanDir)
	if err != nil {
		return network.NetplanConfig{}, fmt.Errorf("reading %s: %w", network.NetplanDir, err)
	}
	var documents []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		content, err := network.LoadState(filepath.Join(network.NetplanDir, entry.Name()))
		if err != nil {
			return network.NetplanConfig{}, err
		}
		documents = append(documents, content)
	}
	return network.MergeNetplanDocuments(documents...)
}

// changeNetplan writes the panel's file, validates it and starts the trial.
func (s *Server) changeNetplan(ctx context.Context, action *helperv1.NetworkRequest,
	change network.Plan) *helperv1.HelperResponse {
	if !network.Exists(network.NetplanPath) {
		return reject(ErrorUnsupported, "this host has no netplan")
	}
	previous, err := network.LoadState(network.NetplanManagedFile)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return reject(ErrorExecFailed, "reading the panel's netplan file: "+err.Error())
	}

	plan := network.RollbackPlan{
		ID:             rollbackIdentifier(),
		Profile:        rollbackProfile(change),
		Interface:      changedInterface(action, change),
		CreatedAt:      time.Now().UTC(),
		Reason:         action.GetReason(),
		Adapter:        network.AdapterNetplan,
		Kind:           change.Operation,
		PreviousExists: existed,
	}
	window := rollbackWindow(action.GetRollbackSeconds())
	plan.Deadline = plan.CreatedAt.Add(window)

	if err := network.SavePlan(network.RollbackDir, plan); err != nil {
		return reject(ErrorExecFailed, "writing the rollback plan: "+err.Error())
	}
	previousPath, _ := network.PreviousStatePath(network.RollbackDir, plan.ID)
	if err := network.SaveState(previousPath, previous); err != nil {
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, "writing the file from before the change: "+err.Error())
	}

	// The file goes to disk first and netplan validates it before anything
	// runs: a rejected file is put back and nothing was applied.
	if err := network.SaveState(network.NetplanManagedFile, change.Document); err != nil {
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, "writing the panel's netplan file: "+err.Error())
	}
	if output, err := runTool(ctx, network.NetplanGenerateArguments()); err != nil {
		_ = restoreNetplanFile(ctx, plan, false)
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorMalformed, fmt.Sprintf("netplan rejected the configuration: %s: %s", err, output))
	}

	// The timer is the second line: it restores the file and applies the
	// configuration on disk after netplan's own revert had its turn, also when
	// this process is gone by then.
	if err := s.armTimer(ctx, network.RollbackUnitName(plan.ID), window+netplanRevertMargin,
		"-rollback", plan.ID); err != nil {
		_ = restoreNetplanFile(ctx, plan, false)
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, "arming the rollback: "+err.Error())
	}

	trial, err := s.startNetplanTrial(plan, window)
	if err != nil {
		_ = s.disarmRollback(ctx, plan.ID)
		_ = restoreNetplanFile(ctx, plan, false)
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
		return reject(ErrorExecFailed, "netplan try: "+err.Error())
	}
	if !trial.awaitPrompt(netplanPromptWait) {
		select {
		case <-trial.done:
			// The trial ended before asking: netplan could not apply the configuration
			// and reverted.
			<-trial.settled
			return reject(ErrorExecFailed, fmt.Sprintf("netplan try ended before the change was applied: %v", trial.exitErr))
		default:
			// Still applying. The deadline stands, and the connectivity check
			// will find the new state or the reverted one.
		}
	}
	return networkResponse(s.adapterProfiles(ctx, network.AdapterNetplan),
		fmt.Sprintf("the change was applied; netplan reverts it at %s unless the agent confirms connectivity",
			plan.Deadline.Format(time.RFC3339)), &plan)
}

// openTerminal opens a pseudo-terminal pair: the helper's end and the end
// the trial gets as its standard streams.
func openTerminal() (*os.File, *os.File, error) {
	masterFD, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("opening /dev/ptmx: %w", err)
	}
	number, err := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
	if err == nil {
		err = unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0)
	}
	if err == nil {
		// Non-blocking: the runtime then polls the descriptor, so closing it
		// wakes up a read waiting on it instead of waiting for that read.
		err = unix.SetNonblock(masterFD, true)
	}
	if err != nil {
		_ = unix.Close(masterFD)
		return nil, nil, fmt.Errorf("preparing the terminal: %w", err)
	}
	master := os.NewFile(uintptr(masterFD), "/dev/ptmx")
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("opening the terminal: %w", err)
	}
	return master, slave, nil
}

// startNetplanTrial runs "netplan try" on a terminal the helper holds, and
// keeps the helper alive as long as the trial runs.
func (s *Server) startNetplanTrial(plan network.RollbackPlan, window time.Duration) (*netplanTrial, error) {
	arguments := network.NetplanTryArguments(int(window.Seconds()))
	master, slave, err := openTerminal()
	if err != nil {
		return nil, err
	}
	// The trial outlives the request that started it, so it runs without the
	// request context: cancelling that would kill the trial mid-way.
	cmd := exec.Command(arguments[0], arguments[1:]...)
	cmd.Env = toolEnvironment()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	// The trial leads a session of its own with the terminal as its controlling
	// one: that is what makes the terminal its standard input in the sense
	// netplan checks, and what carries the signal of Ctrl-C to it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		_ = master.Close()
		return nil, err
	}
	// Only the trial holds its end from now on: its exit is then the end of
	// the output on the other one.
	_ = slave.Close()
	trial := &netplanTrial{
		id: plan.ID, cmd: cmd, terminal: master, started: time.Now(),
		prompt: make(chan struct{}), done: make(chan struct{}), settled: make(chan struct{}),
	}
	netplanTrials.put(trial)

	go func() {
		lines := bufio.NewReader(master)
		seen := false
		for {
			line, err := lines.ReadString('\n')
			if !seen && network.NetplanPromptSeen(line) {
				seen = true
				close(trial.prompt)
			}
			if err != nil {
				if !seen {
					close(trial.prompt)
				}
				return
			}
		}
	}()

	// The watchdog: netplan reverts and exits on its own clock, and a trial still
	// there long after that clock is a trial that lost it.
	go func() {
		select {
		case <-trial.done:
		case <-time.After(window + netplanRevertMargin + netplanPromptWait):
			trial.mu.Lock()
			trial.killed = true
			trial.mu.Unlock()
			_ = cmd.Process.Kill()
		}
	}()

	// The helper counts idleness from its connections; a trial waiting for
	// its confirmation is work in flight and keeps the process here.
	s.active.Add(1)
	go func() {
		defer s.active.Done()
		defer close(trial.settled)
		exitErr := cmd.Wait()
		_ = master.Close()
		trial.mu.Lock()
		trial.exitErr = exitErr
		confirmed, killed := trial.confirmed, trial.killed
		if !confirmed {
			trial.reverted = true
		}
		trial.mu.Unlock()
		close(trial.done)
		if confirmed {
			return
		}
		// netplan reverted the running state; the file on disk still says the new
		// configuration and would come back at the next apply or reboot.
		background, cancel := context.WithTimeout(context.Background(), rollbackToolLimit)
		defer cancel()
		err := restoreNetplanFile(background, plan, killed)
		trial.mu.Lock()
		trial.restoreErr = err
		trial.mu.Unlock()
		if err != nil {
			if s.log != nil {
				s.log.Error("the panel's netplan file was not restored after the revert", "plan", plan.ID, "err", err)
			}
			return
		}
		_ = s.disarmRollback(background, plan.ID)
		_ = network.RemovePlan(network.RollbackDir, plan.ID)
	}()
	return trial, nil
}

// awaitPrompt waits until netplan asks for the confirmation, the process
// ends, or the wait runs out. It says whether the prompt was seen.
func (t *netplanTrial) awaitPrompt(limit time.Duration) bool {
	select {
	case <-t.prompt:
		select {
		case <-t.done:
			return false
		default:
			return true
		}
	case <-t.done:
		return false
	case <-time.After(limit):
		return false
	}
}

// confirmNetplan hands the trial its confirmation. A nil answer means
// netplan kept the change.
func (s *Server) confirmNetplan(ctx context.Context, plan network.RollbackPlan) *helperv1.HelperResponse {
	trial := netplanTrials.get(plan.ID)
	if trial == nil {
		// The trial belongs to a helper process that is gone.
		return reject(ErrorExecFailed,
			"the netplan trial is no longer held by the helper; netplan reverts the change on its own")
	}
	if time.Now().After(plan.Deadline) {
		return reject(ErrorExecFailed, "the trial window has passed; netplan reverts the change on its own")
	}
	trial.mu.Lock()
	if trial.reverted {
		trial.mu.Unlock()
		return reject(ErrorExecFailed, "the change was reverted by netplan before the confirmation arrived")
	}
	// The confirmation is one newline on the trial's terminal.
	_, err := io.WriteString(trial.terminal, "\n")
	if err == nil {
		trial.confirmed = true
	}
	trial.mu.Unlock()
	if err != nil {
		return reject(ErrorExecFailed, "confirming the netplan trial: "+err.Error())
	}
	select {
	case <-trial.done:
	case <-time.After(time.Minute):
		return reject(ErrorExecFailed, "netplan try did not end after the confirmation")
	case <-ctx.Done():
		return reject(ErrorTimeout, "the confirmation was cut short")
	}
	if trial.exitErr != nil {
		return reject(ErrorExecFailed, "netplan try ended with an error after the confirmation: "+trial.exitErr.Error())
	}
	_ = s.disarmRollback(ctx, plan.ID)
	return nil
}

// rollbackNetplan returns to the state from before the change on request.
func (s *Server) rollbackNetplan(ctx context.Context, plan network.RollbackPlan) error {
	trial := netplanTrials.get(plan.ID)
	if trial == nil {
		return restoreNetplanFile(ctx, plan, true)
	}
	select {
	case <-trial.done:
	default:
		_ = trial.cmd.Process.Signal(syscall.SIGINT)
		select {
		case <-trial.done:
		case <-time.After(30 * time.Second):
			trial.mu.Lock()
			trial.killed = true
			trial.mu.Unlock()
			_ = trial.cmd.Process.Kill()
			<-trial.done
		}
	}
	<-trial.settled
	trial.mu.Lock()
	reverted, restoreErr := trial.reverted, trial.restoreErr
	trial.mu.Unlock()
	if reverted {
		return restoreErr
	}
	// The trial kept the change: the file goes back and the configuration on
	// disk is applied.
	return restoreNetplanFile(ctx, plan, true)
}

// restoreNetplanFile puts the panel's file back as it was before the change -
// or removes it, when there was none - and regenerates the configuration for
// the layer below.
func restoreNetplanFile(ctx context.Context, plan network.RollbackPlan, apply bool) error {
	previousPath, err := network.PreviousStatePath(network.RollbackDir, plan.ID)
	if err != nil {
		return err
	}
	if plan.PreviousExists {
		previous, err := network.LoadState(previousPath)
		if err != nil {
			return fmt.Errorf("the file from before the change: %w", err)
		}
		if err := network.SaveState(network.NetplanManagedFile, previous); err != nil {
			return err
		}
	} else if err := os.Remove(network.NetplanManagedFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	if output, err := runTool(ctx, network.NetplanGenerateArguments()); err != nil {
		return fmt.Errorf("netplan generate after the restore: %w: %s", err, output)
	}
	if apply {
		if output, err := runTool(ctx, network.NetplanApplyArguments()); err != nil {
			return fmt.Errorf("netplan apply after the restore: %w: %s", err, output)
		}
	}
	return nil
}

// The layered path: a bond, a bridge or a VLAN.

// networkSnapshot reads the state a layered plan is computed against: the
// interfaces, their layering and the channel the panel comes through.
func (s *Server) networkSnapshot(ctx context.Context, managementAddress string) (network.Snapshot, error) {
	binary := network.ToolPath(network.IPPaths, network.Exists)
	if binary == "" {
		return network.Snapshot{}, fmt.Errorf("this host has no iproute2 (ip) binary")
	}
	run := func(arguments []string) (string, error) {
		return toolOutput(ctx, arguments[0], arguments[1:]...)
	}
	output, err := toolOutput(ctx, binary, "-j", "-d", "addr", "show")
	if err != nil {
		return network.Snapshot{}, fmt.Errorf("ip addr: %w", err)
	}
	interfaces, err := network.ParseInterfaces(output)
	if err != nil {
		return network.Snapshot{}, err
	}
	snapshot := network.Snapshot{Interfaces: interfaces, ObservedAt: time.Now().UTC()}
	network.ReadLayering(&snapshot, run)
	if snapshot.LayeringUnavailableReason != "" {
		// Without the layering every refusal about a relation would be
		// silence, and silence here reads as "nothing is in the way".
		return network.Snapshot{}, fmt.Errorf("the layering of this host was not read: %s",
			snapshot.LayeringUnavailableReason)
	}
	network.ReadIPv6(&snapshot)
	network.MarkManagementChannel(&snapshot, managementAddress)
	return snapshot, nil
}

// adapterLinkPlan computes the layered plan and attaches the document the
// mechanism will apply, the way adapterPlan does for an address change.
func (s *Server) adapterLinkPlan(ctx context.Context, adapter string,
	action *helperv1.NetworkRequest, snapshot network.Snapshot) network.Plan {
	var plan network.Plan
	if networkChangeKind(action) == network.PlanLinkRemove {
		plan = network.ComputeLinkRemoval(snapshot, adapter, action.GetInterface())
	} else {
		plan = network.ComputeLink(snapshot, adapter, linkSpecOf(action.GetLink()))
	}
	if plan.Refusal != "" || plan.DesiredLink == nil || plan.Action == network.PlanNoChange {
		plan.Attach(adapter, "")
		return plan
	}
	var document string
	var err error
	switch adapter {
	case network.AdapterNmstate:
		document, err = network.NmstateLinkDocument(*plan.CurrentLink, *plan.DesiredLink)
	case network.AdapterNetplan:
		config, readErr := s.readNetplanConfig(ctx)
		if readErr != nil {
			plan.Refuse(readErr.Error())
			plan.Attach(adapter, "")
			return plan
		}
		managed, _ := network.LoadState(network.NetplanManagedFile)
		document, err = network.NetplanManagedLinkDocument(managed, config, plan)
	}
	if err != nil {
		// A layer the mechanism cannot express is a refusal the operator
		// sees in the plan, and it keeps its own code where it has one.
		var refusal *network.LinkRefusal
		if errors.As(err, &refusal) {
			plan.RefuseWith(refusal.Code, refusal.Reason)
		} else {
			plan.Refuse(err.Error())
		}
		plan.Attach(adapter, "")
		return plan
	}
	plan.Attach(adapter, document)
	return plan
}

// changeNetworkLink builds, changes or removes a layered interface.
func (s *Server) changeNetworkLink(ctx context.Context, adapter string,
	action *helperv1.NetworkRequest) *helperv1.HelperResponse {
	if action.GetOperation() == helperv1.NetworkRequest_OPERATION_APPLY_LINK &&
		action.GetLink() == nil {
		return reject(ErrorMalformed, "a layered change requires the description of the layer")
	}
	snapshot, err := s.networkSnapshot(ctx, action.GetManagementAddress())
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	now := s.adapterLinkPlan(ctx, adapter, action, snapshot)
	if expected := action.GetPlanHash(); expected != "" && now.PlanHash != expected {
		return reject(ErrorPreconditionFailed,
			"the layering of "+now.Interface+" changed since the planning; the change needs a new plan")
	}
	if now.Refusal != "" {
		// A typed refusal keeps its own code: "malformed" would tell the
		// operator nothing about which relation stood in the way.
		code := now.RefusalCode
		if code == "" {
			code = ErrorMalformed
		}
		return reject(code, now.Refusal)
	}
	if now.Action == network.PlanNoChange {
		return networkResponse(s.adapterProfiles(ctx, adapter),
			"the interface "+now.Interface+" is already in the ordered state", nil)
	}

	switch adapter {
	case network.AdapterNmstate:
		return s.changeNmstate(ctx, action, now)
	case network.AdapterNetplan:
		return s.changeNetplan(ctx, action, now)
	}
	// The mechanism was already refused inside the plan; this is the case the
	// plan itself could not reach, and it refuses rather than falling back to a
	// profile-by-profile write.
	refusal := network.LayerAdapterRefusal(adapter)
	if refusal == nil {
		return reject(ErrorUnsupported, "this host has no mechanism that writes layered interfaces")
	}
	return reject(refusal.Code, refusal.Reason)
}

// nmstatePreviousDocument assembles the document that carries the host back to
// the state from before the change: the same function the change used, with
// the two states swapped.
func nmstatePreviousDocument(change network.Plan) (string, error) {
	if change.CurrentLink != nil && change.DesiredLink != nil {
		return network.NmstateLinkDocument(*change.DesiredLink, *change.CurrentLink)
	}
	if change.Current == nil || change.Desired == nil {
		return "", fmt.Errorf("a change without the states to go back to")
	}
	return network.NmstateDocument(change.Operation, *change.Desired, *change.Current)
}

// rollbackProfile is the profile a rollback plan carries.
func rollbackProfile(change network.Plan) network.Profile {
	if change.Current == nil {
		return network.Profile{}
	}
	return *change.Current
}

// changedInterface names the interface a rollback plan is about.
func changedInterface(action *helperv1.NetworkRequest, change network.Plan) string {
	if change.Interface != "" {
		return change.Interface
	}
	return action.GetInterface()
}
