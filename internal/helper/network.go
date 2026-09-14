package helper

import (
	"bufio"
	"context"
	"encoding/json"
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

// The range of the rollback clock. Too short gives the agent no chance to
// confirm connectivity, too long leaves the host cut off for quarters of an
// hour.
const (
	rollbackDefault = 120 * time.Second
	rollbackMin     = 30 * time.Second
	rollbackMax     = 15 * time.Minute
)

// rollbackToolLimit bounds the tools a rollback runs when the transient unit
// calls the helper directly: that call carries no deadline of its own.
const rollbackToolLimit = 5 * time.Minute

// applyNetwork handles changes of the network configuration.
//
// Every change is armed with a rollback before the host feels it: the helper
// saves the state from before the change and starts a transient systemd timer
// that restores that state. The timer is disarmed only by a confirmation from
// the agent that the host still talks to the panel. The opposite order would
// leave a window in which the host is already cut off and nothing saves it.
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
	}
	return reject(ErrorUnknownAction, "unknown network operation")
}

// networkGuard names the guard of a network operation. A read and a plan take
// none; a confirmation and a rollback change the armed timer and take it like
// the change itself.
func networkGuard(operation helperv1.NetworkRequest_Operation) string {
	switch operation {
	case helperv1.NetworkRequest_OPERATION_READ, helperv1.NetworkRequest_OPERATION_PLAN:
		return ""
	}
	return GuardNetwork
}

// planNetwork computes the difference between the profile found and the one
// requested, without touching the host. It recognizes the kind of change by
// the fields of the order.
func (s *Server) planNetwork(ctx context.Context, adapter string,
	action *helperv1.NetworkRequest) *helperv1.HelperResponse {
	profiles := s.adapterProfiles(ctx, adapter)
	_, profile, err := s.adapterProfile(ctx, adapter, action.GetInterface())
	if err != nil {
		return networkPlanResponse(profiles, network.RefusedPlan(action.GetInterface(),
			networkChangeKind(action), err.Error()))
	}
	return networkPlanResponse(profiles, s.adapterPlan(ctx, adapter, action, profile))
}

// adapterPlan computes the plan and attaches to it what the mechanism will
// apply: nothing for NetworkManager, which takes arguments, the nmstate
// document of the touched interface, or the panel's netplan file after the
// merge. The same function runs at planning and before the change, so the
// two fingerprints compare the same thing.
func (s *Server) adapterPlan(ctx context.Context, adapter string, action *helperv1.NetworkRequest,
	profile network.Profile) network.Plan {
	plan := networkPlan(action, profile)
	if plan.Refusal != "" || plan.Desired == nil {
		plan.Attach(adapter, "")
		return plan
	}
	var document string
	var err error
	switch adapter {
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
func networkPlan(action *helperv1.NetworkRequest, profile network.Profile) network.Plan {
	switch networkChangeKind(action) {
	case network.PlanProfile:
		return network.ComputeProfile(action.GetInterface(), profile, action.GetMethod(),
			action.GetAddresses(), action.GetGateway(), action.GetDns())
	case network.PlanRoutes:
		return network.ComputeRoutes(action.GetInterface(), profile, action.GetRoutes())
	default:
		return network.ComputeMTU(action.GetInterface(), profile, action.GetMtu())
	}
}

// networkChangeKind says which change the order describes. Mutating operations
// name it directly; the plan recognizes it by the fields, because one planning
// operation covers three kinds of change.
func networkChangeKind(action *helperv1.NetworkRequest) string {
	switch action.GetOperation() {
	case helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		return network.PlanProfile
	case helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES:
		return network.PlanRoutes
	case helperv1.NetworkRequest_OPERATION_SET_MTU:
		return network.PlanMTU
	}
	switch {
	case action.GetMethod() != "":
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
	message := "the change will not enter this host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == network.PlanNoChange:
		message = "the profile " + plan.Connection + " is already in the desired state"
	default:
		message = "the profile " + plan.Connection + ": " + strings.Join(plan.Changes, "; ")
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

	// A change approved on the basis of a plan is to enter the state the
	// operator looked at. A plan computed now with a different digest means the
	// profile changed since the planning - and that is a refusal, not a
	// warning.
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

	// The rollback plan is built from the state read before the change. It is
	// written to disk, because the helper ends its work after an idle period -
	// a timer in its memory would disappear together with the process.
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
		return network.RouteArguments(connection, action.GetRoutes())
	case helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		desired := network.Profile{
			Connection: connection,
			Method:     action.GetMethod(),
			Addresses:  action.GetAddresses(),
			Gateway:    action.GetGateway(),
			DNS:        action.GetDns(),
			// Routes, MTU and the rest of the resolver stay as they were: the
			// address profile is a separate operation and must not silently
			// erase settings the operator was never asked about.
			DNSSearch:     current.DNSSearch,
			IgnoreAutoDNS: current.IgnoreAutoDNS,
			Routes:        current.Routes,
			MTU:           current.MTU,
		}
		return network.ProfileArguments(desired)
	}
	return nil, fmt.Errorf("unknown network operation")
}

// confirmChange disarms the rollback after the agent confirmed connectivity.
//
// Each mechanism disarms its own watchdog: NetworkManager the transient
// timer, nmstate its checkpoint with a commit, netplan the waiting "netplan
// try" with the confirmation on its standard input.
func (s *Server) confirmChange(ctx context.Context, id string) *helperv1.HelperResponse {
	plan, err := network.LoadPlan(network.RollbackDir, id)
	if err != nil {
		// A missing plan means the rollback was already performed or already
		// disarmed. This is not an error of the order, but the operator is to
		// know about it.
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
//
// The timer lives outside the helper: the helper ends its work after an idle
// period, and the rollback has to fire also when nobody talks to it any more.
// The unit calls this same helper binary in rollback mode - the command does
// not come from the plan, so the plan cannot express anything else.
func (s *Server) armRollback(ctx context.Context, plan network.RollbackPlan, window time.Duration) error {
	return s.armTimer(ctx, network.RollbackUnitName(plan.ID), window, "-rollback", plan.ID)
}

// armTimer starts a transient unit that, after the given time, calls the
// helper in rollback mode.
//
// The unit calls the same binary that started the change and passes it only the
// identifier of the plan: the content of the rollback comes from the plan file,
// and a plan describes a state, not commands.
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

// adapterProfiles collects the profiles the given mechanism describes. An
// empty adapter means NetworkManager: the resolver module and older plans
// know no other.
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
// The name returned is what the messages call the profile: the connection
// name for NetworkManager, the interface itself elsewhere.
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
// The name is part of a file name and of a systemd unit name, so it has a
// narrow set of characters.
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
//
// The rollback unit has to call exactly the same program that started the
// change: a path looked up in PATH could point somewhere else in the meantime.
func helperPath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("the helper path was not determined: %w", err)
	}
	return filepath.EvalSymlinks(path)
}

// RollbackFromPlan restores the state from before a network change. Called by
// the transient systemd unit when nobody confirmed connectivity within the
// given window.
//
// The function works without the agent and without the panel: it is the last
// thing that works when a change cuts the host off from the world.
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
		// The trial, if it still runs, is not held by this process: the
		// file is restored and the configuration on disk applied, which is
		// the state netplan's own revert also returns to.
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
			// A plan whose timer has already fired is dead also when the
			// rollback failed. Left in the directory it would look like a
			// rollback still waiting for its moment.
			_ = network.SetAsideFailedPlan(network.RollbackDir, id)
			return fmt.Errorf("%s: %w: %s", strings.Join(step, " "), err, output)
		}
	}
	return network.RemovePlan(network.RollbackDir, id)
}

// The nmstate path.
//
// nmstate brings its own watchdog: "apply --no-commit --timeout N" opens a
// NetworkManager checkpoint that NetworkManager itself rolls back after N
// seconds unless somebody commits. Nothing of the helper has to survive for
// that, so no transient timer is armed here. The commit is the panel's
// confirmation of connectivity; the state from before the change is kept
// as a document next to the plan for the rollback on request after the
// checkpoint is gone.

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
	previous, err := network.NmstateDocument(change.Operation, *change.Desired, *change.Current)
	if err != nil {
		return reject(ErrorUnsupported, "the rollback cannot be assembled: "+err.Error())
	}

	plan := network.RollbackPlan{
		ID:        rollbackIdentifier(),
		Profile:   *change.Current,
		Interface: action.GetInterface(),
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
		// A commit that finds no checkpoint arrives after nmstate rolled the
		// change back: the host is in the state from before, and the plan
		// has nothing left to guard.
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
//
// netplan brings its own revert: "netplan try --timeout N" applies the
// configuration and, without a confirmation on its standard input within N
// seconds, returns the host to the running state from before. The helper
// keeps the trial process and hands it the confirmation after the agent
// checked the path to the panel. netplan's revert restores the running
// state, not the files: the panel's file is restored by the helper when the
// trial ends without a confirmation, and by the transient timer when the
// helper is no longer there to do it.
//
// The trial talks to a terminal, not to pipes: "netplan try" puts its
// standard input into character mode before it applies anything, and on a
// pipe that call fails and nothing is tried. The helper opens a
// pseudo-terminal, reads the prompt from one end and writes the newline of
// the confirmation to the same end.

// netplanRevertMargin is how much later than netplan's own revert the
// transient timer restores the file: the timer is the second line, not a
// race with the first.
const netplanRevertMargin = 30 * time.Second

// netplanPromptWait bounds the wait for the confirmation prompt: the change
// is on the host when it appears, and the connectivity check makes sense
// only from then.
const netplanPromptWait = 45 * time.Second

// netplanTrial is a running "netplan try" together with what the helper
// knows about it.
type netplanTrial struct {
	id  string
	cmd *exec.Cmd
	// terminal is the helper's end of the trial's terminal: the prompt is
	// read from it and the confirmation written to it. It stays open until
	// the trial exits - closing it earlier hangs the terminal up under the
	// trial, and the trial dies before it reads the confirmation.
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

// netplanTrialSet holds the trials of this process. The helper has no field
// for them: they are as long-lived as the process, and a trial the process
// no longer holds is handled by the timer, not by memory.
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
// where netplan has it, otherwise by merging the files the way netplan
// does.
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
		Profile:        *change.Current,
		Interface:      action.GetInterface(),
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
	// configuration on disk after netplan's own revert had its turn, also
	// when this process is gone by then.
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
			// The trial ended before asking: netplan could not apply the
			// configuration and reverted. The exit handler puts the file
			// back and disarms the timer.
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
	// request context: cancelling that would kill the trial mid-way. Its
	// clock is netplan's own timeout, and a watchdog below for a trial that
	// does not keep it.
	cmd := exec.Command(arguments[0], arguments[1:]...)
	cmd.Env = toolEnvironment()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	// The trial leads a session of its own with the terminal as its
	// controlling one: that is what makes the terminal its standard input in
	// the sense netplan checks, and what carries the signal of Ctrl-C to it.
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

	// The watchdog: netplan reverts and exits on its own clock, and a trial
	// still there long after that clock is a trial that lost it. It is
	// killed, and the exit handler then applies the configuration on disk,
	// because a killed trial reverted nothing.
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
		// netplan reverted the running state; the file on disk still says
		// the new configuration and would come back at the next apply or
		// reboot. A trial that had to be killed reverted nothing, so the
		// configuration on disk is applied too. The timer is disarmed only
		// after the file is back.
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
		// The trial belongs to a helper process that is gone. Nothing here
		// can reach its standard input: netplan reverts on its own and the
		// timer restores the file.
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
	// The confirmation is one newline on the trial's terminal. The lock is
	// held across the write and the mark, so the exit handler cannot take an
	// accepted trial for a reverted one. The terminal stays open: the exit
	// handler closes it once the trial is gone.
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
//
// A trial still waiting gets the signal Ctrl-C sends and reverts on it; its
// exit handler then restores the file. Without a trial in this process the
// file is restored and the configuration on disk applied.
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

// restoreNetplanFile puts the panel's file back as it was before the change
// - or removes it, when there was none - and regenerates the configuration
// for the layer below. With apply it also applies it.
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
