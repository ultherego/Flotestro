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

// applyNetwork handles changes of the network configuration.
//
// Every change is armed with a rollback before the host feels it: the helper
// saves the state from before the change and starts a transient systemd timer
// that restores that state. The timer is disarmed only by a confirmation from
// the agent that the host still talks to the panel. The opposite order would
// leave a window in which the host is already cut off and nothing saves it.
func (s *Server) applyNetwork(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.NetworkRequest) *helperv1.HelperResponse {
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

	if !network.Istnieje(network.SciezkaNmcli) {
		if action.GetOperation() == helperv1.NetworkRequest_OPERATION_PLAN {
			// A missing NetworkManager is an answer of the plan, not a read
			// error: the campaign is to see this host as a refusal.
			return networkPlanResponse(nil, network.OdmowaPlanu(action.GetInterface(),
				networkChangeKind(action),
				"this host has no NetworkManager; the network configuration is read-only here"))
		}
		return reject(ErrorUnsupported,
			"this host has no NetworkManager; the network configuration is read-only here")
	}

	switch action.GetOperation() {
	case helperv1.NetworkRequest_OPERATION_READ:
		return networkResponse(s.readProfiles(actionCtx), "", nil)

	case helperv1.NetworkRequest_OPERATION_PLAN:
		return s.planNetwork(actionCtx, action)

	case helperv1.NetworkRequest_OPERATION_CONFIRM:
		return s.confirmChange(actionCtx, action.GetRollbackId())

	case helperv1.NetworkRequest_OPERATION_ROLLBACK:
		return s.rollbackNow(actionCtx, action.GetRollbackId())

	case helperv1.NetworkRequest_OPERATION_SET_MTU,
		helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES,
		helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		return s.changeNetwork(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "unknown network operation")
}

// planNetwork computes the difference between the profile found and the one
// requested, without touching the host. It recognizes the kind of change by
// the fields of the order.
func (s *Server) planNetwork(ctx context.Context, action *helperv1.NetworkRequest) *helperv1.HelperResponse {
	profiles := s.readProfiles(ctx)
	_, profile, err := s.interfaceProfile(ctx, action.GetInterface())
	if err != nil {
		return networkPlanResponse(profiles, network.OdmowaPlanu(action.GetInterface(),
			networkChangeKind(action), err.Error()))
	}
	return networkPlanResponse(profiles, networkPlan(action, profile))
}

// networkPlan computes the plan for the change described by the order against
// the profile found.
func networkPlan(action *helperv1.NetworkRequest, profile network.Profil) network.Plan {
	switch networkChangeKind(action) {
	case network.PlanProfil:
		return network.ZaplanujProfil(action.GetInterface(), profile, action.GetMethod(),
			action.GetAddresses(), action.GetGateway(), action.GetDns())
	case network.PlanTrasy:
		return network.ZaplanujTrasy(action.GetInterface(), profile, action.GetRoutes())
	default:
		return network.ZaplanujMTU(action.GetInterface(), profile, action.GetMtu())
	}
}

// networkChangeKind says which change the order describes. Mutating operations
// name it directly; the plan recognizes it by the fields, because one planning
// operation covers three kinds of change.
func networkChangeKind(action *helperv1.NetworkRequest) string {
	switch action.GetOperation() {
	case helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		return network.PlanProfil
	case helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES:
		return network.PlanTrasy
	case helperv1.NetworkRequest_OPERATION_SET_MTU:
		return network.PlanMTU
	}
	switch {
	case action.GetMethod() != "":
		return network.PlanProfil
	case action.Routes != nil:
		return network.PlanTrasy
	default:
		return network.PlanMTU
	}
}

func networkPlanResponse(profiles []network.Profil, plan network.Plan) *helperv1.HelperResponse {
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the change will not enter this host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == network.PlanBezZmian:
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
func (s *Server) changeNetwork(ctx context.Context, action *helperv1.NetworkRequest) *helperv1.HelperResponse {
	connection, profile, err := s.interfaceProfile(ctx, action.GetInterface())
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}

	// A change approved on the basis of a plan is to enter the state the
	// operator looked at. A plan computed now with a different digest means the
	// profile changed since the planning - and that is a refusal, not a
	// warning.
	if expected := action.GetPlanHash(); expected != "" {
		if now := networkPlan(action, profile); now.PlanHash != expected {
			return reject(ErrorPreconditionFailed,
				"the profile "+connection+" changed since the planning; the change needs a new plan")
		}
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
	plan := network.PlanWycofania{
		ID:           rollbackIdentifier(),
		Profil:       profile,
		Interfejs:    action.GetInterface(),
		Zarzadzajacy: false,
		Utworzony:    time.Now().UTC(),
		Powod:        action.GetReason(),
	}
	window := rollbackWindow(action.GetRollbackSeconds())
	plan.Termin = plan.Utworzony.Add(window)

	if _, err := network.KrokiWycofania(plan); err != nil {
		// Without a verified way back the change is not made at all.
		return reject(ErrorUnsupported, "the rollback cannot be assembled: "+err.Error())
	}
	if err := network.ZapiszPlan(network.KatalogWycofan, plan); err != nil {
		return reject(ErrorExecFailed, "writing the rollback plan: "+err.Error())
	}
	if err := s.armRollback(ctx, plan, window); err != nil {
		_ = network.UsunPlan(network.KatalogWycofan, plan.ID)
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
			plan.Termin.Format(time.RFC3339)), &plan)
}

// changeSteps assembles the commands for one concrete operation.
func changeSteps(action *helperv1.NetworkRequest, connection string,
	current network.Profil) ([][]string, error) {
	switch action.GetOperation() {
	case helperv1.NetworkRequest_OPERATION_SET_MTU:
		return network.ArgumentyMTU(connection, action.GetMtu())
	case helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES:
		return network.ArgumentyTras(connection, action.GetRoutes())
	case helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		desired := network.Profil{
			Polaczenie: connection,
			Metoda:     action.GetMethod(),
			Adresy:     action.GetAddresses(),
			Brama:      action.GetGateway(),
			DNS:        action.GetDns(),
			// Routes, MTU and the rest of the resolver stay as they were: the
			// address profile is a separate operation and must not silently
			// erase settings the operator was never asked about.
			DNSSearch:     current.DNSSearch,
			IgnoreAutoDNS: current.IgnoreAutoDNS,
			Trasy:         current.Trasy,
			MTU:           current.MTU,
		}
		return network.ArgumentyProfilu(desired)
	}
	return nil, fmt.Errorf("unknown network operation")
}

// confirmChange disarms the rollback after the agent confirmed connectivity.
func (s *Server) confirmChange(ctx context.Context, id string) *helperv1.HelperResponse {
	plan, err := network.WczytajPlan(network.KatalogWycofan, id)
	if err != nil {
		// A missing plan means the rollback was already performed or already
		// disarmed. This is not an error of the order, but the operator is to
		// know about it.
		return networkResponse(s.readProfiles(ctx),
			"there is nothing to disarm: the rollback "+id+" no longer exists", nil)
	}
	if err := s.disarmRollback(ctx, plan.ID); err != nil {
		return reject(ErrorExecFailed, "disarming the rollback: "+err.Error())
	}
	if err := network.UsunPlan(network.KatalogWycofan, plan.ID); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	response := networkResponse(s.readProfiles(ctx), "the change was confirmed", nil)
	response.NetworkResult.Confirmed = true
	return response
}

// rollbackNow restores the state from before the change at the request of the
// operator.
func (s *Server) rollbackNow(ctx context.Context, id string) *helperv1.HelperResponse {
	plan, err := network.WczytajPlan(network.KatalogWycofan, id)
	if err != nil {
		return reject(ErrorUnsupported, "there is no rollback plan "+id)
	}
	steps, err := network.KrokiWycofania(plan)
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	for _, step := range steps {
		if output, err := runNmcli(ctx, step); err != nil {
			return reject(ErrorExecFailed, fmt.Sprintf("%s: %s", err, output))
		}
	}
	_ = s.disarmRollback(ctx, plan.ID)
	_ = network.UsunPlan(network.KatalogWycofan, plan.ID)
	return networkResponse(s.readProfiles(ctx), "the change was rolled back on request", nil)
}

// armRollback starts a transient systemd timer.
//
// The timer lives outside the helper: the helper ends its work after an idle
// period, and the rollback has to fire also when nobody talks to it any more.
// The unit calls this same helper binary in rollback mode - the command does
// not come from the plan, so the plan cannot express anything else.
func (s *Server) armRollback(ctx context.Context, plan network.PlanWycofania, window time.Duration) error {
	return s.armTimer(ctx, network.NazwaJednostkiWycofania(plan.ID), window, "-rollback", plan.ID)
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
	return s.disarmTimer(ctx, network.NazwaJednostkiWycofania(id))
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
	return network.PoprawnyIdentyfikatorPlanu(id)
}

// readProfiles collects the NetworkManager profiles together with their
// settings.
func (s *Server) readProfiles(ctx context.Context) []network.Profil {
	output, err := nmcliOutput(ctx, "-t", "-f", "NAME,UUID,DEVICE,TYPE,STATE", "connection", "show")
	if err != nil {
		return nil
	}
	var profiles []network.Profil
	for _, connection := range network.ParsujPolaczenia(output) {
		settings, err := nmcliOutput(ctx, "-t", "-f",
			strings.Join(network.PolaProfilu, ","), "connection", "show", connection.Nazwa)
		if err != nil {
			continue
		}
		profile := network.ParsujProfil(settings)
		if profile.Polaczenie == "" {
			profile.Polaczenie = connection.Nazwa
		}
		if profile.Interfejs == "" {
			profile.Interfejs = connection.Urzadzenie
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

// interfaceProfile finds the profile active on an interface.
func (s *Server) interfaceProfile(ctx context.Context, iface string) (string, network.Profil, error) {
	if iface == "" {
		return "", network.Profil{}, fmt.Errorf("the operation needs an interface name")
	}
	output, err := nmcliOutput(ctx, "-t", "-f", "NAME,UUID,DEVICE,TYPE,STATE", "connection", "show")
	if err != nil {
		return "", network.Profil{}, fmt.Errorf("reading the connections: %w", err)
	}
	connection := network.PolaczenieUrzadzenia(network.ParsujPolaczenia(output), iface)
	if connection == nil {
		return "", network.Profil{}, fmt.Errorf(
			"the interface %s has no NetworkManager profile; the panel does not create new profiles here", iface)
	}
	settings, err := nmcliOutput(ctx, "-t", "-f",
		strings.Join(network.PolaProfilu, ","), "connection", "show", connection.Nazwa)
	if err != nil {
		return "", network.Profil{}, fmt.Errorf("reading the profile %s: %w", connection.Nazwa, err)
	}
	profile := network.ParsujProfil(settings)
	if profile.Polaczenie == "" {
		profile.Polaczenie = connection.Nazwa
	}
	return connection.Nazwa, profile, nil
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
	cmd := exec.CommandContext(ctx, network.SciezkaNmcli, arguments...)
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
func encodeProfiles(profiles []network.Profil) ([]byte, error) {
	return json.Marshal(struct {
		Profiles []network.Profil `json:"profiles"`
	}{profiles})
}

func networkResponse(profiles []network.Profil, message string,
	plan *network.PlanWycofania) *helperv1.HelperResponse {
	encoded, err := encodeProfiles(profiles)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	result := &helperv1.NetworkResult{Profiles: encoded, Message: message}
	if plan != nil {
		result.RollbackId = plan.ID
		result.RollbackDeadline = plan.Termin.Format(time.RFC3339)
	}
	return &helperv1.HelperResponse{Accepted: true, NetworkResult: result}
}

// networkErrorResponse describes a change that failed but left the rollback
// armed. The operator is to know that the host will come back on its own.
func networkErrorResponse(plan network.PlanWycofania, message string) *helperv1.HelperResponse {
	response := reject(ErrorExecFailed, message)
	response.NetworkResult = &helperv1.NetworkResult{
		Message:          message,
		RollbackId:       plan.ID,
		RollbackDeadline: plan.Termin.Format(time.RFC3339),
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
	plan, err := network.WczytajPlan(network.KatalogWycofan, id)
	if err != nil {
		return fmt.Errorf("the rollback plan %s: %w", id, err)
	}
	steps, err := network.KrokiWycofania(plan)
	if err != nil {
		_ = network.OdlozNieudanyPlan(network.KatalogWycofan, id)
		return err
	}
	for _, step := range steps {
		if output, err := runNmcli(ctx, step); err != nil {
			// A plan whose timer has already fired is dead also when the
			// rollback failed. Left in the directory it would look like a
			// rollback still waiting for its moment.
			_ = network.OdlozNieudanyPlan(network.KatalogWycofan, id)
			return fmt.Errorf("%s: %w: %s", strings.Join(step, " "), err, output)
		}
	}
	return network.UsunPlan(network.KatalogWycofan, id)
}
