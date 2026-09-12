package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	hosttime "github.com/ultherego/flotestro/internal/modules/time"
)

// syncWindow limits the wait for the daemon after a change of the sources.
//
// A write and an effect are two different things: a file with servers is not
// yet a synchronized clock. With iburst the first exchange takes a few seconds,
// so the wait is long enough to answer the question "did it work" and no
// longer, so as not to hold the task forever.
const (
	syncWindow = 45 * time.Second
	syncStep   = 5 * time.Second

	systemctlPath = "/usr/bin/systemctl"
)

// applyTime handles the operations on the host time.
func (s *Server) applyTime(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.TimeRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.TimeRequest_OPERATION_PLAN:
		return s.planTimeServers(actionCtx, action)
	case helperv1.TimeRequest_OPERATION_CONFIG_APPLY:
		return s.writeTimeServers(actionCtx, action)
	case helperv1.TimeRequest_OPERATION_TIMEZONE_SET:
		return s.setTimezone(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "unknown time operation")
}

// writeTimeServers writes the time sources and reloads the daemon.
func (s *Server) writeTimeServers(ctx context.Context, action *helperv1.TimeRequest) *helperv1.HelperResponse {
	servers := action.GetServers()
	// The shape of the entries is checked here once more even though the panel
	// already did it: the helper is the last gate before a write as root and it
	// does not take on faith what came from above.
	if err := hosttime.WalidujSerwery(servers); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	snapshot := hosttime.Zbierz(ctx, toolOutput)
	// A change approved on the basis of a plan is to enter the state the
	// operator looked at: a different panel file or a different daemon than at
	// planning time is a refusal, not a warning.
	if expected := action.GetPlanHash(); expected != "" {
		if now := hosttime.Zaplanuj(snapshot, servers, action.GetEnableDropin()); now.PlanHash != expected {
			return reject(ErrorPreconditionFailed,
				"the time sources changed since the planning; the change needs a new plan")
		}
	}
	switch snapshot.Service {
	case hosttime.DemonChrony:
		return s.writeChrony(ctx, servers, snapshot, action.GetEnableDropin())
	case hosttime.DemonTimesyncd:
		return s.writeTimesyncd(ctx, servers)
	}
	return reject(ErrorUnsupported,
		"this host has no time daemon the panel could point at servers")
}

// planTimeServers computes the difference for a change of the time sources
// without touching the host. A missing daemon and a missing directory without
// consent are a refusal in the plan.
func (s *Server) planTimeServers(ctx context.Context, action *helperv1.TimeRequest) *helperv1.HelperResponse {
	snapshot := hosttime.Zbierz(ctx, toolOutput)
	plan := hosttime.Zaplanuj(snapshot, action.GetServers(), action.GetEnableDropin())
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the change will not enter this host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == hosttime.PlanBezZmian:
		message = "the time sources are already in the desired state"
	default:
		message = strings.Join(plan.Changes, "; ")
	}
	response := timeResponse(snapshot, message)
	if response.GetTimeResult() != nil {
		response.TimeResult.Plan = encoded
	}
	return response
}

// writeChrony adds the servers to the directory chrony includes on its own.
func (s *Server) writeChrony(ctx context.Context, servers []string,
	snapshot hosttime.Snapshot, directoryConsent bool) *helperv1.HelperResponse {
	// A host that includes no directory can be brought into a writable state
	// with one appended line - but only with explicit consent: this is the only
	// place where the panel touches somebody else's configuration.
	restartNeeded := false
	if snapshot.ManagedPath == "" {
		if !directoryConsent {
			reason := snapshot.WriteReason
			if reason == "" {
				reason = "chrony on this host includes no configuration directory"
			}
			return reject(ErrorUnsupported, reason)
		}
		if refusal := enableSourceDirectory(snapshot); refusal != nil {
			return refusal
		}
		snapshot.ManagedPath = filepath.Join(hosttime.KatalogZrodelPanelu,
			hosttime.NazwaPlikuChrony(hosttime.RodzajZrodel))
		// A change of the main file applies only after the daemon starts;
		// reloading the sources alone does not read it.
		restartNeeded = true
	}
	kind := hosttime.RodzajKonfiguracji
	if filepath.Ext(snapshot.ManagedPath) == ".sources" {
		kind = hosttime.RodzajZrodel
	}
	content, err := hosttime.SkladajChrony(servers, kind)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := os.MkdirAll(filepath.Dir(snapshot.ManagedPath), 0o755); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	previous, _ := os.ReadFile(snapshot.ManagedPath)
	if err := writeKernelFile(snapshot.ManagedPath, content, 0o644); err != nil {
		return reject(ErrorExecFailed, "writing "+snapshot.ManagedPath+": "+err.Error())
	}

	// The daemon reloads the sources directory without a restart, so the host
	// does not lose synchronization during the change. The configuration
	// directory needs a restart.
	message := "the servers were written"
	if kind == hosttime.RodzajZrodel && !restartNeeded {
		if output, err := toolOutput(ctx, hosttime.SciezkaChronyc, "reload", "sources"); err != nil {
			restore(snapshot.ManagedPath, previous)
			return reject(ErrorExecFailed, "chronyc reload sources: "+err.Error()+" "+output)
		}
		message = "the servers were written and reloaded without restarting the daemon"
	} else {
		unit := snapshot.Unit
		if unit == "" {
			unit = "chronyd.service"
		}
		if output, err := toolOutput(ctx, systemctlPath, "restart", unit); err != nil {
			// A daemon that does not come up with the new configuration would
			// leave the host without a clock. The previous content is restored
			// and the daemon brought back up before the error is reported.
			restore(snapshot.ManagedPath, previous)
			_, _ = toolOutput(ctx, systemctlPath, "restart", unit)
			return reject(ErrorExecFailed, "restart "+unit+": "+err.Error()+" "+output)
		}
		message = "the servers were written, the daemon was restarted"
	}

	after, synchronized := waitForSynchronization(ctx)
	return timeResponse(after, message+"; "+describeSynchronization(after, synchronized))
}

// enableSourceDirectory creates the panel directory and points the daemon at
// it.
//
// The line is appended in place and not by replacing the file: the file belongs
// to the distribution, and appending preserves its owner, its permissions and
// its SELinux label. The panel changes nothing there and removes nothing.
func enableSourceDirectory(snapshot hosttime.Snapshot) *helperv1.HelperResponse {
	if snapshot.ConfigPath == "" {
		return reject(ErrorUnsupported, "the main chrony file was not found")
	}
	if err := os.MkdirAll(hosttime.KatalogZrodelPanelu, 0o755); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	content, err := os.ReadFile(snapshot.ConfigPath)
	if err != nil {
		return reject(ErrorExecFailed, "reading "+snapshot.ConfigPath+": "+err.Error())
	}
	// A repeated order must not append the line a second time.
	if hosttime.MaWpisWlaczenia(string(content)) {
		return nil
	}
	file, err := os.OpenFile(snapshot.ConfigPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return reject(ErrorExecFailed, "writing "+snapshot.ConfigPath+": "+err.Error())
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString(hosttime.WpisWlaczenia()); err != nil {
		return reject(ErrorExecFailed, "writing "+snapshot.ConfigPath+": "+err.Error())
	}
	return nil
}

// writeTimesyncd writes the servers for systemd-timesyncd.
func (s *Server) writeTimesyncd(ctx context.Context, servers []string) *helperv1.HelperResponse {
	content, err := hosttime.SkladajTimesyncd(servers)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := os.MkdirAll(hosttime.KatalogTimesyncd, 0o755); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	previous, _ := os.ReadFile(hosttime.PlikTimesyncd)
	if err := writeKernelFile(hosttime.PlikTimesyncd, content, 0o644); err != nil {
		return reject(ErrorExecFailed, "writing "+hosttime.PlikTimesyncd+": "+err.Error())
	}
	// A host with synchronization switched off still has it switched off after
	// the file is written: timesyncd does not run until timedated enables it. A
	// write of the servers without this step would look successful and do
	// nothing.
	if exists(hosttime.SciezkaTimedatectl) {
		if output, err := toolOutput(ctx, hosttime.SciezkaTimedatectl, "set-ntp", "true"); err != nil {
			restore(hosttime.PlikTimesyncd, previous)
			return reject(ErrorExecFailed, "timedatectl set-ntp: "+err.Error()+" "+output)
		}
	}
	if output, err := toolOutput(ctx, systemctlPath, "restart", "systemd-timesyncd.service"); err != nil {
		// As above: a host without a time daemon is worse than a host with old
		// servers, so on an error the previous content comes back.
		restore(hosttime.PlikTimesyncd, previous)
		_, _ = toolOutput(ctx, systemctlPath, "restart", "systemd-timesyncd.service")
		return reject(ErrorExecFailed, "restart systemd-timesyncd: "+err.Error()+" "+output)
	}

	after, synchronized := waitForSynchronization(ctx)
	return timeResponse(after, "the servers were written, the daemon was restarted; "+
		describeSynchronization(after, synchronized))
}

// setTimezone changes the time zone of the host.
func (s *Server) setTimezone(ctx context.Context, action *helperv1.TimeRequest) *helperv1.HelperResponse {
	zone := action.GetTimezone()
	if err := hosttime.WalidujStrefe(zone); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	// A zone the host does not know ends in a tool error without a reason. The
	// zone file is checked so that what is missing can be named directly.
	if !exists(hosttime.SciezkaStrefy(zone)) {
		return reject(ErrorPreconditionFailed, "this host does not know the zone "+zone)
	}
	if !exists(hosttime.SciezkaTimedatectl) {
		return reject(ErrorUnsupported, "this host has no timedatectl")
	}
	if output, err := toolOutput(ctx, hosttime.SciezkaTimedatectl, "set-timezone", zone); err != nil {
		return reject(ErrorExecFailed, "timedatectl set-timezone: "+err.Error()+" "+output)
	}

	// A write does not mean an effect: the host is asked which zone it has now.
	snapshot := hosttime.Zbierz(ctx, toolOutput)
	if snapshot.Timezone != zone {
		return timeResponse(snapshot, "the command ran, but the host reports the zone "+
			snapshot.Timezone+" instead of "+zone)
	}
	message := "the zone was set to " + zone
	// A hardware clock in local time will show a different hour at the next
	// start after a zone change. This is a fact about the host, not about the
	// operation.
	if snapshot.RTCInLocalTime != nil && *snapshot.RTCInLocalTime {
		message += "; the hardware clock runs in local time, so after a restart the host will come up with a shifted hour"
	}
	return timeResponse(snapshot, message)
}

// waitForSynchronization waits until the daemon picks a source.
func waitForSynchronization(ctx context.Context) (hosttime.Snapshot, bool) {
	deadline := time.Now().Add(syncWindow)
	snapshot := hosttime.Zbierz(ctx, toolOutput)
	for time.Now().Before(deadline) {
		if snapshot.Zsynchronizowany() {
			return snapshot, true
		}
		select {
		case <-ctx.Done():
			return snapshot, snapshot.Zsynchronizowany()
		case <-time.After(syncStep):
		}
		snapshot = hosttime.Zbierz(ctx, toolOutput)
	}
	return snapshot, snapshot.Zsynchronizowany()
}

// describeSynchronization names the state of the clock after the change.
func describeSynchronization(snapshot hosttime.Snapshot, synchronized bool) string {
	if !synchronized {
		return "the host did not synchronize within " + syncWindow.String() +
			"; the sources may be unreachable"
	}
	description := "the clock is synchronized"
	if snapshot.ReferenceName != "" {
		description += " against " + snapshot.ReferenceName
	}
	return description
}

// restore gives the file its previous content back or removes it when there
// was none.
func restore(path string, previous []byte) {
	if len(previous) == 0 {
		_ = os.Remove(path)
		return
	}
	_ = writeKernelFile(path, string(previous), 0o644)
}

func timeResponse(snapshot hosttime.Snapshot, message string) *helperv1.HelperResponse {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:   true,
		TimeResult: &helperv1.TimeResult{Snapshot: encoded, Message: message},
	}
}
