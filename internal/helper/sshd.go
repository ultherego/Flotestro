package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	sshmodule "github.com/ultherego/flotestro/internal/modules/ssh"
)

// The paths of the sshd tools.
const (
	sshdPath      = "/usr/sbin/sshd"
	sshKeygenPath = "/usr/bin/ssh-keygen"
)

// applySSH handles the operations on the sshd server.
func (s *Server) applySSH(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.SshRequest) *helperv1.HelperResponse {
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

	if !exists(sshdPath) {
		if action.GetOperation() == helperv1.SshRequest_OPERATION_PLAN {
			// A missing server is an answer of the plan, not a read error: the
			// campaign is to see this host as a refusal.
			return sshPlanResponse(sshmodule.Snapshot{}, sshmodule.Zaplanuj(
				sshmodule.Snapshot{UnavailableReason: "this host has no sshd server"},
				settingsFromRequest(action), action.GetAllowLockout()))
		}
		return reject(ErrorUnsupported, "this host has no sshd server")
	}

	switch action.GetOperation() {
	case helperv1.SshRequest_OPERATION_READ:
		return sshResponse(s.readSSH(actionCtx), "", nil)
	case helperv1.SshRequest_OPERATION_PLAN:
		state := s.readSSH(actionCtx)
		return sshPlanResponse(state, sshmodule.Zaplanuj(state,
			settingsFromRequest(action), action.GetAllowLockout()))
	case helperv1.SshRequest_OPERATION_APPLY:
		return s.writeSSHConfiguration(actionCtx, action)
	case helperv1.SshRequest_OPERATION_ROTATE_HOSTKEY:
		return s.rotateHostKey(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "unknown sshd operation")
}

// writeSSHConfiguration writes the panel file and reloads the server.
//
// The order is the whole content of the operation: the write, the syntax check
// by sshd itself, and only then the reload. A server reloaded with a broken
// configuration does not come up, and then there is nothing left to repair it
// with remotely.
func (s *Server) writeSSHConfiguration(ctx context.Context, action *helperv1.SshRequest) *helperv1.HelperResponse {
	settings := settingsFromRequest(action)
	state := s.readSSH(ctx)

	// A change approved on the basis of a plan is to enter the state the
	// operator looked at. A different digest means the server or the panel file
	// changed since the planning - and that is a refusal, not a warning.
	if expected := action.GetPlanHash(); expected != "" {
		if now := sshmodule.Zaplanuj(state, settings, action.GetAllowLockout()); now.PlanHash != expected {
			return reject(ErrorPreconditionFailed,
				"the sshd configuration changed since the planning; the change needs a new plan")
		}
	}

	// A server nobody can log into by any method is not secured - it is
	// unreachable.
	if !action.GetAllowLockout() && sshmodule.OdcinaWszystkieMetody(settings, state) {
		return reject(ErrorUnsupported,
			"after this change no working authentication method would be left; "+
				"cutting access off deliberately needs explicit operator consent")
	}

	content, err := sshmodule.SkladajDropIn(settings)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	previous, existedBefore := previousDropIn()
	if err := writeDropIn(content); err != nil {
		return reject(ErrorExecFailed, "writing the configuration: "+err.Error())
	}

	// sshd -t reads the whole configuration together with the included files,
	// so it checks exactly what the server is about to read.
	if output, err := runTool(ctx, []string{sshdPath, "-t"}); err != nil {
		restoreDropIn(previous, existedBefore)
		return reject(ErrorMalformed, "sshd rejected the configuration: "+output)
	}

	unit := state.Unit
	if unit == "" {
		unit = sshUnit()
	}
	// A reload and not a restart: the sessions already running are to survive
	// the change. The operator sitting on this host over ssh is one of them.
	if output, err := runTool(ctx,
		[]string{"/usr/bin/systemctl", "reload", unit}); err != nil {
		restoreDropIn(previous, existedBefore)
		_, _ = runTool(ctx, []string{"/usr/bin/systemctl", "reload", unit})
		return reject(ErrorExecFailed, "reloading "+unit+": "+output)
	}

	after := s.readSSH(ctx)
	// In sshd the first value wins, and the included files are read in
	// alphabetical order: an earlier file of the host administrator shadows
	// ours. Silence in this place would be a false success.
	mismatches := sshmodule.RozbiezneUstawienia(settings, after)
	message := "the configuration was written and reloaded"
	if len(mismatches) > 0 {
		message = "the configuration was written, but some settings did not take effect"
	}
	return sshResponse(after, message, mismatches)
}

// rotateHostKey generates a new host key of the given type.
//
// Rotating the key changes the identity of the host as every client sees it:
// each of them will get a warning about a changed known_hosts, and automation
// based on the fingerprint will stop working. That is why the old key stays
// next to it, with a date in its name - so that it can be restored by hand.
func (s *Server) rotateHostKey(ctx context.Context, action *helperv1.SshRequest) *helperv1.HelperResponse {
	keyType := action.GetKeyType()
	if keyType != "ed25519" && keyType != "rsa" && keyType != "ecdsa" {
		return reject(ErrorMalformed, "the panel rotates ed25519, rsa or ecdsa keys, not "+keyType)
	}
	if !exists(sshKeygenPath) {
		return reject(ErrorUnsupported, "this host has no ssh-keygen")
	}
	path := "/etc/ssh/ssh_host_" + keyType + "_key"
	backupPath := path + ".flotestro-" + time.Now().UTC().Format("20060102T150405")

	if exists(path) {
		if err := os.Rename(path, backupPath); err != nil {
			return reject(ErrorExecFailed, "putting the old key aside: "+err.Error())
		}
		if exists(path + ".pub") {
			_ = os.Rename(path+".pub", backupPath+".pub")
		}
	}

	if output, err := runTool(ctx, []string{sshKeygenPath,
		"-q", "-t", keyType, "-N", "", "-f", path}); err != nil {
		// Without a key the server will not come up, so the previous one comes
		// back.
		if exists(backupPath) {
			_ = os.Rename(backupPath, path)
			_ = os.Rename(backupPath+".pub", path+".pub")
		}
		return reject(ErrorExecFailed, "generating the key: "+output)
	}

	unit := sshUnit()
	if output, err := runTool(ctx,
		[]string{"/usr/bin/systemctl", "reload", unit}); err != nil {
		return reject(ErrorExecFailed, "reloading "+unit+": "+output)
	}
	return sshResponse(s.readSSH(ctx),
		"the "+keyType+" key was rotated; the old one stayed as "+backupPath+
			"; every client will see the changed fingerprint in known_hosts", nil)
}

// readSSH assembles the picture of the server configuration.
func (s *Server) readSSH(ctx context.Context) sshmodule.Snapshot {
	snapshot := sshmodule.Snapshot{ObservedAt: time.Now().UTC(), ManagedPath: sshmodule.SciezkaDropIn}

	output, err := toolOutput(ctx, sshdPath, "-T")
	if err != nil {
		snapshot.UnavailableReason = "sshd -T: " + err.Error()
		return snapshot
	}
	effective := sshmodule.ParsujEffective(output)
	effective.ObservedAt = snapshot.ObservedAt
	effective.ManagedPath = snapshot.ManagedPath
	snapshot = effective

	if content, err := os.ReadFile(sshmodule.SciezkaDropIn); err == nil {
		snapshot.Managed = string(content)
		snapshot.ManagedPresent = true
	}
	snapshot.Unit = sshUnit()
	snapshot.HostKeys = keyFingerprints(ctx)
	return snapshot
}

// keyFingerprints collects the fingerprints of the host keys.
func keyFingerprints(ctx context.Context) []sshmodule.HostKey {
	if !exists(sshKeygenPath) {
		return nil
	}
	files, err := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	if err != nil {
		return nil
	}
	var keys []sshmodule.HostKey
	for _, file := range files {
		output, err := toolOutput(ctx, sshKeygenPath, "-l", "-f", file)
		if err != nil {
			continue
		}
		if key, ok := sshmodule.ParsujOdcisk(output, file); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// sshUnit names the systemd unit of the server.
//
// Debian has ssh.service, Fedora sshd.service. Reloading the wrong one does
// nothing and reports no error, so the name must not be guessed once and for
// all.
func sshUnit() string {
	for _, name := range []string{"sshd.service", "ssh.service"} {
		if exists("/usr/lib/systemd/system/"+name) || exists("/lib/systemd/system/"+name) {
			return name
		}
	}
	return "sshd.service"
}

func settingsFromRequest(action *helperv1.SshRequest) sshmodule.Ustawienia {
	return sshmodule.Ustawienia{
		Port:                   action.GetPort(),
		PermitRootLogin:        action.GetPermitRootLogin(),
		PasswordAuthentication: action.GetPasswordAuthentication(),
		PubkeyAuthentication:   action.GetPubkeyAuthentication(),
		KbdInteractive:         action.GetKbdInteractiveAuthentication(),
		MaxAuthTries:           action.GetMaxAuthTries(),
		AllowUsers:             action.GetAllowUsers(),
		AllowGroups:            action.GetAllowGroups(),
		DenyUsers:              action.GetDenyUsers(),
	}
}

func previousDropIn() (string, bool) {
	content, err := os.ReadFile(sshmodule.SciezkaDropIn)
	if err != nil {
		return "", false
	}
	return string(content), true
}

func writeDropIn(content string) error {
	if err := os.MkdirAll(sshmodule.KatalogDropIn, 0o755); err != nil {
		return err
	}
	// The temporary file must not end in .conf: the directory is included by a
	// pattern and sshd would read half of the write as configuration.
	temporary := sshmodule.SciezkaDropIn + ".new"
	if err := os.WriteFile(temporary, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, sshmodule.SciezkaDropIn)
}

func restoreDropIn(content string, existed bool) {
	if !existed {
		_ = os.Remove(sshmodule.SciezkaDropIn)
		return
	}
	_ = writeDropIn(content)
}

func sshResponse(snapshot sshmodule.Snapshot, message string, mismatches []string) *helperv1.HelperResponse {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		SshResult: &helperv1.SshResult{
			Snapshot: encoded, Message: message, Mismatches: mismatches,
		},
	}
}

// sshPlanResponse attaches the plan to the state of the server.
func sshPlanResponse(state sshmodule.Snapshot, plan sshmodule.Plan) *helperv1.HelperResponse {
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the change will not enter this host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == sshmodule.PlanBezZmian:
		message = "the sshd configuration is already in the desired state"
	default:
		message = strings.Join(plan.Changes, "; ")
	}
	response := sshResponse(state, message, nil)
	if response.GetSshResult() != nil {
		response.SshResult.Plan = encoded
	}
	return response
}
