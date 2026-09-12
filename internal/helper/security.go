package helper

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/security"
)

// factNames translates the protocol enumeration into the fact names of the
// module.
//
// The translation exists so that the helper does not accept an arbitrary
// string: the scope of its work is a closed list, not a text from the agent.
var factNames = map[helperv1.SecurityRequest_Fact]string{
	helperv1.SecurityRequest_FACT_APPARMOR_PROFILES: security.FaktProfileAppArmor,
	helperv1.SecurityRequest_FACT_AUDIT_RULES:       security.FaktRegulyAudytu,
	helperv1.SecurityRequest_FACT_SECURE_BOOT:       security.FaktSecureBoot,
	helperv1.SecurityRequest_FACT_SOCKET_OWNERS:     security.FaktWlascicieleGniazd,
}

// applySecurity handles the operations of the security module.
func (s *Server) applySecurity(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.SecurityRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 2 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.SecurityRequest_OPERATION_FACTS:
		return collectFacts(actionCtx, action.GetFacts())
	case helperv1.SecurityRequest_OPERATION_SELINUX_MODE:
		return setMACMode(actionCtx, action.GetMode())
	case helperv1.SecurityRequest_OPERATION_AUDIT_RELOAD:
		return reloadRules(actionCtx)
	}
	return reject(ErrorUnknownAction, "unknown operation of the security module")
}

// collectFacts reads only the facts the agent asked for.
//
// The module does not go through root as a whole: most of the picture the agent
// reads on its own, and only what cannot be seen without root lands here - the
// AppArmor profiles in securityfs, the audit rules, the EFI variable and the
// owners of sockets.
func collectFacts(ctx context.Context, requested []helperv1.SecurityRequest_Fact) *helperv1.HelperResponse {
	if len(requested) == 0 {
		return reject(ErrorMalformed, "the order names no fact")
	}
	names := make([]string, 0, len(requested))
	for _, fact := range requested {
		name, known := factNames[fact]
		if !known {
			return reject(ErrorMalformed, "unknown fact "+fact.String())
		}
		names = append(names, name)
	}

	supplement := security.ZbierzUzupelnienie(ctx, toolOutput, names)
	encoded, err := json.Marshal(supplement)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:       true,
		SecurityResult: &helperv1.SecurityResult{Facts: encoded},
	}
}

// setMACMode switches SELinux between enforcing and permissive.
func setMACMode(ctx context.Context, mode string) *helperv1.HelperResponse {
	if err := security.WalidujTryb(mode); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	state := security.StanMAC()
	if state.System != security.SystemSELinux {
		return reject(ErrorUnsupported, "this host has no SELinux")
	}
	if state.Mode == security.TrybDisabled {
		return reject(ErrorPreconditionFailed,
			"SELinux is disabled in the kernel; enabling it needs a relabeling of the file system and a restart")
	}
	if !exists(security.SciezkaSetenforce) {
		return reject(ErrorUnsupported, "this host has no setenforce tool")
	}

	value := "0"
	if mode == security.TrybEnforcing {
		value = "1"
	}
	if output, err := toolOutput(ctx, security.SciezkaSetenforce, value); err != nil {
		return reject(ErrorExecFailed, "setenforce: "+err.Error()+" "+output)
	}

	// A change made on the spot does not survive a restart, so it is written to
	// the configuration as well. The panel changes one line and does not rewrite
	// the rest of the file.
	message := "the mode " + mode + " applies from now on"
	if err := writeModeToConfiguration(mode); err != nil {
		message += "; it was not written to the configuration (" + err.Error() +
			"), so after a restart the host will go back to " + state.ConfiguredMode
	} else {
		message += " and after a restart"
	}

	// A write does not mean an effect: the kernel is asked which mode it is in
	// now.
	after := security.StanMAC()
	if after.Mode != mode {
		return &helperv1.HelperResponse{
			Accepted: true,
			SecurityResult: &helperv1.SecurityResult{
				Message: "the command ran, but the kernel reports the mode " + after.Mode,
			},
		}
	}
	return &helperv1.HelperResponse{
		Accepted:       true,
		SecurityResult: &helperv1.SecurityResult{Message: message},
	}
}

// reloadRules loads the audit rules from the files into the kernel.
//
// It goes through augenrules and not through a restart of the unit: auditd on
// some distributions has RefuseManualStop and a restart ends in a refusal that
// looks like a panel error while it is a distribution policy.
func reloadRules(ctx context.Context) *helperv1.HelperResponse {
	if !exists(security.SciezkaAugenrules) {
		return reject(ErrorUnsupported, "this host has no augenrules tool")
	}
	output, err := toolOutput(ctx, security.SciezkaAugenrules, "--load")
	if err != nil {
		return reject(ErrorExecFailed, "augenrules: "+err.Error()+" "+output)
	}

	// A write does not mean an effect: the kernel is asked how many rules it
	// knows now.
	message := "the rules were reloaded"
	if result, err := toolOutput(ctx, security.SciezkaAuditctl, "-l"); err == nil {
		message += "; the kernel knows " + strconv.Itoa(security.ParsujReguly(result)) + " rules"
	}
	return &helperv1.HelperResponse{
		Accepted:       true,
		SecurityResult: &helperv1.SecurityResult{Message: message},
	}
}

// writeModeToConfiguration replaces the SELINUX= value in the configuration
// file.
func writeModeToConfiguration(mode string) error {
	content, err := os.ReadFile(security.KonfiguracjaMAC)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	changed := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "SELINUX=") {
			lines[i] = "SELINUX=" + mode
			changed = true
		}
	}
	if !changed {
		lines = append(lines, "SELINUX="+mode)
	}
	return writeKernelFile(security.KonfiguracjaMAC, strings.Join(lines, "\n"), 0o644)
}
