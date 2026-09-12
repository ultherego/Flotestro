package compliance

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/modules/security"
	sshmodul "github.com/ultherego/flotestro/internal/modules/ssh"
	czas "github.com/ultherego/flotestro/internal/modules/time"
)

// The names of the inventory modules the checks are computed from.
const (
	moduleSecurity = "security"
	moduleSSH      = "ssh"
	moduleKernel   = "kernel"
	moduleTime     = "time"
	modulePower    = "power"
	modulePackages = "packages"
)

// Checks is the panel's hardening profile.
//
// The list is short, and deliberately so: every check has to be explainable
// in one sentence, point at evidence and - where a remediation exists - at
// one specific typed operation. A check that does not meet those three
// conditions is an opinion rather than a check.
var Checks = []Check{
	{
		ID: "mac.enforcing", Version: 1, Severity: SeverityHigh, Module: moduleSecurity,
		Title:     "Mandatory access control enforces its policy",
		Expected:  "SELinux in enforcing mode or AppArmor with enforced profiles",
		Rationale: "Without MAC a faulty service reaches as far as the file permissions alone allow it.",
		Evaluate:      evaluateMAC,
	},
	{
		ID: "mac.persistent", Version: 1, Severity: SeverityHigh, Module: moduleSecurity,
		Title:     "The protection survives a reboot of the host",
		Expected:  "the running mode is the same as the configured one",
		Rationale: "A host that comes up unprotected after a reboot looks protected until the first reboot.",
		Evaluate:      evaluateMACPersistence,
	},
	{
		ID: "audit.running", Version: 1, Severity: SeverityMedium, Module: moduleSecurity,
		Title:     "The audit daemon is running",
		Expected:  "auditd active",
		Rationale: "Without auditing there is no way to say afterwards who did what on the host.",
		Evaluate:      evaluateAudit,
	},
	{
		ID: "audit.rules-loaded", Version: 1, Severity: SeverityMedium, Module: moduleSecurity,
		Title:     "The audit rules are loaded",
		Expected:  "the kernel knows every rule written in the files",
		Rationale: "A rule that is written and not loaded records nothing while looking like auditing is on.",
		Evaluate:      evaluateAuditRules,
	},
	{
		ID: "boot.secure-boot", Version: 1, Severity: SeverityInfo, Module: moduleSecurity,
		Title:     "Secure boot",
		Expected:  "secure boot enabled",
		Rationale: "Without secure boot nobody checks what the host runs before the system starts.",
		Evaluate:      evaluateSecureBoot,
	},
	{
		ID: "exposure.listening", Version: 1, Severity: SeverityMedium, Module: moduleSecurity,
		Title:     "Services exposed beyond the host",
		Expected:  "only the services that are meant to be exposed are exposed",
		Rationale: "Every socket outside the loopback is a way into the host for anyone who sees its network.",
		Evaluate:      evaluateExposure,
	},
	{
		ID: "ssh.root-login", Version: 1, Severity: SeverityHigh, Module: moduleSSH,
		Title:     "Root login over SSH",
		Expected:  "PermitRootLogin no",
		Rationale: "The root account is shared, so logging into it leaves no trace of who it was.",
		Evaluate:      evaluateRootLogin,
	},
	{
		ID: "ssh.password-auth", Version: 1, Severity: SeverityMedium, Module: moduleSSH,
		Title:     "Password login over SSH",
		Expected:  "PasswordAuthentication no",
		Rationale: "A password can be guessed remotely; a key cannot.",
		Evaluate:      evaluatePasswords,
	},
	{
		ID: "kernel.rp-filter", Version: 1, Severity: SeverityLow, Module: moduleKernel,
		Title:     "Filtering by source address",
		Expected:  "net.ipv4.conf.all.rp_filter = 1",
		Rationale: "Without it the host accepts packets with a spoofed source address.",
		Evaluate:      evaluateSetting("net.ipv4.conf.all.rp_filter", "1"),
	},
	{
		ID: "kernel.syncookies", Version: 1, Severity: SeverityLow, Module: moduleKernel,
		Title:     "SYN cookies",
		Expected:  "net.ipv4.tcp_syncookies = 1",
		Rationale: "Without them a flood of connections exhausts the queue and the service stops answering.",
		Evaluate:      evaluateSetting("net.ipv4.tcp_syncookies", "1"),
	},
	{
		ID: "time.synchronized", Version: 1, Severity: SeverityMedium, Module: moduleTime,
		Title:     "The clock is synchronised",
		Expected:  "the host synchronises its time with a source",
		Rationale: "A drifted clock rejects Kerberos tickets and certificates and puts the journal in the wrong order.",
		Evaluate:      evaluateTime,
	},
	{
		ID: "packages.security-updates", Version: 1, Severity: SeverityHigh, Module: "",
		Title:     "The security updates are installed",
		Expected:  "no pending security updates",
		Rationale: "Every pending update is publicly described - together with what can be done without it.",
		Evaluate:      evaluateUpdates,
	},
	{
		ID: "reboot.pending", Version: 1, Severity: SeverityMedium, Module: modulePower,
		Title:     "The host is not waiting for a reboot",
		Expected:  "no reboot required",
		Rationale: "A host waiting for a reboot runs on an old kernel or old libraries despite the update being installed.",
		Evaluate:      evaluateReboot,
	},
}

// evaluateMAC checks whether mandatory access control protects the host.
func evaluateMAC(input Input) Result {
	state, ok := protectiveState(input)
	if !ok {
		return unknown(ReasonReadFailed, "the protective state was not read")
	}
	if state.MAC.System == "" {
		return Result{
			Observed: "the host has neither SELinux nor AppArmor",
			Evidence: state.MAC.Reason,
			Remediation: &Remediation{Note: "turning MAC on on a running host requires installing a policy " +
				"and relabelling the filesystem; the panel does not do that in one operation"},
		}
	}
	// AppArmor without profiles read is not AppArmor without protection:
	// without that fact nothing can be judged.
	if state.MAC.System == security.SystemAppArmor && state.MAC.ProfilesEnforcing == nil {
		if reason, missing := state.Missing[security.FaktProfileAppArmor]; missing {
			return unknown(missingCode(reason), reason)
		}
		return unknown(ReasonFactMissing, "the host did not report the number of AppArmor profiles")
	}
	if state.MAC.Chroni() {
		return Result{Passed: true, Observed: describeMAC(state.MAC)}
	}

	result := Result{Observed: describeMAC(state.MAC), Evidence: state.MAC.Reason}
	// A remediation exists only where the change takes effect at once:
	// SELinux in permissive returns to enforcing with one command, AppArmor
	// without enforced profiles needs profiles, and the panel does not write
	// those.
	if state.MAC.System == security.SystemSELinux && state.MAC.Mode == security.TrybPermissive {
		result.Remediation = &Remediation{
			Action:  "selinux.mode.set",
			Payload: json.RawMessage(`{"security":{"mode":"enforcing"}}`),
			Note:    "the switch takes effect at once and is written to the configuration",
		}
		return result
	}
	if state.MAC.System == security.SystemSELinux {
		result.Remediation = &Remediation{Note: "SELinux is disabled in the kernel; coming back requires " +
			"relabelling the filesystem and a reboot"}
		return result
	}
	result.Remediation = &Remediation{Note: "AppArmor has no enforced profiles; profiles come from packages " +
		"rather than from the panel"}
	return result
}

// evaluateMACPersistence checks whether the protection survives a reboot.
func evaluateMACPersistence(input Input) Result {
	state, ok := protectiveState(input)
	if !ok {
		return unknown(ReasonReadFailed, "the protective state was not read")
	}
	if state.MAC.System != security.SystemSELinux {
		// A host with AppArmor neither fails a check requiring SELinux nor
		// passes it silently: it does not concern it.
		return notApplicable("this host does not use SELinux; AppArmor has no separate mode in its configuration")
	}
	if state.MAC.ConfiguredMode == "" {
		return unknown(ReasonFactMissing, "the host did not report the configured mode")
	}
	if state.MAC.ConfiguredMode == state.MAC.Mode {
		return Result{Passed: true, Observed: "now and after a reboot: " + state.MAC.Mode}
	}
	result := Result{
		Observed: "now " + state.MAC.Mode + ", after a reboot " + state.MAC.ConfiguredMode,
		Evidence: security.KonfiguracjaMAC,
	}
	// Changing the mode through the panel also writes the configuration, so
	// the same operation removes the drift - as long as SELinux runs in the
	// kernel at all.
	if state.MAC.Mode == security.TrybEnforcing || state.MAC.Mode == security.TrybPermissive {
		result.Remediation = &Remediation{
			Action:  "selinux.mode.set",
			Payload: json.RawMessage(`{"security":{"mode":"` + state.MAC.Mode + `"}}`),
			Note:    "makes the mode that applies now persistent",
		}
	} else {
		result.Remediation = &Remediation{Note: "SELinux is disabled in the kernel; turning it on requires " +
			"relabelling the filesystem and a reboot"}
	}
	return result
}

func evaluateAudit(input Input) Result {
	state, ok := protectiveState(input)
	if !ok {
		return unknown(ReasonReadFailed, "the protective state was not read")
	}
	if !state.Audit.Present {
		return Result{
			Observed:    "the host has no audit daemon",
			Evidence:    state.Audit.Reason,
			Remediation: &Remediation{Note: "auditd has to be installed first with the packages.install operation"},
		}
	}
	if state.Audit.Active == nil {
		return unknown(ReasonFactMissing, "the state of the audit daemon was not determined")
	}
	if *state.Audit.Active {
		description := "auditd is running"
		if state.Audit.RulesLoaded != nil {
			description += ", rules in the kernel: " + strconv.Itoa(*state.Audit.RulesLoaded)
		}
		return Result{Passed: true, Observed: description}
	}
	return Result{
		Observed: "auditd is installed but not running",
		Remediation: &Remediation{
			Action:  "unit.enable.set",
			Payload: json.RawMessage(`{"unit_toggle":{"unit":"auditd.service","enabled":true}}`),
			Note:    "enables the unit persistently; starting it now is a separate unit.start operation",
		},
	}
}

func evaluateSecureBoot(input Input) Result {
	state, ok := protectiveState(input)
	if !ok {
		return unknown(ReasonReadFailed, "the protective state was not read")
	}
	if state.SecureBoot == nil {
		if reason, missing := state.Missing[security.FaktSecureBoot]; missing {
			return unknown(missingCode(reason), reason)
		}
		// A host booting in BIOS mode does not have secure boot disabled - it
		// does not have it at all, so the check does not concern it.
		return notApplicable(firstNonEmpty(state.SecureBootReason, "this host does not boot through EFI"))
	}
	if *state.SecureBoot {
		return Result{Passed: true, Observed: "enabled"}
	}
	return Result{
		Observed:    "disabled",
		Remediation: &Remediation{Note: "secure boot is turned on in the machine's firmware, not from the panel"},
	}
}

func evaluateExposure(input Input) Result {
	state, ok := protectiveState(input)
	if !ok {
		return unknown(ReasonReadFailed, "the protective state was not read")
	}
	if !state.ListeningKnown {
		return unknown(ReasonFactMissing, "the list of listening sockets was not read")
	}
	beyond := state.PozaPetla()
	if len(beyond) == 0 {
		return Result{Passed: true, Observed: "the host listens on the loopback only"}
	}

	counts := state.WedlugZasiegu()
	descriptions := make([]string, 0, len(beyond))
	for _, socket := range beyond {
		description := socket.Protocol + "/" + strconv.Itoa(socket.Port) + " " + socket.Reach
		if socket.Process != "" {
			description += " (" + socket.Process + ")"
		}
		descriptions = append(descriptions, description)
	}
	evidence := strings.Join(descriptions, ", ")
	// Without the owners of the sockets the list is complete but nameless -
	// and the operator is to know that before they start looking for what
	// service it is.
	if !state.OwnersKnown {
		evidence += "; the owners of the sockets are unknown"
	}

	// The panel does not declare that a service is visible from the internet:
	// that cannot be seen from an address. It says what the socket stands on
	// and leaves the decision to a human.
	return Result{
		Observed: fmt.Sprintf("%d on every interface, %d on the host's address",
			counts[security.ZasiegWszystkie], counts[security.ZasiegAdresHosta]),
		Evidence: evidence,
		Remediation: &Remediation{Note: "every socket is closed differently: a firewall rule, the service's " +
			"configuration or switching it off; the panel does not guess which of those fits here"},
	}
}

// evaluateAuditRules compares the rules written in files with those the kernel knows.
func evaluateAuditRules(input Input) Result {
	state, ok := protectiveState(input)
	if !ok {
		return unknown(ReasonReadFailed, "the protective state was not read")
	}
	if !state.Audit.Present {
		return notApplicable("this host has no audit daemon")
	}
	if state.Audit.RulesConfigured == nil || state.Audit.RulesLoaded == nil {
		if reason, missing := state.Missing[security.FaktRegulyAudytu]; missing {
			return unknown(missingCode(reason), reason)
		}
		return unknown(ReasonFactMissing, "the host did not report its audit rules")
	}
	if *state.Audit.RulesConfigured == 0 {
		return notApplicable("this host has no audit rules written down")
	}
	description := strconv.Itoa(*state.Audit.RulesLoaded) + " of " +
		strconv.Itoa(*state.Audit.RulesConfigured) + " rules loaded into the kernel"
	if *state.Audit.RulesLoaded >= *state.Audit.RulesConfigured {
		return Result{Passed: true, Observed: description}
	}
	// A rules file added and not loaded describes auditing that does not exist.
	return Result{
		Observed: description,
		Remediation: &Remediation{
			Action: "security.audit.reload",
			Note: "augenrules loads the rules; restarting the unit is not the way here, " +
				"because auditd on some distributions refuses a manual restart",
		},
	}
}

func evaluateRootLogin(input Input) Result {
	state, ok := sshState(input)
	if !ok {
		return unknown(ReasonReadFailed, "the sshd configuration was not read")
	}
	if state.Unit == "" && len(state.Ports) == 0 {
		return notApplicable("this host has no sshd server")
	}
	value := strings.ToLower(state.PermitRootLogin)
	if value == "" {
		return unknown(ReasonFactMissing, "sshd did not report the PermitRootLogin setting")
	}
	if value == "no" {
		return Result{Passed: true, Observed: value}
	}
	return Result{
		Observed: value,
		Evidence: "sshd -T",
		Remediation: &Remediation{
			Action:  "ssh.config.apply",
			Payload: json.RawMessage(`{"ssh":{"permit_root_login":"no"}}`),
			Note:    "make sure somebody other than root has access to this host",
		},
	}
}

func evaluatePasswords(input Input) Result {
	state, ok := sshState(input)
	if !ok {
		return unknown(ReasonReadFailed, "the sshd configuration was not read")
	}
	if state.Unit == "" && len(state.Ports) == 0 {
		return notApplicable("this host has no sshd server")
	}
	value := strings.ToLower(state.PasswordAuthentication)
	if value == "" {
		return unknown(ReasonFactMissing, "sshd did not report the PasswordAuthentication setting")
	}
	if value == "no" {
		return Result{Passed: true, Observed: value}
	}
	return Result{
		Observed: value,
		Evidence: "sshd -T",
		Remediation: &Remediation{
			Action:  "ssh.config.apply",
			Payload: json.RawMessage(`{"ssh":{"password_authentication":"no"}}`),
			Note:    "the host refuses a change that leaves no working login method",
		},
	}
}

// evaluateSetting builds the check of one sysctl key.
func evaluateSetting(key, expected string) func(Input) Result {
	return func(input Input) Result {
		fragment, ok := input.Fragment(moduleKernel)
		if !ok {
			return unknown(ReasonFactMissing, "the kernel settings were not read")
		}
		var state kernel.Snapshot
		if err := json.Unmarshal(fragment.Payload, &state); err != nil {
			return unknown(ReasonReadFailed, "the kernel settings were not read: "+err.Error())
		}
		for _, setting := range state.Settings {
			if setting.Key != key {
				continue
			}
			if setting.Current == "" {
				return unknown(ReasonFactMissing, "the host did not report the value of "+key)
			}
			if setting.Current == expected {
				return Result{Passed: true, Observed: key + " = " + setting.Current}
			}
			return Result{
				Observed: key + " = " + setting.Current,
				Evidence: firstNonEmpty(setting.Source, "the kernel default"),
				Remediation: &Remediation{
					Action:  "sysctl.ensure",
					Payload: json.RawMessage(`{"kernel":{"settings":{"` + key + `":"` + expected + `"}}}`),
				},
			}
		}
		return unknown(ReasonFactMissing, "the host did not report the key "+key)
	}
}

func evaluateTime(input Input) Result {
	fragment, ok := input.Fragment(moduleTime)
	if !ok {
		return unknown(ReasonFactMissing, "the time state was not read")
	}
	var state czas.Snapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		return unknown(ReasonReadFailed, "the time state was not read: "+err.Error())
	}
	if state.Synchronized == nil {
		return unknown(ReasonFactMissing, "the host did not report its synchronisation state")
	}
	if *state.Synchronized {
		description := "synchronised"
		if state.ReferenceName != "" {
			description += " of " + state.ReferenceName
		}
		return Result{Passed: true, Observed: description}
	}
	return Result{
		Observed: "not synchronised",
		Evidence: firstNonEmpty(state.Service, "no time daemon"),
		Remediation: &Remediation{Note: "naming the time servers is a decision about infrastructure; " +
			"do it with the time.config.apply operation after testing the sources"},
	}
}

func evaluateUpdates(input Input) Result {
	// This check is not computed from a fragment: the panel knows the number
	// of updates from the package inventory, which it normalises itself.
	if input.Host.PendingSecurityUpdates == nil {
		return unknown(ReasonFactMissing, "the host did not report the number of security updates")
	}
	count := *input.Host.PendingSecurityUpdates
	if count == 0 {
		return Result{Passed: true, Observed: "no pending updates"}
	}
	return Result{
		Observed: strconv.Itoa(count) + " pending security updates",
		Remediation: &Remediation{
			Action:  "packages.plan",
			Payload: json.RawMessage(`{"package_plan":{"mode":"upgrade","security_only":true}}`),
			Note:    "the upgrade goes out only after an approved plan; the plan shows what will change",
		},
	}
}

func evaluateReboot(input Input) Result {
	fragment, ok := input.Fragment(modulePower)
	if !ok {
		return unknown(ReasonFactMissing, "the boot state was not read")
	}
	var state power.Snapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		return unknown(ReasonReadFailed, "the boot state was not read: "+err.Error())
	}
	if state.RebootRequired == nil {
		return unknown(ReasonFactMissing, "the host did not report whether it requires a reboot")
	}
	if !*state.RebootRequired {
		return Result{Passed: true, Observed: "no reboot required"}
	}
	return Result{
		Observed: "the host is waiting for a reboot",
		Evidence: strings.Join(state.RebootReasons, ", "),
		Remediation: &Remediation{
			Action:         "system.reboot",
			Payload:        json.RawMessage(`{"reboot":{"delay_seconds":15,"reason":"reboot after updates"}}`),
			Note:           "a reboot ends the plan: whatever comes after it has to be assessed anew",
			RequiresReboot: true,
		},
	}
}

func protectiveState(input Input) (security.Snapshot, bool) {
	fragment, ok := input.Fragment(moduleSecurity)
	if !ok {
		return security.Snapshot{}, false
	}
	var state security.Snapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		return security.Snapshot{}, false
	}
	return state, true
}

func sshState(input Input) (sshmodul.Snapshot, bool) {
	fragment, ok := input.Fragment(moduleSSH)
	if !ok {
		return sshmodul.Snapshot{}, false
	}
	var state sshmodul.Snapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		return sshmodul.Snapshot{}, false
	}
	return state, true
}

func describeMAC(mac security.Mandatory) string {
	switch mac.System {
	case security.SystemSELinux:
		return "SELinux: " + firstNonEmpty(mac.Mode, "mode not determined")
	case security.SystemAppArmor:
		description := "AppArmor"
		if mac.ProfilesEnforcing != nil {
			description += ": enforced profiles " + strconv.Itoa(*mac.ProfilesEnforcing)
		}
		if mac.ProfilesComplain != nil {
			description += ", in complain mode " + strconv.Itoa(*mac.ProfilesComplain)
		}
		return description
	}
	return "none"
}

// unknown returns an undetermined state together with a reason code. The code
// is mandatory: without it the operator does not know whether to wait for a
// read, repair the agent or grant permissions.
func unknown(code, reason string) Result {
	return Result{Unknown: true, ReasonCode: code, Observed: reason}
}

// notApplicable returns the "not applicable" state: the host does not have
// the component the check asks about. That is neither a pass nor a
// failure.
func notApplicable(reason string) Result {
	return Result{NotApplicable: true, ReasonCode: ReasonUnsupported, Observed: reason}
}

// missingCode translates the reason a fact is missing into a code. A refused
// access and a failed read lead to two different actions by the operator.
func missingCode(reason string) string {
	lowered := strings.ToLower(reason)
	switch {
	case strings.Contains(lowered, "uprawnien"), strings.Contains(lowered, "permission denied"),
		strings.Contains(lowered, "tylko root"), strings.Contains(lowered, "securityfs"):
		return ReasonPermissionDenied
	default:
		return ReasonReadFailed
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
