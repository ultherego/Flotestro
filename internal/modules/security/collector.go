package security

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Runner runs a host tool and returns its output.
type Runner func(ctx context.Context, path string, args ...string) (string, error)

const systemctlPath = "/usr/bin/systemctl"

// auditUnit is the audit daemon unit. The name is the same on both system
// families, so there is nothing to detect here.
const auditUnit = "auditd.service"

// Collect reads what can be read without root.
//
// The module does not go through root as a whole. The SELinux mode, the
// AppArmor switch, FIPS, lockdown, the socket list and the audit unit state
// are readable by everyone - and that is most of the picture. Root is
// needed for four things the agent asks the helper for separately and by
// name.
func Collect(ctx context.Context, run Runner) Snapshot {
	snapshot := Snapshot{ObservedAt: time.Now().UTC(), Missing: map[string]string{}}
	snapshot.MAC = MACState()
	snapshot.Audit = auditState(ctx, run)

	if content, err := os.ReadFile(FIPSFile); err == nil {
		enabled := strings.TrimSpace(string(content)) == "1"
		snapshot.FIPSEnabled = &enabled
	}
	if content, err := os.ReadFile(LockdownFile); err == nil {
		snapshot.Lockdown = ParseLockdown(string(content))
	}
	// Secure boot needs the EFI variables, and only root reads those. A host
	// without EFI answers right away, because the question makes no sense
	// then.
	if !exists(EFIDir) {
		snapshot.SecureBootReason = "the host boots in BIOS mode, so secure boot does not apply"
	} else {
		snapshot.Missing[FactSecureBoot] = "only root reads the EFI variables"
	}

	snapshot.Listening, snapshot.ListeningKnown = sockets(ctx, run)
	if snapshot.ListeningKnown {
		snapshot.Missing[FactSocketOwners] = "only root sees the socket owners"
	}
	if snapshot.MAC.System == SystemAppArmor {
		snapshot.Missing[FactAppArmorProfiles] = "the AppArmor profiles live in securityfs"
	}
	if snapshot.Audit.Present {
		snapshot.Missing[FactAuditRules] = "only root reads the audit rules"
	}
	return snapshot
}

// MissingFacts lists the facts the helper has to be asked for.
func (s Snapshot) MissingFacts() []string {
	names := make([]string, 0, len(s.Missing))
	for name := range s.Missing {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Supplemented adds the facts gathered by the helper to the picture.
//
// A fact that was asked for and could not be read stays on the missing
// list together with the reason: the check turns it into an undetermined
// state, not into a default value.
func (s Snapshot) Supplemented(extra Supplement) Snapshot {
	if s.Missing == nil {
		s.Missing = map[string]string{}
	}
	if extra.ProfilesEnforcing != nil || extra.ProfilesComplain != nil {
		s.MAC.ProfilesEnforcing = extra.ProfilesEnforcing
		s.MAC.ProfilesComplain = extra.ProfilesComplain
		delete(s.Missing, FactAppArmorProfiles)
	}
	if extra.RulesLoaded != nil || extra.RulesConfigured != nil {
		s.Audit.RulesLoaded = extra.RulesLoaded
		s.Audit.RulesConfigured = extra.RulesConfigured
		delete(s.Missing, FactAuditRules)
	}
	if extra.SecureBoot != nil {
		s.SecureBoot = extra.SecureBoot
		s.SecureBootReason = ""
		delete(s.Missing, FactSecureBoot)
	} else if extra.SecureBootReason != "" {
		s.SecureBootReason = extra.SecureBootReason
		delete(s.Missing, FactSecureBoot)
	}
	if extra.SocketOwners != nil {
		for i := range s.Listening {
			key := SocketKey(s.Listening[i].Protocol, s.Listening[i].Address, s.Listening[i].Port)
			if owner, ok := extra.SocketOwners[key]; ok {
				s.Listening[i].Process = owner.Process
				s.Listening[i].PID = owner.PID
			}
		}
		s.OwnersKnown = true
		delete(s.Missing, FactSocketOwners)
	}
	for name, reason := range extra.Errors {
		s.Missing[name] = reason
	}
	if len(s.Missing) == 0 {
		s.Missing = nil
	}
	return s
}

// MACState determines which mandatory access control system protects the
// host.
//
// The read needs no root: the SELinux mode, its configuration and the
// AppArmor switch are readable by everyone. The AppArmor profile count is
// not - that is a separate fact the helper is asked for.
func MACState() Mandatory {
	// SELinux is recognised by its filesystem, not by the configuration
	// file: the configuration is sometimes left on a host where SELinux is
	// disabled in the kernel, and would look like protection.
	configuration, _ := os.ReadFile(MACConfiguration)
	configuredMode, policy := ParseSELinuxConfiguration(string(configuration))

	if exists(SELinuxDir) {
		mac := Mandatory{System: SystemSELinux, ConfiguredMode: configuredMode, Policy: policy}
		if content, err := os.ReadFile(EnforceFile); err == nil {
			mac.Mode = ParseEnforceMode(string(content))
		} else {
			mac.Reason = "mode not read: " + err.Error()
		}
		return mac
	}
	if configuredMode != "" {
		// The configuration says "enforcing", and the kernel has no SELinux
		// at all. This is exactly the case that looks like protection.
		return Mandatory{
			System: SystemSELinux, Mode: ModeDisabled,
			ConfiguredMode: configuredMode, Policy: policy,
			Reason: "SELinux is disabled in the kernel despite the configuration entry",
		}
	}

	if content, err := os.ReadFile(AppArmorFile); err == nil {
		if strings.TrimSpace(string(content)) != "Y" {
			return Mandatory{
				System: SystemAppArmor, Mode: ModeDisabled,
				Reason: "AppArmor is present but disabled in the kernel",
			}
		}
		return Mandatory{System: SystemAppArmor, Mode: ModeEnforcing}
	}
	return Mandatory{Reason: "this host has neither SELinux nor AppArmor"}
}

// auditState describes the audit daemon from what is visible without root.
func auditState(ctx context.Context, run Runner) Audit {
	audit := Audit{Present: exists(AuditctlPath)}
	output, err := run(ctx, systemctlPath, "show", "-p", "LoadState", "-p", "ActiveState", auditUnit)
	if err == nil {
		loaded, active := unitState(output)
		if loaded {
			audit.Present = true
			audit.Active = &active
		}
	}
	if !audit.Present {
		audit.Reason = "this host has no audit daemon"
	}
	return audit
}

// unitState reads the answer of "systemctl show".
func unitState(output string) (loaded, active bool) {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "LoadState":
			loaded = value != "not-found"
		case "ActiveState":
			active = value == "active" || value == "activating"
		}
	}
	return loaded, active
}

// sockets lists what the host exposes to the outside - without owners.
func sockets(ctx context.Context, run Runner) ([]Listener, bool) {
	path := SSPath
	if !exists(path) {
		path = SSPathAlt
	}
	if !exists(path) {
		return nil, false
	}
	// Without -p: the socket owner requires the right to other people's
	// processes, and the socket list itself is complete without it too.
	output, err := run(ctx, path, "-tulnH")
	if err != nil {
		return nil, false
	}
	return ParseListeners(output), true
}

// CollectSupplement reads the facts that need root. The scope is
// enumerated: the helper receives a list of names, not a command to run.
func CollectSupplement(ctx context.Context, run Runner, facts []string) Supplement {
	extra := Supplement{Errors: map[string]string{}}
	for _, fact := range facts {
		switch fact {
		case FactAppArmorProfiles:
			content, err := os.ReadFile(AppArmorProfiles)
			if err != nil {
				extra.Errors[fact] = "profiles not read: " + err.Error()
				continue
			}
			enforcing, complain := ParseAppArmorProfiles(string(content))
			extra.ProfilesEnforcing = &enforcing
			extra.ProfilesComplain = &complain

		case FactAuditRules:
			if output, err := run(ctx, AuditctlPath, "-l"); err == nil {
				loaded := ParseRules(output)
				extra.RulesLoaded = &loaded
			} else {
				extra.Errors[fact] = "kernel rules not read: " + err.Error()
			}
			configured, err := rulesFromFiles()
			if err != nil {
				extra.Errors[fact] = "rules files not read: " + err.Error()
				continue
			}
			extra.RulesConfigured = &configured

		case FactSecureBoot:
			data, err := os.ReadFile(EFIVarsDir + "/" + SecureBootVariable)
			if err != nil {
				extra.SecureBootReason = "EFI variable not read: " + err.Error()
				continue
			}
			state := ParseSecureBoot(data)
			if state == nil {
				extra.SecureBootReason = "the EFI variable has an unexpected size"
				continue
			}
			extra.SecureBoot = state

		case FactSocketOwners:
			path := SSPath
			if !exists(path) {
				path = SSPathAlt
			}
			output, err := run(ctx, path, "-tulpnH")
			if err != nil {
				extra.Errors[fact] = "owners not read: " + err.Error()
				continue
			}
			extra.SocketOwners = map[string]Owner{}
			for _, socket := range ParseListeners(output) {
				extra.SocketOwners[SocketKey(socket.Protocol, socket.Address, socket.Port)] =
					Owner{Process: socket.Process, PID: socket.PID}
			}

		default:
			extra.Errors[fact] = "unknown fact"
		}
	}
	if len(extra.Errors) == 0 {
		extra.Errors = nil
	}
	return extra
}

// rulesFromFiles counts the rules written in the audit configuration.
//
// The source is the rules.d directory if it exists: augenrules assembles
// the audit.rules file from it, so counting both would count the same rules
// twice.
func rulesFromFiles() (int, error) {
	entries, err := os.ReadDir(AuditRulesDir)
	if err == nil {
		total := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
				continue
			}
			content, err := os.ReadFile(filepath.Join(AuditRulesDir, entry.Name()))
			if err != nil {
				return 0, err
			}
			total += ParseRulesFromFile(string(content))
		}
		return total, nil
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	content, err := os.ReadFile(AuditRulesFile)
	if err != nil {
		return 0, err
	}
	return ParseRulesFromFile(string(content)), nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
