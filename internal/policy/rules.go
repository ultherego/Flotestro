package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/compliance"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The inventory modules the rules are judged from.
const (
	modulePackages    = "packages"
	moduleServices    = "services"
	moduleUnitListing = "services.full"
	moduleFiles       = "files"
	moduleKernel      = "kernel"
	moduleAccounts    = "accounts"
)

// The reason codes of a verdict that is not a judgement of the state.
const (
	ReasonFactMissing    = "fact_missing"
	ReasonReadFailed     = "read_failed"
	ReasonStale          = "inventory_stale"
	ReasonListStale      = "package_list_stale"
	ReasonUnsupported    = "unsupported_system"
	ReasonNoRemediation  = "no_remediation"
	ReasonSelectorFailed = "selector_failed"
)

// The pace of the modules, as the agent's cadence classes set it: the services
// in every cycle, the packages and the files every fourth, the kernel and the
// accounts with the daily full report.
var modulePace = map[string]time.Duration{
	moduleServices:    15 * time.Minute,
	modulePackages:    time.Hour,
	moduleFiles:       time.Hour,
	moduleKernel:      24 * time.Hour,
	moduleAccounts:    24 * time.Hour,
	moduleUnitListing: 24 * time.Hour,
}

// MaxFactAge says how old a module's read may be for a verdict to rest
// on it.
func MaxFactAge(module string) time.Duration {
	if pace, ok := modulePace[module]; ok {
		return 2 * pace
	}
	return 2 * 24 * time.Hour
}

// PackageFacts is the panel's copy of a host's package list, with the
// state that says whether the copy still describes the host.
type PackageFacts struct {
	// Loaded says the copy was read at all; a policy without package
	// rules does not read it.
	Loaded bool
	// Digest is the digest of the copy; ReportedDigest the one the host last
	// reported in its inventory.
	Digest         string
	ReportedDigest string
	CollectedAt    *time.Time
	// UnavailableReason says why there is no copy.
	UnavailableReason string
	Installed         map[string]bool
}

// Facts is everything one host is judged from: the record of the host, its
// inventory fragments, the package copy and, for the file rules, a way to
// fetch the content of a managed version.
type Facts struct {
	Host      hosts.Host
	Fragments map[string]inventory.Fragment
	Packages  PackageFacts
	// FileContent returns the content of the managed version with the digest, or
	// false when the panel does not hold it.
	FileContent func(sha256 string) ([]byte, bool)
	Now         time.Time
}

// Judgement is the answer of one rule on one host.
type Judgement struct {
	Verdict string
	Reason  string
	// Revision names the read the verdict rests on.
	Revision string
	// Remediation is the typed operation that removes a drift; nil for a
	// drift the panel cannot fix by itself, with the reason in Reason.
	Remediation *compliance.Remediation
}

// Judge computes the verdict of one rule on one host. It reads facts and
// never touches the host.
func Judge(rule Rule, facts Facts) Judgement {
	switch rule.Kind {
	case KindPackageInstalled:
		return judgePackage(rule, facts, true)
	case KindPackageAbsent:
		return judgePackage(rule, facts, false)
	case KindUnitState:
		return judgeUnit(rule, facts)
	case KindFileContent:
		return judgeFile(rule, facts)
	case KindSysctl:
		return judgeSysctl(rule, facts)
	case KindSSHKeyPresent:
		return judgeSSHKey(rule, facts)
	}
	return errorVerdict(ReasonUnsupported, "the rule kind "+rule.Kind+" is not judged by this panel")
}

// Finding turns a judgement into the shape the remediation builder reads: a
// compliance finding with the rule as its check.
func Finding(index int, rule Rule, version int, judgement Judgement) compliance.Finding {
	finding := compliance.Finding{
		CheckID: CheckID(index, rule), CheckVersion: version, Title: rule.Describe(),
		Severity: compliance.SeverityMedium, Expected: rule.Describe(),
		Observed: judgement.Reason, Revision: judgement.Revision,
	}
	switch judgement.Verdict {
	case VerdictCompliant:
		finding.Applicable, finding.Passed = true, true
	case VerdictDrift:
		finding.Applicable = true
		finding.Remediation = judgement.Remediation
	case VerdictError:
		finding.Applicable, finding.Unknown = true, true
		finding.ReasonCode = reasonCode(judgement.Reason)
	case VerdictNotApplicable:
		finding.ReasonCode = compliance.ReasonUnsupported
	}
	return finding
}

// reasonCode takes the code off the front of a reason.
func reasonCode(reason string) string {
	code, _, _ := strings.Cut(reason, ": ")
	return code
}

// fresh returns the fragment of a module, or the verdict that says why it
// cannot be read from: missing, failed or too old.
func fresh(facts Facts, module string) (inventory.Fragment, *Judgement) {
	fragment, ok := facts.Fragments[module]
	if !ok || len(fragment.Payload) == 0 {
		verdict := errorVerdict(ReasonFactMissing, "the host did not report the module "+module)
		return inventory.Fragment{}, &verdict
	}
	if reason := strings.TrimSpace(fragment.UnavailableReason); reason != "" {
		verdict := errorVerdict(ReasonReadFailed, "the module "+module+" was not read: "+reason)
		verdict.Revision = fragment.Revision
		return inventory.Fragment{}, &verdict
	}
	if !fragment.ObservedAt.IsZero() && facts.Now.Sub(fragment.ObservedAt) > MaxFactAge(module) {
		verdict := errorVerdict(ReasonStale, fmt.Sprintf("the module %s was read %s ago, the limit is %s",
			module, facts.Now.Sub(fragment.ObservedAt).Round(time.Minute), MaxFactAge(module)))
		verdict.Revision = fragment.Revision
		return inventory.Fragment{}, &verdict
	}
	return fragment, nil
}

func errorVerdict(code, reason string) Judgement {
	return Judgement{Verdict: VerdictError, Reason: code + ": " + reason}
}

func notApplicable(reason string) Judgement {
	return Judgement{Verdict: VerdictNotApplicable, Reason: ReasonUnsupported + ": " + reason}
}

// capabilityKnown says whether the host has reported its adapters at all.
func capabilityKnown(host hosts.Host) bool { return len(host.Capabilities) > 0 }

// judgePackage judges the presence or the absence of a package from the
// panel's copy of the list, checked against the digest the host reported.
func judgePackage(rule Rule, facts Facts, wantInstalled bool) Judgement {
	if capabilityKnown(facts.Host) && !facts.Host.Capabilities.Satisfies(hosts.NeedPackages) {
		return notApplicable("the host has no package manager adapter")
	}
	fragment, failed := fresh(facts, modulePackages)
	if failed != nil {
		return *failed
	}
	var reported struct {
		InstalledDigest string `json:"installed_digest"`
		InstalledReason string `json:"installed_unavailable_reason"`
	}
	if err := json.Unmarshal(fragment.Payload, &reported); err != nil {
		return withRevision(errorVerdict(ReasonReadFailed, "the packages module does not decode: "+err.Error()), fragment)
	}
	if reported.InstalledReason != "" {
		return withRevision(errorVerdict(ReasonReadFailed, "the host did not list its packages: "+reported.InstalledReason), fragment)
	}
	if !facts.Packages.Loaded {
		return withRevision(errorVerdict(ReasonFactMissing, "the package list was not consulted"), fragment)
	}
	if facts.Packages.UnavailableReason != "" || facts.Packages.Digest == "" {
		reason := facts.Packages.UnavailableReason
		if reason == "" {
			reason = "the panel holds no copy of the package list"
		}
		return withRevision(errorVerdict(ReasonListStale, reason+"; the list is fetched by the vulnerability cycle"), fragment)
	}
	if reported.InstalledDigest != "" && reported.InstalledDigest != facts.Packages.Digest {
		return withRevision(errorVerdict(ReasonListStale,
			"the panel's copy of the package list is older than the host's; it is refreshed by the vulnerability cycle"), fragment)
	}
	installed := facts.Packages.Installed[rule.Name]
	if installed == wantInstalled {
		if installed {
			return Judgement{Verdict: VerdictCompliant, Reason: rule.Name + " is installed", Revision: fragment.Revision}
		}
		return Judgement{Verdict: VerdictCompliant, Reason: rule.Name + " is not installed", Revision: fragment.Revision}
	}
	if wantInstalled {
		payload, _ := json.Marshal(opspec.Payload{PackageChange: &opspec.PackageChangePayload{Packages: []string{rule.Name}}})
		return Judgement{
			Verdict: VerdictDrift, Reason: rule.Name + " is not installed", Revision: fragment.Revision,
			Remediation: &compliance.Remediation{Action: string(opspec.ActionPackageInstall), Payload: payload},
		}
	}
	// A removal is approved with the set that really goes.
	payload, _ := json.Marshal(opspec.Payload{PackageChange: &opspec.PackageChangePayload{
		Packages: []string{rule.Name}, ExpectedRemovals: []string{rule.Name}}})
	return Judgement{
		Verdict: VerdictDrift, Reason: rule.Name + " is installed", Revision: fragment.Revision,
		Remediation: &compliance.Remediation{Action: string(opspec.ActionPackageRemove), Payload: payload},
	}
}

func withRevision(judgement Judgement, fragment inventory.Fragment) Judgement {
	judgement.Revision = fragment.Revision
	return judgement
}

// unitListing is the shape the gateway writes from a full unit.status
// read.
type unitListing struct {
	Units []struct {
		Name          string `json:"name"`
		ActiveState   string `json:"active_state"`
		UnitFileState string `json:"unit_file_state"`
		LoadState     string `json:"load_state"`
	} `json:"units"`
	Truncated bool `json:"truncated"`
}

// judgeUnit judges a unit from the full listing the panel holds and, for the
// active half, from the failed units of the last cycle: a unit on that list is
// not active whatever the older listing says.
func judgeUnit(rule Rule, facts Facts) Judgement {
	if capabilityKnown(facts.Host) && !facts.Host.Capabilities.Available(hosts.CapSystemd) {
		return notApplicable("the host has no systemd")
	}
	listing, failed := fresh(facts, moduleUnitListing)
	if failed != nil {
		if reasonCode(failed.Reason) == ReasonFactMissing {
			return errorVerdict(ReasonFactMissing,
				"the full unit listing was not read; order unit.status with all=true on the host")
		}
		return *failed
	}
	var units unitListing
	if err := json.Unmarshal(listing.Payload, &units); err != nil {
		return withRevision(errorVerdict(ReasonReadFailed, "the unit listing does not decode: "+err.Error()), listing)
	}
	var enabled, active *bool
	loaded := false
	for _, unit := range units.Units {
		if unit.Name != rule.Unit {
			continue
		}
		loaded = true
		if unit.UnitFileState != "" {
			value := unit.UnitFileState == "enabled" || unit.UnitFileState == "enabled-runtime" ||
				unit.UnitFileState == "static" || unit.UnitFileState == "alias" || unit.UnitFileState == "indirect"
			enabled = &value
		}
		if unit.ActiveState != "" {
			value := unit.ActiveState == "active" || unit.ActiveState == "reloading" || unit.ActiveState == "activating"
			active = &value
		}
	}
	// The failed units come with every cycle; they overrule a listing
	// that may be hours old for the active half.
	if services, failed := fresh(facts, moduleServices); failed == nil {
		var state struct {
			FailedUnits []string `json:"failed_units"`
			Known       bool     `json:"failed_units_known"`
		}
		if json.Unmarshal(services.Payload, &state) == nil && state.Known {
			for _, name := range state.FailedUnits {
				if name == rule.Unit {
					value := false
					active = &value
				}
			}
		}
	}
	if !loaded {
		if units.Truncated {
			return withRevision(errorVerdict(ReasonFactMissing, "the unit listing is cut off and does not carry "+rule.Unit), listing)
		}
		// A unit the host does not know cannot be enabled; the fix for a declared
		// unit is to install what provides it, which is a package rule, not a unit
		// operation.
		return Judgement{Verdict: VerdictDrift, Revision: listing.Revision,
			Reason: ReasonNoRemediation + ": the host has no unit " + rule.Unit + "; declare the package that provides it"}
	}

	var drifts []string
	var steps []compliance.Remediation
	if rule.Enabled != nil {
		switch {
		case enabled == nil:
			return withRevision(errorVerdict(ReasonFactMissing, "the listing does not say whether "+rule.Unit+" is enabled"), listing)
		case *enabled != *rule.Enabled:
			drifts = append(drifts, rule.Unit+" is "+map[bool]string{true: "enabled", false: "disabled"}[*enabled])
			payload, _ := json.Marshal(opspec.Payload{UnitToggle: &opspec.UnitToggle{Unit: rule.Unit, Enabled: *rule.Enabled}})
			steps = append(steps, compliance.Remediation{Action: string(opspec.ActionUnitEnableSet), Payload: payload})
		}
	}
	if rule.Active != nil {
		switch {
		case active == nil:
			return withRevision(errorVerdict(ReasonFactMissing, "the listing does not say whether "+rule.Unit+" is active"), listing)
		case *active != *rule.Active:
			drifts = append(drifts, rule.Unit+" is "+map[bool]string{true: "active", false: "not active"}[*active])
			action := opspec.ActionUnitStart
			if !*rule.Active {
				action = opspec.ActionUnitStop
			}
			payload, _ := json.Marshal(opspec.Payload{Unit: &opspec.UnitPayload{Unit: rule.Unit}})
			steps = append(steps, compliance.Remediation{Action: string(action), Payload: payload})
		}
	}
	if len(drifts) == 0 {
		return Judgement{Verdict: VerdictCompliant, Reason: rule.Unit + " is as declared", Revision: listing.Revision}
	}
	// One rule, one step: the first drift is fixed first, and the next evaluation
	// - the reconciliation cycle the document names - finds the second and fixes
	// it.
	return Judgement{Verdict: VerdictDrift, Reason: strings.Join(drifts, "; "), Revision: listing.Revision,
		Remediation: &steps[0]}
}

// judgeFile judges a managed file from the files module: the host
// reports the digest of every file the panel manages.
func judgeFile(rule Rule, facts Facts) Judgement {
	if capabilityKnown(facts.Host) && !facts.Host.Capabilities.Available(hosts.CapFiles) {
		return notApplicable("the host has no managed files adapter")
	}
	fragment, failed := fresh(facts, moduleFiles)
	if failed != nil {
		return *failed
	}
	var snapshot files.Snapshot
	if err := json.Unmarshal(fragment.Payload, &snapshot); err != nil {
		return withRevision(errorVerdict(ReasonReadFailed, "the files module does not decode: "+err.Error()), fragment)
	}
	var observed *files.File
	for i := range snapshot.Files {
		if snapshot.Files[i].Path == rule.Path {
			observed = &snapshot.Files[i]
		}
	}
	var reason string
	switch {
	case observed == nil:
		reason = "the host does not report " + rule.Path + "; a file the panel has not written is not watched"
	case observed.UnavailableReason != "":
		return withRevision(errorVerdict(ReasonReadFailed, rule.Path+" was not read: "+observed.UnavailableReason), fragment)
	case observed.FromSecret:
		return withRevision(errorVerdict(ReasonFactMissing, rule.Path+" comes from a secret; the host reports no digest for it"), fragment)
	case !observed.Exists:
		reason = rule.Path + " does not exist"
	case observed.SHA256 == "":
		return withRevision(errorVerdict(ReasonFactMissing, "the host reports no digest for "+rule.Path), fragment)
	case observed.SHA256 == rule.SHA256:
		return Judgement{Verdict: VerdictCompliant, Reason: rule.Path + " is at " + shortDigest(rule.SHA256), Revision: fragment.Revision}
	default:
		reason = rule.Path + " is at " + shortDigest(observed.SHA256) + ", not " + shortDigest(rule.SHA256)
	}
	if facts.FileContent == nil {
		return Judgement{Verdict: VerdictDrift, Revision: fragment.Revision,
			Reason: ReasonNoRemediation + ": " + reason + "; the version store was not consulted"}
	}
	content, ok := facts.FileContent(rule.SHA256)
	if !ok {
		return Judgement{Verdict: VerdictDrift, Revision: fragment.Revision,
			Reason: ReasonNoRemediation + ": " + reason + "; the panel holds no version " + shortDigest(rule.SHA256)}
	}
	// The write is bound to the content the host reports now, the way an
	// operator's write is: a file changed again between the judgement and the
	// step is not overwritten blind.
	payload := opspec.FilePayload{Path: rule.Path, Content: string(content)}
	if observed != nil {
		payload.Mode = observed.Mode
		payload.Owner = observed.Owner
		payload.Group = observed.Group
		if observed.Exists {
			payload.ExpectedSHA256 = observed.SHA256
		}
	}
	encoded, _ := json.Marshal(opspec.Payload{File: &payload})
	return Judgement{Verdict: VerdictDrift, Reason: reason, Revision: fragment.Revision,
		Remediation: &compliance.Remediation{Action: string(opspec.ActionFileEnsure), Payload: encoded}}
}

// judgeSysctl judges a kernel setting from the kernel module, the way the
// hardening checks do.
func judgeSysctl(rule Rule, facts Facts) Judgement {
	if capabilityKnown(facts.Host) && !facts.Host.Capabilities.Available(hosts.CapKernel) {
		return notApplicable("the host has no kernel adapter")
	}
	fragment, failed := fresh(facts, moduleKernel)
	if failed != nil {
		return *failed
	}
	var snapshot kernel.Snapshot
	if err := json.Unmarshal(fragment.Payload, &snapshot); err != nil {
		return withRevision(errorVerdict(ReasonReadFailed, "the kernel module does not decode: "+err.Error()), fragment)
	}
	for _, setting := range snapshot.Settings {
		if setting.Key != rule.Key {
			continue
		}
		if setting.Current == "" {
			return withRevision(errorVerdict(ReasonFactMissing, "the host did not report the value of "+rule.Key), fragment)
		}
		if strings.TrimSpace(setting.Current) == strings.TrimSpace(rule.Value) {
			return Judgement{Verdict: VerdictCompliant, Reason: rule.Key + " = " + setting.Current, Revision: fragment.Revision}
		}
		payload, _ := json.Marshal(opspec.Payload{Kernel: &opspec.KernelPayload{Settings: map[string]string{rule.Key: rule.Value}}})
		return Judgement{Verdict: VerdictDrift, Reason: rule.Key + " = " + setting.Current, Revision: fragment.Revision,
			Remediation: &compliance.Remediation{Action: string(opspec.ActionSysctlEnsure), Payload: payload}}
	}
	return withRevision(errorVerdict(ReasonFactMissing, "the host did not report the key "+rule.Key), fragment)
}

// accountListing is the shape of the accounts module.
type accountListing struct {
	Accounts []struct {
		Name    string `json:"name"`
		SSHKeys []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"ssh_keys"`
		UnavailableReason string `json:"unavailable_reason"`
	} `json:"accounts"`
}

// judgeSSHKey judges a key from the fingerprints the host reports on the
// account.
func judgeSSHKey(rule Rule, facts Facts) Judgement {
	fragment, failed := fresh(facts, moduleAccounts)
	if failed != nil {
		return *failed
	}
	var listing accountListing
	if err := json.Unmarshal(fragment.Payload, &listing); err != nil {
		return withRevision(errorVerdict(ReasonReadFailed, "the accounts module does not decode: "+err.Error()), fragment)
	}
	for _, account := range listing.Accounts {
		if account.Name != rule.User {
			continue
		}
		if account.UnavailableReason != "" {
			return withRevision(errorVerdict(ReasonReadFailed, "the keys of "+rule.User+" were not read: "+account.UnavailableReason), fragment)
		}
		fingerprints := make([]string, 0, len(account.SSHKeys))
		for _, key := range account.SSHKeys {
			if key.Fingerprint == rule.Fingerprint {
				return Judgement{Verdict: VerdictCompliant, Reason: "the key is on " + rule.User, Revision: fragment.Revision}
			}
			fingerprints = append(fingerprints, key.Fingerprint)
		}
		sort.Strings(fingerprints)
		switch {
		case rule.PublicKey == "":
			return Judgement{Verdict: VerdictDrift, Revision: fragment.Revision,
				Reason: ReasonNoRemediation + ": the key is not on " + rule.User + "; the rule carries no key material to set"}
		case len(fingerprints) > 0:
			return Judgement{Verdict: VerdictDrift, Revision: fragment.Revision,
				Reason: ReasonNoRemediation + ": the key is not on " + rule.User + ", which holds " +
					fmt.Sprintf("%d other keys", len(fingerprints)) + "; setting the keys would replace them, so set them by hand"}
		}
		payload, _ := json.Marshal(opspec.Payload{LocalUser: &opspec.LocalUserPayload{Name: rule.User, SSHKeys: []string{rule.PublicKey}}})
		return Judgement{Verdict: VerdictDrift, Reason: "the key is not on " + rule.User + ", which holds no key", Revision: fragment.Revision,
			Remediation: &compliance.Remediation{Action: string(opspec.ActionLocalSSHKeysSet), Payload: payload}}
	}
	return Judgement{Verdict: VerdictDrift, Revision: fragment.Revision,
		Reason: ReasonNoRemediation + ": the host has no account " + rule.User}
}
