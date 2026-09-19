//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// The tests of this file check the system module of the host management
// document: the platform picture every online host reports, the history of
// kernels the panel keeps, the local sudo policy the helper reads, and the

// systemPayload mirrors the system fragment: the basic facts every agent
// sends and the platform picture laid over them.
type systemPayload struct {
	Hostname string `json:"hostname"`
	OS       struct {
		Kernel       string `json:"kernel"`
		Distribution string `json:"distribution"`
		Version      string `json:"version"`
	} `json:"os"`
	CPU struct {
		Model     string   `json:"model"`
		Threads   *int     `json:"threads"`
		Flags     []string `json:"flags"`
		FlagCount int      `json:"flag_count"`
	} `json:"cpu"`
	Memory struct {
		TotalBytes *uint64 `json:"total_bytes"`
	} `json:"memory"`
	DMI struct {
		Vendor  string `json:"vendor"`
		Product string `json:"product"`
		Serial  string `json:"serial"`
		UUID    string `json:"uuid"`
	} `json:"dmi"`
	Firmware struct {
		Mode string `json:"mode"`
	} `json:"firmware"`
	Kernel struct {
		Release string `json:"release"`
		Cmdline string `json:"cmdline"`
	} `json:"kernel"`
	Distribution struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	} `json:"distribution"`
	Virtualization struct {
		Kind   string `json:"kind"`
		Source string `json:"source"`
	} `json:"virtualization"`
	Boot struct {
		UptimeSeconds *uint64 `json:"uptime_seconds"`
	} `json:"boot"`
	Missing    map[string]string `json:"missing"`
	ObservedAt *time.Time        `json:"observed_at"`
}

// sudoersFileView is one file the helper opened for the sudo policy.
type sudoersFileView struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// sudoersPayload mirrors the sudoers fragment.
type sudoersPayload struct {
	Rules []struct {
		Users          []string `json:"users"`
		Hosts          []string `json:"hosts"`
		Commands       []string `json:"commands"`
		NoPasswd       bool     `json:"nopasswd"`
		AllCommands    bool     `json:"all_commands"`
		RootEquivalent bool     `json:"root_equivalent"`
		Critical       bool     `json:"critical"`
		Source         string   `json:"source"`
		Line           int      `json:"line"`
	} `json:"rules"`
	Files             []sudoersFileView `json:"files"`
	UnavailableReason string            `json:"unavailable_reason"`
}

// connectedHosts returns the connected hosts of the fleet, or skips.
func connectedHosts(t *testing.T, h *harness) []hostView {
	t.Helper()
	var online []hostView
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			online = append(online, host)
		}
	}
	if len(online) == 0 {
		t.Skip("the fleet has no connected host")
	}
	return online
}

// TestEveryOnlineHostReportsItsPlatform guards the rule of the module: the
// picture names the kernel, the release and the machine, and what it could not
// read it names as unknown with a reason rather than leaving blank.
func TestEveryOnlineHostReportsItsPlatform(t *testing.T) {
	h := newHarness(t)
	for _, host := range connectedHosts(t, h) {
		t.Run(host.Hostname, func(t *testing.T) {
			var fragment inventoryFragment
			h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/system", nil, &fragment, http.StatusOK)
			if fragment.UnavailableReason != "" {
				t.Fatalf("the system module was not read: %s", fragment.UnavailableReason)
			}
			var payload systemPayload
			if err := json.Unmarshal(fragment.Payload, &payload); err != nil {
				t.Fatalf("system payload: %v", err)
			}
			if payload.ObservedAt == nil {
				t.Fatalf("the agent of %s sends the basic facts only; the platform picture needs the system module", host.Hostname)
			}
			if payload.Kernel.Release == "" || payload.OS.Kernel == "" {
				t.Errorf("no kernel release: %+v", payload.Kernel)
			}
			if payload.Distribution.ID == "" {
				t.Errorf("no distribution: %+v", payload.Distribution)
			}
			// A rolling release carries no VERSION_ID in os-release; Arch is the one in
			// the lab.
			if payload.Distribution.Version == "" && payload.Distribution.ID != "arch" {
				t.Errorf("no distribution version: %+v", payload.Distribution)
			}
			// The processor and the memory are readable by everyone; a host
			// without them is a broken read, not a machine without a CPU.
			if payload.CPU.Model == "" || payload.CPU.Threads == nil || *payload.CPU.Threads == 0 {
				t.Errorf("no processor: %+v", payload.CPU)
			}
			if payload.Memory.TotalBytes == nil || *payload.Memory.TotalBytes == 0 {
				t.Errorf("no memory total: %+v", payload.Memory)
			}
			if payload.Kernel.Cmdline == "" {
				if reason := payload.Missing["kernel.cmdline"]; reason == "" {
					t.Error("no kernel command line and no reason for it")
				}
			}
			if payload.Virtualization.Kind == "" || payload.Virtualization.Source == "" {
				t.Errorf("virtualization without a verdict or without evidence: %+v", payload.Virtualization)
			}
			if payload.Boot.UptimeSeconds == nil {
				if reason := payload.Missing["boot"]; reason == "" {
					t.Error("no uptime and no reason for it")
				}
			}
			// The DMI identity: either the machine is named, or the reason it is not
			// is.
			if payload.DMI.Vendor == "" && payload.DMI.Product == "" {
				if reason := payload.Missing["dmi"]; reason == "" {
					t.Error("no DMI vendor or product and no reason for it")
				}
			}
			// The UUID of a virtual machine the firmware always fills in, so an empty
			// one without a reason is a fact the panel made up.
			if payload.DMI.UUID == "" && payload.Missing["dmi.uuid"] == "" && payload.Missing["dmi"] == "" {
				t.Error("dmi.uuid is empty without a reason")
			}
			// A refusal to the agent has to be mended by the helper: the
			// reason left over must not name the unprivileged reader.
			for _, fact := range []string{"dmi.serial", "dmi.uuid"} {
				if reason := payload.Missing[fact]; strings.Contains(reason, "only root") {
					t.Errorf("%s stayed refused to the agent: %s", fact, reason)
				}
			}
			if payload.Firmware.Mode != "uefi" && payload.Firmware.Mode != "bios" {
				if reason := payload.Missing["firmware"]; reason == "" {
					t.Errorf("firmware mode %q without a reason", payload.Firmware.Mode)
				}
			}
			for fact, reason := range payload.Missing {
				if reason == "" {
					t.Errorf("%s is missing without a reason", fact)
				}
			}
		})
	}
}

// TestThePanelKeepsThePlatformHistory: a host that reported its inventory has
// at least one row in its history, and the newest row is the platform the
// system module names now.
func TestThePanelKeepsThePlatformHistory(t *testing.T) {
	h := newHarness(t)
	for _, host := range connectedHosts(t, h) {
		t.Run(host.Hostname, func(t *testing.T) {
			var fragment inventoryFragment
			h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/system", nil, &fragment, http.StatusOK)
			var payload systemPayload
			if err := json.Unmarshal(fragment.Payload, &payload); err != nil {
				t.Fatalf("system payload: %v", err)
			}

			var history struct {
				Items []struct {
					Kernel              string    `json:"kernel"`
					Distribution        string    `json:"distribution"`
					DistributionVersion string    `json:"distribution_version"`
					FirstSeenAt         time.Time `json:"first_seen_at"`
					LastSeenAt          time.Time `json:"last_seen_at"`
				} `json:"items"`
				Count int `json:"count"`
			}
			h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/system/history", nil, &history, http.StatusOK)
			if history.Count == 0 || len(history.Items) == 0 {
				t.Fatal("the history has no row although the host reported its inventory")
			}
			if history.Count > 20 {
				t.Errorf("the history holds %d rows, more than the twenty the panel keeps", history.Count)
			}
			newest := history.Items[0]
			if newest.Kernel != payload.OS.Kernel || newest.Distribution != payload.OS.Distribution ||
				newest.DistributionVersion != payload.OS.Version {
				t.Errorf("the newest row %+v is not the platform the module names (%s, %s %s)",
					newest, payload.OS.Kernel, payload.OS.Distribution, payload.OS.Version)
			}
			if newest.LastSeenAt.Before(newest.FirstSeenAt) {
				t.Errorf("last seen %v before first seen %v", newest.LastSeenAt, newest.FirstSeenAt)
			}
			for i := 1; i < len(history.Items); i++ {
				if history.Items[i].LastSeenAt.After(history.Items[i-1].LastSeenAt) {
					t.Errorf("the history is not newest first: %v after %v",
						history.Items[i].LastSeenAt, history.Items[i-1].LastSeenAt)
				}
			}
		})
	}
}

// TestLocalSudoersReachTheAccessView: the helper reads the distribution's
// default sudoers, the fragment lists the sudo or wheel group rule with every
// command, and the access view shows it as a local rule that amounts to root -
func TestLocalSudoersReachTheAccessView(t *testing.T) {
	h := newHarness(t)
	for _, host := range connectedHosts(t, h) {
		t.Run(host.Hostname, func(t *testing.T) {
			var fragment inventoryFragment
			h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/sudoers", nil, &fragment, http.StatusOK)
			if fragment.UnavailableReason != "" {
				t.Fatalf("the sudo policy was not read: %s", fragment.UnavailableReason)
			}
			var policy sudoersPayload
			if err := json.Unmarshal(fragment.Payload, &policy); err != nil {
				t.Fatalf("sudoers payload: %v", err)
			}
			if policy.UnavailableReason != "" {
				t.Fatalf("the sudo policy was not read: %s", policy.UnavailableReason)
			}
			for _, file := range policy.Files {
				if file.Reason != "" {
					t.Errorf("%s was not read: %s", file.Path, file.Reason)
				}
			}
			if !slices.ContainsFunc(policy.Files, func(file sudoersFileView) bool { return file.Path == "/etc/sudoers" }) {
				t.Errorf("the main file is not among the files read: %+v", policy.Files)
			}

			// The distribution's default: the sudo group on Debian and Ubuntu, wheel on
			// Fedora, with every command as root.
			groupRule := -1
			for index, rule := range policy.Rules {
				if !rule.AllCommands || rule.Source != "/etc/sudoers" {
					continue
				}
				if slices.Contains(rule.Users, "%sudo") || slices.Contains(rule.Users, "%wheel") {
					groupRule = index
					break
				}
			}
			if groupRule < 0 && host.OSFamily != "arch" {
				t.Fatalf("no %%sudo or %%wheel rule with every command in /etc/sudoers: %+v", policy.Rules)
			}
			if groupRule < 0 {
				for index, rule := range policy.Rules {
					if rule.AllCommands && !slices.Contains(rule.Users, "root") {
						groupRule = index
						break
					}
				}
				if groupRule < 0 {
					t.Fatalf("no rule with every command besides root's own: %+v", policy.Rules)
				}
			}
			if !policy.Rules[groupRule].RootEquivalent || !policy.Rules[groupRule].Critical {
				t.Errorf("the group rule is not marked root-equivalent: %+v", policy.Rules[groupRule])
			}

			// The access view carries the same rule as a local one, with the flag and
			// the file it comes from; the directory half does not decide whether the
			// local half is shown.
			var access struct {
				Known        bool `json:"known"`
				LocalSudoers struct {
					Read   bool   `json:"read"`
					Reason string `json:"reason"`
				} `json:"local_sudoers"`
				LocalSudoRules []struct {
					Users          []string `json:"users"`
					Via            []string `json:"via"`
					ReachesHost    bool     `json:"reaches_host"`
					RootEquivalent bool     `json:"root_equivalent"`
					NoPasswd       bool     `json:"nopasswd"`
					Source         string   `json:"source"`
					Line           int      `json:"line"`
				} `json:"local_sudo_rules"`
				RootEquivalentWarnings []string `json:"root_equivalent_warnings"`
			}
			h.get("/api/v1/hosts/"+host.ID+"/access", &access)
			if !access.LocalSudoers.Read {
				t.Fatalf("the access view does not know the local policy: %s", access.LocalSudoers.Reason)
			}
			expected := policy.Rules[groupRule]
			found := false
			for _, rule := range access.LocalSudoRules {
				if rule.Source != expected.Source || rule.Line != expected.Line || !slices.Equal(rule.Users, expected.Users) {
					continue
				}
				found = true
				if !rule.RootEquivalent {
					t.Errorf("the access view dropped the root-equivalent flag: %+v", rule)
				}
				if !rule.ReachesHost || !slices.Contains(rule.Via, "every host") {
					t.Errorf("a rule on ALL hosts does not reach this host: %+v", rule)
				}
			}
			if !found {
				t.Errorf("the group rule %s:%d is not in the access view: %+v", expected.Source, expected.Line, access.LocalSudoRules)
			}
			if len(access.RootEquivalentWarnings) == 0 {
				t.Error("a root-equivalent local rule raised no warning")
			}
			for _, warning := range access.RootEquivalentWarnings {
				if !strings.Contains(warning, "/etc/sudoers") {
					t.Errorf("a warning without the file it comes from: %s", warning)
				}
			}

			// The panel's judgement follows the files: the check fails when
			// some root-equivalent rule is passwordless and passes otherwise.
			passwordless := 0
			for _, rule := range policy.Rules {
				if rule.RootEquivalent && rule.NoPasswd {
					passwordless++
				}
			}
			report := securityReport(t, h, host.ID)
			var verdict *findingView
			for index := range report.Findings {
				if report.Findings[index].CheckID == "sudo.root_nopasswd" {
					verdict = &report.Findings[index]
				}
			}
			if verdict == nil {
				t.Fatal("the report has no sudo.root_nopasswd finding")
			}
			if verdict.Unknown || !verdict.Applicable {
				t.Fatalf("the check did not judge the policy: %+v", verdict)
			}
			if verdict.Module != "sudoers" || verdict.Revision != fragment.Revision {
				t.Errorf("the finding does not rest on the sudoers fragment: module %s, revision %s", verdict.Module, verdict.Revision)
			}
			if passwordless == 0 && !verdict.Passed {
				t.Errorf("no passwordless root grant, yet the check failed: %s", verdict.Observed)
			}
			if passwordless > 0 {
				if verdict.Passed {
					t.Errorf("%d passwordless root grants, yet the check passed", passwordless)
				}
				if verdict.Remediation == nil || verdict.Remediation.Note == "" {
					t.Error("a failed sudo check without a note on what to do")
				}
			}
		})
	}
}
