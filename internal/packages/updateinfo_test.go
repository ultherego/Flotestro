package packages

import (
	"os"
	"strings"
	"testing"
)

// updateinfoOutput is the real output of "dnf updateinfo info" from Fedora 42.
const updateinfoOutput = `Name        : FEDORA-2025-191738fa1f
Title       : firewalld-2.3.2-1.fc42
Severity    : None
Type        : bugfix
Status      : stable
Vendor      : updates@fedoraproject.org
Issued      : 2025-11-25 01:34:32
Description : rebase to v2.3.2
Message     : 
Rights      : Copyright (C) 2026 Red Hat, Inc. and others.
Collection  : 
  Packages  : firewalld-2.3.2-1.fc42.src
            : firewalld-2.3.2-1.fc42.noarch

Name        : FEDORA-2026-d08c298940
Title       : openssh-9.9p1-14.fc42
Severity    : Important
Type        : security
Status      : stable
Vendor      : updates@fedoraproject.org
Issued      : 2026-05-02 01:57:11
Description : Fixes high severity CVE:
            : - CVE-2026-35385: Fix privilege escalation via scp legacy protocol
Message     : 
Rights      : Copyright (C) 2026 Red Hat, Inc. and others.
Reference   : 
  Title     : CVE-2026-35385 openssh: Privilege escalation [fedora-all]
  Id        : 2454941
  Type      : bugzilla
  Url       : https://bugzilla.redhat.com/show_bug.cgi?id=2454941
Collection  : 
  Packages  : openssh-9.9p1-14.fc42.src
            : openssh-clients-9.9p1-14.fc42.x86_64
            : openssh-server-9.9p1-14.fc42.x86_64
            : openssh-9.9p1-14.fc42.x86_64
`

func TestParseUpdateinfoReadsTheVendorFindings(t *testing.T) {
	advisories := ParseUpdateinfo(updateinfoOutput)
	if len(advisories) != 2 {
		t.Fatalf("read %d findings: %+v", len(advisories), advisories)
	}

	bugfix := advisories[0]
	if bugfix.ID != "FEDORA-2025-191738fa1f" || bugfix.Type != "bugfix" {
		t.Fatalf("the first finding: %+v", bugfix)
	}
	// "None" is not a severity: it is a missing severity and is to stay one.
	if bugfix.Severity != "" {
		t.Errorf("the severity of the bug fix = %q", bugfix.Severity)
	}
	if len(bugfix.CVEIDs) != 0 {
		t.Errorf("the bug fix got a CVE: %v", bugfix.CVEIDs)
	}

	security := advisories[1]
	if security.Type != TypeSecurity || security.Severity != "high" {
		t.Fatalf("the security finding: %+v", security)
	}
	// The CVE appears both in the description and in the title of the
	// reference - one is to stay.
	if len(security.CVEIDs) != 1 || security.CVEIDs[0] != "CVE-2026-35385" {
		t.Fatalf("CVE = %v", security.CVEIDs)
	}
	if security.IssuedAt == nil || security.IssuedAt.Year() != 2026 {
		t.Errorf("the date of release = %v", security.IssuedAt)
	}
	if len(security.Packages) != 4 {
		t.Fatalf("read %d packages: %+v", len(security.Packages), security.Packages)
	}
	// The name of a package is sometimes longer than the name of the finding
	// and contains dashes.
	found := false
	for _, pkg := range security.Packages {
		if pkg.Name == "openssh-clients" {
			found = true
			if pkg.EVR != "9.9p1-14.fc42" || pkg.Architecture != "x86_64" {
				t.Errorf("a package with a dash was read as %+v", pkg)
			}
		}
	}
	if !found {
		t.Errorf("the package openssh-clients did not land on the list: %+v", security.Packages)
	}
}

func TestParseNEVRAReadsANameWithDashes(t *testing.T) {
	cases := map[string]AdvisoryPackage{
		"openssh-9.9p1-14.fc42.x86_64":       {Name: "openssh", EVR: "9.9p1-14.fc42", Architecture: "x86_64"},
		"openssh-clients-9.9p1-14.fc42.i686": {Name: "openssh-clients", EVR: "9.9p1-14.fc42", Architecture: "i686"},
		"python3-dnf-plugin-versionlock-4.5.0-1.fc42.noarch": {
			Name: "python3-dnf-plugin-versionlock", EVR: "4.5.0-1.fc42", Architecture: "noarch",
		},
		"kernel-6.17.4-200.fc42.src": {Name: "kernel", EVR: "6.17.4-200.fc42", Architecture: "src"},
	}
	for entry, expected := range cases {
		result, ok := ParseNEVRA(entry)
		if !ok || result != expected {
			t.Errorf("%s -> %+v (ok=%v), expected %+v", entry, result, ok, expected)
		}
	}
	for _, bad := range []string{"", "withoutdashes", "name-withoutarch"} {
		if _, ok := ParseNEVRA(bad); ok {
			t.Errorf("%q was accepted as a NEVRA", bad)
		}
	}
}

// The findings are read from the metadata the host already has: a dnf call
// that may fetch turns an isolated site into a fleet nobody assessed.
func TestTheAdvisoryReadNeverFetches(t *testing.T) {
	source, err := os.ReadFile("updateinfo.go")
	if err != nil {
		t.Fatalf("reading the module: %v", err)
	}
	if !strings.Contains(string(source), `"--cacheonly", "updateinfo"`) {
		t.Error("the advisory read does not pass --cacheonly")
	}
}

// Every advisory the vendor ever published is in that answer, and a host
// carries a handful of them. The blocks are narrowed as they close, so the
// findings that do not concern this host never pile up - and the result has to
// be the one the whole answer would have given.
func TestTheStreamedReadNarrowsToTheSameFindings(t *testing.T) {
	installed := []InstalledPackage{
		{Name: "openssh-server", Architecture: "x86_64"},
		{Name: "firewalld", Architecture: "noarch"},
	}
	present := installedSet(installed)

	var streamed []Advisory
	reader := newUpdateinfoReader(func(advisory Advisory) {
		if narrowed, ok := narrowAdvisory(advisory, present); ok {
			streamed = append(streamed, narrowed)
		}
	})
	for _, line := range strings.Split(updateinfoOutput, "\n") {
		reader.line(line)
	}
	reader.done()

	whole := NarrowToInstalled(ParseUpdateinfo(updateinfoOutput), installed)
	if len(streamed) != len(whole) {
		t.Fatalf("the streamed read gave %d findings and the whole one %d", len(streamed), len(whole))
	}
	for i := range whole {
		if streamed[i].ID != whole[i].ID || len(streamed[i].Packages) != len(whole[i].Packages) {
			t.Errorf("finding %d: %+v, expected %+v", i, streamed[i], whole[i])
		}
	}
	// The bug fix of firewalld is not a vulnerability and must not survive the
	// narrowing, however much of it the host carries.
	if len(streamed) != 1 || streamed[0].Type != TypeSecurity {
		t.Errorf("the narrowing kept %+v", streamed)
	}
}
