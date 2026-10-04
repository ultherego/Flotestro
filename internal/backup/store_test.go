package backup

import "testing"

// A definition keeps its key when what it does changes, so a run is evidence
// about the configuration it used and about no other. Without that the proof of
// a successful copy went on answering for a definition that had been pointed at
// a different repository (audit of 6c38561, DEP-06).
func TestTheFingerprintFollowsWhatADefinitionDoes(t *testing.T) {
	base := Definition{
		Name: "nightly", Tool: "restic", Repository: "/srv/nightly",
		Paths: []string{"/etc", "/var/lib/app"}, Excludes: []string{"/var/lib/app/cache"},
		Runbook: "/usr/local/bin/quiesce",
	}
	same := ConfigFingerprint(base)
	if same != ConfigFingerprint(base) {
		t.Fatal("the fingerprint of one definition is not stable")
	}

	for name, changed := range map[string]Definition{
		"another repository": func() Definition { d := base; d.Repository = "/srv/elsewhere"; return d }(),
		"another tool":       func() Definition { d := base; d.Tool = "borg"; return d }(),
		"another path":       func() Definition { d := base; d.Paths = []string{"/etc"}; return d }(),
		"another exclusion":  func() Definition { d := base; d.Excludes = nil; return d }(),
		"another runbook":    func() Definition { d := base; d.Runbook = ""; return d }(),
	} {
		if ConfigFingerprint(changed) == same {
			t.Errorf("%s gives the same fingerprint, so an older run would answer for it", name)
		}
	}

	// The retention is not in it: keeping fewer copies does not make the
	// copies that exist evidence about somewhere else.
	fewer := base
	fewer.KeepLast = 3
	if ConfigFingerprint(fewer) != same {
		t.Error("a change of the retention invalidates the runs that exist")
	}
}
