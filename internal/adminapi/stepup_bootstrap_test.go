package adminapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
)

// By default an API token does not carry out the operations that need fresh
// authentication: nobody is behind it to authenticate. The one thing that has to
// work before anybody can sign in is the handover - the bootstrap token making the
// first administrator - and it closes the moment somebody else has got in.
func TestTheBootstrapTokenMayDoTheHandoverAndNothingElseAndOnlyUntilItIsDone(t *testing.T) {
	boot := authz.BootstrapSubject
	for _, c := range []struct {
		name      string
		subject   string
		action    string
		live      bool
		takenOver bool
		want      bool
	}{
		{"the first administrator is made", boot, "principal.create", true, false, true},
		{"and given a password", boot, "principal.password.set", true, false, true},
		{"and a token of their own", boot, "principal.token.issue", true, false, true},
		{"and the first group mapping", boot, "group_mapping.create", true, false, true},
		{"not a role definition", boot, "role.create", true, false, false},
		{"not a secret", boot, "secret.create", true, false, false},
		{"not a CA rotation", boot, "pki.ca.activate", true, false, false},
		{"not once somebody has taken over", boot, "principal.create", true, true, false},
		{"not once the token is revoked", boot, "principal.create", false, false, false},
		{"not for another identity", "ops-bot", "principal.create", true, false, false},
	} {
		if got := bootstrapMayCarryOut(c.subject, c.action, c.live, c.takenOver); got != c.want {
			t.Errorf("%s: %s by %s (live %v, taken over %v) = %v, expected %v",
				c.name, c.action, c.subject, c.live, c.takenOver, got, c.want)
		}
	}
}

// A name in the list that no operation uses is a handover step that quietly does
// not work; the names are held to the calls that ask for step-up.
func TestEveryBootstrapActionIsOneAnOperationAsksStepUpFor(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	var source strings.Builder
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		source.Write(raw)
	}
	for action := range bootstrapActions {
		if !strings.Contains(source.String(), `"`+action+`"`) {
			t.Errorf("the bootstrap action %q is not asked for by any operation", action)
		}
	}
}

func TestAnAllowedTokenIsMarkedInTheTrailAndARefusedOneIsTurnedAway(t *testing.T) {
	reason := "an automation changes the access rules"

	allowed := stepUpPolicy{MaxAge: 5 * time.Minute}
	evidence, denial := allowed.evaluate(reason, nil)
	if denial != nil {
		t.Fatalf("a token was refused under allow: %+v", denial)
	}
	if evidence["step_up_waived"] != true || evidence["policy"] != "allow" || evidence["reauthenticated"] != false {
		t.Errorf("the trail does not say the token was let through without fresh authentication: %v", evidence)
	}

	refused := stepUpPolicy{MaxAge: 5 * time.Minute, RefuseTokens: true}
	if _, denial := refused.evaluate(reason, nil); denial == nil || denial.Code != "reauthentication_required" {
		t.Errorf("a token was not turned away under refuse: %+v", denial)
	}
}
