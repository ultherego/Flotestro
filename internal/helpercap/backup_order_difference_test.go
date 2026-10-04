package helpercap

import (
	"strings"
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The read a verifier makes runs under the capability of the run it verifies,
// so it has to send the whole order and not the part the read needs. When it
// did not, the refusal printed two digests and the question "which field" cost
// an hour; this is the answer it gives now.
func TestTheRefusalNamesTheFieldsTheOrderDiffersIn(t *testing.T) {
	payload := &opspec.BackupPayload{
		ID: "nightly", Tool: "restic", Repository: "/srv/backups",
		Paths: []string{"/etc", "/srv"}, KeepLast: 7, KeepDaily: 14,
		Prune: true, Runbook: "notify the team",
	}
	// A request that fills what a plan needs and leaves the rest of the order
	// out: exactly the shape the verifier used to send.
	partial := &helperv1.BackupRequest{
		Operation:  helperv1.BackupRequest_OPERATION_PLAN,
		Id:         payload.ID,
		Tool:       payload.Tool,
		Repository: payload.Repository,
		Paths:      payload.Paths,
	}
	differing := BackupOrderDifference(partial, payload)
	for _, field := range []string{"keep_last", "keep_daily", "prune", "runbook"} {
		if !containsField(differing, field) {
			t.Errorf("the difference does not name %s: %v", field, differing)
		}
	}
	for _, field := range []string{"id", "tool", "repository", "paths"} {
		if containsField(differing, field) {
			t.Errorf("the difference names %s, which the two agree on: %v", field, differing)
		}
	}
	// The whole order, which is what the verifier sends now, agrees.
	whole := &helperv1.BackupRequest{
		Operation:  helperv1.BackupRequest_OPERATION_PLAN,
		Id:         payload.ID,
		Tool:       payload.Tool,
		Repository: payload.Repository,
		Paths:      payload.Paths,
		KeepLast:   int32(payload.KeepLast),
		KeepDaily:  int32(payload.KeepDaily),
		Prune:      payload.Prune,
		Runbook:    payload.Runbook,
	}
	if rest := BackupOrderDifference(whole, payload); len(rest) > 0 {
		t.Errorf("the whole order still differs in %v", rest)
	}
	if backupRequestDigest(whole) != BackupOrderDigest(payload) {
		t.Error("the digests of the whole order disagree although no field does")
	}
}

// A field the request changes is still named, which is the case the binding
// exists for.
func TestATamperedOrderIsNamedByItsField(t *testing.T) {
	payload := &opspec.BackupPayload{ID: "nightly", Tool: "restic", Repository: "/srv/backups"}
	tampered := &helperv1.BackupRequest{
		Id: payload.ID, Tool: payload.Tool, Repository: "/tmp/elsewhere",
	}
	differing := BackupOrderDifference(tampered, payload)
	if len(differing) != 1 || differing[0] != "repository" {
		t.Fatalf("the difference is %v, expected repository alone", differing)
	}
	// And no address of a repository travels into the refusal.
	line := strings.Join(differing, ", ")
	if strings.Contains(line, "/tmp/elsewhere") || strings.Contains(line, "/srv/backups") {
		t.Errorf("the refusal carries a repository address: %q", line)
	}
}

func containsField(fields []string, wanted string) bool {
	for _, field := range fields {
		if field == wanted {
			return true
		}
	}
	return false
}
