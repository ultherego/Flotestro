package helpercap

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"google.golang.org/protobuf/proto"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// wholeBackupOrder is the whole order, which is what both the run and the read of a
// verification carry.
func wholeBackupOrder() (*opspec.BackupPayload, *helperv1.BackupRequest) {
	payload := &opspec.BackupPayload{
		ID: "nightly", Tool: "restic", Repository: "/srv/backups",
		Paths: []string{"/etc", "/srv"}, KeepLast: 7, KeepDaily: 14,
		Prune: true, Runbook: "notify the team",
	}
	order := &helperv1.BackupRequest{
		Id: payload.ID, Tool: payload.Tool, Repository: payload.Repository,
		Paths: payload.Paths, KeepLast: int32(payload.KeepLast),
		KeepDaily: int32(payload.KeepDaily), Prune: payload.Prune,
		Runbook: payload.Runbook,
	}
	return payload, order
}

// TestAReadIsPerformedEveryTimeAndAnEffectOnlyOnce is the pair of rules the
// replay store stands for, asked together. A copy runs once however often the
// agent asks; the read that verifies it runs every time, because a verification
// reads the host with the same request before the change and after it, and an
// answer kept from the first told the verifier about the state from before.
func TestAReadIsPerformedEveryTimeAndAnEffectOnlyOnce(t *testing.T) {
	f := newFixture(t)
	payload, order := wholeBackupOrder()
	canonical, err := CanonicalPayload(opspec.ActionBackupRun, opspec.ActionVersion,
		opspec.Payload{Backup: payload})
	if err != nil {
		t.Fatal(err)
	}
	capability, signature := f.issue(Mint{
		ActionType:    string(opspec.ActionBackupRun),
		PayloadSHA256: PayloadDigest(canonical),
	})
	backup := func(operation helperv1.BackupRequest_Operation) *helperv1.HelperRequest {
		asked, ok := proto.Clone(order).(*helperv1.BackupRequest)
		if !ok {
			t.Fatal("the order did not clone")
		}
		asked.Operation = operation
		return &helperv1.HelperRequest{
			TaskId:              "task-1",
			Capability:          capability,
			CapabilitySignature: signature,
			CanonicalPayload:    append([]byte(nil), canonical...),
			Action:              &helperv1.HelperRequest_Backup{Backup: asked},
		}
	}

	// The read before the change.
	before := backup(helperv1.BackupRequest_OPERATION_PLAN)
	expectation := Expect(before)
	if expectation.Mutating || !expectation.Authorized {
		t.Fatalf("a plan is %+v, expected an authorized read", expectation)
	}
	baseline, err := f.verifier.Verify(before, expectation)
	if err != nil {
		t.Fatalf("the read before the change was refused: %v", err)
	}
	if !baseline.Fresh || baseline.Kept != nil || baseline.complete != nil {
		t.Fatalf("the read was reserved as an effect: %+v", baseline)
	}

	// The copy itself: once, and a repeat is answered from what it answered.
	run := backup(helperv1.BackupRequest_OPERATION_RUN)
	taken, err := f.verifier.Verify(run, Expect(run))
	if err != nil {
		t.Fatalf("the copy was refused: %v", err)
	}
	if !taken.Fresh || taken.complete == nil {
		t.Fatalf("the copy carries no way to record its answer: %+v", taken)
	}
	if err := taken.complete([]byte("the copy was made")); err != nil {
		t.Fatalf("recording the answer of the copy: %v", err)
	}
	again, err := f.verifier.Verify(run, Expect(run))
	if err != nil {
		t.Fatalf("a repeat of the copy was refused: %v", err)
	}
	if string(again.Kept) != "the copy was made" {
		t.Fatalf("the copy would have run a second time: %+v", again)
	}

	// The read after the change is the same request as the read before it. It
	// has to reach the host, or the verification reports what was true earlier.
	after := backup(helperv1.BackupRequest_OPERATION_PLAN)
	verification, err := f.verifier.Verify(after, Expect(after))
	if err != nil {
		t.Fatalf("the read that verifies the copy was refused: %v", err)
	}
	if !verification.Fresh || verification.Kept != nil {
		t.Fatalf("the verification was answered from the reading taken before the change: %+v", verification)
	}
}

// TestEveryAuthorizedReadIsCovered keeps the case above from going stale: a new
// read that runs under a capability has to be named here, because the rule it
// lives by is not the rule of a mutation.
func TestEveryAuthorizedReadIsCovered(t *testing.T) {
	covered := map[string]bool{"backup.plan": true}
	file, err := parser.ParseFile(token.NewFileSet(), "expect.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || name.Name != "authorizedRead" || len(call.Args) == 0 {
			return true
		}
		kind, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		found++
		if literal := kind.Value[1 : len(kind.Value)-1]; !covered[literal] {
			t.Errorf("%s is a read carried out under a capability and no case here asks that it is performed every time", literal)
		}
		return true
	})
	if found != len(covered) {
		t.Fatalf("expect.go names %d authorized reads, this guard knows %d", found, len(covered))
	}
}
