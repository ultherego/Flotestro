package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// present says whether a path is there, a dangling link included.
func present(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func wipeRequest() *helperv1.HelperRequest {
	return &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "final-wipe",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  30,
		Action: &helperv1.HelperRequest_FinalWipe{
			FinalWipe: &helperv1.FinalWipeRequest{Reason: "handed over"},
		},
	}
}

// agentStateDirFixture builds a state directory the way the agent leaves
// it: the identity store with a generation, the journal, the old flat key,
// and the state file that is to stay.
func agentStateDirFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	generation := filepath.Join(dir, "identity", "generations", "1")
	if err := os.MkdirAll(generation, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{
		filepath.Join(generation, "agent.key"),
		filepath.Join(dir, "tasks", "journal-1.json"),
		filepath.Join(dir, "agent.key"),
		filepath.Join(dir, "state.json"),
	} {
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The wipe removes the identity and the journal, disables the agent unit
// and schedules the stop for after the reply; what is not the agent's
// membership in the fleet stays.
func TestFinalWipeRemovesTheIdentityAndDisablesTheAgent(t *testing.T) {
	dir := agentStateDirFixture(t)
	tool := &fakeAccountTool{}
	server := testServer()
	server.accountTool = tool.run
	server.agentStateDir = dir

	response := server.handle(context.Background(), wipeRequest(), nil)
	if !response.GetAccepted() {
		t.Fatalf("the wipe was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	for _, gone := range []string{"identity", "tasks", "agent.key"} {
		if present(filepath.Join(dir, gone)) {
			t.Errorf("%s is still there", gone)
		}
	}
	if !present(filepath.Join(dir, "state.json")) {
		t.Error("the state file was removed; the diagnostic tool needs it")
	}
	result := response.GetFinalWipeResult()
	if len(result.GetRemoved()) != 3 || !result.GetServiceDisabled() || !result.GetStopScheduled() {
		t.Fatalf("result = %+v", result)
	}
	if len(tool.calls) != 2 ||
		joinedCall(tool.calls[0]) != "systemctl disable "+AgentUnit ||
		!strings.HasPrefix(joinedCall(tool.calls[1]), "systemd-run ") ||
		!strings.HasSuffix(joinedCall(tool.calls[1]), "-- systemctl stop "+AgentUnit) {
		t.Fatalf("calls = %v", tool.calls)
	}
}

// A unit that cannot be disabled fails the request - the identity is gone
// by then, and the answer says so rather than passing it over.
func TestFinalWipeReportsAUnitThatWasNotDisabled(t *testing.T) {
	dir := agentStateDirFixture(t)
	tool := &fakeAccountTool{fail: "systemctl"}
	server := testServer()
	server.accountTool = tool.run
	server.agentStateDir = dir

	response := server.handle(context.Background(), wipeRequest(), nil)
	if response.GetAccepted() || response.GetErrorCode() != ErrorExecFailed {
		t.Fatalf("response = %+v", response)
	}
	if present(filepath.Join(dir, "identity")) {
		t.Error("the identity stayed although the answer says it was removed")
	}
	if len(response.GetFinalWipeResult().GetRemoved()) != 3 {
		t.Errorf("removed = %v", response.GetFinalWipeResult().GetRemoved())
	}
	if len(tool.calls) != 1 {
		t.Errorf("the stop was scheduled after the disable failed: %v", tool.calls)
	}
}

// A symbolic link in the state directory is removed as a link. The helper
// runs as root and does not remove through links.
func TestFinalWipeDoesNotFollowLinks(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, "identity")); err != nil {
		t.Fatal(err)
	}
	tool := &fakeAccountTool{}
	server := testServer()
	server.accountTool = tool.run
	server.agentStateDir = dir

	response := server.handle(context.Background(), wipeRequest(), nil)
	if !response.GetAccepted() {
		t.Fatalf("the wipe was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	if present(filepath.Join(dir, "identity")) {
		t.Error("the link is still there")
	}
	if !present(filepath.Join(elsewhere, "keep")) {
		t.Error("the wipe followed the link and removed the target")
	}
}

// An empty state directory is a host that never enrolled: nothing to remove
// is not a failure, and the service is still disabled.
func TestFinalWipeOnAnEmptyDirectory(t *testing.T) {
	tool := &fakeAccountTool{}
	server := testServer()
	server.accountTool = tool.run
	server.agentStateDir = t.TempDir()

	response := server.handle(context.Background(), wipeRequest(), nil)
	if !response.GetAccepted() {
		t.Fatalf("the wipe was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	if len(response.GetFinalWipeResult().GetRemoved()) != 0 {
		t.Errorf("removed = %v", response.GetFinalWipeResult().GetRemoved())
	}
}
