package helper

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os/user"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/schedules"
)

func testServer() *Server {
	return NewServer(1000, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func unitRequest(unit string, mutate func(*helperv1.HelperRequest)) *helperv1.HelperRequest {
	request := &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "task-1",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  30,
		MaxOutputBytes:  4096,
		Action: &helperv1.HelperRequest_UnitAction{
			UnitAction: &helperv1.UnitActionRequest{
				Unit:      unit,
				Operation: helperv1.UnitActionRequest_OPERATION_RESTART,
			},
		},
	}
	if mutate != nil {
		mutate(request)
	}
	return request
}

func TestTheHelperRejectsAnUnknownProtocolVersion(t *testing.T) {
	// The helper runs as root: an unknown version means it does not understand
	// the meaning of the fields, so it must not guess.
	request := unitRequest("nginx.service", func(r *helperv1.HelperRequest) {
		r.ProtocolVersion = ProtocolVersion + 1
	})
	response := testServer().handle(context.Background(), request, nil)
	if response.GetAccepted() {
		t.Fatal("a request in an unknown protocol version was accepted")
	}
	if response.GetErrorCode() != ErrorUnsupportedVersion {
		t.Fatalf("code = %q, expected %q", response.GetErrorCode(), ErrorUnsupportedVersion)
	}
}

func TestTheHelperRejectsARequestPastItsDeadline(t *testing.T) {
	// The TTL is checked by the helper as well, not only by the agent. A
	// request that arrived after the network came back must not be performed.
	request := unitRequest("nginx.service", func(r *helperv1.HelperRequest) {
		r.ExpiresAt = timestamppb.New(time.Now().Add(-time.Second))
	})
	response := testServer().handle(context.Background(), request, nil)
	if response.GetAccepted() {
		t.Fatal("a request past its deadline was performed")
	}
	if response.GetErrorCode() != ErrorExpired {
		t.Fatalf("code = %q, expected %q", response.GetErrorCode(), ErrorExpired)
	}
}

func TestTheHelperProtectsCriticalUnits(t *testing.T) {
	// The validation is repeated on the root side: the helper does not trust
	// that the agent checked the protection policy.
	for _, unit := range []string{"flotestro-agent.service", "sshd.service", "NetworkManager.service"} {
		response := testServer().handle(context.Background(), unitRequest(unit, nil), nil)
		if response.GetAccepted() {
			t.Errorf("an operation on the protected unit %q was allowed", unit)
			continue
		}
		if response.GetErrorCode() != ErrorProtectedUnit {
			t.Errorf("for %q code = %q, expected %q", unit, response.GetErrorCode(), ErrorProtectedUnit)
		}
	}
}

func TestTheHelperRejectsAnInvalidUnitName(t *testing.T) {
	for _, unit := range []string{"nginx.service; reboot", "../../x.service", "nginx"} {
		response := testServer().handle(context.Background(), unitRequest(unit, nil), nil)
		if response.GetAccepted() {
			t.Errorf("the name %q was allowed", unit)
			continue
		}
		if response.GetErrorCode() != ErrorInvalidUnit {
			t.Errorf("for %q code = %q, expected %q", unit, response.GetErrorCode(), ErrorInvalidUnit)
		}
	}
}

func TestTheHelperRejectsAMissingAction(t *testing.T) {
	request := &helperv1.HelperRequest{ProtocolVersion: ProtocolVersion, TaskId: "task-2"}
	response := testServer().handle(context.Background(), request, nil)
	if response.GetAccepted() || response.GetErrorCode() != ErrorUnknownAction {
		t.Fatalf("code = %q, expected %q", response.GetErrorCode(), ErrorUnknownAction)
	}
}

func TestTheHelperRejectsAnUnknownOperation(t *testing.T) {
	request := unitRequest("nginx.service", func(r *helperv1.HelperRequest) {
		r.GetUnitAction().Operation = helperv1.UnitActionRequest_OPERATION_UNSPECIFIED
	})
	response := testServer().handle(context.Background(), request, nil)
	if response.GetAccepted() || response.GetErrorCode() != ErrorUnknownAction {
		t.Fatalf("code = %q, expected %q", response.GetErrorCode(), ErrorUnknownAction)
	}
}

func TestMessageFraming(t *testing.T) {
	var buffer bytes.Buffer
	original := unitRequest("nginx.service", nil)
	if err := WriteMessage(&buffer, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	var decoded helperv1.HelperRequest
	if err := ReadMessage(&buffer, &decoded); err != nil {
		t.Fatalf("read: %v", err)
	}
	if decoded.GetTaskId() != original.GetTaskId() {
		t.Fatalf("task_id = %q, expected %q", decoded.GetTaskId(), original.GetTaskId())
	}
	if decoded.GetUnitAction().GetUnit() != "nginx.service" {
		t.Fatalf("unit = %q", decoded.GetUnitAction().GetUnit())
	}
}

func TestTheReadRejectsAnOversizedFrame(t *testing.T) {
	// The peer of the helper must not force an arbitrary allocation in the root
	// process.
	header := []byte{0xff, 0xff, 0xff, 0xff}
	var decoded helperv1.HelperRequest
	err := ReadMessage(bytes.NewReader(header), &decoded)
	if err == nil {
		t.Fatal("a frame over the limit was accepted")
	}
}

func TestClampTrimsTheOutput(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 100)
	clamped, truncated := clamp(data, 10)
	if len(clamped) != 10 || !truncated {
		t.Fatalf("len=%d truncated=%v, expected 10/true", len(clamped), truncated)
	}
	short, truncated := clamp([]byte("abc"), 10)
	if len(short) != 3 || truncated {
		t.Fatalf("a short output was cut")
	}
}

func scheduleRequest(mutate func(*helperv1.ScheduleRequest)) *helperv1.HelperRequest {
	action := &helperv1.ScheduleRequest{
		Operation:  helperv1.ScheduleRequest_OPERATION_ENSURE,
		Id:         "probe",
		Expression: "0 3 * * *",
		Command:    []string{"/usr/bin/true"},
		User:       "root",
	}
	if mutate != nil {
		mutate(action)
	}
	return &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "task-schedule",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  30,
		Action:          &helperv1.HelperRequest_Schedule{Schedule: action},
	}
}

// The user of a cron line is separated from the command by whitespace
// only, and the helper used to put whatever the request said into that
// field, root by default. A value with a space, a newline or a comment
// sign is refused before anything on the host is read, as is a name the
// host has no account for and an entry that names no account at all.
func TestTheHelperRefusesAScheduleUserThatIsNotAnAccount(t *testing.T) {
	cases := map[string]string{
		"":                             ErrorUserRequired,
		"root; /bin/sh":                ErrorUnknownUser,
		"root\n* * * * * root /bin/sh": ErrorUnknownUser,
		"root #":                       ErrorUnknownUser,
		"Root":                         ErrorUnknownUser,
		"no-such-user-flotestro":       ErrorUnknownUser,
	}
	for name, code := range cases {
		request := scheduleRequest(func(r *helperv1.ScheduleRequest) { r.User = name })
		response := testServer().handle(context.Background(), request, nil)
		if response.GetAccepted() {
			t.Errorf("user %q was accepted", name)
			continue
		}
		if response.GetErrorCode() != code {
			t.Errorf("for user %q code = %q, expected %q: %s", name, response.GetErrorCode(), code, response.GetMessage())
		}
	}
}

// The account has to exist under exactly the name asked for: a resolver
// that answers a lookup of one spelling with another account would put
// the spelling on the line, not the account.
func TestTheScheduleUserCheckAcceptsAnExistingAccount(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	for _, name := range []string{"root", current.Username} {
		if !schedules.ValidUser(name) {
			// The account running the tests may have a name outside the
			// conservative set; root is always inside it.
			continue
		}
		if refusal := checkScheduleUser(name, nil); refusal != nil {
			t.Errorf("the account %q was refused: %s %s", name, refusal.GetErrorCode(), refusal.GetMessage())
		}
	}
}

// Root needs its grant once the request carries a capability. A request
// without one is judged by the panel alone, as before the capability
// existed; a capability without the grant refuses root and root only.
func TestRootScheduleNeedsTheGrantWhenGrantsAreKnown(t *testing.T) {
	if refusal := checkScheduleUser("root", nil); refusal != nil {
		t.Fatalf("root without a capability was refused: %s", refusal.GetErrorCode())
	}
	refusal := checkScheduleUser("root", []string{"schedule.write"})
	if refusal == nil || refusal.GetErrorCode() != ErrorRootGrantRequired {
		t.Fatalf("root without the grant = %v, want %s", refusal, ErrorRootGrantRequired)
	}
	if refusal := checkScheduleUser("root", []string{"schedule.write", PermissionScheduleRootExec}); refusal != nil {
		t.Fatalf("root with the grant was refused: %s", refusal.GetErrorCode())
	}
	if refusal := checkScheduleUser("nobody", []string{"schedule.write"}); refusal != nil {
		t.Fatalf("a non-root account was held to the root grant: %s", refusal.GetErrorCode())
	}
}

// A zero byte ends the string for the tools that read the line; the line
// composer looks for shell characters and would not see it.
func TestTheHelperRefusesAScheduleCommandWithAZeroByte(t *testing.T) {
	for _, command := range [][]string{
		{"/usr/bin/true\x00; /bin/sh"},
		{"/usr/bin/true", "a\x00b"},
		{"true"},
		{},
	} {
		request := scheduleRequest(func(r *helperv1.ScheduleRequest) { r.Command = command })
		response := testServer().handle(context.Background(), request, nil)
		if response.GetAccepted() || response.GetErrorCode() != ErrorMalformed {
			t.Errorf("command %q: code = %q, expected %q", command, response.GetErrorCode(), ErrorMalformed)
		}
	}
}
