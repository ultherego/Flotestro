package helper

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
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
