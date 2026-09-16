package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The capability at the server: the policy runs before any handler, so a
// refusal has no side effect, and the mode reaches the agent with every
// answer.

type capabilityLab struct {
	server *Server
	signer *helpercap.Signer
	trust  helpercap.TrustStore
}

func newCapabilityLab(t *testing.T, mode helpercap.Mode) *capabilityLab {
	t.Helper()
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := helpercap.NewSignerFromKey(private)
	trust := helpercap.TrustStore{Dir: filepath.Join(dir, "trust.d"), HostIDPath: filepath.Join(dir, "host-id")}
	replay, err := helpercap.OpenReplayStore(filepath.Join(dir, "replay"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replay.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(1000, log)
	server.SetCapabilityPolicy(helpercap.NewPolicy(mode, helpercap.NewVerifier(trust, replay, log)), trust)
	return &capabilityLab{server: server, signer: signer, trust: trust}
}

// enroll hands the server the bundle the panel would return at enrollment.
func (lab *capabilityLab) enroll(t *testing.T, hostID string) {
	t.Helper()
	response := lab.server.handle(context.Background(), &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		Action: &helperv1.HelperRequest_TrustUpdate{TrustUpdate: &helperv1.HelperTrustUpdateRequest{
			Bundle: lab.signer.TrustBundle(hostID, time.Now())}},
	}, nil)
	if !response.GetAccepted() {
		t.Fatalf("the trust bundle was refused: %s: %s", response.GetErrorCode(), response.GetMessage())
	}
	if response.GetTrustResult().GetHostId() != hostID || len(response.GetTrustResult().GetKeyIds()) != 1 {
		t.Fatalf("trust result = %+v", response.GetTrustResult())
	}
}

func (lab *capabilityLab) fileRequest(t *testing.T, path string, capability bool) *helperv1.HelperRequest {
	t.Helper()
	request := &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion, TaskId: "task-1",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)), TimeoutSeconds: 30,
		Action: &helperv1.HelperRequest_File{File: &helperv1.FileRequest{
			Operation: helperv1.FileRequest_OPERATION_ENSURE, Path: path, Content: []byte("x\n"), Mode: "0644"}},
	}
	if capability {
		canonical, err := helpercap.CanonicalPayload(opspec.ActionFileEnsure, opspec.ActionVersion,
			opspec.Payload{File: &opspec.FilePayload{Path: path, Content: "x\n", Mode: "0644"}})
		if err != nil {
			t.Fatal(err)
		}
		issued, signature, err := lab.signer.Issue(helpercap.Mint{HostID: "host-1", TaskID: "task-1",
			ActionType: string(opspec.ActionFileEnsure), PayloadSHA256: helpercap.PayloadDigest(canonical)})
		if err != nil {
			t.Fatal(err)
		}
		request.Capability, request.CapabilitySignature, request.CanonicalPayload = issued, signature, canonical
	}
	return request
}

// policyCodes are the refusals of the capability policy.
var policyCodes = map[string]bool{
	helpercap.ErrorCapabilityRequired: true, helpercap.ErrorCapabilityVersion: true,
	helpercap.ErrorWrongHost: true, helpercap.ErrorWrongAction: true,
	helpercap.ErrorCapabilityExpired: true, helpercap.ErrorTTLTooLong: true,
	helpercap.ErrorPayloadMismatch: true, helpercap.ErrorPayloadBinding: true,
	helpercap.ErrorUnknownKey: true, helpercap.ErrorBadSignature: true,
	helpercap.ErrorInvalidNonce: true, helpercap.ErrorCapabilityReplay: true,
}

// HLP-01 at the server: the right user, no capability, enforce. The file
// the request would write does not come into being.
func TestEnforceRefusesAnUnsignedMutationBeforeAnythingRuns(t *testing.T) {
	lab := newCapabilityLab(t, helpercap.ModeEnforce)
	lab.enroll(t, "host-1")
	path := filepath.Join(t.TempDir(), "managed.conf")

	response := lab.server.handle(context.Background(), lab.fileRequest(t, path, false), nil)
	if response.GetAccepted() || response.GetErrorCode() != helpercap.ErrorCapabilityRequired {
		t.Fatalf("code = %q (%s), expected %s", response.GetErrorCode(), response.GetMessage(), helpercap.ErrorCapabilityRequired)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the refused request wrote the file")
	}
	// A read is still answered under enforce.
	read := &helperv1.HelperRequest{ProtocolVersion: ProtocolVersion, TaskId: "task-r",
		Action: &helperv1.HelperRequest_File{File: &helperv1.FileRequest{
			Operation: helperv1.FileRequest_OPERATION_READ, Path: "/etc/hostname"}}}
	if response := lab.server.handle(context.Background(), read, nil); response.GetErrorCode() == helpercap.ErrorCapabilityRequired {
		t.Fatal("a read was refused for want of a capability")
	}
}

// Under prefer the same request passes as a legacy one, and the answer
// names the mode; a request with a capability is verified and the answer
// echoes the capability.
func TestPreferLetsALegacyRequestThroughAndVerifiesASignedOne(t *testing.T) {
	lab := newCapabilityLab(t, helpercap.ModePrefer)
	lab.enroll(t, "host-1")
	path := filepath.Join(t.TempDir(), "managed.conf")

	legacy := lab.server.handle(context.Background(), lab.fileRequest(t, path, false), nil)
	if legacy.GetErrorCode() == helpercap.ErrorCapabilityRequired {
		t.Fatalf("prefer refused a legacy request: %s", legacy.GetMessage())
	}
	if legacy.GetCapabilityId() != "" {
		t.Error("a legacy answer names a capability")
	}

	request := lab.fileRequest(t, path, true)
	signed := lab.server.handle(context.Background(), request, nil)
	// The write itself may fail on the machine running the tests; what is
	// checked is that the policy did not refuse it.
	if code := signed.GetErrorCode(); policyCodes[code] {
		t.Fatalf("the signed request was refused by the policy: %s: %s", code, signed.GetMessage())
	}
	if signed.GetCapabilityId() != request.GetCapability().GetCapabilityId() {
		t.Errorf("the answer names the capability %q, expected %q", signed.GetCapabilityId(), request.GetCapability().GetCapabilityId())
	}

	// A helper without an identity yet: a capability for the host is a
	// capability for a host the helper cannot vouch for.
	fresh := newCapabilityLab(t, helpercap.ModePrefer)
	refused := fresh.server.handle(context.Background(), fresh.fileRequest(t, path, true), nil)
	if refused.GetErrorCode() != helpercap.ErrorWrongHost {
		t.Fatalf("code = %q, expected %s", refused.GetErrorCode(), helpercap.ErrorWrongHost)
	}
}

// The trust bundle: a second panel cannot replace the keys, and the
// answer of the update says what the keyring holds.
func TestTrustUpdateRefusesAStranger(t *testing.T) {
	lab := newCapabilityLab(t, helpercap.ModePrefer)
	lab.enroll(t, "host-1")
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	response := lab.server.handle(context.Background(), &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		Action: &helperv1.HelperRequest_TrustUpdate{TrustUpdate: &helperv1.HelperTrustUpdateRequest{
			Bundle: helpercap.NewSignerFromKey(stranger).TrustBundle("host-1", time.Now())}},
	}, nil)
	if response.GetAccepted() || response.GetErrorCode() != helpercap.ErrorTrustUntrusted {
		t.Fatalf("code = %q, expected %s", response.GetErrorCode(), helpercap.ErrorTrustUntrusted)
	}
	hostID, _ := lab.trust.HostID()
	if hostID != "host-1" {
		t.Errorf("host id = %q", hostID)
	}
}
