package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helper"
)

// HelperClient talks to the root helper over a unix socket. The agent has no
// other way to root privileges.
type HelperClient struct {
	socketPath string

	// capabilities holds, by task, the panel's authorization of the task in
	// flight: the capability, its signature and the canonical payload.
	capabilities sync.Map
	// mode is what the helper last said about its capability mode; empty
	// until the helper has answered once.
	mode atomic.Pointer[string]
}

// taskCapability is the authorization of one task as the envelope carried
// it.
type taskCapability struct {
	capability *helperv1.HelperCapability
	signature  []byte
	canonical  []byte
}

func NewHelperClient(socketPath string) *HelperClient {
	return &HelperClient{socketPath: socketPath}
}

// Attach remembers the capability of a task for the requests made on its
// behalf.
func (c *HelperClient) Attach(taskID string, capability *helperv1.HelperCapability, signature, canonical []byte) {
	if c == nil || taskID == "" || capability == nil {
		return
	}
	c.capabilities.Store(taskID, &taskCapability{capability: capability, signature: signature, canonical: canonical})
}

// Detach forgets the capability of a task once the task ended.
func (c *HelperClient) Detach(taskID string) {
	if c == nil || taskID == "" {
		return
	}
	c.capabilities.Delete(taskID)
}

// CapabilityMode is the mode the helper reported with its last answer:
// observe, prefer or enforce.
func (c *HelperClient) CapabilityMode() string {
	if c == nil {
		return ""
	}
	if mode := c.mode.Load(); mode != nil {
		return *mode
	}
	return ""
}

// ProbeCapabilityMode asks the helper which mode it runs in.
func (c *HelperClient) ProbeCapabilityMode(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, _ = c.Call(ctx, &helperv1.HelperRequest{TaskId: "capability-mode-probe"}, 5*time.Second)
	return c.CapabilityMode()
}

// DeliverTrust hands the helper the panel's trust bundle: the host identifier
// and the keys that sign capabilities.
func (c *HelperClient) DeliverTrust(ctx context.Context, bundle *helperv1.HelperTrustBundle) (*helperv1.HelperTrustResult, error) {
	if bundle == nil {
		return nil, errors.New("no trust bundle to deliver")
	}
	response, err := c.Call(ctx, &helperv1.HelperRequest{
		TaskId: "trust-update",
		Action: &helperv1.HelperRequest_TrustUpdate{TrustUpdate: &helperv1.HelperTrustUpdateRequest{Bundle: bundle}},
	}, 30*time.Second)
	if err != nil {
		return nil, err
	}
	if !response.GetAccepted() {
		if response.GetErrorCode() == RejectHelperRejected {
			return nil, fmt.Errorf("%w: %s", ErrHelperWithoutTrust, response.GetMessage())
		}
		return nil, fmt.Errorf("%s: %s", response.GetErrorCode(), response.GetMessage())
	}
	return response.GetTrustResult(), nil
}

// ErrHelperWithoutTrust means a helper from before the trust bundle.
var ErrHelperWithoutTrust = errors.New("the helper does not know the trust bundle")

// Call sends one request and waits for the answer.
func (c *HelperClient) Call(ctx context.Context, request *helperv1.HelperRequest,
	timeout time.Duration) (*helperv1.HelperResponse, error) {
	return c.CallWithProgress(ctx, request, timeout, nil)
}

// CallWithProgress sends a request and passes on the progress the helper
// reports along the way.
func (c *HelperClient) CallWithProgress(ctx context.Context, request *helperv1.HelperRequest,
	timeout time.Duration, progress func(*helperv1.TaskProgress)) (*helperv1.HelperResponse, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to the helper: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout + 30*time.Second))
	}

	request.ProtocolVersion = helper.ProtocolVersion
	request.WantProgress = progress != nil
	// The capability of the task rides on every request made for it.
	if request.GetCapability() == nil && request.GetTaskId() != "" {
		if attached, ok := c.capabilities.Load(request.GetTaskId()); ok {
			bound := attached.(*taskCapability)
			request.Capability = bound.capability
			request.CapabilitySignature = bound.signature
			request.CanonicalPayload = bound.canonical
		}
	}
	if err := helper.WriteMessage(conn, request); err != nil {
		return nil, fmt.Errorf("sending the request to the helper: %w", err)
	}

	// The progress messages precede the final answer.
	for {
		var response helperv1.HelperResponse
		if err := helper.ReadMessage(conn, &response); err != nil {
			return nil, fmt.Errorf("the answer of the helper: %w", err)
		}
		if p := response.GetProgress(); p != nil && !response.GetFinal() {
			if progress != nil {
				progress(p)
			}
			continue
		}
		// What the helper says about its mode is remembered for the next
		// Hello; a helper from before the field says nothing.
		if mode := response.GetCapabilityMode(); mode != "" {
			c.mode.Store(&mode)
		}
		// The helper guards its resources by class, as the agent guards its own
		// claims.
		if !response.GetAccepted() && response.GetErrorCode() == helper.ErrorLocked &&
			helper.BusyResource(response.GetMessage()) != "" {
			response.ErrorCode = RejectResourceBusy
		}
		// A refusal at the helper's own check of the contract is the same answer
		// whichever module asked: the helper did not understand the request and ran
		// nothing.
		if !response.GetAccepted() && helperRefusedContract(response.GetErrorCode()) {
			response.Message = response.GetErrorCode() + ": " + response.GetMessage()
			response.ErrorCode = RejectHelperRejected
		}
		return &response, nil
	}
}

// helperRefusedContract says whether a helper code is a refusal of the request
// itself - its shape, its protocol version or its action - rather than an
// outcome of the operation.
func helperRefusedContract(code string) bool {
	switch code {
	case helper.ErrorMalformed, helper.ErrorUnsupportedVersion, helper.ErrorUnknownAction:
		return true
	}
	return false
}
