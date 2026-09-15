package agent

import (
	"context"
	"fmt"
	"net"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helper"
)

// HelperClient talks to the root helper over a unix socket. The agent has no
// other way to root privileges.
type HelperClient struct {
	socketPath string
}

func NewHelperClient(socketPath string) *HelperClient {
	return &HelperClient{socketPath: socketPath}
}

// Call sends one request and waits for the answer.
func (c *HelperClient) Call(ctx context.Context, request *helperv1.HelperRequest,
	timeout time.Duration) (*helperv1.HelperResponse, error) {
	return c.CallWithProgress(ctx, request, timeout, nil)
}

// CallWithProgress sends a request and passes on the progress the helper
// reports along the way. The connection is single-use: the helper is activated
// on demand and ends its work after an idle period.
//
// A nil progress receiver means no interest - the helper then sends no
// intermediate message at all.
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
	if err := helper.WriteMessage(conn, request); err != nil {
		return nil, fmt.Errorf("sending the request to the helper: %w", err)
	}

	// The progress messages precede the final answer. The read continues until
	// that answer arrives instead of taking the first message: progress is not
	// the result of the operation.
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
		// The helper guards its resources by class, as the agent guards its
		// own claims. A refusal on a busy class is the same answer as the
		// agent's - "wait for that task", not a failure of the operation -
		// and travels under the same code, whichever module asked.
		if !response.GetAccepted() && response.GetErrorCode() == helper.ErrorLocked &&
			helper.BusyResource(response.GetMessage()) != "" {
			response.ErrorCode = RejectResourceBusy
		}
		// A refusal at the helper's own check of the contract is the same
		// answer whichever module asked: the helper did not understand the
		// request and ran nothing. It travels under one code, with the
		// helper's word kept in the message.
		if !response.GetAccepted() && helperRefusedContract(response.GetErrorCode()) {
			response.Message = response.GetErrorCode() + ": " + response.GetMessage()
			response.ErrorCode = RejectHelperRejected
		}
		return &response, nil
	}
}

// helperRefusedContract says whether a helper code is a refusal of the
// request itself - its shape, its protocol version or its action - rather
// than an outcome of the operation. Only those become helper_rejected; a
// locked resource, a failed precondition or an exec failure keep their own
// codes, because the operator does different things about each.
func helperRefusedContract(code string) bool {
	switch code {
	case helper.ErrorMalformed, helper.ErrorUnsupportedVersion, helper.ErrorUnknownAction:
		return true
	}
	return false
}
