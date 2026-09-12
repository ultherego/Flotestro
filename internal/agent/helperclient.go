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
		return &response, nil
	}
}
