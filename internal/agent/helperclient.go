package agent

import (
	"context"
	"fmt"
	"net"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helper"
)

// HelperClient rozmawia z helperem roota przez gniazdo unixowe.
// Agent nie ma innej drogi do uprawnien roota.
type HelperClient struct {
	socketPath string
}

func NewHelperClient(socketPath string) *HelperClient {
	return &HelperClient{socketPath: socketPath}
}

// Call wysyla jedno zadanie i czeka na odpowiedz. Polaczenie jest
// jednorazowe: helper jest aktywowany na zadanie i konczy prace po bezczynnosci.
func (c *HelperClient) Call(ctx context.Context, request *helperv1.HelperRequest,
	timeout time.Duration) (*helperv1.HelperResponse, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("polaczenie z helperem: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout + 30*time.Second))
	}

	request.ProtocolVersion = helper.ProtocolVersion
	if err := helper.WriteMessage(conn, request); err != nil {
		return nil, fmt.Errorf("wyslanie zadania do helpera: %w", err)
	}

	var response helperv1.HelperResponse
	if err := helper.ReadMessage(conn, &response); err != nil {
		return nil, fmt.Errorf("odpowiedz helpera: %w", err)
	}
	return &response, nil
}
