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

// Call wysyla jedno zadanie i czeka na odpowiedz.
func (c *HelperClient) Call(ctx context.Context, request *helperv1.HelperRequest,
	timeout time.Duration) (*helperv1.HelperResponse, error) {
	return c.CallWithProgress(ctx, request, timeout, nil)
}

// CallWithProgress wysyla zadanie i przekazuje postep, ktory helper melduje
// w trakcie. Polaczenie jest jednorazowe: helper jest aktywowany na zadanie
// i konczy prace po bezczynnosci.
//
// Odbiorca postepu nil oznacza brak zainteresowania - helper nie wysyla wtedy
// zadnej wiadomosci posredniej.
func (c *HelperClient) CallWithProgress(ctx context.Context, request *helperv1.HelperRequest,
	timeout time.Duration, postep func(*helperv1.TaskProgress)) (*helperv1.HelperResponse, error) {
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
	request.WantProgress = postep != nil
	if err := helper.WriteMessage(conn, request); err != nil {
		return nil, fmt.Errorf("wyslanie zadania do helpera: %w", err)
	}

	// Wiadomosci z postepem poprzedzaja odpowiedz koncowa. Czytamy do skutku,
	// a nie pierwsza z brzegu: postep nie jest wynikiem operacji.
	for {
		var response helperv1.HelperResponse
		if err := helper.ReadMessage(conn, &response); err != nil {
			return nil, fmt.Errorf("odpowiedz helpera: %w", err)
		}
		if p := response.GetProgress(); p != nil && !response.GetFinal() {
			if postep != nil {
				postep(p)
			}
			continue
		}
		return &response, nil
	}
}
