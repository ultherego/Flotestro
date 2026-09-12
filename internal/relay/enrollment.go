package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
)

// Enrollment is the proxy of host registrations in an isolated site.
//
// A host that does not see the centre has no way of getting an identity. The
// relay is the only point that sees both sides, so it accepts the registration
// and forwards it over its own mTLS channel. It signs nothing: the CA of the
// fleet stays in the centre, and the relay adds only what the host cannot
// prove - which site the registration came from.
type Enrollment struct {
	relay *Relay
}

// EnrollmentHandler exposes the enrollment proxy.
func (r *Relay) EnrollmentHandler() (string, http.Handler) {
	return agentv1connect.NewEnrollmentServiceHandler(&Enrollment{relay: r})
}

// Enroll forwards the registration of a host to the centre.
//
// With the WAN link down the relay does not finish the enrollment itself and
// does not set the registration aside in the buffer. A token and a CSR must
// not wait in a queue: the token is one-time, and a host that got its
// certificate hours late would have tried again in the meantime anyway. The
// agent retries once the centre is back.
func (e *Enrollment) Enroll(ctx context.Context,
	req *connect.Request[agentv1.EnrollRequest],
) (*connect.Response[agentv1.EnrollResponse], error) {
	if e.relay.options.EnrollmentURL == "" {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("this relay does not mediate in the registration of hosts"))
	}
	client_ := e.relay.relayCentre()
	response, err := client_.ProxyEnroll(ctx, connect.NewRequest(&agentv1.ProxyEnrollRequest{
		Enrollment: req.Msg,
	}))
	if err != nil {
		e.relay.log.Warn("the registration of the host did not reach the centre",
			"machine_id", req.Msg.GetMachineId(), "err", err)
		return nil, err
	}
	e.relay.log.Info("the host was registered through the relay",
		"machine_id", req.Msg.GetMachineId(), "host_id", response.Msg.GetHostId())
	return connect.NewResponse(response.Msg), nil
}

// relayCentre assembles the client of the relay service in the centre.
//
// A client separate from the one that carries the sessions of the agents: that
// one goes to the agent gateway, and the registrations go to the relay
// service. The address is the same, but the identity used in the handshake -
// the certificate of the relay - can change at a renewal, so the client is
// created on demand.
func (r *Relay) relayCentre() agentv1connect.RelayServiceClient {
	material := r.identity.Load()
	return agentv1connect.NewRelayServiceClient(
		&http.Client{
			Timeout: 60 * time.Second,
			Transport: &http2.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{material.cert},
					RootCAs:      material.trust,
					MinVersion:   tls.VersionTLS13,
				},
			},
		},
		r.Gateway(),
	)
}
