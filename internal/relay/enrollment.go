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

// Enrollment jest proxy zgloszen hostow w izolowanej lokalizacji.
//
// Host, ktory nie widzi centrali, nie ma jak zdobyc tozsamosci. Relay jest
// jedynym punktem, ktory widzi obie strony, wiec przyjmuje zgloszenie i
// przekazuje je swoim kanalem mTLS. Nie podpisuje niczego: CA floty zostaje
// w centrali, a relay doklada wylacznie to, czego host udowodnic nie moze -
// z ktorej lokalizacji przyszlo zgloszenie.
type Enrollment struct {
	relay *Relay
}

// EnrollmentHandler wystawia proxy enrollmentu.
func (r *Relay) EnrollmentHandler() (string, http.Handler) {
	return agentv1connect.NewEnrollmentServiceHandler(&Enrollment{relay: r})
}

// Enroll przekazuje zgloszenie hosta do centrali.
//
// Przy zerwanym laczu WAN relay nie konczy enrollmentu sam i nie odklada
// zgloszenia do bufora. Token i CSR nie moga czekac w kolejce: token jest
// jednorazowy, a host, ktory dostalby certyfikat z opoznieniem godzin, i tak
// probowalby w miedzyczasie ponownie. Agent ponawia po powrocie centrali.
func (e *Enrollment) Enroll(ctx context.Context,
	req *connect.Request[agentv1.EnrollRequest],
) (*connect.Response[agentv1.EnrollResponse], error) {
	if e.relay.options.EnrollmentURL == "" {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("ten relay nie posredniczy w rejestracji hostow"))
	}
	klient := e.relay.centralaRelaya()
	odpowiedz, err := klient.ProxyEnroll(ctx, connect.NewRequest(&agentv1.ProxyEnrollRequest{
		Enrollment: req.Msg,
	}))
	if err != nil {
		e.relay.log.Warn("zgloszenie hosta nie doszlo do centrali",
			"machine_id", req.Msg.GetMachineId(), "err", err)
		return nil, err
	}
	e.relay.log.Info("host zarejestrowany przez relay",
		"machine_id", req.Msg.GetMachineId(), "host_id", odpowiedz.Msg.GetHostId())
	return connect.NewResponse(odpowiedz.Msg), nil
}

// centralaRelaya sklada klienta uslugi relayow w centrali.
//
// Osobny klient od tego, ktory niesie sesje agentow: tamten idzie do bramy
// agentow, a zgloszenia ida do uslugi relayow. Adres jest ten sam, ale
// tozsamosc uzywana w uscisku - certyfikat relaya - moze sie zmienic przy
// odnowieniu, wiec klient powstaje na zadanie.
func (r *Relay) centralaRelaya() agentv1connect.RelayServiceClient {
	material := r.tozsamosc.Load()
	return agentv1connect.NewRelayServiceClient(
		&http.Client{
			Timeout: 60 * time.Second,
			Transport: &http2.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{material.cert},
					RootCAs:      material.zaufanie,
					MinVersion:   tls.VersionTLS13,
				},
			},
		},
		r.Brama(),
	)
}
