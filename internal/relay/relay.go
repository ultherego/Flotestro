package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/pki"
)

// hostHeader niesie tozsamosc hosta poswiadczona przez relay. Nazwa musi byc
// zgodna z gatewayem: to jedyne miejsce, w ktorym panel dowiaduje sie, czyj
// ruch przechodzi przez relay.
const hostHeader = "Flotestro-Relay-Host"

// Options opisuje relay lokalizacji.
type Options struct {
	// UpstreamURL jest adresem bramy agentow w centrali.
	UpstreamURL string
	// Identity jest tozsamoscia relaya wobec centrali.
	Identity tls.Certificate
	// TrustPool weryfikuje zarowno centrale, jak i certyfikaty agentow:
	// jedno CA floty obejmuje obie strony.
	TrustPool *x509.CertPool
	// BufferBytes ogranicza pamiec przeznaczona na wyniki czekajace na
	// powrot lacza.
	BufferBytes int
	Log         *slog.Logger
}

// Relay posredniczy miedzy agentami lokalizacji a centrala.
type Relay struct {
	options Options
	client  agentv1connect.AgentServiceClient
	buffer  *Buffer
	log     *slog.Logger

	mu sync.RWMutex
	// sesje trzymaja funkcje przerwania. Po powrocie lacza sesja pracujaca
	// w trybie buforowania jest konczona, zeby agent polaczyl sie na nowo
	// i wrocil do przekazywania na zywo; inaczej zostalaby w tym trybie
	// do konca swojego zycia, mimo ze centrala znowu odpowiada.
	sesje    map[string]context.CancelFunc
	upstream atomic.Bool
}

func New(options Options) *Relay {
	log := options.Log
	if log == nil {
		log = slog.Default()
	}
	client := agentv1connect.NewAgentServiceClient(
		&http.Client{Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{options.Identity},
				RootCAs:      options.TrustPool,
				MinVersion:   tls.VersionTLS13,
			},
			// Zerwane lacze WAN nie objawia sie bledem wysylki: dane mieszcza
			// sie w buforze jadra, a TCP retransmituje je kilkanascie minut.
			// Bez aktywnego badania relay przez ten czas uwazalby, ze wszystko
			// dziala, i nie zaczalby buforowac.
			ReadIdleTimeout: 15 * time.Second,
			PingTimeout:     10 * time.Second,
		}},
		options.UpstreamURL,
		connect.WithGRPC(),
	)
	return &Relay{
		options: options, client: client, log: log,
		buffer: NewBuffer(options.BufferBytes),
		sesje:  map[string]context.CancelFunc{},
	}
}

// Handler obsluguje polaczenia agentow. Relay wystawia ten sam kontrakt co
// centrala, wiec agent nie wie i nie musi wiedziec, ze rozmawia przez relay.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(agentv1connect.NewAgentServiceHandler(r))
	return mux
}

// RenewCertificate przekazuje odnowienie certyfikatu do centrali.
//
// Relay nie podpisuje niczego sam: CA floty zostaje w centrali, a relay
// jedynie posredniczy. Certyfikat agenta jest tu weryfikowany w uscisku TLS,
// wiec tozsamosc wnioskujacego jest znana i doklejana tak samo jak w sesji.
func (r *Relay) RenewCertificate(ctx context.Context,
	req *connect.Request[agentv1.RenewCertificateRequest],
) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("brak certyfikatu klienta"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	forwarded := connect.NewRequest(req.Msg)
	forwarded.Header().Set(hostHeader, hostID)
	response, err := r.client.RenewCertificate(ctx, forwarded)
	if err != nil {
		// Odnowienie musi dojsc do centrali; bufor tu nie pomoze, bo agent
		// czeka na odpowiedz. Powtorzy probe zgodnie z wlasnym harmonogramem.
		return nil, err
	}
	return connect.NewResponse(response.Msg), nil
}

// FetchSecret przekazuje pobranie sekretu do centrali.
//
// Relay nie przechowuje ani nie oglada wartosci: przekazuje wywolanie razem
// z tozsamoscia hosta, a decyzje o wydaniu podejmuje centrala na podstawie
// dzierzawy. Bufor tu nie ma sensu - host czeka na odpowiedz, a dzierzawa
// jest krotka.
func (r *Relay) FetchSecret(ctx context.Context,
	req *connect.Request[agentv1.FetchSecretRequest],
) (*connect.Response[agentv1.FetchSecretResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("brak certyfikatu klienta"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	forwarded := connect.NewRequest(req.Msg)
	forwarded.Header().Set(hostHeader, hostID)
	response, err := r.client.FetchSecret(ctx, forwarded)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response.Msg), nil
}

// Ping przekazuje badanie lacznosci do centrali. Relay nie odpowiada sam:
// pytanie dotyczy drogi do centrali, a nie tego, czy relay dziala.
func (r *Relay) Ping(ctx context.Context,
	req *connect.Request[agentv1.PingRequest],
) (*connect.Response[agentv1.PingResponse], error) {
	response, err := r.client.Ping(ctx, connect.NewRequest(req.Msg))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response.Msg), nil
}

// Connect przekazuje sesje agenta do centrali.
//
// Tozsamosc hosta pochodzi z certyfikatu agenta zweryfikowanego w uscisku TLS
// po stronie relaya i jest doklejana do polaczenia w gore. Relay nie przeglada
// tresci zadan; jego rola konczy sie na przekazaniu i zbuforowaniu.
func (r *Relay) Connect(ctx context.Context,
	stream *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("brak certyfikatu klienta"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return connect.NewError(connect.CodeUnauthenticated, err)
	}

	sessionCtx, zakoncz := context.WithCancel(ctx)
	defer zakoncz()
	r.trackSession(hostID, zakoncz)
	defer r.trackSession(hostID, nil)

	upstream := r.client.Connect(sessionCtx)
	upstream.RequestHeader().Set(hostHeader, hostID)
	defer func() {
		_ = upstream.CloseRequest()
		_ = upstream.CloseResponse()
	}()

	// Zerwanie lacza poznajemy po stronie odbioru. Wysylka tego nie pokaze:
	// dane trafiaja do kolejki HTTP/2 i do bufora jadra, wiec Send konczy sie
	// powodzeniem jeszcze dlugo po tym, jak centrala przestala odpowiadac.
	utracone := make(chan struct{})
	var raz sync.Once
	go func() {
		err := r.pumpDown(ctx, hostID, stream, upstream)
		r.upstream.Store(false)
		raz.Do(func() { close(utracone) })
		if err != nil && ctx.Err() == nil {
			r.log.Warn("polaczenie z centrala zerwane, przechodze na buforowanie",
				"host_id", hostID, "err", err)
		}
	}()

	r.upstream.Store(true)

	// Odbior od agenta idzie osobna goroutine, zeby petla mogla zareagowac na
	// przerwanie sesji. Receive blokuje sie na kontekscie zadania i nie widzi
	// naszego przerwania: bez tego sesja przelaczona na buforowanie zostalaby
	// w tym trybie na zawsze, mimo ze centrala juz odpowiada.
	odebrane := make(chan *agentv1.AgentMessage)
	bledy := make(chan error, 1)
	go func() {
		for {
			message, err := stream.Receive()
			if err != nil {
				bledy <- err
				return
			}
			select {
			case odebrane <- message:
			case <-sessionCtx.Done():
				return
			}
		}
	}()

	// Sesja zaczyna sie od Hello; dopiero po nim wolno odeslac to, co czekalo
	// w buforze - centrala odrzuca strumien, ktory zaczyna sie inaczej.
	pierwsza := true
	for {
		var message *agentv1.AgentMessage
		select {
		case <-sessionCtx.Done():
			// Sesja wznowi sie sama: agent laczy sie ponownie po sekundach.
			return nil
		case err := <-bledy:
			return err
		case message = <-odebrane:
		}

		select {
		case <-utracone:
			// Centrala jest nieosiagalna: wiadomosc czeka w buforze zamiast
			// zginac. Utracony wynik wyglada dla panelu jak zadanie, ktore
			// wciaz trwa, i blokuje hosta na czas TTL.
			r.zbuforuj(hostID, message)
		default:
			if sendErr := upstream.Send(message); sendErr != nil {
				r.upstream.Store(false)
				raz.Do(func() { close(utracone) })
				r.zbuforuj(hostID, message)
				continue
			}
			if pierwsza {
				pierwsza = false
				r.odeslijBufor(hostID, upstream)
			}
		}
	}
}

// zbuforuj odklada wiadomosc i zglasza przepelnienie. Pelny bufor jest
// zdarzeniem operacyjnym: od tej chwili lokalizacja gubi wyniki.
func (r *Relay) zbuforuj(hostID string, message *agentv1.AgentMessage) {
	if err := r.buffer.Add(hostID, message); err != nil {
		r.log.Error("bufor relaya pelny, wynik odrzucony",
			"host_id", hostID, "err", err, "stan", r.buffer.Stats())
	}
}

// pumpDown przekazuje zadania z centrali do agenta.
//
// Zadanie, ktoremu uplynal TTL, nie jest przekazywane. Dokument mowi wprost:
// relay buforuje wyniki, ale nie wykonuje zadania po TTL - a przekazanie
// przeterminowanego zadania jest wlasnie zleceniem pracy, o ktora nikt juz
// nie prosi.
func (r *Relay) pumpDown(ctx context.Context, hostID string,
	to *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage],
	from *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	for {
		message, err := from.Receive()
		if err != nil {
			return err
		}
		if task := message.GetTask(); task != nil && wygaslo(task) {
			r.log.Warn("zadanie pominiete po uplywie TTL",
				"host_id", hostID, "task_id", task.GetTaskId(),
				"expires_at", task.GetExpiresAt().AsTime().Format(time.RFC3339))
			continue
		}
		if err := to.Send(message); err != nil {
			return err
		}
	}
}

func wygaslo(task *agentv1.TaskEnvelope) bool {
	expires := task.GetExpiresAt()
	if expires == nil {
		return false
	}
	return time.Now().After(expires.AsTime())
}

func (r *Relay) trackSession(hostID string, zakoncz context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if zakoncz != nil {
		r.sesje[hostID] = zakoncz
		return
	}
	delete(r.sesje, hostID)
}

// resetSessions konczy sesje agentow po powrocie lacza. Agent laczy sie
// ponownie w ciagu sekund i od razu pracuje na zywo.
func (r *Relay) resetSessions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, zakoncz := range r.sesje {
		zakoncz()
	}
	return len(r.sesje)
}

// Stats opisuje stan relaya na potrzeby metryk i diagnostyki.
func (r *Relay) Stats() (sesje int, bufor Stats, upstreamOK bool) {
	r.mu.RLock()
	sesje = len(r.sesje)
	r.mu.RUnlock()
	return sesje, r.buffer.Stats(), r.upstream.Load()
}

// WatchUpstream bada lacznosc z centrala, gdy relay pracuje w trybie
// buforowania.
//
// Badanie idzie osobnym wywolaniem bez skutkow ubocznych. Wczesniejsza wersja
// sprawdzala lacze, wysylajac zbuforowane wiadomosci osobnym strumieniem - i
// gubila je, bo sesja agenta zaczyna sie od Hello, a strumien bez Hello jest
// przez centrale odrzucany. Bufor ma chronic wyniki, a nie je tracic.
func (r *Relay) WatchUpstream(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if r.upstream.Load() {
				continue
			}
			probeCtx, anuluj := context.WithTimeout(ctx, 10*time.Second)
			_, err := r.client.Ping(probeCtx, connect.NewRequest(&agentv1.PingRequest{}))
			anuluj()
			if err != nil {
				continue
			}
			r.upstream.Store(true)
			// Sesje pracujace w trybie buforowania konczymy: agent polaczy sie
			// ponownie w ciagu sekund i wtedy odeslemy jego bufor w tej samej
			// sesji, ktora zaczyna sie od Hello.
			if zakonczone := r.resetSessions(); zakonczone > 0 {
				r.log.Info("lacznosc z centrala wrocila, sesje zostana wznowione",
					"sesji", zakonczone, "bufor", r.buffer.Stats().Messages)
			}
		}
	}
}

// certKey przenosi certyfikat agenta z warstwy TLS do obslugi strumienia.
type certKey struct{}

// WithClientCertificate przenosi certyfikat klienta do kontekstu zadania.
// Kontrakt nie niesie tozsamosci: pochodzi ona wylacznie z uscisku TLS.
func WithClientCertificate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			ctx = context.WithValue(ctx, certKey{}, r.TLS.PeerCertificates[0])
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func clientCertificate(ctx context.Context) (*x509.Certificate, bool) {
	cert, ok := ctx.Value(certKey{}).(*x509.Certificate)
	return cert, ok
}

// odeslijBufor odsyla zbuforowane wiadomosci hosta w jego zywej sesji.
// Wiadomosc znika z bufora dopiero po wyslaniu, wiec zerwanie w polowie
// oznacza ponowna probe, a nie utrate wyniku.
func (r *Relay) odeslijBufor(hostID string,
	upstream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage]) {
	wyslane := 0
	for {
		message, ok := r.buffer.TakeFor(hostID)
		if !ok {
			break
		}
		if err := upstream.Send(message); err != nil {
			r.log.Warn("nie odeslano bufora", "host_id", hostID, "err", err)
			return
		}
		r.buffer.CommitFor(hostID)
		wyslane++
	}
	if wyslane > 0 {
		r.log.Info("odeslano zbuforowane wiadomosci", "host_id", hostID, "wiadomosci", wyslane)
	}
}
