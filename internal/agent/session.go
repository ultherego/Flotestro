package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/endpoints"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
)

// SessionOptions konfiguruje polaczenie agenta z control plane.
type SessionOptions struct {
	// GatewayURLs sa bramami w kolejnosci priorytetu. Agent utrzymuje jedna
	// aktywna sesje, ale zna cala liste: przelaczenie na brame zapasowa nie
	// moze byc reczna czynnoscia operatora w chwili awarii centrali.
	GatewayURLs       []string
	Identity          *Identity
	InventoryInterval time.Duration
	Executor          *TaskExecutor
	// CollectFacts pozwala podstawic fakty syntetyczne. Symulator floty nie
	// czyta prawdziwego hosta, bo tysiac agentow na jednej maszynie
	// raportowaloby ten sam stan.
	CollectFacts func(context.Context) (Facts, error)
	// MaxConcurrentTasks ogranicza liczbe zadan wykonywanych rownolegle.
	// Host nie moze zostac zalany praca przez control plane.
	MaxConcurrentTasks int
	Log                *slog.Logger
	// Renewed sygnalizuje odnowienie certyfikatu. Sesja konczy sie wtedy
	// natychmiast, zeby nastepna poszla juz nowa tozsamoscia; czekanie do
	// naturalnego zerwania oznaczaloby prace na certyfikacie, ktory wlasnie
	// zostal zastapiony.
	Renewed <-chan struct{}
	// Stan zapisuje na dysk to, co sie z agentem dzieje. Bez tego narzedzie
	// diagnostyczne na hoscie widzi tylko pliki tozsamosci i nie umie
	// odpowiedziec, czy agent naprawde rozmawia z panelem.
	Stan *PisarzStanu

	// gatewayURL jest brama wybrana na te jedna sesje. Nie pochodzi
	// z konfiguracji, tylko z menedzera bram, wiec nie jest polem publicznym.
	gatewayURL string
}

const (
	minBackoff = 2 * time.Second
	maxBackoff = 5 * time.Minute
)

// Run utrzymuje polaczenie z gatewayem i wznawia je z backoffem oraz jitterem.
// Awaria control plane nie moze wywolac lawiny reconnectow z calej floty.
func Run(ctx context.Context, opts SessionOptions) error {
	menedzer := endpoints.Nowy(opts.GatewayURLs, minBackoff, maxBackoff)
	if len(menedzer.Bramy()) == 0 {
		return errors.New("agent nie ma zadnej bramy do polaczenia")
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		brama, err := menedzer.Wybierz(time.Now())
		if err != nil {
			// Odwolana tozsamosc nie jest awaria lacza. Agent przestaje sie
			// dobijac i zostawia powod tam, gdzie zajrzy operator hosta:
			// dalsze proby niczego nie naprawia, a enrollment jest decyzja
			// czlowieka, nie skutkiem ubocznym reconnectu.
			opts.Log.Error("polaczenie zatrzymane", "err", err)
			opts.Stan.Rozlaczony(err.Error(), time.Now())
			return err
		}
		if brama == nil {
			// Kazda brama ma jeszcze okno ponowienia. Czekamy do najblizszej,
			// zamiast krecic sie w petli.
			czekanie := menedzer.DoNastepnej(time.Now())
			opts.Log.Info("wszystkie bramy w oknie ponowienia",
				"za", czekanie.Round(time.Second).String())
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(czekanie):
			}
			continue
		}

		// Klient powstaje przy kazdym polaczeniu, bo tozsamosc moze sie
		// w miedzyczasie zmienic: odnowiony certyfikat musi wejsc do uzycia
		// bez restartu agenta.
		client := agentv1connect.NewAgentServiceClient(
			newHTTP2Client(opts.Identity),
			brama.URL,
			// Protokol Connect nie obsluguje pelnego dupleksu, wiec stream
			// dwukierunkowy jedzie po gRPC nad HTTP/2.
			connect.WithGRPC(),
		)
		start := time.Now()
		sesja := opts
		sesja.gatewayURL = brama.URL
		err = runSession(ctx, client, sesja)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			opts.Log.Warn("sesja zakonczona", "brama", brama.URL, "err", err)
			opts.Stan.Rozlaczony(err.Error(), time.Now())
		} else {
			opts.Stan.Rozlaczony("", time.Now())
		}

		switch {
		case errors.Is(err, errIdentityRenewed):
			// Przerwanie po odnowieniu certyfikatu nie jest bledem bramy:
			// nastepne polaczenie idzie nowa tozsamoscia i to samo miejsce.
			menedzer.Sukces(brama.URL, time.Now())
			continue
		case time.Since(start) > time.Minute:
			// Sesja, ktora pracowala dluzej niz minute, nie jest objawem
			// petli bledu - nawet jesli skonczyla sie zerwaniem.
			menedzer.Sukces(brama.URL, time.Now())
			if err == nil {
				continue
			}
		}

		klasa := endpoints.Rozpoznaj(err)
		menedzer.Blad(brama.URL, klasa, time.Now())
		if klasa == endpoints.KlasaKonfiguracji {
			// Zla konfiguracja nie naprawi sie ponowieniem, wiec mowimy
			// o niej wprost i tam, gdzie widac ja bez panelu.
			opts.Log.Error("brama odrzucila polaczenie z powodu konfiguracji",
				"brama", brama.URL, "err", err,
				"podpowiedz", "sprawdz bootstrap_ca_file i nazwe w gateway_urls")
		}
	}
}

// errIdentityRenewed konczy sesje po odnowieniu certyfikatu. Nastepne
// polaczenie idzie juz nowa tozsamoscia.
var errIdentityRenewed = errors.New("tozsamosc agenta odnowiona")

func runSession(ctx context.Context, client agentv1connect.AgentServiceClient,
	opts SessionOptions) (wynik error) {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Odnowienie certyfikatu konczy sesje: nastepna ma isc nowa tozsamoscia.
	// Zerwanie streamu wyglada wtedy jak zwykly blad, wiec powod jest
	// podmieniany przy wyjsciu - Run nie ma czekac z ponownym polaczeniem.
	odnowiona := make(chan struct{})
	if opts.Renewed != nil {
		go func() {
			select {
			case <-opts.Renewed:
				close(odnowiona)
				cancel()
			case <-sessionCtx.Done():
			}
		}()
	}
	defer func() {
		select {
		case <-odnowiona:
			wynik = errIdentityRenewed
		default:
		}
	}()

	stream := client.Connect(sessionCtx)
	defer func() { _ = stream.CloseRequest() }()

	// Adres, ktorym host dosiega panelu, jest ustalany raz na sesje i podany
	// modulowi sieci: to on rozstrzyga, ktory interfejs jest kanalem
	// zarzadzania, a wiec ktorej zmiany nie wolno zrobic bez ostrzezenia.
	adresLokalny := adresDoPanelu(opts.gatewayURL)

	collect := opts.CollectFacts
	if collect == nil {
		collect = func(ctx context.Context) (Facts, error) {
			return CollectFrom(ctx, adresLokalny)
		}
	}

	facts, err := collect(sessionCtx)
	if err != nil {
		return err
	}
	revision, _, err := facts.Revision()
	if err != nil {
		return err
	}

	if err := stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
			AgentVersion:      Version,
			BootId:            facts.BootID,
			Capabilities:      capabilitiesToProto(facts.Capabilities),
			InventoryRevision: revision,
			LocalAddress:      adresLokalny,
		}},
	}); err != nil {
		return err
	}

	first, err := stream.Receive()
	if err != nil {
		return err
	}
	sessionConfig := first.GetSessionConfig()
	if sessionConfig == nil {
		return errors.New("serwer nie odeslal konfiguracji sesji")
	}
	heartbeatInterval := time.Duration(sessionConfig.GetHeartbeatSeconds()) * time.Second
	if heartbeatInterval <= 0 {
		heartbeatInterval = 60 * time.Second
	}
	jitterWindow := time.Duration(sessionConfig.GetHeartbeatJitterSeconds()) * time.Second

	opts.Log.Info("sesja nawiazana",
		"host_id", opts.Identity.HostID, "heartbeat", heartbeatInterval.String())
	opts.Stan.Polaczony(opts.gatewayURL, time.Now())

	// Send nie jest bezpieczny dla rownoleglych wywolan.
	var sendMu sync.Mutex
	send := func(msg *agentv1.AgentMessage) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(msg)
	}

	sendInventory := func(f Facts) error {
		rev, raw, err := f.Revision()
		if err != nil {
			return err
		}
		if err := send(&agentv1.AgentMessage{
			Payload: &agentv1.AgentMessage_Inventory{Inventory: inventoryToProto(f, rev, raw)},
		}); err != nil {
			return err
		}
		opts.Stan.Inwentarz(rev, time.Now())
		return nil
	}

	if err := sendInventory(facts); err != nil {
		return err
	}

	// Fakty sa czytane przez wykonawce zadan przy sprawdzaniu preconditions,
	// a aktualizowane przez cykl inventory, wiec wymagaja synchronizacji.
	var factsMu sync.RWMutex
	cachedFacts := facts
	currentFacts := func() Facts {
		factsMu.RLock()
		defer factsMu.RUnlock()
		return cachedFacts
	}
	updateFacts := func(fresh Facts) {
		factsMu.Lock()
		cachedFacts = fresh
		factsMu.Unlock()
	}
	if opts.Executor != nil {
		opts.Executor.facts = currentFacts
		// Postep idzie tym samym strumieniem co wyniki. Bledu wysylki nie
		// eskalujemy: utrata podgladu nie moze przerwac trwajacej operacji.
		// Podglad dziennika idzie tym samym strumieniem co wyniki.
		opts.Executor.logLines = func(linie *agentv1.TaskLogLines) {
			if err := send(&agentv1.AgentMessage{
				Payload: &agentv1.AgentMessage_TaskLogLines{TaskLogLines: linie},
			}); err != nil {
				opts.Log.Debug("nie wyslano podgladu dziennika",
					"task_id", linie.GetTaskId(), "err", err)
			}
		}
		// Sekret pobiera sie osobnym wywolaniem, w chwili wykonania operacji.
		// Wartosc zyje wtedy w pamieci hosta i nigdzie jej nie zapisujemy -
		// ani w dzienniku agenta, ani w wyniku zadania.
		opts.Executor.sekrety = func(ctx context.Context, taskID, nazwa string, wersja int) ([]byte, error) {
			odpowiedz, err := client.FetchSecret(ctx, connect.NewRequest(&agentv1.FetchSecretRequest{
				TaskId: taskID, SecretName: nazwa, SecretVersion: uint32(wersja),
			}))
			if err != nil {
				return nil, err
			}
			wartosc := odpowiedz.Msg.GetValue()
			// Panel podaje odcisk tego, co wydal: sprawdzamy, ze dostalismy
			// dokladnie to, a nie tresc uszkodzona po drodze.
			if odcisk := odpowiedz.Msg.GetSha256(); odcisk != "" && odcisk != odciskWartosci(wartosc) {
				return nil, errors.New("odcisk pobranego sekretu nie zgadza sie z podanym przez panel")
			}
			return wartosc, nil
		}
		opts.Executor.progress = func(p *agentv1.TaskProgress) {
			if err := send(&agentv1.AgentMessage{
				Payload: &agentv1.AgentMessage_TaskProgress{TaskProgress: p},
			}); err != nil {
				opts.Log.Debug("nie wyslano postepu zadania",
					"task_id", p.GetTaskId(), "err", err)
			}
		}
	}

	// Miejsca sa liczone osobno dla kazdej klasy zasobu: dlugi odczyt
	// pakietow nie moze zajac calej puli i zatrzymac operacji, ktore trwaja
	// milisekundy.
	miejsca := nowyBudzet(opts.MaxConcurrentTasks)
	// Blokady zasobow sa druga warstwa obok budzetu: budzet mowi, ile zadan
	// host uniesie, a zamki - ktore z nich nie moga isc obok siebie.
	zasoby := noweZamki()

	receiveErr := make(chan error, 1)
	zglosBlad := func(err error) {
		select {
		case receiveErr <- err:
		default:
		}
	}

	// Zbieranie inventory idzie obok petli odbioru: ciezki odczyt nie moze
	// zatrzymac przyjmowania zadan.
	inventory := nowyKolektor()
	go func() {
		zbierz := func(ctx context.Context, moduly []string) (Facts, error) {
			if len(moduly) == 0 {
				return collect(ctx)
			}
			// Odswiezenie czesciowe wchodzi w poprzedni obraz: modul spoza
			// zakresu ma zostac taki, jaki byl, a nie zniknac.
			return ZbierzModuly(ctx, adresLokalny, currentFacts(), moduly)
		}
		przyjmij := func(fresh Facts) (Odswiezenie, error) {
			poprzednia := ""
			if rev, _, err := currentFacts().Revision(); err == nil {
				poprzednia = rev
			}
			updateFacts(fresh)
			if err := sendInventory(fresh); err != nil {
				return Odswiezenie{}, err
			}
			nowa, _, err := fresh.Revision()
			if err != nil {
				return Odswiezenie{}, err
			}
			return Odswiezenie{Rewizja: nowa, Zmieniona: nowa != poprzednia}, nil
		}
		if err := inventory.pracuj(sessionCtx, zbierz, przyjmij, opts.Log); err != nil {
			zglosBlad(err)
		}
	}()

	// Odswiezenie na zadanie jest operacja typowana, wiec wykonawca musi
	// umiec o nie poprosic - i doczekac sie rewizji, ktora z niego powstala.
	if opts.Executor != nil {
		opts.Executor.odswiezInwentarz = func(ctx context.Context, moduly []string) Odswiezenie {
			return inventory.odswiez(ctx, moduly)
		}
	}

	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				receiveErr <- err
				return
			}
			switch payload := msg.GetPayload().(type) {
			case *agentv1.ServerMessage_InventoryRequest:
				inventory.zazadaj()

			case *agentv1.ServerMessage_Task:
				// Zadanie wykonuje sie obok petli odbioru: restart jednostki
				// trwa, a heartbeat i kolejne zadania nie moga na niego czekac.
				task := payload.Task
				go func() {
					// Najpierw zasoby, potem miejsce w budzecie: zadanie
					// czekajace na zajety zasob nie ma powodu trzymac miejsca,
					// ktore przydaloby sie operacji bez kolizji.
					roszczenia := roszczeniaZadania(task)
					oddajZasoby, powod := zajmijZasoby(sessionCtx, zasoby, task, roszczenia)
					if powod != "" {
						// Odmowa z nazwa blokujacego zadania jest odpowiedzia;
						// cisza do konca limitu czasu operacji nia nie jest.
						odmowa := rejected(agentv1.TaskResult_STATUS_REJECTED,
							RejectResourceBusy, powod)
						odmowa.TaskId = task.GetTaskId()
						opts.Log.Info("zadanie odrzucone przez blokade zasobu",
							"task_id", task.GetTaskId(), "powod", powod)
						if err := send(&agentv1.AgentMessage{
							Payload: &agentv1.AgentMessage_TaskResult{TaskResult: odmowa},
						}); err != nil {
							opts.Log.Error("nie odeslano odmowy zadania",
								"task_id", task.GetTaskId(), "err", err)
						}
						return
					}
					if oddajZasoby == nil {
						return
					}
					defer oddajZasoby()

					zwolnij := miejsca.zajmij(sessionCtx, klasaZadania(task))
					if zwolnij == nil {
						return
					}
					defer zwolnij()
					if len(roszczenia) > 0 {
						opts.Log.Info("zasoby zajete", "task_id", task.GetTaskId(),
							"roszczenia", strings.Join(roszczenia, ","))
					}
					result := executeTask(sessionCtx, opts.Executor, task, opts.Log)
					// Wymiana agenta nie ma wyniku do odeslania: proces,
					// ktory ja wykonal, wlasnie jest zastepowany, a o tym,
					// czy sie udala, rozstrzyga powrot hosta z nowa wersja.
					// Kazda inna odpowiedz bylaby zgadywaniem.
					if result.GetErrorCode() == StatusPoWymianie {
						opts.Log.Info("wymiana agenta w toku",
							"task_id", task.GetTaskId(), "opis", result.GetMessage())
						return
					}
					opts.Log.Info("zadanie zakonczone",
						"task_id", task.GetTaskId(), "status", result.GetStatus(),
						"error_code", result.GetErrorCode(), "replayed", result.GetReplayed())
					if err := send(&agentv1.AgentMessage{
						Payload: &agentv1.AgentMessage_TaskResult{TaskResult: result},
					}); err != nil {
						opts.Log.Error("nie odeslano wyniku zadania",
							"task_id", task.GetTaskId(), "err", err)
					}
				}()

			case *agentv1.ServerMessage_CancelTask:
				// Nie kazda operacja systemowa da sie bezpiecznie przerwac -
				// transakcji pakietowej nie wolno urwac w polowie - wiec
				// anulowanie dziala tam, gdzie zostalo zgloszone jako
				// bezpieczne, a poza tym zostaje odnotowane.
				przerwane := false
				if opts.Executor != nil && opts.Executor.cancels != nil {
					przerwane = opts.Executor.cancels.Anuluj(payload.CancelTask.GetTaskId())
				}
				opts.Log.Info("zadano anulowania zadania",
					"task_id", payload.CancelTask.GetTaskId(),
					"reason", payload.CancelTask.GetReason(),
					"przerwane", przerwane)
			}
		}
	}()

	// Stabilny offset per host rozklada heartbeaty calej floty w czasie.
	heartbeatTimer := time.NewTimer(stableOffset(facts.MachineID, heartbeatInterval))
	defer heartbeatTimer.Stop()
	inventoryTicker := time.NewTicker(opts.InventoryInterval)
	defer inventoryTicker.Stop()

	for {
		select {
		case <-sessionCtx.Done():
			return nil

		case err := <-receiveErr:
			return err

		case <-heartbeatTimer.C:
			health := ReadHealth(currentFacts())
			if err := send(&agentv1.AgentMessage{
				Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
					SentAt: timestampNow(),
					Health: healthToProto(health),
				}},
			}); err != nil {
				return err
			}
			heartbeatTimer.Reset(nextHeartbeat(heartbeatInterval, jitterWindow))

		case <-inventoryTicker.C:
			inventory.zazadaj()
		}
	}
}

// adresDoPanelu zwraca adres lokalny, ktorym host dosiegnie control plane.
// Gniazdo UDP nie wysyla zadnego pakietu - samo przypisanie adresu wybiera
// tablica routingu. To odpowiedz na pytanie "ktorym adresem ten host rozmawia
// z panelem", a nie pierwszy adres z listy interfejsow, ktory nie znaczy nic.
//
// Nieustalony adres zostaje pusty. Panel woli nie znac adresu, niz pokazac
// operatorowi adres, pod ktorym hosta nie ma.
func adresDoPanelu(gatewayURL string) string {
	parsed, err := url.Parse(gatewayURL)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	conn, err := net.Dial("udp", net.JoinHostPort(parsed.Hostname(), port))
	if err != nil {
		return ""
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func newHTTP2Client(identity *Identity) *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{identity.Certificate},
				RootCAs:      identity.CAPool,
				MinVersion:   tls.VersionTLS13,
			},
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		},
	}
}

// stableOffset rozklada pierwszy heartbeat deterministycznie wedlug machine-id,
// wiec ten sam host zawsze trafia w to samo miejsce okna.
func stableOffset(machineID string, window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(machineID))
	slot := binary.BigEndian.Uint64(sum[:8]) % uint64(window)
	return time.Duration(slot)
}

func nextHeartbeat(interval, jitterWindow time.Duration) time.Duration {
	if jitterWindow <= 0 {
		return interval
	}
	return interval + time.Duration(rand.Int64N(int64(jitterWindow)))
}

func withJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return minBackoff
	}
	return base/2 + time.Duration(rand.Int64N(int64(base)))
}

// executeTask uruchamia zadanie za bariera odpornosci.
//
// Panika w obsludze jednego zadania nie moze zabic agenta: host stracilby
// wtedy zarzadzanie przez blad w jednej operacji, a control plane zobaczylby
// zerwana sesje zamiast informacji, co poszlo nie tak. Zadanie konczy sie
// wynikiem negatywnym, a agent dziala dalej.
func executeTask(ctx context.Context, executor *TaskExecutor, task *agentv1.TaskEnvelope,
	log *slog.Logger) (result *agentv1.TaskResult) {
	if executor == nil {
		// Agent bez wykonawcy zadan nie jest zepsuty - taka jest na przyklad
		// rola symulatora. Odrzucenie jest odpowiedzia, a nie awaria.
		return &agentv1.TaskResult{
			TaskId:    task.GetTaskId(),
			Status:    agentv1.TaskResult_STATUS_REJECTED,
			ExitCode:  -1,
			ErrorCode: RejectUnsupported,
			Message:   "agent nie wykonuje zadan",
		}
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			log.Error("panika przy wykonaniu zadania",
				"task_id", task.GetTaskId(), "powod", fmt.Sprint(recovered),
				"stos", string(debug.Stack()))
			result = &agentv1.TaskResult{
				TaskId:    task.GetTaskId(),
				Status:    agentv1.TaskResult_STATUS_FAILED,
				ExitCode:  -1,
				ErrorCode: RejectInternalError,
				Message:   "wewnetrzny blad agenta przy wykonaniu zadania",
			}
		}
	}()

	result = executor.Execute(ctx, task)
	if result == nil {
		// Milczenie agenta jest dla control plane nieodrozninalne od zerwanego
		// polaczenia, wiec brak wyniku jest tu bledem, a nie pustka.
		result = &agentv1.TaskResult{
			TaskId:    task.GetTaskId(),
			Status:    agentv1.TaskResult_STATUS_FAILED,
			ExitCode:  -1,
			ErrorCode: RejectInternalError,
			Message:   "wykonawca nie zwrocil wyniku",
		}
	}
	return result
}

// odciskWartosci liczy sume kontrolna pobranej wartosci sekretu.
//
// Sluzy wylacznie do sprawdzenia, ze host dostal to, co panel wydal. Odcisku
// nigdzie nie zapisujemy: dla krotkiej wartosci sam odcisk bywa wskazowka.
func odciskWartosci(wartosc []byte) string {
	suma := sha256.Sum256(wartosc)
	return hex.EncodeToString(suma[:])
}
