package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
)

// SessionOptions konfiguruje polaczenie agenta z control plane.
type SessionOptions struct {
	GatewayURL        string
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
}

const (
	minBackoff = 2 * time.Second
	maxBackoff = 5 * time.Minute
)

// Run utrzymuje polaczenie z gatewayem i wznawia je z backoffem oraz jitterem.
// Awaria control plane nie moze wywolac lawiny reconnectow z calej floty.
func Run(ctx context.Context, opts SessionOptions) error {
	backoff := minBackoff
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Klient powstaje przy kazdym polaczeniu, bo tozsamosc moze sie
		// w miedzyczasie zmienic: odnowiony certyfikat musi wejsc do uzycia
		// bez restartu agenta.
		client := agentv1connect.NewAgentServiceClient(
			newHTTP2Client(opts.Identity),
			opts.GatewayURL,
			// Protokol Connect nie obsluguje pelnego dupleksu, wiec stream
			// dwukierunkowy jedzie po gRPC nad HTTP/2.
			connect.WithGRPC(),
		)
		start := time.Now()
		err := runSession(ctx, client, opts)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			opts.Log.Warn("sesja zakonczona", "err", err)
		}
		// Sesja, ktora dzialala dluzej niz minute, nie jest objawem petli bledu.
		if time.Since(start) > time.Minute {
			backoff = minBackoff
		}
		wait := withJitter(backoff)
		// Sesja przerwana przez odnowienie certyfikatu nie jest bledem, wiec
		// nie ma powodu odczekiwac przed ponownym polaczeniem.
		if errors.Is(err, errIdentityRenewed) {
			wait = 0
			backoff = minBackoff
		}
		opts.Log.Info("ponowne laczenie", "za", wait.Round(time.Second).String())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if backoff < maxBackoff {
			backoff *= 2
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

	collect := opts.CollectFacts
	if collect == nil {
		collect = Collect
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
		return send(&agentv1.AgentMessage{
			Payload: &agentv1.AgentMessage_Inventory{Inventory: inventoryToProto(f, rev, raw)},
		})
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
	}

	concurrency := opts.MaxConcurrentTasks
	if concurrency <= 0 {
		concurrency = 2
	}
	taskSlots := make(chan struct{}, concurrency)

	receiveErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				receiveErr <- err
				return
			}
			switch payload := msg.GetPayload().(type) {
			case *agentv1.ServerMessage_InventoryRequest:
				fresh, err := collect(sessionCtx)
				if err != nil {
					opts.Log.Error("nie zebrano inventory", "err", err)
					continue
				}
				updateFacts(fresh)
				if err := sendInventory(fresh); err != nil {
					receiveErr <- err
					return
				}

			case *agentv1.ServerMessage_Task:
				// Zadanie wykonuje sie obok petli odbioru: restart jednostki
				// trwa, a heartbeat i kolejne zadania nie moga na niego czekac.
				task := payload.Task
				go func() {
					select {
					case taskSlots <- struct{}{}:
						defer func() { <-taskSlots }()
					case <-sessionCtx.Done():
						return
					}
					result := executeTask(sessionCtx, opts.Executor, task, opts.Log)
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
				// Nie kazda operacja systemowa da sie bezpiecznie przerwac,
				// wiec anulowanie jest odnotowane, a nie wymuszane.
				opts.Log.Info("zadano anulowania zadania",
					"task_id", payload.CancelTask.GetTaskId(),
					"reason", payload.CancelTask.GetReason())
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
			fresh, err := collect(sessionCtx)
			if err != nil {
				opts.Log.Error("nie zebrano inventory", "err", err)
				continue
			}
			updateFacts(fresh)
			if err := sendInventory(fresh); err != nil {
				return err
			}
		}
	}
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
