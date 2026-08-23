package helper

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/docker/compose"
)

// dockerCLI jest jedynym punktem wejscia do compose. Argumenty sa skladane
// w kodzie, nigdy przez powloke: nie istnieje operacja "wykonaj to polecenie".
const dockerCLI = "/usr/bin/docker"

// katalogCompose trzyma manifesty w trakcie operacji. Nalezy do roota
// i nie jest wspoldzielony z niczym innym.
func (s *Server) katalogCompose() string {
	katalog := os.Getenv("STATE_DIRECTORY")
	if katalog == "" {
		katalog = "/var/lib/flotestro-helper"
	}
	return filepath.Join(katalog, "compose")
}

// runnerCompose uruchamia compose z ustalonymi argumentami.
func runnerCompose(ctx context.Context) compose.Runner {
	return func(callCtx context.Context, args ...string) (string, string, error) {
		pelne := append([]string{"compose"}, args...)
		cmd := exec.CommandContext(callCtx, dockerCLI, pelne...)
		cmd.Env = []string{
			"LC_ALL=C", "LANG=C",
			"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=/var/lib/flotestro-helper",
		}
		stdoutPipe := &bufor{limit: 4 << 20}
		stderrPipe := &bufor{limit: 1 << 20}
		cmd.Stdout = stdoutPipe
		cmd.Stderr = stderrPipe
		err := cmd.Run()
		return string(stdoutPipe.Bytes()), string(stderrPipe.Bytes()), err
	}
}

// applyCompose obsluguje plan i wdrozenie projektu.
func (s *Server) applyCompose(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.ComposeRequest) *helperv1.HelperResponse {
	if info, err := os.Stat(dockerCLI); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return reject(ErrorUnsupported, "host nie ma klienta Dockera")
	}

	// Projekty Compose dziel z pozostalymi operacjami kontenerowymi ten sam
	// zasob: wdrozenie i restart tego samego projektu naraz daja
	// nieprzewidywalny wynik.
	if !s.containerMutex.TryLock() {
		return reject(ErrorLocked, "inna operacja na kontenerach jest w toku")
	}
	defer s.containerMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > time.Hour {
		timeout = 15 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	planner := compose.Planner{Runner: runnerCompose(actionCtx), Dir: s.katalogCompose()}

	switch action.GetOperation() {
	case helperv1.ComposeRequest_OPERATION_PLAN:
		plan, err := planner.Plan(actionCtx, action.GetProject(), action.GetManifest())
		if err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
		return odpowiedzCompose(plan)

	case helperv1.ComposeRequest_OPERATION_DEPLOY:
		executor := compose.Executor{Planner: planner}
		wynik, err := executor.Deploy(actionCtx, action.GetProject(),
			action.GetManifest(), action.GetPlanDigest())
		if err != nil {
			// Wynik czesciowy trafia do odpowiedzi takze przy bledzie:
			// bez tego nie wiadomo, co zdazylo wejsc w zycie.
			response := reject(ErrorExecFailed, err.Error())
			if encoded, blad := json.Marshal(wynik); blad == nil {
				response.ComposeResult = &helperv1.ComposeResult{Payload: encoded}
			}
			return response
		}
		return odpowiedzCompose(wynik)
	}
	return reject(ErrorUnknownAction, "nieznana operacja projektu Compose")
}

func odpowiedzCompose(tresc any) *helperv1.HelperResponse {
	encoded, err := json.Marshal(tresc)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:      true,
		ComposeResult: &helperv1.ComposeResult{Payload: encoded},
	}
}

// bufor zbiera wyjscie do limitu. Compose potrafi wypisac duzo, a helper
// dziala jako root i nie moze pozwolic sobie na nieograniczona alokacje.
type bufor struct {
	dane  []byte
	limit int
}

func (b *bufor) Write(p []byte) (int, error) {
	if len(b.dane) < b.limit {
		dozwolone := b.limit - len(b.dane)
		if dozwolone > len(p) {
			dozwolone = len(p)
		}
		b.dane = append(b.dane, p[:dozwolone]...)
	}
	return len(p), nil
}

func (b *bufor) Bytes() []byte { return b.dane }
