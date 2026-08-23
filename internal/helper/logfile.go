package helper

import (
	"context"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/logs"
)

// readLogFile czyta plik logu z allowlisty administratora hosta.
//
// Rozstrzyga tutaj, a nie w panelu: panel moze byc zle skonfigurowany albo
// przejety, a zakres odczytu jest wlasnoscia hosta. Helper dziala jako root
// i bez tego ograniczenia byl by narzedziem do czytania dowolnego pliku.
func (s *Server) readLogFile(_ context.Context, _ *helperv1.HelperRequest,
	action *helperv1.LogFileRequest) *helperv1.HelperResponse {
	allowlist := logs.WczytajAllowliste(logs.SciezkaAllowlisty)
	fragment, err := logs.Czytaj(allowlist, action.GetPath(), action.GetLines())
	if err != nil {
		// Powod odmowy niesie zakres: bez tego operator nie wie, czy pliku
		// nie ma, czy jest poza dozwolonym zakresem.
		return reject(ErrorUnsupported, err.Error()+" (zakres: "+allowlist.Zrodlo+")")
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		LogFileResult: &helperv1.LogFileResult{
			Path:      fragment.Path,
			Lines:     fragment.Lines,
			Truncated: fragment.Truncated,
			SizeBytes: fragment.SizeBytes,
			Allowlist: fragment.Allowlist,
		},
	}
}
