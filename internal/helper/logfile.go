package helper

import (
	"context"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/logs"
)

// readLogFile reads a log file from the allowlist of the host administrator.
//
// It is decided here, not in the panel: the panel may be misconfigured or
// taken over, and the read scope is the property of the host. The helper runs
// as root and without this limit it would be a tool for reading any file.
func (s *Server) readLogFile(_ context.Context, _ *helperv1.HelperRequest,
	action *helperv1.LogFileRequest) *helperv1.HelperResponse {
	allowlist := logs.WczytajAllowliste(logs.SciezkaAllowlisty)
	fragment, err := logs.Czytaj(allowlist, action.GetPath(), action.GetLines())
	if err != nil {
		// The reason for the refusal carries the scope: without it the operator
		// does not know whether the file is missing or outside the allowed
		// scope.
		return reject(ErrorUnsupported, err.Error()+" (scope: "+allowlist.Zrodlo+")")
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
