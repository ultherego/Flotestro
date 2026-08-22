package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/authz"
)

// handleMetrics wystawia stan panelu dla monitoringu.
//
// Endpoint wymaga uwierzytelnienia: liczba hostow, stany zadan i czas do
// wygasniecia CA opisuja flote i nie moga byc dostepne bez uprawnienia,
// nawet jesli zwyczaj wielu instalacji jest inny.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metrics == nil {
		problem(w, http.StatusNotImplemented, "metrics_disabled",
			"metrics are not enabled in this installation")
		return
	}
	if _, ok := s.authorize(w, r, authz.PermMetricsRead, authz.GlobalScope, "metrics", ""); !ok {
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.metrics.Gather(r.Context()))
}
