package adminapi

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/events"
)

// odstepUtrzymania trzyma strumien przy zyciu przez posrednikow, ktore
// zamykaja bezczynne polaczenia. Komentarz SSE nie jest zdarzeniem i nie
// budzi interfejsu.
const odstepUtrzymania = 25 * time.Second

// handleJobEvents strumieniuje postep jednej operacji.
//
// Strumien niesie wylacznie sygnal "stan sie zmienil". Trescia wyniku jest
// baza: gdyby stan jechal strumieniem, ekran po zerwaniu polaczenia
// pokazywalby cos innego niz zapisano, a operator nie mialby jak tego
// zauwazyc.
func (s *Server) handleJobEvents(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	job, err := s.jobs.Get(r.Context(), jobID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if job == nil {
		problem(w, http.StatusNotFound, "job_not_found", "no such job")
		return
	}
	host, scope, ok := s.hostScope(w, r, job.HostID)
	if !ok {
		return
	}
	_ = host
	if _, ok := s.authorize(w, r, authz.PermJobRead, scope, "job", jobID); !ok {
		return
	}
	s.strumien(w, r, events.ForJob(jobID))
}

// handleCampaignEvents strumieniuje postep kampanii. Kampania nie ma wlasnego
// stanu w czasie rzeczywistym - sklada sie ze stanow swoich operacji, wiec
// zdarzenia sa te same, tylko filtrowane inaczej.
func (s *Server) handleCampaignEvents(w http.ResponseWriter, r *http.Request) {
	campaignID := r.PathValue("id")
	if _, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign"); !ok {
		return
	}
	s.strumien(w, r, events.ForCampaign(campaignID))
}

// strumien wysyla zdarzenia jako Server-Sent Events.
func (s *Server) strumien(w http.ResponseWriter, r *http.Request, filtr func(events.Event) bool) {
	if s.events == nil {
		// Brak magistrali nie jest bledem klienta: panel dziala, tylko bez
		// strumienia. Odpowiedz mowi to wprost, zamiast wisiec w oczekiwaniu.
		problem(w, http.StatusServiceUnavailable, "events_unavailable",
			"the control plane is not streaming progress right now")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		problem(w, http.StatusInternalServerError, "streaming_unsupported",
			"this connection cannot stream events")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	// Posrednicy buforujacy odpowiedz zamienilyby strumien w jedno dlugie
	// pobranie, ktore dociera dopiero na koncu.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	zdarzenia, koniec := s.events.Subscribe(filtr)
	defer koniec()

	// Pierwsze zdarzenie idzie od razu: ekran, ktory wlasnie sie podlaczyl,
	// nie moze czekac na nastepna zmiane, zeby odswiezyc dane.
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()

	utrzymanie := time.NewTicker(odstepUtrzymania)
	defer utrzymanie.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-utrzymanie.C:
			fmt.Fprint(w, ": utrzymanie\n\n")
			flusher.Flush()
		case zdarzenie := <-zdarzenia:
			fmt.Fprintf(w, "event: job\ndata: {\"job_id\":%q,\"state\":%q}\n\n",
				zdarzenie.JobID, zdarzenie.State)
			flusher.Flush()
		}
	}
}
