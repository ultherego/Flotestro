package adminapi

import (
	"context"
	"encoding/json"
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
	s.strumien(w, r, events.ForJob(jobID), nil)
}

// handleCampaignEvents strumieniuje postep kampanii. Kampania nie ma wlasnego
// stanu w czasie rzeczywistym - sklada sie ze stanow swoich operacji, wiec
// zdarzenia sa te same, tylko filtrowane inaczej.
func (s *Server) handleCampaignEvents(w http.ResponseWriter, r *http.Request) {
	campaignID := r.PathValue("id")
	if _, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign"); !ok {
		return
	}
	s.strumien(w, r, events.ForCampaign(campaignID), nil)
}

// handleFleetEvents strumieniuje zdarzenia wszystkich operacji, ktore
// operator ma prawo widziec.
//
// Osobny strumien na kazda operacje bylby nie do utrzymania: panel idzie po
// HTTP/1.1, gdzie przegladarka trzyma szesc polaczen na domene, a strumien
// zajmuje jedno na stale. Jeden strumien na karte zostawia reszte na zwykle
// zapytania.
func (s *Server) handleFleetEvents(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermJobRead, "job")
	if !ok {
		return
	}
	s.strumien(w, r, func(events.Event) bool { return true }, s.filtrZakresu(principal))
}

// filtrZakresu przepuszcza wylacznie zdarzenia operacji z hostow widocznych
// dla tej tozsamosci. Sprawdzenie idzie w watku polaczenia, a nie w magistrali:
// odpytanie bazy przy rozglaszaniu wstrzymywaloby wszystkich odbiorcow.
func (s *Server) filtrZakresu(principal authz.Principal) func(context.Context, events.Event) bool {
	widoczne := map[string]bool{}
	return func(ctx context.Context, event events.Event) bool {
		if event.JobID == "" {
			return false
		}
		if wolno, znane := widoczne[event.JobID]; znane {
			return wolno
		}
		wolno := false
		if job, err := s.jobs.Get(ctx, event.JobID); err == nil && job != nil {
			if host, err := s.hosts.Get(ctx, job.HostID); err == nil && host != nil {
				wolno = principal.Can(authz.PermJobRead,
					authz.Scope{Site: host.Site, Environment: host.Environment})
			}
		}
		widoczne[event.JobID] = wolno
		return wolno
	}
}

// strumien wysyla zdarzenia jako Server-Sent Events.
func (s *Server) strumien(w http.ResponseWriter, r *http.Request,
	filtr func(events.Event) bool, wolno func(context.Context, events.Event) bool) {
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
			if wolno != nil && !wolno(r.Context(), zdarzenie) {
				continue
			}
			dane, err := json.Marshal(zdarzenie)
			if err != nil {
				continue
			}
			// Postep i zmiana stanu to dwa rozne zdarzenia. Ekran odswieza
			// dane po zmianie stanu, a pasek rysuje z postepu - polaczenie
			// ich w jedno kazaloby odpytywac API kilka razy na sekunde.
			nazwa := "job"
			switch {
			case zdarzenie.Log != nil:
				nazwa = "log"
			case zdarzenie.Progress != nil:
				nazwa = "progress"
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", nazwa, dane)
			flusher.Flush()
		}
	}
}
