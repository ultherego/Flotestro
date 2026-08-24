package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/secrets"
)

// Magazyn sekretow ma jedna wlasciwosc, ktorej nie wolno zgubic: wartosc
// wchodzi i nie wychodzi. API pozwala sekret zalozyc, obrocic, wycofac
// i zniszczyc wersje - ale nie ma sposobu, zeby przez nie odczytac tresc.
// Jedyna droga wyjscia wartosci prowadzi przez dzierzawe wystawiona hostowi
// na czas jednego zadania.

type sekretRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Value jest jedynym miejscem, w ktorym wartosc pojawia sie w API - i to
	// wylacznie w kierunku do panelu.
	Value string `json:"value"`
}

// handleListSecrets zwraca metadane sekretow.
func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermSecretRead, "secrets"); !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}
	lista, err := s.secrets.Lista(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if lista == nil {
		lista = []secrets.Secret{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": lista, "count": len(lista)})
}

// handleGetSecret zwraca metadane jednego sekretu wraz z historia wersji.
func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermSecretRead, "secrets"); !ok {
		return
	}
	sekret, ok := s.sekret(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, sekret)
}

// handleCreateSecret zaklada sekret wraz z pierwsza wersja.
func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecretWrite, "secrets")
	if !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}

	var request sekretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	sekret, err := s.secrets.Utworz(r.Context(), request.Name, request.Description,
		[]byte(request.Value), principal.Subject)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_secret", err.Error())
		return
	}
	// Audyt notuje zalozenie i rozmiar - nigdy wartosc.
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.create", TargetType: "secret", TargetID: sekret.Name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"version": sekret.CurrentVersion, "size_bytes": len(request.Value)},
	})
	writeJSON(w, http.StatusCreated, sekret)
}

// handleRotateSecret dokłada nowa wersje i czyni ja biezaca.
func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecretWrite, "secrets")
	if !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}

	var request sekretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	sekret, err := s.secrets.Obroc(r.Context(), r.PathValue("name"), []byte(request.Value), principal.Subject)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		problem(w, http.StatusNotFound, "secret_not_found", "no such secret")
		return
	case errors.Is(err, secrets.ErrRetired):
		problem(w, http.StatusConflict, "secret_retired", "this secret has been retired")
		return
	case err != nil:
		problem(w, http.StatusBadRequest, "invalid_secret", err.Error())
		return
	}
	// Poprzednie wersje zostaja: host z dzierzawa na wersje wczesniejsza ma ja
	// dostac takze po obrocie.
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.rotate", TargetType: "secret", TargetID: sekret.Name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"version": sekret.CurrentVersion, "size_bytes": len(request.Value)},
	})
	writeJSON(w, http.StatusOK, sekret)
}

// handleRetireSecret zamyka sekret: metadane zostaja, wydawanie sie konczy.
func (s *Server) handleRetireSecret(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecretDestroy, "secrets")
	if !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}
	nazwa := r.PathValue("name")
	if err := s.secrets.Wycofaj(r.Context(), nazwa); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusNotFound, "secret_not_found", "no such secret")
			return
		}
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.retire", TargetType: "secret", TargetID: nazwa,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
	})
	sekret, err := s.secrets.Sekret(r.Context(), nazwa)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sekret)
}

// handleDestroySecretVersion kasuje tresc jednej wersji.
//
// Wiersz zostaje: historia ma pokazac, ze wersja istniala i kiedy przestala.
// Zniszczonej tresci nie da sie odzyskac takze z kopii bazy.
func (s *Server) handleDestroySecretVersion(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecretDestroy, "secrets")
	if !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}
	nazwa := r.PathValue("name")
	wersja, err := wersjaZeSciezki(r.PathValue("version"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_version", err.Error())
		return
	}
	if err := s.secrets.Zniszcz(r.Context(), nazwa, wersja); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusNotFound, "version_not_found", "no such secret version")
			return
		}
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.destroy", TargetType: "secret", TargetID: nazwa,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"version": wersja},
	})
	sekret, err := s.secrets.Sekret(r.Context(), nazwa)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sekret)
}

func (s *Server) sekret(w http.ResponseWriter, r *http.Request) (*secrets.Secret, bool) {
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return nil, false
	}
	sekret, err := s.secrets.Sekret(r.Context(), r.PathValue("name"))
	if errors.Is(err, secrets.ErrNotFound) {
		problem(w, http.StatusNotFound, "secret_not_found", "no such secret")
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return sekret, true
}

func wersjaZeSciezki(wartosc string) (int, error) {
	wersja := 0
	for _, znak := range wartosc {
		if znak < '0' || znak > '9' {
			return 0, errors.New("wersja musi byc liczba")
		}
		wersja = wersja*10 + int(znak-'0')
		if wersja > 1<<20 {
			return 0, errors.New("wersja poza zakresem")
		}
	}
	if wersja == 0 {
		return 0, errors.New("wersja musi byc liczba dodatnia")
	}
	return wersja, nil
}
