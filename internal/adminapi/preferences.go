package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/authz"
)

// What an identity may read and write about itself without any permission
// beyond being signed in: its preferences, its sessions and its tokens.
//
// The preferences are how one person likes the panel - the zone the
// times are read in, the language, the theme, the page the panel opens
// on - and follow the person from browser to browser, so they live on
// the server under the identity rather than in one browser's storage.
// The sessions and the tokens are listed here for the same identity
// that owns them: the access screen shows them to whoever manages the
// identities, but an operator is entitled to see where they are signed
// in without holding that right.

// preferences is the row of principal_preferences as the API shows it.
// An empty field means the panel's default, never a value of its own.
type preferences struct {
	// TimeZone is an IANA zone name the times of the panel are read in;
	// empty for the browser's own zone.
	TimeZone string `json:"time_zone"`
	// PageSize is the rows per page of the lists; zero for the default.
	PageSize int `json:"page_size"`
	// LandingPage is the path the panel opens on after signing in; empty
	// for the dashboard.
	LandingPage string `json:"landing_page"`
	// Language and Theme are the codes the panel's switches use; empty
	// leaves the choice to the browser, as for an identity without a row.
	Language string `json:"language"`
	Theme    string `json:"theme"`
	// UpdatedAt is when the row was last written; absent for an identity
	// on the defaults, which has no row.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// The bounds of a preference. They are checked here rather than left to
// the screen: a preference is written by a script as well, and a page of
// ten thousand rows or a landing page on another site is not a preference.
const (
	maxPreferredPageSize = 500
	maxLandingPageLength = 200
	maxTimeZoneLength    = 64
)

// requireIdentity is the gate of the routes about the caller: signed in
// is enough, because the resource is the caller. A token without an
// identity row cannot reach here - every token belongs to a principal.
func requireIdentity(w http.ResponseWriter, r *http.Request) (authz.Principal, bool) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() || principal.ID == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated", "no valid token")
		return principal, false
	}
	return principal, true
}

// handleGetPreferences serves the caller's preferences. An identity
// without a row is on the defaults, and the answer says so with empty
// fields rather than with a 404: the screen has nothing to do differently.
func (s *Server) handleGetPreferences(w http.ResponseWriter, r *http.Request) {
	principal, ok := requireIdentity(w, r)
	if !ok {
		return
	}
	var stored preferences
	var updatedAt time.Time
	err := s.pool.QueryRow(r.Context(), `
		select time_zone, page_size, landing_page, language, theme, updated_at
		  from principal_preferences where principal_id = $1`, principal.ID).
		Scan(&stored.TimeZone, &stored.PageSize, &stored.LandingPage, &stored.Language, &stored.Theme, &updatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.fail(w, err)
		return
	}
	if err == nil {
		stored.UpdatedAt = &updatedAt
	}
	writeJSON(w, http.StatusOK, stored)
}

// handleSetPreferences writes the caller's preferences whole. The body is
// the whole row: a field left out goes back to the default, so a screen
// sends what it read plus the change, as it does for the tags of a host.
// The write is not audited: a preference changes nothing for anyone but
// the person who set it.
func (s *Server) handleSetPreferences(w http.ResponseWriter, r *http.Request) {
	principal, ok := requireIdentity(w, r)
	if !ok {
		return
	}
	var request preferences
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if code, detail := validatePreferences(&request); code != "" {
		problem(w, http.StatusBadRequest, code, detail)
		return
	}
	var updatedAt time.Time
	if err := s.pool.QueryRow(r.Context(), `
		insert into principal_preferences (principal_id, time_zone, page_size, landing_page, language, theme)
		values ($1, $2, $3, $4, $5, $6)
		on conflict (principal_id) do update
		   set time_zone = excluded.time_zone, page_size = excluded.page_size,
		       landing_page = excluded.landing_page, language = excluded.language,
		       theme = excluded.theme, updated_at = now()
		returning updated_at`,
		principal.ID, request.TimeZone, request.PageSize, request.LandingPage, request.Language, request.Theme).
		Scan(&updatedAt); err != nil {
		s.fail(w, err)
		return
	}
	request.UpdatedAt = &updatedAt
	writeJSON(w, http.StatusOK, request)
}

// validatePreferences normalises the fields in place and names the first
// one the panel cannot accept, as a problem code and its detail.
func validatePreferences(p *preferences) (code, detail string) {
	p.TimeZone = strings.TrimSpace(p.TimeZone)
	p.LandingPage = strings.TrimSpace(p.LandingPage)
	p.Language = strings.TrimSpace(p.Language)
	p.Theme = strings.TrimSpace(p.Theme)
	if p.TimeZone != "" {
		if len(p.TimeZone) > maxTimeZoneLength {
			return "invalid_time_zone", "the time zone name is too long"
		}
		// The zone must be one this panel can read times in, so the
		// preference never names a zone the browser then fails on.
		if _, err := time.LoadLocation(p.TimeZone); err != nil || p.TimeZone == "Local" {
			return "invalid_time_zone", "the time zone is not an IANA zone name"
		}
	}
	if p.PageSize < 0 || p.PageSize > maxPreferredPageSize {
		return "invalid_page_size", "the page size must be between 0 (the default) and 500"
	}
	// The landing page is a path of this panel, never another origin: a
	// preference that sent the operator elsewhere after signing in would
	// be a phishing hook stored under their own name.
	if p.LandingPage != "" && (!strings.HasPrefix(p.LandingPage, "/") || strings.HasPrefix(p.LandingPage, "//") ||
		len(p.LandingPage) > maxLandingPageLength || strings.ContainsAny(p.LandingPage, " \t\n\r")) {
		return "invalid_landing_page", "the landing page must be a path of this panel, such as /hosts"
	}
	switch p.Language {
	case "", "en", "pl":
	default:
		return "invalid_language", "the language must be en or pl"
	}
	switch p.Theme {
	case "", "mocha-peach", "mocha-green", "latte":
	default:
		return "invalid_theme", "the theme must be one of mocha-peach, mocha-green or latte"
	}
	return "", ""
}

// handleMySessions lists the caller's own live browser sessions: where
// they are signed in, since when, from what. The same list the access
// screen shows to the identity's manager, for the identity itself.
func (s *Server) handleMySessions(w http.ResponseWriter, r *http.Request) {
	principal, ok := requireIdentity(w, r)
	if !ok {
		return
	}
	sessions, err := s.authz.ListSessionsOf(r.Context(), principal.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": sessions, "count": len(sessions)})
}

// handleMyTokens lists the caller's own live API tokens, without their
// values: a value was shown once, at issue, and is nowhere to be read
// again.
func (s *Server) handleMyTokens(w http.ResponseWriter, r *http.Request) {
	principal, ok := requireIdentity(w, r)
	if !ok {
		return
	}
	tokens, err := s.authz.ListTokens(r.Context(), principal.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tokens, "count": len(tokens)})
}
