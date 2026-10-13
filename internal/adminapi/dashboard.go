package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// The layout of an arrangeable screen: which widgets it draws, in what order
// and how wide each one is. It belongs to the installation rather than to a
// person - see the migration for why - so one row per screen holds it and
// whoever may write the settings decides it for everybody.

// A screen the panel can be told how to arrange. The panel owns the
// catalogue of widgets of each; this package only keeps the arrangement.
var screenName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// DashboardWidget is one widget of the layout.
type DashboardWidget struct {
	// The panel's own name for the widget. This package never interprets it:
	// the catalogue of widgets belongs to the screen, and a key this panel
	// does not know is skipped when the dashboard is drawn.
	Key string `json:"key"`
	// How many of the twelve columns the widget takes.
	Width int `json:"width"`
}

// DashboardLayout is the stored record, with who wrote it and when.
type DashboardLayout struct {
	Widgets   []DashboardWidget `json:"widgets"`
	UpdatedAt *time.Time        `json:"updated_at,omitempty"`
	UpdatedBy string            `json:"updated_by,omitempty"`
	Revision  int64             `json:"revision,omitempty"`
	// Present is false when the installation never stored a layout; the
	// panel then draws the one it ships with, which is not the same thing as
	// a layout somebody deliberately emptied.
	Present bool `json:"present"`
}

// The widths a widget may take: a twelfth of the grid is unreadable and a
// width the grid has no class for would silently fall back to the full row.
var dashboardWidths = map[int]bool{3: true, 4: true, 6: true, 8: true, 12: true}

// A key is the panel's identifier for a widget, not free text: it reaches
// the browser as a class and a React key.
var dashboardKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// How many widgets a layout may hold. The catalogue is far smaller; the cap
// is here so a write cannot turn the dashboard into a denial of service
// against the people who open it.
const dashboardWidgetLimit = 40

const (
	dashboardRead = `
		select widgets, updated_at, updated_by, revision
		  from screen_layout
		 where screen = $1`
	dashboardWrite = `
		insert into screen_layout (screen, widgets, updated_at, updated_by, revision)
		values ($1, $2, now(), $3, 1)
		on conflict (screen) do update set
		    widgets    = excluded.widgets,
		    updated_at = now(),
		    updated_by = excluded.updated_by,
		    revision   = screen_layout.revision + 1
		returning updated_at, revision`
)

// readDashboardLayout answers what the installation stored. A schema from
// before the table and an installation that stored nothing answer the same
// way: no layout, and the panel draws its own.
func (s *Server) readDashboardLayout(ctx context.Context, screen string) (DashboardLayout, error) {
	var (
		layout    DashboardLayout
		raw       []byte
		updatedAt time.Time
	)
	err := s.pool.QueryRow(ctx, dashboardRead, screen).Scan(&raw, &updatedAt, &layout.UpdatedBy, &layout.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return DashboardLayout{Widgets: []DashboardWidget{}}, nil
	}
	if err != nil {
		return DashboardLayout{}, err
	}
	if err := json.Unmarshal(raw, &layout.Widgets); err != nil {
		return DashboardLayout{}, err
	}
	layout.Present = true
	layout.UpdatedAt = &updatedAt
	return layout, nil
}

// validateDashboardWidgets refuses a layout the screen could not draw. The
// keys themselves are not checked against a catalogue: this package does not
// own one, and a panel that refused a key it had not heard of could not be
// written to by a newer panel's screen.
func validateDashboardWidgets(widgets []DashboardWidget) (string, error) {
	if len(widgets) == 0 {
		return "widgets", errors.New("a layout with no widget would leave the dashboard blank; remove the stored layout instead to go back to the one the panel ships with")
	}
	if len(widgets) > dashboardWidgetLimit {
		return "widgets", errors.New("a dashboard holds at most 40 widgets")
	}
	seen := make(map[string]bool, len(widgets))
	for _, widget := range widgets {
		if !dashboardKey.MatchString(widget.Key) {
			return "key", errors.New("a widget key is lower-case letters, digits and underscores: " + widget.Key)
		}
		if seen[widget.Key] {
			// Twice in one layout is a widget drawn twice, and the second
			// copy would carry the same React key as the first.
			return "key", errors.New("the same widget twice: " + widget.Key)
		}
		seen[widget.Key] = true
		if !dashboardWidths[widget.Width] {
			return "width", errors.New("a width is 3, 4, 6, 8 or 12 of the twelve columns")
		}
	}
	return "", nil
}

// handleDashboardLayout answers the layout. Everybody who may open the
// dashboard may read it: a screen cannot draw itself without it.
func (s *Server) handleDashboardLayout(w http.ResponseWriter, r *http.Request) {
	screen := r.PathValue("screen")
	if !screenName.MatchString(screen) {
		problem(w, http.StatusBadRequest, "invalid_request", "screen: a screen is named in lower-case letters, digits and underscores")
		return
	}
	if _, ok := s.authorize(w, r, authz.PermHostRead, authz.GlobalScope, "screen_layout", screen); !ok {
		return
	}
	layout, err := s.readDashboardLayout(r.Context(), screen)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, layout)
}

// handleSetDashboardLayout stores the layout for the whole installation.
func (s *Server) handleSetDashboardLayout(w http.ResponseWriter, r *http.Request) {
	screen := r.PathValue("screen")
	if !screenName.MatchString(screen) {
		problem(w, http.StatusBadRequest, "invalid_request", "screen: a screen is named in lower-case letters, digits and underscores")
		return
	}
	principal, ok := s.authorize(w, r, authz.PermSettingsAdvertiseWrite, authz.GlobalScope, "screen_layout", screen)
	if !ok {
		return
	}
	var body struct {
		Widgets []DashboardWidget `json:"widgets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if field, err := validateDashboardWidgets(body.Widgets); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", field+": "+err.Error())
		return
	}
	raw, err := json.Marshal(body.Widgets)
	if err != nil {
		s.fail(w, err)
		return
	}
	var (
		updatedAt time.Time
		revision  int64
	)
	if err := s.pool.QueryRow(r.Context(), dashboardWrite, screen, raw, principal.Subject).Scan(&updatedAt, &revision); err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "screen.layout.write", TargetType: "screen_layout", TargetID: screen,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"widgets": len(body.Widgets), "revision": revision},
	})
	writeJSON(w, http.StatusOK, DashboardLayout{
		Widgets: body.Widgets, UpdatedAt: &updatedAt, UpdatedBy: principal.Subject,
		Revision: revision, Present: true,
	})
}
