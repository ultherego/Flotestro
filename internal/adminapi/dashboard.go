package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
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
	// How many rows of the board it takes. One row is the height of the
	// shortest useful tile; a widget that holds a long list is given more,
	// and two widgets of one row each stand one under another in the space
	// a taller neighbour leaves beside them.
	Height int `json:"height,omitempty"`
	// Hidden marks a widget somebody took off the screen on purpose. It
	// stays in the record so that "removed" and "did not exist when this
	// was arranged" remain two different answers: the panel places a
	// widget the record says nothing about, and leaves a hidden one off.
	Hidden bool `json:"hidden,omitempty"`
	// Where it stands, for an arrangement somebody placed on the grid
	// rather than ordered: the column it starts at and the row. A widget
	// without them flows, and a record may not mix the two - see the
	// validation, which refuses half a placement.
	X *int `json:"x,omitempty"`
	Y *int `json:"y,omitempty"`
}

// DashboardLayout is the stored record, with who wrote it and when.
type DashboardLayout struct {
	Widgets   []DashboardWidget `json:"widgets"`
	UpdatedAt *time.Time        `json:"updated_at,omitempty"`
	UpdatedBy string            `json:"updated_by,omitempty"`
	Revision  int64             `json:"revision,omitempty"`
	// Reason is why this arrangement was written, in the words of whoever
	// wrote it. Empty for the rows that predate the field.
	Reason string `json:"reason,omitempty"`
	// Present is false when the installation never stored a layout; the
	// panel then draws the one it ships with, which is not the same thing as
	// a layout somebody deliberately emptied.
	Present bool `json:"present"`
}

// The grid a screen lays out on. Width is counted in columns rather than
// pixels: an arrangement made on a wide monitor has to survive a laptop, and
// a column is the same fraction of the width on both.
//
// Until 15.10 only 3, 4, 6, 8 and 12 were allowed, because the stylesheet
// had a class for those five. The owner asked for panels that can be given
// any width, and the references he gave are full of rows that add up out of
// unequal parts - three narrow tiles beside two wider ones. So every width
// from one to twelve is allowed and the grid has a class for each.
const dashboardColumns = 12

// How many rows a widget may take. Zero means the panel decides, which is
// what a record written before heights existed carries. Sixteen rather than
// eight since 15.10: a widget holding a list scrolls inside its own box, and
// a box worth scrolling is taller than half a screen.
const dashboardMaxHeight = 16

// How far down the grid a widget may be placed. Two hundred rows is a
// screen nobody could scroll to the end of; the cap is here so one write
// cannot make a page that never finishes laying out.
const dashboardMaxRow = 200

// A key is the panel's identifier for a widget, not free text: it reaches
// the browser as a class and a React key.
var dashboardKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// How many widgets a layout may hold. The catalogue is far smaller; the cap
// is here so a write cannot turn the dashboard into a denial of service
// against the people who open it.
const dashboardWidgetLimit = 40

const (
	dashboardRead = `
		select widgets, updated_at, updated_by, revision, reason
		  from screen_layout
		 where screen = $1`
	dashboardWrite = `
		insert into screen_layout (screen, widgets, updated_at, updated_by, revision, reason)
		values ($1, $2, now(), $3, 1, $4)
		on conflict (screen) do update set
		    widgets    = excluded.widgets,
		    updated_at = now(),
		    updated_by = excluded.updated_by,
		    revision   = screen_layout.revision + 1,
		    reason     = excluded.reason
		returning updated_at, revision`
	// The arrangement being replaced is kept before it is gone, and only
	// the last few are kept: this is an undo, not an archive.
	dashboardKeep = `
		insert into screen_layout_history (screen, revision, widgets, updated_at, updated_by, reason)
		select screen, revision, widgets, updated_at, updated_by, reason
		  from screen_layout where screen = $1
		on conflict (screen, revision) do nothing`
	dashboardTrim = `
		delete from screen_layout_history
		 where screen = $1
		   and revision <= (select max(revision) - $2 from screen_layout_history where screen = $1)`
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
	err := s.pool.QueryRow(ctx, dashboardRead, screen).Scan(&raw, &updatedAt, &layout.UpdatedBy, &layout.Revision, &layout.Reason)
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
		if widget.Width < 1 || widget.Width > dashboardColumns {
			return "width", errors.New("a width is between 1 and 12 of the twelve columns")
		}
		if widget.Height < 0 || widget.Height > dashboardMaxHeight {
			return "height", errors.New("a height is between 1 and 16 rows, or absent for the one the panel chooses")
		}
		// A place is both coordinates or neither: half of one would leave
		// the panel somewhere the screen has to guess at.
		if (widget.X == nil) != (widget.Y == nil) {
			return "place", errors.New("a widget is placed by both its column and its row, or by neither: " + widget.Key)
		}
		if widget.X != nil {
			if *widget.X < 0 || *widget.X+widget.Width > dashboardColumns {
				return "x", errors.New("a widget starts inside the twelve columns and ends inside them: " + widget.Key)
			}
			if *widget.Y < 0 || *widget.Y > dashboardMaxRow {
				return "y", errors.New("a widget stands on a row of the grid: " + widget.Key)
			}
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
	// Its own permission since 15.10. It used to borrow the one for naming
	// the fleet's address, which meant "may change where agents dial" and
	// "may rearrange everyone's screen" were the same right - two unrelated
	// powers behind one grant.
	principal, ok := s.authorize(w, r, authz.PermSettingsLayoutWrite, authz.GlobalScope, "screen_layout", screen)
	if !ok {
		return
	}
	var body struct {
		Widgets []DashboardWidget `json:"widgets"`
		// Revision the editor read. A write without it is refused: "I did
		// not look" is not grounds for overwriting somebody who did.
		Revision *int64 `json:"revision"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if len([]rune(reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"this operation requires a reason (field reason, min. 8 characters): it changes the screen of everybody who opens it")
		return
	}
	if body.Revision == nil {
		problem(w, http.StatusBadRequest, "revision_required",
			"send the revision this arrangement was read at, so a change made in the meantime is not overwritten unseen")
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

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// The row is locked while its revision is read, so two administrators
	// arranging the same screen cannot both pass this check.
	var current int64
	err = tx.QueryRow(r.Context(), `select revision from screen_layout where screen = $1 for update`, screen).Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.fail(w, err)
		return
	}
	if current != *body.Revision {
		problem(w, http.StatusConflict, "layout_changed",
			"somebody else arranged this screen while this one was being edited; read it again and put the change on top of what is there now")
		return
	}
	if current > 0 {
		if _, err := tx.Exec(r.Context(), dashboardKeep, screen); err != nil {
			s.fail(w, err)
			return
		}
		if _, err := tx.Exec(r.Context(), dashboardTrim, screen, dashboardHistoryKept); err != nil {
			s.fail(w, err)
			return
		}
	}

	var (
		updatedAt time.Time
		revision  int64
	)
	if err := tx.QueryRow(r.Context(), dashboardWrite, screen, raw, principal.Subject, reason).Scan(&updatedAt, &revision); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "screen.layout.write", TargetType: "screen_layout", TargetID: screen,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"widgets": len(body.Widgets), "revision": revision, "reason": reason,
			// The blast radius, said rather than left to be inferred.
			"applies_to": "every identity that can open this screen",
		},
	})
	writeJSON(w, http.StatusOK, DashboardLayout{
		Widgets: body.Widgets, UpdatedAt: &updatedAt, UpdatedBy: principal.Subject,
		Revision: revision, Reason: reason, Present: true,
	})
}

// How many previous arrangements of a screen are kept. Enough to undo an
// afternoon, not enough to be an archive.
const dashboardHistoryKept = 10

// handleResetScreenLayout takes the stored arrangement away, so the screen
// goes back to the one the panel ships with. The history stays: a reset is a
// change like any other and has to be undoable too.
func (s *Server) handleResetScreenLayout(w http.ResponseWriter, r *http.Request) {
	screen := r.PathValue("screen")
	if !screenName.MatchString(screen) {
		problem(w, http.StatusBadRequest, "invalid_request", "screen: a screen is named in lower-case letters, digits and underscores")
		return
	}
	principal, ok := s.authorize(w, r, authz.PermSettingsLayoutWrite, authz.GlobalScope, "screen_layout", screen)
	if !ok {
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	if len([]rune(strings.TrimSpace(reason))) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"this operation requires a reason (field reason, min. 8 characters)")
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if _, err := tx.Exec(r.Context(), dashboardKeep, screen); err != nil {
		s.fail(w, err)
		return
	}
	tag, err := tx.Exec(r.Context(), `delete from screen_layout where screen = $1`, screen)
	if err != nil {
		s.fail(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, http.StatusNotFound, "no_layout", "this screen has no stored arrangement; it already draws the one the panel ships with")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "screen.layout.reset", TargetType: "screen_layout", TargetID: screen,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"reason": strings.TrimSpace(reason),
			"applies_to": "every identity that can open this screen"},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleScreenLayoutHistory answers what this screen looked like before,
// newest first, so an arrangement that made it worse can be put back.
func (s *Server) handleScreenLayoutHistory(w http.ResponseWriter, r *http.Request) {
	screen := r.PathValue("screen")
	if !screenName.MatchString(screen) {
		problem(w, http.StatusBadRequest, "invalid_request", "screen: a screen is named in lower-case letters, digits and underscores")
		return
	}
	if _, ok := s.authorize(w, r, authz.PermSettingsLayoutWrite, authz.GlobalScope, "screen_layout", screen); !ok {
		return
	}
	rows, err := s.pool.Query(r.Context(), `
		select revision, widgets, updated_at, updated_by, reason
		  from screen_layout_history
		 where screen = $1
		 order by revision desc
		 limit $2`, screen, dashboardHistoryKept)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer rows.Close()
	items := []DashboardLayout{}
	for rows.Next() {
		var (
			one       DashboardLayout
			raw       []byte
			updatedAt time.Time
		)
		if err := rows.Scan(&one.Revision, &raw, &updatedAt, &one.UpdatedBy, &one.Reason); err != nil {
			s.fail(w, err)
			return
		}
		if err := json.Unmarshal(raw, &one.Widgets); err != nil {
			s.fail(w, err)
			return
		}
		one.UpdatedAt = &updatedAt
		one.Present = true
		items = append(items, one)
	}
	if err := rows.Err(); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
