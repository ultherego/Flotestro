package adminapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

/*
The layout is written by whoever administers the panel and drawn for
everybody, so what it refuses matters more than what it accepts: a width the
grid has no class for would silently become a full row, and the same widget
twice would be two tiles sharing one identity on the screen.
*/

// Every width the server accepts has a class in the stylesheet, and every
// class the stylesheet has is accepted. The two drifted apart once already -
// the server allowed five widths because those were the five classes - and a
// width without a class does not fail: it falls silently back to a full row,
// which looks like the arrangement was ignored.
func TestEveryAcceptedWidthHasAGridClass(t *testing.T) {
	stylesheet, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "styles.css"))
	if err != nil {
		t.Fatalf("the stylesheet could not be read: %v", err)
	}
	for width := 1; width <= dashboardColumns; width++ {
		class := fmt.Sprintf(".span-%d { grid-column: span %d; }", width, width)
		if !strings.Contains(string(stylesheet), class) {
			t.Errorf("the server accepts a width of %d and the stylesheet has no %q", width, class)
		}
		if _, err := validateDashboardWidgets([]DashboardWidget{{Key: "a", Width: width}}); err != nil {
			t.Errorf("the stylesheet has a class for %d columns and the server refuses it: %v", width, err)
		}
	}
	// And one past the end, so the bound is a bound and not a coincidence.
	if _, err := validateDashboardWidgets([]DashboardWidget{{Key: "a", Width: dashboardColumns + 1}}); err == nil {
		t.Error("a width wider than the grid was accepted")
	}
}

// A height has to be drawable too: the stylesheet gives each row count a
// height, and the server must not accept one the grid cannot express.
func TestEveryAcceptedHeightHasARowHeight(t *testing.T) {
	stylesheet, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "styles.css"))
	if err != nil {
		t.Fatalf("the stylesheet could not be read: %v", err)
	}
	for rows := 1; rows <= dashboardMaxHeight; rows++ {
		selector := fmt.Sprintf(`.widgets > [data-rows="%d"]`, rows)
		if !strings.Contains(string(stylesheet), selector) {
			t.Errorf("the server accepts a height of %d rows and the stylesheet has no %s", rows, selector)
		}
	}
}

func TestValidateDashboardWidgets(t *testing.T) {
	ok := []DashboardWidget{{Key: "host_availability", Width: 12}, {Key: "needs_you", Width: 6}}
	if field, err := validateDashboardWidgets(ok); err != nil {
		t.Fatalf("a layout of two widgets was refused on %s: %v", field, err)
	}

	cases := []struct {
		name    string
		widgets []DashboardWidget
		field   string
	}{
		{"nothing at all", nil, "widgets"},
		{"a width of zero", []DashboardWidget{{Key: "a", Width: 0}}, "width"},
		{"the same widget twice", []DashboardWidget{{Key: "a", Width: 6}, {Key: "a", Width: 6}}, "key"},
		{"a key that is not one", []DashboardWidget{{Key: "Host Availability", Width: 6}}, "key"},
		{"a key with a path in it", []DashboardWidget{{Key: "../etc", Width: 6}}, "key"},
		{"a width wider than the grid", []DashboardWidget{{Key: "a", Width: 13}}, "width"},
		{"half a placement", []DashboardWidget{{Key: "a", Width: 6, X: ptr(0)}}, "place"},
		{"placed off the right edge", []DashboardWidget{{Key: "a", Width: 6, X: ptr(8), Y: ptr(0)}}, "x"},
		{"placed above the grid", []DashboardWidget{{Key: "a", Width: 6, X: ptr(0), Y: ptr(-1)}}, "y"},
		{"placed past the last row", []DashboardWidget{{Key: "a", Width: 6, X: ptr(0), Y: ptr(201)}}, "y"},
		{"a height taller than the board", []DashboardWidget{{Key: "a", Width: 6, Height: 17}}, "height"},
		{"a height below zero", []DashboardWidget{{Key: "a", Width: 6, Height: -1}}, "height"},
	}
	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			field, err := validateDashboardWidgets(one.widgets)
			if err == nil {
				t.Fatalf("accepted %v", one.widgets)
			}
			if field != one.field {
				t.Fatalf("blamed %q, wanted %q: %v", field, one.field, err)
			}
		})
	}
}

/*
A key the panel does not know is not refused here. The catalogue of widgets
belongs to the screen, and a record written by a newer panel - one that
knows a widget this one does not - has to remain readable: the screen skips
what it cannot draw. A server that refused it would make the record
unwritable from the newer panel instead.
*/
/*
A record written before widgets had a height carries none, and must go on
being readable: no height means the panel chooses one.
*/
func TestAWidgetWithoutAHeightIsValid(t *testing.T) {
	if _, err := validateDashboardWidgets([]DashboardWidget{{Key: "a", Width: 6}}); err != nil {
		t.Fatalf("refused a widget that names no height: %v", err)
	}
}

func TestADashboardKeyThisPanelDoesNotKnowIsStillValid(t *testing.T) {
	if _, err := validateDashboardWidgets([]DashboardWidget{{Key: "a_widget_from_the_future", Width: 4}}); err != nil {
		t.Fatalf("refused a key the catalogue has no entry for: %v", err)
	}
}

func ptr(value int) *int { return &value }

// A placement the grid can draw is accepted, because a validator that
// refuses everything is not a validator.
func TestAPlacedWidgetIsAccepted(t *testing.T) {
	widgets := []DashboardWidget{
		{Key: "left", Width: 8, Height: 4, X: ptr(0), Y: ptr(0)},
		{Key: "right", Width: 4, Height: 2, X: ptr(8), Y: ptr(0)},
		{Key: "under", Width: 12, Height: 3, X: ptr(0), Y: ptr(4)},
	}
	if field, err := validateDashboardWidgets(widgets); err != nil {
		t.Fatalf("refused a placement the grid can draw: %s: %v", field, err)
	}
}
