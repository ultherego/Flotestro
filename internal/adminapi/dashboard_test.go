package adminapi

import "testing"

/*
The layout is written by whoever administers the panel and drawn for
everybody, so what it refuses matters more than what it accepts: a width the
grid has no class for would silently become a full row, and the same widget
twice would be two tiles sharing one identity on the screen.
*/

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
		{"a width the grid has no class for", []DashboardWidget{{Key: "a", Width: 5}}, "width"},
		{"a width of zero", []DashboardWidget{{Key: "a", Width: 0}}, "width"},
		{"the same widget twice", []DashboardWidget{{Key: "a", Width: 6}, {Key: "a", Width: 6}}, "key"},
		{"a key that is not one", []DashboardWidget{{Key: "Host Availability", Width: 6}}, "key"},
		{"a key with a path in it", []DashboardWidget{{Key: "../etc", Width: 6}}, "key"},
		{"a height taller than the board", []DashboardWidget{{Key: "a", Width: 6, Height: 9}}, "height"},
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
