//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// campaignScheduleView is the schedule record as the API serves it.
type campaignScheduleView struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	StartAt        *time.Time `json:"start_at"`
	Recurrence     string     `json:"recurrence"`
	Timezone       string     `json:"timezone"`
	NextRunAt      *time.Time `json:"next_run_at"`
	LastRunAt      *time.Time `json:"last_run_at"`
	LastCampaignID string     `json:"last_campaign_id"`
	LastError      string     `json:"last_error"`
	CreatedBy      string     `json:"created_by"`
	Enabled        bool       `json:"enabled"`
	Reason         string     `json:"reason"`
}

type calendarView struct {
	Items []struct {
		Kind  string     `json:"kind"`
		ID    string     `json:"id"`
		Name  string     `json:"name"`
		Start *time.Time `json:"start"`
		End   *time.Time `json:"end"`
	} `json:"items"`
}

// labScheduleOrder is a restart of a harmless unit on the first two lab
// hosts, named host by host: what a schedule keeps and places.
func labScheduleOrder(t *testing.T, h *harness, name string) map[string]any {
	t.Helper()
	hosts := h.hosts()
	if len(hosts) < 2 {
		t.Skip("the schedule test needs at least two hosts")
	}
	order := labCampaign(name, "cron.service", nil)
	order["selector"] = map[string]any{"host_ids": []string{hosts[0].ID, hosts[1].ID}}
	return order
}

// createCampaignSchedule records a schedule and removes it at the end of the
// test, with the campaign it may have placed canceled first.
func (h *harness) createCampaignSchedule(body map[string]any) campaignScheduleView {
	h.t.Helper()
	var schedule campaignScheduleView
	h.do(http.MethodPost, "/api/v1/campaign-schedules", body, &schedule, http.StatusCreated)
	h.t.Cleanup(func() {
		var last campaignScheduleView
		h.do(http.MethodGet, "/api/v1/campaign-schedules/"+schedule.ID, nil, &last, 0)
		if last.LastCampaignID != "" {
			h.do(http.MethodPost, "/api/v1/campaigns/"+last.LastCampaignID+"/cancel",
				map[string]any{"reason": "end of the test"}, nil, 0)
		}
		h.do(http.MethodDelete, "/api/v1/campaign-schedules/"+schedule.ID+"?reason="+url.QueryEscape("end of the test"), nil, nil, 0)
	})
	return schedule
}

// awaitSchedulePlacement polls the schedule until a run is recorded on
// it - a campaign placed or a refusal kept.
func (h *harness) awaitSchedulePlacement(id string, timeout time.Duration) campaignScheduleView {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var schedule campaignScheduleView
		h.get("/api/v1/campaign-schedules/"+id, &schedule)
		if schedule.LastCampaignID != "" || schedule.LastError != "" {
			return schedule
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the schedule %s placed nothing within %s (next_run_at %v)", id, timeout, schedule.NextRunAt)
		}
		time.Sleep(time.Second)
	}
}

// TestAScheduledCampaignIsPlacedAtItsMomentAndWaitsForApproval guards the
// schedule loop: a schedule with a moment a few seconds ahead places its order
// at that moment, the campaign it places is an ordinary one - requested by the
func TestAScheduledCampaignIsPlacedAtItsMomentAndWaitsForApproval(t *testing.T) {
	h := newHarness(t)
	startAt := time.Now().UTC().Add(5 * time.Second).Truncate(time.Second)
	schedule := h.createCampaignSchedule(map[string]any{
		"name":     "restart cron once",
		"order":    labScheduleOrder(t, h, "scheduled cron restart"),
		"start_at": startAt.Format(time.RFC3339),
		"timezone": "UTC",
		"reason":   "integration test of a scheduled campaign",
	})
	if !schedule.Enabled || schedule.NextRunAt == nil || !schedule.NextRunAt.Equal(startAt) {
		t.Fatalf("the schedule was recorded as enabled=%v next_run_at=%v, expected %s", schedule.Enabled, schedule.NextRunAt, startAt)
	}
	if schedule.CreatedBy == "" {
		t.Error("the schedule records no author; the order would be placed under nobody's rights")
	}

	placed := h.awaitSchedulePlacement(schedule.ID, 60*time.Second)
	if placed.LastCampaignID == "" {
		t.Fatalf("the schedule placed nothing: %s", placed.LastError)
	}
	if placed.NextRunAt != nil {
		t.Errorf("a single moment fired and the schedule still names %v as its next moment", placed.NextRunAt)
	}
	if placed.LastRunAt == nil || placed.LastRunAt.Before(startAt.Add(-time.Second)) {
		t.Errorf("the run was recorded at %v, before the moment %s", placed.LastRunAt, startAt)
	}

	campaign := h.campaign(placed.LastCampaignID)
	if campaign.State != "awaiting_approval" {
		t.Errorf("the placed campaign is %s, expected awaiting_approval: a schedule cannot waive the consent", campaign.State)
	}
	if campaign.CreatedBy != "schedule:"+schedule.ID {
		t.Errorf("the placed campaign was requested by %q, expected schedule:%s", campaign.CreatedBy, schedule.ID)
	}
	if campaign.Name != "scheduled cron restart" {
		t.Errorf("the placed campaign is named %q", campaign.Name)
	}
	if !campaign.RequiresApproval {
		t.Error("the placed campaign does not require approval")
	}
	if targets := h.campaignTargets(campaign.ID); len(targets) != 2 {
		t.Errorf("the placed campaign has %d targets, expected the two hosts of the order", len(targets))
	}
	// The campaign list finds it by its requester, like any other.
	var listed struct {
		Items []campaignView `json:"items"`
	}
	h.get("/api/v1/campaigns?requester="+url.QueryEscape("schedule:"+schedule.ID), &listed)
	if len(listed.Items) != 1 || listed.Items[0].ID != campaign.ID {
		t.Errorf("the campaign list filtered by the schedule returns %d campaigns", len(listed.Items))
	}
}

// TestRunNowPlacesTheScheduledOrderAtOnce guards the on-demand run: the order
// is placed immediately under the schedule's name, the run is recorded on the
// schedule and the next moment of a recurring schedule stays where the rule
func TestRunNowPlacesTheScheduledOrderAtOnce(t *testing.T) {
	h := newHarness(t)
	schedule := h.createCampaignSchedule(map[string]any{
		"name":       "monthly cron restart",
		"order":      labScheduleOrder(t, h, "monthly cron restart"),
		"recurrence": "FREQ=MONTHLY;BYMONTHDAY=1;BYHOUR=3;BYMINUTE=0",
		"timezone":   "UTC",
		"reason":     "integration test of run-now",
	})
	if schedule.NextRunAt == nil {
		t.Fatal("a recurring schedule has no next moment")
	}
	before := *schedule.NextRunAt

	var refusal struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/campaign-schedules/"+schedule.ID+"/run-now",
		map[string]any{"reason": "now"}, &refusal, http.StatusBadRequest)
	if refusal.Code != "reason_required" {
		t.Errorf("a run without a reason was refused with %s", refusal.Code)
	}

	var campaign campaignView
	h.do(http.MethodPost, "/api/v1/campaign-schedules/"+schedule.ID+"/run-now",
		map[string]any{"reason": "rehearsal of the monthly window"}, &campaign, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/campaigns/"+campaign.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})
	if campaign.State != "awaiting_approval" || campaign.CreatedBy != "schedule:"+schedule.ID {
		t.Errorf("run-now placed a campaign in %s requested by %q", campaign.State, campaign.CreatedBy)
	}
	// A recurring order names its moment, so this month's window is told
	// from the next one's.
	if !strings.HasPrefix(campaign.Name, "monthly cron restart ") {
		t.Errorf("the recurring campaign is named %q, expected the moment appended", campaign.Name)
	}

	var after campaignScheduleView
	h.get("/api/v1/campaign-schedules/"+schedule.ID, &after)
	if after.LastCampaignID != campaign.ID || after.LastRunAt == nil {
		t.Errorf("the run was not recorded on the schedule: last_campaign_id=%q last_run_at=%v", after.LastCampaignID, after.LastRunAt)
	}
	if after.NextRunAt == nil || !after.NextRunAt.Equal(before) {
		t.Errorf("run-now moved the next moment from %s to %v", before, after.NextRunAt)
	}
}

// TestAScheduleIsRefusedWhereItCouldNeverFire guards the door of the
// schedules: a moment in the past, a rule outside the subset, an operation
// that does not run in bulk and a write without a reason are each refused with
func TestAScheduleIsRefusedWhereItCouldNeverFire(t *testing.T) {
	h := newHarness(t)
	order := labScheduleOrder(t, h, "refused")
	ahead := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	cases := []struct {
		name string
		body map[string]any
		code string
	}{
		{"no reason", map[string]any{"name": "x", "order": order, "start_at": ahead}, "reason_required"},
		{"moment in the past", map[string]any{"name": "x", "order": order, "reason": "integration test",
			"start_at": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)}, "moment_in_past"},
		{"no moment", map[string]any{"name": "x", "order": order, "reason": "integration test"}, "moment_required"},
		{"daily rule", map[string]any{"name": "x", "order": order, "reason": "integration test",
			"recurrence": "FREQ=DAILY;BYHOUR=1"}, "invalid_recurrence"},
		{"unknown zone", map[string]any{"name": "x", "order": order, "reason": "integration test",
			"start_at": ahead, "timezone": "Mars/Olympus"}, "invalid_timezone"},
		{"order without an operation", map[string]any{"name": "x", "reason": "integration test",
			"start_at": ahead, "order": map[string]any{"name": "y"}}, "invalid_order"},
		{"operation that is not bulk", map[string]any{"name": "x", "reason": "integration test",
			"start_at": ahead, "order": map[string]any{"name": "y", "action": "inventory.refresh"}}, "unknown_action"},
	}
	for _, tc := range cases {
		var refusal struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		h.do(http.MethodPost, "/api/v1/campaign-schedules", tc.body, &refusal, http.StatusBadRequest)
		if refusal.Code != tc.code {
			t.Errorf("%s: refused with %s (%s), expected %s", tc.name, refusal.Code, refusal.Detail, tc.code)
		}
	}
}

// TestTheCalendarListsScheduleMomentsAndDisablingRemovesThem guards the
// calendar and the life of a schedule: a weekly rule draws its moments in the
// month, a disabled schedule draws none and names no next moment, a removal
func TestTheCalendarListsScheduleMomentsAndDisablingRemovesThem(t *testing.T) {
	h := newHarness(t)
	order := labScheduleOrder(t, h, "weekly cron restart")
	schedule := h.createCampaignSchedule(map[string]any{
		"name":       "weekly cron restart",
		"order":      order,
		"recurrence": "FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=22;BYMINUTE=30",
		"timezone":   "UTC",
		"reason":     "integration test of the calendar",
	})
	if schedule.Recurrence != "FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=22;BYMINUTE=30" {
		t.Errorf("the rule was stored as %q", schedule.Recurrence)
	}
	if schedule.NextRunAt == nil {
		t.Fatal("the weekly schedule has no next moment")
	}
	next := *schedule.NextRunAt
	if next.Weekday() != time.Monday && next.Weekday() != time.Thursday || next.Hour() != 22 || next.Minute() != 30 {
		t.Errorf("the next moment %s is not a Monday or Thursday at 22:30", next)
	}

	from := time.Now().UTC().Truncate(24 * time.Hour)
	to := from.AddDate(0, 0, 28)
	var calendar calendarView
	h.get("/api/v1/maintenance/calendar?from="+url.QueryEscape(from.Format(time.RFC3339))+
		"&to="+url.QueryEscape(to.Format(time.RFC3339)), &calendar)
	moments := 0
	for _, entry := range calendar.Items {
		if entry.Kind == "schedule" && entry.ID == schedule.ID {
			moments++
			if entry.Start == nil || entry.Start.Before(from) || !entry.Start.Before(to) {
				t.Errorf("the calendar draws the schedule at %v, outside the range", entry.Start)
			}
		}
	}
	// Four weeks hold eight Mondays and Thursdays, one of which may fall
	// before today's moment.
	if moments < 7 || moments > 8 {
		t.Errorf("the calendar draws %d moments of a twice-weekly rule over four weeks", moments)
	}

	var refusal struct {
		Code string `json:"code"`
	}
	h.do(http.MethodGet, "/api/v1/maintenance/calendar?from="+url.QueryEscape(to.Format(time.RFC3339))+
		"&to="+url.QueryEscape(from.Format(time.RFC3339)), nil, &refusal, http.StatusBadRequest)
	if refusal.Code != "invalid_range" {
		t.Errorf("a range that ends before it starts was refused with %s", refusal.Code)
	}

	var disabled campaignScheduleView
	h.do(http.MethodPut, "/api/v1/campaign-schedules/"+schedule.ID, map[string]any{
		"name":       "weekly cron restart",
		"order":      order,
		"recurrence": "FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=22;BYMINUTE=30",
		"timezone":   "UTC",
		"enabled":    false,
		"reason":     "integration test: paused",
	}, &disabled, http.StatusOK)
	if disabled.Enabled || disabled.NextRunAt != nil {
		t.Errorf("the disabled schedule is enabled=%v with next_run_at=%v", disabled.Enabled, disabled.NextRunAt)
	}
	h.get("/api/v1/maintenance/calendar?from="+url.QueryEscape(from.Format(time.RFC3339))+
		"&to="+url.QueryEscape(to.Format(time.RFC3339)), &calendar)
	for _, entry := range calendar.Items {
		if entry.Kind == "schedule" && entry.ID == schedule.ID {
			t.Errorf("the calendar still draws the disabled schedule at %v", entry.Start)
		}
	}

	h.do(http.MethodDelete, "/api/v1/campaign-schedules/"+schedule.ID, map[string]any{"reason": "short"}, &refusal, http.StatusBadRequest)
	if refusal.Code != "reason_required" {
		t.Errorf("a removal without a reason was refused with %s", refusal.Code)
	}
	h.do(http.MethodDelete, "/api/v1/campaign-schedules/"+schedule.ID, map[string]any{"reason": "end of the test"}, nil, http.StatusNoContent)
	h.do(http.MethodGet, "/api/v1/campaign-schedules/"+schedule.ID, nil, &refusal, http.StatusNotFound)
	if refusal.Code != "schedule_not_found" {
		t.Errorf("a removed schedule answers %s", refusal.Code)
	}
}
