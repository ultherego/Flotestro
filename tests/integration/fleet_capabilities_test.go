//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"testing"
)

// TestTheFleetDividesByATechnologyIntoHasHasNotAndUnknown reads one technology three ways - the
// fleet counts, and the host list asked for each state - and the two have to agree, with the three
// parts adding up to the whole: a host that never said is counted apart, not as a host without.
func TestTheFleetDividesByATechnologyIntoHasHasNotAndUnknown(t *testing.T) {
	h := newHarness(t)

	var fleet struct {
		Total int `json:"total"`
		Items []struct {
			Name      string `json:"name"`
			Available int    `json:"available"`
			Missing   int    `json:"missing"`
			Unknown   int    `json:"unknown"`
		} `json:"items"`
	}
	h.get("/api/v1/fleet/capabilities", &fleet)
	if fleet.Total == 0 || len(fleet.Items) == 0 {
		absent(t, "the fleet reports no technology")
	}
	for _, item := range fleet.Items {
		if item.Available+item.Missing+item.Unknown != fleet.Total {
			t.Errorf("%s: %d + %d + %d is not the %d hosts of the fleet",
				item.Name, item.Available, item.Missing, item.Unknown, fleet.Total)
		}
		for state, want := range map[string]int{"available": item.Available, "missing": item.Missing, "unknown": item.Unknown} {
			var list struct {
				Items []hostView `json:"items"`
			}
			h.get("/api/v1/hosts?limit=200&capability="+url.QueryEscape(item.Name)+"&capability_state="+state, &list)
			if len(list.Items) != want && fleet.Total <= 200 {
				t.Errorf("%s %s: the list holds %d hosts, the count says %d", item.Name, state, len(list.Items), want)
			}
		}
	}

	// A page by number is the same rows as the list walked from its start.
	var whole, second struct {
		Items []hostView `json:"items"`
	}
	h.get("/api/v1/hosts?limit=4", &whole)
	h.get("/api/v1/hosts?limit=2&offset=2", &second)
	if len(whole.Items) == 4 {
		for i, host := range second.Items {
			if host.ID != whole.Items[2+i].ID {
				t.Errorf("row %d of the page at offset 2 is %s, the list has %s there", i, host.Hostname, whole.Items[2+i].Hostname)
			}
		}
	}

	h.do(http.MethodGet, "/api/v1/hosts?capability=docker&capability_state=sometimes", nil, nil, http.StatusBadRequest)
}
