package adminapi

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/hosts"
)

// attentionFilters reads the "needs attention" filters of the host list into
// the filter: the ones a dashboard tile links here with, so the count on the
// tile leads to the hosts it counted. Each yes-or-no filter takes true or
// false, and a value that is neither is refused rather than read as one of
// them. The answer has been written when the result is false.
func attentionFilters(w http.ResponseWriter, query url.Values, filter *hosts.ListFilter) bool {
	flags := []struct {
		name   string
		target **bool
	}{
		{"failed_units", &filter.FailedUnits},
		{"package_db_broken", &filter.PackageDatabaseBroken},
		{"sssd_offline", &filter.SSSDOffline},
		{"agent_behind", &filter.AgentBehind},
	}
	for _, flag := range flags {
		value := query.Get(flag.name)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", flag.name+" must be true or false")
			return false
		}
		*flag.target = &parsed
	}
	// The relay is a typed column: an identifier that is not one would
	// fail in the database and come back as a server fault, when it is
	// the request that is wrong. A relay that does not exist is a valid
	// question with an empty answer.
	if relay := strings.TrimSpace(query.Get("relay")); relay != "" {
		if _, err := uuid.Parse(relay); err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", "relay must be a relay identifier")
			return false
		}
		filter.Relay = relay
	}
	// A domain name is matched as an operator recorded it; a name that
	// could not have been recorded is refused for the same reason it
	// could not be set.
	if domain := query.Get("failure_domain"); domain != "" {
		normalized, err := hosts.NormalizeFailureDomain(domain)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", err.Error())
			return false
		}
		filter.FailureDomain = normalized
	}
	return true
}
