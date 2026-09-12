package integrations

import (
	"strings"
	"time"
)

// Mapping translates a host of the panel into the labels of the monitoring
// systems.
//
// That is the whole difficulty of this integration: the panel knows a host by
// its identifier and name, Prometheus by the label "instance", which is
// usually an address with the port of an exporter, and Alertmanager by
// whatever happened to be written in a rule. Guessing ends with an empty chart
// without an explanation, so the mapping is explicit, configurable and shown
// to the operator together with the result.
type Mapping struct {
	// HostLabel is the name of the label that identifies a host.
	HostLabel string
	// HostValue is the template of the value of that label.
	HostValue string
	// SiteLabel and EnvironmentLabel are optional: we use them in the fleet
	// view and for silences covering more than one host.
	SiteLabel        string
	EnvironmentLabel string
	// DashboardURL and LogsURL are templates of links. The panel does not draw
	// somebody else's dashboards - it leads to them.
	DashboardURL string
	LogsURL      string
	// Window is the default time range of the charts.
	Window time.Duration
}

// Host describes a host in the language of the panel.
type Host struct {
	ID          string
	Hostname    string
	Address     string
	Site        string
	Environment string
}

// DefaultMapping matches an installation with node_exporter on port 9100.
//
// A default rather than the only one: an installation that names its hosts
// differently replaces the template in the configuration instead of getting
// empty charts.
func DefaultMapping() Mapping {
	return Mapping{
		HostLabel:        "instance",
		HostValue:        "{hostname}:9100",
		SiteLabel:        "site",
		EnvironmentLabel: "environment",
		Window:           3 * time.Hour,
	}
}

// Label returns the value of the label of a host.
func (m Mapping) Label(host Host) string {
	return m.Substitute(m.HostValue, host)
}

// Substitute puts the data of a host into a template.
//
// The fields a template does not use simply do not appear; empty fields are
// left empty instead of inserting the word "unknown" - a link with such a word
// would lead to a chart that does not exist.
func (m Mapping) Substitute(template string, host Host) string {
	replacements := []string{
		"{hostname}", host.Hostname,
		"{host_id}", host.ID,
		"{address}", host.Address,
		"{site}", host.Site,
		"{environment}", host.Environment,
	}
	return strings.NewReplacer(replacements...).Replace(template)
}

// HostFilter returns the Alertmanager filter for one host.
func (m Mapping) HostFilter(host Host) string {
	return m.HostLabel + `="` + m.Label(host) + `"`
}

// Links describe where the panel leads for the details.
type Links struct {
	Dashboard string `json:"dashboard,omitempty"`
	Logs      string `json:"logs,omitempty"`
}

// For returns the links for a host.
func (m Mapping) For(host Host) Links {
	links := Links{}
	if m.DashboardURL != "" {
		links.Dashboard = m.Substitute(m.DashboardURL, host)
	}
	if m.LogsURL != "" {
		links.Logs = m.Substitute(m.LogsURL, host)
	}
	return links
}

// WindowOr returns the time range of a chart.
func (m Mapping) WindowOr(requested time.Duration) time.Duration {
	if requested > 0 {
		return requested
	}
	if m.Window > 0 {
		return m.Window
	}
	return 3 * time.Hour
}
