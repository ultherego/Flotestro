package agent

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand/v2"
	"slices"
	"time"
)

// CadenceClass says how often a module is read in the periodic cycle.
type CadenceClass string

const (
	// CadenceFast marks a module read in every cycle: a unit fails, a container
	// stops, an inhibitor appears - the operator wants to see it at the next
	// cycle, and the read is cheap.
	CadenceFast CadenceClass = "fast"
	// CadenceNormal marks a module read in every fourth cycle: the state
	// changes on its own, but slowly, and the read starts tools.
	CadenceNormal CadenceClass = "normal"
	// CadenceSlow marks a module read every six hours and at the start of a
	// session: these facts change only when somebody changes the machine.
	CadenceSlow CadenceClass = "slow"
	// CadenceStatic marks a module read once a day, at the full report, or on
	// demand: the state changes only when somebody changes it, and then the
	// change usually comes from the panel and orders its own refresh.
	CadenceStatic CadenceClass = "static"
)

// slowInterval is the pace of the slow class.
const slowInterval = 6 * time.Hour

// moduleCadence assigns every module of ModuleOrder to a class.
var moduleCadence = map[string]CadenceClass{
	ModuleSystem:  CadenceSlow,
	ModuleSudoers: CadenceSlow,

	ModuleServices:   CadenceFast,
	ModuleContainers: CadenceFast,
	ModulePower:      CadenceFast,

	ModulePackages: CadenceNormal,
	ModuleNetwork:  CadenceNormal,
	ModuleDNS:      CadenceNormal,
	ModuleFirewall: CadenceNormal,
	ModuleStorage:  CadenceNormal,
	ModuleSecurity: CadenceNormal,
	ModuleFiles:    CadenceNormal,
	ModuleCerts:    CadenceNormal,
	ModuleTime:     CadenceNormal,

	ModuleIdentity:  CadenceStatic,
	ModuleAccounts:  CadenceStatic,
	ModuleKernel:    CadenceStatic,
	ModuleSchedules: CadenceStatic,
	ModuleSSH:       CadenceStatic,
	ModuleBackups:   CadenceStatic,
}

// ModuleCadence returns the class of a module. A module the table does not
// know is read as static: an unknown module is not a cheap one.
func ModuleCadence(module string) CadenceClass {
	if class, ok := moduleCadence[module]; ok {
		return class
	}
	return CadenceStatic
}

// ModulesOfCadence lists the modules of a class in the collection order.
func ModulesOfCadence(classes ...CadenceClass) []string {
	var modules []string
	for _, name := range ModuleOrder {
		if slices.Contains(classes, ModuleCadence(name)) {
			modules = append(modules, name)
		}
	}
	return modules
}

// The defaults of the periodic cycle. The panel may override them in the
// session configuration; a value of zero there means "the agent's own".
const (
	// defaultNormalEvery says every which cycle the normal modules go.
	defaultNormalEvery = 4
	// cadenceJitter is the spread of one interval around its base: ten per cent
	// either way, so that a fleet started by one reboot does not report in step
	// for the rest of its life.
	cadenceJitter = 0.10
)

// Cadence decides what the periodic inventory cycle collects and when.
type Cadence struct {
	// Interval is the base interval of the cycle; every wait is jittered
	// around it.
	Interval time.Duration
	// NormalEvery says every which cycle the normal modules are read.
	NormalEvery int
	// FullHourUTC is the hour of the daily full report.
	FullHourUTC int

	random   func(n int64) int64
	ticks    int
	lastFull time.Time
	// lastSlow is when the slow modules last went: with the full report
	// that opens the session, with the daily one, or on their own cycle.
	lastSlow time.Time
}

// newCadence builds the cycle of a host. A non-positive interval means the
// default of a quarter of an hour: a cycle of zero would be a busy loop.
func newCadence(interval time.Duration, hostID string) *Cadence {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	return &Cadence{
		Interval:    interval,
		NormalEvery: defaultNormalEvery,
		FullHourUTC: fullReportHour(hostID),
		random:      rand.Int64N,
	}
}

// applyRemote takes the cadence the panel sent in the session configuration.
// A zero field keeps the agent's own value.
func (c *Cadence) applyRemote(intervalSeconds, normalEvery int32, fullHourUTC *int32) {
	if intervalSeconds > 0 {
		c.Interval = time.Duration(intervalSeconds) * time.Second
	}
	if normalEvery > 0 {
		c.NormalEvery = int(normalEvery)
	}
	if fullHourUTC != nil && *fullHourUTC >= 0 && *fullHourUTC < 24 {
		c.FullHourUTC = int(*fullHourUTC)
	}
}

// started records the full report that opens a session.
func (c *Cadence) started(at time.Time) {
	c.lastFull = at
	c.lastSlow = at
}

// next returns how long to wait for the next cycle: the interval spread by
// the jitter either way.
func (c *Cadence) next() time.Duration {
	spread := int64(float64(c.Interval) * cadenceJitter)
	if spread <= 0 {
		return c.Interval
	}
	return c.Interval - time.Duration(spread) + time.Duration(c.random(2*spread+1))
}

// due says what the cycle collects at the given moment. A nil list with full
// set means the whole inventory; otherwise the list names the modules due.
func (c *Cadence) due(at time.Time) (modules []string, full bool) {
	c.ticks++
	if c.fullDue(at) {
		c.lastFull = at
		c.lastSlow = at
		return nil, true
	}
	classes := []CadenceClass{CadenceFast}
	every := c.NormalEvery
	if every <= 0 {
		every = defaultNormalEvery
	}
	if c.ticks%every == 0 {
		classes = append(classes, CadenceNormal)
	}
	// The slow read goes two cycles before the six hours are up rather than the
	// first cycle after: the panel judges a fact older than six hours as stale,
	// and a read landing a jittered cycle late would leave the sudo check unknown
	switch next := c.lastSlow.Add(slowInterval); {
	case c.lastSlow.IsZero():
		c.lastSlow = at
		classes = append(classes, CadenceSlow)
	case !at.Add(2 * c.Interval).Before(next):
		c.lastSlow = next
		if next.Before(at) {
			// A cycle longer than the pace reads the slow modules every
			// time; the mark follows the clock rather than falling behind.
			c.lastSlow = at
		}
		classes = append(classes, CadenceSlow)
	}
	return ModulesOfCadence(classes...), false
}

// fullDue decides the daily full report: the report is due when the most
// recent window of the host has opened and no full report covers it.
func (c *Cadence) fullDue(at time.Time) bool {
	if c.lastFull.IsZero() {
		return true
	}
	window := c.windowStart(at)
	return c.lastFull.Before(window.Add(-c.Interval))
}

// windowStart returns the start of the most recent daily window at or before
// the given moment.
func (c *Cadence) windowStart(at time.Time) time.Time {
	utc := at.UTC()
	start := time.Date(utc.Year(), utc.Month(), utc.Day(), c.FullHourUTC, 0, 0, 0, time.UTC)
	if start.After(utc) {
		start = start.Add(-24 * time.Hour)
	}
	return start
}

// fullReportHour derives the hour of the daily full report from the host
// identifier: a stable spread of the fleet over the day.
func fullReportHour(hostID string) int {
	sum := sha256.Sum256([]byte("inventory-window:" + hostID))
	return int(binary.BigEndian.Uint64(sum[:8]) % 24)
}
