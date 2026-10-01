package release

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// GateSchemaVersion is the shape of the laboratory's result.json this code
// reads. A report that declares another number is refused, not guessed at.
const GateSchemaVersion = 1

// The three verdicts a gate run may reach. A stable release accepts only
// VerdictPass; VerdictLimited says the run was green over limitations somebody
// approved by name.
const (
	VerdictPass    = "pass"
	VerdictLimited = "limited"
	VerdictFail    = "fail"
)

// How a skipped scenario has to account for itself.
const (
	// SkipAbsent: the test should have run and the laboratory did not prepare
	// the condition. In a full gate this is a failure, not an exemption.
	SkipAbsent = "absent"
	// SkipNotApplicable: the scenario does not apply to this host but runs on
	// another host of the matrix, which RunsOn has to name.
	SkipNotApplicable = "not_applicable"
	// SkipWaived: a named, time-limited limitation with substitute evidence.
	SkipWaived = "waived"
)

var (
	gateSHA      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	gateTreeHash = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
	gateDay      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// GateStage is one step of the run and how long it took.
type GateStage struct {
	Result  string  `json:"result"`
	Seconds float64 `json:"seconds"`
}

// GateHost is a machine the suite ran against, named as it names itself.
type GateHost struct {
	Name         string `json:"name"`
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
}

// GateAgent is the agent on one host, before the run installed anything and
// after it did: a suite that exercised yesterday's binary proves nothing about
// the commit it is attesting.
type GateAgent struct {
	Host   string `json:"host"`
	Before string `json:"version_before"`
	After  string `json:"version_after"`
}

// GateCounts is the arithmetic of the run. It is checked against the list of
// skips rather than believed.
type GateCounts struct {
	Discovered    int `json:"discovered"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Skipped       int `json:"skipped"`
	Absent        int `json:"absent"`
	NotApplicable int `json:"not_applicable"`
	Waived        int `json:"waived"`
}

// GateSkip is one scenario that did not run, and its account of itself.
type GateSkip struct {
	Test   string `json:"test"`
	Suite  string `json:"suite"`
	Class  string `json:"class"`
	Reason string `json:"reason"`
	// RunsOn names the host of the matrix that does execute this scenario;
	// required of not_applicable, so a scenario cannot vanish from the run.
	RunsOn string `json:"runs_on,omitempty"`
	// The three fields a waiver has to carry to be one.
	Waiver   string `json:"waiver,omitempty"`
	Until    string `json:"until,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// GateReport is the laboratory's result.json.
//
// Every field the verdict rests on is a pointer or a slice, so that a report
// which is silent about it is refused rather than read as the safe answer. The
// bug this schema exists to kill is exactly that: a missing "quick" meaning
// "not a quick run".
type GateReport struct {
	SchemaVersion   *int                 `json:"schema_version"`
	SHA             string               `json:"sha"`
	TreeHash        string               `json:"tree_hash"`
	TreeClean       *bool                `json:"tree_clean"`
	Quick           *bool                `json:"quick"`
	HarnessDigest   string               `json:"harness_digest"`
	LabConfigDigest string               `json:"lab_config_digest"`
	StartedAt       string               `json:"started_at"`
	FinishedAt      string               `json:"finished_at"`
	Commands        []string             `json:"commands"`
	Hosts           []GateHost           `json:"hosts"`
	Agents          []GateAgent          `json:"agents"`
	Stages          map[string]GateStage `json:"stages"`
	Counts          *GateCounts          `json:"counts"`
	Skips           []GateSkip           `json:"skips"`
	Logs            map[string]string    `json:"logs"`
	Artifacts       map[string]string    `json:"artifacts"`
	Verdict         string               `json:"verdict"`
}

// The keys a report has to carry as keys. Presence is checked before the
// values are read, because a field that is absent and a field that is empty
// are different mistakes and only one of them has an innocent explanation.
var gateRequiredKeys = []string{
	"schema_version", "sha", "tree_hash", "tree_clean", "quick",
	"harness_digest", "lab_config_digest", "started_at", "finished_at",
	"commands", "hosts", "agents", "stages", "counts", "skips", "logs",
	"verdict",
}

// ParseGateReport reads a report and refuses one it cannot vouch for. It says
// nothing about the verdict: that is recomputed, by ComputeVerdict, from the evidence
// the report carries.
func ParseGateReport(data []byte) (GateReport, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return GateReport{}, fmt.Errorf("the gate report is not a JSON object: %w", err)
	}
	var missing []string
	for _, key := range gateRequiredKeys {
		if _, present := keys[key]; !present {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return GateReport{}, fmt.Errorf(
			"the gate report says nothing about %s; an absent field is not an answer",
			strings.Join(missing, ", "))
	}

	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var report GateReport
	if err := decoder.Decode(&report); err != nil {
		return GateReport{}, fmt.Errorf("the gate report does not have the shape of one: %w", err)
	}
	if err := report.validate(); err != nil {
		return GateReport{}, err
	}
	return report, nil
}

// stageIntegration is the stage that runs the Go suite; its presence is what
// tells a report that reached the suite from one that stopped before it.
const stageIntegration = "integration"

// fullRunStages are the stages a run that calls itself complete has to account
// for. A verdict is computed over the stages a report names, so a report that
// simply leaves one out would be judged on the rest: the missing stage has to
// be fatal, or omitting it is the way past the gate.
var fullRunStages = []string{
	"tree", "gofmt", "panel", "web", "vitest",
	// fleet proves the deployment the agents stage reports rather than assuming
	// it. On 30.09 every host agreed it ran 0.62.0 while one of them ran a build
	// from four days earlier, published under the same version: a deployment
	// nobody verified is a suite judging code the gate was not given.
	"agents", "fleet", "relay",
	// identity asks each level of the laboratory which commit it is, before
	// anything is measured on it. Three failures in one day had the same shape:
	// the suite talked to something that was not the commit being gated and
	// every stage stayed green - a panel on the right port but from an older
	// deployment, a database belonging to a second installation, a relay from
	// another day that answered and was registered. A report without this stage
	// is a report that never established what it tested.
	"identity",
	"fixtures", "preflight", stageIntegration, "playwright",
}

func (r GateReport) validate() error {
	if *r.SchemaVersion != GateSchemaVersion {
		return fmt.Errorf("the gate report declares schema_version %d; this checker reads %d",
			*r.SchemaVersion, GateSchemaVersion)
	}
	if !gateSHA.MatchString(r.SHA) {
		return fmt.Errorf("the gate report names the commit %q; it has to be forty hex digits", r.SHA)
	}
	if !gateTreeHash.MatchString(r.TreeHash) {
		return fmt.Errorf("the tree hash %q is not one", r.TreeHash)
	}
	for name, value := range map[string]string{
		"harness_digest":    r.HarnessDigest,
		"lab_config_digest": r.LabConfigDigest,
	} {
		if !digest.MatchString(value) {
			return fmt.Errorf("%s is %q; it has to be sha256 and sixty-four hex digits", name, value)
		}
	}
	started, err := gateTime("started_at", r.StartedAt)
	if err != nil {
		return err
	}
	finished, err := gateTime("finished_at", r.FinishedAt)
	if err != nil {
		return err
	}
	if finished.Before(started) {
		return fmt.Errorf("the gate report finishes at %s, before it started at %s", r.FinishedAt, r.StartedAt)
	}
	if len(r.Commands) == 0 {
		return fmt.Errorf("the gate report names no command it ran")
	}
	if len(r.Stages) == 0 {
		return fmt.Errorf("the gate report names no stage")
	}
	for name, stage := range r.Stages {
		switch stage.Result {
		case "pass", "fail":
		default:
			return fmt.Errorf("the stage %s reports %q, which is neither pass nor fail", name, stage.Result)
		}
	}
	// A run that never reached the suite has no log of one. That is not a
	// malformed report - a stage before it failed, and the verdict says so.
	_, ranTheSuite := r.Stages[stageIntegration]
	quick := r.Quick == nil || *r.Quick
	if _, named := r.Logs["go_test_json"]; !named && ranTheSuite && !quick {
		return fmt.Errorf("the gate report carries no digest of the raw go test -json log")
	}
	for name, value := range r.Logs {
		if !digest.MatchString(value) {
			return fmt.Errorf("the digest of the %s log is %q; it has to be sha256 and sixty-four hex digits", name, value)
		}
	}
	for name, value := range r.Artifacts {
		if !digest.MatchString(value) {
			return fmt.Errorf("the digest of the artefact %s is %q; it has to be sha256 and sixty-four hex digits", name, value)
		}
	}
	for _, host := range r.Hosts {
		if host.Name == "" || host.Distribution == "" || host.Version == "" {
			return fmt.Errorf("the host %q is reported without its distribution and version", host.Name)
		}
	}
	for _, agent := range r.Agents {
		if agent.Host == "" || agent.Before == "" || agent.After == "" {
			return fmt.Errorf("the agent on %q is reported without both its versions", agent.Host)
		}
	}
	if r.Counts == nil {
		return fmt.Errorf("the gate report carries no counts")
	}
	switch r.Verdict {
	case VerdictPass, VerdictLimited, VerdictFail:
	default:
		return fmt.Errorf("the gate report reaches the verdict %q, which is not one of pass, limited, fail", r.Verdict)
	}
	return nil
}

func gateTime(field, value string) (time.Time, error) {
	// RFC 3339 carries the offset. A naive timestamp is refused here rather
	// than read in whatever zone the reader happens to sit in.
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s is %q, not a timestamp with a timezone: %w", field, value, err)
	}
	return parsed, nil
}

// ComputeVerdict recomputes the verdict from the evidence and returns it with the
// reasons it is not a pass. The report's own verdict is not consulted: a field
// a human could set is the mechanism this exists to replace.
func (r GateReport) ComputeVerdict() (string, []string) {
	var fatal, limits []string

	if r.Quick == nil || *r.Quick {
		fatal = append(fatal, "the run was a quick one: it executes neither the fleet nor the screenshots")
	}
	if r.TreeClean == nil || !*r.TreeClean {
		fatal = append(fatal, "the tree was not clean, so the run is not about this commit")
	}

	names := make([]string, 0, len(r.Stages))
	for name := range r.Stages {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if r.Stages[name].Result != "pass" {
			fatal = append(fatal, fmt.Sprintf("the stage %s did not pass", name))
		}
	}
	for _, name := range fullRunStages {
		if _, ran := r.Stages[name]; !ran {
			fatal = append(fatal, fmt.Sprintf("the run never reached the stage %s", name))
		}
	}

	hosts := make(map[string]bool, len(r.Hosts))
	for _, host := range r.Hosts {
		hosts[host.Name] = true
	}
	// The clock a waiver expires against is the run's own end: a report is
	// judged by when it was produced, not by when somebody reads it.
	finished, err := time.Parse(time.RFC3339, r.FinishedAt)
	if err != nil {
		fatal = append(fatal, "the run has no usable finishing time")
	}

	var absent, notApplicable, waived int
	for _, skip := range r.Skips {
		name := skip.Test
		if name == "" {
			name = "(an unnamed test)"
		}
		switch skip.Class {
		case SkipAbsent:
			absent++
			fatal = append(fatal, fmt.Sprintf("%s did not run: %s", name, skip.Reason))
		case SkipNotApplicable:
			notApplicable++
			if skip.RunsOn == "" {
				fatal = append(fatal, fmt.Sprintf("%s is not_applicable here and names no host that does run it", name))
				break
			}
			if len(hosts) > 0 && !hosts[skip.RunsOn] {
				fatal = append(fatal, fmt.Sprintf("%s says it runs on %s, which is not a host of this run", name, skip.RunsOn))
			}
		case SkipWaived:
			waived++
			switch {
			case skip.Waiver == "" || skip.Evidence == "":
				fatal = append(fatal, fmt.Sprintf("the waiver of %s has no name or no substitute evidence", name))
			case !gateDay.MatchString(skip.Until):
				fatal = append(fatal, fmt.Sprintf("the waiver %s of %s has no expiry date", skip.Waiver, name))
			default:
				expiry, parseErr := time.Parse("2006-01-02", skip.Until)
				if parseErr == nil && err == nil && finished.After(expiry.AddDate(0, 0, 1)) {
					fatal = append(fatal, fmt.Sprintf("the waiver %s of %s expired on %s", skip.Waiver, name, skip.Until))
					break
				}
				limits = append(limits, fmt.Sprintf("%s is waived until %s by %s", name, skip.Until, skip.Waiver))
			}
		default:
			fatal = append(fatal, fmt.Sprintf("%s was skipped without saying which kind of skip it is", name))
		}
	}

	if r.Counts != nil {
		counts := *r.Counts
		if counts.Skipped != len(r.Skips) {
			fatal = append(fatal, fmt.Sprintf("the report counts %d skips and names %d", counts.Skipped, len(r.Skips)))
		}
		if counts.Absent != absent || counts.NotApplicable != notApplicable || counts.Waived != waived {
			fatal = append(fatal, "the counts of the skips do not match the skips themselves")
		}
		// A count below zero is not a quantity of tests, and every comparison
		// under it reads the wrong way round: "failed > 0" lets a negative
		// through, and so does a discovered count that only has to differ from
		// zero. A report that says it ran -99 failures is not a green run that
		// happens to be odd - it is a report that cannot be believed at all.
		negative := ""
		for _, count := range []struct {
			name  string
			value int
		}{
			{"discovered", counts.Discovered}, {"passed", counts.Passed},
			{"failed", counts.Failed}, {"skipped", counts.Skipped},
			{"absent", counts.Absent}, {"not applicable", counts.NotApplicable},
			{"waived", counts.Waived},
		} {
			if count.value < 0 {
				negative = count.name
				break
			}
		}
		if negative != "" {
			fatal = append(fatal, fmt.Sprintf("the report counts a negative number of %s tests", negative))
		}
		// And the three outcomes are a partition of what was discovered: every
		// test the run found ended passed, failed or skipped. Without this the
		// numbers can be made to say anything - discovered 310 over one pass
		// and ninety-nine failures that are carried as a negative.
		if counts.Passed+counts.Failed+counts.Skipped != counts.Discovered {
			fatal = append(fatal, fmt.Sprintf(
				"the report discovered %d tests and accounts for %d of them",
				counts.Discovered, counts.Passed+counts.Failed+counts.Skipped))
		}
		if counts.Failed != 0 {
			fatal = append(fatal, fmt.Sprintf("%d tests failed", counts.Failed))
		}
		if counts.Discovered == 0 || counts.Passed == 0 {
			fatal = append(fatal, "the report discovered nothing, which is not a green run")
		}
	}

	if len(fatal) > 0 {
		return VerdictFail, fatal
	}
	if len(limits) > 0 {
		return VerdictLimited, limits
	}
	return VerdictPass, nil
}

// CheckGateReport is what a workflow calls: it parses the report, insists it is
// about the commit being attested, recomputes the verdict and refuses a report
// whose own verdict disagrees with the evidence in it.
func CheckGateReport(data []byte, sha string) (GateReport, string, []string, error) {
	report, err := ParseGateReport(data)
	if err != nil {
		return GateReport{}, "", nil, err
	}
	if sha != "" && !strings.EqualFold(report.SHA, sha) {
		return report, "", nil, fmt.Errorf(
			"the gate ran on %s and this attests %s; they have to be the same commit", report.SHA, sha)
	}
	verdict, reasons := report.ComputeVerdict()
	if report.Verdict != verdict {
		return report, verdict, reasons, fmt.Errorf(
			"the report claims the verdict %q; the evidence in it says %q", report.Verdict, verdict)
	}
	return report, verdict, reasons, nil
}

// Summary is the one line a commit status carries. It begins with the verdict
// in a fixed form, because the release workflow reads it to tell a pass from a
// run that was green over approved limitations.
func (r GateReport) Summary(verdict string) string {
	counts := GateCounts{}
	if r.Counts != nil {
		counts = *r.Counts
	}
	line := fmt.Sprintf("verdict=%s %d tests, %d failed, %d skipped (%d waived) on %s",
		verdict, counts.Discovered, counts.Failed, counts.Skipped, counts.Waived, r.SHA[:12])
	if len(line) > 120 {
		line = line[:120]
	}
	return line
}
