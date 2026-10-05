package release

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The counts and the skips of a run used to be fields of the report, and the
// checker read them. The bundle carries the raw logs they were computed from,
// so it checked that those logs had not been altered - and nothing checked that
// they said what the report said they said. A report claiming 803 passed over a
// log holding a failure was accepted, with every digest correct.
//
// So the numbers are recomputed here, from the bytes, and the report's own are
// compared against them. The laboratory computes the same thing in Python when
// it writes the report; two implementations of one rule, and a disagreement
// between them stops the verdict instead of being averaged out.

// skipSentinel is the one line a skipped scenario has to carry, and the fields
// it carries. The sentinel is a word no message says by accident.
const skipSentinel = "FLOTESTRO-SKIP"

var skipField = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|(\S+))`)

// goEvent is the part of a `go test -json` event this reads.
type goEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

// suiteOutcome is what the logs of a run add up to.
type suiteOutcome struct {
	Counts GateCounts
	Skips  []GateSkip
	// Problems are what the logs say that no count can carry. A verdict is
	// computed from the counts, and the counts are about scenarios - so a
	// package that failed after every one of its tests passed, a test that
	// started and never ended, and a log with nothing in it all left the
	// arithmetic spotless. Each of them is a run that proved less than it
	// says, so each of them ends the verdict.
	Problems []string
}

// countFromLogs recomputes the arithmetic of a run from the logs the bundle
// carries. An absent log contributes nothing: a quick run has no suite log
// because it ran no suite, and that is a verdict matter rather than a malformed
// report.
// named says the report claims a log of the run. An empty file the report names
// is a run that proved nothing, and until the two were told apart the checker
// read a zero-byte log exactly as it reads a quick run that carries none.
func countFromLogs(goTestJSON, playwrightJSON []byte, named bool) (suiteOutcome, error) {
	outcome := suiteOutcome{}
	if len(goTestJSON) > 0 {
		if err := outcome.addGoSuite(goTestJSON); err != nil {
			return suiteOutcome{}, err
		}
	}
	if len(playwrightJSON) > 0 {
		if err := outcome.addPlaywright(playwrightJSON); err != nil {
			return suiteOutcome{}, err
		}
	}
	if named && outcome.Counts.Discovered == 0 {
		outcome.Problems = append(outcome.Problems,
			"the logs of the run name no scenario at all")
	}
	for _, skip := range outcome.Skips {
		switch skip.Class {
		case SkipAbsent:
			outcome.Counts.Absent++
		case SkipNotApplicable:
			outcome.Counts.NotApplicable++
		case SkipWaived:
			outcome.Counts.Waived++
		}
	}
	return outcome, nil
}

// addGoSuite reads the events of `go test -json`.
func (o *suiteOutcome) addGoSuite(raw []byte) error {
	type key struct{ pkg, test string }
	output := map[key][]string{}
	final := map[key]string{}

	started := map[key]bool{}
	startedPackages := map[string]bool{}
	endedPackages := map[string]bool{}
	var packageFailures []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var event goEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			// A line that is not an event is not a scenario; the laboratory
			// skips it too rather than refusing the whole log.
			continue
		}
		if event.Test == "" {
			switch event.Action {
			case "start":
				startedPackages[event.Package] = true
			case "pass", "fail", "skip":
				endedPackages[event.Package] = true
			}
			// A package-level verdict. "skip" there only means the package
			// holds no test files, which is nothing anybody was owed - but
			// "fail" is the package itself failing after its tests are done:
			// a panic in TestMain, a cleanup that exits non-zero, a data race
			// the runner reports against the package. Every test passes and
			// `go test` exits 1, and counting scenarios alone never sees it.
			if event.Action == "fail" {
				packageFailures = append(packageFailures, event.Package)
			}
			continue
		}
		at := key{event.Package, event.Test}
		switch event.Action {
		case "run":
			started[at] = true
		case "output":
			output[at] = append(output[at], event.Output)
		case "pass", "fail", "skip":
			final[at] = event.Action
		}
	}

	// A package that started and never reached a verdict is a process that was
	// killed: the runner reports nothing for it, and every test it had already
	// finished still counts. On 05.10 a real run interrupted after a passing
	// test came out of the arithmetic clean.
	var unfinishedPackages []string
	for name := range startedPackages {
		if !endedPackages[name] {
			unfinishedPackages = append(unfinishedPackages, name)
		}
	}
	sort.Strings(unfinishedPackages)
	for _, name := range unfinishedPackages {
		o.Problems = append(o.Problems,
			fmt.Sprintf("the package %s started and never reached a verdict", name))
	}

	sort.Strings(packageFailures)
	for _, name := range packageFailures {
		o.Problems = append(o.Problems,
			fmt.Sprintf("the package %s failed, after its tests were done", name))
	}
	// A scenario that started and never ended is a suite that was cut off -
	// by a timeout, a signal, a machine that went away. The counts are of what
	// finished, so they come out of such a run looking complete.
	var unfinished []string
	for at := range started {
		if _, ended := final[at]; !ended {
			name := at.test
			if at.pkg != "" {
				name = at.pkg + "." + at.test
			}
			unfinished = append(unfinished, name)
		}
	}
	sort.Strings(unfinished)
	for _, name := range unfinished {
		o.Problems = append(o.Problems, fmt.Sprintf("%s started and never ended", name))
	}

	// A parent whose subtests all skipped is reported skipped too. The subtests
	// are the scenarios; the parent is a container and is not counted twice.
	skipped := map[key]bool{}
	for at, action := range final {
		if action == "skip" {
			skipped[at] = true
		}
	}
	container := map[key]bool{}
	for at := range skipped {
		for other := range skipped {
			if other.pkg == at.pkg && strings.HasPrefix(other.test, at.test+"/") {
				container[at] = true
				break
			}
		}
	}

	ordered := make([]key, 0, len(final))
	for at := range final {
		ordered = append(ordered, at)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].pkg != ordered[j].pkg {
			return ordered[i].pkg < ordered[j].pkg
		}
		return ordered[i].test < ordered[j].test
	})

	for _, at := range ordered {
		if container[at] {
			continue
		}
		o.Counts.Discovered++
		switch final[at] {
		case "pass":
			o.Counts.Passed++
			continue
		case "fail":
			o.Counts.Failed++
			continue
		}
		o.Counts.Skipped++
		name := at.test
		if at.pkg != "" {
			name = at.pkg + "." + at.test
		}
		o.Skips = append(o.Skips, skipOf(name, "go", strings.Join(output[at], "")))
	}
	return nil
}

// playwrightReport is the part of Playwright's JSON report this reads.
type playwrightReport struct {
	Suites []playwrightSuite `json:"suites"`
	// Errors are the failures that belong to no test: a globalSetup or
	// globalTeardown that threw, a configuration the runner refused. The run
	// exits 1 and every spec in it may still read "expected", so counting
	// specs alone comes out clean - which is what a real teardown failure did
	// on 05.10.
	Errors []struct {
		Message  string `json:"message"`
		Value    string `json:"value"`
		Location struct {
			File string `json:"file"`
		} `json:"location"`
	} `json:"errors"`
}

type playwrightSuite struct {
	Title  string            `json:"title"`
	Suites []playwrightSuite `json:"suites"`
	Specs  []playwrightSpec  `json:"specs"`
}

type playwrightSpec struct {
	Title string `json:"title"`
	Tests []struct {
		Status      string `json:"status"`
		Annotations []struct {
			Description string `json:"description"`
		} `json:"annotations"`
	} `json:"tests"`
}

// addPlaywright reads the browser suite the same way.
func (o *suiteOutcome) addPlaywright(raw []byte) error {
	// The runner prints before the document; the laboratory starts at the first
	// brace and so does this.
	at := strings.Index(string(raw), "{")
	if at < 0 {
		return fmt.Errorf("the playwright log carries no report")
	}
	var report playwrightReport
	if err := json.Unmarshal(raw[at:], &report); err != nil {
		return fmt.Errorf("the playwright log is not a report: %w", err)
	}
	for _, suite := range report.Suites {
		o.walkPlaywright(suite, []string{suite.Title})
	}
	for _, failure := range report.Errors {
		where := failure.Location.File
		if where == "" {
			where = "the run itself"
		}
		o.Problems = append(o.Problems,
			fmt.Sprintf("the browser suite failed outside any test, in %s", where))
	}
	return nil
}

func (o *suiteOutcome) walkPlaywright(node playwrightSuite, trail []string) {
	for _, child := range node.Suites {
		o.walkPlaywright(child, append(append([]string{}, trail...), child.Title))
	}
	for _, spec := range node.Specs {
		parts := make([]string, 0, len(trail)+1)
		for _, part := range trail {
			if part != "" {
				parts = append(parts, part)
			}
		}
		parts = append(parts, spec.Title)
		name := strings.Join(parts, " > ")
		for _, test := range spec.Tests {
			o.Counts.Discovered++
			switch test.Status {
			case "skipped":
				o.Counts.Skipped++
				notes := make([]string, 0, len(test.Annotations))
				for _, annotation := range test.Annotations {
					notes = append(notes, annotation.Description)
				}
				o.Skips = append(o.Skips, skipOf(name, "playwright", strings.Join(notes, " ")))
			case "expected":
				o.Counts.Passed++
			default:
				o.Counts.Failed++
			}
		}
	}
}

// skipOf reads the classification a skipped scenario carries, or records that
// it carried none - which is itself a failure of the run, decided by the
// verdict rather than here.
func skipOf(name, suite, text string) GateSkip {
	skip := GateSkip{Test: name, Suite: suite}
	at := strings.Index(text, skipSentinel)
	if at < 0 {
		skip.Reason = trimReason(text)
		if skip.Reason == "" {
			skip.Reason = "(the test gave no reason)"
		}
		return skip
	}
	line := text[at+len(skipSentinel):]
	if end := strings.Index(line, "\n"); end >= 0 {
		line = line[:end]
	}
	for _, match := range skipField.FindAllStringSubmatch(line, -1) {
		value := match[2]
		if value == "" {
			value = match[3]
		}
		switch match[1] {
		case "class":
			skip.Class = value
		case "reason":
			skip.Reason = value
		case "runs_on":
			skip.RunsOn = value
		case "waiver":
			skip.Waiver = value
		case "until":
			skip.Until = value
		case "evidence":
			skip.Evidence = value
		}
	}
	return skip
}

// trimReason keeps a reason to the length the report carries it at.
func trimReason(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 400 {
		text = text[:400]
	}
	return text
}

// disagreement names where a report and the logs it travels with differ. The
// fields are named rather than the numbers dumped: the first question anybody
// asks is which number moved.
func (r GateReport) disagreement(computed suiteOutcome) []string {
	var differs []string
	claimed := GateCounts{}
	if r.Counts != nil {
		claimed = *r.Counts
	}
	for _, field := range []struct {
		name            string
		claimed, actual int
	}{
		{"discovered", claimed.Discovered, computed.Counts.Discovered},
		{"passed", claimed.Passed, computed.Counts.Passed},
		{"failed", claimed.Failed, computed.Counts.Failed},
		{"skipped", claimed.Skipped, computed.Counts.Skipped},
		{"absent", claimed.Absent, computed.Counts.Absent},
		{"not_applicable", claimed.NotApplicable, computed.Counts.NotApplicable},
		{"waived", claimed.Waived, computed.Counts.Waived},
	} {
		if field.claimed != field.actual {
			differs = append(differs, fmt.Sprintf("%s: the report says %d, the logs hold %d",
				field.name, field.claimed, field.actual))
		}
	}

	// The skips by name and class. A report that drops a skip from the list
	// keeps the count honest and loses the scenario, which is the same trick
	// one level down.
	claimedSkips := map[string]string{}
	for _, skip := range r.Skips {
		claimedSkips[skip.Suite+"/"+skip.Test] = skip.Class
	}
	for _, skip := range computed.Skips {
		at := skip.Suite + "/" + skip.Test
		class, listed := claimedSkips[at]
		if !listed {
			differs = append(differs, fmt.Sprintf("the logs hold a skipped %s the report does not list", at))
			continue
		}
		if class != skip.Class {
			differs = append(differs, fmt.Sprintf("%s is %q in the report and %q in the log",
				at, class, skip.Class))
		}
		delete(claimedSkips, at)
	}
	names := make([]string, 0, len(claimedSkips))
	for at := range claimedSkips {
		names = append(names, at)
	}
	sort.Strings(names)
	for _, at := range names {
		differs = append(differs, fmt.Sprintf("the report lists %s as skipped and no log says so", at))
	}
	return differs
}
