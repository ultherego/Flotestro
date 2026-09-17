package plan

import (
	"fmt"
	"sort"
	"strings"
)

// The kinds of an effect a package plan promises.
const (
	// EffectPackageVersion: the subject is installed at the value.
	EffectPackageVersion = "package_version"
	// EffectPackageAbsent: the subject is not installed.
	EffectPackageAbsent = "package_absent"
)

// Outcome is the settlement of one expected effect once the change ran:
// achieved or not, with what was observed instead. A partial result lists
// every outcome, so the operator sees what the host reached and what it
// did not rather than one word for the whole transaction.
type Outcome struct {
	Effect   Effect `json:"effect"`
	Achieved bool   `json:"achieved"`
	// Observed is the value found on the host: the installed version, or
	// "absent" for a package that is not there.
	Observed string `json:"observed"`
}

// Settle reads every expected effect off the installed state - package
// name to installed version, a package not in the map is absent - and
// returns the outcomes achieved and the outcomes missed, each sorted by
// subject.
func (e Effects) Settle(installed map[string]string) (achieved, missed []Outcome) {
	for _, effect := range e.Expected {
		version, present := installed[effect.Subject]
		observed := version
		if !present {
			observed = "absent"
		}
		ok := false
		switch effect.Kind {
		case EffectPackageVersion:
			ok = present && version == effect.Value
		case EffectPackageAbsent:
			ok = !present
		}
		outcome := Outcome{Effect: effect, Achieved: ok, Observed: observed}
		if ok {
			achieved = append(achieved, outcome)
		} else {
			missed = append(missed, outcome)
		}
	}
	sort.Slice(achieved, func(i, j int) bool { return lessEffect(achieved[i].Effect, achieved[j].Effect) })
	sort.Slice(missed, func(i, j int) bool { return lessEffect(missed[i].Effect, missed[j].Effect) })
	return achieved, missed
}

// Partial turns the missed outcomes into the typed error of a partial
// result, or nil when nothing was missed. The message names the subjects
// so the job says which effects the host did not reach.
func Partial(missed []Outcome) error {
	if len(missed) == 0 {
		return nil
	}
	names := make([]string, 0, len(missed))
	for _, outcome := range missed {
		expected := outcome.Effect.Value
		if outcome.Effect.Kind == EffectPackageAbsent {
			expected = "absent"
		}
		names = append(names, fmt.Sprintf("%s (expected %s, found %s)",
			outcome.Effect.Subject, expected, outcome.Observed))
	}
	return fmt.Errorf("%w: %s", ErrEffectsPartial, strings.Join(names, ", "))
}
