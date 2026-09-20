package packages

import (
	"context"
	"strings"
	"time"
)

// The kinds of block. They are read apart because only the first is a fault
// of the host that a repair fixes.
const (
	// BlockedDatabase: the package database needs repairing before any
	// package operation runs.
	BlockedDatabase = "database"
	// BlockedAdvisory: the update is left out of a security plan because no
	// advisory of the host says whether it closes a vulnerability.
	BlockedAdvisory = "advisory"
)

// Blocked describes a package that blocks package operations.
type Blocked struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	// Kind is empty on an agent older than the field, and empty means
	// BlockedDatabase: that is what every block meant before it.
	Kind      string     `json:"kind,omitempty"`
	Questions []Question `json:"questions,omitempty"`
}

// Question is a configuration question of a package.
type Question struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Answered is undetermined when the state of the question could not be
	// read.
	Answered *bool `json:"answered,omitempty"`
}

// Answer is the answer of the operator to a configuration question.
type Answer struct {
	Package  string
	Question string
	Type     string
	Value    string
}

// BlockedPackages describes the packages that block a transaction, together
// with the configuration questions without an answer.
func (a *APT) BlockedPackages(ctx context.Context) []Blocked {
	blocked := a.blockedFromStatus()
	for index := range blocked {
		// Only root reads the configuration questions: the debconf database is not
		// readable by the agent.
		blocked[index].Questions = a.questions(ctx, blocked[index].Name)
	}
	return blocked
}

// questions reads the configuration questions of a package.
func (a *APT) questions(ctx context.Context, pkg string) []Question {
	result := run(ctx, 30*time.Second, debconfShowPath, pkg)
	if !result.Ran || result.ExitCode != 0 {
		return nil
	}
	var questions []Question
	for _, line := range strings.Split(result.Stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		answered := strings.HasPrefix(trimmed, "*")
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "*"))
		name, value, _ := strings.Cut(trimmed, ":")
		state := answered
		questions = append(questions, Question{
			Name:     strings.TrimSpace(name),
			Value:    strings.TrimSpace(value),
			Answered: &state,
		})
	}
	return questions
}

// Repair sets the answers of the operator and finishes the configuration of
// the packages.
func (a *APT) Repair(ctx context.Context, answers []Answer) ([]string, []Blocked, error) {
	blocking := map[string]bool{}
	for _, pkg := range a.PackagesNeedingAttention(ctx) {
		blocking[pkg] = true
	}

	var set_ []string
	var lines []string
	for _, answer := range answers {
		// An answer for a package that blocks nothing is skipped rather than
		// rejected: the host may have been repaired in the meantime, and a campaign
		// repeating the same repair must not fail because of that.
		if !blocking[answer.Package] {
			continue
		}
		if strings.ContainsAny(answer.Question+answer.Type+answer.Value, "\n\r") {
			return nil, nil, ErrInvalidAnswer
		}
		lines = append(lines, strings.Join(
			[]string{answer.Package, answer.Question, answer.Type, answer.Value}, " "))
		// The name of the question already carries the package, so gluing them
		// together gave a label of the sort grub-pc/grub-pc/install_devices.
		set_ = append(set_, answer.Question)
	}

	if len(lines) > 0 {
		result := runWithInput(ctx, time.Minute, strings.Join(lines, "\n")+"\n", debconfSetPath)
		if !result.Ran || result.ExitCode != 0 {
			return nil, nil, errorf("debconf-set-selections: %s", result.Reason())
		}
	}

	// Finishing the configuration is the only change of state here: we neither
	// install nor remove anything.
	result := run(ctx, 15*time.Minute, dpkgPath, "--configure", "-a")
	remaining := a.BlockedPackages(ctx)
	if !result.Ran || result.ExitCode != 0 {
		return set_, remaining, errorf("dpkg --configure -a: %s", result.Reason())
	}
	return set_, remaining, nil
}
