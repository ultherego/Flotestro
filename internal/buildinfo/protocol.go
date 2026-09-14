package buildinfo

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrProtocolIncompatible means an agent version whose protocol this panel
// does not speak. Ordering it would replace a working agent with one the
// panel cannot talk to - the host would come back and stay unmanaged.
var ErrProtocolIncompatible = errors.New("protocol_incompatible")

// protocolStep says from which release the agent speaks a given protocol.
type protocolStep struct {
	Since    string
	Protocol int
}

// protocolByVersion is the table of protocol changes by release, oldest
// first. A release between two steps speaks the protocol of the earlier
// one; a release newer than the last step speaks the newest known protocol.
//
// The table grows with every incompatible change of the contract: the step
// that bumps AgentProtocol adds its release here, so an older panel refuses
// to order that release before the host is cut off.
var protocolByVersion = []protocolStep{
	{Since: "0.1.0", Protocol: 1},
}

// MinimumProtocol returns the protocol an agent of the given version speaks.
func MinimumProtocol(version string) (int, error) {
	return minimumProtocol(protocolByVersion, version)
}

func minimumProtocol(table []protocolStep, version string) (int, error) {
	target, err := parseVersion(version)
	if err != nil {
		return 0, err
	}
	protocol := 0
	for _, step := range table {
		since, err := parseVersion(step.Since)
		if err != nil {
			return 0, fmt.Errorf("the protocol table names %q, which is not a version", step.Since)
		}
		if compareVersions(target, since) >= 0 {
			protocol = step.Protocol
		}
	}
	if protocol == 0 {
		return 0, fmt.Errorf("the version %s is older than any release with a known protocol", version)
	}
	return protocol, nil
}

// CheckProtocol says whether this binary can talk to an agent of the given
// version: the protocol that version speaks must not be newer than
// AgentProtocol. An older protocol is fine - the panel keeps speaking the
// older ones - a newer one is not.
func CheckProtocol(version string) error {
	return checkProtocol(protocolByVersion, AgentProtocol, version)
}

func checkProtocol(table []protocolStep, supported int, version string) error {
	required, err := minimumProtocol(table, version)
	if err != nil {
		return err
	}
	if required > supported {
		return fmt.Errorf("%w: the agent %s speaks protocol %d, this panel speaks up to %d",
			ErrProtocolIncompatible, version, required, supported)
	}
	return nil
}

// CheckProtocolRange says whether this binary can talk to an agent that
// announced the protocols it speaks, from min to max.
//
// The announcement is preferred over the table: it is what the agent
// knows about itself, and it holds for a release the table has not heard
// of yet. The sides can talk when the ranges overlap - the agent's oldest
// is not newer than what the panel speaks, and its newest is not older
// than what the panel still accepts. An agent that announced nothing (a
// max of zero) is judged by its version and the table, as before the
// range existed.
func CheckProtocolRange(version string, min, max int) error {
	return checkProtocolRange(protocolByVersion, AgentProtocolMin, AgentProtocol, version, min, max)
}

func checkProtocolRange(table []protocolStep, supportedMin, supportedMax int,
	version string, min, max int) error {
	if max == 0 {
		return checkProtocol(table, supportedMax, version)
	}
	if min < 1 || min > max {
		return fmt.Errorf("%w: the agent %s announces the protocols %d to %d, which is not a range",
			ErrProtocolIncompatible, version, min, max)
	}
	if min > supportedMax || max < supportedMin {
		return fmt.Errorf("%w: the agent %s speaks protocols %d to %d, this panel speaks %d to %d",
			ErrProtocolIncompatible, version, min, max, supportedMin, supportedMax)
	}
	return nil
}

// parseVersion reads the numeric part of a release version: the dotted
// numbers before any suffix. "0.41.0-1" and "0.41.0~beta2" are both 0.41.0
// for the protocol: the suffix is the package build, not the contract.
func parseVersion(version string) ([]int, error) {
	core := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if at := strings.IndexAny(core, "-+~:_"); at >= 0 {
		core = core[:at]
	}
	if core == "" {
		return nil, fmt.Errorf("%q is not a version", version)
	}
	parts := strings.Split(core, ".")
	numbers := make([]int, 0, len(parts))
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return nil, fmt.Errorf("%q is not a version", version)
		}
		numbers = append(numbers, number)
	}
	return numbers, nil
}

// compareVersions orders two parsed versions; a missing component counts as
// zero, so 0.41 and 0.41.0 are the same release.
func compareVersions(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var left, right int
		if i < len(a) {
			left = a[i]
		}
		if i < len(b) {
			right = b[i]
		}
		switch {
		case left < right:
			return -1
		case left > right:
			return 1
		}
	}
	return 0
}

// hashSchemeByVersion says from which release the agent verifies a given
// plan hash scheme, oldest first. The scheme is not the protocol: an agent
// that speaks the protocol of a task still refuses it when it cannot
// recompute the hash the panel put on it, so the panel hashes for the
// agent it is talking to.
var hashSchemeByVersion = []protocolStep{
	{Since: "0.1.0", Protocol: 1},
	{Since: "0.43.0", Protocol: 2},
}

// PayloadHashSchemeFor returns the newest plan hash scheme an agent of the
// given version verifies. A version that cannot be read gets the oldest
// scheme: every agent verifies that one, and refusing to dispatch over a
// version string would cut the host off for a spelling.
func PayloadHashSchemeFor(version string) int {
	scheme, err := minimumProtocol(hashSchemeByVersion, version)
	if err != nil {
		return 1
	}
	return scheme
}

// ackSince is the first release whose agent acknowledges a task
// ("accepted", "started") before carrying it. The panel keeps the short
// dispatch lease for such an agent; an older one gets the execution lease
// from the start, since its silence says nothing.
const ackSince = "0.47.0"

// AcknowledgesTasks says whether an agent of the given version sends the
// acceptance of a task. A version that cannot be read is taken as an old
// one: the longer lease is the safe mistake.
func AcknowledgesTasks(version string) bool {
	return atLeast(version, ackSince)
}

// helloBuildSince is the first release whose agent introduces itself with
// its build commit, its protocol range and the fingerprint of its
// configuration. A Hello without them from an older agent is not a Hello
// with an empty build: the panel records nothing rather than a blank.
const helloBuildSince = "0.47.0"

// ReportsBuild says whether an agent of the given version puts its build
// and configuration into the Hello. A version that cannot be read is taken
// as an old one: not knowing is the honest answer for such a host.
func ReportsBuild(version string) bool {
	return atLeast(version, helloBuildSince)
}

// atLeast says whether a version is the given release or a later one. A
// version that cannot be read is older than every release.
func atLeast(version, since string) bool {
	target, err := parseVersion(version)
	if err != nil {
		return false
	}
	floor, _ := parseVersion(since)
	return compareVersions(target, floor) >= 0
}
