package buildinfo

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrProtocolIncompatible means an agent version whose protocol this panel
// does not speak.
var ErrProtocolIncompatible = errors.New("protocol_incompatible")

// protocolStep says from which release the agent speaks a given protocol.
type protocolStep struct {
	Since    string
	Protocol int
}

// protocolByVersion is the table of protocol changes by release, oldest first.
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
// AgentProtocol.
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

// parseVersion reads the numeric part of a release version: the dotted numbers
// before any suffix.
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

// hashSchemeByVersion says from which release the agent verifies a given plan
// hash scheme, oldest first.
var hashSchemeByVersion = []protocolStep{
	{Since: "0.1.0", Protocol: 1},
	{Since: "0.43.0", Protocol: 2},
}

// PayloadHashSchemeFor returns the newest plan hash scheme an agent of the
// given version verifies.
func PayloadHashSchemeFor(version string) int {
	scheme, err := minimumProtocol(hashSchemeByVersion, version)
	if err != nil {
		return 1
	}
	return scheme
}

// ackSince is the first release whose agent acknowledges a task ("accepted",
// "started") before carrying it.
const ackSince = "0.47.0"

// AcknowledgesTasks says whether an agent of the given version sends the
// acceptance of a task.
func AcknowledgesTasks(version string) bool {
	return atLeast(version, ackSince)
}

// helloBuildSince is the first release whose agent introduces itself with its
// build commit, its protocol range and the fingerprint of its configuration.
const helloBuildSince = "0.47.0"

// ReportsBuild says whether an agent of the given version puts its build and
// configuration into the Hello.
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
