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
