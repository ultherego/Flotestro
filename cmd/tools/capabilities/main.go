// Command capabilities prints every adapter the agent declares, one per line.
//
// The laboratory's gate has to account for each of them in the capability
// manifest of its report, and the fixtures have to prepare a host for each. A
// list kept by hand in a shell script drifts from the code the day somebody
// adds an adapter, and the gate would then be accounting for the adapters the
// script remembered.
//
//	go run ./cmd/tools/capabilities
package main

import (
	"fmt"
	"sort"

	"github.com/ultherego/flotestro/internal/agent"
)

func main() {
	declared := make([]string, len(agent.AllCapabilities))
	copy(declared, agent.AllCapabilities)
	sort.Strings(declared)
	for _, capability := range declared {
		fmt.Println(capability)
	}
}
