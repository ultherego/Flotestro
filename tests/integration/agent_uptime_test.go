//go:build integration

package integration

import "sync"

// agentStaysUp keeps two families of test off each other's hosts. A replacement
// of the agent package restarts the agent and the helper, and an operation that
// runs for minutes - a followed journal - dies with them: its lease stops being
// renewed and the scheduler reclaims the attempt, which is exactly what the long
// operation tests are there to prove does not happen.
//
// The tests that replace the agent hold it for writing, the long ones for
// reading, so they never overlap while everything else still runs in parallel.
var agentStaysUp sync.RWMutex

// keepAgentUp is taken by a test that needs the agent of a host to stay where it
// is for the length of the test.
func keepAgentUp() func() {
	agentStaysUp.RLock()
	return agentStaysUp.RUnlock
}

// replacingAgent is taken by a test that restarts or replaces the agent.
func replacingAgent() func() {
	agentStaysUp.Lock()
	return agentStaysUp.Unlock
}
