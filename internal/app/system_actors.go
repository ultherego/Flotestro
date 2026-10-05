package app

import "strings"

// systemActorPrefixes are the names the panel's own machinery records as the
// author of work nobody typed: a campaign, a schedule, a remediation plan, a
// policy rule. None of them is a principal, and none of them ever will be.
//
// They are listed because the alternative is inferring them from the absence of
// an account, and that inference has been wrong in both directions on one day:
// reading absence as "a system task" let a blocked operator's queued work leave
// with a signed capability, and reading it as "blocked" would have stopped every
// campaign in the fleet.
var systemActorPrefixes = []string{
	"campaign:",
	"schedule:",
	"remediation:",
	"policy:",
}

// systemActor says whether a task's author is the panel's own machinery.
func systemActor(subject string) bool {
	for _, prefix := range systemActorPrefixes {
		if strings.HasPrefix(subject, prefix) {
			return true
		}
	}
	return false
}
