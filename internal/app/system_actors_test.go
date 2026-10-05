package app

import "testing"

// The author of work nobody typed is named, not guessed at. Reading the absence
// of an account as "a system task" let a blocked operator's queued work leave
// with a signed capability; reading it as "blocked" would have stopped every
// campaign in the fleet, because a campaign's jobs carry "campaign:<name>" and
// no such principal exists. Both happened on 05.10, hours apart.
func TestThePanelsOwnMachineryIsNamedAndNotInferred(t *testing.T) {
	for _, subject := range []string{
		"campaign:nightly security updates",
		"schedule:3f1a2b4c",
		"remediation:plan-9",
		"policy:require-ssh-hardening",
	} {
		if !systemActor(subject) {
			t.Errorf("%q is the panel's own machinery and was not recognised", subject)
		}
	}
	// A person is not, however their name is spelled.
	for _, subject := range []string{
		"alice", "alice@ipa.example.test", "a.smith@keycloak.example.test",
		"campaigns-team", "schedules", "",
	} {
		if systemActor(subject) {
			t.Errorf("%q was taken for the panel's own machinery", subject)
		}
	}
}
