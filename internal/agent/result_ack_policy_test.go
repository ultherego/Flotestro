package agent

import "testing"

// The session used to decide this alone: the panel sets
// task_results_acknowledged, and an agent told false released a spooled
// answer as soon as the send returned. The relay terminates that session, so
// a relay could set the field false, let the send succeed, drop the answer,
// and the host would have thrown away the only durable copy of work it had
// already carried out - without forging an acknowledgement, without a key,
// without touching the spool.
//
// The host's own file now has the last word, and it can only ever be
// stricter than the session.
func TestTheSessionCannotMakeAHostReleaseAnAnswerItWouldHaveKept(t *testing.T) {
	for _, one := range []struct {
		name               string
		panelAcknowledges  bool
		hostReleasesOnSend bool
		keeps              bool
		why                string
	}{
		{
			name:              "a panel that acknowledges, on a host with the default setting",
			panelAcknowledges: true, hostReleasesOnSend: false, keeps: true,
			why: "both say keep",
		},
		{
			name:              "a session claiming the panel acknowledges nothing",
			panelAcknowledges: false, hostReleasesOnSend: false, keeps: true,
			why: "this is the attack: the relay says no and the host keeps the answer anyway",
		},
		{
			name:              "an operator who wrote on_send in the agent's own file",
			panelAcknowledges: false, hostReleasesOnSend: true, keeps: false,
			why: "the host's own word, for an agent running against a panel from before the acknowledgement",
		},
		{
			name:              "that same operator, against a panel that does acknowledge",
			panelAcknowledges: true, hostReleasesOnSend: true, keeps: true,
			why: "the session may add to the keeping; there is an acknowledgement to wait for",
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			got := keepsResultsUntilAcknowledged(one.panelAcknowledges, one.hostReleasesOnSend)
			if got != one.keeps {
				t.Errorf("the answer is %s, and it should be %s: %s",
					kept(got), kept(one.keeps), one.why)
			}
		})
	}
}

func kept(keeps bool) string {
	if keeps {
		return "kept until the panel claims it"
	}
	return "released on a successful send"
}
