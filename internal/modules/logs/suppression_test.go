package logs

import "testing"

// journald says in its own log how much it dropped at the source. The notice
// is the only place that number exists, so it is read from the line.
func TestSuppressedMessagesReadsTheNoticeOfJournald(t *testing.T) {
	for _, testCase := range []struct {
		line string
		want uint32
	}{
		{"2026-09-20T12:00:03+0200 web-1 systemd-journald[412]: Suppressed 4213 messages from unit-x.service", 4213},
		{"2026-09-20T12:00:03+0200 web-1 systemd-journald: Suppressed 7 messages from /system.slice/unit-x.service", 7},
	} {
		got, ok := SuppressedMessages(testCase.line)
		if !ok || got != testCase.want {
			t.Errorf("%q gave %d (%t), want %d", testCase.line, got, ok, testCase.want)
		}
	}
}

// Anything that is not the notice is not counted: a wrong number here would
// tell the operator the host silenced messages it never silenced.
func TestSuppressedMessagesIgnoresEverythingElse(t *testing.T) {
	for _, line := range []string{
		"2026-09-20T12:00:03+0200 web-1 sshd[900]: Accepted publickey for root",
		// An application quoting the notice is not journald.
		"2026-09-20T12:00:03+0200 web-1 app[900]: Suppressed 4213 messages from unit-x.service",
		// A count no journal could produce is not read as a smaller one.
		"2026-09-20T12:00:03+0200 web-1 systemd-journald[412]: Suppressed 12345678901 messages from unit-x.service",
		"2026-09-20T12:00:03+0200 web-1 systemd-journald[412]: Missed 17 kernel messages",
		"",
	} {
		if got, ok := SuppressedMessages(line); ok {
			t.Errorf("%q was read as a notice of %d suppressed messages", line, got)
		}
	}
}
