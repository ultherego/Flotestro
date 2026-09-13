package power

import (
	"testing"
	"time"
)

func TestInhibitorsAreReadByColumnsAndNotBySpaces(t *testing.T) {
	output := "WHO            UID USER PID COMM           WHAT  WHY                                       MODE\n" +
		"ModemManager   0   root 678 ModemManager   sleep ModemManager needs to reset devices       delay\n" +
		"UnattendedUpgr 0   root 912 unattended-upg shutdown Stop ordered but upgrade in progress   block\n" +
		"\n2 inhibitors listed.\n"
	inhibitors, known := ParseInhibitors(output)

	if !known {
		t.Fatal("the read of the inhibitors was taken for failed")
	}
	if len(inhibitors) != 2 {
		t.Fatalf("inhibitors = %d", len(inhibitors))
	}
	// The justification has spaces: splitting on whitespace would cut it after
	// the first word and lose the mode column.
	if inhibitors[0].Why != "ModemManager needs to reset devices" {
		t.Errorf("reason = %q", inhibitors[0].Why)
	}
	if inhibitors[0].Mode != "delay" || inhibitors[0].PID != 678 {
		t.Errorf("inhibitor = %+v", inhibitors[0])
	}
	// "delay" postpones, "block" does not allow at all - these are two
	// different answers.
	if inhibitors[0].Blocks() {
		t.Error("a delay was taken for a block")
	}
	if !inhibitors[1].Blocks() {
		t.Error("a block was taken for a delay")
	}
}

// No inhibitors is an answer of the host, not the absence of one.
func TestNoInhibitorsIsAnAnswer(t *testing.T) {
	inhibitors, known := ParseInhibitors("No inhibitors.\n")
	if len(inhibitors) != 0 {
		t.Fatalf("inhibitors = %d", len(inhibitors))
	}
	if !known {
		t.Error("an empty list was taken for unknown")
	}

	if _, known := ParseInhibitors("systemd-inhibit: command not found\n"); known {
		t.Error("a missing tool was taken for an empty list")
	}
}

func TestTheBootListReadsIdentifiersAndTimes(t *testing.T) {
	output := " -2 684cfa5e381c4dcfa57c572f7c1036b6 Sun 2026-08-23 08:30:41 UTC Sun 2026-08-23 19:23:13 UTC\n" +
		" -1 3c4c6a15649744c8a69cd02c33b364c2 Sun 2026-08-23 19:23:48 UTC Sun 2026-08-23 20:54:46 UTC\n" +
		"  0 90b4ac23c8304fc4816e609ee28c9ea8 Mon 2026-08-24 16:40:09 UTC Mon 2026-08-24 17:17:35 UTC\n"
	boots := ParseBootList(output)

	if len(boots) != 3 {
		t.Fatalf("boots = %d", len(boots))
	}
	if boots[2].Index != 0 || boots[2].BootID != "90b4ac23c8304fc4816e609ee28c9ea8" {
		t.Errorf("the current boot = %+v", boots[2])
	}
	if boots[0].FirstEntry.IsZero() || boots[0].LastEntry.Before(boots[0].FirstEntry) {
		t.Errorf("the boot times = %+v", boots[0])
	}
}

func TestAScheduledShutdownIsAFact(t *testing.T) {
	moment := time.Date(2026, 8, 24, 20, 0, 0, 0, time.UTC)
	content := "USEC=" + itoa(moment.UnixMicro()) + "\nWARN_WALL=1\nMODE=poweroff\n"
	shutdown := ParseScheduled(content)

	if shutdown == nil {
		t.Fatal("the scheduled shutdown was not read")
	}
	if shutdown.Mode != ModePoweroff || !shutdown.At.Equal(moment) {
		t.Errorf("shutdown = %+v", shutdown)
	}
	// A file without a time describes nothing that could be shown to the
	// operator.
	if ParseScheduled("MODE=reboot\n") != nil {
		t.Error("an entry without a time was taken for a scheduled shutdown")
	}
}

func TestUptimeDoesNotInventAZero(t *testing.T) {
	if seconds := ParseUptime("12345.67 98765.43\n"); seconds == nil || *seconds != 12345.67 {
		t.Fatalf("uptime = %v", seconds)
	}
	// A host running for zero seconds does not exist: a file that was not read
	// stays a nil pointer.
	if seconds := ParseUptime(""); seconds != nil {
		t.Fatalf("an empty read became %v", *seconds)
	}
}

func TestAShutdownNeedsAReason(t *testing.T) {
	if err := ValidateShutdownReason("because"); err == nil {
		t.Error("a shutdown passed without a reason")
	}
	if err := ValidateShutdownReason("replacing the power supply in rack B12"); err != nil {
		t.Errorf("a sensible reason was rejected: %v", err)
	}
	if err := ValidateShutdownReason("replacing the power supply\nMODE=reboot"); err == nil {
		t.Error("a reason with a newline passed the validation")
	}
	if err := ValidateDelay(7200); err == nil {
		t.Error("a delay over an hour passed the validation")
	}
}

func itoa(value int64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
