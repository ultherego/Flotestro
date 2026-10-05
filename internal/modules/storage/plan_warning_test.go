package storage

import (
	"strings"
	"testing"
)

// A persisted mount whose options carry no nofail stops the host booting when
// the device is away: systemd waits for it without a timeout, so the machine
// never finishes starting and even a login hangs. On 05.10 a laboratory host
// was lost exactly that way, by an entry a test had persisted the evening
// before - and nothing in the plan said it would cost that.
func TestAPersistedMountWithoutNofailSaysWhatItCosts(t *testing.T) {
	for name, options := range map[string]string{
		"defaults":           "defaults",
		"defaults,noatime":   "defaults,noatime",
		"a nofail lookalike": "defaults,nofailover",
	} {
		t.Run(name, func(t *testing.T) {
			warnings := mountWarnings(options, true, PlanCreate)
			if len(warnings) != 1 {
				t.Fatalf("the plan says %v about %q", warnings, options)
			}
			if !strings.Contains(warnings[0], "will not finish") {
				t.Errorf("the warning does not say what it costs: %q", warnings[0])
			}
		})
	}

	// nofail, with and without company, is the answer and says nothing.
	for _, options := range []string{"nofail", "defaults,nofail", "defaults, nofail ,noatime"} {
		if warnings := mountWarnings(options, true, PlanCreate); len(warnings) != 0 {
			t.Errorf("%q still warns: %v", options, warnings)
		}
	}

	// A mount nobody persists is gone at the next boot, so the question does
	// not arise; neither does it for a removal.
	if warnings := mountWarnings("defaults", false, PlanCreate); len(warnings) != 0 {
		t.Errorf("a mount that is not persisted warns: %v", warnings)
	}
	if warnings := mountWarnings("defaults", true, PlanRemove); len(warnings) != 0 {
		t.Errorf("a removal warns: %v", warnings)
	}
}
