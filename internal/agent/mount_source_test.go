package agent

import "testing"

// A filesystem mounted at the right place from the wrong device is not the
// change ordered. A tag and a device path name one thing, so they are not judged.
func TestTheMountSourceIsJudgedOnlyAgainstItsOwnForm(t *testing.T) {
	cases := []struct {
		name     string
		ordered  string
		observed string
		fault    bool
	}{
		{"the same device", "/dev/sdb1", "/dev/sdb1", false},
		{"another device", "/dev/sdb1", "/dev/sdc1", true},
		{"another tag", "UUID=1111", "UUID=2222", true},
		{"a tag against the device it names", "UUID=1111", "/dev/sdb1", false},
		{"a device against a tag", "/dev/sdb1", "LABEL=data", false},
		{"nothing observed", "/dev/sdb1", "", false},
		{"nothing ordered", "", "/dev/sdb1", false},
	}
	for _, test := range cases {
		reason := sourceMismatch(test.ordered, test.observed, "/srv")
		if (reason != "") != test.fault {
			t.Errorf("%s: %q against %q says %q", test.name, test.ordered, test.observed, reason)
		}
	}
}
