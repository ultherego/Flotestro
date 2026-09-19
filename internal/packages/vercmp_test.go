package packages

import "testing"

// The direction of a change decides what the operator approves and which
// switches the transaction gets, so the ordering has to agree with the tools
// on the cases that come up on real hosts.
func TestCompareDebVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1.0-2", "1.0-1", 1},
		{"1:1.0", "2.0", 1},
		{"3.0.16-1~deb12u1", "3.0.15-1~deb12u1", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0+", -1},
		{"2.36-9+deb12u10", "2.36-9+deb12u9", 1},
		{"6.1.0-37", "6.1.0-4", 1},
		{"0.9.1", "1.0.0", -1},
		{"1.0", "0:1.0", 0},
	}
	for _, tc := range cases {
		if got := CompareDebVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("deb %q vs %q = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareRPMVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0-1.fc42", "1.0-1.fc42", 0},
		{"1.0-2.fc42", "1.0-1.fc42", 1},
		{"1:1.52.2-1.fc42", "1.52.3-1.fc42", 1},
		{"6.16.5-200.fc42", "6.16.4-200.fc42", 1},
		{"2.2.1-1.fc42", "2.2.1-1.fc41", 1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0^git1-1", "1.0-1", 1},
		{"1.0^git1-1", "1.0.1-1", -1},
		{"1.0a-1", "1.0-1", 1},
		{"1.0-1", "1.0a-1", -1},
		{"10.0-1", "9.0-1", 1},
		{"1.0.010-1", "1.0.9-1", 1},
		{"6.16.6.arch1-1", "6.16.5.arch1-1", 1},
		{"1.0-1", "1.0", 1},
	}
	for _, tc := range cases {
		if got := CompareRPMVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("rpm %q vs %q = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestChangeActionNamesTheDirection(t *testing.T) {
	if got := changeAction("apt", "", "1.0"); got != ActionInstall {
		t.Errorf("a new package = %s", got)
	}
	if got := changeAction("apt", "1.0", ""); got != ActionRemove {
		t.Errorf("a package going away = %s", got)
	}
	if got := changeAction("apt", "1.0-1", "1.0-2"); got != ActionUpgrade {
		t.Errorf("apt going up = %s", got)
	}
	if got := changeAction("apt", "1.0-2", "1.0-1"); got != ActionDowngrade {
		t.Errorf("apt going down = %s", got)
	}
	if got := changeAction("dnf", "1:1.0-1.fc42", "1.1-1.fc42"); got != ActionDowngrade {
		t.Errorf("dnf with an epoch = %s", got)
	}
	if got := changeAction("pacman", "6.16.5.arch1-1", "6.16.6.arch1-1"); got != ActionUpgrade {
		t.Errorf("pacman going up = %s", got)
	}
}
