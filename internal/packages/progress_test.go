package packages

import (
	"strings"
	"testing"
)

// The progress lines of dnf come straight from a test host. The description
// column is padded to a fixed width, so sometimes one space is left before the
// percentage and sometimes a dozen - the pattern has to cope with both.
func TestTheDNFStepRecognisesBothColumnWidths(t *testing.T) {
	cases := []struct {
		line        string
		step        uint32
		total       uint32
		description string
	}{
		{"[1/6] Verify package files              100% | 166.0   B/s |   2.0   B |  00m00s", 1, 6, "Verify package files"},
		{"[3/6] Upgrading tcpdump-14:4.99.6-2.fc4 100% |  36.0 MiB/s |   1.2 MiB |  00m00s", 3, 6, "Upgrading tcpdump-14:4.99.6-2.fc4"},
		{"[ 9/33] Upgrading samba-common-2:4.22.9 100% |   4.7 MiB/s | 218.1 KiB |  00m00s", 9, 33, "Upgrading samba-common-2:4.22.9"},
		{"[33/33] Removing NetworkManager-1:1.52. 100% |  21.0   B/s |  87.0   B |  00m04s", 33, 33, "Removing NetworkManager-1:1.52."},
	}
	for _, c := range cases {
		progress, ok := dnfStepFrom(c.line)
		if !ok {
			t.Errorf("the line was not recognised: %q", c.line)
			continue
		}
		if progress.Step != c.step || progress.Total != c.total {
			t.Errorf("%q: step = %d/%d, expected %d/%d",
				c.line, progress.Step, progress.Total, c.step, c.total)
		}
		if progress.Message != c.description {
			t.Errorf("%q: description = %q, expected %q", c.line, progress.Message, c.description)
		}
	}
}

// A line without the percentage column carries the number of the step as well.
func TestTheDNFStepWithoutThePercentageColumn(t *testing.T) {
	progress, ok := dnfStepFrom("[2/4] Prepare transaction")
	if !ok || progress.Step != 2 || progress.Total != 4 {
		t.Fatalf("progress = %+v, ok = %v", progress, ok)
	}
}

// Ordinary output of a tool must not pretend to be progress.
func TestOrdinaryLinesAreNotASteps(t *testing.T) {
	for _, line := range []string{
		"Error: Transaction failed",
		"[RPM] tcpdump-14:4.99.6-2.fc42.x86_64: install failed",
		"Upgrading tcpdump",
		"[0/0] nothing",
	} {
		if progress, ok := dnfStepFrom(line); ok {
			t.Errorf("%q was treated as progress: %+v", line, progress)
		}
	}
}

// Apt reports progress over a machine channel of its own. The format is
// "kind:package:percentage:description" and it does not depend on the width of
// the terminal or on the locale - which is why we read it rather than the bars
// on the screen.
func TestTheAPTStatusIsParsed(t *testing.T) {
	input := strings.Join([]string{
		"dlstatus:1:20.0000:Fetching file 1 of 5",
		"pmstatus:dpkg-exec:0.0000:Running dpkg",
		"pmstatus:libc6:12.5000:Preparing libc6",
		"pmstatus:libc6:25.0000:Unpacking libc6",
		"nonsense without colons",
		"pmstatus:bad:notanumber:Description",
	}, "\n")

	var gathered []Progress
	throttle := &throttler{receiver: func(p Progress) { gathered = append(gathered, p) }}
	// Every report gets a timestamp of its own outside the throttling window,
	// so that the test checks the parsing rather than the limiting of the
	// pace.
	readAPTStatusForTest(strings.NewReader(input), throttle)

	if len(gathered) != 4 {
		t.Fatalf("gathered %d reports, expected 4: %+v", len(gathered), gathered)
	}
	if gathered[0].Percent == nil || *gathered[0].Percent != 20 {
		t.Errorf("the first percentage = %v", gathered[0].Percent)
	}
	if gathered[0].Message != "Downloading: Fetching file 1 of 5" {
		t.Errorf("the description of the download = %q", gathered[0].Message)
	}
	if gathered[3].Percent == nil || *gathered[3].Percent != 25 {
		t.Errorf("the last percentage = %v", gathered[3].Percent)
	}
}

// Undetermined progress must not be shown as zero per cent - a bar at zero
// looks like work that is standing still.
func TestAMissingPercentageIsNotZero(t *testing.T) {
	progress, ok := dnfStepFrom("[2/4] Prepare transaction")
	if !ok {
		t.Fatal("the step was not recognised")
	}
	if progress.Percent != nil {
		t.Errorf("percentage = %v, expected an undetermined one", *progress.Percent)
	}
}
