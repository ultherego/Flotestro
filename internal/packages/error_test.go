package packages

import (
	"strings"
	"testing"
)

// Dnf prints progress bars on stderr. Taking the first line gave the operator
// a message that was true, useless and indistinguishable from a success -
// exactly what could be seen in the panel after a failed upgrade.
func TestAProgressBarIsNotTheCauseOfAnError(t *testing.T) {
	stderr := strings.Join([]string{
		"[ 1/36] Verify package files            100% |  33.0   B/s |  16.0   B |  00m00s",
		"[ 2/36] Prepare transaction             100% | 1.2 KiB/s |  36.0   B |  00m00s",
		"Error: Transaction failed: package nfs-utils-2.8.7 cannot be verified",
	}, "\n")

	description := errorDescription(stderr, "")
	if strings.Contains(description, "Verify package files") {
		t.Errorf("the description carries a progress bar: %q", description)
	}
	if !strings.Contains(description, "Transaction failed") {
		t.Errorf("the description does not carry the cause: %q", description)
	}
}

// The details of an error come after the line with the marker, so they must
// not be cut off.
func TestTheDetailsAfterTheErrorLineAreKept(t *testing.T) {
	stderr := strings.Join([]string{
		"Error: Transaction test failed",
		"  file /usr/bin/foo conflicts between attempted installs",
	}, "\n")

	description := errorDescription(stderr, "")
	if !strings.Contains(description, "conflicts between") {
		t.Errorf("the details of the error were lost: %q", description)
	}
}

// Output without an error marker means something as well - what counts is its
// end rather than its beginning.
func TestWithoutAMarkerTheEndOfTheOutputCounts(t *testing.T) {
	stderr := "first\nsecond\nthird\nfourth\nfifth"
	description := errorDescription(stderr, "")
	if strings.Contains(description, "first") {
		t.Errorf("the description starts at the beginning of the output: %q", description)
	}
	if !strings.Contains(description, "fifth") {
		t.Errorf("the description skips the end of the output: %q", description)
	}
}

// Apt writes the cause on stdout when stderr says nothing.
func TestTheCauseComesFromStdoutWhenStderrIsSilent(t *testing.T) {
	stdout := "Reading database ... 45%\nE: Sub-process /usr/bin/dpkg returned an error code (1)"
	description := errorDescription("", stdout)
	if !strings.Contains(description, "Sub-process") {
		t.Errorf("the description skips the cause from stdout: %q", description)
	}
	if strings.Contains(description, "Reading database") {
		t.Errorf("the description carries a progress line: %q", description)
	}
}

// Output made of progress bars alone carries no cause, and it is better to say
// so outright than to quote a bar.
func TestProgressBarsAloneGiveNoDescription(t *testing.T) {
	stderr := "[ 1/36] Verify package files 100% |  33.0   B/s |  16.0   B |  00m00s"
	if description := errorDescription(stderr, ""); description != "" {
		t.Errorf("description = %q, expected an empty one", description)
	}
}

// Long output is trimmed visibly: a cut message without a mark would look like
// the full text of the error.
func TestALongDescriptionIsTrimmedVisibly(t *testing.T) {
	stderr := "Error: " + strings.Repeat("a", 1000)
	description := errorDescription(stderr, "")
	if len([]rune(description)) > maxReasonLength+1 {
		t.Errorf("the description has %d characters", len([]rune(description)))
	}
	if !strings.HasSuffix(description, "…") {
		t.Error("the trim is not marked")
	}
}
