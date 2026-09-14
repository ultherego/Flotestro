package packages

import (
	"strings"
	"testing"
)

func TestScriptletFailuresAreNamedFromTheOutput(t *testing.T) {
	output := strings.Join([]string{
		"[3/3] Installing flotestro-lab-broken-0 100% |   9.0 KiB/s | 768.0   B |  00m00s",
		">>> Running %post scriptlet: flotestro-lab-broken-0:1.0.0-1.noarch",
		">>> Non-critical error in %post scriptlet: flotestro-lab-broken-0:1.0.0-1.noarch",
		">>> Scriptlet output:",
		">>> flotestro-lab-broken: the maintainer script of this package fails by design;",
		">>> [RPM] %post(flotestro-lab-broken-1.0.0-1.noarch) scriptlet failed, exit status 1",
		"Error in POSTIN scriptlet in rpm package my-tool-2.0-1.fc42.x86_64",
		"Complete!",
	}, "\n")
	got := scriptletFailures(output)
	want := []string{"flotestro-lab-broken", "my-tool"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("scriptletFailures = %v, want %v", got, want)
	}
	if got := scriptletFailures("Complete!\n"); len(got) != 0 {
		t.Fatalf("a clean transaction names %v", got)
	}
}
