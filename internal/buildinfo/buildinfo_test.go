package buildinfo

import (
	"strings"
	"testing"
)

func TestOpisNiesieWersjeISrodowisko(t *testing.T) {
	opis := Opis("flotestro-agentctl")
	if !strings.HasPrefix(opis, "flotestro-agentctl "+Wersja) {
		t.Fatalf("opis = %q", opis)
	}
	if !strings.Contains(opis, "go1") {
		t.Fatalf("opis bez wersji toolchainu: %q", opis)
	}
}

// TestKrotkiCommitNieZmysla pilnuje zasady, ze nieznane nie jest zerem ani
// wymyslona wartoscia: bez wpisanego commita i bez metadanych zostaje pustka,
// ktora widac, a nie odcisk, ktory wyglada wiarygodnie.
func TestKrotkiCommitNieZmysla(t *testing.T) {
	poprzedni := Commit
	t.Cleanup(func() { Commit = poprzedni })

	Commit = "0123456789abcdef0123456789abcdef01234567"
	if got := KrotkiCommit(); got != "0123456789ab" {
		t.Fatalf("KrotkiCommit = %q", got)
	}
	Commit = "krotki"
	if got := KrotkiCommit(); got != "krotki" {
		t.Fatalf("KrotkiCommit = %q", got)
	}
}
