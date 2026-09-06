package helper

import "testing"

func TestWymianaAgentaRozpoznajePakietAgenta(t *testing.T) {
	przypadki := []struct {
		nazwa      string
		pakiety    []string
		oczekiwana bool
		spec       string
	}{
		{"apt z wersja", []string{"flotestro-agent=0.6.0"}, true, "flotestro-agent=0.6.0"},
		{"dnf z wersja", []string{"flotestro-agent-0.6.0"}, true, "flotestro-agent-0.6.0"},
		{"bez wersji", []string{"flotestro-agent"}, true, "flotestro-agent"},
		{"obcy pakiet", []string{"curl=8.0"}, false, ""},
		{"podobna nazwa", []string{"flotestro-agent-tools=1.0"}, false, ""},
		{"agent w towarzystwie", []string{"flotestro-agent=0.6.0", "curl"}, false, ""},
		{"pusto", nil, false, ""},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.nazwa, func(t *testing.T) {
			spec, ok := wymianaAgenta(przypadek.pakiety)
			if ok != przypadek.oczekiwana {
				t.Fatalf("wymianaAgenta(%v) = %v, oczekiwano %v",
					przypadek.pakiety, ok, przypadek.oczekiwana)
			}
			if ok && spec != przypadek.spec {
				t.Fatalf("spec = %q, oczekiwano %q", spec, przypadek.spec)
			}
		})
	}
}
