package remediation

import (
	"encoding/json"
	"testing"

	"github.com/ultherego/flotestro/internal/compliance"
)

func ustalenie(id, akcja string, restart bool) compliance.Ustalenie {
	wynik := compliance.Ustalenie{
		CheckID: id, CheckVersion: 1, Applicable: true, Severity: compliance.WagaMedium,
	}
	if akcja != "" {
		wynik.Remediation = &compliance.Naprawa{
			Action: akcja, Payload: json.RawMessage(`{}`), RequiresReboot: restart,
		}
	}
	return wynik
}

// Restart konczy plan: to, co po nim, i tak trzeba ocenic na nowo, bo kroki
// zaplanowane wczesniej odnosza sie do faktow sprzed restartu.
func TestRestartJestOstatnimKrokiem(t *testing.T) {
	ulozony, err := Ulozenie([]compliance.Ustalenie{
		ustalenie("reboot.pending", "system.reboot", true),
		ustalenie("kernel.rp-filter", "sysctl.ensure", false),
		ustalenie("ssh.root-login", "ssh.config.apply", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ulozony.Kroki) != 3 {
		t.Fatalf("krokow = %d", len(ulozony.Kroki))
	}
	if !ulozony.Kroki[2].RequiresReboot {
		t.Errorf("restart nie jest ostatni: %+v", ulozony.Kroki)
	}
	// Pozycje sa zaleznoscia: krok rusza dopiero po poprzednim.
	for i, krok := range ulozony.Kroki {
		if krok.Position != i+1 {
			t.Errorf("krok %s ma pozycje %d", krok.CheckID, krok.Position)
		}
		if krok.State != KrokOczekuje {
			t.Errorf("krok %s zaczyna w stanie %q", krok.CheckID, krok.State)
		}
	}
	// Klasa blokady zasobu pochodzi z kontraktu operacji, a nie z planu.
	for _, krok := range ulozony.Kroki {
		if krok.ActionType == "ssh.config.apply" && krok.LockClass == "" {
			t.Error("krok zmieniajacy sshd nie niesie klasy blokady")
		}
	}
}

// Dwa restarty to dwa plany: po pierwszym stan hosta trzeba ocenic na nowo.
func TestDwaRestartyNieTworzaJednegoPlanu(t *testing.T) {
	_, err := Ulozenie([]compliance.Ustalenie{
		ustalenie("reboot.pending", "system.reboot", true),
		ustalenie("kernel.blacklist", "system.reboot", true),
	})
	if err == nil {
		t.Fatal("plan z dwoma restartami zostal ulozony")
	}
}

// Ustalenie bez operacji naprawczej nie tworzy kroku - i mowi dlaczego.
func TestUstalenieBezOperacjiJestPominiete(t *testing.T) {
	bezOperacji := ustalenie("exposure.listening", "", false)
	bezOperacji.Remediation = &compliance.Naprawa{Note: "kazde gniazdo zamyka sie inaczej"}
	spelnione := ustalenie("mac.enforcing", "selinux.mode.set", false)
	spelnione.Passed = true

	ulozony, err := Ulozenie([]compliance.Ustalenie{
		bezOperacji, spelnione, ustalenie("kernel.rp-filter", "sysctl.ensure", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ulozony.Kroki) != 1 || ulozony.Kroki[0].CheckID != "kernel.rp-filter" {
		t.Fatalf("kroki = %+v", ulozony.Kroki)
	}
	if ulozony.Pominiete["exposure.listening"] != "kazde gniazdo zamyka sie inaczej" {
		t.Errorf("pominiete = %v", ulozony.Pominiete)
	}
	if ulozony.Pominiete["mac.enforcing"] == "" {
		t.Error("ustalenie spelnione pominieto bez powodu")
	}
}

// Plan bez ani jednego wykonalnego kroku nie jest planem.
func TestPlanBezKrokowJestBledem(t *testing.T) {
	bezOperacji := ustalenie("exposure.listening", "", false)
	if _, err := Ulozenie([]compliance.Ustalenie{bezOperacji}); err == nil {
		t.Fatal("plan bez krokow zostal ulozony")
	}
}

// Nieznana operacja nie moze trafic do planu: odrzucilby ja dopiero runner,
// juz po zatwierdzeniu przez operatora.
func TestNieznanaOperacjaNieWchodziDoPlanu(t *testing.T) {
	if _, err := Ulozenie([]compliance.Ustalenie{
		ustalenie("wymyslone", "nie.ma.takiej.operacji", false),
	}); err == nil {
		t.Fatal("plan przyjal nieznana operacje")
	}
}

// Ten sam zbior ustalen daje ten sam plan: kolejnosc nie zalezy od tego,
// w jakiej kolejnosci przyszly ustalenia.
func TestKolejnoscKrokowJestPowtarzalna(t *testing.T) {
	pierwszy, err := Ulozenie([]compliance.Ustalenie{
		ustalenie("ssh.root-login", "ssh.config.apply", false),
		ustalenie("kernel.rp-filter", "sysctl.ensure", false),
		ustalenie("audit.rules-loaded", "unit.restart", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	drugi, err := Ulozenie([]compliance.Ustalenie{
		ustalenie("audit.rules-loaded", "unit.restart", false),
		ustalenie("kernel.rp-filter", "sysctl.ensure", false),
		ustalenie("ssh.root-login", "ssh.config.apply", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range pierwszy.Kroki {
		if pierwszy.Kroki[i].CheckID != drugi.Kroki[i].CheckID {
			t.Fatalf("kolejnosc rozna: %s vs %s", pierwszy.Kroki[i].CheckID, drugi.Kroki[i].CheckID)
		}
	}
}

// Biezacy krok to pierwszy niezamkniety - na nim plan czeka.
func TestBiezacyKrokIPostep(t *testing.T) {
	plan := Plan{Steps: []Krok{
		{CheckID: "a", State: KrokUdany},
		{CheckID: "b", State: KrokWToku},
		{CheckID: "c", State: KrokOczekuje},
	}}
	if biezacy := plan.Biezacy(); biezacy == nil || biezacy.CheckID != "b" {
		t.Fatalf("biezacy = %+v", plan.Biezacy())
	}
	if postep := plan.Postep(); postep[KrokUdany] != 1 || postep[KrokOczekuje] != 1 {
		t.Errorf("postep = %v", postep)
	}

	zamkniety := Plan{Steps: []Krok{{State: KrokUdany}, {State: KrokPominiety}}}
	if zamkniety.Biezacy() != nil {
		t.Error("plan bez otwartych krokow ma krok biezacy")
	}
}
