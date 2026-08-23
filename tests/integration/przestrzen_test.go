//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type urzadzenieView struct {
	Path        string   `json:"path"`
	Type        string   `json:"type"`
	SizeBytes   uint64   `json:"size_bytes"`
	FSType      string   `json:"fs_type"`
	UUID        string   `json:"uuid"`
	Parent      string   `json:"parent"`
	Mountpoints []string `json:"mountpoints"`
}

type montowanieView struct {
	Target            string  `json:"target"`
	Source            string  `json:"source"`
	FSType            string  `json:"fs_type"`
	InFstab           bool    `json:"in_fstab"`
	Mounted           bool    `json:"mounted"`
	Managed           bool    `json:"managed"`
	UsedPercent       *uint32 `json:"used_percent"`
	InodesUsedPercent *uint32 `json:"inodes_used_percent"`
}

type migawkaPrzestrzeni struct {
	Devices []urzadzenieView `json:"devices"`
	Mounts  []montowanieView `json:"mounts"`
	Groups  []struct {
		Name      string `json:"name"`
		FreeBytes uint64 `json:"free_bytes"`
	} `json:"groups"`
	LVMUnavailableReason string `json:"lvm_unavailable_reason"`
	UnavailableReason    string `json:"unavailable_reason"`
}

const powodPrzestrzeni = "test integracyjny modulu przestrzeni"

// TestTopologiaMaStabilneIdentyfikatory sprawdza rzecz, ktora decyduje o
// bezpieczenstwie kazdej operacji na dysku: urzadzenie ma byc rozpoznawalne
// po UUID, a nie po /dev/sdX, ktore po restarcie wskazuje co innego.
func TestTopologiaMaStabilneIdentyfikatory(t *testing.T) {
	h := newHarness(t)

	for _, rodzina := range []string{"debian", "rhel"} {
		t.Run(rodzina, func(t *testing.T) {
			host := h.hostByFamily(rodzina)
			stan := migawkaPrzestrzeniHosta(t, h, host.ID)
			if stan.UnavailableReason != "" {
				t.Fatalf("topologii nie odczytano: %s", stan.UnavailableReason)
			}
			if len(stan.Devices) == 0 {
				t.Fatal("host nie zglosil zadnego urzadzenia")
			}

			var zFilesystemem, zRodzicem int
			for _, urzadzenie := range stan.Devices {
				if urzadzenie.FSType != "" && urzadzenie.FSType != "swap" &&
					urzadzenie.FSType != "LVM2_member" {
					zFilesystemem++
					if urzadzenie.UUID == "" {
						t.Errorf("filesystem bez UUID: %+v", urzadzenie)
					}
				}
				if urzadzenie.Parent != "" {
					zRodzicem++
				}
			}
			if zFilesystemem == 0 {
				t.Error("host nie zglosil zadnego filesystemu")
			}
			// Topologia bez odsylaczy do rodzica nie jest topologia, tylko
			// lista - a przy planie rozszerzenia liczy sie wlasnie hierarchia.
			if zRodzicem == 0 {
				t.Error("zadne urzadzenie nie wskazuje rodzica")
			}
		})
	}
}

// TestMontowaniaRozdzielajaStanOdFstab sprawdza rozroznienie, po ktore
// operator tu przychodzi: co jest zamontowane teraz, a co przetrwa restart.
func TestMontowaniaRozdzielajaStanOdFstab(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	stan := migawkaPrzestrzeniHosta(t, h, host.ID)

	var korzen montowanieView
	var bezWpisu int
	for _, montowanie := range stan.Mounts {
		if montowanie.Target == "/" {
			korzen = montowanie
		}
		if montowanie.Mounted && !montowanie.InFstab {
			bezWpisu++
		}
		// Filesystem zamontowany bez odczytanej zajetosci wygladalby na
		// pusty; brak wartosci ma byc brakiem, a nie zerem.
		if montowanie.Mounted && montowanie.UsedPercent != nil && *montowanie.UsedPercent > 100 {
			t.Errorf("zajetosc poza zakresem: %+v", montowanie)
		}
		if montowanie.InodesUsedPercent != nil && *montowanie.InodesUsedPercent > 100 {
			t.Errorf("zajetosc i-wezlow poza zakresem: %+v", montowanie)
		}
	}
	if !korzen.Mounted || !korzen.InFstab || korzen.UsedPercent == nil {
		t.Errorf("korzen = %+v", korzen)
	}
	// Host z kontenerami i bind-mountami zawsze ma montowania spoza fstab;
	// gdyby ich nie bylo, znaczyloby to, ze czytamy sam plik.
	if bezWpisu == 0 {
		t.Error("panel nie rozpoznal zadnego montowania spoza fstab")
	}
}

// TestMontowanieNaKatalogSystemowyJestOdrzucane pilnuje granicy, ktorej
// przekroczenie odcina host od samego siebie.
func TestMontowanieNaKatalogSystemowyJestOdrzucane(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, przypadek := range []struct {
		zmiana   map[string]any
		dlaczego string
	}{
		{map[string]any{"source": "UUID=aaaa", "target": "/etc", "fs_type": "ext4"}, "katalog systemowy"},
		{map[string]any{"source": "UUID=aaaa", "target": "/mnt/../etc", "fs_type": "ext4"}, "sciezka z wyjsciem w gore"},
		{map[string]any{"source": "sdb1", "target": "/mnt/dane", "fs_type": "ext4"}, "zrodlo bez sciezki"},
		{map[string]any{"source": "UUID=aaaa", "target": "/mnt/dane", "fs_type": "ext4",
			"options": "defaults;reboot"}, "opcje ze srednikiem"},
	} {
		t.Run(przypadek.dlaczego, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "mount.ensure", "reason": powodPrzestrzeni,
					"payload": map[string]any{"storage": przypadek.zmiana}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestSprawdzenieFilesystemuWymagaOdmontowania pilnuje reguly, ktorej
// zlamanie konczy sie uszkodzeniem danych: fsck na zamontowanym filesystemie.
func TestSprawdzenieFilesystemuWymagaOdmontowania(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	stan := migawkaPrzestrzeniHosta(t, h, host.ID)

	var zamontowane string
	for _, urzadzenie := range stan.Devices {
		if len(urzadzenie.Mountpoints) > 0 && urzadzenie.FSType != "" && urzadzenie.FSType != "swap" {
			zamontowane = urzadzenie.Path
			break
		}
	}
	if zamontowane == "" {
		t.Skip("host nie ma zamontowanego filesystemu")
	}

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "filesystem.check", "reason": powodPrzestrzeni,
		"payload": map[string]any{"storage": map[string]any{"device": zamontowane}},
	}, 2*time.Minute)
	if zadanie.State == "succeeded" {
		t.Fatalf("panel sprawdzil zamontowany filesystem %s", zamontowane)
	}
	if !strings.Contains(ostatniKomunikat(proby), "zamontowany") {
		t.Errorf("odmowa bez powodu: %q", ostatniKomunikat(proby))
	}
}

func migawkaPrzestrzeniHosta(t *testing.T, h *harness, hostID string) migawkaPrzestrzeni {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/storage", nil, &fragment, http.StatusOK)
	var stan migawkaPrzestrzeni
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		t.Fatalf("migawka przestrzeni: %v", err)
	}
	return stan
}

// TestOperacjaNiszczacaWymagaDwochOsob sprawdza granice, ktora odroznia
// formatowanie od kazdej innej operacji: pomylka jednej osoby z prawem
// zatwierdzania kosztuje dane, ktorych nikt nie odtworzy.
func TestOperacjaNiszczacaWymagaDwochOsob(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Cel wybieramy tak, zeby zadanie i tak zostalo odrzucone przez host:
	// test dotyczy liczenia zgod, a nie kasowania danych.
	zadanie := h.createOperation(host.ID, map[string]any{
		"action": "disk.wipe", "reason": powodPrzestrzeni,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"storage": map[string]any{
			"device": "/dev/sdz", "expected_serial": "URZADZENIE-KTOREGO-NIE-MA"}},
	})
	if zadanie.RequiredApprovals != 2 {
		t.Fatalf("wymaganych zgod = %d", zadanie.RequiredApprovals)
	}

	po := h.approve(zadanie.ID, zadanie.PayloadHash)
	if po.State != "awaiting_approval" || po.CollectedApprovals != 1 {
		t.Fatalf("po pierwszej zgodzie: stan = %s, zgod = %d", po.State, po.CollectedApprovals)
	}
	// Ta sama osoba klikajaca drugi raz to nadal jedna osoba.
	po = h.approve(zadanie.ID, zadanie.PayloadHash)
	if po.CollectedApprovals != 1 {
		t.Fatalf("ta sama osoba policzona dwa razy: %d", po.CollectedApprovals)
	}

	druga := h.withToken(h.createPrincipal("druga-osoba-przestrzen",
		[]map[string]string{{"role": "platform_admin", "scope": "*"}}))
	po = druga.approve(zadanie.ID, zadanie.PayloadHash)
	if po.State != "queued" || po.CollectedApprovals != 2 {
		t.Fatalf("po drugiej zgodzie: stan = %s, zgod = %d", po.State, po.CollectedApprovals)
	}

	// Zadanie idzie na host i tam ma zostac odrzucone: urzadzenia nie ma.
	koncowe := h.awaitTerminal(zadanie.ID, 2*time.Minute)
	if koncowe.State == "succeeded" {
		t.Error("host wykonal operacje na urzadzeniu, ktorego nie ma")
	}
}

// TestOperacjaNiszczacaSprawdzaTozsamoscUrzadzenia pilnuje, ze formatowanie
// trafia w ten dysk, ktory operator ogladal. Sciezka /dev/sdX po restarcie
// wskazuje co innego.
func TestOperacjaNiszczacaSprawdzaTozsamoscUrzadzenia(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	stan := migawkaPrzestrzeniHosta(t, h, host.ID)

	var pusty urzadzenieView
	for _, urzadzenie := range stan.Devices {
		if urzadzenie.Type == "disk" && len(urzadzenie.Mountpoints) == 0 {
			// Dysk bez zamontowanych potomkow: sprawdzamy po drzewie.
			zajety := false
			for _, dziecko := range stan.Devices {
				if dziecko.Parent == urzadzenie.Path && len(dziecko.Mountpoints) > 0 {
					zajety = true
				}
			}
			if !zajety {
				pusty = urzadzenie
				break
			}
		}
	}
	if pusty.Path == "" {
		t.Skip("host nie ma wolnego dysku")
	}

	// Zla tozsamosc: host ma odmowic, zanim cokolwiek zrobi.
	zadanie := h.createOperation(host.ID, map[string]any{
		"action": "disk.wipe", "reason": powodPrzestrzeni,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"storage": map[string]any{
			"device": pusty.Path, "expected_size_bytes": 1024}},
	})
	h.approve(zadanie.ID, zadanie.PayloadHash)
	druga := h.withToken(h.createPrincipal("druga-osoba-tozsamosc",
		[]map[string]string{{"role": "platform_admin", "scope": "*"}}))
	druga.approve(zadanie.ID, zadanie.PayloadHash)

	koncowe := h.awaitTerminal(zadanie.ID, 2*time.Minute)
	if koncowe.State == "succeeded" {
		t.Fatalf("host wyczyscil %s mimo niezgodnego rozmiaru", pusty.Path)
	}
	proby := h.attempts(zadanie.ID)
	if !strings.Contains(ostatniKomunikat(proby), "bajtow") {
		t.Errorf("odmowa nie tlumaczy niezgodnosci: %q", ostatniKomunikat(proby))
	}
}

// TestOperacjaNiszczacaWymagaTozsamosci sprawdza, ze zlecenie bez zadnego
// identyfikatora urzadzenia nie dojezdza do hosta.
func TestOperacjaNiszczacaWymagaTozsamosci(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "disk.wipe", "reason": powodPrzestrzeni,
			"target_confirmation": host.Hostname,
			"payload":             map[string]any{"storage": map[string]any{"device": "/dev/sdb"}}},
		nil, http.StatusBadRequest)

	// Bez przepisanej nazwy hosta operacja niszczaca nie powstaje w ogole.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "disk.wipe", "reason": powodPrzestrzeni,
			"payload": map[string]any{"storage": map[string]any{
				"device": "/dev/sdb", "expected_size_bytes": 2147483648}}},
		nil, http.StatusBadRequest)
}
