package packages

import "testing"

// TestPolicyRozpoznajePochodzenie pilnuje reguly, na ktorej stoi pokrycie
// oceny podatnosci dla rodziny APT.
//
// dpkg nie zapisuje przy pakiecie producenta - zna go tylko APT z list
// pakietow. Bez tego pakiet z obcego repozytorium wygladalby jak pakiet
// dystrybucji i liczylby sie jako objety jej ustaleniami, choc producent nie
// ma o nim nic do powiedzenia.
func TestPolicyRozpoznajePochodzenie(t *testing.T) {
	wyjscie := `openssl:
  Installed: 3.0.15-1~deb12u1
  Candidate: 3.0.15-1~deb12u1
  Version table:
 *** 3.0.15-1~deb12u1 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
        100 /var/lib/dpkg/status
     3.0.11-1~deb12u2 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
nginx:
  Installed: 1.27.0-1~bookworm
  Candidate: 1.27.0-1~bookworm
  Version table:
 *** 1.27.0-1~bookworm 500
        500 http://nginx.org/packages/debian bookworm/nginx amd64 Packages
        100 /var/lib/dpkg/status
wlasny-agent:
  Installed: 0.9.1
  Candidate: 0.9.1
  Version table:
 *** 0.9.1 100
        100 /var/lib/dpkg/status
linux-image-6.12.43+deb13-amd64:
  Installed: 6.12.43-1
  Candidate: 6.12.43-1
  Version table:
 *** 6.12.43-1 100
        100 /var/lib/dpkg/status
linux-image-amd64:
  Installed: 6.12.43-1
  Candidate: 6.12.48-1
  Version table:
     6.12.48-1 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
 *** 6.12.43-1 100
        100 /var/lib/dpkg/status
nieobecny:
  Installed: (none)
  Candidate: 1.0-1
  Version table:
     1.0-1 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
`
	wynik := ParsujPolicyAPT(wyjscie)

	oczekiwane := map[string]WpisPochodzenia{
		"openssl":      {Origin: "http://deb.debian.org/debian", Class: OriginDistribution},
		"nginx":        {Origin: "http://nginx.org/packages/debian", Class: OriginThirdParty},
		"wlasny-agent": {Origin: "/var/lib/dpkg/status", Class: OriginLocal},
		// Wersja wycofana z repozytorium wyglada w policy tak samo jak pakiet
		// zbudowany lokalnie - a to jest stare jadro, ktore lezy na dysku po
		// aktualizacji. Wypchniete poza pokrycie ukrywaloby dokladnie te
		// podatnosci, ktore najbardziej trzeba widziec.
		"linux-image-amd64": {Origin: "http://deb.debian.org/debian",
			Class: OriginDistribution},
	}
	for nazwa, chciane := range oczekiwane {
		if wynik[nazwa] != chciane {
			t.Errorf("%s: pochodzenie = %+v, oczekiwano %+v", nazwa, wynik[nazwa], chciane)
		}
	}
	// Pakiet niezainstalowany nie ma wersji zainstalowanej, wiec nie ma tez
	// pochodzenia - i nie moze go dostac z wiersza cudzej wersji.
	if _, jest := wynik["nieobecny"]; jest {
		t.Errorf("pakiet niezainstalowany dostal pochodzenie: %+v", wynik["nieobecny"])
	}
	// Pakiet, ktorego zadnej wersji nie ma juz w repozytoriach, zostaje
	// lokalny: nie ma po czym poznac, skad przyszedl.
	wersjonowane := wynik["linux-image-6.12.43+deb13-amd64"]
	if wersjonowane.Class != OriginLocal {
		t.Errorf("pakiet bez ani jednego zrodla = %+v", wersjonowane)
	}
}

// TestBrakPochodzeniaJestNieznanym pilnuje, zeby nieodczytane pochodzenie
// zostawalo nieznanym, a nie stawalo sie pakietem dystrybucji.
func TestBrakPochodzeniaJestNieznanym(t *testing.T) {
	if wpis := KlasaZrodlaAPT(""); wpis.Class != OriginUnknown {
		t.Errorf("pusty wiersz zrodla = %+v", wpis)
	}
	if wpis := KlasaZrodlaAPT("500 http://ppa.example.net/x ./ Packages"); wpis.Class != OriginThirdParty {
		t.Errorf("obce repozytorium = %+v", wpis)
	}
}
