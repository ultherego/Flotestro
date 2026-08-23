package packages

import (
	"strings"
	"testing"
)

// Linie postepu dnf pochodza wprost z hosta testowego. Kolumna opisu jest
// dopelniana do stalej szerokosci, wiec raz zostaje przed procentem jedna
// spacja, a raz kilkanascie - wzorzec musi radzic sobie z obydwoma.
func TestKrokDnfRozpoznajeObieSzerokosciKolumny(t *testing.T) {
	przypadki := []struct {
		linia string
		krok  uint32
		total uint32
		opis  string
	}{
		{"[1/6] Verify package files              100% | 166.0   B/s |   2.0   B |  00m00s", 1, 6, "Verify package files"},
		{"[3/6] Upgrading tcpdump-14:4.99.6-2.fc4 100% |  36.0 MiB/s |   1.2 MiB |  00m00s", 3, 6, "Upgrading tcpdump-14:4.99.6-2.fc4"},
		{"[ 9/33] Upgrading samba-common-2:4.22.9 100% |   4.7 MiB/s | 218.1 KiB |  00m00s", 9, 33, "Upgrading samba-common-2:4.22.9"},
		{"[33/33] Removing NetworkManager-1:1.52. 100% |  21.0   B/s |  87.0   B |  00m04s", 33, 33, "Removing NetworkManager-1:1.52."},
	}
	for _, przypadek := range przypadki {
		postep, ok := krokDnf(przypadek.linia)
		if !ok {
			t.Errorf("nie rozpoznano linii: %q", przypadek.linia)
			continue
		}
		if postep.Step != przypadek.krok || postep.Total != przypadek.total {
			t.Errorf("%q: krok = %d/%d, oczekiwano %d/%d",
				przypadek.linia, postep.Step, postep.Total, przypadek.krok, przypadek.total)
		}
		if postep.Message != przypadek.opis {
			t.Errorf("%q: opis = %q, oczekiwano %q", przypadek.linia, postep.Message, przypadek.opis)
		}
	}
}

// Linia bez kolumny procentu tez niesie numer kroku.
func TestKrokDnfBezKolumnyProcentu(t *testing.T) {
	postep, ok := krokDnf("[2/4] Prepare transaction")
	if !ok || postep.Step != 2 || postep.Total != 4 {
		t.Fatalf("postep = %+v, ok = %v", postep, ok)
	}
}

// Zwykle wyjscie narzedzia nie moze udawac postepu.
func TestZwykleLinieNieSaKrokiem(t *testing.T) {
	for _, linia := range []string{
		"Error: Transaction failed",
		"[RPM] tcpdump-14:4.99.6-2.fc42.x86_64: install failed",
		"Upgrading tcpdump",
		"[0/0] nic",
	} {
		if postep, ok := krokDnf(linia); ok {
			t.Errorf("%q uznane za postep: %+v", linia, postep)
		}
	}
}

// Apt melduje postep wlasnym, maszynowym kanalem. Format to
// "rodzaj:pakiet:procent:opis" i jest niezalezny od szerokosci terminala
// oraz od locale - dlatego czytamy jego, a nie paskow z ekranu.
func TestStatusAptaJestParsowany(t *testing.T) {
	wejscie := strings.Join([]string{
		"dlstatus:1:20.0000:Pobieranie pliku 1 z 5",
		"pmstatus:dpkg-exec:0.0000:Running dpkg",
		"pmstatus:libc6:12.5000:Preparing libc6",
		"pmstatus:libc6:25.0000:Unpacking libc6",
		"nonsens bez dwukropkow",
		"pmstatus:zle:nieliczba:Opis",
	}, "\n")

	var zebrane []Progress
	throttle := &dlawik{odbiorca: func(p Progress) { zebrane = append(zebrane, p) }}
	// Kazdy meldunek dostaje wlasny znacznik czasu poza oknem dlawienia,
	// zeby test sprawdzal parsowanie, a nie ograniczanie tempa.
	czytajStatusAptaTest(strings.NewReader(wejscie), throttle)

	if len(zebrane) != 4 {
		t.Fatalf("zebrano %d meldunkow, oczekiwano 4: %+v", len(zebrane), zebrane)
	}
	if zebrane[0].Percent == nil || *zebrane[0].Percent != 20 {
		t.Errorf("pierwszy procent = %v", zebrane[0].Percent)
	}
	if zebrane[0].Message != "Downloading: Pobieranie pliku 1 z 5" {
		t.Errorf("opis pobierania = %q", zebrane[0].Message)
	}
	if zebrane[3].Percent == nil || *zebrane[3].Percent != 25 {
		t.Errorf("ostatni procent = %v", zebrane[3].Percent)
	}
}

// Postep nieustalony nie moze byc pokazany jako zero procent - pasek przy
// zerze wyglada jak praca, ktora stoi.
func TestBrakProcentuNieJestZerem(t *testing.T) {
	postep, ok := krokDnf("[2/4] Prepare transaction")
	if !ok {
		t.Fatal("nie rozpoznano kroku")
	}
	if postep.Percent != nil {
		t.Errorf("procent = %v, oczekiwano nieustalonego", *postep.Percent)
	}
}
