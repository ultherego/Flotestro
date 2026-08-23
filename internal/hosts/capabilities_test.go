package hosts

import "testing"

// Wymaganie operacji jest nazwa logiczna: aktualizacja nie ma wiedziec, czy
// host uzywa apta czy dnf-a.
func TestWymaganiePakietySpelniaKazdyMenedzer(t *testing.T) {
	apt := Capabilities{{Name: CapAPT, Version: 1, Available: true}}
	dnf := Capabilities{{Name: CapDNF, Version: 1, Available: true}}
	brak := Capabilities{
		{Name: CapAPT, Version: 1, Available: false},
		{Name: CapDNF, Version: 1, Available: false},
	}
	if !apt.Spelnia(WymaganiePakiety) || !dnf.Spelnia(WymaganiePakiety) {
		t.Error("obecny menedzer pakietow nie spelnil wymagania")
	}
	if brak.Spelnia(WymaganiePakiety) {
		t.Error("host bez menedzera pakietow spelnil wymaganie")
	}
}

// Naprawa bazy pakietow istnieje tylko dla apta. Host ma to powiedziec przy
// zlecaniu, a nie odrzucic zadanie po dostarczeniu.
func TestNaprawaWymagaCechyAdaptera(t *testing.T) {
	zNaprawa := Capabilities{{Name: CapAPT, Version: 1, Available: true,
		Features: map[string]bool{"repair": true}}}
	if !zNaprawa.Spelnia(WymaganieNaprawaPakietow) {
		t.Error("apt z cecha repair nie spelnil wymagania naprawy")
	}

	fedora := Capabilities{{Name: CapDNF, Version: 1, Available: true,
		Features: map[string]bool{"repair": false}}}
	if fedora.Spelnia(WymaganieNaprawaPakietow) {
		t.Error("dnf bez naprawy spelnil wymaganie naprawy")
	}

	bezNarzedzi := Capabilities{{Name: CapAPT, Version: 1, Available: true,
		Features: map[string]bool{"repair": false}}}
	if bezNarzedzi.Spelnia(WymaganieNaprawaPakietow) {
		t.Error("apt bez narzedzi debconfa spelnil wymaganie naprawy")
	}
}

// Agent sprzed rejestru nie przysyla cech. Milczenie nie moze odebrac hostowi
// operacji, ktora u niego dziala - to byloby uznanie niewiedzy za fakt.
func TestNieznanaCechaNieOdbieraOperacji(t *testing.T) {
	sprzedRejestru := Capabilities{{Name: CapAPT, Version: 0, Available: true}}
	if !sprzedRejestru.Spelnia(WymaganieNaprawaPakietow) {
		t.Error("host sprzed rejestru stracil naprawe pakietow")
	}

	wartosc, znana := sprzedRejestru.FeatureStan(CapAPT, "repair")
	if wartosc || znana {
		t.Errorf("cecha = %v, znana = %v; oczekiwano stanu nieustalonego", wartosc, znana)
	}
}

// Adapter, ktorego nie ma, na pewno nie ma zadnej czesci - i to jest wiedza,
// a nie jej brak.
func TestBrakAdapteraJestOdpowiedzia(t *testing.T) {
	rejestr := Capabilities{{Name: CapAPT, Version: 1, Available: false}}
	if wartosc, znana := rejestr.FeatureStan(CapAPT, "repair"); wartosc || !znana {
		t.Errorf("cecha = %v, znana = %v; oczekiwano znanego braku", wartosc, znana)
	}
	pusty := Capabilities{}
	if wartosc, znana := pusty.FeatureStan(CapDocker, "cokolwiek"); wartosc || !znana {
		t.Errorf("cecha = %v, znana = %v; oczekiwano znanego braku", wartosc, znana)
	}
}

// Powod niedostepnosci pochodzi z hosta i ma dotrzec do operatora bez zmian.
func TestPowodPochodziZHosta(t *testing.T) {
	rejestr := Capabilities{{Name: CapSystemd, Available: false,
		Reason: "this host does not run systemd"}}
	if got := rejestr.Reason(CapSystemd); got != "this host does not run systemd" {
		t.Errorf("powod = %q", got)
	}
	if got := rejestr.Reason(CapDocker); got != "" {
		t.Errorf("powod nieznanego adaptera = %q, oczekiwano pustego", got)
	}
}
