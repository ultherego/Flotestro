package gateway

import (
	"testing"

	"github.com/ultherego/flotestro/internal/hosts"
)

// Adres widziany przez panel na wlasnym koncu polaczenia jest najmocniejszym
// faktem, jaki ma o hoscie - ale tylko wtedy, gdy miedzy nimi nikogo nie ma.
func TestAdresZPolaczeniaBezposredniego(t *testing.T) {
	address, source := managementAddress("192.168.56.30:41234", "10.0.0.5", "")
	if address != "192.168.56.30" {
		t.Errorf("adres = %q, oczekiwano adresu z polaczenia", address)
	}
	if source != hosts.AddressFromSession {
		t.Errorf("zrodlo = %q, oczekiwano %q", source, hosts.AddressFromSession)
	}
}

// Za relayem panel widzi adres relaya. Podanie go jako adresu hosta byloby
// falszem, wiec liczy sie wylacznie deklaracja hosta.
func TestZaRelayemLiczySieDeklaracjaHosta(t *testing.T) {
	address, source := managementAddress("192.168.56.60:9000", "10.20.4.17", "b7c0-relay")
	if address != "10.20.4.17" {
		t.Errorf("adres = %q, oczekiwano adresu zadeklarowanego przez hosta", address)
	}
	if source != hosts.AddressFromAgent {
		t.Errorf("zrodlo = %q, oczekiwano %q", source, hosts.AddressFromAgent)
	}
}

// Brak obu zrodel zostawia adres nieustalony. Adres relaya nie moze podszyc
// sie pod adres hosta tylko dlatego, ze innego nie ma.
func TestBrakZrodelZostawiaAdresNieustalony(t *testing.T) {
	address, source := managementAddress("192.168.56.60:9000", "", "b7c0-relay")
	if address != "" || source != "" {
		t.Fatalf("adres = %q, zrodlo = %q; oczekiwano stanu nieustalonego", address, source)
	}
}

// Adres bez portu nie da sie rozdzielic. Zamiast zapisac smiec, zostaje
// deklaracja hosta albo stan nieustalony.
func TestNiepoprawnyAdresPolaczeniaNieJestZapisywany(t *testing.T) {
	address, source := managementAddress("bez-portu", "", "")
	if address != "" || source != "" {
		t.Fatalf("adres = %q, zrodlo = %q; oczekiwano stanu nieustalonego", address, source)
	}

	address, source = managementAddress("bez-portu", "10.20.4.17", "")
	if address != "10.20.4.17" || source != hosts.AddressFromAgent {
		t.Fatalf("adres = %q, zrodlo = %q; oczekiwano deklaracji hosta", address, source)
	}
}
