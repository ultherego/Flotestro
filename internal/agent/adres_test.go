package agent

import "testing"

// Adres do panelu wybiera tablica routingu, a nie lista interfejsow.
// Petla zwrotna jest osiagalna zawsze, wiec test nie zalezy od sieci labu.
func TestAdresDoPaneluWybieraAdresTrasy(t *testing.T) {
	if got := adresDoPanelu("https://127.0.0.1:8443"); got != "127.0.0.1" {
		t.Errorf("adres = %q, oczekiwano 127.0.0.1", got)
	}
}

// Nieustalony adres zostaje pusty. Panel woli nie znac adresu, niz pokazac
// operatorowi adres, pod ktorym hosta nie ma.
func TestAdresDoPaneluNieZgaduje(t *testing.T) {
	for _, url := range []string{"", "://bez-schematu", "https://"} {
		if got := adresDoPanelu(url); got != "" {
			t.Errorf("adresDoPanelu(%q) = %q, oczekiwano pustego", url, got)
		}
	}
}
