package freeipa

import "testing"

func TestRecordSpecWalidujeTypIWartosc(t *testing.T) {
	dobre := []RecordSpec{
		{Zone: "flotestro.test", Name: "web", Type: RekordA, Value: "10.0.0.5"},
		{Zone: "flotestro.test", Name: "web6", Type: RekordAAAA, Value: "2001:db8::5"},
		{Zone: "flotestro.test", Name: "alias", Type: RekordCNAME, Value: "web.flotestro.test."},
		{Zone: "flotestro.test", Name: "@", Type: RekordTXT, Value: "v=spf1 -all"},
		{Zone: "flotestro.test", Name: "_ldap._tcp", Type: RekordSRV, Value: "0 100 389 ipa.flotestro.test."},
	}
	for _, spec := range dobre {
		if err := spec.Validate(); err != nil {
			t.Errorf("poprawny rekord %+v odrzucony: %v", spec, err)
		}
	}

	zle := map[string]RecordSpec{
		// Adres w rekordzie A musi byc adresem IPv4: nazwa w tym miejscu
		// tworzy rekord, ktory nigdy nie zadziala.
		"A z nazwa":         {Zone: "flotestro.test", Name: "web", Type: RekordA, Value: "web.example.test"},
		"A z adresem IPv6":  {Zone: "flotestro.test", Name: "web", Type: RekordA, Value: "2001:db8::5"},
		"AAAA z IPv4":       {Zone: "flotestro.test", Name: "web", Type: RekordAAAA, Value: "10.0.0.5"},
		"pusta wartosc":     {Zone: "flotestro.test", Name: "web", Type: RekordA},
		"nieznany typ":      {Zone: "flotestro.test", Name: "web", Type: "NS", Value: "ipa.flotestro.test."},
		"zla strefa":        {Zone: "flotestro test", Name: "web", Type: RekordA, Value: "10.0.0.5"},
		"nazwa ze spacja":   {Zone: "flotestro.test", Name: "we b", Type: RekordA, Value: "10.0.0.5"},
		"TTL poza zakresem": {Zone: "flotestro.test", Name: "web", Type: RekordA, Value: "10.0.0.5", TTL: -1},
		"SRV bez pol":       {Zone: "flotestro.test", Name: "_ldap._tcp", Type: RekordSRV, Value: "389 ipa"},
		"nowa linia":        {Zone: "flotestro.test", Name: "web", Type: RekordTXT, Value: "a\nb"},
	}
	for nazwa, spec := range zle {
		if err := spec.Validate(); err == nil {
			t.Errorf("%s: rekord zostal przyjety", nazwa)
		}
	}
}

func TestStrefaOdwrotnaLiczyNazweIStrefe(t *testing.T) {
	strefa, nazwa, err := StrefaOdwrotna("192.168.56.10")
	if err != nil {
		t.Fatalf("StrefaOdwrotna: %v", err)
	}
	if strefa != "56.168.192.in-addr.arpa" || nazwa != "10" {
		t.Fatalf("IPv4: strefa=%q nazwa=%q", strefa, nazwa)
	}

	strefa, nazwa, err = StrefaOdwrotna("2001:db8::1")
	if err != nil {
		t.Fatalf("StrefaOdwrotna IPv6: %v", err)
	}
	// Strefa obejmuje pierwsze 64 bity, nazwa - pozostale.
	if strefa != "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Fatalf("IPv6: strefa=%q", strefa)
	}
	if nazwa != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0" {
		t.Fatalf("IPv6: nazwa=%q", nazwa)
	}

	if _, _, err := StrefaOdwrotna("to nie jest adres"); err == nil {
		t.Fatal("nazwa zostala przyjeta jako adres")
	}
}

func TestRekordFQDNSkladaNazwe(t *testing.T) {
	rekord := Rekord{Zone: "flotestro.test", Name: "web"}
	if rekord.FQDN() != "web.flotestro.test" {
		t.Fatalf("FQDN = %q", rekord.FQDN())
	}
	// Wpis w korzeniu strefy zapisuje sie jako "@" i nie moze dac nazwy
	// zaczynajacej sie kropka.
	korzen := Rekord{Zone: "flotestro.test", Name: "@"}
	if korzen.FQDN() != "flotestro.test" {
		t.Fatalf("FQDN korzenia = %q", korzen.FQDN())
	}
}

func TestPoleceniaDNSSaNaLiscieDozwolonych(t *testing.T) {
	// Adapter nie ma sposobu wywolania dowolnego polecenia katalogu, wiec
	// kazda nowa operacja musi byc dopisana swiadomie.
	for _, metoda := range []string{"dnszone_find", "dnsrecord_find", "dnsrecord_add", "dnsrecord_del"} {
		if !allowedMethod(metoda) {
			t.Errorf("polecenie %s nie jest dozwolone", metoda)
		}
	}
	// Polecen zmieniajacych sama strefe nie ma i byc nie powinno.
	for _, metoda := range []string{"dnszone_add", "dnszone_del", "dnszone_mod", "dnsconfig_mod"} {
		if allowedMethod(metoda) {
			t.Errorf("polecenie %s nie powinno byc dozwolone", metoda)
		}
	}
}
