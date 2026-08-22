package freeipa

import "testing"

func TestLookupIgnorujeWielkoscLiter(t *testing.T) {
	// Katalog zwraca raz krbLastPwdChange, raz krblastpwdchange, zaleznie od
	// trybu odpowiedzi. Przypiecie sie do jednej pisowni konczy sie cichym
	// brakiem danych, a nie bledem.
	record := map[string]any{"krbLastPwdChange": []any{"20260822144537Z"}}
	if got := first(record, "krblastpwdchange"); got != "20260822144537Z" {
		t.Fatalf("odczytano %q, oczekiwano wartosci mimo innej pisowni", got)
	}
	if got := first(record, "nieistniejace"); got != "" {
		t.Fatalf("nieistniejace pole zwrocilo %q", got)
	}
}

func TestStringsObslugujeKsztaltyOdpowiedzi(t *testing.T) {
	// FreeIPA zwraca wartosci jako listy, ciagi albo obiekty base64.
	cases := map[string]struct {
		value any
		want  int
	}{
		"lista":  {[]any{"a", "b"}, 2},
		"ciag":   {"a", 1},
		"base64": {[]any{map[string]any{"__base64__": "zakodowane"}}, 1},
		"pusto":  {nil, 0},
		"liczba": {[]any{42}, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := strings_(map[string]any{"pole": tc.value}, "pole")
			if len(got) != tc.want {
				t.Fatalf("odczytano %d wartosci, oczekiwano %d", len(got), tc.want)
			}
		})
	}
}

func TestSudoRiskOznaczaReguleBezHasla(t *testing.T) {
	// NOPASSWD znosi potwierdzenie tozsamosci, a ALL daje pelne uprawnienia
	// roota. Dokument wymienia oba jako krytyczne.
	critical, reasons := sudoRisk(map[string]any{}, SudoRule{Options: []string{"!authenticate"}})
	if !critical {
		t.Fatal("regula bez potwierdzenia hasla nie zostala oznaczona jako krytyczna")
	}
	if len(reasons) == 0 {
		t.Fatal("brak opisu powodu")
	}
}

func TestSudoRiskOznaczaKategorieWszystko(t *testing.T) {
	cases := map[string]string{
		"cmdcategory":       "wszystkie polecenia",
		"hostcategory":      "wszystkie hosty",
		"usercategory":      "wszyscy uzytkownicy",
		"runasusercategory": "dowolny uzytkownik",
	}
	for field := range cases {
		t.Run(field, func(t *testing.T) {
			critical, reasons := sudoRisk(map[string]any{field: []any{"all"}}, SudoRule{})
			if !critical || len(reasons) == 0 {
				t.Fatalf("kategoria all w polu %s nie zostala oznaczona jako ryzykowna", field)
			}
		})
	}
}

func TestSudoRiskNieOznaczaZwyklejReguly(t *testing.T) {
	critical, reasons := sudoRisk(
		map[string]any{"cmdcategory": []any{}, "hostcategory": []any{}},
		SudoRule{Users: []string{"jkowalski"}, Commands: []string{"/usr/bin/systemctl"}},
	)
	if critical {
		t.Fatalf("zwykla regula oznaczona jako krytyczna: %v", reasons)
	}
}

func TestHostGroupsFromDNs(t *testing.T) {
	// W trybie surowym czlonkostwo przychodzi jako pelne DN-y; interesuja nas
	// wylacznie grupy hostow, nie role ani inne obiekty.
	dns := []string{
		"cn=ipaservers,cn=hostgroups,cn=accounts,dc=flotestro,dc=test",
		"cn=produkcja,cn=hostgroups,cn=accounts,dc=flotestro,dc=test",
		"cn=Flotestro Connector,cn=roles,cn=accounts,dc=flotestro,dc=test",
		"niepoprawny-dn",
	}
	groups := hostGroupsFromDNs(dns)
	if len(groups) != 2 {
		t.Fatalf("wyciagnieto %v, oczekiwano dwoch grup hostow", groups)
	}
	if groups[0] != "ipaservers" || groups[1] != "produkcja" {
		t.Fatalf("nieoczekiwane nazwy grup: %v", groups)
	}
}

func TestAllowedMethodJestZamknietaLista(t *testing.T) {
	// Adapter udostepnia wylacznie jawnie wspierane polecenia. Nie istnieje
	// sposob wywolania dowolnej komendy katalogu.
	for _, method := range []string{"user_find", "group_find", "hbacrule_find", "ping"} {
		if !allowedMethod(method) {
			t.Errorf("polecenie %s powinno byc dozwolone", method)
		}
	}
	for _, method := range []string{
		"user_del", "user_mod", "group_add", "config_mod",
		"permission_add", "", "user_find; drop",
	} {
		if allowedMethod(method) {
			t.Errorf("polecenie %s nie powinno byc dozwolone na etapie odczytu", method)
		}
	}
}

func TestSplitPrincipal(t *testing.T) {
	name, realm := splitPrincipal("flotestro/panel.flotestro.test@FLOTESTRO.TEST", "INNY")
	if name != "flotestro/panel.flotestro.test" || realm != "FLOTESTRO.TEST" {
		t.Fatalf("rozdzielono na %q i %q", name, realm)
	}
	name, realm = splitPrincipal("flotestro/panel.flotestro.test", "FLOTESTRO.TEST")
	if name != "flotestro/panel.flotestro.test" || realm != "FLOTESTRO.TEST" {
		t.Fatalf("brak realmu w principalu dal %q i %q", name, realm)
	}
}
