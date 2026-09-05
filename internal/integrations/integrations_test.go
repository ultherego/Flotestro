package integrations

import (
	"errors"
	"testing"
	"time"
)

func TestObwodOtwieraSieDopieroPoSeriiBledow(t *testing.T) {
	teraz := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	obwod := NowyObwod()
	obwod.zegar = func() time.Time { return teraz }
	blad := errors.New("zrodlo milczy")

	// Jeden blad nie moze odciac zrodla: awarie bywaja chwilowe.
	for i := 0; i < ProgBledow-1; i++ {
		if err := obwod.Wykonaj(func() error { return blad }); !errors.Is(err, blad) {
			t.Fatalf("proba %d: %v", i, err)
		}
	}
	if obwod.Otwarty() {
		t.Fatal("bezpiecznik otworzyl sie przed progiem")
	}

	if err := obwod.Wykonaj(func() error { return blad }); !errors.Is(err, blad) {
		t.Fatalf("ostatnia proba: %v", err)
	}
	if !obwod.Otwarty() {
		t.Fatal("bezpiecznik nie otworzyl sie po serii bledow")
	}

	// Otwarty bezpiecznik odmawia od reki i ma wlasny blad: ekran, ktory
	// czeka po piec sekund na kazdy panel, jest ekranem bez uzytkownikow.
	wywolano := false
	err := obwod.Wykonaj(func() error { wywolano = true; return nil })
	if !errors.Is(err, ErrOtwartyObwod) {
		t.Fatalf("otwarty bezpiecznik zwrocil %v", err)
	}
	if wywolano {
		t.Fatal("otwarty bezpiecznik przepuscil wywolanie")
	}

	// Po przerwie probujemy ponownie; jedna udana odpowiedz zamyka obwod.
	teraz = teraz.Add(PrzerwaObwodu + time.Second)
	if err := obwod.Wykonaj(func() error { return nil }); err != nil {
		t.Fatalf("po przerwie: %v", err)
	}
	if obwod.Otwarty() {
		t.Fatal("bezpiecznik nie zamknal sie po udanej odpowiedzi")
	}
}

func TestMapowaniePodstawiaDaneHosta(t *testing.T) {
	mapowanie := DomyslneMapowanie()
	mapowanie.DashboardURL = "https://grafana.example.test/d/hosts?var-host={hostname}&var-site={site}"
	host := Host{ID: "abc", Hostname: "web-01", Site: "waw", Environment: "prod"}

	if etykieta := mapowanie.Etykieta(host); etykieta != "web-01:9100" {
		t.Fatalf("etykieta hosta = %q", etykieta)
	}
	if filtr := mapowanie.FiltrHosta(host); filtr != `instance="web-01:9100"` {
		t.Fatalf("filtr alertow = %q", filtr)
	}
	odnosniki := mapowanie.Dla(host)
	if odnosniki.Dashboard != "https://grafana.example.test/d/hosts?var-host=web-01&var-site=waw" {
		t.Fatalf("odnosnik do dashboardu = %q", odnosniki.Dashboard)
	}
	// Instalacja bez dashboardu nie dostaje odnosnika prowadzacego donikad.
	puste := DomyslneMapowanie()
	if puste.Dla(host).Dashboard != "" {
		t.Fatal("panel wymyslil odnosnik do dashboardu, ktorego nie ma")
	}
}
