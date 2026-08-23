package docker

import "testing"

// Podsumowanie ma odpowiadac na pytanie "czy cos wymaga uwagi", a nie liczyc
// wszystko po kolei. Kontener wstajacy w kolko jest sprawny w kazdej
// pojedynczej chwili i mimo to zepsuty.
func TestPodsumowanieWykrywaPetleRestartow(t *testing.T) {
	snapshot := Snapshot{Containers: []Container{
		{Name: "spokojny", State: "running", RestartCount: 1},
		{Name: "wstaje-w-kolko", State: "running", RestartCount: 12},
		{Name: "wlasnie-wstaje", State: "restarting"},
	}}
	podsumowanie := podsumuj(snapshot, Summary{})

	if podsumowanie.RestartLooping != 2 {
		t.Errorf("petli restartow = %d, oczekiwano 2", podsumowanie.RestartLooping)
	}
	if podsumowanie.Running != 2 {
		t.Errorf("dzialajacych = %d, oczekiwano 2", podsumowanie.Running)
	}
	if podsumowanie.Stopped != 1 {
		t.Errorf("zatrzymanych = %d, oczekiwano 1 (restarting nie dziala)", podsumowanie.Stopped)
	}
}

// Kontenery Compose sa grupowane w projekty: operator zarzadza projektem,
// a nie pojedynczymi kontenerami, ktore Compose sam utworzyl.
func TestKontenerySaGrupowaneWProjekty(t *testing.T) {
	snapshot := Snapshot{Containers: []Container{
		{Name: "sklep-web-1", State: "running", Compose: &ComposeMembership{Project: "sklep", Service: "web"}},
		{Name: "sklep-db-1", State: "exited", Compose: &ComposeMembership{Project: "sklep", Service: "db"}},
		{Name: "sklep-web-2", State: "running", Compose: &ComposeMembership{Project: "sklep", Service: "web"}},
		{Name: "samotny", State: "running"},
	}}
	podsumowanie := podsumuj(snapshot, Summary{})

	if len(podsumowanie.Projects) != 1 {
		t.Fatalf("projektow = %d, oczekiwano 1", len(podsumowanie.Projects))
	}
	projekt := podsumowanie.Projects[0]
	if projekt.Name != "sklep" || projekt.Total != 3 || projekt.Running != 2 {
		t.Errorf("projekt = %+v", projekt)
	}
	if len(projekt.Services) != 2 {
		t.Errorf("uslugi = %v, oczekiwano dwoch unikalnych", projekt.Services)
	}
}

// Silnik niedostepny to nie to samo co host bez kontenerow. Pusta lista bez
// powodu wygladalaby jak porzadek na hoscie.
func TestBrakAdapteraNiesiePowod(t *testing.T) {
	snapshot := Collect(t.Context(), nil)
	if snapshot.Summary.UnavailableReason == "" {
		t.Error("brak adaptera nie zostal wyjasniony")
	}
	if snapshot.Summary.Containers != 0 || snapshot.Containers != nil {
		t.Error("nieodczytany stan nie moze udawac pustej listy")
	}
}

// Etykieta z nazwa sugerujaca poswiadczenie jest ukrywana. Inventory jest
// trwale i widoczne szerzej niz sam host.
func TestEtykietyZPoswiadczeniamiSaUkrywane(t *testing.T) {
	wynik := etykietyBezSekretow(map[string]string{
		"com.docker.compose.project": "sklep",
		"DB_PASSWORD":                "tajne",
		"api_key":                    "abc123",
		"opis":                       "zwykla etykieta",
	})
	if wynik["DB_PASSWORD"] != "[ukryte]" || wynik["api_key"] != "[ukryte]" {
		t.Errorf("poswiadczenia nie zostaly ukryte: %v", wynik)
	}
	if wynik["opis"] != "zwykla etykieta" || wynik["com.docker.compose.project"] != "sklep" {
		t.Errorf("zwykle etykiety zostaly zmienione: %v", wynik)
	}
}

// Compose oznacza swoje kontenery etykietami; kontener spoza projektu nie
// moze zostac do zadnego przypisany.
func TestPrzynaleznoscComposeTylkoZEtykiet(t *testing.T) {
	if przynaleznoscCompose(map[string]string{"cokolwiek": "x"}) != nil {
		t.Error("kontener bez etykiet Compose zostal przypisany do projektu")
	}
	czlonkostwo := przynaleznoscCompose(map[string]string{
		"com.docker.compose.project": "sklep",
		"com.docker.compose.service": "web",
	})
	if czlonkostwo == nil || czlonkostwo.Project != "sklep" || czlonkostwo.Service != "web" {
		t.Errorf("czlonkostwo = %+v", czlonkostwo)
	}
}
