package docker

import (
	"errors"
	"strings"
	"testing"
)

// stanTestowy sklada host z dwiema sieciami i dwoma wolumenami, z ktorych
// jeden jest montowany przez kontener zatrzymany.
func stanTestowy() Snapshot {
	return Snapshot{
		Containers: []Container{
			{
				ID: "aaaa000000000000", Name: "sklep-web-1", State: "running",
				Networks: []ContainerNetwork{{Name: "sklep_default", ID: "net-sklep", IPv4: "172.18.0.2"}},
				Mounts:   []Mount{{Type: "volume", Name: "sklep_dane", Destination: "/var/lib/dane"}},
			},
			{
				ID: "bbbb000000000000", Name: "sklep-db-1", State: "exited",
				Networks: []ContainerNetwork{{Name: "sklep_default", ID: "net-sklep"}},
				Mounts:   []Mount{{Type: "volume", Name: "sklep_baza", Destination: "/var/lib/postgresql"}},
			},
		},
		Networks: []Network{
			{ID: "net-bridge", Name: "bridge", Driver: "bridge", Predefined: true},
			{ID: "net-sklep", Name: "sklep_default", Driver: "bridge"},
			{ID: "net-stara", Name: "stara_siec", Driver: "bridge"},
		},
		Volumes: []Volume{
			{Name: "sklep_dane", Driver: "local"},
			{Name: "sklep_baza", Driver: "local"},
			{Name: "porzucony", Driver: "local"},
		},
	}
}

// TestUzycieSieciWynikaZKontenerow pilnuje najwazniejszej wlasciwosci tego
// widoku: silnik w liscie sieci zwraca pusta mape kontenerow, wiec bez
// wyliczenia z kontenerow kazda siec wygladalaby na porzucona - i trafilaby
// pod sprzatanie.
func TestUzycieSieciWynikaZKontenerow(t *testing.T) {
	stan := stanTestowy()
	powiazUzycie(&stan)

	sklep := siecPoID(stan.Networks, "net-sklep")
	if !sklep.InUse {
		t.Fatal("siec z dwoma kontenerami zglaszana jako nieuzywana")
	}
	if len(sklep.Containers) != 2 {
		t.Fatalf("kontenerow w sieci = %d", len(sklep.Containers))
	}
	// Kolejnosc jest ustalona, bo lista trafia wprost do widoku.
	if sklep.Containers[0].Name != "sklep-db-1" {
		t.Errorf("pierwszy kontener = %s", sklep.Containers[0].Name)
	}
	if stan.Networks[2].InUse {
		t.Error("siec bez kontenerow zglaszana jako uzywana")
	}
}

// TestWolumenZatrzymanegoKontenieraJestWUzyciu pilnuje granicy sprzatania:
// wolumen kontenera, ktory teraz nie dziala, nie jest wolumenem niczyim.
func TestWolumenZatrzymanegoKontenieraJestWUzyciu(t *testing.T) {
	stan := stanTestowy()
	powiazUzycie(&stan)

	baza := wolumenPoNazwie(stan.Volumes, "sklep_baza")
	if !baza.InUse {
		t.Fatal("wolumen zatrzymanego kontenera uznany za porzucony")
	}
	if len(baza.UsedBy) != 1 || baza.UsedBy[0].State != "exited" {
		t.Fatalf("uzycie wolumenu = %+v", baza.UsedBy)
	}
	if wolumenPoNazwie(stan.Volumes, "porzucony").InUse {
		t.Error("wolumen bez kontenerow zglaszany jako uzywany")
	}
}

// TestPodsumowanieLiczyKandydatowDoSprzatania pilnuje, ze licznik mowi
// o obiektach, ktore naprawde mozna usunac: siec wbudowana nie jest
// kandydatem, wiec nie moze podbijac licznika na kazdym hoscie.
func TestPodsumowanieLiczyKandydatowDoSprzatania(t *testing.T) {
	stan := stanTestowy()
	powiazUzycie(&stan)
	podsumowanie := podsumuj(stan, Summary{})

	if podsumowanie.NetworksUnused != 1 {
		t.Errorf("nieuzywanych sieci = %d, oczekiwano 1", podsumowanie.NetworksUnused)
	}
	if podsumowanie.VolumesUnused != 1 {
		t.Errorf("nieuzywanych wolumenow = %d, oczekiwano 1", podsumowanie.VolumesUnused)
	}
}

// TestSprzatanieOdmawiaObiektuWUzyciu pilnuje, ze host odmawia sam, zanim
// cokolwiek zniknie - i mowi, kto z obiektu korzysta.
func TestSprzatanieOdmawiaObiektuWUzyciu(t *testing.T) {
	stan := stanTestowy()
	powiazUzycie(&stan)

	err := sprawdzSprzatanie(stan, []string{"sklep_baza"}, nil)
	if !errors.Is(err, ErrWUzyciu) {
		t.Fatalf("usuniecie wolumenu w uzyciu dalo %v", err)
	}
	if !strings.Contains(err.Error(), "sklep-db-1") {
		t.Errorf("odmowa nie nazywa kontenera: %v", err)
	}

	err = sprawdzSprzatanie(stan, nil, []string{"net-sklep"})
	if !errors.Is(err, ErrWUzyciu) {
		t.Fatalf("usuniecie sieci w uzyciu dalo %v", err)
	}
}

func TestSprzatanieOdmawiaSieciWbudowanej(t *testing.T) {
	stan := stanTestowy()
	powiazUzycie(&stan)
	if err := sprawdzSprzatanie(stan, nil, []string{"net-bridge"}); !errors.Is(err, ErrSiecWbudowana) {
		t.Fatalf("usuniecie sieci wbudowanej dalo %v", err)
	}
}

// TestSprzatanieOdmawiaNieistniejacego pilnuje, ze operator nie zobaczy
// sukcesu operacji, ktora niczego nie usunela.
func TestSprzatanieOdmawiaNieistniejacego(t *testing.T) {
	stan := stanTestowy()
	powiazUzycie(&stan)
	if err := sprawdzSprzatanie(stan, []string{"nie-ma-takiego"}, nil); !errors.Is(err, ErrNieIstnieje) {
		t.Fatalf("usuniecie nieistniejacego wolumenu dalo %v", err)
	}
}

// TestSprzatanieSprawdzaCalaListeZGory pilnuje, ze zajety obiekt na koncu
// listy zatrzymuje operacje, zanim pierwszy zniknie: sprzatanie w polowie
// zostawiloby host w stanie, o ktory nikt nie prosil.
func TestSprzatanieSprawdzaCalaListeZGory(t *testing.T) {
	stan := stanTestowy()
	powiazUzycie(&stan)
	err := sprawdzSprzatanie(stan, []string{"porzucony", "sklep_dane"}, nil)
	if !errors.Is(err, ErrWUzyciu) {
		t.Fatalf("lista z zajetym wolumenem na koncu dala %v", err)
	}
}
