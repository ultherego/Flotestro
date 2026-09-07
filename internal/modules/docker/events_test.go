package docker

import (
	"testing"
	"time"
)

// TestOknoOdczytuJestDomykane pilnuje wlasciwosci, dla ktorej ta operacja
// w ogole moze istniec: zamowienie spoza granic zostaje przyciete, wiec
// zadanie zawsze sie konczy. Odczyt bez konca zostalby na hoscie na zawsze.
func TestOknoOdczytuJestDomykane(t *testing.T) {
	opcje := domknijOpcje(EventsOptions{
		Since:  7 * 24 * time.Hour,
		Follow: time.Hour,
		Max:    100000,
	})
	if opcje.Since != MaksymalneOknoZdarzen {
		t.Errorf("okno wstecz = %s", opcje.Since)
	}
	if opcje.Follow != MaksymalneSledzenieZdarzen {
		t.Errorf("sledzenie = %s", opcje.Follow)
	}
	if opcje.Max != MaksymalnieZdarzen {
		t.Errorf("limit zdarzen = %d", opcje.Max)
	}
}

// TestBrakZamowieniaDajeDomyslneOkno pilnuje, ze najczestsza droga - "pokaz,
// co sie tu dzialo" - nie wymaga niczego od operatora, a mimo to jest
// ograniczona.
func TestBrakZamowieniaDajeDomyslneOkno(t *testing.T) {
	opcje := domknijOpcje(EventsOptions{})
	if opcje.Since != domyslneOknoZdarzen {
		t.Errorf("domyslne okno = %s", opcje.Since)
	}
	if opcje.Follow != 0 {
		t.Errorf("domyslne sledzenie = %s, a zadanie ma konczyc sie od razu", opcje.Follow)
	}
	if opcje.Max != domyslnieZdarzen {
		t.Errorf("domyslny limit = %d", opcje.Max)
	}
	if len(opcje.Types) != len(RodzajeZdarzen) {
		t.Errorf("domyslne rodzaje = %v", opcje.Types)
	}
}

// TestNieznaneRodzajeSaPomijane pilnuje granicy filtra: rodzaj jedzie do
// Engine API, wiec lista jest zamknieta. Zdarzenia demona i wtyczek nie sa
// odpowiedzia na zadne pytanie tej zakladki.
func TestNieznaneRodzajeSaPomijane(t *testing.T) {
	opcje := domknijOpcje(EventsOptions{Types: []string{"daemon", "plugin", "Container", "container"}})
	if len(opcje.Types) != 1 || opcje.Types[0] != "container" {
		t.Fatalf("rodzaje = %v", opcje.Types)
	}
}

// TestZdarzenieNiesieTylkoWybraneAtrybuty pilnuje, ze dziennik zdarzen nie
// staje sie droga wycieku: silnik dokleda do zdarzenia wszystkie etykiety
// obiektu, a w etykiecie bywa wpisany token.
func TestZdarzenieNiesieTylkoWybraneAtrybuty(t *testing.T) {
	linia := []byte(`{"Type":"container","Action":"die","Actor":{"ID":"abc123",
		"Attributes":{"name":"sklep-web-1","image":"nginx:alpine","exitCode":"137",
		"api_token":"sekret-ktory-nie-moze-wyjsc",
		"com.docker.compose.project":"sklep"}},"timeNano":1700000000000000000}`)

	zdarzenie, ok := zdarzenieZLinii(linia)
	if !ok {
		t.Fatal("zdarzenie nieodczytane")
	}
	if zdarzenie.Type != "container" || zdarzenie.Action != "die" {
		t.Fatalf("zdarzenie = %+v", zdarzenie)
	}
	if zdarzenie.ActorName != "sklep-web-1" {
		t.Errorf("nazwa aktora = %q", zdarzenie.ActorName)
	}
	if zdarzenie.Attributes["exitCode"] != "137" {
		t.Errorf("kod wyjscia = %q", zdarzenie.Attributes["exitCode"])
	}
	if _, jest := zdarzenie.Attributes["api_token"]; jest {
		t.Error("zdarzenie wyniosloby etykiete spoza listy")
	}
	if zdarzenie.Time.IsZero() {
		t.Error("zdarzenie bez czasu")
	}
}

// TestZdarzenieBezRodzajuJestPomijane pilnuje, ze linia, ktorej nie da sie
// zrozumiec, nie staje sie pustym wpisem w dzienniku.
func TestZdarzenieBezRodzajuJestPomijane(t *testing.T) {
	for _, linia := range []string{"", "{}", "nie-json", `{"Action":"die"}`} {
		if _, ok := zdarzenieZLinii([]byte(linia)); ok {
			t.Errorf("linia %q uznana za zdarzenie", linia)
		}
	}
}
