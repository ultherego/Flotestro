package monitoring

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestZlecenieWalidujeCel(t *testing.T) {
	dobre := []Zlecenie{
		{Kind: SondaHTTP, Target: "https://usluga.example.test/health"},
		{Kind: SondaHTTP, Target: "http://10.0.0.5:8080/", ExpectStatus: 204},
		{Kind: SondaTCP, Target: "baza.example.test:5432"},
	}
	for _, zlecenie := range dobre {
		if err := zlecenie.Waliduj(); err != nil {
			t.Errorf("poprawne zlecenie %+v odrzucone: %v", zlecenie, err)
		}
	}

	zle := map[string]Zlecenie{
		// Sonda mowi po HTTP; "file://" nie jest sprawdzeniem uslugi,
		// tylko czytaniem hosta cudzymi rekami.
		"plik lokalny":        {Kind: SondaHTTP, Target: "file:///etc/shadow"},
		"inny protokol":       {Kind: SondaHTTP, Target: "gopher://usluga.example.test"},
		"pusty cel":           {Kind: SondaHTTP, Target: ""},
		"tcp bez portu":       {Kind: SondaTCP, Target: "baza.example.test"},
		"nieznany rodzaj":     {Kind: "icmp", Target: "10.0.0.1"},
		"kod poza zakresem":   {Kind: SondaHTTP, Target: "https://a.test", ExpectStatus: 9000},
		"limit poza zakresem": {Kind: SondaTCP, Target: "a.test:1", TimeoutSeconds: 3600},
		"cel ze spacja":       {Kind: SondaTCP, Target: "a.test:1 b"},
	}
	for nazwa, zlecenie := range zle {
		if err := zlecenie.Waliduj(); err == nil {
			t.Errorf("%s: zlecenie zostalo przyjete", nazwa)
		}
	}
}

func TestSondaHTTPRozrozniaDostepnoscOdOczekiwan(t *testing.T) {
	serwer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blad" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte("wszystko dziala"))
	}))
	defer serwer.Close()

	// Usluga odpowiada tak, jak oczekiwano.
	wynik := Wykonaj(context.Background(), Zlecenie{
		Kind: SondaHTTP, Target: serwer.URL, ExpectBody: "dziala",
	})
	if !wynik.Reachable || !wynik.Passed {
		t.Fatalf("poprawna odpowiedz opisana jako %+v", wynik)
	}
	if wynik.StatusCode == nil || *wynik.StatusCode != 200 {
		t.Fatalf("kod odpowiedzi = %v", wynik.StatusCode)
	}

	// Usluga odpowiada, ale nie tak, jak oczekiwano - to dwie rozne rzeczy
	// i musza byc rozroznione, bo prowadza do innych decyzji.
	zlyKod := Wykonaj(context.Background(), Zlecenie{Kind: SondaHTTP, Target: serwer.URL + "/blad"})
	if !zlyKod.Reachable {
		t.Fatal("odpowiedz 500 opisana jako brak odpowiedzi")
	}
	if zlyKod.Passed || zlyKod.Error == "" {
		t.Fatalf("odpowiedz 500 opisana jako poprawna: %+v", zlyKod)
	}

	brakFragmentu := Wykonaj(context.Background(), Zlecenie{
		Kind: SondaHTTP, Target: serwer.URL, ExpectBody: "czegos takiego tam nie ma",
	})
	if brakFragmentu.Passed {
		t.Fatal("odpowiedz bez oczekiwanego fragmentu uznana za poprawna")
	}
	if brakFragmentu.BodyMatched == nil || *brakFragmentu.BodyMatched {
		t.Fatalf("dopasowanie tresci opisane jako %v", brakFragmentu.BodyMatched)
	}
}

func TestSondaHTTPNieUfaCertyfikatowiSpozaMagazynu(t *testing.T) {
	serwer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer serwer.Close()

	// Sonda nie wylacza sprawdzania certyfikatu: usluga z certyfikatem,
	// ktoremu host nie ufa, jest usluga, z ktorej ten host nie skorzysta.
	wynik := Wykonaj(context.Background(), Zlecenie{Kind: SondaHTTP, Target: serwer.URL})
	if wynik.Reachable || wynik.Passed {
		t.Fatalf("certyfikat spoza magazynu zaufania zostal przyjety: %+v", wynik)
	}
	if wynik.Error == "" {
		t.Fatal("odmowa nie ma powodu")
	}
}

func TestSondaTCPMowiCzyPolaczenieDoszlo(t *testing.T) {
	nasluch, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer nasluch.Close()
	go func() {
		for {
			polaczenie, err := nasluch.Accept()
			if err != nil {
				return
			}
			polaczenie.Close()
		}
	}()

	wynik := Wykonaj(context.Background(), Zlecenie{Kind: SondaTCP, Target: nasluch.Addr().String()})
	if !wynik.Reachable || !wynik.Passed {
		t.Fatalf("otwarty port opisany jako %+v", wynik)
	}

	// Port zamkniety: sonda konczy sie odpowiedzia "nie dziala", a nie bledem
	// wykonania - to jest wynik pomiaru, a nie awaria panelu.
	zamkniety := nasluch.Addr().String()
	nasluch.Close()
	time.Sleep(20 * time.Millisecond)
	wynikZamkniety := Wykonaj(context.Background(), Zlecenie{
		Kind: SondaTCP, Target: zamkniety, TimeoutSeconds: 2,
	})
	if wynikZamkniety.Reachable {
		t.Fatalf("zamkniety port opisany jako dostepny: %+v", wynikZamkniety)
	}
	if wynikZamkniety.Error == "" {
		t.Fatal("brak polaczenia nie ma powodu")
	}
}
