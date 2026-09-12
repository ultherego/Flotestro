package adminapi

import (
	"context"
	"time"

	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Powody, dla ktorych host z migawki nie wykona operacji. Kazdy jest osobna
// odpowiedzia: host w oknie serwisowym wroci sam, host bez adaptera nie wroci
// nigdy, a host, o ktorym panel nic nie wie, wymaga odczytu, a nie decyzji.
const (
	// PowodSerwis oznacza host w oknie serwisowym: ktos przy nim pracuje.
	PowodSerwis = "maintenance"
	// PowodBrakZdolnosci oznacza host bez adaptera wymaganego przez operacje.
	PowodBrakZdolnosci = "capability_missing"
	// PowodKwarantanna oznacza host odciety od zarzadzania.
	PowodKwarantanna = "quarantined"
	// PowodNieznanaZdolnosc oznacza host, ktory nie zglosil jeszcze rejestru
	// adapterow. To nie jest brak zdolnosci - to brak wiedzy, i lekiem na
	// niego jest odczyt inwentarza, a nie wykluczenie z kampanii.
	PowodNieznanaZdolnosc = "capability_unknown"
	// PowodPozaZakresem oznacza host poza zakresem uprawnien operatora.
	PowodPozaZakresem = "out_of_scope"
	// PowodKolizja oznacza host, ktory jest juz celem innej trwajacej
	// kampanii. Nie blokuje zamowienia - blokady zasobow i tak ustawia
	// operacje w kolejce - ale operator ma to wiedziec przed startem.
	PowodKolizja = "conflict"
	// PowodOffline oznacza host niepodlaczony. Kampania na niego czeka,
	// zamiast go wykluczac: host wroci i wykona swoja czesc.
	PowodOffline = "offline"
)

// grupaHostow zbiera hosty o wspolnym powodzie.
type grupaHostow struct {
	Powod  string   `json:"reason"`
	Liczba int      `json:"count"`
	Probka []string `json:"sample"`
}

// kwalifikacja jest rozstrzygnieciem, ktore hosty migawki naprawde ruszaja.
//
// Jedna funkcja liczy to dla podgladu i dla utworzenia kampanii. Rozjazd
// miedzy nimi bylby najgorszym rodzajem bledu: operator widzialby na ekranie
// inna kampanie niz ta, ktora zatwierdza.
type kwalifikacja struct {
	Gotowe []hosts.Host
	// Zamkniete to hosty, ktore wchodza do migawki juz zamkniete. Kolejnosc
	// odpowiada Gotowym: to jedna lista celow, nie dwie kampanie.
	Zamkniete []zamknietyHost
	// Uwagi nie wykluczaja hosta - opisuja to, co operator ma wiedziec, zanim
	// zatwierdzi. Host offline wroci, host w kolizji poczeka na blokade.
	Uwagi []grupaHostow
}

// zamknietyHost jest hostem w migawce, ktory nie ruszy.
type zamknietyHost struct {
	Host  hosts.Host
	Stan  campaigns.TargetState
	Powod string
	Opis  string
}

// oceniKandydatow rozstrzyga kazdy host wobec operacji.
//
// Kolejnosc ma znaczenie: mowimy o najpowazniejszej przeszkodzie, a nie
// o pierwszej napotkanej. Kwarantanna wyprzedza okno serwisowe, bo host
// odciety od zarzadzania nie wroci sam po godzinie.
func oceniKandydatow(kandydaci []hosts.Host, action opspec.ActionType,
	kolizje map[string]string, teraz time.Time) kwalifikacja {
	wynik := kwalifikacja{}
	wymaganie := action.RequiredCapability()
	offline := grupaHostow{Powod: PowodOffline}
	wKolizji := grupaHostow{Powod: PowodKolizja}
	nieznane := grupaHostow{Powod: PowodNieznanaZdolnosc}

	for _, host := range kandydaci {
		switch {
		case host.LifecycleState == "quarantined":
			wynik.zamknij(host, campaigns.TargetIneligible, PowodKwarantanna,
				"host jest w kwarantannie i nie przyjmuje operacji")
			continue
		case host.Maintenance.Active(teraz):
			wynik.zamknij(host, campaigns.TargetSkipped, PowodSerwis,
				"host jest w oknie serwisowym do "+host.Maintenance.Until.Format(time.RFC3339))
			continue
		}

		// Host, ktory nie zglosil jeszcze rejestru adapterow, nie jest hostem
		// bez adapterow. Wpuszczamy go i mowimy o tym wprost: rozstrzygnie
		// preflight na samym hoscie.
		if wymaganie != "" && len(host.Capabilities) == 0 {
			dodaj(&nieznane, host)
		} else if wymaganie != "" && !host.Capabilities.Satisfies(wymaganie) {
			wynik.zamknij(host, campaigns.TargetIneligible, PowodBrakZdolnosci,
				"host nie ma adaptera wymaganego przez te operacje: "+wymaganie)
			continue
		}

		if host.ConnectionState != "online" {
			dodaj(&offline, host)
		}
		if kolizje[host.ID] != "" {
			dodaj(&wKolizji, host)
		}
		wynik.Gotowe = append(wynik.Gotowe, host)
	}

	for _, grupa := range []grupaHostow{offline, wKolizji, nieznane} {
		if grupa.Liczba > 0 {
			wynik.Uwagi = append(wynik.Uwagi, grupa)
		}
	}
	return wynik
}

// Niepewne wylicza hosty, ktore nie wykonaja zmiany teraz: zamkniete
// w migawce i te, na ktore kampania dopiero czeka.
//
// Dla wiekszosci operacji to sa tylko uwagi. Dla zmiany, ktora obowiazuje
// cala flote naraz, sa powodem, zeby jej nie zaczynac.
func (k kwalifikacja) Niepewne() []grupaHostow {
	grupy := k.Wykluczenia()
	for _, uwaga := range k.Uwagi {
		if uwaga.Powod == PowodOffline || uwaga.Powod == PowodNieznanaZdolnosc {
			grupy = append(grupy, uwaga)
		}
	}
	return grupy
}

func (k *kwalifikacja) zamknij(host hosts.Host, stan campaigns.TargetState, powod, opis string) {
	k.Zamkniete = append(k.Zamkniete, zamknietyHost{
		Host: host, Stan: stan, Powod: powod, Opis: opis,
	})
}

// Wykluczenia grupuje zamkniete hosty po powodzie.
func (k kwalifikacja) Wykluczenia() []grupaHostow {
	kolejnosc := []string{}
	wedlugPowodu := map[string]*grupaHostow{}
	for _, wpis := range k.Zamkniete {
		grupa, mamy := wedlugPowodu[wpis.Powod]
		if !mamy {
			grupa = &grupaHostow{Powod: wpis.Powod}
			wedlugPowodu[wpis.Powod] = grupa
			kolejnosc = append(kolejnosc, wpis.Powod)
		}
		dodaj(grupa, wpis.Host)
	}
	grupy := make([]grupaHostow, 0, len(kolejnosc))
	for _, powod := range kolejnosc {
		grupy = append(grupy, *wedlugPowodu[powod])
	}
	return grupy
}

// Cele sklada migawke kampanii: hosty gotowe i zamkniete w jednej liscie.
func (k kwalifikacja) Cele() []campaigns.TargetHost {
	cele := make([]campaigns.TargetHost, 0, len(k.Gotowe)+len(k.Zamkniete))
	for _, host := range k.Gotowe {
		cele = append(cele, campaigns.TargetHost{ID: host.ID, BootID: host.BootID})
	}
	for _, wpis := range k.Zamkniete {
		cele = append(cele, campaigns.TargetHost{
			ID: wpis.Host.ID, BootID: wpis.Host.BootID,
			State: wpis.Stan, Reason: wpis.Powod, Message: wpis.Opis,
		})
	}
	return cele
}

// dodaj dopisuje host do grupy, trzymajac probke krotka.
//
// Probka jest probka i tak sie nazywa: liczba mowi o calosci, a nazwy sa po
// to, zeby operator rozpoznal, o ktore maszyny chodzi.
func dodaj(grupa *grupaHostow, host hosts.Host) {
	grupa.Liczba++
	if len(grupa.Probka) < rozmiarProbkiPodgladu {
		grupa.Probka = append(grupa.Probka, host.Hostname)
	}
}

// aktywneKolizje mowi, ktore hosty sa juz celami trwajacych kampanii.
func (s *Server) aktywneKolizje(ctx context.Context) map[string]string {
	kolizje, err := s.campaigns.ActiveTargets(ctx)
	if err != nil {
		// Brak tej wiedzy nie zatrzymuje zamowienia: kolizja jest uwaga,
		// a nie wykluczeniem. Milczymy o niej, zamiast zmyslac.
		s.log.Error("nie odczytano celow trwajacych kampanii", "err", err)
		return nil
	}
	return kolizje
}
