package packages

import (
	"context"
	"strings"
	"time"
)

// Blocked opisuje pakiet blokujacy operacje pakietowe.
type Blocked struct {
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	Questions []Question `json:"questions,omitempty"`
}

// Question jest pytaniem konfiguracyjnym pakietu.
type Question struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Answered jest nieustalone, gdy nie udalo sie odczytac stanu pytania.
	Answered *bool `json:"answered,omitempty"`
}

// Answer jest odpowiedzia operatora na pytanie konfiguracyjne.
type Answer struct {
	Package  string
	Question string
	Type     string
	Value    string
}

// BlockedPackages opisuje pakiety, ktore blokuja transakcje, wraz z pytaniami
// konfiguracyjnymi bez odpowiedzi.
//
// Sama nazwa pakietu mowi, gdzie szukac; dopiero pytania mowia, jaka decyzje
// trzeba podjac. Panel ich nie rozstrzyga - przekazuje je operatorowi.
func (a *APT) BlockedPackages(ctx context.Context) []Blocked {
	blocked := a.blockedFromStatus()
	for index := range blocked {
		// Pytania konfiguracyjne czyta wylacznie root: baza debconfa nie jest
		// czytelna dla agenta. Ich brak w planie nie oznacza wiec, ze pytan
		// nie ma - operator zobaczy je przy naprawie, ktora idzie przez
		// helpera.
		blocked[index].Questions = a.questions(ctx, blocked[index].Name)
	}
	return blocked
}

// questions czyta pytania konfiguracyjne pakietu. Gwiazdka przed nazwa oznacza
// pytanie z udzielona odpowiedzia; brak narzedzia debconf daje pusta liste,
// a nie zmyslona informacje o braku pytan.
func (a *APT) questions(ctx context.Context, pakiet string) []Question {
	result := run(ctx, 30*time.Second, debconfShowPath, pakiet)
	if !result.Ran || result.ExitCode != 0 {
		return nil
	}
	var pytania []Question
	for _, linia := range strings.Split(result.Stdout, "\n") {
		trimmed := strings.TrimSpace(linia)
		if trimmed == "" {
			continue
		}
		odpowiedziane := strings.HasPrefix(trimmed, "*")
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "*"))
		nazwa, wartosc, _ := strings.Cut(trimmed, ":")
		stan := odpowiedziane
		pytania = append(pytania, Question{
			Name:     strings.TrimSpace(nazwa),
			Value:    strings.TrimSpace(wartosc),
			Answered: &stan,
		})
	}
	return pytania
}

// Repair ustawia odpowiedzi operatora i konczy konfiguracje pakietow.
//
// Odpowiedzi dotycza wylacznie pakietow, ktore faktycznie blokuja operacje.
// Bez tego ograniczenia operacja bylaby dowolnym ustawianiem konfiguracji
// dowolnego pakietu na hoscie, czyli tym, czego kontrakt operacji typowanych
// ma nie dopuszczac.
func (a *APT) Repair(ctx context.Context, answers []Answer) ([]string, []Blocked, error) {
	blokujace := map[string]bool{}
	for _, pakiet := range a.PackagesNeedingAttention(ctx) {
		blokujace[pakiet] = true
	}

	var ustawione []string
	var linie []string
	for _, answer := range answers {
		if !blokujace[answer.Package] {
			return nil, nil, ErrPackageNotBlocked
		}
		if strings.ContainsAny(answer.Question+answer.Type+answer.Value, "\n\r") {
			return nil, nil, ErrInvalidAnswer
		}
		linie = append(linie, strings.Join(
			[]string{answer.Package, answer.Question, answer.Type, answer.Value}, " "))
		// Nazwa pytania zawiera juz pakiet, wiec sklejanie ich dawalo
		// etykiete w rodzaju grub-pc/grub-pc/install_devices.
		ustawione = append(ustawione, answer.Question)
	}

	if len(linie) > 0 {
		result := runWithInput(ctx, time.Minute, strings.Join(linie, "\n")+"\n", debconfSetPath)
		if !result.Ran || result.ExitCode != 0 {
			return nil, nil, errorf("debconf-set-selections: %s", result.Reason())
		}
	}

	// Dokonczenie konfiguracji jest tu jedyna zmiana stanu: nie instalujemy
	// ani nie usuwamy niczego.
	result := run(ctx, 15*time.Minute, dpkgPath, "--configure", "-a")
	pozostale := a.BlockedPackages(ctx)
	if !result.Ran || result.ExitCode != 0 {
		return ustawione, pozostale, errorf("dpkg --configure -a: %s", result.Reason())
	}
	return ustawione, pozostale, nil
}
