package compose

import (
	"context"
	"fmt"
	"strings"
)

// Executor wdraza projekt na hoscie.
type Executor struct {
	Planner Planner
}

// ErrPlanMismatch oznacza, ze stan podstawy zmienil sie od zatwierdzenia.
var ErrPlanMismatch = fmt.Errorf("plan wdrozenia zmienil sie od zatwierdzenia")

// Deploy wdraza manifest, ale wylacznie ten, ktory operator zatwierdzil.
//
// Digest jest liczony ponownie tuz przed wdrozeniem. Zgodnosc oznacza, ze
// manifest i obrazy sa te same, ktore operator obejrzal; roznica oznacza, ze
// wdrozenie przynioslo by cos innego - i wtedy odmowa jest wlasciwa reakcja,
// a nie wykonanie czegos, czego nikt nie zatwierdzil.
func (e Executor) Deploy(ctx context.Context, project, manifest, expectedDigest string) (Result, error) {
	wynik := Result{Project: project}

	plan, err := e.Planner.Plan(ctx, project, manifest)
	if err != nil {
		return wynik, err
	}
	wynik.Digest = plan.Digest
	if expectedDigest != "" && !strings.EqualFold(plan.Digest, expectedDigest) {
		return wynik, fmt.Errorf("%w: zatwierdzono %s, teraz %s",
			ErrPlanMismatch, skroc(expectedDigest), skroc(plan.Digest))
	}
	wynik.Before = e.stanProjektu(ctx, project)

	sciezka, sprzataj, err := e.Planner.zapiszManifest(project, manifest)
	if err != nil {
		return wynik, err
	}
	defer sprzataj()

	// --remove-orphans usuwa kontenery, ktorych manifest juz nie opisuje.
	// Bez tego projekt rozjezdza sie ze swoim opisem po kazdej zmianie,
	// a operator zatwierdzil stan docelowy, a nie dopisanie do biezacego.
	stdout, stderr, err := e.Planner.Runner(ctx,
		"-p", project, "-f", sciezka, "up", "-d", "--remove-orphans")
	wynik.Applied = zmianyZSuchegoPrzebiegu(stdout + "\n" + stderr)
	wynik.After = e.stanProjektu(ctx, project)
	if err != nil {
		wynik.Output = koncowkaWyjscia(stderr, stdout)
		return wynik, fmt.Errorf("compose up: %s", pierwszaLinia(stderr))
	}
	return wynik, nil
}

// stanProjektu odczytuje uslugi projektu dzialajace na hoscie. Nieudany
// odczyt zwraca pustke, a nie blad: stan przed i po jest dodatkiem do wyniku,
// a nie warunkiem jego powstania.
func (e Executor) stanProjektu(ctx context.Context, project string) []Service {
	stdout, _, err := e.Planner.Runner(ctx, "-p", project, "ps", "--format", "json", "--all")
	if err != nil {
		return nil
	}
	return uslugiZListy(stdout)
}

// koncowkaWyjscia zwraca ostatnie linie wyjscia narzedzia.
func koncowkaWyjscia(stderr, stdout string) []string {
	zrodlo := strings.TrimSpace(stderr)
	if zrodlo == "" {
		zrodlo = strings.TrimSpace(stdout)
	}
	var linie []string
	for _, linia := range strings.Split(zrodlo, "\n") {
		if linia = strings.TrimSpace(linia); linia != "" {
			linie = append(linie, linia)
		}
	}
	if len(linie) > 20 {
		linie = linie[len(linie)-20:]
	}
	return linie
}

func skroc(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}
