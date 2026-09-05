package backup

import "time"

// Progi swiezosci kopii. Ocena powstaje w panelu, tak samo jak ocena zgodnosci
// i terminow certyfikatow: to polityka, a nie fakt o hoscie. Host mowi, kiedy
// ostatnia kopia sie udala; panel mowi, czy to juz jest problem.
const (
	// ProgOstrzezenia to wiek kopii, przy ktorym warto zapytac, czemu nie ma
	// nowszej. Doba z okladem miesci dobowy harmonogram i jedno potkniecie.
	ProgOstrzezenia = 26 * time.Hour
	// ProgPilny to wiek, przy ktorym kopia przestaje byc zabezpieczeniem.
	ProgPilny = 72 * time.Hour
	// ProgWeryfikacji to wiek ostatniego sprawdzenia kopii. Backup, ktorego
	// nikt nigdy nie odczytal, jest obietnica, a nie zabezpieczeniem.
	ProgWeryfikacji = 30 * 24 * time.Hour
)

// Stany kopii widziane przez panel.
const (
	StanNieznany = "unknown"
	StanBrak     = "never"
	StanPilny    = "critical"
	StanUwaga    = "warning"
	StanDobry    = "ok"
)

// Stan ocenia wiek ostatniej udanej kopii.
//
// Brak kopii to osobny stan, a nie "stara kopia": host bez zadnej kopii i host
// z kopia sprzed tygodnia to dwie rozne sytuacje i dwie rozne decyzje.
func Stan(ostatnia *time.Time, teraz time.Time) string {
	if ostatnia == nil {
		return StanBrak
	}
	wiek := teraz.Sub(*ostatnia)
	switch {
	case wiek >= ProgPilny:
		return StanPilny
	case wiek >= ProgOstrzezenia:
		return StanUwaga
	}
	return StanDobry
}

// waga porzadkuje stany od najgorszego.
var waga = map[string]int{
	StanBrak:     4,
	StanPilny:    3,
	StanNieznany: 2,
	StanUwaga:    1,
	StanDobry:    0,
}

// Gorszy zwraca gorszy z dwoch stanow. Host opisuje jego najgorsza definicja:
// jedna kopia, ktorej nie ma, wystarczy, zeby dane byly niezabezpieczone.
func Gorszy(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if waga[b] > waga[a] {
		return b
	}
	return a
}

// Niesprawdzona mowi, czy kopie nikt nie weryfikowal wystarczajaco dawno.
func Niesprawdzona(ostatnia *time.Time, teraz time.Time) bool {
	return ostatnia == nil || teraz.Sub(*ostatnia) > ProgWeryfikacji
}
