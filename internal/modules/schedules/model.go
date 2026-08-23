// Package schedules zarzadza zadaniami cyklicznymi hosta niezaleznie od
// mechanizmu: cron i timery systemd sa dwoma adapterami tego samego modelu.
//
// Wpisy zarzadzane przez panel maja wlasny plik i stabilny identyfikator.
// Wpisy zastane naleza do administratora hosta i panel ich nie nadpisuje bez
// jawnego przejecia - inaczej pierwsza operacja z panelu kasowalaby prace,
// ktorej nikt do panelu nie wprowadzal.
package schedules

import "time"

// Rodzaje mechanizmow.
const (
	KindCron  = "cron"
	KindTimer = "timer"
)

// Pochodzenie wpisu.
const (
	// SourceManaged oznacza wpis zalozony przez panel: ma wlasny plik
	// i stabilny identyfikator.
	SourceManaged = "managed"
	// SourceManual oznacza wpis zastany na hoscie.
	SourceManual = "manual"
)

// Schedule opisuje jedno zadanie cykliczne.
type Schedule struct {
	// ID jest stabilne wylacznie dla wpisow zarzadzanych. Wpis zastany
	// identyfikuje sciezka pliku i numer linii, bo nic trwalszego nie ma.
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Source rozroznia wpis panelu od wpisu administratora hosta.
	Source string `json:"source"`
	// Enabled mowi, czy wpis jest aktywny. Wpis wylaczony zostaje na hoscie
	// razem ze swoja trescia: wylaczenie nie jest usunieciem.
	Enabled bool `json:"enabled"`
	// Expression to wyrazenie crona albo OnCalendar timera.
	Expression string `json:"expression"`
	// Command jest tablica argumentow. Wypelnione tylko dla wpisow
	// zarzadzanych: tam panel decyduje o kazdym argumencie i zadna powloka
	// nie bierze udzialu w uruchomieniu.
	Command []string `json:"command,omitempty"`
	// CommandLine jest trescia, ktora cron przekaze do /bin/sh. Wpis zastany
	// ma tylko ja: rozdzielenie cudzego wiersza powloki na argumenty
	// pokazywaloby cos, czego host nigdy tak nie uruchomi.
	CommandLine string `json:"command_line,omitempty"`
	User        string `json:"user,omitempty"`
	// Path wskazuje plik, w ktorym wpis zyje. Operator ma wiedziec, gdzie
	// szukac, gdy panel czegos nie potrafi.
	Path string `json:"path,omitempty"`
	Line int    `json:"line,omitempty"`
	// NextRun jest liczony na hoscie i przesylany jako fakt: panel nie zna
	// strefy czasowej hosta ani jego kalendarza.
	NextRun *time.Time `json:"next_run,omitempty"`
	// Timezone hosta. Bez niej "03:00" nie znaczy nic konkretnego.
	Timezone string `json:"timezone,omitempty"`
	// LastResult opisuje ostatnie znane wykonanie; puste oznacza brak
	// wiedzy, a nie brak wykonan.
	LastResult string `json:"last_result,omitempty"`
	Comment    string `json:"comment,omitempty"`
}

// Snapshot to wynik odczytu harmonogramow hosta.
type Snapshot struct {
	Schedules []Schedule `json:"schedules"`
	Timezone  string     `json:"timezone,omitempty"`
	// UnavailableReason mowi, dlaczego stanu nie udalo sie ustalic.
	// Host bez crona i bez timerow to nie to samo co host nieodpytany.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}
