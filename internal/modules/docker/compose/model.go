// Package compose obsluguje projekty Docker Compose.
//
// Manifest opisuje stan docelowy projektu, a nie polecenie do wykonania.
// Plan liczy roznice miedzy tym, co dziala, a tym, co manifest opisuje;
// wdrozenie jest zwiazane z konkretnym planem i odmawia, gdy stan podstawy
// zmienil sie od czasu zatwierdzenia.
package compose

import "time"

// Change opisuje jedna zmiane, ktora przyniesie wdrozenie.
type Change struct {
	// Kind to rodzaj obiektu: container, network, volume, image.
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Action mowi, co sie z nim stanie: create, recreate, start, stop,
	// remove albo pull.
	Action string `json:"action"`
}

// Service to usluga projektu po znormalizowaniu manifestu.
type Service struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	// ImageDigest jest wypelniony, gdy obraz jest juz na hoscie. Pusty
	// oznacza obraz, ktory zostanie dopiero pobrany - i wtedy nie da sie
	// z gory powiedziec, co dokladnie wstanie.
	ImageDigest string `json:"image_digest,omitempty"`
	Replicas    int    `json:"replicas,omitempty"`
}

// Plan opisuje, co wdrozenie zmieni na hoscie.
type Plan struct {
	Project string `json:"project"`
	// Digest wiaze wdrozenie z tym planem. Liczony ze znormalizowanego
	// manifestu i z digestow obrazow, wiec zmiana ktoregokolwiek z nich
	// uniewaznia zatwierdzenie.
	Digest   string    `json:"digest"`
	Services []Service `json:"services"`
	Changes  []Change  `json:"changes"`
	// Warnings mowia o rzeczach, ktore nie blokuja wdrozenia, ale operator
	// ma o nich wiedziec, zanim je zatwierdzi.
	Warnings []string `json:"warnings,omitempty"`
	// Current opisuje stan projektu przed zmiana.
	Current []Service `json:"current,omitempty"`
	// UnavailableReason mowi, dlaczego planu nie udalo sie policzyc.
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
	ComputedAt        time.Time `json:"computed_at"`
}

// Result opisuje wynik wdrozenia.
type Result struct {
	Project string `json:"project"`
	Digest  string `json:"digest"`
	// Applied wylicza zmiany zgloszone przez silnik w trakcie wdrozenia.
	Applied []Change  `json:"applied,omitempty"`
	Before  []Service `json:"before,omitempty"`
	After   []Service `json:"after,omitempty"`
	// Output to koncowka wyjscia narzedzia przy niepowodzeniu.
	Output []string `json:"output,omitempty"`
}
