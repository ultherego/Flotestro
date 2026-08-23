// Package docker jest adapterem silnika kontenerow. Modul czyta stan przez
// Engine API i wykonuje wylacznie operacje typowane; nie istnieje operacja
// "dowolne zadanie do Dockera".
//
// Agent nie dostaje dostepu do gniazda Dockera. Gniazdo nalezy do roota, a
// czlonkostwo w grupie docker jest rownowazne rootowi - agent dzialajacy bez
// uprawnien nie moze go miec. Cala rozmowa z silnikiem idzie przez helpera.
package docker

import "time"

// Container to jeden kontener widziany na hoscie.
type Container struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
	// ImageDigest jednoznacznie wskazuje obraz. Tag moze wskazywac co innego
	// jutro, digest nie.
	ImageDigest string    `json:"image_digest,omitempty"`
	State       string    `json:"state"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	// Health jest pusty, gdy obraz nie definiuje sprawdzenia. Brak sprawdzenia
	// to nie to samo co sprawdzenie nieudane.
	Health string            `json:"health,omitempty"`
	Ports  []Port            `json:"ports,omitempty"`
	Mounts []Mount           `json:"mounts,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
	// Compose wypelnia sie dla kontenerow zarzadzanych przez Compose.
	Compose *ComposeMembership `json:"compose,omitempty"`
	// RestartCount pomaga odroznic kontener zdrowy od takiego, ktory wstaje
	// w petli.
	RestartCount int `json:"restart_count"`
}

// ComposeMembership opisuje przynaleznosc kontenera do projektu Compose.
type ComposeMembership struct {
	Project     string `json:"project"`
	Service     string `json:"service"`
	ConfigFiles string `json:"config_files,omitempty"`
	WorkingDir  string `json:"working_dir,omitempty"`
}

// Port to opublikowany port kontenera.
type Port struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port,omitempty"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// Mount to punkt montowania kontenera.
type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
	Name        string `json:"name,omitempty"`
}

// Image to obraz obecny na hoscie.
type Image struct {
	ID        string    `json:"id"`
	Tags      []string  `json:"tags,omitempty"`
	Digests   []string  `json:"digests,omitempty"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	// InUse mowi, czy jakis kontener korzysta z obrazu. Bez tego operator nie
	// wie, co skasuje sprzatanie.
	InUse bool `json:"in_use"`
}

// Network to siec Dockera.
type Network struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Driver  string   `json:"driver"`
	Scope   string   `json:"scope,omitempty"`
	Subnets []string `json:"subnets,omitempty"`
	InUse   bool     `json:"in_use"`
}

// Volume to wolumen Dockera.
type Volume struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint,omitempty"`
	InUse      bool   `json:"in_use"`
	// SizeBytes bywa nieustalony: policzenie rozmiaru wymaga przejscia po
	// calym wolumenie i silnik nie podaje go w kazdym zapytaniu.
	SizeBytes *int64 `json:"size_bytes,omitempty"`
}

// Project to projekt Compose zlozony z kontenerow jednego hosta.
type Project struct {
	Name        string   `json:"name"`
	ConfigFiles string   `json:"config_files,omitempty"`
	WorkingDir  string   `json:"working_dir,omitempty"`
	Services    []string `json:"services"`
	Running     int      `json:"running"`
	Total       int      `json:"total"`
}

// Summary jest lekkim podsumowaniem do inventory. Pelne listy sa pobierane na
// zadanie: odpytywanie silnika przy kazdym heartbeacie obciazaloby host bez
// powodu.
type Summary struct {
	EngineVersion string `json:"engine_version,omitempty"`
	APIVersion    string `json:"api_version,omitempty"`
	Containers    int    `json:"containers"`
	Running       int    `json:"running"`
	Paused        int    `json:"paused"`
	Stopped       int    `json:"stopped"`
	Unhealthy     int    `json:"unhealthy"`
	// RestartLooping liczy kontenery, ktore wstaja w kolko. To sygnal
	// decyzyjny, a nie metryka - dlatego jest w inventory.
	RestartLooping int       `json:"restart_looping"`
	Images         int       `json:"images"`
	Volumes        int       `json:"volumes"`
	Networks       int       `json:"networks"`
	Projects       []Project `json:"projects,omitempty"`
	// UnavailableReason mowi, dlaczego stanu nie udalo sie ustalic. Pusty
	// silnik i silnik nieodpytany to dwie rozne informacje.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}
