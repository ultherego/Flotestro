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
	// Networks wylicza sieci, do ktorych kontener jest podlaczony. To stad
	// wiadomo, ktora siec jest w uzyciu: lista sieci silnika tego nie mowi.
	Networks []ContainerNetwork `json:"networks,omitempty"`
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

// ContainerNetwork opisuje podlaczenie kontenera do jednej sieci.
type ContainerNetwork struct {
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
	// IPv4 bywa puste: kontener zatrzymany nie ma adresu, a to nie znaczy,
	// ze do sieci nie nalezy.
	IPv4    string   `json:"ipv4,omitempty"`
	IPv6    string   `json:"ipv6,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
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
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Driver   string   `json:"driver"`
	Scope    string   `json:"scope,omitempty"`
	Subnets  []string `json:"subnets,omitempty"`
	Gateways []string `json:"gateways,omitempty"`
	// Internal oznacza siec bez wyjscia na zewnatrz, Attachable - siec,
	// do ktorej wolno podlaczyc kontener spoza uslugi. Jedno i drugie
	// zmienia to, co przez ta siec przejdzie, wiec nie jest szczegolem.
	Internal   bool              `json:"internal"`
	Attachable bool              `json:"attachable"`
	IPv6       bool              `json:"ipv6"`
	Ingress    bool              `json:"ingress,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	CreatedAt  time.Time         `json:"created_at,omitempty"`
	// Predefined oznacza siec wbudowana w silnik - bridge, host, none.
	// Silnik nie pozwala jej usunac, wiec panel nie moze tego proponowac.
	Predefined bool `json:"predefined"`
	// Compose wskazuje projekt, ktory te siec utworzyl. Siec projektu usunieta
	// recznie wroci przy nastepnym wdrozeniu, wiec to nie jest sprzatanie.
	Compose string `json:"compose,omitempty"`
	// Containers wylicza podlaczone kontenery. Lista sieci silnika ich nie
	// podaje, wiec sa wyliczane z listy kontenerow - i to one, a nie flaga
	// z silnika, rozstrzygaja o uzyciu.
	Containers []NetworkMember `json:"containers,omitempty"`
	InUse      bool            `json:"in_use"`
}

// NetworkMember to kontener podlaczony do sieci.
type NetworkMember struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state,omitempty"`
	IPv4  string `json:"ipv4,omitempty"`
}

// Volume to wolumen Dockera.
type Volume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint,omitempty"`
	Scope      string            `json:"scope,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	CreatedAt  time.Time         `json:"created_at,omitempty"`
	// Compose wskazuje projekt, ktory wolumen utworzyl.
	Compose string `json:"compose,omitempty"`
	// UsedBy wylicza kontenery, ktore ten wolumen montuja - razem
	// z zatrzymanymi. Wolumen zatrzymanego kontenera nie jest wolumenem
	// porzuconym, a to on ginie przy sprzataniu.
	UsedBy []VolumeMount `json:"used_by,omitempty"`
	InUse  bool          `json:"in_use"`
	// SizeBytes bywa nieustalony: policzenie rozmiaru wymaga przejscia po
	// calym wolumenie i silnik nie podaje go w kazdym zapytaniu.
	SizeBytes *int64 `json:"size_bytes,omitempty"`
	// SizeReason mowi, dlaczego rozmiaru nie ma. Zero znaczyloby wolumen
	// pusty, gotowy do skasowania - a to zupelnie inna informacja.
	SizeReason string `json:"size_reason,omitempty"`
}

// VolumeMount to montowanie wolumenu w kontenerze.
type VolumeMount struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	State         string `json:"state,omitempty"`
	Destination   string `json:"destination"`
	ReadOnly      bool   `json:"read_only"`
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
	RestartLooping int `json:"restart_looping"`
	Images         int `json:"images"`
	Volumes        int `json:"volumes"`
	Networks       int `json:"networks"`
	// Nieuzywane wolumeny i sieci sa sygnalem do sprzatania, a nie metryka:
	// to one zajmuja miejsce i to one sa kandydatami do usuniecia.
	VolumesUnused  int       `json:"volumes_unused"`
	NetworksUnused int       `json:"networks_unused"`
	Projects       []Project `json:"projects,omitempty"`
	// UnavailableReason mowi, dlaczego stanu nie udalo sie ustalic. Pusty
	// silnik i silnik nieodpytany to dwie rozne informacje.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}
