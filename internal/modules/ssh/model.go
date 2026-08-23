// Package ssh opisuje konfiguracje serwera sshd na hoscie.
//
// Modul dotyczy serwera, a nie kont: klucze uzytkownikow naleza do modulu
// kont lokalnych. Rozdzielenie jest celowe, bo to dwie rozne decyzje - jedna
// mowi, jak host wpuszcza, druga kogo.
package ssh

import "time"

// SciezkaDropIn to plik, ktorym zarzadza panel.
//
// Konfiguracja idzie do wlasnego pliku, a nie do sshd_config: plik glowny
// nalezy do dystrybucji i administratora hosta, a jego przepisywanie kasuje
// zmiany, ktorych nikt do panelu nie wprowadzal.
const (
	KatalogDropIn = "/etc/ssh/sshd_config.d"
	SciezkaDropIn = KatalogDropIn + "/90-flotestro.conf"
	NaglowekPliku = "# Zarzadzane przez Flotestro. Recznych zmian nie zachowa kolejna operacja."
)

// HostKey opisuje klucz hosta.
//
// Trzymamy odcisk i metadane, nigdy klucz prywatny: panel nie ma powodu go
// widziec, a jego kopia w bazie bylaby kopia tozsamosci hosta.
type HostKey struct {
	Type        string `json:"type"`
	Bits        int    `json:"bits"`
	Fingerprint string `json:"fingerprint"`
	Path        string `json:"path"`
}

// Snapshot to konfiguracja obowiazujaca na hoscie.
//
// Wartosci pochodza z "sshd -T", a wiec z tego, co serwer naprawde uwaza za
// swoja konfiguracje - nie z sumy plikow, ktora trzeba by skladac samemu.
type Snapshot struct {
	Ports           []string `json:"ports,omitempty"`
	ListenAddresses []string `json:"listen_addresses,omitempty"`
	// PermitRootLogin, PasswordAuthentication i PubkeyAuthentication sa
	// tekstem, bo sshd ma tu wiecej niz dwie wartosci: "prohibit-password"
	// nie jest ani "yes", ani "no".
	PermitRootLogin        string    `json:"permit_root_login,omitempty"`
	PasswordAuthentication string    `json:"password_authentication,omitempty"`
	PubkeyAuthentication   string    `json:"pubkey_authentication,omitempty"`
	KbdInteractive         string    `json:"kbd_interactive_authentication,omitempty"`
	GSSAPIAuthentication   string    `json:"gssapi_authentication,omitempty"`
	MaxAuthTries           int       `json:"max_auth_tries"`
	AllowUsers             []string  `json:"allow_users,omitempty"`
	AllowGroups            []string  `json:"allow_groups,omitempty"`
	DenyUsers              []string  `json:"deny_users,omitempty"`
	DenyGroups             []string  `json:"deny_groups,omitempty"`
	HostKeys               []HostKey `json:"host_keys,omitempty"`
	// Managed opisuje plik panelu: jego tresc i to, czy w ogole istnieje.
	Managed        string `json:"managed_config,omitempty"`
	ManagedPath    string `json:"managed_path,omitempty"`
	ManagedPresent bool   `json:"managed_present"`
	// Unit nazywa jednostke systemd serwera. Debian ma ssh.service, Fedora
	// sshd.service - a przeladowanie niewlasciwej nie robi nic.
	Unit              string    `json:"unit,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// Ustawienia opisuja zmiane zlecona przez panel.
//
// Puste pole oznacza "nie zmieniaj": panel nie przepisuje calej konfiguracji
// serwera, tylko te ustawienia, o ktore operator poprosil.
type Ustawienia struct {
	Port                   string   `json:"port,omitempty"`
	PermitRootLogin        string   `json:"permit_root_login,omitempty"`
	PasswordAuthentication string   `json:"password_authentication,omitempty"`
	PubkeyAuthentication   string   `json:"pubkey_authentication,omitempty"`
	KbdInteractive         string   `json:"kbd_interactive_authentication,omitempty"`
	MaxAuthTries           string   `json:"max_auth_tries,omitempty"`
	AllowUsers             []string `json:"allow_users,omitempty"`
	AllowGroups            []string `json:"allow_groups,omitempty"`
	DenyUsers              []string `json:"deny_users,omitempty"`
}
