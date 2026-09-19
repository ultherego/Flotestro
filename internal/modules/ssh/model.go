// Package ssh describes the sshd server configuration on a host.
package ssh

import "time"

// DropInPath is the file managed by the panel.
const (
	DropInDir  = "/etc/ssh/sshd_config.d"
	DropInPath = DropInDir + "/90-flotestro.conf"
	FileHeader = "# Managed by Flotestro. Manual changes will not survive the next operation."
)

// HostKey describes a host key.
type HostKey struct {
	Type        string `json:"type"`
	Bits        int    `json:"bits"`
	Fingerprint string `json:"fingerprint"`
	Path        string `json:"path"`
}

// Snapshot is the configuration in effect on the host.
type Snapshot struct {
	Ports           []string `json:"ports,omitempty"`
	ListenAddresses []string `json:"listen_addresses,omitempty"`
	// PermitRootLogin, PasswordAuthentication and PubkeyAuthentication are text,
	// because sshd has more than two values here: "prohibit-password" is neither
	// "yes" nor "no".
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
	// Managed describes the panel's file: its content and whether it exists
	// at all.
	Managed        string `json:"managed_config,omitempty"`
	ManagedPath    string `json:"managed_path,omitempty"`
	ManagedPresent bool   `json:"managed_present"`
	// Unit names the server's systemd unit. Debian has ssh.service, Fedora
	// sshd.service - and reloading the wrong one does nothing.
	Unit              string    `json:"unit,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// Settings describe a change ordered by the panel.
type Settings struct {
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
