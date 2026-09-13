package ssh

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParseEffective reads the output of "sshd -T".
//
// It is the only source that says what the server really considers its
// configuration: included files have their own order and the first value
// wins in them, so assembling this by hand from the file contents ends in a
// picture the host does not confirm.
func ParseEffective(output string) Snapshot {
	snapshot := Snapshot{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "port":
			snapshot.Ports = append(snapshot.Ports, value)
		case "listenaddress":
			snapshot.ListenAddresses = append(snapshot.ListenAddresses, value)
		case "permitrootlogin":
			snapshot.PermitRootLogin = value
		case "passwordauthentication":
			snapshot.PasswordAuthentication = value
		case "pubkeyauthentication":
			snapshot.PubkeyAuthentication = value
		case "kbdinteractiveauthentication":
			snapshot.KbdInteractive = value
		case "gssapiauthentication":
			snapshot.GSSAPIAuthentication = value
		case "maxauthtries":
			snapshot.MaxAuthTries, _ = strconv.Atoi(value)
		case "allowusers":
			snapshot.AllowUsers = append(snapshot.AllowUsers, strings.Fields(value)...)
		case "allowgroups":
			snapshot.AllowGroups = append(snapshot.AllowGroups, strings.Fields(value)...)
		case "denyusers":
			snapshot.DenyUsers = append(snapshot.DenyUsers, strings.Fields(value)...)
		case "denygroups":
			snapshot.DenyGroups = append(snapshot.DenyGroups, strings.Fields(value)...)
		}
	}
	return snapshot
}

var keyFingerprint = regexp.MustCompile(`^(\d+)\s+(\S+)\s+.*\((\w+)\)\s*$`)

// ParseFingerprint reads one row of "ssh-keygen -l -f".
//
// The fingerprint and metadata are taken, never the private key: its copy in
// the panel database would be a copy of the host's identity.
func ParseFingerprint(line, path string) (HostKey, bool) {
	fields := keyFingerprint.FindStringSubmatch(strings.TrimSpace(line))
	if fields == nil {
		return HostKey{}, false
	}
	bits, _ := strconv.Atoi(fields[1])
	return HostKey{
		Type:        strings.ToLower(fields[3]),
		Bits:        bits,
		Fingerprint: fields[2],
		Path:        path,
	}, true
}

// ComposeDropIn composes the content of the panel's configuration file.
//
// Only the settings the operator asked for are written. Printing the whole
// configuration "for tidiness" would freeze on the host the defaults of the
// day of the write - and those change with the OpenSSH version.
func ComposeDropIn(settings Settings) (string, error) {
	if err := Validate(settings); err != nil {
		return "", err
	}
	lines := []string{FileHeader}
	add := func(key, value string) {
		if value != "" {
			lines = append(lines, key+" "+value)
		}
	}
	add("Port", settings.Port)
	add("PermitRootLogin", settings.PermitRootLogin)
	add("PasswordAuthentication", settings.PasswordAuthentication)
	add("PubkeyAuthentication", settings.PubkeyAuthentication)
	add("KbdInteractiveAuthentication", settings.KbdInteractive)
	add("MaxAuthTries", settings.MaxAuthTries)
	if len(settings.AllowUsers) > 0 {
		add("AllowUsers", strings.Join(settings.AllowUsers, " "))
	}
	if len(settings.AllowGroups) > 0 {
		add("AllowGroups", strings.Join(settings.AllowGroups, " "))
	}
	if len(settings.DenyUsers) > 0 {
		add("DenyUsers", strings.Join(settings.DenyUsers, " "))
	}
	if len(lines) == 1 {
		return "", fmt.Errorf("the change contains no setting")
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// DivergentSettings compares what the operator asked for with what the
// server really applies.
//
// In the sshd configuration the first value wins, and included files are in
// alphabetical order: an earlier file of the host administrator shadows ours
// and the change looks done although it changes nothing. Instead of
// pretending success, it says directly which setting did not take effect.
func DivergentSettings(desired Settings, state Snapshot) []string {
	var divergent []string
	compare := func(name, wanted, current string) {
		if wanted == "" {
			return
		}
		if !strings.EqualFold(wanted, current) {
			divergent = append(divergent, fmt.Sprintf("%s: ordered %q, the server applies %q",
				name, wanted, current))
		}
	}
	compare("PermitRootLogin", desired.PermitRootLogin, state.PermitRootLogin)
	compare("PasswordAuthentication", desired.PasswordAuthentication, state.PasswordAuthentication)
	compare("PubkeyAuthentication", desired.PubkeyAuthentication, state.PubkeyAuthentication)
	compare("KbdInteractiveAuthentication", desired.KbdInteractive, state.KbdInteractive)
	if desired.MaxAuthTries != "" {
		compare("MaxAuthTries", desired.MaxAuthTries, strconv.Itoa(state.MaxAuthTries))
	}
	if desired.Port != "" {
		current := ""
		if len(state.Ports) > 0 {
			current = state.Ports[0]
		}
		compare("Port", desired.Port, current)
	}
	return divergent
}
