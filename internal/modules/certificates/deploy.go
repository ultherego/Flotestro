package certificates

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	filesmodule "github.com/ultherego/flotestro/internal/modules/files"
)

// Default permissions. The certificate is public and the service must read
// it; the key is not public and nobody but the owner may read it.
const (
	CertificateMode = "0644"
	KeyMode         = "0600"
)

// ProbeWindow bounds the wait for the service answer after a reload.
const ProbeWindow = 10 * time.Second

// Deployment describes one certificate replacement on the host.
//
// The key is in this structure as bytes and only here: it comes from the
// store right before the operation, lives in the process memory for its
// duration and goes neither into the result, nor the log, nor any file but
// the one that is to be created.
type Deployment struct {
	Path        string
	KeyPath     string
	Certificate []byte
	Key         []byte
	Owner       string
	Group       string
	Mode        string
	KeyMode     string
	Unit        string
	Target      string
}

// Check verifies the material before the replacement.
//
// The order of the questions is the whole point here: a certificate that
// does not match the key stops the service only at start - after the old
// file has already ceased to exist. That is why everything that can be
// checked without touching the disk is checked before the first write.
func Check(deployment Deployment, now time.Time) ([]*x509.Certificate, error) {
	if err := ValidatePath(deployment.Path); err != nil {
		return nil, err
	}
	if deployment.KeyPath != "" {
		if err := ValidatePath(deployment.KeyPath); err != nil {
			return nil, err
		}
	}
	if err := ValidateUnit(deployment.Unit); err != nil {
		return nil, err
	}
	if err := ValidateTarget(deployment.Target); err != nil {
		return nil, err
	}

	certs, err := ParsePEM(deployment.Certificate)
	if err != nil {
		return nil, err
	}
	if err := CheckDates(certs[0], now); err != nil {
		return nil, err
	}
	if err := CheckChain(certs); err != nil {
		return nil, err
	}
	if len(deployment.Key) > 0 {
		if deployment.KeyPath == "" {
			return nil, errors.New("the key came from the store, but the order does not say where to write it")
		}
		if err := MatchKey(certs[0], deployment.Key); err != nil {
			return nil, err
		}
	}
	// The probe is meant to check this certificate, not any. A target name
	// outside the certificate means the test would not confirm the
	// deployment anyway.
	if deployment.Target != "" {
		if host, _, err := net.SplitHostPort(deployment.Target); err == nil {
			if net.ParseIP(host) == nil && !Covers(certs[0], host) {
				return nil, fmt.Errorf("the certificate does not cover the name %q, so the probe will not confirm the deployment", host)
			}
		}
	}
	return certs, nil
}

// Backup holds the previous file content for the duration of the
// operation.
//
// The backup lives in memory, not next to the file: writing the old key to
// a second file would leave a key nobody watches any more on the disk -
// also when the deployment succeeds.
type Backup struct {
	Path     string
	Existed  bool
	Content  []byte
	Mode     os.FileMode
	UID, GID int
}

// Remember reads the file that is about to be replaced.
func Remember(path string) (Backup, error) {
	backup := Backup{Path: path, Mode: 0o644, UID: -1, GID: -1}
	if path == "" {
		return backup, nil
	}
	data, err := ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return backup, nil
	}
	if err != nil {
		return backup, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return backup, err
	}
	backup.Existed = true
	backup.Content = data
	backup.Mode = info.Mode().Perm()
	if uid, gid, ok := fileOwner(info); ok {
		backup.UID, backup.GID = uid, gid
	}
	return backup, nil
}

// Restore returns to the remembered file content.
//
// A file that did not exist before the operation vanishes: returning to
// the state before the change also means the absence of the file the
// change created.
func (b Backup) Restore() error {
	if b.Path == "" {
		return nil
	}
	if !b.Existed {
		if err := os.Remove(b.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return filesmodule.WriteAtomically(b.Path, b.Content, b.Mode, b.UID, b.GID)
}

// Write puts the certificate and the key in their places.
//
// The key goes first: a service reloaded between one write and the other
// sees the old certificate with the new key or the new certificate with the
// old key, and only the first of these pairs does not end in a handshake
// error.
func Write(deployment Deployment, uid, gid int) error {
	if len(deployment.Key) > 0 {
		mode, err := filesmodule.ValidateMode(valueOr(deployment.KeyMode, KeyMode))
		if err != nil {
			return err
		}
		if mode.Perm()&0o044 != 0 {
			return fmt.Errorf("the permissions %q let the private key be read outside the owner",
				valueOr(deployment.KeyMode, KeyMode))
		}
		if err := filesmodule.WriteAtomically(deployment.KeyPath, deployment.Key, mode, uid, gid); err != nil {
			return err
		}
	}
	mode, err := filesmodule.ValidateMode(valueOr(deployment.Mode, CertificateMode))
	if err != nil {
		return err
	}
	return filesmodule.WriteAtomically(deployment.Path, deployment.Certificate, mode, uid, gid)
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// ProbeResult describes what the service shows after a reload.
type ProbeResult struct {
	Target            string `json:"target"`
	Reachable         bool   `json:"reachable"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	Subject           string `json:"subject,omitempty"`
	NotAfter          string `json:"not_after,omitempty"`
	Error             string `json:"error,omitempty"`
}

// Probe asks the service what it presents itself as now.
//
// The connection does not check trust and should not: the question is
// "does the service present the certificate we have just deployed", not
// "does this host trust this authority". Chain verification against the
// host trust store would reject every certificate from a private CA - that
// is most of those the panel deploys.
func Probe(ctx context.Context, target string) ProbeResult {
	result := ProbeResult{Target: target}
	if err := ValidateTarget(target); err != nil || target == "" {
		if err != nil {
			result.Error = err.Error()
		}
		return result
	}
	host, _, _ := net.SplitHostPort(target)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: ProbeWindow},
		Config: &tls.Config{
			// The name is given so the server picks the right certificate
			// for SNI; the verification is done by us, comparing the
			// fingerprint.
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.Error = "the service presented no certificate"
		return result
	}
	leaf := state.PeerCertificates[0]
	result.Reachable = true
	result.FingerprintSHA256 = Fingerprint(leaf)
	result.Subject = leaf.Subject.String()
	result.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	return result
}

// Confirms says whether the service shows exactly this certificate.
func (r ProbeResult) Confirms(fingerprint string) bool {
	return r.Reachable && r.FingerprintSHA256 == fingerprint
}
