// Package certificates describes the certificates lying on a host: their
// dates, issuers, the names they cover and the service that uses them.
//
// The module gathers facts about named files, it does not search the host.
// A panel that walks the whole filesystem looking for certificates finds
// above all the trust store - a few hundred authority certificates that
// belong to no service - and looks into directories with nothing to find.
// The scope is therefore enumerated: the paths named in the panel and what
// the host knows about itself, because certmonger watches it.
//
// The module never reads the private key when reading the state. It knows
// about the key only what is visible from the outside: whether the file
// exists, what permissions it has and whom it belongs to. The match of the
// key with the certificate is checked exactly once - at deployment, when
// the key is in the host's hands for a moment anyway.
package certificates

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Source says where the certificate on the host came from.
const (
	// SourcePanel means a certificate deployed by Flotestro.
	SourcePanel = "flotestro"
	// SourceCertmonger means a certificate watched by the certmonger
	// daemon: it requested it and it renews it.
	SourceCertmonger = "certmonger"
	// SourceExternal means a file somebody placed outside the panel.
	SourceExternal = "external"
)

// Certificate renewal method.
const (
	// RenewalTracked means a certificate with a certmonger request: the
	// host renews it itself before it expires.
	RenewalTracked = "tracked"
	// RenewalManual means a certificate nobody on the host watches - the
	// renewal is a decision of a human or the panel.
	RenewalManual = "manual"
	// RenewalUnknown means an undetermined state: it could not be read
	// whether anything watches this certificate. That is not the same as
	// "manual".
	RenewalUnknown = "unknown"
)

// Tool paths. Certmonger is the only one the module reaches for.
const (
	GetcertPath    = "/usr/bin/getcert"
	GetcertPathAlt = "/usr/sbin/getcert"
)

// MaxFileSize bounds a file the module opens at all.
//
// A certificate with a chain has a few kilobytes. A file bigger than this
// is not a certificate, and loading it would only be a way to take up
// memory.
const MaxFileSize = 256 << 10

// MaxCertificates bounds one read.
//
// The bound applies to a single file too: somebody may name the trust
// store as a path to look at, and then the host answer would be a list of
// a few hundred authorities instead of the state of its services.
const MaxCertificates = 64

// KeyMetadata describes a private key without its content.
//
// The panel does not need the key to say what matters about it: whether it
// lies where the service looks for it and whether it is not readable by
// everyone.
type KeyMetadata struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   string `json:"mode,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Group  string `json:"group,omitempty"`
	// WorldReadable is a conclusion from the permissions, not a separate
	// read.
	WorldReadable bool `json:"world_readable,omitempty"`
	// Reason says why the key state was not determined. No knowledge about
	// the key is not the same as a key that does not exist.
	Reason string `json:"reason,omitempty"`
}

// Tracking describes a certmonger request concerning one certificate.
type Tracking struct {
	Request string `json:"request,omitempty"`
	// Status is the request state as seen by the daemon: MONITORING means a
	// certificate under care, CA_UNREACHABLE - care that does not work.
	Status  string `json:"status,omitempty"`
	CA      string `json:"ca,omitempty"`
	KeyPath string `json:"key_path,omitempty"`
	// AutoRenew says whether the daemon renews the certificate itself. A
	// request without this entry is only a date observation.
	AutoRenew *bool      `json:"auto_renew,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
}

// Certificate describes one certificate lying on the host.
type Certificate struct {
	Path    string   `json:"path"`
	Subject string   `json:"subject,omitempty"`
	Issuer  string   `json:"issuer,omitempty"`
	Serial  string   `json:"serial,omitempty"`
	SANs    []string `json:"sans,omitempty"`
	// The dates are pointers, because an unread file has no date at all. A
	// zero date here would look like a certificate issued in the first year
	// of our era - that is, like an expired one.
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	KeyAlgorithm      string     `json:"key_algorithm,omitempty"`
	KeyBits           int        `json:"key_bits,omitempty"`
	SignatureAlgo     string     `json:"signature_algorithm,omitempty"`
	SelfSigned        bool       `json:"self_signed,omitempty"`
	IsCA              bool       `json:"is_ca,omitempty"`
	// ChainLength counts the certificates in the file including the leaf.
	// One means a certificate without a chain - and that is the most common
	// reason a client rejects the connection despite a valid certificate.
	ChainLength int `json:"chain_length,omitempty"`

	// The private key described from the outside; the module does not read
	// its content.
	Key *KeyMetadata `json:"key,omitempty"`

	// Relations: what this file is for the host.
	Source string `json:"source"`
	// OwnerService is the unit that reads this file. The panel does not
	// guess it from the directory name: a human who knows what reads what
	// enters it.
	OwnerService string    `json:"owner_service,omitempty"`
	Renewal      string    `json:"renewal"`
	Tracking     *Tracking `json:"tracking,omitempty"`

	// UnavailableReason describes a file that could not be read or
	// recognised. An empty certificate list in such a file is not the
	// answer "there is no certificate here".
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// DaysToExpiry counts the full days until the end of validity. A negative
// value means an already expired certificate.
func (c Certificate) DaysToExpiry(now time.Time) *int {
	if c.NotAfter == nil {
		return nil
	}
	days := int(c.NotAfter.Sub(now).Hours() / 24)
	return &days
}

// Snapshot is the picture of the certificates on the host.
type Snapshot struct {
	Certificates []Certificate `json:"certificates,omitempty"`
	// Scanned lists the paths the panel asked about. Without it an empty
	// certificate list would not tell a host without certificates from a
	// host nobody has configured yet.
	Scanned []string `json:"scanned,omitempty"`
	// TrackingKnown says whether it could be determined what watches the
	// certificates.
	TrackingKnown bool `json:"tracking_known"`
	// TrackingReason says why it could not be determined.
	TrackingReason string `json:"tracking_reason,omitempty"`
	// KeysKnown says whether the certificates carry the key state. Without
	// root the key directory is at times closed and then the answer is
	// "unknown", not "there is no key".
	KeysKnown bool `json:"keys_known"`
	// Missing lists the facts not gathered, with the reason.
	Missing map[string]string `json:"missing,omitempty"`
	// Trust describes the host trust store: which authorities the host
	// trusts and which of them the panel created. Without it an authority
	// rotation is invisible from the panel: it cannot be seen who already
	// trusts the new one and who does not yet.
	Trust *TrustStore `json:"trust,omitempty"`
	// Truncated counts the targets skipped by the limit of one read, and
	// TruncatedReason says so directly. A list cut off quietly would look
	// like a full answer.
	Truncated       int    `json:"truncated,omitempty"`
	TruncatedReason string `json:"truncated_reason,omitempty"`

	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// Names of the facts the agent cannot read without root. The helper
// receives a list of them, not a command to run: the scope of its work is
// enumerated.
const (
	FactKeyMetadata      = "key_metadata"
	FactTracking         = "renewal_tracking"
	FactCertificateFiles = "certificate_files"
)

// MissingFacts lists the facts the helper has to be asked for.
func (s Snapshot) MissingFacts() []string {
	var names []string
	for name := range s.Missing {
		names = append(names, name)
	}
	return names
}

// Supplement holds the facts gathered by the helper on explicit request.
//
// A nil field means a fact that was not asked for or could not be read -
// the reason is then in Errors, under the fact name.
type Supplement struct {
	// Keys is the key metadata, by key path.
	Keys map[string]KeyMetadata `json:"keys,omitempty"`
	// Tracking is the state of the certmonger requests, by certificate
	// path.
	Tracking       map[string]Tracking `json:"tracking,omitempty"`
	TrackingKnown  bool                `json:"tracking_known,omitempty"`
	TrackingReason string              `json:"tracking_reason,omitempty"`
	// Targets is the list of targets the host knows on its own: those
	// entered by the panel earlier and those watched by certmonger. Thanks
	// to it the inventory describes the same scope as the last scan.
	Targets []Target `json:"targets,omitempty"`
	// Files is the content of the files the agent could not open: a
	// certificate is at times kept in a directory closed to everyone but
	// the service.
	Files  map[string]string `json:"files,omitempty"`
	Errors map[string]string `json:"errors,omitempty"`
}

// Fingerprint computes the digest of a certificate in DER form.
//
// It is the same fingerprint a browser and openssl show, so it can be
// compared with what is visible on the other side of the connection.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// ParsePEM extracts the certificates from a PEM file in the order they lie.
//
// The order matters: the first is the service leaf, the following ones are
// the chain. A file with a private key inside is not an error - blocks
// other than CERTIFICATE are simply skipped and copied nowhere.
func ParsePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate not recognised: %w", err)
		}
		certs = append(certs, cert)
		if len(certs) >= MaxCertificates {
			break
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("the file contains no certificate in PEM format")
	}
	return certs, nil
}

// Describe assembles the certificate description from what it carries
// itself.
func Describe(path string, certs []*x509.Certificate) Certificate {
	leaf := certs[0]
	start, end := leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
	description := Certificate{
		Path:              path,
		Subject:           leaf.Subject.String(),
		Issuer:            leaf.Issuer.String(),
		Serial:            leaf.SerialNumber.String(),
		SANs:              AlternativeNames(leaf),
		NotBefore:         &start,
		NotAfter:          &end,
		FingerprintSHA256: Fingerprint(leaf),
		SignatureAlgo:     leaf.SignatureAlgorithm.String(),
		IsCA:              leaf.IsCA,
		ChainLength:       len(certs),
		Source:            SourceExternal,
		Renewal:           RenewalUnknown,
	}
	description.KeyAlgorithm, description.KeyBits = KeyDescription(leaf.PublicKey)
	description.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()
	return description
}

// AlternativeNames gathers all the names the certificate covers.
//
// Addresses, names and URIs stand in one list with a type prefix: the
// operator asks "does this certificate cover this address", not "in which
// extension field is this name".
func AlternativeNames(cert *x509.Certificate) []string {
	var names []string
	names = append(names, cert.DNSNames...)
	for _, address := range cert.IPAddresses {
		names = append(names, address.String())
	}
	names = append(names, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		names = append(names, uri.String())
	}
	return names
}

// KeyDescription names the algorithm and the strength of a public key.
func KeyDescription(key crypto.PublicKey) (string, int) {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		return "RSA", typed.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", typed.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "", 0
}

// Covers says whether the certificate covers the given name.
//
// The check goes through the library name verification, so the wildcard
// "*.example.com" works the same as it does for a client.
func Covers(cert *x509.Certificate, name string) bool {
	return cert.VerifyHostname(name) == nil
}

// MatchKey checks whether the private key belongs to the certificate.
//
// This is the only place in the module where the key is read - and it
// happens right before deployment, when the key has to pass through the
// host's hands anyway. The result is the bare answer "matches or not": the
// key content is neither in the error message nor in the operation result.
func MatchKey(cert *x509.Certificate, keyPEM []byte) error {
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return err
	}
	public, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return fmt.Errorf("key of an unknown kind")
	}
	comparable, ok := public.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("a key of this kind cannot be compared with the certificate")
	}
	if !comparable.Equal(cert.PublicKey) {
		return fmt.Errorf("the private key does not belong to this certificate")
	}
	return nil
}

// ParsePrivateKey reads a key in one of the three encodings in use.
func ParsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		// An encrypted key is recognised by the header and said so
		// directly: the panel has nowhere to ask for the passphrase, and
		// "key not recognised" would be a misleading answer to a different
		// question.
		if _, encrypted := block.Headers["DEK-Info"]; encrypted {
			return nil, fmt.Errorf("the key is encrypted with a passphrase; the store keeps keys without a passphrase")
		}
		if strings.HasPrefix(block.Type, "ENCRYPTED") {
			return nil, fmt.Errorf("the key is encrypted with a passphrase; the store keeps keys without a passphrase")
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, fmt.Errorf("the private key encoding was not recognised")
	}
	return nil, fmt.Errorf("the data contains no private key in PEM format")
}

// CheckChain checks whether the certificates in the file go from the leaf
// to the root and whether each is signed by the next.
//
// A wrong chain order is an error visible only at the client: the server
// starts, and every other program rejects the connection. That is why it
// is checked before the replacement, not after.
func CheckChain(certs []*x509.Certificate) error {
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return fmt.Errorf("certificate %d in the file does not sign the previous one (%s): %w",
				i+2, certs[i+1].Subject.CommonName, err)
		}
	}
	return nil
}

// CheckDates checks whether the certificate can be used today.
func CheckDates(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("the certificate becomes valid only on %s",
			cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if !cert.NotAfter.After(now) {
		return fmt.Errorf("the certificate expired on %s",
			cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// Directories the panel deploys certificates and keys into.
//
// The list is narrow on purpose. Writing a certificate anywhere in the
// filesystem is writing an arbitrary file - and for that there is the files
// module with its own safeguards, which does not touch keys and
// certificates anyway.
var allowedPrefixes = []string{
	"/etc/pki/tls/",
	"/etc/pki/flotestro/",
	"/etc/ssl/private/",
	"/etc/ssl/local/",
	// Debian keeps the server certificate in the same directory as the
	// trust store. A file lying there by itself makes nothing trusted yet
	// - trust comes from the generated bundle and the hash symlinks. That
	// is why the directory is allowed, and those two things are not.
	"/etc/ssl/certs/",
	"/etc/nginx/",
	"/etc/httpd/",
	"/etc/apache2/",
	"/etc/postfix/",
	"/etc/dovecot/",
	"/etc/letsencrypt/live/",
	"/etc/flotestro/certs/",
	"/opt/flotestro/certs/",
}

// forbiddenPrefixes lists the places the panel never touches - even when
// they lie inside an allowed directory.
//
// The trust store answers a different question than a service certificate:
// it says whom the host trusts, not what it presents itself as. Adding an
// authority there is a change of a different weight and must not look like
// a certificate deployment.
var forbiddenPrefixes = []string{
	"/etc/pki/ca-trust/",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ca-certificates/",
	"/usr/share/ca-certificates/",
	"/usr/local/share/ca-certificates/",
	// The agent identity is a separate subsystem with its own renewal:
	// replacing its certificate by an ordinary operation would cut the
	// panel off from the host at the moment the host stopped being itself.
	"/etc/flotestro/agent/",
	"/var/lib/flotestro/agent/",
}

// hashSymlink recognises the name OpenSSL looks an authority up by in the
// trust directory: eight hex digits and a sequence number. A file under
// such a name is not a service certificate - it is a trust store entry.
var hashSymlink = regexp.MustCompile(`^[0-9a-f]{8}\.[0-9]+$`)

// ValidatePath checks whether the panel may name this file.
//
// The same rule binds reading and writing: a path the panel does not write
// is not a path whose content it asks about either. Otherwise "look at
// this file" would be a way to read any file of the host.
func ValidatePath(p string) error {
	if p == "" {
		return fmt.Errorf("the path is empty")
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("the path %q is not absolute", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("the path %q leaves the named directory", p)
	}
	if strings.ContainsAny(p, "\n\t*?") {
		return fmt.Errorf("the path %q contains a disallowed character", p)
	}
	if p != path.Clean(p) {
		return fmt.Errorf("the path %q is not in normalised form", p)
	}
	if len(p) > 4096 {
		return fmt.Errorf("the path is longer than 4096 characters")
	}
	for _, prefix := range forbiddenPrefixes {
		if strings.HasPrefix(p, prefix) {
			return fmt.Errorf("the path %q belongs to the trust store or to the agent identity", p)
		}
	}
	if hashSymlink.MatchString(path.Base(p)) {
		return fmt.Errorf("the name %q is a trust store entry, not a service certificate",
			path.Base(p))
	}
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return nil
		}
	}
	return fmt.Errorf("the path %q lies outside the certificate directories", p)
}

// ValidateTarget checks the address the panel checks the deployed
// certificate at.
//
// The probe connects from the host, so an address without a port or with a
// name that cannot be split would turn the test into a random connection.
func ValidateTarget(target string) error {
	if target == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("the probe target %q does not have the form host:port", target)
	}
	if host == "" {
		return fmt.Errorf("the probe target %q names no host", target)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("the probe target %q has an invalid port", target)
	}
	return nil
}

// ValidateUnit checks the name of the service that is to read the new
// file.
func ValidateUnit(unit string) error {
	if unit == "" {
		return nil
	}
	if strings.ContainsAny(unit, " \t\n/;&|$`") {
		return fmt.Errorf("the unit name %q contains a disallowed character", unit)
	}
	if len(unit) > 256 {
		return fmt.Errorf("the unit name is too long")
	}
	return nil
}

// ValidateRequest bounds what goes to certmonger as a request name. The
// value comes from the panel and lands in a command argument.
func ValidateRequest(request string) error {
	if request == "" {
		return fmt.Errorf("a renewal requires a certmonger request identifier")
	}
	if len(request) > 128 {
		return fmt.Errorf("the request identifier is too long")
	}
	for _, r := range request {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("the request identifier %q contains a disallowed character", request)
	}
	return nil
}

// ParseGetcert reads the output of "getcert list".
//
// The entries are indented "Request ID 'name':" blocks. Four things are of
// interest: where the certificate lies, where the key, what state the
// request is in and whether the daemon renews it itself. The result is
// mapped by certificate path, because that is what links the request to
// the file the panel sees.
func ParseGetcert(output string) map[string]Tracking {
	trackings := map[string]Tracking{}
	var current Tracking
	var certPath string

	save := func() {
		if certPath != "" {
			trackings[certPath] = current
		}
		current, certPath = Tracking{}, ""
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Request ID"):
			save()
			current.Request = strings.Trim(strings.TrimSpace(
				strings.TrimSuffix(strings.TrimPrefix(trimmed, "Request ID"), ":")), "'")
		case strings.HasPrefix(trimmed, "status:"):
			current.Status = strings.TrimSpace(strings.TrimPrefix(trimmed, "status:"))
		case strings.HasPrefix(trimmed, "CA:"):
			current.CA = strings.TrimSpace(strings.TrimPrefix(trimmed, "CA:"))
		case strings.HasPrefix(trimmed, "certificate:"):
			certPath = pathFromLocation(strings.TrimPrefix(trimmed, "certificate:"))
		case strings.HasPrefix(trimmed, "key pair storage:"):
			current.KeyPath = pathFromLocation(strings.TrimPrefix(trimmed, "key pair storage:"))
		case strings.HasPrefix(trimmed, "auto-renew:"):
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "auto-renew:")) == "yes"
			current.AutoRenew = &value
		case strings.HasPrefix(trimmed, "expires:"):
			if moment, ok := ParseGetcertDate(strings.TrimPrefix(trimmed, "expires:")); ok {
				current.Expires = &moment
			}
		}
	}
	save()
	return trackings
}

// pathFromLocation extracts the path from a "type=FILE,location='/path'"
// description.
func pathFromLocation(description string) string {
	for _, field := range strings.Split(strings.TrimSpace(description), ",") {
		key, value, ok := strings.Cut(field, "=")
		if !ok || strings.TrimSpace(key) != "location" {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), "'\"")
	}
	return ""
}

// ParseGetcertDate reads a date in the format certmonger answers with.
func ParseGetcertDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{
		"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05", time.RFC3339,
	} {
		if moment, err := time.Parse(layout, value); err == nil {
			return moment.UTC(), true
		}
	}
	return time.Time{}, false
}
