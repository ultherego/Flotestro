package cryptostate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/pki"
)

// The certificate authorities of the fleet as rows of the database.
//
// This is the same material the state directory held, under the same names:
// one wrapped row per authority, kept for 'agent-ca', named by the issuer
// identifier of its certificate. What decides which of them signs and which is
// only prepared to take over is the bundle itself - a prepared one carries the
// moment it was prepared - and nothing else: a name, a column or an ordering
// would be a second opinion about the thing the certificate already says.

// AuthorityKeyStore is what the authorities need of the database on top of the
// wrapped keys: the certificates of the withdrawn ones, which carry no key,
// and the writes that have to be one step.
type AuthorityKeyStore interface {
	KeyStore
	// ReplaceAuthority writes one authority and removes the named ones in a
	// single transaction, and only while the installation record still names
	// the key encryption key the row was sealed with. A replica reading in
	// the middle of a handover must not find two authorities claiming to
	// sign, or none - nor one wrapped with a key a rewrap has been past.
	// seen names the authorities the caller read before it decided; the write
	// is refused when the installation no longer holds exactly those.
	ReplaceAuthority(ctx context.Context, row WrappedKey, remove, seen []string) error
	// DeleteAuthorities removes authority rows together.
	DeleteAuthorities(ctx context.Context, keyIDs []string) error
	// RetiredAuthorities returns the certificates withdrawn from signing,
	// in a stable order.
	RetiredAuthorities(ctx context.Context) ([][]byte, error)
	// PutRetiredAuthority keeps a withdrawn certificate under its serial.
	PutRetiredAuthority(ctx context.Context, serial string, certPEM []byte) error
	// DeleteRetiredAuthority forgets one. A serial that is not there is not
	// an error.
	DeleteRetiredAuthority(ctx context.Context, serial string) error
}

// authorityTimeout bounds one read or write of the authorities. They are small
// statements against the installation's own rows, and a panel hanging on one
// of them is a panel that signs nothing.
const authorityTimeout = 15 * time.Second

// DBAuthorities serves pki.AuthorityStore out of the database.
//
// It carries the context the panel runs under rather than taking one per call,
// because the seam it fills is the shape the CA has: a set the panel prepares,
// activates and retires from, with no request behind it.
type DBAuthorities struct {
	ctx   context.Context
	store AuthorityKeyStore
	kek   *InstallationKEK
}

// NewDBAuthorities reads and writes the authorities of an installation whose
// keys are in the database.
func NewDBAuthorities(ctx context.Context, store AuthorityKeyStore, kek *InstallationKEK) *DBAuthorities {
	return &DBAuthorities{ctx: ctx, store: store, kek: kek}
}

// authority is one CA as the database holds it, opened.
type authority struct {
	keyID      string
	keyPEM     []byte
	certPEM    []byte
	preparedAt time.Time
}

// Describe implements pki.AuthorityStore.
func (a *DBAuthorities) Describe() string { return "the database of this installation" }

// load opens every authority row and tells the one that signs from the one
// prepared to take over.
func (a *DBAuthorities) load() (active, prepared *authority, err error) {
	ctx, cancel := context.WithTimeout(a.ctx, authorityTimeout)
	defer cancel()
	rows, err := a.store.WrappedKeys(ctx, PurposeAgentCA)
	if err != nil {
		return nil, nil, fmt.Errorf("the authorities of the installation: %w", err)
	}
	for _, row := range rows {
		material, err := a.kek.Open(row)
		if err != nil {
			return nil, nil, err
		}
		keyPEM, certPEM, preparedAt, err := AuthorityParts(material)
		if err != nil {
			return nil, nil, fmt.Errorf("the authority %s: %w", row.KeyID, err)
		}
		found := &authority{keyID: row.KeyID, keyPEM: keyPEM, certPEM: certPEM}
		if len(preparedAt) > 0 {
			// A moment that does not parse is a marker that was damaged, not an
			// authority that is no longer prepared: the block is what makes it
			// prepared, and the caller takes an unreadable moment as now.
			found.preparedAt, _ = time.Parse(time.RFC3339, strings.TrimSpace(string(preparedAt)))
			if prepared != nil {
				return nil, nil, fmt.Errorf(
					"the installation holds two authorities prepared to take over, %s and %s",
					prepared.keyID, found.keyID)
			}
			prepared = found
			continue
		}
		if active != nil {
			return nil, nil, fmt.Errorf("the installation holds two authorities that both sign, %s and %s",
				active.keyID, found.keyID)
		}
		active = found
	}
	return active, prepared, nil
}

// HasMaterial implements pki.AuthorityStore.
func (a *DBAuthorities) HasMaterial() (bool, error) {
	active, prepared, err := a.load()
	if err != nil {
		return false, err
	}
	if active != nil || prepared != nil {
		return true, nil
	}
	retired, err := a.ReadRetired()
	if err != nil {
		return false, err
	}
	return len(retired) > 0, nil
}

// ReadActive implements pki.AuthorityStore. A row holds the key and the
// certificate together, so the halves are never apart: there is an authority
// or there is none.
func (a *DBAuthorities) ReadActive() ([]byte, []byte, error) {
	active, _, err := a.load()
	if err != nil || active == nil {
		return nil, nil, err
	}
	return active.keyPEM, active.certPEM, nil
}

// ReadPrepared implements pki.AuthorityStore.
func (a *DBAuthorities) ReadPrepared() ([]byte, []byte, time.Time, error) {
	_, prepared, err := a.load()
	if err != nil || prepared == nil {
		return nil, nil, time.Time{}, err
	}
	return prepared.keyPEM, prepared.certPEM, prepared.preparedAt, nil
}

// ReadRetired implements pki.AuthorityStore.
func (a *DBAuthorities) ReadRetired() ([][]byte, error) {
	ctx, cancel := context.WithTimeout(a.ctx, authorityTimeout)
	defer cancel()
	return a.store.RetiredAuthorities(ctx)
}

// WriteActive implements pki.AuthorityStore. The authority that signed until
// now goes in the same transaction as the one that signs from now on, whether
// it was a handover from a prepared authority or the first authority of the
// installation.
func (a *DBAuthorities) WriteActive(keyPEM, certPEM []byte) error {
	row, keyID, err := a.seal(keyPEM, certPEM, time.Time{})
	if err != nil {
		return err
	}
	active, prepared, err := a.load()
	if err != nil {
		return err
	}
	var remove []string
	if active != nil {
		remove = append(remove, active.keyID)
	}
	// A handover activates the prepared authority under the name it already
	// has; the row that carried it as prepared makes way for the row that
	// carries it as signing.
	if prepared != nil && prepared.keyID == keyID {
		remove = append(remove, keyID)
	}
	return a.replace(row, remove, observed(active, prepared))
}

// observed names the authorities a decision rested on, so the write can carry
// that condition: between the read and the write another replica may have
// activated an authority of its own, and a write without the condition would
// delete it.
func observed(active, prepared *authority) []string {
	var seen []string
	if active != nil {
		seen = append(seen, active.keyID)
	}
	if prepared != nil {
		seen = append(seen, prepared.keyID)
	}
	return seen
}

// WritePrepared implements pki.AuthorityStore.
func (a *DBAuthorities) WritePrepared(keyPEM, certPEM []byte, preparedAt time.Time) error {
	row, keyID, err := a.seal(keyPEM, certPEM, preparedAt)
	if err != nil {
		return err
	}
	active, prepared, err := a.load()
	if err != nil {
		return err
	}
	if active != nil && active.keyID == keyID {
		return fmt.Errorf("the authority %s signs for this installation and cannot also be the one prepared to take over",
			keyID)
	}
	var remove []string
	if prepared != nil {
		remove = append(remove, prepared.keyID)
	}
	return a.replace(row, remove, observed(active, prepared))
}

// DropPrepared implements pki.AuthorityStore.
func (a *DBAuthorities) DropPrepared() error {
	_, prepared, err := a.load()
	if err != nil || prepared == nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, authorityTimeout)
	defer cancel()
	return a.store.DeleteAuthorities(ctx, []string{prepared.keyID})
}

// WriteRetired implements pki.AuthorityStore.
func (a *DBAuthorities) WriteRetired(serial string, certPEM []byte) error {
	ctx, cancel := context.WithTimeout(a.ctx, authorityTimeout)
	defer cancel()
	return a.store.PutRetiredAuthority(ctx, serial, certPEM)
}

// DropRetired implements pki.AuthorityStore.
func (a *DBAuthorities) DropRetired(serial string) error {
	ctx, cancel := context.WithTimeout(a.ctx, authorityTimeout)
	defer cancel()
	return a.store.DeleteRetiredAuthority(ctx, serial)
}

// seal wraps one authority into the row that holds it, named by the issuer
// identifier of its certificate - the same name the migration of the keys into
// the database gave it.
func (a *DBAuthorities) seal(keyPEM, certPEM []byte, preparedAt time.Time) (WrappedKey, string, error) {
	cert, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		return WrappedKey{}, "", fmt.Errorf("the certificate of the authority: %w", err)
	}
	var stamp []byte
	if !preparedAt.IsZero() {
		stamp = []byte(preparedAt.UTC().Format(time.RFC3339))
	}
	keyID := pki.IssuerIDOf(cert)
	row, err := a.kek.Seal(keyID, PurposeAgentCA, AuthorityBundle(keyPEM, certPEM, stamp))
	if err != nil {
		return WrappedKey{}, "", err
	}
	return row, keyID, nil
}

// replace writes the row and removes the ones it takes the place of.
func (a *DBAuthorities) replace(row WrappedKey, remove, seen []string) error {
	ctx, cancel := context.WithTimeout(a.ctx, authorityTimeout)
	defer cancel()
	listed := map[string]bool{}
	names := make([]string, 0, len(remove))
	for _, name := range remove {
		if listed[name] {
			continue
		}
		listed[name] = true
		names = append(names, name)
	}
	return a.store.ReplaceAuthority(ctx, row, names, seen)
}
