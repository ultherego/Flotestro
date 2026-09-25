package cryptostate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/secrets"
)

// The states that stop the start. Each is a code the log carries and the
// runbook names; the reason next to it says which file or row it is about.
const (
	// CodeSecretsKeyUnavailable: the installation has secrets, or a record naming
	// a key, and that key is not there or does not open the sentinel.
	CodeSecretsKeyUnavailable = "secrets_key_unavailable"
	// CodeIssuerKeyUnavailable: the certificate of the fleet CA is there
	// and its private key is not.
	CodeIssuerKeyUnavailable = "issuer_key_unavailable"
	// CodePKIStateMismatch: the CA material does not fit together, or the
	// CA on disk is not the one the installation record names.
	CodePKIStateMismatch = "pki_state_mismatch"
	// CodeStateAmbiguous: no record, and what is there does not add up to
	// either an empty installation or a complete old one.
	CodeStateAmbiguous = "crypto_state_ambiguous"
	// CodeInstallationMismatch: the state directory and the database describe two
	// different installations, or one of them describes none while the other has
	// a history.
	CodeInstallationMismatch = "installation_state_mismatch"
)

// RunbookHint is the one line every fatal state ends with.
const RunbookHint = "do not create keys or a CA by hand; follow docs/runbooks/db-restore.md, section \"Cryptographic state at start\""

// FatalError is a state the panel refuses to start in.
type FatalError struct {
	Code   string
	Reason string
	// Stranger is set on the refusals that compare the state directory with the
	// database: it names the half that does not belong to the installation the
	// other half describes.
	Stranger Stranger
	Err      error
}

func (e *FatalError) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Reason + ": " + e.Err.Error()
	}
	return e.Code + ": " + e.Reason
}

func (e *FatalError) Unwrap() error { return e.Err }

func fatal(code, reason string, err error) error {
	return &FatalError{Code: code, Reason: reason, Err: err}
}

// fatalStranger is the refusal that compares the two halves of the
// installation and blames one of them.
func fatalStranger(code string, stranger Stranger, reason string) error {
	return &FatalError{Code: code, Reason: reason, Stranger: stranger}
}

// Options is what the guard works with.
type Options struct {
	Storage  Storage
	Provider Provider
	// CADir is the state directory the fleet CA lives in.
	CADir string
	// LegacyKeyPath is where an installation from before the provider
	// kept its one key. Empty means nowhere to look.
	LegacyKeyPath string
	// RotateTo names a key to switch the store to at this start; empty leaves the
	// active key alone.
	RotateTo string
	Log      *slog.Logger
}

// Runtime is the installation as the guard left it: the trust set, the
// provider with its active key, and the record they were checked against.
type Runtime struct {
	storage  Storage
	provider Provider
	trust    *pki.Trust
	log      *slog.Logger
	// caDir is where the fleet CA lives, so a reload reads what another
	// instance wrote there.
	caDir string

	mu     sync.RWMutex
	record Record
	// stale says this instance's picture of the crypto state is older than the
	// record and could not be brought up to date. It signs and seals with what
	// it has; the readiness answer says it is not fit to serve.
	stale string
	// initialised and adopted say what this start did: made a new
	// installation, or wrote the record for an existing one.
	initialised bool
	adopted     bool
	store       *secrets.Store
}

// Open is the startup guard.
func Open(ctx context.Context, o Options) (*Runtime, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	unlock, err := o.Storage.Lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	r := &Runtime{storage: o.Storage, provider: o.Provider, log: o.Log, caDir: o.CADir}
	record, err := o.Storage.Load(ctx)
	switch {
	case errors.Is(err, ErrNoRecord):
		if err := r.establish(ctx, o); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("reading the installation record: %w", err)
	default:
		if err := r.verify(ctx, o, *record); err != nil {
			return nil, err
		}
	}

	if o.RotateTo != "" {
		if err := r.rotate(ctx, o.RotateTo); err != nil {
			return nil, err
		}
	}
	r.trust.SetActivationHook(func(active *pki.CA) { r.recordIssuer(context.WithoutCancel(ctx), active) })
	r.assignIssuers(ctx)
	return r, nil
}

// verify is the path of an installation with a record: the key it names must
// be there and must open the sentinel, and the CA on disk must be the one it
// names.
func (r *Runtime) verify(ctx context.Context, o Options, record Record) error {
	// Which installation the state directory belongs to is asked before anything
	// else.
	marker, err := readMarker(o.CADir)
	if err != nil {
		return err
	}
	switch {
	case marker != "" && marker != record.InstallationID:
		return fatalStranger(CodeInstallationMismatch, StrangerStateDirectory, fmt.Sprintf(
			"the state directory %s belongs to the installation %s and the database describes the "+
				"installation %s: two installations were mixed, and this control plane would sign with "+
				"one fleet CA while the database records another",
			o.CADir, marker, record.InstallationID))
	case marker == "" && stateDirectoryEmpty(o):
		// The shape of the mistake chapter 21 forbids: a replica with a state volume
		// of its own next to the database of an installation that exists.
		return fatalStranger(CodeInstallationMismatch, StrangerStateDirectory, fmt.Sprintf(
			"the database describes the installation %s and %s holds no secret store key, no fleet CA "+
				"and no marker of any installation: this is either a control plane started with a state "+
				"volume of its own against an existing installation, or a database restored without the "+
				"state directory that belongs to it",
			record.InstallationID, o.CADir))
	}

	if record.Provider != o.Provider.Name() {
		return fatal(CodeSecretsKeyUnavailable,
			fmt.Sprintf("the installation was sealed by the provider %q and this panel runs %q",
				record.Provider, o.Provider.Name()), nil)
	}
	if err := o.Provider.RequireKey(ctx, record.ActiveKeyID); err != nil {
		return fatal(CodeSecretsKeyUnavailable,
			fmt.Sprintf("the installation %s names the key %s and the provider does not hold it",
				record.InstallationID, record.ActiveKeyID), err)
	}
	if err := openSentinel(ctx, o.Provider, record); err != nil {
		return fatal(CodeSecretsKeyUnavailable,
			fmt.Sprintf("the key %s does not open the sentinel of the installation %s: it is not the key the installation was sealed with",
				record.Sentinel.KeyID, record.InstallationID), err)
	}
	// Every key a live secret was sealed with, not only the active one. A key
	// the provider no longer holds is a secret nobody can read, and the panel
	// used to find that at the first read of that particular secret - a backup
	// credential, a repository token - which is the moment it must not.
	live, err := o.Storage.LiveKeyIDs(ctx)
	if err != nil {
		return fatal(CodeStateAmbiguous, "the keys of the live secret versions could not be read", err)
	}
	for _, keyID := range live {
		if keyID == record.ActiveKeyID || keyID == secrets.LegacyKeyID {
			continue
		}
		if err := o.Provider.RequireKey(ctx, keyID); err != nil {
			return fatal(CodeSecretsKeyUnavailable,
				fmt.Sprintf("secret versions of this installation are sealed with the key %s and the provider does not hold it",
					keyID), err)
		}
	}

	// The legacy key stays registered as long as it is on disk; a row of
	// the first form needs it until the rewrap reaches the row.
	if o.LegacyKeyPath != "" {
		if key, err := secrets.ReadKeyFile(o.LegacyKeyPath); err == nil {
			if err := o.Provider.Adopt(ctx, secrets.LegacyKeyID, key); err != nil {
				return fatal(CodeStateAmbiguous, "the legacy key file and keys/legacy.key differ", err)
			}
		}
	}
	o.Provider.SetActive(record.ActiveKeyID)

	trust, err := openTrust(o.CADir)
	if err != nil {
		return err
	}
	active := trust.Active()
	if active.IssuerID() != record.IssuerID {
		// The one benign case: the files were swapped by an activation and the
		// record was not told - the panel died between the two, or the update
		// failed.
		if !isRetired(trust, record.IssuerID) {
			return fatal(CodePKIStateMismatch,
				fmt.Sprintf("the CA on disk (%s, issuer %s) is not the one the installation %s records (issuer %s)",
					active.Certificate.SerialNumber, active.IssuerID(), record.InstallationID, record.IssuerID), nil)
		}
		record.IssuerID = active.IssuerID()
		record.IssuerFingerprint = active.FingerprintHex()
		if err := o.Storage.Update(ctx, record); err != nil {
			return fmt.Errorf("recording the CA that took over signing: %w", err)
		}
		if loaded, err := o.Storage.Load(ctx); err == nil {
			record = *loaded
		}
		r.log.Warn("the record of the fleet CA was behind the files and was caught up",
			"serial", active.Certificate.SerialNumber.String(), "issuer_id", active.IssuerID())
	} else if active.FingerprintHex() != record.IssuerFingerprint {
		return fatal(CodePKIStateMismatch,
			fmt.Sprintf("the CA on disk has the fingerprint %s and the installation records %s",
				active.FingerprintHex(), record.IssuerFingerprint), nil)
	}
	// Everything matched, so a directory that carried no marker is this
	// installation's and may now say so.
	if marker == "" {
		if err := writeMarker(o.CADir, record.InstallationID); err != nil {
			return fmt.Errorf("naming the installation of the state directory: %w", err)
		}
		r.log.Info("the state directory now names the installation it belongs to",
			"installation_id", record.InstallationID, "marker", MarkerPath(o.CADir))
	}
	r.trust = trust
	r.record = record
	r.log.Info("the cryptographic state of the installation was verified",
		"installation_id", record.InstallationID, "active_key_id", record.ActiveKeyID,
		"issuer_id", record.IssuerID, "revision", record.Revision)
	return nil
}

// establish is the path without a record: an empty installation is
// initialised, an installation from before the record has its material
// adopted, and anything in between stops.
func (r *Runtime) establish(ctx context.Context, o Options) error {
	facts, err := o.Storage.Facts(ctx)
	if err != nil {
		return fmt.Errorf("reading what the database holds: %w", err)
	}
	// A state directory that names an installation next to a database that
	// describes none: the database is the stranger.
	marker, err := readMarker(o.CADir)
	if err != nil {
		return err
	}
	if marker != "" {
		return fatalStranger(CodeInstallationMismatch, StrangerDatabase, fmt.Sprintf(
			"the state directory %s belongs to the installation %s and the database describes no "+
				"installation at all (%d hosts, %d certificates, %d secret versions): the control plane "+
				"was pointed at another database, or at a database restored from before this "+
				"installation existed",
			o.CADir, marker, facts.Hosts, facts.Certificates, facts.SecretVersions))
	}
	var legacyKey []byte
	if o.LegacyKeyPath != "" {
		legacyKey, err = secrets.ReadKeyFile(o.LegacyKeyPath)
		if err != nil && !errors.Is(err, secrets.ErrKeyMissing) {
			return fatal(CodeSecretsKeyUnavailable, "the legacy key file cannot be read", err)
		}
	}
	fresh := facts.Empty() && !o.Provider.HasMaterial() && !pki.HasAnyMaterial(o.CADir) && legacyKey == nil

	// The CA: opened when there is one, made only for a fleet that does
	// not exist yet.
	var trust *pki.Trust
	var createdCA bool
	switch {
	case pki.HasAnyMaterial(o.CADir):
		trust, err = openTrust(o.CADir)
		if err != nil {
			return err
		}
	case facts.Hosts > 0 || facts.Certificates > 0:
		return fatal(CodeStateAmbiguous,
			fmt.Sprintf("the database knows %d hosts and %d certificates, but %s holds no CA: the state directory was not restored with the database",
				facts.Hosts, facts.Certificates, o.CADir), nil)
	default:
		trust, err = pki.InitTrust(o.CADir)
		if err != nil {
			return fmt.Errorf("creating the fleet CA: %w", err)
		}
		createdCA = true
	}

	// The key: the legacy file is adopted when it is there; without it an
	// installation with secrets has lost its key, and one without secrets may
	// take a key that exists alone or make a new one.
	var activeKey string
	var createdKey bool
	switch {
	case legacyKey != nil:
		if err := o.Provider.Adopt(ctx, secrets.LegacyKeyID, legacyKey); err != nil {
			return fatal(CodeStateAmbiguous,
				fmt.Sprintf("%s and the key %q of the provider differ", o.LegacyKeyPath, secrets.LegacyKeyID), err)
		}
		activeKey = secrets.LegacyKeyID
	case facts.SecretVersions > 0:
		return fatal(CodeSecretsKeyUnavailable,
			fmt.Sprintf("the database holds %d secret versions and neither %s nor an installation record exists",
				facts.SecretVersions, legacyPathOrNone(o.LegacyKeyPath)), nil)
	case len(o.Provider.KeyIDs()) == 1:
		// An initialisation that wrote its key and died before the record:
		// nothing was sealed under it yet, and it is the only candidate.
		activeKey = o.Provider.KeyIDs()[0]
	case len(o.Provider.KeyIDs()) > 1:
		return fatal(CodeStateAmbiguous,
			fmt.Sprintf("the provider holds the keys %v and no record says which is active", o.Provider.KeyIDs()), nil)
	default:
		activeKey, err = o.Provider.Generate(ctx)
		if err != nil {
			return fmt.Errorf("creating the key of the secret store: %w", err)
		}
		createdKey = true
	}
	o.Provider.SetActive(activeKey)

	record := Record{
		InstallationID: uuid.NewString(),
		Provider:       o.Provider.Name(),
		ActiveKeyID:    activeKey,
	}
	record.IssuerID = trust.Active().IssuerID()
	record.IssuerFingerprint = trust.Active().FingerprintHex()
	record.Sentinel, err = sealSentinel(ctx, o.Provider, activeKey, record.InstallationID)
	if err != nil {
		return err
	}
	if err := o.Storage.Insert(ctx, record); err != nil {
		// The material of this run has nothing sealed under it; leaving
		// it would make the next start ambiguous.
		if createdKey {
			if remover, ok := o.Provider.(interface{ Remove(string) error }); ok {
				_ = remover.Remove(activeKey)
			}
		}
		if createdCA {
			for _, name := range []string{"ca.pem", "ca.key"} {
				_ = os.Remove(filepath.Join(o.CADir, name))
			}
		}
		return fmt.Errorf("recording the installation: %w", err)
	}
	loaded, err := o.Storage.Load(ctx)
	if err != nil {
		return fmt.Errorf("reading the installation record back: %w", err)
	}
	// The directory is named only once the record is safely in the database: a
	// marker without a record would refuse the very next start of an installation
	// that was never created.
	if err := writeMarker(o.CADir, record.InstallationID); err != nil {
		return fmt.Errorf("naming the installation of the state directory: %w", err)
	}
	r.trust = trust
	r.record = *loaded
	r.initialised = fresh
	r.adopted = !fresh
	if fresh {
		r.log.Info("the installation was initialised: a new secret store key and a new fleet CA",
			"installation_id", record.InstallationID, "active_key_id", activeKey, "issuer_id", record.IssuerID)
	} else {
		r.log.Info("the existing installation was adopted: its key and CA are now recorded and checked at every start",
			"installation_id", record.InstallationID, "active_key_id", activeKey, "issuer_id", record.IssuerID,
			"secret_versions", facts.SecretVersions, "hosts", facts.Hosts, "created_key", createdKey, "created_ca", createdCA)
	}
	return nil
}

// stateDirectoryEmpty says whether the state directory holds nothing that
// could belong to any installation: no key of the provider, no CA material and
// no legacy key file.
func stateDirectoryEmpty(o Options) bool {
	if o.Provider.HasMaterial() || pki.HasAnyMaterial(o.CADir) {
		return false
	}
	if o.LegacyKeyPath != "" {
		if _, err := os.Stat(o.LegacyKeyPath); err == nil {
			return false
		}
	}
	return true
}

func legacyPathOrNone(path string) string {
	if path == "" {
		return "a legacy key file"
	}
	return path
}

// openTrust reads the CA and translates its states into the fatal ones.
func openTrust(dir string) (*pki.Trust, error) {
	trust, err := pki.OpenTrust(dir)
	switch {
	case err == nil:
		return trust, nil
	case errors.Is(err, pki.ErrIssuerKeyUnavailable):
		return nil, fatal(CodeIssuerKeyUnavailable,
			fmt.Sprintf("the fleet CA certificate is in %s and its private key is not; the hosts trust that certificate, so a new CA would cut them off", dir), err)
	case errors.Is(err, pki.ErrStateMismatch):
		return nil, fatal(CodePKIStateMismatch,
			fmt.Sprintf("the CA material in %s does not fit together", dir), err)
	case errors.Is(err, pki.ErrNoMaterial):
		return nil, fatal(CodeIssuerKeyUnavailable,
			fmt.Sprintf("%s holds no fleet CA while the installation has one recorded", dir), err)
	default:
		return nil, fmt.Errorf("reading the fleet CA: %w", err)
	}
}

func isRetired(trust *pki.Trust, issuerID string) bool {
	for _, ca := range trust.Retired() {
		if ca.IssuerID() == issuerID {
			return true
		}
	}
	return false
}

// The sentinel is the installation identifier sealed under the active key,
// bound to itself by the associated data.
const sentinelKind = "sentinel"

func sentinelAssociated(installationID string) []byte {
	return secrets.AssociatedData(installationID, 0, sentinelKind, secrets.EnvelopeVersion)
}

func sealSentinel(ctx context.Context, keys secrets.KeyProvider, keyID, installationID string) (secrets.Envelope, error) {
	envelope, err := secrets.SealWith(ctx, keys, keyID, []byte(installationID), sentinelAssociated(installationID))
	if err != nil {
		return secrets.Envelope{}, fmt.Errorf("sealing the installation sentinel: %w", err)
	}
	return envelope, nil
}

func openSentinel(ctx context.Context, keys secrets.KeyProvider, record Record) error {
	if record.Sentinel.KeyID != record.ActiveKeyID {
		return fmt.Errorf("the sentinel is sealed under %s and the active key is %s", record.Sentinel.KeyID, record.ActiveKeyID)
	}
	value, err := record.Sentinel.Open(ctx, keys, sentinelAssociated(record.InstallationID))
	if err != nil {
		return err
	}
	if string(value) != record.InstallationID {
		return errors.New("the sentinel opened to another installation identifier")
	}
	return nil
}

// rotate switches the store to another key: the key is made when it does not
// exist yet, the sentinel is resealed under it and the record moves.
func (r *Runtime) rotate(ctx context.Context, to string) error {
	if err := ValidateKeyID(to); err != nil {
		return fmt.Errorf("FLOTESTRO_SECRETS_KEY_ROTATE_TO: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if to == r.record.ActiveKeyID {
		return nil
	}
	if to == secrets.LegacyKeyID {
		return fmt.Errorf("FLOTESTRO_SECRETS_KEY_ROTATE_TO: the store does not rotate back to the legacy key")
	}
	if err := r.provider.RequireKey(ctx, to); err != nil {
		if err := r.provider.GenerateNamed(ctx, to); err != nil {
			return fmt.Errorf("creating the key %s: %w", to, err)
		}
	}
	sentinel, err := sealSentinel(ctx, r.provider, to, r.record.InstallationID)
	if err != nil {
		return err
	}
	previous := r.record.ActiveKeyID
	moved := r.record
	moved.ActiveKeyID = to
	moved.Sentinel = sentinel
	if err := r.storage.UpdateIfRevision(ctx, moved, r.record.Revision); err != nil {
		return fmt.Errorf("recording the key rotation: %w", err)
	}
	loaded, err := r.storage.Load(ctx)
	if err != nil {
		return err
	}
	r.record = *loaded
	r.provider.SetActive(to)
	r.log.Warn("the secret store switched to a new key; the versions are rewrapped in the background and the old key is needed until none of them names it",
		"from", previous, "to", to)
	return nil
}

// recordIssuer is the activation hook: the record follows the files.
func (r *Runtime) recordIssuer(ctx context.Context, active *pki.CA) {
	r.mu.Lock()
	defer r.mu.Unlock()
	moved := r.record
	moved.IssuerID = active.IssuerID()
	moved.IssuerFingerprint = active.FingerprintHex()
	if err := r.storage.Update(ctx, moved); err != nil {
		r.log.Error("the fleet CA took over signing, but the installation record could not be updated; the next start catches it up",
			"err", err, "issuer_id", moved.IssuerID)
		return
	}
	if loaded, err := r.storage.Load(ctx); err == nil {
		r.record = *loaded
	}
	r.assignIssuers(ctx)
}

// assignIssuers fills in the issuer identifier of certificate rows that
// carry only the subject and serial of their CA.
func (r *Runtime) assignIssuers(ctx context.Context) {
	authorities := append([]*pki.CA{r.trust.Active()}, r.trust.Retired()...)
	for _, ca := range authorities {
		filled, err := r.storage.AssignIssuer(ctx, ca.Certificate.Subject.CommonName,
			ca.Certificate.SerialNumber.String(), ca.IssuerID())
		if err != nil {
			r.log.Warn("the issuer of the agent certificates could not be filled in", "err", err)
			return
		}
		if filled > 0 {
			r.log.Info("the issuer identifier of the agent certificates was filled in",
				"rows", filled, "issuer_id", ca.IssuerID())
		}
	}
}

// Trust returns the checked trust set.
func (r *Runtime) Trust() *pki.Trust { return r.trust }

// Provider returns the provider with its active key set.
func (r *Runtime) Provider() Provider { return r.provider }

// Record returns the installation record as last read.
func (r *Runtime) Record() Record {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.record
}

// SetSecrets hands the store over for the rewrap and the report.
func (r *Runtime) SetSecrets(store *secrets.Store) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.store = store
}

// rewrapBatch bounds one transaction of the rewrap.
const rewrapBatch = 200

// maintainInterval is how often the background work repeats: the rewrap of
// rows still on another key, and the issuer identifier of certificate rows
// written without one.
const maintainInterval = 5 * time.Minute

// reloadInterval is how often an instance asks whether the record moved. The
// window is what another instance's rotation costs: until this one reloads it
// signs with the old authority, and an agent that renewed against the new one
// does not verify here.
const reloadInterval = 15 * time.Second

// Maintain runs the background work until the context ends: once at start and
// then at every interval.
func (r *Runtime) Maintain(ctx context.Context) {
	ticker := time.NewTicker(maintainInterval)
	defer ticker.Stop()
	// The reload runs on its own, faster clock: an authority another instance
	// activated has to reach this one in seconds, not in the five minutes a
	// rewrap pass is happy with.
	reload := time.NewTicker(reloadInterval)
	defer reload.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reload.C:
				r.Reload(ctx)
			}
		}
	}()
	for {
		r.Rewrap(ctx)
		r.assignIssuers(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Reload brings this instance up to the record when another one has moved it:
// a key rotated, an authority activated. The state directory is shared - the
// installation check refuses a replica with one of its own - so what another
// instance wrote is on disk here, and reading it is the whole of the work.
//
// Without this, an authority activated on one replica left every other replica
// signing with the old one and rejecting the agents that had renewed against
// the new one: a routine, documented maintenance action taking a site down.
func (r *Runtime) Reload(ctx context.Context) {
	loaded, err := r.storage.Load(ctx)
	if err != nil || loaded == nil {
		if err != nil {
			r.log.Warn("the installation record was not read", "err", err)
		}
		return
	}
	r.mu.RLock()
	known := r.record.Revision
	r.mu.RUnlock()
	if loaded.Revision == known {
		return
	}

	// The key first: a seal with a key this instance does not hold fails at the
	// moment a secret is written, which is too late to be useful.
	if err := r.provider.RequireKey(ctx, loaded.ActiveKeyID); err != nil {
		r.markStale("the record names the key " + loaded.ActiveKeyID + " and this instance does not hold it")
		return
	}
	trust, err := openTrust(r.caDir)
	if err != nil {
		r.markStale("the fleet authority on disk could not be read: " + err.Error())
		return
	}
	if active := trust.Active(); active.IssuerID() != loaded.IssuerID {
		// The files and the record disagree, which is not this instance's to
		// resolve: it says so and keeps what it had.
		r.markStale("the authority on disk is " + active.IssuerID() +
			" and the record names " + loaded.IssuerID)
		return
	}

	r.mu.Lock()
	r.record = *loaded
	r.trust = trust
	r.stale = ""
	r.mu.Unlock()
	r.provider.SetActive(loaded.ActiveKeyID)
	r.log.Info("the crypto state of this instance was brought up to the record",
		"revision", loaded.Revision, "active_key", loaded.ActiveKeyID, "issuer", loaded.IssuerID)
}

// markStale records why this instance could not keep up, once per reason.
func (r *Runtime) markStale(reason string) {
	r.mu.Lock()
	changed := r.stale != reason
	r.stale = reason
	r.mu.Unlock()
	if changed {
		r.log.Error("this instance is behind the installation record and could not catch up", "reason", reason)
	}
}

// Stale says why this instance is behind the record, and is empty when it is
// not. The readiness answer reads it: an instance signing with an authority the
// installation has retired is not fit to serve.
func (r *Runtime) Stale() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.stale
}

// Rewrap moves every live version onto the active key, a batch at a time, and
// returns when none is left or the context ends.
func (r *Runtime) Rewrap(ctx context.Context) {
	r.mu.RLock()
	store := r.store
	r.mu.RUnlock()
	if store == nil {
		return
	}
	total := 0
	for {
		moved, remaining, err := store.RewrapBatch(ctx, rewrapBatch)
		if err != nil {
			if ctx.Err() == nil {
				r.log.Error("rewrapping the secret store stopped; it resumes at the next start", "err", err, "moved", total)
			}
			return
		}
		total += moved
		if remaining == 0 || moved == 0 {
			break
		}
	}
	if total > 0 {
		r.log.Info("the secret store was rewrapped onto the active key", "versions", total)
	}
}

// Report is the installation's cryptographic state for the status screen.
type Report struct {
	InstallationID    string
	Provider          string
	ActiveKeyID       string
	IssuerID          string
	IssuerFingerprint string
	Revision          int64
	InitializedAt     time.Time
	// Keys lists the keys the provider holds; one that no row names any
	// more may go.
	Keys []string
	// VersionsByKey counts the live versions per key; PendingRewrap is
	// the sum over every key but the active one.
	VersionsByKey map[string]int
	PendingRewrap int
	// Initialised and Adopted say what this process did at start.
	Initialised bool
	Adopted     bool
	// Err is what is wrong, when something is: the provider's health or
	// the sentinel self-test.
	Err error
}

// Report runs the self-test again and gathers the counts.
func (r *Runtime) Report(ctx context.Context) Report {
	r.mu.RLock()
	record := r.record
	store := r.store
	report := Report{
		InstallationID: record.InstallationID, Provider: record.Provider,
		ActiveKeyID: record.ActiveKeyID, IssuerID: record.IssuerID, IssuerFingerprint: record.IssuerFingerprint,
		Revision: record.Revision, InitializedAt: record.InitializedAt,
		Keys: r.provider.KeyIDs(), Initialised: r.initialised, Adopted: r.adopted,
		VersionsByKey: map[string]int{},
	}
	r.mu.RUnlock()

	if err := r.provider.Health(ctx); err != nil {
		report.Err = err
	} else if err := openSentinel(ctx, r.provider, record); err != nil {
		report.Err = fmt.Errorf("the sentinel does not open: %w", err)
	}
	if store != nil {
		counts, err := store.VersionsByKey(ctx)
		if err != nil {
			if report.Err == nil {
				report.Err = fmt.Errorf("counting the versions by key: %w", err)
			}
			return report
		}
		report.VersionsByKey = counts
		for keyID, count := range counts {
			if keyID != record.ActiveKeyID {
				report.PendingRewrap += count
			}
		}
	}
	return report
}
