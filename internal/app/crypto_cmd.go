package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/cryptostate"
	"github.com/ultherego/flotestro/internal/database"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/secrets"
)

// The commands that move the cryptographic identity of an installation
// between the state directory and the database.
//
// None of this runs on its own. The panel does not migrate itself at start,
// does not rewrap on a schedule, and never removes a key file: each of these
// is an operator saying, at a moment of their choosing, that they know what
// the installation is about to depend on.

const cryptoUsage = "the crypto commands are status, verify-secrets, import-state, revert-state, rewrap-kek and forget-files"

// runCrypto dispatches the crypto commands.
func runCrypto(args []string) error {
	if len(args) == 0 {
		return errors.New(cryptoUsage)
	}
	switch args[0] {
	case "status":
		return cryptoStatus(args[1:])
	case "verify-secrets":
		return cryptoVerifySecrets(args[1:])
	case "import-state":
		return cryptoImportState(args[1:])
	case "revert-state":
		return cryptoRevertState(args[1:])
	case "rewrap-kek":
		return cryptoRewrapKEK(args[1:])
	case "forget-files":
		return cryptoForgetFiles(args[1:])
	default:
		return fmt.Errorf("%q is not a crypto command; %s", args[0], cryptoUsage)
	}
}

// cryptoStatusReport is the cryptographic state of an installation as a
// command that only reads can tell it.
type cryptoStatusReport struct {
	// Installation is empty when the database holds no record: either a new
	// installation or one made before the record existed.
	Installation  string         `json:"installation_id"`
	Provider      string         `json:"provider,omitempty"`
	ActiveKeyID   string         `json:"active_key_id,omitempty"`
	Revision      int64          `json:"revision,omitempty"`
	InitializedAt string         `json:"initialized_at,omitempty"`
	VersionsByKey map[string]int `json:"versions_by_key"`
	// Pending counts the live versions that are not sealed the current way
	// under the active key: the first form, and anything on another key.
	Pending int `json:"pending_migration"`
}

// pendingMigration counts the live versions a rewrap still owes.
//
// Every key but the active one, which is what the status screen of a running
// panel counts too. An installation with no record has no active key, so every
// live version is owed - and that is the honest answer: the start adopts a key
// and rewraps all of them.
func pendingMigration(counts map[string]int, activeKeyID string) int {
	pending := 0
	for keyID, count := range counts {
		if keyID != activeKeyID || activeKeyID == "" {
			pending += count
		}
	}
	return pending
}

// cryptoStatus reports what the database says about the installation's keys
// and how many secret versions a rewrap still owes.
//
// It exists because nothing else could answer the second question without
// answering it wrongly. The counts are on the status screen of a running
// panel, but a panel that runs rewraps as it starts: by the time the screen
// could be read, the number it would have shown is zero. An operator about to
// restore a backup, or to upgrade an installation whose secrets predate the
// envelope, has no way to see what is there first. This command reads and
// changes nothing, so the number it prints is the number that was there.
func cryptoStatus(args []string) error {
	databaseURL, err := config.OptionalSecretValue("FLOTESTRO_DATABASE_URL")
	if err != nil {
		return err
	}
	set := flag.NewFlagSet("crypto status", flag.ContinueOnError)
	set.StringVar(&databaseURL, "database-url", databaseURL, "the PostgreSQL DSN")
	asJSON := set.Bool("json", false, "print the report as JSON")
	if err := set.Parse(args); err != nil {
		return err
	}
	if databaseURL == "" {
		return errors.New("no database was named; pass -database-url or set FLOTESTRO_DATABASE_URL")
	}

	ctx := context.Background()
	settings, err := config.DatabasePoolFromEnv()
	if err != nil {
		return err
	}
	pool, err := database.Open(ctx, databaseURL, settings)
	if err != nil {
		return err
	}
	defer pool.Close()

	report := cryptoStatusReport{VersionsByKey: map[string]int{}}
	record, err := cryptostate.NewPostgres(pool).Load(ctx)
	switch {
	case errors.Is(err, cryptostate.ErrNoRecord):
	case err != nil:
		return fmt.Errorf("the installation record: %w", err)
	default:
		report.Installation = record.InstallationID
		report.Provider = record.Provider
		report.ActiveKeyID = record.ActiveKeyID
		report.Revision = record.Revision
		report.InitializedAt = record.InitializedAt.UTC().Format(time.RFC3339)
	}
	// The store is built without a provider on purpose: the count is a query
	// over the rows, and a command that only reports must not need the keys.
	counts, err := secrets.NewStore(pool, nil).VersionsByKey(ctx)
	if err != nil {
		return fmt.Errorf("counting the live secret versions by key: %w", err)
	}
	report.VersionsByKey = counts
	report.Pending = pendingMigration(counts, report.ActiveKeyID)

	if *asJSON {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", encoded)
		return nil
	}
	printCryptoStatus(os.Stdout, report)
	return nil
}

// printCryptoStatus writes the report as name: value lines, so that a script
// asserting one number does not have to read a sentence.
func printCryptoStatus(out io.Writer, report cryptoStatusReport) {
	if report.Installation == "" {
		fmt.Fprintln(out, "installation_id: none")
		fmt.Fprintln(out, "note: this database holds no installation record; the next start adopts one")
	} else {
		fmt.Fprintf(out, "installation_id: %s\n", report.Installation)
		fmt.Fprintf(out, "provider: %s\n", report.Provider)
		fmt.Fprintf(out, "active_key_id: %s\n", report.ActiveKeyID)
		fmt.Fprintf(out, "revision: %d\n", report.Revision)
		fmt.Fprintf(out, "initialized_at: %s\n", report.InitializedAt)
	}
	live := 0
	for _, keyID := range slices.Sorted(maps.Keys(report.VersionsByKey)) {
		count := report.VersionsByKey[keyID]
		live += count
		label := keyID
		if label == "" {
			label = "(no key)"
		}
		fmt.Fprintf(out, "versions_by_key %s: %d\n", label, count)
	}
	fmt.Fprintf(out, "live_versions: %d\n", live)
	fmt.Fprintf(out, "pending_migration: %d\n", report.Pending)
	if report.Pending > 0 {
		fmt.Fprintf(out, "note: %d live secret versions are in the first form or on another key; "+
			"the rewrap of a running panel moves them onto %s\n", report.Pending,
			orNone(report.ActiveKeyID))
	}
}

// orNone names the active key for a message, for an installation that has none
// yet.
func orNone(activeKeyID string) string {
	if activeKeyID == "" {
		return "the key the next start adopts"
	}
	return activeKeyID
}

// cryptoVerifySecrets opens every stored secret version with the keys the
// installation holds and prints, per version, the form it is in, the key it
// names and the fingerprint of its value.
//
// It exists because the store has no reader an operator can use. A value is
// handed out on a lease, to a host, for one task - correctly - and nothing
// else in the product will say whether the installation can still open what it
// holds. That is the question of a restore drill, and it is the question a key
// migration has to answer about itself: the fingerprints before and after are
// the comparison, and the value does not leave the process to make it.
//
// Nothing is written. The keys it uses are the ones already on disk or in the
// rows, so it does not adopt, create or rotate anything, and it may be run
// against an installation nobody has started.
func cryptoVerifySecrets(args []string) error {
	databaseURL, err := config.OptionalSecretValue("FLOTESTRO_DATABASE_URL")
	if err != nil {
		return err
	}
	set := flag.NewFlagSet("crypto verify-secrets", flag.ContinueOnError)
	set.StringVar(&databaseURL, "database-url", databaseURL, "the PostgreSQL DSN")
	stateDir := set.String("state-dir", config.Env("FLOTESTRO_STATE_DIR", "/var/lib/flotestro"),
		"the state directory the keys are read from")
	kekFile := set.String("kek-file", config.Env("FLOTESTRO_KEK_FILE", cryptostate.DefaultKEKFile),
		"the file the key encryption key is mounted at, for an installation whose keys are rows")
	asJSON := set.Bool("json", false, "print the report as JSON")
	if err := set.Parse(args); err != nil {
		return err
	}
	if databaseURL == "" {
		return errors.New("no database was named; pass -database-url or set FLOTESTRO_DATABASE_URL")
	}

	ctx := context.Background()
	settings, err := config.DatabasePoolFromEnv()
	if err != nil {
		return err
	}
	pool, err := database.Open(ctx, databaseURL, settings)
	if err != nil {
		return err
	}
	defer pool.Close()

	local, err := cryptostate.NewLocalProvider(filepath.Join(*stateDir, cryptostate.KeysDir), "")
	if err != nil {
		return fmt.Errorf("the key provider: %w", err)
	}
	storage := cryptostate.NewPostgres(pool)
	// The same choice the start makes, and from the record rather than from a
	// flag: a report that read the files of an installation that has moved its
	// keys into the database would be a report about material the installation
	// stopped sealing with.
	provider, err := cryptostate.SelectProvider(ctx, storage, *kekFile, "", local)
	if err != nil {
		return err
	}
	checks, err := secrets.NewStore(pool, provider).Verify(ctx)
	if err != nil {
		return err
	}

	if *asJSON {
		if err := printVerificationJSON(os.Stdout, checks); err != nil {
			return err
		}
	} else {
		printVerification(os.Stdout, checks)
	}
	failed := 0
	for _, check := range checks {
		if check.Err != nil {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d stored secret versions did not open with the keys of this installation",
			failed, len(checks))
	}
	return nil
}

// verifiedVersion is one line of the report, for the JSON form.
type verifiedVersion struct {
	Secret          string `json:"secret"`
	Version         int    `json:"version"`
	EnvelopeVersion int    `json:"envelope_version"`
	KeyID           string `json:"key_id,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
	Destroyed       bool   `json:"destroyed,omitempty"`
	Error           string `json:"error,omitempty"`
}

// renderVerification turns the checks into the lines both forms print.
func renderVerification(checks []secrets.VersionCheck) []verifiedVersion {
	rendered := make([]verifiedVersion, 0, len(checks))
	for _, check := range checks {
		line := verifiedVersion{
			Secret: check.SecretName, Version: check.Version,
			EnvelopeVersion: check.EnvelopeVersion, KeyID: check.KeyID,
			SHA256: check.SHA256, Destroyed: check.Destroyed,
		}
		if check.Err != nil {
			line.Error = check.Err.Error()
		}
		rendered = append(rendered, line)
	}
	return rendered
}

// printVerification writes one line per version, in a shape a script can read
// field by field.
func printVerification(out io.Writer, checks []secrets.VersionCheck) {
	opened, failed, destroyed := 0, 0, 0
	for _, line := range renderVerification(checks) {
		switch {
		case line.Destroyed:
			destroyed++
			fmt.Fprintf(out, "%s version %d envelope %d key %s destroyed\n",
				line.Secret, line.Version, line.EnvelopeVersion, orNoKey(line.KeyID))
		case line.Error != "":
			failed++
			fmt.Fprintf(out, "%s version %d envelope %d key %s FAILED %s\n",
				line.Secret, line.Version, line.EnvelopeVersion, orNoKey(line.KeyID), line.Error)
		default:
			opened++
			fmt.Fprintf(out, "%s version %d envelope %d key %s sha256 %s\n",
				line.Secret, line.Version, line.EnvelopeVersion, orNoKey(line.KeyID), line.SHA256)
		}
	}
	fmt.Fprintf(out, "opened: %d\n", opened)
	fmt.Fprintf(out, "destroyed: %d\n", destroyed)
	fmt.Fprintf(out, "failed: %d\n", failed)
}

// printVerificationJSON writes the same report for something that parses it.
func printVerificationJSON(out io.Writer, checks []secrets.VersionCheck) error {
	encoded, err := json.MarshalIndent(renderVerification(checks), "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s\n", encoded)
	return err
}

// orNoKey names the key of a version of the first form, which names none.
func orNoKey(keyID string) string {
	if keyID == "" {
		return "-"
	}
	return keyID
}

// cryptoOptions is what every crypto command needs to know.
type cryptoOptions struct {
	set         *flag.FlagSet
	databaseURL string
	files       installationFiles
	kekFile     string
	backupTo    string
	dryRun      bool
}

// cryptoFlags defines the flags all four commands share. The defaults follow
// the serving panel's, so that an operator running a command against a
// deployment does not have to restate where anything lives.
func cryptoFlags(name string) (*cryptoOptions, error) {
	databaseURL, err := config.OptionalSecretValue("FLOTESTRO_DATABASE_URL")
	if err != nil {
		return nil, err
	}
	options := &cryptoOptions{set: flag.NewFlagSet("crypto "+name, flag.ContinueOnError)}
	options.set.StringVar(&options.databaseURL, "database-url", databaseURL, "the PostgreSQL DSN")
	options.set.StringVar(&options.files.StateDir, "state-dir",
		config.Env("FLOTESTRO_STATE_DIR", "/var/lib/flotestro"), "the state directory")
	options.set.StringVar(&options.kekFile, "kek-file",
		config.Env("FLOTESTRO_KEK_FILE", cryptostate.DefaultKEKFile),
		"the file the key encryption key is mounted at (64 hexadecimal characters)")
	options.set.StringVar(&options.files.LegacyKeyPath, "secrets-key-file",
		config.Env("FLOTESTRO_SECRETS_KEY_FILE", ""),
		"the one key of an installation from before the keys were named; the default is secrets.key in the state directory")
	options.set.StringVar(&options.files.HelperKeyPath, "helper-signing-key",
		config.Env("FLOTESTRO_HELPER_SIGNING_KEY", ""),
		"the Ed25519 key that signs helper capabilities; the default is helper-signing.key in the state directory")
	options.set.StringVar(&options.backupTo, "backup-to", "",
		"the directory a record of the state before the change is written to (required)")
	options.set.BoolVar(&options.dryRun, "dry-run", false,
		"say what would happen and change nothing")
	return options, nil
}

// parse reads the arguments and fills in what the defaults could only express
// relative to the state directory.
func (o *cryptoOptions) parse(args []string) error {
	if err := o.set.Parse(args); err != nil {
		return err
	}
	if o.files.LegacyKeyPath == "" {
		o.files.LegacyKeyPath = filepath.Join(o.files.StateDir, "secrets.key")
	}
	if o.files.HelperKeyPath == "" {
		o.files.HelperKeyPath = filepath.Join(o.files.StateDir, "helper-signing.key")
	}
	if o.databaseURL == "" {
		return errors.New("no database was named; pass -database-url or set FLOTESTRO_DATABASE_URL")
	}
	if o.backupTo == "" {
		return errors.New("no backup directory was named; pass -backup-to")
	}
	// A copy that lives in the directory being emptied is not a copy:
	// forget-files puts the key files in the backup directory and then removes
	// them from the state directory.
	inside, err := within(o.files.StateDir, o.backupTo)
	if err != nil {
		return err
	}
	if inside {
		return fmt.Errorf("the backup directory %s is inside the state directory %s; "+
			"a copy kept where the originals are is not a copy", o.backupTo, o.files.StateDir)
	}
	return nil
}

// within says whether one path lies inside another, with both resolved as far
// as the filesystem allows: a symbolic link into the state directory is still
// the state directory.
func within(outer, inner string) (bool, error) {
	outerPath, err := filepath.Abs(outer)
	if err != nil {
		return false, err
	}
	innerPath, err := filepath.Abs(inner)
	if err != nil {
		return false, err
	}
	if resolved, err := filepath.EvalSymlinks(outerPath); err == nil {
		outerPath = resolved
	}
	if resolved, err := filepath.EvalSymlinks(innerPath); err == nil {
		innerPath = resolved
	}
	relative, err := filepath.Rel(outerPath, innerPath)
	if err != nil {
		return false, nil
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)), nil
}

// open connects to the fleet database and reads the key encryption key, bound
// to the installation the database describes.
//
// The binding is done here, in the one place every crypto command comes
// through, and from the record rather than from a flag: a key bound to an
// installation an operator typed would seal rows into a deployment that is not
// the one at the other end of this connection string.
func (o *cryptoOptions) open(ctx context.Context) (*cryptostate.Postgres, *cryptostate.InstallationKEK, func(), error) {
	kek, err := cryptostate.ReadKEKFile(o.kekFile)
	if err != nil {
		return nil, nil, nil, err
	}
	// The pool the deployment configured, not one of this command's own: the
	// floors database.Open enforces are the serving panel's, and a command that
	// invented its own numbers would be refused by them before it reached the
	// database.
	settings, err := config.DatabasePoolFromEnv()
	if err != nil {
		return nil, nil, nil, err
	}
	pool, err := database.Open(ctx, o.databaseURL, settings)
	if err != nil {
		return nil, nil, nil, err
	}
	store := cryptostate.NewPostgres(pool)
	record, err := store.Load(ctx)
	if err != nil {
		pool.Close()
		return nil, nil, nil, fmt.Errorf("the installation record: %w", err)
	}
	return store, kek.For(record.InstallationID), pool.Close, nil
}

// cryptoBackup is what is written before anything changes: enough to put the
// installation back the way it was, and never any key in the clear. The rows
// it carries are the wrapped ones; whoever restores them needs the key
// encryption key of the day they were written, which is the point.
type cryptoBackup struct {
	Operation      string                   `json:"operation"`
	At             time.Time                `json:"at"`
	InstallationID string                   `json:"installation_id"`
	KEKID          string                   `json:"kek_id,omitempty"`
	Entries        []cryptostate.Entry      `json:"entries,omitempty"`
	Rows           []cryptostate.WrappedKey `json:"rows,omitempty"`
	Note           string                   `json:"note"`
}

// writeBackup puts the record of the state before the change where the
// operator asked for it, and refuses to overwrite one.
func writeBackup(dir, operation string, backup cryptoBackup) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("the backup directory: %w", err)
	}
	name := fmt.Sprintf("flotestro-crypto-%s-%s.json", operation, backup.At.UTC().Format("20060102T150405Z"))
	path := filepath.Join(dir, name)
	content, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("the backup file: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(content, '\n')); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	return path, nil
}

// printReport says what a migration did, or would do, in the same words either
// way: a dry run an operator cannot compare with the run itself is worth
// nothing.
func printReport(out io.Writer, report cryptostate.MigrationReport, dryRun bool) {
	verb := "moved"
	if dryRun {
		verb = "would move"
	}
	fmt.Fprintf(out, "%s %d keys, wrapped with %s\n", verb, len(report.Entries), report.KEKID)
	if report.PreviousKEKID != "" {
		fmt.Fprintf(out, "  from %s\n", report.PreviousKEKID)
	}
	for _, entry := range report.Entries {
		fmt.Fprintf(out, "  %-12s %-40s %s\n", entry.Purpose, entry.KeyID, entry.Digest)
		if entry.Source != "" {
			fmt.Fprintf(out, "               from %s\n", entry.Source)
		}
	}
}

// cryptoImportState moves every private key of the installation into the
// database. The files are left where they are: until the operator says
// otherwise they are the way back.
func cryptoImportState(args []string) error {
	options, err := cryptoFlags("import-state")
	if err != nil {
		return err
	}
	if err := options.parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, kek, closePool, err := options.open(ctx)
	if err != nil {
		return err
	}
	defer closePool()

	record, err := store.Load(ctx)
	if err != nil {
		return fmt.Errorf("the installation record: %w", err)
	}
	materials, err := options.files.collect()
	if err != nil {
		return err
	}
	retired, err := options.files.collectRetired()
	if err != nil {
		return err
	}
	preview, err := cryptostate.Preview(ctx, store, kek, materials, retired)
	if err != nil {
		return err
	}
	if options.dryRun {
		printReport(os.Stdout, preview, true)
		fmt.Printf("nothing was changed; the files under %s stay where they are\n", options.files.StateDir)
		return nil
	}
	path, err := writeBackup(options.backupTo, "import-state", cryptoBackup{
		Operation:      "import-state",
		At:             time.Now().UTC(),
		InstallationID: record.InstallationID,
		KEKID:          kek.ID(),
		Entries:        preview.Entries,
		Note: "the keys were in these files when this was written; they are not removed by import-state, " +
			"and crypto revert-state puts the installation back",
	})
	if err != nil {
		return err
	}
	report, err := cryptostate.Import(ctx, store, kek, materials, retired)
	if err != nil {
		return err
	}
	printReport(os.Stdout, report, false)
	fmt.Printf("the record of the installation now names %s\n", kek.ID())
	fmt.Printf("what the files held is written down in %s\n", path)
	fmt.Println("the panel reads its keys from the database once it is restarted with the same key encryption key")
	return nil
}

// cryptoRevertState writes the keys back into the state directory and takes
// them out of the database. The files come first: an interrupted revert leaves
// the installation readable from the database rather than from nowhere.
func cryptoRevertState(args []string) error {
	options, err := cryptoFlags("revert-state")
	if err != nil {
		return err
	}
	if err := options.parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, kek, closePool, err := options.open(ctx)
	if err != nil {
		return err
	}
	defer closePool()

	record, err := store.Load(ctx)
	if err != nil {
		return fmt.Errorf("the installation record: %w", err)
	}
	materials, err := cryptostate.Export(ctx, store, kek)
	if err != nil {
		return err
	}
	retired, err := cryptostate.ExportRetired(ctx, store)
	if err != nil {
		return err
	}
	plan, err := options.files.restorePlan(materials, record)
	if err != nil {
		return err
	}
	plan = append(plan, options.files.retiredPlan(retired)...)
	if options.dryRun {
		fmt.Printf("would write %d files back into %s\n", len(plan), options.files.StateDir)
		for _, step := range plan {
			fmt.Printf("  %s\n", step.path)
		}
		fmt.Println("and would then take the keys out of the database; nothing was changed")
		return nil
	}
	rows, err := allRows(ctx, store)
	if err != nil {
		return err
	}
	path, err := writeBackup(options.backupTo, "revert-state", cryptoBackup{
		Operation:      "revert-state",
		At:             time.Now().UTC(),
		InstallationID: record.InstallationID,
		KEKID:          kek.ID(),
		Rows:           rows,
		Note: "these are the wrapped keys as the database held them; they open with the key encryption key " +
			"named here and with no other",
	})
	if err != nil {
		return err
	}
	for _, step := range plan {
		if err := step.write(); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", step.path)
	}
	written := make([]string, 0, len(materials))
	for _, material := range materials {
		written = append(written, material.KeyID)
	}
	if err := store.ForgetKeys(ctx, kek.ID(), written); err != nil {
		return fmt.Errorf("the files are back, but the rows could not be dropped: %w", err)
	}
	fmt.Printf("the installation reads its keys from %s again\n", options.files.StateDir)
	fmt.Printf("the rows as they were are written down in %s\n", path)
	return nil
}

// cryptoRewrapKEK moves every row from one key encryption key to another. The
// keys themselves do not change, so nothing the hosts hold has to change
// either.
func cryptoRewrapKEK(args []string) error {
	options, err := cryptoFlags("rewrap-kek")
	if err != nil {
		return err
	}
	newKEKFile := options.set.String("new-kek-file", "",
		"the file the new key encryption key is mounted at (required)")
	if err := options.parse(args); err != nil {
		return err
	}
	if *newKEKFile == "" {
		return errors.New("no new key encryption key was named; pass -new-kek-file")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, current, closePool, err := options.open(ctx)
	if err != nil {
		return err
	}
	defer closePool()
	unbound, err := cryptostate.ReadKEKFile(*newKEKFile)
	if err != nil {
		return err
	}
	record, err := store.Load(ctx)
	if err != nil {
		return fmt.Errorf("the installation record: %w", err)
	}
	// The key the rows are moving to answers for the same installation as the
	// key they are moving from; a rewrap changes the wrapping and nothing else.
	next := unbound.For(record.InstallationID)
	rows, err := allRows(ctx, store)
	if err != nil {
		return err
	}
	if options.dryRun {
		fmt.Printf("would rewrap %d keys from %s to %s\n", len(rows), current.ID(), next.ID())
		for _, row := range rows {
			if _, err := current.Open(row); err != nil {
				return err
			}
			fmt.Printf("  %-12s %s\n", row.Purpose, row.KeyID)
		}
		fmt.Println("nothing was changed")
		return nil
	}
	path, err := writeBackup(options.backupTo, "rewrap-kek", cryptoBackup{
		Operation:      "rewrap-kek",
		At:             time.Now().UTC(),
		InstallationID: record.InstallationID,
		KEKID:          current.ID(),
		Rows:           rows,
		Note: "these are the wrapped keys before the rewrap; they open with the key encryption key named here, " +
			"which is the one being replaced",
	})
	if err != nil {
		return err
	}
	report, err := cryptostate.Rewrap(ctx, store, current, next)
	if err != nil {
		return err
	}
	printReport(os.Stdout, report, false)
	fmt.Printf("the rows as they were are written down in %s\n", path)
	fmt.Printf("mount %s as the key encryption key of every replica and restart them\n", *newKEKFile)
	return nil
}

func allRows(ctx context.Context, store *cryptostate.Postgres) ([]cryptostate.WrappedKey, error) {
	var rows []cryptostate.WrappedKey
	for _, purpose := range []string{
		cryptostate.PurposeSecrets, cryptostate.PurposeAgentCA, cryptostate.PurposeHelperSigning,
	} {
		found, err := store.WrappedKeys(ctx, purpose)
		if err != nil {
			return nil, err
		}
		rows = append(rows, found...)
	}
	return rows, nil
}

// restoreStep is one file a revert puts back.
type restoreStep struct {
	path    string
	mode    os.FileMode
	content []byte
}

func (s restoreStep) write() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	temporary := s.path + ".new"
	if err := writeFileSynced(temporary, s.content, s.mode); err != nil {
		return err
	}
	// The mode is set after the write, because a umask would take the bits off
	// again and leave a key readable by whoever the account shares a group with.
	if err := os.Chmod(temporary, s.mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, s.path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(s.path))
}

// writeFileSynced puts the content on the disk rather than in the page cache.
// A revert interrupted by a power cut must leave the old file or the new one,
// never a ca.key of the right length and the wrong content.
func writeFileSynced(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// restorePlan works out which file each key goes back to. Which authority is
// the active one is the record's to say, not a guess from a file name: that is
// the half of the installation that was never in doubt.
func (f installationFiles) restorePlan(materials []cryptostate.Material, record *cryptostate.Record) ([]restoreStep, error) {
	var plan []restoreStep
	authorities := 0
	for _, material := range materials {
		switch material.Purpose {
		case cryptostate.PurposeSecrets:
			plan = append(plan, restoreStep{
				path:    filepath.Join(f.keysDir(), material.KeyID+".key"),
				mode:    0o600,
				content: material.Bytes,
			})
		case cryptostate.PurposeAgentCA:
			keyPEM, certPEM, preparedAt, err := cryptostate.AuthorityParts(material.Bytes)
			if err != nil {
				return nil, fmt.Errorf("the authority %s: %w", material.KeyID, err)
			}
			authorities++
			if authorities > 2 {
				return nil, fmt.Errorf(
					"the installation holds %d authorities; only the active one and a prepared one have a place on disk",
					authorities)
			}
			keyFile, certFile := pki.CAKeyFile, pki.CACertFile
			if material.KeyID != record.IssuerID {
				keyFile, certFile = pki.PendingKeyFile, pki.PendingCertFile
			}
			plan = append(plan,
				restoreStep{path: filepath.Join(f.StateDir, keyFile), mode: 0o600, content: keyPEM},
				restoreStep{path: filepath.Join(f.StateDir, certFile), mode: 0o644, content: certPEM})
			if len(preparedAt) > 0 {
				plan = append(plan, restoreStep{
					path: filepath.Join(f.StateDir, pki.PreparedAtFile), mode: 0o644, content: preparedAt})
			}
		case cryptostate.PurposeHelperSigning:
			path := f.HelperKeyPath
			if strings.HasPrefix(material.KeyID, cryptostate.HelperPreviousPrefix) {
				path = helpercap.PreviousKeyPath(f.HelperKeyPath)
			}
			plan = append(plan, restoreStep{path: path, mode: 0o600, content: material.Bytes})
		default:
			return nil, fmt.Errorf("the key %s is kept for %s, which has no place on disk",
				material.KeyID, material.Purpose)
		}
	}
	return plan, nil
}

// cryptoForgetFiles removes the key files the installation no longer reads.
//
// It never runs by itself. The migration leaves the files in place on purpose:
// they are the controlled way back, and the moment they go, going back needs a
// backup instead. So this command asks the installation six questions and
// refuses on the first "no":
//
//	is the migration finished;
//	does every key the installation needs open from the database;
//	is this the same installation the files belong to;
//	is the record still at the revision the operator read;
//	did the operator say the installation's own name back;
//	and have they been told what stops working afterwards.
//
// What it then does is remove the files and synchronise the directories. On an
// SSD, on a copy-on-write filesystem or on network storage that is an unlink,
// not an erasure of the bytes, and nothing here pretends otherwise.
func cryptoForgetFiles(args []string) error {
	options, err := cryptoFlags("forget-files")
	if err != nil {
		return err
	}
	confirm := options.set.String("confirm-installation", "",
		"the installation identifier, said back as confirmation")
	expect := options.set.Int64("expect-revision", 0,
		"the revision of the crypto state the operator read (required)")
	if err := options.parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, kek, closePool, err := options.open(ctx)
	if err != nil {
		return err
	}
	defer closePool()

	record, err := store.Load(ctx)
	if err != nil {
		return fmt.Errorf("the installation record: %w", err)
	}
	// One: the migration is finished, and with this key.
	recorded, err := store.KEKID(ctx)
	if err != nil {
		return err
	}
	if recorded == "" {
		return errors.New("the keys of this installation are not in the database; there is nothing the files are a copy of")
	}
	if !kek.Is(recorded) {
		return fmt.Errorf("the installation is wrapped with %s and this deployment holds %s", recorded, kek.ID())
	}
	// Two: every key opens from the database, and holds what the file holds.
	fromDatabase, err := cryptostate.Export(ctx, store, kek)
	if err != nil {
		return err
	}
	fromFiles, err := options.files.collect()
	if err != nil {
		return err
	}
	if err := sameKeys(fromFiles, fromDatabase); err != nil {
		return err
	}
	retiredOnDisk, err := options.files.collectRetired()
	if err != nil {
		return err
	}
	retiredInDatabase, err := cryptostate.ExportRetired(ctx, store)
	if err != nil {
		return err
	}
	if err := sameAuthorities(retiredOnDisk, retiredInDatabase); err != nil {
		return err
	}
	// Three: the files belong to this installation and not to another one that
	// happens to sit in the same directory.
	marker, err := cryptostate.ReadMarker(options.files.StateDir)
	if err != nil {
		return fmt.Errorf("the installation marker: %w", err)
	}
	if marker != record.InstallationID {
		return fmt.Errorf("%s belongs to the installation %s, and the database is %s",
			options.files.StateDir, marker, record.InstallationID)
	}
	// Four: the record has not moved since the operator looked.
	if *expect == 0 {
		return fmt.Errorf(
			"pass -expect-revision %d, the revision of the crypto state this installation stands at",
			record.Revision)
	}
	if *expect != record.Revision {
		return fmt.Errorf("the crypto state is at revision %d and the command was given %d",
			record.Revision, *expect)
	}
	// Five: the operator says the name of the installation back.
	if *confirm != record.InstallationID {
		return fmt.Errorf(
			"pass -confirm-installation %s to say which installation's key files are to be removed",
			record.InstallationID)
	}

	paths := append(materialPaths(fromFiles), retiredPaths(retiredOnDisk)...)
	// The certificates go with the keys they belong to. They are public, so
	// nothing is protected by removing them; what is avoided is a directory
	// that holds half an authority.
	paths = append(paths, options.files.companionPaths()...)
	// Six: what stops working is said before it stops working, not after.
	fmt.Println("after this, an installation that is rolled back to a panel from before the keys moved")
	fmt.Println("into the database will not start without a backup of these files.")
	fmt.Println("the files are removed and the directories synchronised; on an SSD, a copy-on-write")
	fmt.Println("filesystem or network storage that is an unlink, not a guaranteed erasure of the bytes.")
	if options.dryRun {
		fmt.Printf("would remove %d files:\n", len(paths))
		for _, path := range paths {
			fmt.Printf("  %s\n", path)
		}
		fmt.Println("nothing was changed")
		return nil
	}
	copied, err := copyFilesTo(options.backupTo, paths)
	if err != nil {
		return err
	}
	fmt.Printf("the files were copied to %s before being removed\n", copied)
	removed, err := removeFiles(paths)
	if err != nil {
		return err
	}
	for _, path := range removed {
		fmt.Printf("removed %s\n", path)
	}
	fmt.Printf("%d files are gone; the installation reads its keys from the database\n", len(removed))
	return nil
}

// sameKeys checks that the database holds what the files hold, key for key.
// An extra file is as much of a refusal as a missing one: a key on disk that
// the database never received is a key this command would be throwing away.
func sameKeys(files, database []cryptostate.Material) error {
	inDatabase := map[string]string{}
	for _, material := range database {
		inDatabase[material.KeyID] = material.Digest()
	}
	for _, material := range files {
		digest, ok := inDatabase[material.KeyID]
		if !ok {
			return fmt.Errorf("the key %s is in %s and not in the database", material.KeyID, material.Source)
		}
		if digest != material.Digest() {
			return fmt.Errorf("the key %s holds one thing in %s and another in the database",
				material.KeyID, material.Source)
		}
		delete(inDatabase, material.KeyID)
	}
	return nil
}

// copyFilesTo puts the files somewhere else before they are removed. This is
// the backup the warning talks about, so it is made here rather than left to
// the operator to remember.
func copyFilesTo(dir string, paths []string) (string, error) {
	into := filepath.Join(dir, "flotestro-crypto-files-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(into, 0o700); err != nil {
		return "", err
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		target := filepath.Join(into, filepath.Base(path))
		if err := writeFileSynced(target, content, 0o600); err != nil {
			return "", err
		}
	}
	if err := syncDir(into); err != nil {
		return "", err
	}
	return into, nil
}

// removeFiles unlinks the key files and synchronises the directories they were
// in, so that the removal survives a power cut.
func removeFiles(paths []string) ([]string, error) {
	var removed []string
	dirs := map[string]bool{}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed = append(removed, path)
		dirs[filepath.Dir(path)] = true
	}
	for dir := range dirs {
		if err := syncDir(dir); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// sameAuthorities checks that the database holds the withdrawn certificates
// the files hold. A certificate only on disk is one the fleet would stop
// recognising the moment the file went.
func sameAuthorities(files, database []cryptostate.RetiredAuthority) error {
	inDatabase := map[string]string{}
	for _, authority := range database {
		inDatabase[authority.Serial] = string(authority.Certificate)
	}
	for _, authority := range files {
		certificate, ok := inDatabase[authority.Serial]
		if !ok {
			return fmt.Errorf("the withdrawn authority %s is in %s and not in the database",
				authority.Serial, authority.Source)
		}
		if certificate != string(authority.Certificate) {
			return fmt.Errorf("the withdrawn authority %s is one certificate in %s and another in the database",
				authority.Serial, authority.Source)
		}
	}
	return nil
}
