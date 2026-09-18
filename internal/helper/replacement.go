package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/packages"
)

// AgentReplacementUnit is the name of the transient unit in which the agent
// replacement happens. The name is fixed: two replacements at once on one host
// make no sense, and systemd refuses the second one instead of letting both
// onto the same package database.
const AgentReplacementUnit = "flotestro-agent-replacement"

// ErrorSelfReplacement means the host cannot be replaced safely.
const ErrorSelfReplacement = "self_replacement_unavailable"

// The refusals of an agent replacement bound to an artefact. Each of them
// leaves the host exactly as it was: they are answered before the package
// manager is allowed near the database.
const (
	// ErrorArtefactDigest means the artefact the host obtained is not the one
	// the order names. The repository signature says the file comes from the
	// distribution; the digest says it is the file the release published, and
	// only the second one the panel can check on its own side.
	ErrorArtefactDigest = "agent_package_digest_mismatch"
	// ErrorArtefactUnavailable means the artefact was not obtained at all -
	// the repository does not carry that version, or the download failed.
	ErrorArtefactUnavailable = "agent_package_unavailable"
	// ErrorRollbackUnavailable means the order asked for a prepared return
	// and the host could not keep the artefact of that version. An upgrade
	// without the return it promised is not carried out: the whole point of
	// naming a rollback version is not to depend on the repository still
	// holding the old release afterwards.
	ErrorRollbackUnavailable = "agent_rollback_unavailable"
)

// agentUpgradeDir is where the replacement keeps what it fetched: the
// verified artefact of the new version and the artefact of the version the
// host can go back to. It sits under the helper's own state directory,
// because the replacement has to work when the agent is already gone.
//
// It is a value rather than a constant so that what a replacement keeps can
// be watched without writing under /var.
var agentUpgradeDir = "/var/lib/flotestro-helper/agent-upgrade"

// replacementOrder is what the helper hands to the transient unit that
// outlives it.
//
// The unit gets the package specification on its command line, as before, and
// everything the order added - the verified artefact and the copy to go back
// to - from this file. The file is read only when it names the same
// specification: a leftover of an abandoned order must not decide what a new
// one installs.
type replacementOrder struct {
	Spec                 string    `json:"spec"`
	ArtefactPath         string    `json:"artefact_path,omitempty"`
	ArtefactSHA256       string    `json:"artefact_sha256,omitempty"`
	RollbackVersion      string    `json:"rollback_version,omitempty"`
	RollbackArtefactPath string    `json:"rollback_artefact_path,omitempty"`
	OrderedAt            time.Time `json:"ordered_at"`
}

// agentReplacement recognizes an order in which the agent replaces itself.
//
// The recognition goes by the package name, not by a field in the request:
// this is a fact about the host, not a wish of the panel. The agent package in
// the company of others is not a replacement but an installation of a set -
// and that one is not performed, because the scripts of the agent package cut
// the transaction in half, leaving the rest of the set in a state nobody
// ordered.
func agentReplacement(packageSpecs []string) (string, bool) {
	if len(packageSpecs) != 1 {
		return "", false
	}
	spec := strings.TrimSpace(packageSpecs[0])
	if spec == packages.AgentPackage {
		return spec, true
	}
	rest, ok := strings.CutPrefix(spec, packages.AgentPackage)
	if !ok || len(rest) < 2 {
		return "", false
	}
	// apt separates the version with "=", dnf with a dash. The prefix alone is
	// not enough: "flotestro-agent-tools" starts with it too and is not this
	// package. A digit decides - a version starts with one, a name does not.
	if rest[0] != '=' && rest[0] != '-' {
		return "", false
	}
	if rest[1] < '0' || rest[1] > '9' {
		return "", false
	}
	return spec, true
}

// specForVersion writes the same package specification for another version.
//
// The separator comes from the order itself rather than from a second copy of
// the rules each manager has: whatever notation the panel used to name the
// target version is the notation the rollback version is named in too.
func specForVersion(spec, version string) (string, bool) {
	rest, ok := strings.CutPrefix(spec, packages.AgentPackage)
	if !ok || len(rest) < 2 || version == "" {
		return "", false
	}
	return packages.AgentPackage + string(rest[0]) + version, true
}

// orderAgentReplacement starts the installation of the agent package outside
// the helper.
//
// The scripts of the agent package stop the helper - and with it its whole
// control group, that is the package manager in the middle of the transaction.
// An installation led by the helper would therefore end with a half-installed
// package and a host that did not come back. That is why this one transaction
// starts as a separate systemd unit: it outlives the death of the one who
// ordered it.
//
// What can be settled before that unit starts is settled here, while there is
// still somebody to answer: the artefact is fetched and checked against the
// digest of the release, and the artefact of the version to go back to is put
// aside. Neither step touches the package database, so a refusal at this
// point leaves the host exactly where it was.
//
// The answer does not carry the result of the transaction and is not meant to:
// success is decided by the agent coming back in the expected version, which
// the panel sees.
func (s *Server) orderAgentReplacement(ctx context.Context, manager packages.Manager,
	spec string, action *helperv1.PackageActionRequest) *helperv1.HelperResponse {
	if _, ok := manager.(packages.Lifecycle); !ok {
		return reject(ErrorUnsupported,
			"the manager "+manager.Name()+" does not support installing packages")
	}

	order := replacementOrder{Spec: spec, OrderedAt: time.Now().UTC()}
	if version := action.GetRollbackVersion(); version != "" {
		path, err := keepRollbackArtefact(ctx, manager.Name(), spec, version)
		if err != nil {
			return reject(ErrorRollbackUnavailable, err.Error())
		}
		order.RollbackVersion = version
		order.RollbackArtefactPath = path
		s.log.Info("the artefact of the version to go back to was kept",
			"version", version, "path", path, "manager", manager.Name())
	}

	if digest := action.GetPackageSha256(); digest != "" {
		path, err := fetchArtefact(ctx, manager.Name(), spec, digest)
		if err != nil {
			code := ErrorArtefactUnavailable
			if errors.Is(err, errDigestMismatch) {
				code = ErrorArtefactDigest
			}
			s.log.Error("the artefact of the agent release was refused",
				"package", spec, "manager", manager.Name(), "code", code, "err", err)
			return reject(code, err.Error())
		}
		order.ArtefactPath = path
		order.ArtefactSHA256 = digest
	}

	result := &helperv1.PackageActionResult{
		Manager:              manager.Name(),
		VerifiedArtefactPath: order.ArtefactPath,
		RollbackArtefactPath: order.RollbackArtefactPath,
	}

	// An order that only proves itself stops here. The host is already at the
	// version the order names, so there is nothing to install - but the
	// artefact and the prepared return were checked, and that is what the
	// answer reports.
	if action.GetVerifyOnly() {
		installed, reason := installedAgentVersion(ctx, manager.Name())
		result.InstalledVersion = installed
		return &helperv1.HelperResponse{
			Accepted:      true,
			Message:       "the order was proven and nothing was installed; " + describeInstalled(installed, reason),
			PackageResult: result,
		}
	}

	if err := writeReplacementOrder(order); err != nil {
		return reject(ErrorSelfReplacement, err.Error())
	}
	if err := StartAgentReplacement(ctx, spec); err != nil {
		return reject(ErrorSelfReplacement, err.Error())
	}
	s.log.Info("the agent replacement was started outside the helper",
		"package", spec, "unit", AgentReplacementUnit, "manager", manager.Name(),
		"artefact", order.ArtefactPath, "rollback", order.RollbackArtefactPath)
	return &helperv1.HelperResponse{
		Accepted: true,
		Message: "the installation of " + spec + " is running in the unit " +
			AgentReplacementUnit + "; the result is decided by the return of the agent",
		PackageResult: result,
	}
}

// StartAgentReplacement starts the transient unit that calls this same helper
// binary in replacement mode.
//
// The unit gets only the package name with the version - not a command. The
// content of the transaction is assembled by the manager adapter on the other
// side, exactly as with every other package operation.
func StartAgentReplacement(ctx context.Context, spec string) error {
	if _, ok := agentReplacement([]string{spec}); !ok {
		return fmt.Errorf("%q is not the agent package", spec)
	}
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return fmt.Errorf("a host without systemd-run cannot replace the agent")
	}
	binary, err := helperPath()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, systemdRun,
		"--collect", "--quiet",
		// Without --no-block systemd-run waits for the end of a oneshot unit,
		// that is for the whole transaction - while standing in the helper's
		// control group, which that transaction is about to stop. The order is
		// to return after the unit starts, not after it finishes: the result is
		// decided by the return of the agent.
		"--no-block",
		"--unit="+AgentReplacementUnit,
		"--description=Flotestro: agent replacement",
		"--property=Type=oneshot",
		// The package transaction has its own time limit; this one is the last
		// net, so that a hung installation does not stay on the host forever.
		"--property=TimeoutStartSec=3600",
		"--", binary, "-agent-replacement", spec)
	cmd.Env = toolEnvironment()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// RunAgentReplacement installs the given version of the agent package.
//
// The function works without the agent, without the socket and without the
// panel: at the moment when the package scripts stop the helper and restart
// the agent, it is the only process that still knows what was supposed to
// happen.
//
// When the order left a verified artefact, that exact file is installed. The
// digest is checked once more here, immediately before the transaction: the
// check and the installation are two moments, and only a check in the second
// one says what is really going onto the host. Without an artefact the
// installation resolves the version from the repository, as it did before an
// order could carry a digest.
func RunAgentReplacement(ctx context.Context, spec string, log *slog.Logger) error {
	if _, ok := agentReplacement([]string{spec}); !ok {
		return fmt.Errorf("%q is not the agent package", spec)
	}
	if err := packages.SetRuntimeDir("/var/lib/flotestro-helper"); err != nil {
		return fmt.Errorf("the working directory of the helper: %w", err)
	}
	manager, err := packages.Detect()
	if err != nil {
		return err
	}
	lifecycle, ok := manager.(packages.Lifecycle)
	if !ok {
		return fmt.Errorf("the manager %s does not support installing packages", manager.Name())
	}

	target := spec
	order, hasOrder := readReplacementOrder(spec)
	if hasOrder && order.ArtefactPath != "" {
		if err := verifyDigest(order.ArtefactPath, order.ArtefactSHA256); err != nil {
			log.Error("the artefact of the agent release was not installed",
				"package", spec, "artefact", order.ArtefactPath, "err", err)
			return err
		}
		target = order.ArtefactPath
	}

	// The version is given explicitly, so a downgrade is an operator decision
	// as well: that is how the return after a failed agent release works.
	options := packages.Options{
		Mode:           packages.ModeInstall,
		Packages:       []string{target},
		AllowDowngrade: true,
	}
	var apply packages.Apply
	if target != spec && manager.Name() == packages.PacmanName {
		// pacman installs a file with -U and a repository name with -S; the
		// two are different commands rather than two forms of one, so the
		// adapter's install cannot be used for a file.
		err = installPacmanArtefact(ctx, target)
	} else {
		apply, err = lifecycle.Install(ctx, options)
	}
	if err != nil {
		// There is nobody for the result to return to - the agent is no longer
		// listening to this transaction. The host journal is the only place the
		// reason stays in; the panel will only see that the host did not come
		// back in the requested version.
		log.Error("the agent replacement failed",
			"package", spec, "artefact", order.ArtefactPath, "manager", manager.Name(),
			"changed", len(apply.Applied), "rollback", order.RollbackArtefactPath, "err", err)
		return err
	}

	// What is installed is read from the package database rather than taken
	// from the order: the transaction saying it went through is not the same
	// statement as the host holding that version.
	installed, reason := installedAgentVersion(ctx, manager.Name())
	log.Info("the agent replacement was performed",
		"package", spec, "artefact", order.ArtefactPath, "manager", manager.Name(),
		"changed", len(apply.Applied), "installed_version", installed,
		"installed_version_unknown", reason, "rollback", order.RollbackArtefactPath)
	return nil
}

// installPacmanArtefact installs one package file with pacman.
func installPacmanArtefact(ctx context.Context, path string) error {
	pacman, err := exec.LookPath("pacman")
	if err != nil {
		return fmt.Errorf("a host without pacman cannot install %s", path)
	}
	cmd := exec.CommandContext(ctx, pacman, "-U", "--noconfirm", "--noprogressbar", path)
	cmd.Env = toolEnvironment()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pacman -U %s: %w: %s", path, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// keepRollbackArtefact puts the artefact of the version to go back to under
// the helper's state directory.
//
// The package cache of the manager is looked at first: the file of the
// version the host runs is usually still there and copying it asks nothing of
// the network. Only when it is not is the version fetched from the
// repository - and a repository that no longer carries it is exactly the case
// the prepared return exists for, so the failure is the refusal of the whole
// upgrade rather than a note in the result.
func keepRollbackArtefact(ctx context.Context, managerName, spec, version string) (string, error) {
	rollbackDir := filepath.Join(agentUpgradeDir, "rollback")
	if err := os.MkdirAll(rollbackDir, 0o700); err != nil {
		return "", fmt.Errorf("the directory for the artefact to go back to: %w", err)
	}
	if cached, ok := findCachedArtefact(managerName, version); ok {
		kept := filepath.Join(rollbackDir, filepath.Base(cached))
		if err := copyFile(cached, kept); err != nil {
			return "", fmt.Errorf("copying %s out of the package cache: %w", cached, err)
		}
		return kept, nil
	}

	rollbackSpec, ok := specForVersion(spec, version)
	if !ok {
		return "", fmt.Errorf("the version %q cannot be named in the notation of %q", version, spec)
	}
	download := filepath.Join(agentUpgradeDir, "rollback-download")
	if err := os.RemoveAll(download); err != nil {
		return "", fmt.Errorf("clearing the download directory: %w", err)
	}
	if err := downloadArtefact(ctx, managerName, rollbackSpec, download); err != nil {
		return "", fmt.Errorf("the artefact of the version %s is neither in the package cache "+
			"nor in the repository: %w", version, err)
	}
	found, err := artefactsIn(download)
	if err != nil {
		return "", err
	}
	// The file has to be the version that was asked for. A manager that
	// cannot select a version in its download mode answers with whatever its
	// database holds, and keeping that as the prepared return would leave the
	// host a way back to a version nobody named.
	artefact := ""
	for _, path := range found {
		if nameCarriesVersion(filepath.Base(path), version) {
			artefact = path
			break
		}
	}
	if artefact == "" {
		return "", fmt.Errorf("the artefact of the version %s was not downloaded", version)
	}
	kept := filepath.Join(rollbackDir, filepath.Base(artefact))
	if err := os.Rename(artefact, kept); err != nil {
		if err := copyFile(artefact, kept); err != nil {
			return "", fmt.Errorf("keeping the artefact of the version %s: %w", version, err)
		}
	}
	return kept, nil
}

// errDigestMismatch says the artefact is not the one the release published.
var errDigestMismatch = errors.New("the artefact does not match the digest of the order")

// fetchArtefact downloads the package of the ordered version and returns the
// file whose digest is the one the order names.
//
// The digest decides which file it is, not the name: the naming of an
// artefact differs between managers and encodes the epoch of a version
// differently in each, while the digest is the same statement everywhere. A
// download in which no file matches is refused - and refused before anything
// is installed, which is the whole reason this runs here rather than inside
// the transaction.
func fetchArtefact(ctx context.Context, managerName, spec, digest string) (string, error) {
	dir := filepath.Join(agentUpgradeDir, "download")
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("clearing the download directory: %w", err)
	}
	if err := downloadArtefact(ctx, managerName, spec, dir); err != nil {
		return "", err
	}
	found, err := artefactsIn(dir)
	if err != nil {
		return "", err
	}
	if len(found) == 0 {
		return "", fmt.Errorf("the repository gave no artefact of %s", spec)
	}
	for _, path := range found {
		sum, err := digestOf(path)
		if err != nil {
			return "", err
		}
		if strings.EqualFold(sum, digest) {
			return path, nil
		}
	}
	first, err := digestOf(found[0])
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("%w: the order names %s and the host obtained %s (%s)",
		errDigestMismatch, digest, first, filepath.Base(found[0]))
}

// downloadArtefact fetches one package specification into the given directory
// without installing anything.
//
// The command is the manager's own download mode. Nothing here writes to the
// package database, so a host on which this step fails is a host that was not
// touched.
func downloadArtefact(ctx context.Context, managerName, spec, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("the download directory: %w", err)
	}
	attempts := downloadCommands(managerName, spec, dir)
	if len(attempts) == 0 {
		return fmt.Errorf("the manager %s cannot fetch a package artefact", managerName)
	}
	lastErr := fmt.Errorf("the manager %s fetched nothing", managerName)
	for _, attempt := range attempts {
		path, err := exec.LookPath(attempt.tool)
		if err != nil {
			return fmt.Errorf("the host has no %s", attempt.tool)
		}
		if err := attempt.prepare(dir); err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, path, attempt.args...)
		cmd.Env = append(toolEnvironment(), "DEBIAN_FRONTEND=noninteractive")
		output, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%s: %w: %s", attempt.tool, err, strings.TrimSpace(string(output)))
	}
	return lastErr
}

// downloadCommand is one way of asking a manager for a package file. A
// manager may offer more than one and not have them all: dnf downloads with a
// subcommand of its own where the plugin is installed and through the
// transaction's download mode where it is not.
type downloadCommand struct {
	tool    string
	args    []string
	prepare func(dir string) error
}

// downloadCommands lists the ways of fetching an artefact with the given
// manager, in the order they are tried.
func downloadCommands(managerName, spec, dir string) []downloadCommand {
	nothing := func(string) error { return nil }
	switch managerName {
	case "apt":
		return []downloadCommand{{
			tool: "apt-get",
			// --reinstall matters: the version may be the one the host
			// already has, and without it apt would answer "nothing to do"
			// and leave the order unproven.
			args: []string{"--yes", "--quiet", "--download-only", "--reinstall",
				"--allow-downgrades", "--allow-change-held-packages",
				"-o", "Dir::Cache::archives=" + dir,
				"-o", "APT::Sandbox::User=root",
				"install", spec},
			// apt keeps half-finished downloads in a subdirectory of the
			// archive directory and refuses to work without it. Its own
			// sandbox user cannot write under the helper's state directory,
			// so the download stays with the identity the helper runs as.
			prepare: func(dir string) error {
				if err := os.MkdirAll(filepath.Join(dir, "partial"), 0o700); err != nil {
					return fmt.Errorf("the download directory: %w", err)
				}
				return nil
			},
		}}
	case "dnf":
		return []downloadCommand{
			// The download subcommand fetches the file whether or not the
			// version is installed, which the transaction's download mode
			// does not; it is not on every host, and then the second form
			// answers.
			{tool: "dnf", args: []string{"--assumeyes", "download",
				"--destdir=" + dir, spec}, prepare: nothing},
			{tool: "dnf", args: []string{"--assumeyes", "install", "--downloadonly",
				"--destdir=" + dir, spec}, prepare: nothing},
		}
	case packages.PacmanName:
		// pacman cannot ask a repository for a version other than the one its
		// database holds, so the bare name is fetched and the digest settles
		// whether what the repository holds is what the release published.
		return []downloadCommand{{tool: "pacman", args: []string{"-Sw", "--noconfirm",
			"--noprogressbar", "--cachedir", dir, packages.AgentPackage}, prepare: nothing}}
	}
	return nil
}

// nameCarriesVersion says whether the name of an artefact is the name of that
// version. Every manager builds the file name from the package name and the
// version; the epoch is written differently by each and is left out of the
// comparison.
func nameCarriesVersion(name, version string) bool {
	if _, rest, found := strings.Cut(version, ":"); found {
		version = rest
	}
	return strings.Contains(name, version)
}

// artefactSuffixes are the file names of a package of each manager. A file
// that is not one of them is not an artefact, whatever it is doing in the
// download directory.
var artefactSuffixes = []string{".deb", ".rpm", ".pkg.tar.zst", ".pkg.tar.xz"}

// artefactsIn lists the package files of the agent in a directory.
func artefactsIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var found []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), packages.AgentPackage) {
			continue
		}
		for _, suffix := range artefactSuffixes {
			if strings.HasSuffix(entry.Name(), suffix) {
				found = append(found, filepath.Join(dir, entry.Name()))
				break
			}
		}
	}
	return found, nil
}

// managerCacheDirs are the package caches the artefact of an installed
// version is looked for in before the repository is asked.
var managerCacheDirs = map[string][]string{
	"apt":               {"/var/cache/apt/archives"},
	"dnf":               {"/var/cache/dnf", "/var/cache/libdnf5"},
	packages.PacmanName: {"/var/cache/pacman/pkg"},
}

// findCachedArtefact looks for the artefact of a version in the manager's own
// cache, which is where the file of the version the host runs usually still
// is.
func findCachedArtefact(managerName, version string) (string, bool) {
	for _, dir := range managerCacheDirs[managerName] {
		var match string
		_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || match != "" {
				return nil
			}
			name := entry.Name()
			if !strings.HasPrefix(name, packages.AgentPackage) || !nameCarriesVersion(name, version) {
				return nil
			}
			for _, suffix := range artefactSuffixes {
				if strings.HasSuffix(name, suffix) {
					match = path
					return nil
				}
			}
			return nil
		})
		if match != "" {
			return match, true
		}
	}
	return "", false
}

// digestOf computes the SHA-256 of a file.
func digestOf(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("reading the artefact: %w", err)
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", fmt.Errorf("reading the artefact %s: %w", path, err)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// verifyDigest refuses an artefact whose content is not the ordered one.
func verifyDigest(path, expected string) error {
	if expected == "" {
		return nil
	}
	sum, err := digestOf(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, expected) {
		return fmt.Errorf("%w: the order names %s and %s hashes to %s",
			errDigestMismatch, expected, path, sum)
	}
	return nil
}

// copyFile copies a file, keeping the original where it is.
func copyFile(from, to string) error {
	source, err := os.Open(from)
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(target, source); err != nil {
		target.Close()
		return err
	}
	return target.Close()
}

// replacementOrderPath is where the order waits for the unit that carries it
// out.
func replacementOrderPath() string {
	return filepath.Join(agentUpgradeDir, "order.json")
}

// writeReplacementOrder records what the transient unit is to install.
func writeReplacementOrder(order replacementOrder) error {
	if err := os.MkdirAll(agentUpgradeDir, 0o700); err != nil {
		return fmt.Errorf("the directory of the replacement order: %w", err)
	}
	encoded, err := json.Marshal(order)
	if err != nil {
		return err
	}
	if err := os.WriteFile(replacementOrderPath(), encoded, 0o600); err != nil {
		return fmt.Errorf("writing the replacement order: %w", err)
	}
	return nil
}

// readReplacementOrder reads the order of this replacement. An order for
// another specification is no order at all: it belongs to a run that was
// abandoned, and installing its artefact would replace the agent with a
// version nobody asked for now.
func readReplacementOrder(spec string) (replacementOrder, bool) {
	content, err := os.ReadFile(replacementOrderPath())
	if err != nil {
		return replacementOrder{}, false
	}
	var order replacementOrder
	if err := json.Unmarshal(content, &order); err != nil {
		return replacementOrder{}, false
	}
	if order.Spec != spec {
		return replacementOrder{}, false
	}
	return order, true
}

// installedAgentVersion reads the version of the agent package as the package
// database of the host holds it. An unreadable database gives no version and
// a reason for it: not knowing is not the same as the package being absent.
func installedAgentVersion(ctx context.Context, managerName string) (string, string) {
	list := packages.Installed(ctx, managerName)
	if list.UnavailableReason != "" {
		return "", list.UnavailableReason
	}
	for _, pkg := range list.Packages {
		if pkg.Name == packages.AgentPackage {
			return pkg.EVR(), ""
		}
	}
	return "", "the package " + packages.AgentPackage + " is not in the package database"
}

// describeInstalled names the installed version, or says why it is unknown.
func describeInstalled(version, reason string) string {
	if version == "" {
		return "the installed version is unknown (" + reason + ")"
	}
	return "the package database holds " + version
}
