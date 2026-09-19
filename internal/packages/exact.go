package packages

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/plan"
)

// Exact is a manager that carries an approved plan out exactly as it was
// approved: every element at the version, the architecture and the origin the
// plan names, nothing the tool resolves anew at the time of the transaction.
type Exact interface {
	ApplyExact(ctx context.Context, approved Plan, options Options) (Apply, error)
}

// settleEffects reads the expected effects of the plan off the state after the
// transaction.
func settleEffects(apply *Apply, approved Plan, after map[string]string) error {
	achieved, missed := approved.Envelope().Effects.Settle(after)
	apply.EffectsAchieved, apply.EffectsMissed = achieved, missed
	return plan.Partial(missed)
}

// removalSpecs lists the names the plan removes.
func removalSpecs(approved Plan) []string {
	var names []string
	for _, change := range approved.Changes {
		if change.Action == ActionRemove {
			names = append(names, change.Name)
		}
	}
	sort.Strings(names)
	return names
}

// ApplyExact installs the exact versions of the plan with apt-get: every
// element as name=version, a removal as name-, in one transaction.
func (a *APT) ApplyExact(ctx context.Context, approved Plan, options Options) (Apply, error) {
	apply := Apply{Manager: a.Name()}
	specs := approved.ExactSpecs()
	for _, name := range removalSpecs(approved) {
		specs = append(specs, name+"-")
	}
	if len(specs) == 0 {
		return apply, nil
	}
	if held, path := a.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	before := a.installedVersions(ctx)
	args := []string{
		"--yes", "--quiet",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "APT::Get::Assume-Yes=true",
	}
	if approved.HasDowngrade() {
		args = append(args, "--allow-downgrades")
	}
	args = append(args, "install")
	if approved.Mode == "" || approved.Mode == ModeUpgrade {
		args = append(args, "--only-upgrade")
	}
	args = append(args, specs...)
	// The agent is not raised in a transaction it carries out itself; the plan
	// does not name it, and the hold keeps a dependency from pulling it in.
	if release, err := a.holdAgent(ctx); err == nil {
		defer release()
	}
	if options.Progress != nil {
		args = append([]string{"-o", "APT::Status-Fd=3"}, args...)
	}
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, options.Progress != nil,
		aptGetPath, args...)
	if (!result.Ran || result.ExitCode != 0) && BrokenDownload(result.Stderr, result.Stdout) {
		cleaning := run(ctx, 5*time.Minute, aptGetPath, "--quiet", "clean")
		if cleaning.Ran && cleaning.ExitCode == 0 {
			apply.SelfRepair = append(apply.SelfRepair,
				"the damaged archives were removed from the cache and the transaction was retried")
			result = runWithProgress(ctx, 45*time.Minute, options.Progress,
				options.Progress != nil, aptGetPath, args...)
		}
	}

	after := a.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.PackagesNeedingAttention = a.PackagesNeedingAttention(ctx)
	apply.DatabaseBroken = len(apply.PackagesNeedingAttention) > 0
	apply.RebootRequired = fileExists("/var/run/reboot-required") || fileExists("/run/reboot-required")
	apply.ServicesNeedingRestart = a.servicesNeedingRestart(ctx)
	partial := settleEffects(&apply, approved, after)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		if len(apply.PackagesNeedingAttention) > 0 {
			return apply, fmt.Errorf("apt-get install: %s; needs attention: %s",
				result.Reason(), strings.Join(apply.PackagesNeedingAttention, ", "))
		}
		return apply, fmt.Errorf("apt-get install: %s", result.Reason())
	}
	return apply, partial
}

// ApplyExact carries the plan out with dnf on the exact NEVRAs and only from
// the repositories the plan names, against the metadata the plan was read
// from: the cached metadata is declared never expired, so dnf resolves on
func (d *DNF) ApplyExact(ctx context.Context, approved Plan, options Options) (Apply, error) {
	apply := Apply{Manager: d.Name()}
	byAction := map[string][]string{}
	for _, change := range approved.Changes {
		spec := exactSpec(d.Name(), change)
		byAction[change.Action] = append(byAction[change.Action], spec)
	}
	if len(approved.Changes) == 0 {
		return apply, nil
	}
	if held, path := d.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	base := []string{"--assumeyes", "--quiet", "--setopt=metadata_expire=-1"}
	for _, repo := range approved.RepositoryIDs() {
		base = append(base, "--repo="+repo)
	}
	before := d.installedVersions(ctx)
	var result commandResult
	var failed string
	for _, step := range []struct{ action, command string }{
		{ActionUpgrade, "upgrade"}, {ActionInstall, "install"},
		{ActionDowngrade, "downgrade"}, {ActionRemove, "remove"},
	} {
		specs := byAction[step.action]
		if len(specs) == 0 {
			continue
		}
		sort.Strings(specs)
		args := append(append(append([]string(nil), base...), step.command), specs...)
		result = runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)
		if (!result.Ran || result.ExitCode != 0) && BrokenDownload(result.Stderr, result.Stdout) {
			cleaning := run(ctx, 5*time.Minute, dnfPath, "--assumeyes", "--quiet", "clean", "packages")
			if cleaning.Ran && cleaning.ExitCode == 0 {
				apply.SelfRepair = append(apply.SelfRepair,
					"the damaged packages were removed from the cache and the transaction was retried")
				result = runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)
			}
		}
		apply.ScriptletErrors = append(apply.ScriptletErrors,
			scriptletFailures(result.Stdout+"\n"+result.Stderr)...)
		if !result.Ran || result.ExitCode != 0 {
			failed = "dnf " + step.command
			break
		}
	}

	after := d.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = d.DatabaseBroken(ctx)
	apply.RebootRequired = d.rebootRequired(ctx)
	partial := settleEffects(&apply, approved, after)
	if failed != "" {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, fmt.Errorf("%s: %s", failed, result.Reason())
	}
	return apply, partial
}

// ApplyExact carries the plan out with pacman from downloaded, signed
// archives: the targets are resolved against the private copy of the sync
// database the plan was read from, downloaded into the cache with -Sw, and.
func (p *Pacman) ApplyExact(ctx context.Context, approved Plan, options Options) (Apply, error) {
	apply := Apply{Manager: p.Name()}
	if len(approved.Changes) == 0 {
		return apply, nil
	}
	if held, path := p.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	if hidden, dir := pacmanModulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	// The targets and their archives, as the copy resolves them.
	var installs []Change
	for _, change := range approved.Changes {
		if change.Action != ActionRemove {
			installs = append(installs, change)
		}
	}
	before := p.installedVersions(ctx)
	var files []string
	if len(installs) > 0 {
		upgrade := approved.Mode == "" || approved.Mode == ModeUpgrade
		var printArgs, downloadArgs []string
		if upgrade {
			// The archives are fetched against the same database the plan was read
			// from, so the transaction carries out the plan that was approved.
			database := pacmanDatabaseArgs(pacmanPlanDatabase())
			printArgs = append([]string{"-Sup", "--noconfirm", "--ignore", AgentPackage,
				"--print-format", pacmanPrintFormat}, database...)
			downloadArgs = append([]string{"-Suw", "--noconfirm", "--noprogressbar", "--ignore", AgentPackage}, database...)
		} else {
			names := changeNames(installs)
			printArgs = append([]string{"-Sp", "--needed", "--noconfirm", "--print-format", pacmanPrintFormat}, names...)
			downloadArgs = append([]string{"-Sw", "--needed", "--noconfirm", "--noprogressbar"}, names...)
		}
		printed := run(ctx, 5*time.Minute, pacmanPath, printArgs...)
		if !printed.Ran || printed.ExitCode != 0 {
			return apply, p.failure("pacman --print", printed)
		}
		targets := ParsePacmanTargets(printed.Stdout)
		for _, change := range installs {
			target, ok := targets[change.Name]
			if !ok || target.Version != change.CandidateVersion || target.File() == "" {
				return apply, fmt.Errorf("%w: %s resolves to %s now, the plan names %s",
					plan.ErrStalePlan, change.Name, orUnknown(target.Version), change.CandidateVersion)
			}
			files = append(files, filepath.Join(pacmanCacheDir, target.File()))
		}
		sort.Strings(files)

		download := runWithProgress(ctx, 45*time.Minute, options.Progress, false, pacmanPath, downloadArgs...)
		if (!download.Ran || download.ExitCode != 0) && BrokenDownload(download.Stderr, download.Stdout) {
			if removed := p.dropDamagedArchives(download.Stderr + "\n" + download.Stdout); len(removed) > 0 {
				apply.SelfRepair = append(apply.SelfRepair,
					"the damaged archives were removed from the cache ("+strings.Join(removed, ", ")+
						") and the download was retried")
				download = runWithProgress(ctx, 45*time.Minute, options.Progress, false, pacmanPath, downloadArgs...)
			}
		}
		if !download.Ran || download.ExitCode != 0 {
			apply.Output = tailLines(download.Stderr, download.Stdout, maxResultLines)
			return apply, p.failure("pacman -Sw", download)
		}
		for _, file := range files {
			if _, err := os.Stat(file); err != nil {
				return apply, fmt.Errorf("pacman -Sw: the archive %s is not in the cache after the download", filepath.Base(file))
			}
		}
	}

	result := commandResult{Ran: true}
	command := "pacman -U"
	if len(files) > 0 {
		args := append([]string{"-U", "--noconfirm", "--noprogressbar"}, files...)
		result = runWithProgress(ctx, 45*time.Minute, options.Progress, false, pacmanPath, args...)
	}
	if removals := removalSpecs(approved); len(removals) > 0 && result.Ran && result.ExitCode == 0 {
		command = "pacman -Rs"
		removing := append([]string{"-Rs", "--noconfirm", "--noprogressbar"}, removals...)
		result = runWithProgress(ctx, 45*time.Minute, options.Progress, false, pacmanPath, removing...)
	}

	after := p.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = p.DatabaseBroken(ctx)
	apply.RebootRequired = pacmanRebootRequired()
	partial := settleEffects(&apply, approved, after)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = tailLines(result.Stderr, result.Stdout, maxResultLines)
		return apply, p.failure(command, result)
	}
	return apply, partial
}

func orUnknown(value string) string {
	if value == "" {
		return "nothing"
	}
	return value
}
