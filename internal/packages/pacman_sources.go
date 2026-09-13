package packages

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The sources of pacman are the sections of /etc/pacman.conf: [core] and
// [extra] of the distribution, and whatever the administrator added with a
// "Server =" line or an included mirror list. There is no directory of
// sources, so a source the panel manages is a section of the same file,
// marked with the panel's comment in the line above its header. Only such
// sections are rewritten; the sections of the distribution and of the
// administrator are shown and left alone.

// pacmanIncludeDepth limits how far the includes are followed. The mirror
// list is one level; anything deeper is a configuration nobody reads by
// hand either.
const pacmanIncludeDepth = 4

// pacmanSection is one section of the configuration, with its entries read
// through the includes and its raw lines from the file the header stands in.
type pacmanSection struct {
	Name string
	Path string
	// Managed marks a section preceded by the panel's marker; Disabled marks
	// a managed section written commented out.
	Managed  bool
	Disabled bool
	// Raw keeps the lines of the section as they stand in its own file,
	// includes not followed. The refresh of a single source copies them into
	// a configuration of its own.
	Raw     []string
	Entries []pacmanKV
}

type pacmanKV struct {
	Key, Value string
}

// values returns every value of the key, in order.
func (s *pacmanSection) values(key string) []string {
	var found []string
	for _, entry := range s.Entries {
		if entry.Key == key {
			found = append(found, entry.Value)
		}
	}
	return found
}

func (s *pacmanSection) first(key string) string {
	if values := s.values(key); len(values) > 0 {
		return values[0]
	}
	return ""
}

// pacmanConfig is the configuration as read from the file and its includes.
type pacmanConfig struct {
	Sections []*pacmanSection
}

func (c *pacmanConfig) section(name string) *pacmanSection {
	for _, section := range c.Sections {
		if section.Name == name {
			return section
		}
	}
	return nil
}

// parsePacmanConf reads the configuration file together with its includes.
func parsePacmanConf(path string) (*pacmanConfig, error) {
	config := &pacmanConfig{}
	var current *pacmanSection
	if err := parsePacmanConfFile(path, 0, config, &current); err != nil {
		return nil, err
	}
	return config, nil
}

// parsePacmanConfFile reads one file. An include is read in the context of
// the current section - that is how the mirror list gives [core] its
// servers - and a section header inside an included file starts a section
// like one in the main file.
func parsePacmanConfFile(path string, depth int, config *pacmanConfig,
	current **pacmanSection) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		afterMarker := i > 0 && strings.TrimSpace(lines[i-1]) == panelMarker
		disabled := false
		if afterMarker && strings.HasPrefix(trimmed, "#[") {
			// A managed source written commented out: the section is read
			// so that the panel sees it, and pacman does not.
			trimmed = strings.TrimPrefix(trimmed, "#")
			disabled = true
		}
		if header, ok := pacmanSectionHeader(trimmed); ok {
			section := &pacmanSection{
				Name: header, Path: path, Managed: afterMarker, Disabled: disabled,
			}
			config.Sections = append(config.Sections, section)
			*current = section
			continue
		}
		if *current != nil && (*current).Path == path {
			if trimmed == panelMarker {
				// The marker of the next managed section is not a line of
				// this one.
				continue
			}
			(*current).Raw = append((*current).Raw, line)
		}
		if *current != nil && (*current).Disabled {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		}
		key, value, ok := pacmanEntry(trimmed)
		if !ok {
			continue
		}
		if key == "Include" {
			if depth >= pacmanIncludeDepth || (*current != nil && (*current).Disabled) {
				continue
			}
			matches, _ := filepath.Glob(value)
			for _, included := range matches {
				if err := parsePacmanConfFile(included, depth+1, config, current); err != nil {
					// A mirror list that cannot be read leaves the section
					// without servers rather than the whole file unread.
					continue
				}
			}
			continue
		}
		if *current != nil {
			(*current).Entries = append((*current).Entries, pacmanKV{Key: key, Value: value})
		}
	}
	return nil
}

// readPacman lists the sources of pacman.
func readPacman() []Repository {
	config, err := parsePacmanConf(PacmanConfPath)
	if err != nil {
		return []Repository{{
			ID: "pacman", Path: PacmanConfPath, UnavailableReason: err.Error(),
		}}
	}
	return pacmanRepositories(config)
}

// pacmanRepositories turns the sections into sources. The options section
// is not a source; it gives the default signature level.
func pacmanRepositories(config *pacmanConfig) []Repository {
	defaultLevel := ""
	if options := config.section("options"); options != nil {
		defaultLevel = strings.Join(options.values("SigLevel"), " ")
	}
	var sources []Repository
	for _, section := range config.Sections {
		if section.Name == "options" {
			continue
		}
		level := strings.Join(section.values("SigLevel"), " ")
		if level == "" {
			level = defaultLevel
		}
		sources = append(sources, Repository{
			ID: section.Name, Name: section.Name, Path: section.Path,
			URL:     section.first("Server"),
			Enabled: !section.Disabled,
			Signed:  SigLevelRequiresSignature(level),
			Managed: section.Managed,
		})
	}
	return sources
}

// SigLevelRequiresSignature reads the package part of a SigLevel line.
//
// "Never" disables the check, "Optional" checks a signature only when there
// is one - and a source whose packages may arrive unsigned is not a source
// with signatures checked. The distribution ships "Required DatabaseOptional";
// the built-in default when nothing is set is "Optional", so an empty level
// means unchecked.
func SigLevelRequiresSignature(level string) bool {
	required := false
	for _, token := range strings.Fields(level) {
		switch token {
		case "Never", "PackageNever":
			required = false
		case "Optional", "PackageOptional":
			required = false
		case "Required", "PackageRequired":
			required = true
		}
	}
	return required
}

// PacmanSourceBlock composes the section the panel writes. The signature
// level is explicit either way: a source without checking says so in the
// file rather than inheriting whatever the options section happens to say.
func PacmanSourceBlock(repo Repository) []string {
	level := "SigLevel = Never"
	if repo.Signed {
		level = "SigLevel = Required DatabaseOptional"
	}
	lines := []string{"[" + repo.ID + "]", level, "Server = " + repo.URL}
	if !repo.Enabled {
		// pacman has no switch for a source: a disabled one is commented
		// out, and the marker keeps it recognisable.
		for i := range lines {
			lines[i] = "#" + lines[i]
		}
	}
	return append([]string{panelMarker}, lines...)
}

// AddPacmanSource writes the section into the content of pacman.conf,
// replacing the panel's earlier section of the same name.
func AddPacmanSource(content string, repo Repository) (string, error) {
	lines, err := dropPacmanSource(strings.Split(content, "\n"), repo.ID)
	if err != nil {
		return "", err
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	lines = append(lines, "")
	lines = append(lines, PacmanSourceBlock(repo)...)
	lines = append(lines, "")
	return strings.Join(lines, "\n"), nil
}

// RemovePacmanSource takes the panel's section out of the content.
func RemovePacmanSource(content, id string) (string, error) {
	lines, err := dropPacmanSource(strings.Split(content, "\n"), id)
	if err != nil {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}

// dropPacmanSource removes the managed section with the name. A section of
// the same name that is not the panel's is an error: rewriting it would take
// a source away from the administrator, and writing a second one would leave
// pacman with two.
func dropPacmanSource(lines []string, id string) ([]string, error) {
	var kept []string
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		managed := i > 0 && strings.TrimSpace(lines[i-1]) == panelMarker
		candidate := trimmed
		if managed {
			// A managed section may stand commented out; a commented header
			// without the marker is an ordinary comment of the file.
			candidate = strings.TrimPrefix(trimmed, "#")
		}
		header, isHeader := pacmanSectionHeader(candidate)
		if !isHeader || header != id {
			kept = append(kept, lines[i])
			continue
		}
		if !managed {
			return nil, fmt.Errorf("the section [%s] in %s is not managed by the panel",
				id, PacmanConfPath)
		}
		// The marker above the header belongs to the block.
		if len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == panelMarker {
			kept = kept[:len(kept)-1]
		}
		// Everything up to the next header or marker goes with it.
		for i++; i < len(lines); i++ {
			next := strings.TrimSpace(lines[i])
			if _, ok := pacmanSectionHeader(next); ok || next == panelMarker {
				i--
				break
			}
		}
		// One blank line before the block is enough.
		for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
			kept = kept[:len(kept)-1]
		}
		if len(kept) > 0 {
			kept = append(kept, "")
		}
	}
	return kept, nil
}

// PacmanKeyPath names the file the key of a managed source is kept in. The
// keyring is what pacman reads; the file is what lets the panel remove the
// key again when the source goes.
func PacmanKeyPath(id string) string {
	return filepath.Join(PacmanConfDir, flotestroFilePrefix+id+".asc")
}

// WritePacmanSource puts the section into pacman.conf and, for a signed
// source, imports its key. It requires root.
//
// The key file has already been written by the caller at PacmanKeyPath: the
// panel writes files the same way for every manager, and only the keyring
// step is pacman's own.
func WritePacmanSource(ctx context.Context, repo Repository) error {
	data, err := os.ReadFile(PacmanConfPath)
	if err != nil {
		return fmt.Errorf("%s: %w", PacmanConfPath, err)
	}
	content, err := AddPacmanSource(string(data), repo)
	if err != nil {
		return err
	}
	if err := replaceFile(PacmanConfPath, []byte(content)); err != nil {
		return fmt.Errorf("%s: %w", PacmanConfPath, err)
	}
	if repo.Signed {
		if err := ImportPacmanKey(ctx, PacmanKeyPath(repo.ID), repo.GPGKeyFingerprint); err != nil {
			return err
		}
	}
	return nil
}

// DropPacmanSource takes the section out of pacman.conf and the key out of
// the keyring. The key file itself is removed by the caller along with the
// other files of the source.
func DropPacmanSource(ctx context.Context, id string) error {
	data, err := os.ReadFile(PacmanConfPath)
	if err != nil {
		return fmt.Errorf("%s: %w", PacmanConfPath, err)
	}
	content, err := RemovePacmanSource(string(data), id)
	if err != nil {
		return err
	}
	if content != string(data) {
		if err := replaceFile(PacmanConfPath, []byte(content)); err != nil {
			return fmt.Errorf("%s: %w", PacmanConfPath, err)
		}
	}
	// The fingerprint comes from the file the panel wrote: pacman-key
	// removes keys by fingerprint, and the panel keeps no other record.
	material, err := os.ReadFile(PacmanKeyPath(id))
	if err != nil {
		return nil
	}
	fingerprint, err := KeyFingerprint(string(material))
	if err != nil {
		return nil
	}
	return ForgetPacmanKey(ctx, fingerprint)
}

// pacmanRefreshSource fetches the database of one source.
//
// pacman syncs every source of its configuration at once, so the one source
// is given a configuration of its own: the options section as it stands and
// the section of the source, nothing else. The database lands in the system
// sync directory like after an ordinary sync - only for this source.
func pacmanRefreshSource(ctx context.Context, id string) error {
	config, err := parsePacmanConf(PacmanConfPath)
	if err != nil {
		return fmt.Errorf("%s: %w", PacmanConfPath, err)
	}
	section := config.section(id)
	if section == nil {
		return fmt.Errorf("the section [%s] is not in %s", id, PacmanConfPath)
	}
	if section.Disabled {
		return nil
	}
	var content strings.Builder
	content.WriteString("[options]\n")
	if options := config.section("options"); options != nil {
		content.WriteString(strings.Join(options.Raw, "\n") + "\n")
	}
	content.WriteString("\n[" + id + "]\n")
	content.WriteString(strings.Join(section.Raw, "\n") + "\n")

	directory, err := os.MkdirTemp("", "flotestro-repo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "pacman.conf")
	if err := os.WriteFile(path, []byte(content.String()), 0o644); err != nil {
		return err
	}
	result := run(ctx, 5*time.Minute, pacmanPath, "--config", path, "-Sy",
		"--noconfirm", "--noprogressbar")
	if !result.Ran || result.ExitCode != 0 {
		return fmt.Errorf("pacman -Sy: %s", result.Reason())
	}
	// pacman ends with zero when the database was fetched; a source that
	// does not answer ends with an error of its own. What is read here is a
	// signature nobody trusts, which pacman reports as a failure of the sync
	// as well - and the reason is to reach the operator rather than a bare
	// exit code.
	if line := PacmanTrustProblem(result.Stdout + "\n" + result.Stderr); line != "" {
		return fmt.Errorf("pacman -Sy: %s", line)
	}
	return nil
}
