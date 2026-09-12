package packages

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Repository is a source of packages the host will treat as its own.
//
// This is the operation with the widest reach in the whole package module:
// adding a source installs nothing today but settles whose packages the host
// will accept tomorrow - along with their installation scripts, which run as
// root. That is why a source without a signature requires explicit consent,
// and the password to a private source does not travel in the order.
type Repository struct {
	// ID is the name of the file and the name of the section. The panel does
	// not allow a name that would leave the directory of the sources.
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
	// Suites and Components describe a source in the Debian format. DNF has
	// none of them: there the whole address is in the URL.
	Suites        []string `json:"suites,omitempty"`
	Components    []string `json:"components,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Enabled       bool     `json:"enabled"`
	// Priority settles which source wins for the same version of a package.
	Priority int `json:"priority,omitempty"`
	// GPGKeyFingerprint is the fingerprint of the key the source signs its
	// metadata with. The fingerprint is shown to a person, because only they
	// can compare it with the one given by the supplier.
	GPGKeyFingerprint string `json:"gpg_key_fingerprint,omitempty"`
	// Signed says whether the host checks the signatures of this source at
	// all.
	Signed bool `json:"signed"`
	// Username is the user name of a private source; the password never lands
	// here - it is in the secret store and only there.
	Username string `json:"username,omitempty"`
	// SecretName says which secret the password comes from. The name, not the
	// value.
	SecretName string `json:"secret_name,omitempty"`
	// Managed marks a source written by the panel. The sources of the
	// distribution are shown but not rewritten.
	Managed bool   `json:"managed"`
	Path    string `json:"path,omitempty"`
	// UnavailableReason describes a file that could not be read. A source with
	// a password has the permissions 0600 and the agent without root will not
	// read it - and that is a different answer than "there is no such
	// source".
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// RepositoryImage is the state of the package sources on a host.
type RepositoryImage struct {
	Repositories []Repository `json:"repositories,omitempty"`
	// Known says whether the list could be read at all. An empty list and a
	// list that was not read are two different answers.
	Known             bool      `json:"repositories_known"`
	Manager           string    `json:"manager,omitempty"`
	ObservedAt        time.Time `json:"repositories_observed_at,omitempty"`
	UnavailableReason string    `json:"repositories_unavailable_reason,omitempty"`
}

// The directories of the sources and the keys.
const (
	APTSourcesDir       = "/etc/apt/sources.list.d"
	APTSourcesFile      = "/etc/apt/sources.list"
	APTKeyringsDir      = "/etc/apt/keyrings"
	APTAuthDir          = "/etc/apt/auth.conf.d"
	DNFSourcesDir       = "/etc/yum.repos.d"
	DNFKeysDir          = "/etc/pki/rpm-gpg"
	flotestroFilePrefix = "flotestro-"
)

// panelMarker stands in the first line of every file written by the panel.
// The host recognises a managed source by it - also when the panel does not
// happen to be asking about it.
const panelMarker = "# flotestro: a source managed by the panel"

// secretMarker records the name of the secret with the password. The name,
// not the value: this way the panel sees the link and the file gives nothing
// else away.
const secretMarker = "# flotestro-secret: "

// userMarker records the user name of a private source. In APT the name lies
// together with the password in a file for root, so without this comment the
// panel would see a source with a password but would not know who it presents
// itself as. A user name is not a secret - it is in the order and in the
// audit.
const userMarker = "# flotestro-user: "

// repositoryName limits the identifier to what can be the name of a file.
var repositoryName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)

// File describes one file to write on the host.
type File struct {
	Path string
	// The content of a file with a password reaches neither the result nor the
	// log.
	Content []byte
	Mode    os.FileMode
	// Sensitive marks a file whose content must not be shown anywhere outside
	// the file itself.
	Sensitive bool
}

// ValidateRepository checks a source before it is written.
//
// The check is shared by the panel and the host: an order the host would not
// accept anyway falls out already at the ordering, with the same reason.
func ValidateRepository(repo Repository, manager string, withSecret bool) error {
	if !repositoryName.MatchString(repo.ID) {
		return fmt.Errorf("an invalid identifier of a source %q", repo.ID)
	}
	if repo.Absent() {
		return nil
	}
	address, err := url.Parse(repo.URL)
	if err != nil || address.Host == "" {
		return fmt.Errorf("the address of the source %q is not a valid URL", repo.URL)
	}
	switch address.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("a source may be fetched over http or https alone")
	}
	if strings.ContainsAny(repo.URL, " \t\n\"'") {
		return fmt.Errorf("the address of the source contains a forbidden character")
	}
	// A source without signature checking means the host will install
	// everything that comes from that address - along with the scripts of the
	// packages, which run as root. Without TLS it means on top of that that
	// being on the way is enough.
	if !repo.Signed && address.Scheme != "https" {
		return fmt.Errorf("a source without signature checking has to be at least over https")
	}
	// A password travelling over plain http is read by anyone who is on the
	// way.
	if withSecret && address.Scheme != "https" {
		return fmt.Errorf("a source with a password has to be fetched over https")
	}
	if withSecret && repo.Username == "" {
		return fmt.Errorf("a source with a password requires a user name")
	}
	if repo.Username != "" && strings.ContainsAny(repo.Username, " \t\n:") {
		return fmt.Errorf("the user name contains a forbidden character")
	}
	if repo.Priority < 0 || repo.Priority > 1000 {
		return fmt.Errorf("the priority %d is outside the range 0-1000", repo.Priority)
	}
	for _, field := range append(append([]string{}, repo.Suites...), repo.Components...) {
		if field == "" || strings.ContainsAny(field, " \t\n\"'/") {
			return fmt.Errorf("an invalid value %q in the description of the source", field)
		}
	}
	for _, architecture := range repo.Architectures {
		if architecture == "" || strings.ContainsAny(architecture, " \t\n\"'/") {
			return fmt.Errorf("an invalid architecture %q", architecture)
		}
	}
	if repo.Name != "" && strings.ContainsAny(repo.Name, "\n\r") {
		return fmt.Errorf("the name of the source contains a newline character")
	}

	switch manager {
	case "apt":
		if len(repo.Suites) == 0 {
			return fmt.Errorf("an APT source requires a suite to be named")
		}
	case "dnf":
		if len(repo.Suites) > 0 || len(repo.Components) > 0 {
			return fmt.Errorf("a DNF source is described by its address alone, without suites and components")
		}
	default:
		return fmt.Errorf("%s: the manager %q does not support managing sources",
			ErrorUnsupported, manager)
	}
	return nil
}

// Absent says whether the order removes the source. A source without an
// address is not an empty source - it is a source that is to disappear.
func (r Repository) Absent() bool { return r.URL == "" }

// SourceFiles assembles the files that describe a source.
//
// The password arrives separately, because it is not in the description of the
// source and must not end up there: it comes from the store right before the
// write and lives only here.
func SourceFiles(repo Repository, manager, key string, password []byte) ([]File, error) {
	switch manager {
	case "apt":
		return aptFiles(repo, key, password)
	case "dnf":
		return dnfFiles(repo, key, password)
	}
	return nil, fmt.Errorf("%s: the manager %q does not support managing sources",
		ErrorUnsupported, manager)
}

// SourcePaths lists the files that belong to a source. We use them when
// removing as well: a removed source has to take its key and its password with
// it.
func SourcePaths(id, manager string) []string {
	switch manager {
	case "apt":
		return []string{
			filepath.Join(APTSourcesDir, id+".sources"),
			filepath.Join(APTKeyringsDir, flotestroFilePrefix+id+".asc"),
			filepath.Join(APTAuthDir, flotestroFilePrefix+id+".conf"),
		}
	case "dnf":
		return []string{
			filepath.Join(DNFSourcesDir, id+".repo"),
			filepath.Join(DNFKeysDir, "RPM-GPG-KEY-"+flotestroFilePrefix+id),
		}
	}
	return nil
}

// aptFiles assembles a source in the deb822 format.
//
// The one-line format is left to the distribution: deb822 allows naming the
// key next to the source (Signed-By) instead of adding it to the trust of the
// whole system. That is the difference between "we trust this source in this
// scope" and "we trust this key everywhere".
func aptFiles(repo Repository, key string, password []byte) ([]File, error) {
	keyPath := filepath.Join(APTKeyringsDir, flotestroFilePrefix+repo.ID+".asc")
	var files []File

	var description strings.Builder
	description.WriteString(panelMarker + "\n")
	if repo.SecretName != "" {
		description.WriteString(secretMarker + repo.SecretName + "\n")
	}
	if repo.Username != "" {
		description.WriteString(userMarker + repo.Username + "\n")
	}
	description.WriteString("Types: deb\n")
	description.WriteString("URIs: " + repo.URL + "\n")
	description.WriteString("Suites: " + strings.Join(repo.Suites, " ") + "\n")
	if len(repo.Components) > 0 {
		description.WriteString("Components: " + strings.Join(repo.Components, " ") + "\n")
	}
	if len(repo.Architectures) > 0 {
		description.WriteString("Architectures: " + strings.Join(repo.Architectures, " ") + "\n")
	}
	description.WriteString("Enabled: " + yesNo(repo.Enabled) + "\n")
	if repo.Signed {
		description.WriteString("Signed-By: " + keyPath + "\n")
		files = append(files, File{Path: keyPath, Content: []byte(key), Mode: 0o644})
	} else {
		// Without a signature apt will ask anyway, so the consent of the
		// operator has to be written into the file - along with the fact that
		// it is a consent rather than a default setting.
		description.WriteString("Trusted: yes\n")
	}
	files = append(files, File{
		Path:    filepath.Join(APTSourcesDir, repo.ID+".sources"),
		Content: []byte(description.String()), Mode: 0o644,
	})

	if len(password) > 0 {
		address, err := url.Parse(repo.URL)
		if err != nil {
			return nil, err
		}
		// The password lies separately, in a file for root. It is not in the
		// file of the source at all: that one is readable by everyone and is
		// to stay that way.
		entry := panelMarker + "\nmachine " + address.Host + strings.TrimSuffix(address.Path, "/") +
			" login " + repo.Username + " password " + string(password) + "\n"
		files = append(files, File{
			Path:      filepath.Join(APTAuthDir, flotestroFilePrefix+repo.ID+".conf"),
			Content:   []byte(entry),
			Mode:      0o600,
			Sensitive: true,
		})
	}
	return files, nil
}

// dnfFiles assembles a source in the ini format.
func dnfFiles(repo Repository, key string, password []byte) ([]File, error) {
	keyPath := filepath.Join(DNFKeysDir, "RPM-GPG-KEY-"+flotestroFilePrefix+repo.ID)
	var files []File

	name := repo.Name
	if name == "" {
		name = repo.ID
	}
	var description strings.Builder
	description.WriteString(panelMarker + "\n")
	if repo.SecretName != "" {
		description.WriteString(secretMarker + repo.SecretName + "\n")
	}
	description.WriteString("[" + repo.ID + "]\n")
	description.WriteString("name=" + name + "\n")
	description.WriteString("baseurl=" + repo.URL + "\n")
	description.WriteString("enabled=" + oneZero(repo.Enabled) + "\n")
	description.WriteString("gpgcheck=" + oneZero(repo.Signed) + "\n")
	if repo.Signed {
		description.WriteString("gpgkey=file://" + keyPath + "\n")
		files = append(files, File{Path: keyPath, Content: []byte(key), Mode: 0o644})
	}
	if repo.Priority > 0 {
		description.WriteString(fmt.Sprintf("priority=%d\n", repo.Priority))
	}
	mode := os.FileMode(0o644)
	sensitive := false
	if len(password) > 0 {
		// DNF has no separate password file: the credentials are in the
		// description of the source. That is why the whole file gets the
		// permissions of root, and the operator is to know it.
		description.WriteString("username=" + repo.Username + "\n")
		description.WriteString("password=" + string(password) + "\n")
		mode, sensitive = 0o600, true
	}
	files = append(files, File{
		Path:    filepath.Join(DNFSourcesDir, repo.ID+".repo"),
		Content: []byte(description.String()), Mode: mode, Sensitive: sensitive,
	})
	return files, nil
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func oneZero(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// ReadRepositories lists the sources visible on the host.
//
// The read goes without root: the files of the sources are public. The
// exception is a source with a password, which the panel itself wrote with the
// permissions of root - such a source is left with a reason rather than
// disappearing from the list.
func ReadRepositories(manager string) RepositoryImage {
	image := RepositoryImage{Manager: manager, ObservedAt: time.Now().UTC()}
	switch manager {
	case "apt":
		image.Repositories = readAPT()
		image.Known = true
	case "dnf":
		image.Repositories = readDNF()
		image.Known = true
	default:
		image.UnavailableReason = "this package manager does not expose repositories"
	}
	sort.Slice(image.Repositories, func(i, j int) bool {
		return image.Repositories[i].ID < image.Repositories[j].ID
	})
	return image
}

// readAPT reads the sources in both formats apt understands.
func readAPT() []Repository {
	var sources []Repository
	entries, _ := os.ReadDir(APTSourcesDir)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(APTSourcesDir, entry.Name())
		switch filepath.Ext(entry.Name()) {
		case ".sources":
			sources = append(sources, readDeb822Source(path))
		case ".list":
			sources = append(sources, readListSource(path)...)
		}
	}
	if _, err := os.Stat(APTSourcesFile); err == nil {
		sources = append(sources, readListSource(APTSourcesFile)...)
	}
	return sources
}

// readDeb822Source reads one file in the deb822 format.
func readDeb822Source(path string) Repository {
	repo := Repository{
		ID:   strings.TrimSuffix(filepath.Base(path), ".sources"),
		Path: path,
	}
	data, err := os.ReadFile(path)
	if err != nil {
		repo.UnavailableReason = err.Error()
		return repo
	}
	// Enabled without an entry means an enabled source: that is the default
	// state of apt.
	repo.Enabled = true
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == panelMarker {
			repo.Managed = true
			continue
		}
		if strings.HasPrefix(trimmed, secretMarker) {
			repo.SecretName = strings.TrimSpace(strings.TrimPrefix(trimmed, secretMarker))
			continue
		}
		if strings.HasPrefix(trimmed, userMarker) {
			repo.Username = strings.TrimSpace(strings.TrimPrefix(trimmed, userMarker))
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "uris":
			repo.URL = firstField(value)
		case "suites":
			repo.Suites = strings.Fields(value)
		case "components":
			repo.Components = strings.Fields(value)
		case "architectures":
			repo.Architectures = strings.Fields(value)
		case "enabled":
			repo.Enabled = !strings.EqualFold(value, "no") && !strings.EqualFold(value, "false")
		case "signed-by":
			repo.Signed = value != ""
		}
	}
	return repo
}

// readListSource reads the sources in the one-line format.
func readListSource(path string) []Repository {
	data, err := os.ReadFile(path)
	if err != nil {
		return []Repository{{
			ID:                strings.TrimSuffix(filepath.Base(path), ".list"),
			Path:              path,
			UnavailableReason: err.Error(),
		}}
	}
	return readListSourceFromContent(path, string(data))
}

// readListSourceFromContent splits the content of a file into sources.
func readListSourceFromContent(path, content string) []Repository {
	var sources []Repository
	number := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 || (fields[0] != "deb" && fields[0] != "deb-src") {
			continue
		}
		number++
		repo := Repository{
			ID:      fmt.Sprintf("%s#%d", strings.TrimSuffix(filepath.Base(path), ".list"), number),
			Path:    path,
			Enabled: true,
		}
		// The options in square brackets stand before the address; the only
		// thing that interests us in them is whether the source names a key.
		rest := fields[1:]
		if strings.HasPrefix(rest[0], "[") {
			for i, field := range rest {
				if strings.Contains(field, "signed-by=") {
					repo.Signed = true
				}
				if strings.HasSuffix(field, "]") {
					rest = rest[i+1:]
					break
				}
			}
		}
		if len(rest) < 2 {
			continue
		}
		repo.URL = rest[0]
		repo.Suites = rest[1:2]
		if len(rest) > 2 {
			repo.Components = rest[2:]
		}
		sources = append(sources, repo)
	}
	return sources
}

// readDNF reads the .repo files. One file can describe several sources.
func readDNF() []Repository {
	var sources []Repository
	entries, _ := os.ReadDir(DNFSourcesDir)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".repo" {
			continue
		}
		path := filepath.Join(DNFSourcesDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			sources = append(sources, Repository{
				ID:                strings.TrimSuffix(entry.Name(), ".repo"),
				Path:              path,
				UnavailableReason: err.Error(),
			})
			continue
		}
		sources = append(sources, readDNFSections(path, string(data))...)
	}
	return sources
}

// readDNFSections splits a file into sections and reads from them what is
// visible.
func readDNFSections(path, content string) []Repository {
	var sources []Repository
	var current *Repository
	managed, secret := false, ""

	flush := func() {
		if current != nil {
			sources = append(sources, *current)
		}
		current = nil
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == panelMarker {
			managed = true
			continue
		}
		if strings.HasPrefix(trimmed, secretMarker) {
			secret = strings.TrimSpace(strings.TrimPrefix(trimmed, secretMarker))
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			flush()
			current = &Repository{
				ID: strings.Trim(trimmed, "[]"), Path: path,
				Enabled: true, Managed: managed, SecretName: secret,
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "name":
			current.Name = value
		case "baseurl", "metalink", "mirrorlist":
			if current.URL == "" {
				current.URL = firstField(value)
			}
		case "enabled":
			current.Enabled = value == "1" || strings.EqualFold(value, "true")
		case "gpgcheck":
			current.Signed = value == "1" || strings.EqualFold(value, "true")
		case "username":
			current.Username = value
		case "priority":
			fmt.Sscanf(value, "%d", &current.Priority)
		}
	}
	flush()
	return sources
}

func firstField(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// RefreshSource fetches the metadata of one source.
//
// One rather than all: a full refresh also pulls the sources that have nothing
// to do with this change, and their failure would look like a failure of our
// write - and would roll a correct change back.
func RefreshSource(ctx context.Context, manager, id string, sourcePath string) error {
	switch manager {
	case "apt":
		// apt-get update reads the sources from a directory, so we give it a
		// temporary directory holding our source alone.
		directory, err := os.MkdirTemp("", "flotestro-repo-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(directory)
		data, err := os.ReadFile(sourcePath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, id+".sources"), data, 0o644); err != nil {
			return err
		}
		// apt ends with the code zero also when a source could not be fetched:
		// a failed index is a warning to it, one that can be ignored. To the
		// panel that is not a warning - it is the answer "there is no such
		// source", and a source that does not answer will block every next
		// package operation on this host.
		result := run(ctx, 5*time.Minute, aptGetPath, "update", "--quiet",
			"-o", "APT::Update::Error-Mode=any",
			"-o", "Dir::Etc::sourcelist=/dev/null",
			"-o", "Dir::Etc::sourceparts="+directory)
		if !result.Ran || result.ExitCode != 0 {
			return fmt.Errorf("apt-get update: %s", result.Reason())
		}
		// An older apt does not know this setting and passes over it together
		// with the error, so we also read what it wrote.
		if line := firstAPTError(result.Stdout + "\n" + result.Stderr); line != "" {
			return fmt.Errorf("apt-get update: %s", line)
		}
		return nil
	case "dnf":
		result := run(ctx, 5*time.Minute, dnfPath, "--disablerepo=*",
			"--enablerepo="+id, "makecache", "--refresh")
		if !result.Ran || result.ExitCode != 0 {
			return fmt.Errorf("dnf makecache: %s", result.Reason())
		}
		// dnf, just like apt, ends with the code zero and the message
		// "Metadata cache created" also when not a single address of the
		// source could be opened. The exit code therefore does not answer the
		// question we are asking, and one has to read what the tool wrote.
		if line := firstDNFError(result.Stdout + "\n" + result.Stderr); line != "" {
			return fmt.Errorf("dnf makecache: %s", line)
		}
		return nil
	}
	return fmt.Errorf("%s: the manager %q does not support managing sources",
		ErrorUnsupported, manager)
}

// firstAPTError extracts the first error line out of the output of apt.
func firstAPTError(wyjscie string) string {
	for _, line := range strings.Split(wyjscie, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Err:") || strings.HasPrefix(trimmed, "E: ") {
			return trimmed
		}
	}
	return ""
}

// dnfErrors list the traces of a failed fetch of the metadata. The set covers
// both generations of the tool: dnf4 writes about synchronisation errors, dnf5
// about errors of the curl library and about a missing usable address.
var dnfErrors = []string{
	"curl error",
	"usable url not found",
	"failed to download metadata",
	"errors during downloading metadata",
	"cannot download repomd.xml",
	"failed to synchronize cache",
}

// firstDNFError extracts the first trace of a failed fetch out of the output
// of dnf.
func firstDNFError(wyjscie string) string {
	for _, line := range strings.Split(wyjscie, "\n") {
		trimmed := strings.TrimSpace(strings.TrimLeft(line, "> "))
		lower := strings.ToLower(trimmed)
		for _, trace := range dnfErrors {
			if strings.Contains(lower, trace) {
				return trimmed
			}
		}
	}
	return ""
}
