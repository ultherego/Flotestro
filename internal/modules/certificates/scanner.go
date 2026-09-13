package certificates

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// Runner runs a host tool. Injection instead of a direct call lets the
// parsing be checked without a host with certmonger.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// Target names a file to look at together with what the panel already
// knows about it.
//
// The key path and the service name are not guessed from the directory
// name: a human who knows what reads what enters them. A panel that
// guessed them would show relations looking checked and being a guess.
type Target struct {
	Path    string `json:"path"`
	KeyPath string `json:"key_path,omitempty"`
	Service string `json:"service,omitempty"`
}

// Scan reads the named files without root privileges.
//
// The scope is exactly what came in the order, later extended by what the
// host knows about itself - that is the certmonger requests. The module
// does not search the filesystem, so it will not find a certificate nobody
// mentioned; that is the price of not looking where it should not.
func Scan(targets []Target) Snapshot {
	snapshot := Snapshot{
		ObservedAt: time.Now().UTC(),
		Missing:    map[string]string{},
	}

	for _, target := range targets {
		snapshot.Scanned = append(snapshot.Scanned, target.Path)
		snapshot.Certificates = append(snapshot.Certificates, inspect(target, snapshot.Missing))
		if len(snapshot.Certificates) >= MaxCertificates {
			// A cut-off list must say so. Silence here looks like a host
			// that has no more certificates - and it is a host nobody asked
			// about the rest.
			if len(targets) > len(snapshot.Certificates) {
				snapshot.Truncated = len(targets) - len(snapshot.Certificates)
				snapshot.TruncatedReason = fmt.Sprintf(
					"the target list is longer than %d: the first %d described, %d skipped",
					MaxCertificates, len(snapshot.Certificates), snapshot.Truncated)
			}
			break
		}
	}

	// The state of the certmonger requests needs root, but the question
	// "does anything on this host watch certificates at all" has an answer
	// without it: a host without the tool has nothing to track and that is
	// not an unknown state.
	if !HasCertmonger() {
		snapshot.TrackingKnown = true
		snapshot.TrackingReason = "this host does not run certmonger"
		for i := range snapshot.Certificates {
			if snapshot.Certificates[i].UnavailableReason == "" {
				snapshot.Certificates[i].Renewal = RenewalManual
			}
		}
	} else {
		snapshot.Missing[FactTracking] = "certmonger request list requires root"
	}

	// The private key lies in a directory closed to everyone but the
	// service, so even its permissions are seen only by root. No knowledge
	// about the key is not the same as a key that does not exist.
	if keysNeeded(targets) {
		snapshot.Missing[FactKeyMetadata] = "private key metadata requires root"
	} else {
		snapshot.KeysKnown = true
	}
	return snapshot
}

// keysNeeded says whether any target names a key.
func keysNeeded(targets []Target) bool {
	for _, target := range targets {
		if target.KeyPath != "" {
			return true
		}
	}
	return false
}

// HasCertmonger says whether the certmonger tool is on the host.
func HasCertmonger() bool {
	return ToolPath() != ""
}

// ToolPath returns the path to getcert or an empty string.
func ToolPath() string {
	for _, path := range []string{GetcertPath, GetcertPathAlt} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// inspect reads one file and assembles a certificate description from it.
func inspect(target Target, missing map[string]string) Certificate {
	description := Certificate{
		Path:         target.Path,
		OwnerService: target.Service,
		Source:       SourceExternal,
		Renewal:      RenewalUnknown,
	}
	if target.KeyPath != "" {
		description.Key = &KeyMetadata{Path: target.KeyPath, Reason: "not read yet"}
	}
	if err := ValidatePath(target.Path); err != nil {
		description.UnavailableReason = err.Error()
		return description
	}

	data, err := ReadFile(target.Path)
	if err != nil {
		description.UnavailableReason = err.Error()
		// A file the agent cannot open is not a file that does not exist:
		// a service certificate is at times kept in a directory closed to
		// everyone but the service. The helper is then asked for the
		// content, by file name.
		if errors.Is(err, os.ErrPermission) {
			missing[FactCertificateFiles] = "certificate files are not readable without root"
		}
		return description
	}

	certs, err := ParsePEM(data)
	if err != nil {
		description.UnavailableReason = err.Error()
		return description
	}
	gathered := Describe(target.Path, certs)
	gathered.OwnerService = target.Service
	gathered.Key = description.Key
	return gathered
}

// ReadFile reads a certificate file with an upper size bound.
//
// The open goes with O_NOFOLLOW: a certificate path is at times a symlink,
// but a symlink may also point anywhere else - and the module would then
// read a file nobody named for it.
func ReadFile(path string) ([]byte, error) {
	handle, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("the path does not point at a regular file")
	}
	if info.Size() > MaxFileSize {
		return nil, errors.New("the file is bigger than " +
			strconv.Itoa(MaxFileSize) + " bytes; this is not a certificate")
	}
	return io.ReadAll(io.LimitReader(handle, MaxFileSize))
}

// DescribeKey gathers the private key metadata without reading its
// content.
func DescribeKey(path string) KeyMetadata {
	description := KeyMetadata{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// A missing file is an answer, not a read error: a service with
			// a certificate without a key does not come up and the operator
			// is meant to see that.
			return description
		}
		description.Reason = err.Error()
		return description
	}
	description.Exists = true
	description.Mode = strconv.FormatUint(uint64(info.Mode().Perm()), 8)
	if len(description.Mode) < 4 {
		description.Mode = "0000"[:4-len(description.Mode)] + description.Mode
	}
	description.WorldReadable = info.Mode().Perm()&0o004 != 0
	if stat, ok := info.Sys().(*unix.Stat_t); ok {
		description.Owner = userName(int(stat.Uid))
		description.Group = groupName(int(stat.Gid))
	}
	return description
}

func userName(uid int) string {
	if entry, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return entry.Username
	}
	return strconv.Itoa(uid)
}

func groupName(gid int) string {
	if entry, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		return entry.Name
	}
	return strconv.Itoa(gid)
}

// CollectSupplement reads the facts the agent asked for by name.
//
// The helper receives neither a "read this file" nor a "run this tool"
// command: it receives a list of fact names and a list of targets the panel
// has already approved once, and checks every path again with its own
// rule.
func CollectSupplement(ctx context.Context, run Runner,
	facts []string, targets []Target) Supplement {
	extra := Supplement{Errors: map[string]string{}}

	for _, fact := range facts {
		switch fact {
		case FactKeyMetadata:
			extra.Keys = map[string]KeyMetadata{}
			for _, target := range targets {
				if target.KeyPath == "" {
					continue
				}
				if err := ValidatePath(target.KeyPath); err != nil {
					extra.Keys[target.KeyPath] = KeyMetadata{Path: target.KeyPath, Reason: err.Error()}
					continue
				}
				extra.Keys[target.KeyPath] = DescribeKey(target.KeyPath)
			}

		case FactCertificateFiles:
			extra.Files = map[string]string{}
			for _, target := range targets {
				if err := ValidatePath(target.Path); err != nil {
					extra.Errors[target.Path] = err.Error()
					continue
				}
				data, err := ReadFile(target.Path)
				if err != nil {
					extra.Errors[target.Path] = err.Error()
					continue
				}
				extra.Files[target.Path] = string(data)
			}

		case FactTracking:
			tool := ToolPath()
			if tool == "" {
				extra.TrackingKnown = true
				extra.TrackingReason = "this host does not run certmonger"
				continue
			}
			output, err := run(ctx, tool, "list")
			if err != nil {
				extra.Errors[FactTracking] = err.Error()
				continue
			}
			extra.Tracking = ParseGetcert(output)
			extra.TrackingKnown = true
		}
	}
	return extra
}

// Supplemented inserts the helper facts into the picture gathered without
// root.
func (s Snapshot) Supplemented(extra Supplement) Snapshot {
	if extra.Keys != nil {
		delete(s.Missing, FactKeyMetadata)
		s.KeysKnown = true
		for i := range s.Certificates {
			key := s.Certificates[i].Key
			if key == nil {
				continue
			}
			if metadata, known := extra.Keys[key.Path]; known {
				s.Certificates[i].Key = &metadata
			}
		}
	}

	if extra.Files != nil {
		for path, content := range extra.Files {
			certs, err := ParsePEM([]byte(content))
			if err != nil {
				continue
			}
			for i := range s.Certificates {
				if s.Certificates[i].Path != path {
					continue
				}
				gathered := Describe(path, certs)
				gathered.OwnerService = s.Certificates[i].OwnerService
				gathered.Key = s.Certificates[i].Key
				s.Certificates[i] = gathered
			}
		}
		if len(extra.Files) > 0 {
			delete(s.Missing, FactCertificateFiles)
		}
	}

	if extra.TrackingKnown {
		delete(s.Missing, FactTracking)
		s.TrackingKnown = true
		s.TrackingReason = extra.TrackingReason
		for i := range s.Certificates {
			if s.Certificates[i].UnavailableReason != "" {
				continue
			}
			tracking, tracked := extra.Tracking[s.Certificates[i].Path]
			if !tracked {
				s.Certificates[i].Renewal = RenewalManual
				continue
			}
			copied := tracking
			s.Certificates[i].Tracking = &copied
			s.Certificates[i].Renewal = RenewalTracked
			s.Certificates[i].Source = SourceCertmonger
			if s.Certificates[i].Key == nil && tracking.KeyPath != "" {
				s.Certificates[i].Key = &KeyMetadata{
					Path:   tracking.KeyPath,
					Reason: "key is managed by certmonger",
				}
			}
		}
	}

	for name, reason := range extra.Errors {
		if s.Missing == nil {
			s.Missing = map[string]string{}
		}
		s.Missing[name] = reason
	}
	return s
}

// AddTracked adds to the scope the certificates watched by certmonger.
//
// The host knows about them itself, so the panel does not have to configure
// them - and without them the tab would show emptiness on a host that has
// its own domain certificate and has been renewing it for months.
func AddTracked(targets []Target, trackings map[string]Tracking) []Target {
	known := map[string]bool{}
	for _, target := range targets {
		known[target.Path] = true
	}
	for path, tracking := range trackings {
		if path == "" || known[path] {
			continue
		}
		if ValidatePath(path) != nil {
			continue
		}
		targets = append(targets, Target{Path: path, KeyPath: tracking.KeyPath})
		known[path] = true
	}
	return targets
}

// fileOwner reads the owner identifiers from the file metadata.
func fileOwner(info os.FileInfo) (int, int, bool) {
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok {
		return -1, -1, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
