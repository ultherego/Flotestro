package main

import (
	"bufio"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Binary is what the tool knows about one built binary: the same thing the
// binary carries in its build metadata, no more. A dependency that is not in
// the binary is not in the bill.
type Binary struct {
	// Name is the file name of the binary, e.g. flotestro-agent.
	Name string
	// Path is the main package, e.g. github.com/ultherego/flotestro/cmd/agent.
	Path string
	// Module is the main module and its version as the toolchain recorded
	// it: "(devel)" for a build from a working tree.
	Module Module
	// Toolchain is the Go version the binary was built with.
	Toolchain string
	// Deps are the modules that entered the binary, in the order the
	// toolchain lists them.
	Deps []Module
	// Settings are the build settings: GOOS, GOARCH, CGO_ENABLED, the
	// linker flags, the VCS revision.
	Settings map[string]string
}

// Module is one Go module and its version. Replace names the module that
// really entered the binary in place of it.
type Module struct {
	Path    string
	Version string
	Sum     string
	Replace *Module
}

// ReadBinary reads the build metadata of a binary file. The read works
// across architectures: a bill of an arm64 binary is made on the amd64
// build machine.
func ReadBinary(file string) (Binary, error) {
	info, err := buildinfo.ReadFile(file)
	if err != nil {
		return Binary{}, err
	}
	binary := Binary{
		Name:      filepath.Base(file),
		Path:      info.Path,
		Toolchain: info.GoVersion,
		Module:    Module{Path: info.Main.Path, Version: info.Main.Version, Sum: info.Main.Sum},
		Settings:  map[string]string{},
	}
	for _, dep := range info.Deps {
		module := Module{Path: dep.Path, Version: dep.Version, Sum: dep.Sum}
		if dep.Replace != nil {
			module.Replace = &Module{Path: dep.Replace.Path, Version: dep.Replace.Version, Sum: dep.Replace.Sum}
		}
		binary.Deps = append(binary.Deps, module)
	}
	for _, setting := range info.Settings {
		binary.Settings[setting.Key] = setting.Value
	}
	return binary, nil
}

// ParseModules reads the output of "go version -m": one or more binaries,
// each with a header line and tab-indented records. The format is the
// toolchain's; the parser takes what the toolchain prints and nothing else.
func ParseModules(r io.Reader) ([]Binary, error) {
	var (
		binaries []Binary
		current  *Binary
	)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "\t") {
			// "<file>: go1.25.0" opens a binary.
			file, toolchain, ok := strings.Cut(line, ": ")
			if !ok {
				return nil, fmt.Errorf("the line %q is neither a binary header nor a record", line)
			}
			binaries = append(binaries, Binary{
				Name:      filepath.Base(strings.TrimSpace(file)),
				Toolchain: strings.TrimSpace(toolchain),
				Settings:  map[string]string{},
			})
			current = &binaries[len(binaries)-1]
			continue
		}
		if current == nil {
			return nil, fmt.Errorf("the record %q comes before any binary header", line)
		}
		fields := strings.Split(strings.TrimPrefix(line, "\t"), "\t")
		switch fields[0] {
		case "path":
			if len(fields) < 2 {
				return nil, fmt.Errorf("the path record %q has no path", line)
			}
			current.Path = fields[1]
		case "mod":
			current.Module = moduleOf(fields)
		case "dep":
			current.Deps = append(current.Deps, moduleOf(fields))
		case "=>":
			// A replacement follows the module it replaces.
			if len(current.Deps) == 0 {
				return nil, fmt.Errorf("the replacement %q follows no module", line)
			}
			replacement := moduleOf(fields)
			current.Deps[len(current.Deps)-1].Replace = &replacement
		case "build":
			if len(fields) < 2 {
				continue
			}
			key, value, _ := strings.Cut(fields[1], "=")
			current.Settings[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(binaries) == 0 {
		return nil, fmt.Errorf("no binary in the input")
	}
	return binaries, nil
}

func moduleOf(fields []string) Module {
	module := Module{}
	if len(fields) > 1 {
		module.Path = fields[1]
	}
	if len(fields) > 2 {
		module.Version = fields[2]
	}
	if len(fields) > 3 {
		module.Sum = fields[3]
	}
	return module
}

// The CycloneDX 1.5 document, limited to what the bill of a Go binary
// needs. The field names are the specification's.
type document struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     metadata     `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

type metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     tools     `json:"tools"`
	Component component `json:"component"`
}

type tools struct {
	Components []component `json:"components"`
}

type component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref,omitempty"`
	Supplier   *supplier  `json:"supplier,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type supplier struct {
	Name string `json:"name"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// Options shapes the bill: the release version of the application, its
// supplier and the timestamp.
type Options struct {
	// Version is the release version of the binary. The toolchain records
	// "(devel)" for a build from a working tree, and the release script
	// knows the real one.
	Version  string
	Supplier string
	// Timestamp is the time of the bill. Zero means now; the release script
	// passes the build time, so the bills of one release agree.
	Timestamp time.Time
	// ToolVersion names this tool in the bill.
	ToolVersion string
}

// Write renders the bill of one binary as CycloneDX 1.5 JSON.
//
// The serial number is derived from the content, so the same binary gives
// the same bill: two builds of one release are told apart by their
// provenance, not by a random number in the bill.
func Write(w io.Writer, binary Binary, options Options) error {
	// The release version comes from the caller; a binary built from a tagged
	// module carries it itself, and a build from a working tree carries
	// "(devel)", which is not a version.
	version := options.Version
	if version == "" && binary.Module.Version != "" && binary.Module.Version != "(devel)" {
		version = strings.TrimPrefix(binary.Module.Version, "v")
	}
	application := component{
		Type:    "application",
		BOMRef:  purl(binary.Path, version),
		Name:    binary.Name,
		Version: version,
		PURL:    purl(binary.Path, version),
	}
	if options.Supplier != "" {
		application.Supplier = &supplier{Name: options.Supplier}
	}
	for _, key := range []string{"GOOS", "GOARCH", "CGO_ENABLED", "vcs.revision", "vcs.time", "vcs.modified"} {
		if value, ok := binary.Settings[key]; ok {
			application.Properties = append(application.Properties, property{"golang:build." + key, value})
		}
	}

	components := []component{{
		Type:    "library",
		BOMRef:  purl("stdlib", strings.TrimPrefix(binary.Toolchain, "go")),
		Name:    "stdlib",
		Version: strings.TrimPrefix(binary.Toolchain, "go"),
		PURL:    purl("stdlib", strings.TrimPrefix(binary.Toolchain, "go")),
		Properties: []property{
			{"golang:toolchain", binary.Toolchain},
		},
	}}
	for _, dep := range binary.Deps {
		entered := dep
		var properties []property
		if dep.Replace != nil {
			// The module that entered the binary is the replacement; the
			// original is kept as a property, because the go.mod names it.
			entered = *dep.Replace
			properties = append(properties, property{"golang:module.replaces", dep.Path + "@" + dep.Version})
		}
		if entered.Sum != "" {
			properties = append(properties, property{"golang:module.sum", entered.Sum})
		}
		components = append(components, component{
			Type:       "library",
			BOMRef:     purl(entered.Path, entered.Version),
			Name:       entered.Path,
			Version:    entered.Version,
			PURL:       purl(entered.Path, entered.Version),
			Properties: properties,
		})
	}
	sort.SliceStable(components[1:], func(i, j int) bool {
		return components[1+i].BOMRef < components[1+j].BOMRef
	})

	dependsOn := make([]string, 0, len(components))
	for _, item := range components {
		dependsOn = append(dependsOn, item.BOMRef)
	}

	stamp := options.Timestamp
	if stamp.IsZero() {
		stamp = time.Now()
	}
	doc := document{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: serialNumber(application.BOMRef, dependsOn),
		Version:      1,
		Metadata: metadata{
			Timestamp: stamp.UTC().Format(time.RFC3339),
			Tools: tools{Components: []component{{
				Type: "application", Name: "flotestro-sbom", Version: options.ToolVersion,
			}}},
			Component: application,
		},
		Components:   components,
		Dependencies: []dependency{{Ref: application.BOMRef, DependsOn: dependsOn}},
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

// purl renders a package URL of the golang type. The path is the module or
// package path and the version is the module version; a version of a Go
// module already carries its "v", and a release version of the application
// does not.
func purl(modulePath, version string) string {
	escaped := strings.ReplaceAll(modulePath, "@", "%40")
	if version == "" {
		return "pkg:golang/" + escaped
	}
	return "pkg:golang/" + escaped + "@" + version
}

// serialNumber derives the urn:uuid of the bill from its content.
func serialNumber(application string, refs []string) string {
	digest := sha256.New()
	digest.Write([]byte(application))
	for _, ref := range refs {
		digest.Write([]byte{0})
		digest.Write([]byte(ref))
	}
	sum := digest.Sum(nil)
	// A name-based UUID: version 8 (custom) with the variant bits set, so
	// that the serial is a valid UUID and still a function of the content.
	sum[6] = (sum[6] & 0x0f) | 0x80
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// WriteFile writes the bill of a binary into a directory as
// <name>.cdx.json.
func WriteFile(dir string, binary Binary, options Options) (string, error) {
	target := filepath.Join(dir, binary.Name+".cdx.json")
	file, err := os.Create(target)
	if err != nil {
		return "", err
	}
	if err := Write(file, binary, options); err != nil {
		_ = file.Close()
		return "", err
	}
	return target, file.Close()
}
