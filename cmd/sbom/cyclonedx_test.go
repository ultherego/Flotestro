package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) []Binary {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", "modules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	binaries, err := ParseModules(file)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return binaries
}

// TestParseModulesReadsWhatTheToolchainPrints: the header opens a binary,
// the records fill it in, a replacement follows the module it replaces, and
// a second header opens a second binary.
func TestParseModulesReadsWhatTheToolchainPrints(t *testing.T) {
	binaries := fixture(t)
	if len(binaries) != 2 {
		t.Fatalf("parsed %d binaries, expected 2", len(binaries))
	}
	agent := binaries[0]
	if agent.Name != "flotestro-agent" || agent.Toolchain != "go1.25.0" ||
		agent.Path != "github.com/ultherego/flotestro/cmd/agent" {
		t.Fatalf("agent = %+v", agent)
	}
	if agent.Module.Path != "github.com/ultherego/flotestro" || agent.Module.Version != "(devel)" {
		t.Fatalf("main module = %+v", agent.Module)
	}
	if len(agent.Deps) != 4 {
		t.Fatalf("deps = %+v, expected 4", agent.Deps)
	}
	net := agent.Deps[2]
	if net.Path != "golang.org/x/net" || net.Replace == nil || net.Replace.Path != "github.com/ultherego/net" ||
		net.Replace.Version != "v0.30.1" {
		t.Fatalf("the replacement was not attached: %+v", net)
	}
	if agent.Settings["GOARCH"] != "amd64" || agent.Settings["CGO_ENABLED"] != "0" ||
		agent.Settings["vcs.revision"] != "3f3b0e0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a" {
		t.Fatalf("settings = %v", agent.Settings)
	}
	if !strings.HasPrefix(agent.Settings["-ldflags"], `"-s -w`) {
		t.Fatalf("the linker flags were split at the first equals sign: %q", agent.Settings["-ldflags"])
	}
	if binaries[1].Name != "flotestro-relay" || len(binaries[1].Deps) != 1 {
		t.Fatalf("relay = %+v", binaries[1])
	}

	for _, bad := range []string{"\tdep\tx\tv1\n", "not a header\n", "x: go1\n\t=>\ty\tv1\n"} {
		if _, err := ParseModules(strings.NewReader(bad)); err == nil {
			t.Errorf("%q was parsed", bad)
		}
	}
}

// bill is the part of the document the tests read back.
type bill struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []struct{ Name string } `json:"components"`
		} `json:"tools"`
		Component struct {
			Type       string `json:"type"`
			BOMRef     string `json:"bom-ref"`
			Name       string `json:"name"`
			Version    string `json:"version"`
			PURL       string `json:"purl"`
			Supplier   struct{ Name string }
			Properties []struct{ Name, Value string }
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		Type       string `json:"type"`
		BOMRef     string `json:"bom-ref"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		PURL       string `json:"purl"`
		Properties []struct{ Name, Value string }
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

// TestWriteRendersCycloneDX: the bill names the format and version, the
// application with the release version, one library per module with a
// golang package URL, the toolchain, and the dependency edge from the
// application to every one of them.
func TestWriteRendersCycloneDX(t *testing.T) {
	agent := fixture(t)[0]
	var out bytes.Buffer
	stamp := time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)
	if err := Write(&out, agent, Options{Version: "0.41.0", Supplier: "Flotestro", Timestamp: stamp, ToolVersion: "0.41.0"}); err != nil {
		t.Fatal(err)
	}
	var doc bill
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("the bill is not JSON: %v\n%s", err, out.String())
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
		t.Fatalf("format = %s %s", doc.BOMFormat, doc.SpecVersion)
	}
	if !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") || len(doc.SerialNumber) != len("urn:uuid:")+36 {
		t.Fatalf("serial = %q", doc.SerialNumber)
	}
	if doc.Metadata.Timestamp != "2026-09-14T08:00:00Z" {
		t.Fatalf("timestamp = %q", doc.Metadata.Timestamp)
	}
	app := doc.Metadata.Component
	if app.Type != "application" || app.Name != "flotestro-agent" || app.Version != "0.41.0" ||
		app.PURL != "pkg:golang/github.com/ultherego/flotestro/cmd/agent@0.41.0" || app.BOMRef != app.PURL ||
		app.Supplier.Name != "Flotestro" {
		t.Fatalf("application = %+v", app)
	}
	properties := map[string]string{}
	for _, property := range app.Properties {
		properties[property.Name] = property.Value
	}
	if properties["golang:build.GOARCH"] != "amd64" || properties["golang:build.vcs.revision"] == "" {
		t.Fatalf("application properties = %v", properties)
	}

	// The toolchain plus the four modules; the replacement stands in for
	// the module it replaced, which is kept as a property.
	if len(doc.Components) != 5 {
		t.Fatalf("components = %d, expected 5", len(doc.Components))
	}
	byPURL := map[string]int{}
	for i, item := range doc.Components {
		if item.Type != "library" || item.BOMRef != item.PURL || !strings.HasPrefix(item.PURL, "pkg:golang/") {
			t.Errorf("component %+v", item)
		}
		byPURL[item.PURL] = i
	}
	if _, ok := byPURL["pkg:golang/stdlib@1.25.0"]; !ok {
		t.Errorf("the toolchain is missing: %v", byPURL)
	}
	if _, ok := byPURL["pkg:golang/connectrpc.com/connect@v1.16.2"]; !ok {
		t.Errorf("connect is missing: %v", byPURL)
	}
	if _, ok := byPURL["pkg:golang/golang.org/x/net@v0.30.0"]; ok {
		t.Errorf("the replaced module is listed as if it entered the binary")
	}
	replacement, ok := byPURL["pkg:golang/github.com/ultherego/net@v0.30.1"]
	if !ok {
		t.Fatalf("the replacement is missing: %v", byPURL)
	}
	found := map[string]string{}
	for _, property := range doc.Components[replacement].Properties {
		found[property.Name] = property.Value
	}
	if found["golang:module.replaces"] != "golang.org/x/net@v0.30.0" || !strings.HasPrefix(found["golang:module.sum"], "h1:") {
		t.Errorf("replacement properties = %v", found)
	}
	// The modules are sorted after the toolchain, so the bill is stable.
	for i := 2; i < len(doc.Components); i++ {
		if doc.Components[i-1].BOMRef > doc.Components[i].BOMRef {
			t.Errorf("the components are not sorted at %s", doc.Components[i].BOMRef)
		}
	}

	if len(doc.Dependencies) != 1 || doc.Dependencies[0].Ref != app.BOMRef ||
		len(doc.Dependencies[0].DependsOn) != len(doc.Components) {
		t.Fatalf("dependencies = %+v", doc.Dependencies)
	}
	if len(doc.Metadata.Tools.Components) != 1 || doc.Metadata.Tools.Components[0].Name != "flotestro-sbom" {
		t.Fatalf("tools = %+v", doc.Metadata.Tools)
	}

	// The same binary gives the same bill.
	var again bytes.Buffer
	if err := Write(&again, agent, Options{Version: "0.41.0", Supplier: "Flotestro", Timestamp: stamp, ToolVersion: "0.41.0"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), again.Bytes()) {
		t.Error("two bills of the same binary differ")
	}
}

// TestVersionComesFromTheModuleWhenTagged: a binary built from a tagged
// module carries its version, and a working-tree build carries none.
func TestVersionComesFromTheModuleWhenTagged(t *testing.T) {
	binary := Binary{Name: "x", Path: "example.com/x/cmd/x", Module: Module{Path: "example.com/x", Version: "v1.2.3"},
		Toolchain: "go1.25.0", Settings: map[string]string{}}
	var out bytes.Buffer
	if err := Write(&out, binary, Options{}); err != nil {
		t.Fatal(err)
	}
	var doc bill
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Component.Version != "1.2.3" || doc.Metadata.Component.PURL != "pkg:golang/example.com/x/cmd/x@1.2.3" {
		t.Fatalf("application = %+v", doc.Metadata.Component)
	}
	binary.Module.Version = "(devel)"
	out.Reset()
	if err := Write(&out, binary, Options{}); err != nil {
		t.Fatal(err)
	}
	// A fresh value: decoding into the bill read before would keep the
	// version of the tagged build where the new bill omits the field.
	var devel bill
	if err := json.Unmarshal(out.Bytes(), &devel); err != nil {
		t.Fatal(err)
	}
	if devel.Metadata.Component.Version != "" || devel.Metadata.Component.PURL != "pkg:golang/example.com/x/cmd/x" {
		t.Fatalf("a working-tree build got a version: %+v", devel.Metadata.Component)
	}
}

// TestRunWritesOneBillPerBinary: the command reads the fixture and writes
// <name>.cdx.json for every binary in it.
func TestRunWritesOneBillPerBinary(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"-modules", filepath.Join("testdata", "modules.txt"), "-out-dir", dir, "-version", "0.41.0"},
		strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, name := range []string{"flotestro-agent.cdx.json", "flotestro-relay.cdx.json"} {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
		if !json.Valid(content) {
			t.Fatalf("%s is not JSON", name)
		}
		if !strings.Contains(out.String(), name) {
			t.Errorf("%s was not announced: %s", name, out.String())
		}
	}
	if run([]string{"-out-dir", dir}, strings.NewReader(""), &out, &errOut) != 2 {
		t.Error("a call without an input did not fail with usage")
	}
}
