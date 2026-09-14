// Command sbom writes the software bill of materials of a built binary.
//
// The bill is CycloneDX 1.5 JSON with one component per Go module that
// entered the binary, named by its package URL (pkg:golang/...). The source
// is the build metadata the binary itself carries - read from the file, or
// from the text "go version -m" prints - so the bill describes exactly the
// release artefact, not the go.mod of the working tree at the time somebody
// ran the tool.
//
//	flotestro-sbom -binary <file> [-binary <file> ...] -out-dir <dir>
//	flotestro-sbom -modules <go version -m output> -out-dir <dir>
//
// Every binary gets <name>.cdx.json in the output directory.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/ultherego/flotestro/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// multiFlag collects a repeated flag.
type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint([]string(*m)) }

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func run(args []string, in io.Reader, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("flotestro-sbom", flag.ContinueOnError)
	flags.SetOutput(errOut)
	var binaries multiFlag
	flags.Var(&binaries, "binary", "a built binary to describe; may repeat")
	modules := flags.String("modules", "", `the output of "go version -m" to read instead of binaries ("-" for stdin)`)
	outDir := flags.String("out-dir", ".", "the directory the bills are written into")
	version := flags.String("version", "", "the release version of the binaries (the toolchain records (devel) for a working tree)")
	supplier := flags.String("supplier", "Flotestro", "the supplier named in the bill")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if len(binaries) == 0 && *modules == "" {
		fmt.Fprintln(errOut, "give -binary or -modules")
		flags.Usage()
		return 2
	}

	options := Options{
		Version:     *version,
		Supplier:    *supplier,
		Timestamp:   buildTime(),
		ToolVersion: buildinfo.Version,
	}

	var described []Binary
	for _, file := range binaries {
		binary, err := ReadBinary(file)
		if err != nil {
			fmt.Fprintf(errOut, "%s: %v\n", file, err)
			return 1
		}
		described = append(described, binary)
	}
	if *modules != "" {
		reader := in
		if *modules != "-" {
			file, err := os.Open(*modules)
			if err != nil {
				fmt.Fprintln(errOut, err)
				return 1
			}
			defer file.Close()
			reader = file
		}
		parsed, err := ParseModules(reader)
		if err != nil {
			fmt.Fprintf(errOut, "%s: %v\n", *modules, err)
			return 1
		}
		described = append(described, parsed...)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	for _, binary := range described {
		target, err := WriteFile(*outDir, binary, options)
		if err != nil {
			fmt.Fprintf(errOut, "%s: %v\n", binary.Name, err)
			return 1
		}
		fmt.Fprintln(out, target)
	}
	return 0
}

// buildTime is the timestamp of the bill: SOURCE_DATE_EPOCH when the
// release sets it, so that the bills of one release agree and a rebuild
// gives the same file; otherwise now.
func buildTime() time.Time {
	if epoch := os.Getenv("SOURCE_DATE_EPOCH"); epoch != "" {
		if seconds, err := strconv.ParseInt(epoch, 10, 64); err == nil {
			return time.Unix(seconds, 0).UTC()
		}
	}
	return time.Now().UTC()
}
