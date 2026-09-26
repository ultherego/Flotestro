// contractgen writes the interface's copy of the operation catalogue from the
// registry the panel serves it from.
//
// The panel's tests used to read the Go sources with regular expressions to
// find out which operations exist - three files, three patterns, and a silent
// pass the moment any of them was written differently. The catalogue is
// generated now, and a test compares what the generator would write with what is
// on disk, so the copy cannot drift without the suite saying so.
//
//	go run ./cmd/tools/contractgen            writes web/src/generated/actions.ts
//	go run ./cmd/tools/contractgen -check     says whether the file is current
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/ultherego/flotestro/internal/contract"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Target is where the generated catalogue goes, relative to the repository root.
const Target = "web/src/generated/actions.ts"

func main() {
	check := flag.Bool("check", false, "compare the file on disk with what would be written")
	root := flag.String("root", ".", "the root of the repository")
	flag.Parse()

	wanted := Generate()
	path := filepath.Join(*root, Target)
	if *check {
		found, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "contractgen: %v\n", err)
			os.Exit(1)
		}
		if !bytes.Equal(found, wanted) {
			fmt.Fprintf(os.Stderr,
				"contractgen: %s is not what the registry says; run go run ./cmd/tools/contractgen\n", Target)
			os.Exit(1)
		}
		fmt.Println(Target + " is current")
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "contractgen: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, wanted, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "contractgen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote " + Target)
}

// entry is one name the panel may put on a control.
type entry struct {
	Action     string
	Permission string
	Mutating   bool
	Risk       string
	Lifecycle  bool
	// Campaign is the bulk mode, empty for an order that is not opened to the
	// fleet. An operation the panel can order over many hosts and has no form
	// for is one an operator can only order as raw JSON, so the interface reads
	// this to know what it owes.
	Campaign string
}

// Catalogue is every order the API serves: the typed operations and the
// lifecycle transitions, which have no adapter and no job but are ordered from
// the same screens.
func Catalogue() []entry {
	var entries []entry
	for _, action := range opspec.AllActions() {
		spec := action.Describe()
		entries = append(entries, entry{
			Action: string(action), Permission: spec.Permission,
			Mutating: spec.Mutating, Risk: string(spec.Risk),
			Campaign: string(action.CampaignMode()),
		})
	}
	for _, transition := range contract.HostLifecycleActions {
		entries = append(entries, entry{
			Action: transition.Action, Permission: string(transition.Permission),
			Mutating: true, Risk: string(opspec.RiskCritical), Lifecycle: true,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Action < entries[j].Action })
	return entries
}

// Generate renders the file. The shape is deliberately dull: a list of names and
// three maps, because whatever reads it in the interface should need no parser.
func Generate() []byte {
	entries := Catalogue()
	var out bytes.Buffer
	out.WriteString("// Written by cmd/tools/contractgen from the operation registry of the panel.\n")
	out.WriteString("// Do not edit: run go run ./cmd/tools/contractgen instead. A test compares\n")
	out.WriteString("// this file with the registry, so an order added in Go and not here fails the\n")
	out.WriteString("// suite rather than hiding a control that would never work.\n\n")

	out.WriteString("export const ACTION_TYPES = [\n")
	for _, e := range entries {
		fmt.Fprintf(&out, "  %s,\n", strconv.Quote(e.Action))
	}
	out.WriteString("] as const;\n\n")
	out.WriteString("export type ActionType = (typeof ACTION_TYPES)[number];\n\n")

	out.WriteString("/** The permission each order needs, in the scope of the host it is ordered on. */\n")
	out.WriteString("export const ACTION_PERMISSION: Record<ActionType, string> = {\n")
	for _, e := range entries {
		fmt.Fprintf(&out, "  %s: %s,\n", strconv.Quote(e.Action), strconv.Quote(e.Permission))
	}
	out.WriteString("};\n\n")

	out.WriteString("/** Whether the order changes the host, as against reading it. */\n")
	out.WriteString("export const ACTION_MUTATING: Record<ActionType, boolean> = {\n")
	for _, e := range entries {
		fmt.Fprintf(&out, "  %s: %t,\n", strconv.Quote(e.Action), e.Mutating)
	}
	out.WriteString("};\n\n")

	out.WriteString("/** low, medium, high, critical or destructive, as the registry rates it. */\n")
	out.WriteString("export const ACTION_RISK: Record<ActionType, string> = {\n")
	for _, e := range entries {
		fmt.Fprintf(&out, "  %s: %s,\n", strconv.Quote(e.Action), strconv.Quote(e.Risk))
	}
	out.WriteString("};\n\n")

	out.WriteString("/** The bulk mode of each order; the empty string for one not opened to the fleet. */\n")
	out.WriteString("export const ACTION_CAMPAIGN_MODE: Record<ActionType, string> = {\n")
	for _, e := range entries {
		fmt.Fprintf(&out, "  %s: %s,\n", strconv.Quote(e.Action), strconv.Quote(e.Campaign))
	}
	out.WriteString("};\n\n")

	out.WriteString("/** The orders that change what the panel thinks of a host rather than the host. */\n")
	out.WriteString("export const LIFECYCLE_ACTIONS: readonly ActionType[] = [\n")
	for _, e := range entries {
		if e.Lifecycle {
			fmt.Fprintf(&out, "  %s,\n", strconv.Quote(e.Action))
		}
	}
	out.WriteString("];\n")
	return out.Bytes()
}
