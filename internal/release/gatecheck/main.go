// Command gatecheck judges a laboratory gate report, from the bundle the
// laboratory produced.
//
// It takes the bundle, not a report: a pasted report was the finding. The
// report is read out of the bundle, every log and artefact it claims a digest
// of is hashed from the bytes beside it, and the tree is compared with the one
// git holds for the commit - which the caller reads from git, not from the
// report. Then the verdict is recomputed from the evidence.
//
//	gatecheck -sha <commit> -tree <tree of that commit, from git> bundle.tar.gz
//
// Stdout is three lines: the verdict, the line a status carries, and the digest
// of the bundle the verdict was computed over. Anything else goes to stderr,
// and a refusal is a non-zero exit.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ultherego/flotestro/internal/release"
)

func main() {
	sha := flag.String("sha", "", "the commit the evidence has to be about")
	tree := flag.String("tree", "", "the tree of that commit as git holds it")
	flag.Parse()

	if *sha == "" || *tree == "" {
		fail(fmt.Errorf("both -sha and -tree are required: the tree has to come from git, not from the report"))
	}
	path := flag.Arg(0)
	if path == "" {
		fail(fmt.Errorf("name the evidence bundle the laboratory produced"))
	}
	bundle, err := os.Open(path)
	if err != nil {
		fail(err)
	}
	defer bundle.Close()

	evidence, verdict, reasons, err := release.CheckGateEvidence(bundle, *sha, *tree)
	if err != nil {
		fail(err)
	}
	for _, reason := range reasons {
		fmt.Fprintf(os.Stderr, "  - %s\n", reason)
	}
	fmt.Fprintf(os.Stderr, "%d files in the bundle hash to the digests the report claims\n", evidence.Verified)
	fmt.Println(verdict)
	fmt.Println(evidence.Report.Summary(verdict))
	fmt.Println(evidence.Digest)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(1)
}
