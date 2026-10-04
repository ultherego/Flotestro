// Command gatecheck judges a laboratory gate report, from the bundle the
// laboratory produced.
//
// It takes the bundle, not a report: a pasted report was the finding. The
// report is read out of the bundle, every log and artefact it claims a digest
// of is hashed from the bytes beside it, and the tree is compared with the one
// git holds for the commit - which the caller reads from git, not from the
// report. Then the verdict is recomputed from the evidence.
//
//	gatecheck -sha <commit> -tree <tree of that commit, from git> \
//	    [-report report.json] bundle.tar.gz
//
// Stdout is three lines: the verdict, the line a status carries, and the digest
// of the bundle the verdict was computed over. Anything else goes to stderr,
// and a refusal is a non-zero exit.
//
// -report writes the report this verdict was computed over. The caller gets it
// from here rather than reaching into the archive itself: the workflow used to
// run "tar -xzOf bundle result.json" beside this command, and the gate writes
// its archive with tar -C dir ., which names that member "./result.json". So
// the checker accepted the bundle and the step beside it exited 2 before the
// status was recorded - two parsers of one archive, disagreeing about which
// member is the report.
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
	reportTo := flag.String("report", "", "write the verified report here, for the caller that wants to show it")
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
	if *reportTo != "" {
		if err := os.WriteFile(*reportTo, evidence.ReportBytes, 0o644); err != nil {
			fail(err)
		}
	}
	fmt.Println(verdict)
	fmt.Println(evidence.Report.Summary(verdict))
	fmt.Println(evidence.Digest)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(1)
}
