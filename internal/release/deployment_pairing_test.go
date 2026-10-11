package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The three volume names are fixed and carry no project prefix, so a second
// deployment reaches the same data however it is named: -p separates
// containers and not volumes.
//
// Measured on 11.10, with a copy of compose.yaml in a second directory: the
// init step ran over the shared secrets, a second PostgreSQL started on the
// live data directory, the migrations ran, and the only thing that stopped
// the control plane was a port that happened to be taken. The first
// PostgreSQL then shut itself down - "data directory lock file is invalid",
// which is its defence against corruption and is also an outage of a running
// installation.
//
// So the init step refuses first, before the secrets, the migrations and the
// database. This reads both compose files for the pieces that refusal is made
// of, because every one of them is a line away from being deleted and the
// deletion would look like a tidy-up.
func TestBothComposeFilesRefuseASecondDeploymentOnTheSameVolumes(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, name := range []string{"compose.yaml", "compose.podman.yaml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, "docker", name))
			if err != nil {
				t.Fatalf("reading %s: %v", name, err)
			}
			text := string(raw)

			for _, piece := range []struct{ what, why string }{
				{
					what: "- ./deployment:/deployment",
					why: "without the deployment's half of the pairing mounted, the check " +
						"has nothing to compare and a copied compose.yaml starts",
				},
				{
					what: "/run/flotestro/deployment.id",
					why:  "the volumes' half of the pairing",
				},
				{
					what: "REFUSING TO START: these volumes already belong to another deployment.",
					why:  "the refusal a copied compose.yaml in a fresh directory earns",
				},
				{
					what: "REFUSING TO START: this directory and these volumes name different deployments.",
					why:  "the refusal when both halves exist and disagree",
				},
				{
					// Broken across two echo lines in the file, so the test
					// matches the half that carries the instruction.
					what: "three name: entries, then start it again.",
					why: "the refusal has to say how to make a separate installation, " +
						"or the operator's next move is to delete the check",
				},
				{
					what: "FLOTESTRO_GATEWAY_ID",
					why: "a second replica is a different thing from a second deployment, " +
						"and the refusal has to send the operator to the right one",
				},
			} {
				if !strings.Contains(text, piece.what) {
					t.Errorf("%s does not carry %q: %s", name, piece.what, piece.why)
				}
			}

			// The check has to come before the work it is protecting. Reading
			// the order rather than trusting it: a refusal that runs after the
			// secrets have been written is not a refusal.
			refusal := strings.Index(text, "REFUSING TO START: these volumes")
			for _, after := range []struct{ marker, what string }{
				{"/run/flotestro/database-url", "the DSN and the password of the secrets volume"},
				{"/import/", "the files copied out of ./secrets"},
			} {
				at := strings.Index(text, after.marker)
				if at >= 0 && at < refusal {
					t.Errorf("%s touches %s before it refuses; the refusal has to come first",
						name, after.what)
				}
			}
		})
	}
}
