package compose

import (
	"context"
	"testing"
	"time"
)

// A registry that does not answer must not hold the whole operation: the
// digest the host already has is the better answer, and the operation says
// which source it came from. Before this, the ask ran until the operation's
// own deadline - fifteen minutes - and the fall-back beside it was never
// reached.
func TestARegistryThatDoesNotAnswerFallsBackToTheHost(t *testing.T) {
	const local = `["nginx@sha256:1111111111111111111111111111111111111111111111111111111111111111"]`
	previous := registryDeadline
	registryDeadline = 50 * time.Millisecond
	defer func() { registryDeadline = previous }()

	var asked []string
	runner := func(ctx context.Context, args ...string) (string, string, error) {
		asked = append(asked, args[0])
		if args[0] == "manifest" {
			// The registry is not answering: wait for the caller to give up.
			<-ctx.Done()
			return "", "", ctx.Err()
		}
		return local, "", nil
	}

	resolved, err := ResolveWithDocker(runner)(context.Background(), "nginx:alpine")
	if err != nil {
		t.Fatalf("the resolution failed instead of falling back: %v", err)
	}
	if resolved.Source != DigestFromLocal {
		t.Errorf("the digest came from %q, expected the host's own copy", resolved.Source)
	}
	if len(asked) != 2 || asked[1] != "image" {
		t.Errorf("the host was not asked for its own copy: %v", asked)
	}
}
