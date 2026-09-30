package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/oidc"
)

// The checklist over an installation that deliberately integrates with nothing.
// A panel with no identity provider and no directory is a supported shape - the
// laboratory flow is exactly that - so the steps about an integration nobody
// asked for have to be optional, which is the state the tally leaves out of the
// count. They used to be undone, which put the first-run screen permanently at
// "to do" on a panel that was finished.
func TestAnInstallationWithNoIntegrationsHasNothingUndoneAboutThem(t *testing.T) {
	server := &Server{}
	provider := server.identityProviderStep(context.Background())
	if provider.State != setupOptional {
		t.Errorf("with no identity provider the step is %q, and an installation that signs its "+
			"operators in with API tokens is not behind on it: %s", provider.State, provider.Detail)
	}
	mapping := groupMappingStep(0, false)
	if mapping.State != setupOptional {
		t.Errorf("with no identity provider the group mapping step is %q; there is no login token "+
			"for a mapping to be about: %s", mapping.State, mapping.Detail)
	}
	directory := server.directoryStep()
	if directory.State != setupOptional {
		t.Errorf("with no directory connector the step is %q: %s", directory.State, directory.Detail)
	}

	// And the tally has to agree: an optional step counts neither for nor
	// against, so a checklist made only of these is complete.
	checklist := tally([]setupStep{provider, mapping, directory})
	if checklist.Total != 0 || checklist.Next != "" || !checklist.Complete {
		t.Errorf("the steps about the integrations count %d of %d with next %q and complete=%v; "+
			"an integration nobody configured must not hold the checklist back",
			checklist.Done, checklist.Total, checklist.Next, checklist.Complete)
	}
}

// And the other half of the distinction: an issuer that is set and does not
// answer is a fault, not a choice. It must not fall into the same state as an
// installation that named no issuer at all, or a broken login would read as a
// deliberate one.
func TestAnIssuerThatIsSetAndBrokenIsNotTheSameAsNoIssuer(t *testing.T) {
	// The provider is discovered against a live endpoint - Discover fetches the
	// document - and the endpoint is then taken away, which is what an issuer
	// that has moved, been firewalled off or been misspelled looks like from here.
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/keys",
		})
	})
	endpoint := httptest.NewServer(mux)
	issuer = endpoint.URL

	provider, err := oidc.Discover(context.Background(), oidc.Config{
		IssuerURL: issuer, ClientID: "flotestro-panel",
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Close()

	server := &Server{oidc: provider}
	step := server.identityProviderStep(context.Background())
	if step.State != setupWarning {
		t.Fatalf("an issuer that is configured and does not answer reports %q; it has to stay a "+
			"fault: %s", step.State, step.Detail)
	}
	if !strings.Contains(step.Detail, "configured but did not answer") {
		t.Errorf("the detail of a provider that does not answer is %q, and it has to say what "+
			"went wrong rather than that there is no provider", step.Detail)
	}

	// The two are distinguishable, which is the property the operator reads.
	absent := (&Server{}).identityProviderStep(context.Background())
	if absent.State == step.State {
		t.Errorf("no provider and a broken provider both report %q, so the checklist cannot say "+
			"which of the two the installation is in", step.State)
	}
	if tally([]setupStep{step}).Total == 0 {
		t.Error("a configured provider that does not answer is not counted at all, so it is as " +
			"invisible in the summary as one nobody configured")
	}
}

// A mapping is still demanded of an installation that has a provider: a panel
// that signs people in and grants them nothing is the commonest way a fresh
// installation looks broken, and that case is not a choice.
func TestAProviderWithNoMappingIsStillUndone(t *testing.T) {
	step := groupMappingStep(0, true)
	if step.State != setupUndone {
		t.Errorf("with an identity provider and no mapping the step is %q; whoever signs in gets "+
			"nothing, which is a half-configuration and not a shape: %s", step.State, step.Detail)
	}
	if done := groupMappingStep(2, true); done.State != setupDone {
		t.Errorf("two mappings report %q", done.State)
	}
}

// The address the agents dial is the one step no installation may declare itself
// out of: a panel started without the setting does not know what name it is
// reached under, and not knowing is not the same as being settled. Optional would
// drop it from the count, done would claim an address nobody confirmed - so it
// has to be counted, and counted as unfinished.
func TestAPanelWithNoAdvertisedAddressSettingIsNotSettledOnOne(t *testing.T) {
	step := (&Server{}).advertisedAddressStep()
	if step.Key != "advertised_address" {
		t.Fatalf("the step is keyed %q", step.Key)
	}
	if step.State != setupWarning {
		t.Errorf("with no advertised-address setting the step is %q: %s", step.State, step.Detail)
	}
	if counted := tally([]setupStep{step}); counted.Total != 1 || counted.Done != 0 {
		t.Errorf("the step counts %d of %d; an address nobody confirmed is neither invisible "+
			"nor finished", counted.Done, counted.Total)
	}
}
