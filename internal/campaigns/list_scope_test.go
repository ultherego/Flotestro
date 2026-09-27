package campaigns

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
)

// The campaign list takes the bindings as authz holds them: a copy with three
// fields would leave the other categories empty, and an empty category reaches
// no row - the listing would come back empty even for an administrator.
func TestTheCampaignListKeepsEveryScopeCategory(t *testing.T) {
	if condition, args := scopeCondition([]authz.Scope{authz.GlobalScope}, 0); condition != "" || args != nil {
		t.Fatalf("a global scope gives %q with %v, expected no condition at all", condition, args)
	}

	condition, args := scopeCondition([]authz.Scope{authz.Placement("lab", "test")}, 0)
	if strings.Contains(condition, "false") {
		t.Errorf("a placement gives %q, which reaches no row", condition)
	}
	if !strings.Contains(condition, "h.site = $1") || !strings.Contains(condition, "h.environment = $2") {
		t.Errorf("a placement gives %q, expected the site and the environment", condition)
	}
	if len(args) != 2 || args[0] != "lab" || args[1] != "test" {
		t.Errorf("a placement gives the arguments %v, expected lab and test", args)
	}
	if condition, _ := scopeCondition(nil, 0); condition == "" {
		t.Error("no scope at all gives no condition, which would show the whole fleet")
	}
}
