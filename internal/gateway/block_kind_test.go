package gateway

import (
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	packagestore "github.com/ultherego/flotestro/internal/packages"
)

// An unclassified update is not a broken package database. An agent from
// before the field names no kind, and every block it sends is the old meaning.
func TestOnlyADatabaseBlockSaysThePackageDatabaseIsBroken(t *testing.T) {
	advisory := &agentv1.BlockedPackage{Name: "docker-ce", Kind: packagestore.BlockedAdvisory}
	database := &agentv1.BlockedPackage{Name: "libc6", Kind: packagestore.BlockedDatabase}
	older := &agentv1.BlockedPackage{Name: "libc6"}

	cases := []struct {
		name    string
		blocked []*agentv1.BlockedPackage
		broken  bool
	}{
		{"nothing blocked", nil, false},
		{"an unclassified update", []*agentv1.BlockedPackage{advisory}, false},
		{"a half-configured package", []*agentv1.BlockedPackage{database}, true},
		{"an agent that names no kind", []*agentv1.BlockedPackage{older}, true},
		{"both", []*agentv1.BlockedPackage{advisory, database}, true},
	}
	for _, test := range cases {
		result := &agentv1.TaskResult{Detail: &agentv1.TaskResult_PackagePlan{
			PackagePlan: &agentv1.PackagePlanResult{Blocked: test.blocked},
		}}
		broken, known := packageDatabaseState(result)
		if !known {
			t.Fatalf("%s: a plan result says nothing about the database", test.name)
		}
		if broken != test.broken {
			t.Errorf("%s: broken is %v, want %v", test.name, broken, test.broken)
		}
	}
}
