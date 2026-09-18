package freeipa

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// answerList answers a search command with records and the directory's own
// statement about whether it cut the list short.
func answerList(truncated bool, records ...map[string]any) func(rpcCall) (any, *rpcError) {
	return func(rpcCall) (any, *rpcError) {
		list := make([]any, 0, len(records))
		for _, record := range records {
			list = append(list, record)
		}
		return map[string]any{"result": list, "count": len(list), "truncated": truncated}, nil
	}
}

// answerMembership answers a membership command the way the directory
// does: a count of what it completed and a list of what it did not.
func answerMembership(completed int, failures ...string) func(rpcCall) (any, *rpcError) {
	return func(rpcCall) (any, *rpcError) {
		failed := []any{}
		for _, failure := range failures {
			failed = append(failed, []any{"member", failure})
		}
		return map[string]any{
			"result":    map[string]any{},
			"completed": completed,
			"failed":    map[string]any{"member": map[string]any{"permission": failed}},
		}, nil
	}
}

// accessDenied is the directory refusing a change to the connector's own
// account: the class it uses for an ACI that does not allow the operation.
func accessDenied(message string) func(rpcCall) (any, *rpcError) {
	return func(rpcCall) (any, *rpcError) {
		return nil, &rpcError{Code: 4204, Name: "ACIError", Message: message}
	}
}

// readableDirectory answers the reads the preflight makes, so that a test
// about the provisioning does not fail on the verification that follows it.
// The rights say the move is allowed: that is what the provisioning is for.
func readableDirectory(fake *fakeDirectory, entryRights string) {
	fake.answers["dnszone_find"] = answerList(false)
	fake.answers["user_find"] = answerList(false, map[string]any{"uid": []any{"jane"}})
	fake.answers["user_show"] = answerWith(map[string]any{
		"uid":                  []any{"jane"},
		"entrylevelrights":     []any{entryRights},
		"attributelevelrights": map[string]any{"nsaccountlock": "rscwo"},
	})
}

func outcomes(report ProvisioningReport) []string {
	result := make([]string, 0, len(report.Steps))
	for _, step := range report.Steps {
		result = append(result, step.Outcome)
	}
	return result
}

// The provisioning binds the connector's own account to the permission the
// directory already publishes, through a privilege and a role of the
// panel's own, and says what it created.
func TestTheProvisioningCreatesWhatIsMissingAndNamesIt(t *testing.T) {
	fake, client := newFakeDirectory(t)
	readableDirectory(fake, "vadn")
	fake.answers["permission_show"] = answerWith(map[string]any{"cn": []any{PreservePermission}})
	fake.answers["privilege_show"] = notFound
	fake.answers["role_show"] = notFound
	fake.answers["privilege_add_permission"] = answerMembership(1)
	fake.answers["role_add_privilege"] = answerMembership(1)
	fake.answers["role_add_member"] = answerMembership(1)

	report, err := client.ProvisionPreserveRights(context.Background())
	if err != nil {
		t.Fatalf("the provisioning: %v", err)
	}

	wanted := []string{"permission_show", "privilege_show", "privilege_add",
		"privilege_add_permission", "role_show", "role_add", "role_add_privilege", "role_add_member"}
	if got := fake.methods(); len(got) < len(wanted) || !slices.Equal(got[:len(wanted)], wanted) {
		t.Fatalf("the provisioning sent %v", got)
	}
	if got := outcomes(report); !slices.Equal(got, []string{
		ProvisionAlreadyPresent, ProvisionCreated, ProvisionCreated,
		ProvisionCreated, ProvisionCreated, ProvisionCreated}) {
		t.Fatalf("the steps read %v", got)
	}
	if !report.Changed || !report.Complete || !report.Verified {
		t.Fatalf("the report reads changed=%v complete=%v verified=%v",
			report.Changed, report.Complete, report.Verified)
	}
	if len(report.OperatorActions) != 0 {
		t.Fatalf("a run that did the work itself asked an operator for %v", report.OperatorActions)
	}

	// The permission is the directory's own and is never created or
	// widened here: the step only reads it.
	for _, method := range fake.methods() {
		if strings.HasPrefix(method, "permission_") && method != "permission_show" {
			t.Fatalf("the provisioning sent %s; it may only read a permission", method)
		}
	}

	// The role holds the connector's account under the name the directory
	// knows it by: a principal with a host in it is a service.
	call, _ := fake.find("role_add_member")
	if got := optionStrings(call, "service"); len(got) != 1 || got[0] != "flotestro/panel@TEST" {
		t.Fatalf("the role took the member %v", call.Options)
	}
}

// Running the step again is the point of it: everything is read before it
// is written, the directory's own "already a member" is the wanted state,
// and the report says nothing changed.
func TestASecondRunOfTheProvisioningChangesNothingAndSaysSo(t *testing.T) {
	fake, client := newFakeDirectory(t)
	readableDirectory(fake, "vadn")
	fake.answers["permission_show"] = answerWith(map[string]any{"cn": []any{PreservePermission}})
	fake.answers["privilege_show"] = answerWith(map[string]any{"cn": []any{PreservePrivilege}})
	fake.answers["role_show"] = answerWith(map[string]any{"cn": []any{PreserveRole}})
	already := answerMembership(0, "This entry is already a member")
	fake.answers["privilege_add_permission"] = already
	fake.answers["role_add_privilege"] = already
	fake.answers["role_add_member"] = already

	report, err := client.ProvisionPreserveRights(context.Background())
	if err != nil {
		t.Fatalf("the second run: %v", err)
	}
	if report.Changed {
		t.Fatal("a second run reported a change")
	}
	if !report.Complete || !report.Verified {
		t.Fatalf("a second run reads complete=%v verified=%v", report.Complete, report.Verified)
	}
	for _, step := range report.Steps {
		if step.Outcome != ProvisionAlreadyPresent {
			t.Errorf("the step %q reads %s on a second run", step.Object, step.Outcome)
		}
	}
	for _, method := range []string{"privilege_add", "role_add"} {
		if fake.count(method) != 0 {
			t.Errorf("a second run sent %s although the object was there", method)
		}
	}
	if !strings.Contains(report.Summary(), "0 created") {
		t.Errorf("the summary of a second run reads %q", report.Summary())
	}
}

// A connector that may not create the objects itself says so, hands the
// operator the exact commands, and stops instead of carrying on into
// refusals that would all say the same thing.
func TestTheProvisioningReportsWhatItMayNotDoItself(t *testing.T) {
	fake, client := newFakeDirectory(t)
	readableDirectory(fake, "vad")
	fake.answers["permission_show"] = answerWith(map[string]any{"cn": []any{PreservePermission}})
	fake.answers["privilege_show"] = notFound
	fake.answers["privilege_add"] = accessDenied(
		"Insufficient access: Insufficient 'add' privilege to add the entry 'cn=Flotestro Preserve Users,cn=privileges,cn=pbac,dc=test'.")

	report, err := client.ProvisionPreserveRights(context.Background())
	if err != nil {
		t.Fatalf("a refused provisioning came back as an error: %v", err)
	}
	if report.Complete || report.Changed {
		t.Fatalf("a refused provisioning reads complete=%v changed=%v", report.Complete, report.Changed)
	}
	last := report.Steps[len(report.Steps)-1]
	if last.Outcome != ProvisionNotPermitted || !strings.Contains(last.Detail, "Insufficient access") {
		t.Fatalf("the refused step reads %+v", last)
	}
	if fake.count("role_show") != 0 {
		t.Error("the step carried on after the directory refused the privilege")
	}
	wanted := `ipa privilege-add "` + PreservePrivilege + `" --desc="` + privilegeDescription + `"`
	if !slices.Contains(report.OperatorActions, wanted) {
		t.Fatalf("the report does not name the command to run: %v", report.OperatorActions)
	}
	if !strings.Contains(strings.Join(report.OperatorActions, "\n"), "directory administrator") {
		t.Errorf("the report does not say who runs them: %v", report.OperatorActions)
	}
}

// A directory that does not publish the permission at all cannot be given
// one through the API: a permission has no moddn right. The step says so
// and writes out the ACI an administrator adds instead.
func TestADirectoryWithoutThePermissionGetsTheACIAnAdministratorAdds(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["permission_show"] = notFound

	report, err := client.ProvisionPreserveRights(context.Background())
	if err != nil {
		t.Fatalf("the provisioning: %v", err)
	}
	if len(report.Steps) != 1 || report.Steps[0].Outcome != ProvisionMissing {
		t.Fatalf("the report reads %+v", report.Steps)
	}
	if report.Complete || report.Changed {
		t.Fatal("a directory without the permission read as provisioned")
	}
	if fake.count("privilege_show") != 0 || fake.count("privilege_add") != 0 {
		t.Error("the step tried to bind to a permission that is not there")
	}
	instruction := strings.Join(report.OperatorActions, "\n")
	for _, part := range []string{"moddn",
		"cn=deleted users,cn=accounts,cn=provisioning,dc=test",
		"krbprincipalname=flotestro/panel@TEST,cn=services,cn=accounts,dc=test"} {
		if !strings.Contains(instruction, part) {
			t.Errorf("the ACI does not name %q: %s", part, instruction)
		}
	}
}

// The commands that change the directory's own configuration are not part
// of any ordinary operation: the closed list does not hold them, and the
// provisioning door takes nothing else.
func TestTheProvisioningCommandsAreOutOfReachOfAnOrdinaryOperation(t *testing.T) {
	fake, client := newFakeDirectory(t)
	for method := range provisioningMethods {
		if allowedMethod(method) {
			t.Errorf("the configuration command %s entered the closed list of operations", method)
		}
		if _, err := client.call(context.Background(), method, []string{"x"}, nil); err == nil ||
			!strings.Contains(err.Error(), "not supported") {
			t.Errorf("an ordinary call of %s was not refused: %v", method, err)
		}
	}
	// The other way round: the provisioning door is not a way past the
	// closed list either.
	_, err := client.provision(context.Background(), "user_del", []string{"jane"},
		map[string]any{"preserve": true})
	if err == nil || !strings.Contains(err.Error(), "not a provisioning command") {
		t.Fatalf("the provisioning door took a user command: %v", err)
	}
	// Nothing that widens an existing permission or removes anything is
	// reachable at all.
	for _, method := range []string{"permission_add", "permission_mod", "permission_del",
		"privilege_del", "role_del", "aci_mod", "config_mod"} {
		if provisioningMethods[method] {
			t.Errorf("the provisioning may run %s; it may only bind to what the directory publishes", method)
		}
	}
	if len(fake.methods()) != 0 {
		t.Fatalf("a refused command reached the directory: %v", fake.methods())
	}
}
