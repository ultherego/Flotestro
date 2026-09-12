package freeipa

import "testing"

func TestLookupIgnoresLetterCase(t *testing.T) {
	// The directory returns krbLastPwdChange one time and krblastpwdchange
	// another, depending on the response mode. Pinning to one spelling ends
	// in silently missing data rather than in an error.
	record := map[string]any{"krbLastPwdChange": []any{"20260822144537Z"}}
	if got := first(record, "krblastpwdchange"); got != "20260822144537Z" {
		t.Fatalf("read %q, expected the value despite the different spelling", got)
	}
	if got := first(record, "nonexistent"); got != "" {
		t.Fatalf("a field that does not exist returned %q", got)
	}
}

func TestStringsHandlesTheShapesOfAnswers(t *testing.T) {
	// FreeIPA returns values as lists, strings or base64 objects.
	cases := map[string]struct {
		value any
		want  int
	}{
		"list":   {[]any{"a", "b"}, 2},
		"string": {"a", 1},
		"base64": {[]any{map[string]any{"__base64__": "encoded"}}, 1},
		"empty":  {nil, 0},
		"number": {[]any{42}, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := strings_(map[string]any{"field": tc.value}, "field")
			if len(got) != tc.want {
				t.Fatalf("read %d values, expected %d", len(got), tc.want)
			}
		})
	}
}

func TestSudoRiskMarksARuleWithoutAPassword(t *testing.T) {
	// NOPASSWD removes the identity confirmation and ALL grants full root
	// rights. The document names both as critical.
	critical, reasons := sudoRisk(map[string]any{}, SudoRule{Options: []string{"!authenticate"}})
	if !critical {
		t.Fatal("a rule without password confirmation was not marked as critical")
	}
	if len(reasons) == 0 {
		t.Fatal("no description of the reason")
	}
}

func TestSudoRiskMarksTheAllCategory(t *testing.T) {
	cases := map[string]string{
		"cmdcategory":       "all commands",
		"hostcategory":      "all hosts",
		"usercategory":      "all users",
		"runasusercategory": "any user",
	}
	for field := range cases {
		t.Run(field, func(t *testing.T) {
			critical, reasons := sudoRisk(map[string]any{field: []any{"all"}}, SudoRule{})
			if !critical || len(reasons) == 0 {
				t.Fatalf("the all category in the field %s was not marked as risky", field)
			}
		})
	}
}

func TestSudoRiskDoesNotMarkAnOrdinaryRule(t *testing.T) {
	critical, reasons := sudoRisk(
		map[string]any{"cmdcategory": []any{}, "hostcategory": []any{}},
		SudoRule{Users: []string{"jkowalski"}, Commands: []string{"/usr/bin/systemctl"}},
	)
	if critical {
		t.Fatalf("an ordinary rule was marked as critical: %v", reasons)
	}
}

func TestHostGroupsFromDNs(t *testing.T) {
	// In raw mode the membership arrives as full DNs; only host groups are of
	// interest here, not roles or other objects.
	dns := []string{
		"cn=ipaservers,cn=hostgroups,cn=accounts,dc=flotestro,dc=test",
		"cn=produkcja,cn=hostgroups,cn=accounts,dc=flotestro,dc=test",
		"cn=Flotestro Connector,cn=roles,cn=accounts,dc=flotestro,dc=test",
		"an-invalid-dn",
	}
	groups := hostGroupsFromDNs(dns)
	if len(groups) != 2 {
		t.Fatalf("extracted %v, expected two host groups", groups)
	}
	if groups[0] != "ipaservers" || groups[1] != "produkcja" {
		t.Fatalf("unexpected group names: %v", groups)
	}
}

func TestAllowedMethodIsAClosedList(t *testing.T) {
	// The adapter exposes only explicitly supported commands. There is no way
	// of calling an arbitrary directory command.
	for _, method := range []string{"user_find", "group_find", "hbacrule_find", "ping"} {
		if !allowedMethod(method) {
			t.Errorf("the read command %s should be allowed", method)
		}
	}
	// Unsupported commands cover deleting objects, changing the configuration
	// of the directory itself and managing permissions. Their absence is
	// deliberate: the panel cannot delete an account or grant itself wider
	// rights.
	for _, method := range []string{
		"user_del", "group_del", "host_del", "config_mod",
		"permission_add", "privilege_add", "role_add_member",
		"hbacrule_add", "sudorule_add", "", "user_find; drop",
	} {
		if allowedMethod(method) {
			t.Errorf("the command %s should not be available through the adapter", method)
		}
	}
}

func TestSplitPrincipal(t *testing.T) {
	name, realm := splitPrincipal("flotestro/panel.flotestro.test@FLOTESTRO.TEST", "INNY")
	if name != "flotestro/panel.flotestro.test" || realm != "FLOTESTRO.TEST" {
		t.Fatalf("split into %q and %q", name, realm)
	}
	name, realm = splitPrincipal("flotestro/panel.flotestro.test", "FLOTESTRO.TEST")
	if name != "flotestro/panel.flotestro.test" || realm != "FLOTESTRO.TEST" {
		t.Fatalf("a principal without a realm gave %q and %q", name, realm)
	}
}
