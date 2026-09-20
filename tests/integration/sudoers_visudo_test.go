//go:build integration

package integration

import (
	"context"
	"testing"
	"time"
)

// The site the synthetic hosts of this file live on, apart from the lab ones.
const visudoSite = "visudo-test"

// The rules every host of this file reports: the distribution's own grant to
// the sudo group, which parses cleanly and asks for a password.
const visudoCleanRules = `"rules":[{"users":["%sudo"],"hosts":["ALL"],"run_as":["ALL"],` +
	`"commands":["ALL"],"nopasswd":false,"all_users":false,"all_hosts":true,"all_commands":true,` +
	`"run_as_any_user":true,"root_equivalent":true,"critical":true,"source":"/etc/sudoers","line":24,` +
	`"text":"%sudo ALL=(ALL:ALL) ALL"}],"defaults":[],"files":[{"path":"/etc/sudoers","lines":30}]`

// TestACheckerRefusalNeverPassesTheSudoChecks holds the rule of the chapter:
// visudo -c is the syntactic proof, and a host that cannot show it fails.
func TestACheckerRefusalNeverPassesTheSudoChecks(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool := h.database(ctx)
	t.Cleanup(func() {
		// The fragments hang off the host rows and go with them.
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := pool.Exec(cleanup, "delete from hosts where site = $1", visudoSite); err != nil {
			t.Errorf("removing the synthetic hosts: %v", err)
		}
	})

	for _, host := range []struct {
		name string
		// payload is the sudoers fragment the host reports.
		payload string
		// The verdict on the proof itself, and on the policy check that rests
		// on the same files.
		syntaxUnknown bool
		syntaxPassed  bool
		syntaxReason  string
		policyPassed  bool
	}{
		{
			name: "refused",
			payload: `{` + visudoCleanRules + `,"syntax_check":{"tool":"/usr/sbin/visudo",` +
				`"available":true,"ran":true,"exit_code":1,` +
				`"output":"/etc/sudoers.d/ops:3:10: unknown defaults entry \"authenticat\""}}`,
		},
		{
			name: "accepted",
			payload: `{` + visudoCleanRules + `,"syntax_check":{"tool":"/usr/sbin/visudo",` +
				`"available":true,"ran":true,"exit_code":0,"output":"/etc/sudoers: parsed OK"}}`,
			syntaxPassed: true, policyPassed: true,
		},
		{
			name: "no checker on the host",
			payload: `{` + visudoCleanRules + `,"syntax_check":{"available":false,` +
				`"ran":false,"exit_code":0,"reason":"visudo was not found on this host"}}`,
			syntaxUnknown: true, syntaxReason: "checker_missing", policyPassed: true,
		},
		{
			// An agent of the previous release reports nothing here.
			name:          "nothing reported",
			payload:       `{` + visudoCleanRules + `}`,
			syntaxUnknown: true, syntaxReason: "fact_missing", policyPassed: true,
		},
	} {
		t.Run(host.name, func(t *testing.T) {
			id := insertVisudoHost(t, ctx, h, host.payload)
			report := securityReport(t, h, id)

			syntax := findFinding(t, report, "sudo.syntax_valid")
			if !syntax.Applicable {
				t.Fatalf("the proof does not apply to a host that reports its sudo policy: %+v", syntax)
			}
			if syntax.Passed != host.syntaxPassed || syntax.Unknown != host.syntaxUnknown {
				t.Errorf("passed=%v unknown=%v, expected %v and %v: %+v",
					syntax.Passed, syntax.Unknown, host.syntaxPassed, host.syntaxUnknown, syntax)
			}
			if syntax.ReasonCode != host.syntaxReason {
				t.Errorf("reason code = %q, expected %q", syntax.ReasonCode, host.syntaxReason)
			}
			// A refusal is a finding of its own, with a way out that names
			// the tool and not an operation the panel would run.
			if !host.syntaxPassed && !host.syntaxUnknown {
				if syntax.Remediation == nil || syntax.Remediation.Action != "" || syntax.Remediation.Note == "" {
					t.Errorf("a refused file without a note: %+v", syntax.Remediation)
				}
			}

			// The rules are the same on every host here, so the policy check
			// moves only where the files cannot be parsed at all.
			policy := findFinding(t, report, "sudo.root_nopasswd")
			if policy.Passed != host.policyPassed {
				t.Errorf("the policy check passed=%v, expected %v: %+v", policy.Passed, host.policyPassed, policy)
			}
			if !host.policyPassed && policy.ReasonCode != "parse_error" {
				t.Errorf("a policy nobody can trust was judged as %q: %+v", policy.ReasonCode, policy)
			}
		})
	}
}

// insertVisudoHost brings one synthetic host with its sudoers fragment into
// the database and returns its identifier.
func insertVisudoHost(t *testing.T, ctx context.Context, h *harness, payload string) string {
	t.Helper()
	pool := h.database(ctx)
	name := uniqueName("visudo")
	var id string
	if err := pool.QueryRow(ctx, `
		insert into hosts (id, machine_id, hostname, site, environment, os_family, os_distribution,
		                   os_version, architecture, agent_version, connection_state, lifecycle_state,
		                   enrolled_at)
		values (gen_random_uuid(), $1, $1, $2, 'test', 'debian', 'debian', '12', 'x86_64',
		        '0.56.0', 'offline', 'active', now())
		returning id`, name, visudoSite).Scan(&id); err != nil {
		t.Fatalf("inserting the synthetic host: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		insert into host_module_inventory (host_id, module, revision, source, payload, observed_at)
		values ($1::uuid, 'sudoers', $2, 'helper/sudoers', $3::jsonb, now())`,
		id, name, payload); err != nil {
		t.Fatalf("inserting the sudoers fragment: %v", err)
	}
	return id
}
