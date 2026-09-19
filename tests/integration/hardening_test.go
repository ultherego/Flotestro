//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The tests of this file check the closing of the review findings: the bounds
// an agent cannot move, the management of tokens and identities, the key
// policy of the fleet, the replacement of a certificate, and the scope of the

const hardeningReason = "integration test of the security hardening"

// TestIdentityTokensAreIssuedRevokedAndDisabled walks the life of an automated
// identity: a token issued later than the identity, revoked by its identifier,
// a role taken away by its scope, and the identity disabled with every
func TestIdentityTokensAreIssuedRevokedAndDisabled(t *testing.T) {
	h := newHarness(t)
	subject := uniqueSubject("token-life")
	first := h.createPrincipal(subject, []map[string]string{
		{"role": "viewer", "site": "lab", "environment": "test"},
		{"role": "viewer", "site": "other", "environment": "test"},
	})
	var listing struct {
		Items []struct {
			ID       string `json:"id"`
			Subject  string `json:"subject"`
			Bindings []struct {
				Role string `json:"role"`
			} `json:"bindings"`
			Tokens []struct {
				ID string `json:"id"`
			} `json:"tokens"`
		} `json:"items"`
	}
	find := func() (id string, bindings, tokens int) {
		h.get("/api/v1/principals", &listing)
		for _, item := range listing.Items {
			if item.Subject == subject {
				return item.ID, len(item.Bindings), len(item.Tokens)
			}
		}
		return "", 0, 0
	}
	id, bindings, tokens := find()
	if id == "" || bindings != 2 || tokens != 1 {
		t.Fatalf("the identity lists as %q with %d bindings and %d tokens", id, bindings, tokens)
	}

	// Another token, with the value in this answer alone.
	var problem struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/principals/"+id+"/tokens", map[string]any{}, &problem, http.StatusBadRequest)
	if problem.Code != "reason_required" {
		t.Errorf("issuing without a reason: code = %q", problem.Code)
	}
	var issued struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/principals/"+id+"/tokens", map[string]any{
		"description": "second token", "reason": hardeningReason, "token_ttl_hours": 1,
	}, &issued, http.StatusCreated)
	if issued.Token == "" || issued.ID == "" {
		t.Fatalf("the token was not issued: %+v", issued)
	}
	second := h.withToken(issued.Token)
	second.get("/api/v1/whoami", nil)
	if _, _, tokens := find(); tokens != 2 {
		t.Errorf("after the issue the identity has %d tokens, expected 2", tokens)
	}

	// Revoking the first token leaves the second working.
	firstID := ""
	for _, item := range listing.Items {
		if item.Subject == subject {
			for _, token := range item.Tokens {
				if token.ID != issued.ID {
					firstID = token.ID
				}
			}
		}
	}
	h.do(http.MethodDelete, "/api/v1/principals/"+id+"/tokens/"+firstID+
		"?reason="+url.QueryEscape(hardeningReason), nil, nil, http.StatusNoContent)
	h.withToken(first).do(http.MethodGet, "/api/v1/whoami", nil, nil, http.StatusUnauthorized)
	second.get("/api/v1/whoami", nil)
	// A token identifier of this identity revokes nothing under another.
	h.do(http.MethodDelete, "/api/v1/principals/"+uuid.NewString()+"/tokens/"+issued.ID+
		"?reason="+url.QueryEscape(hardeningReason), nil, nil, http.StatusNotFound)

	// A binding goes by role and scope: the other site keeps its role.
	h.do(http.MethodDelete, "/api/v1/principals/"+id+"/roles/viewer", map[string]any{
		"site": "other", "environment": "test", "reason": hardeningReason,
	}, nil, http.StatusNoContent)
	if _, bindings, _ := find(); bindings != 1 {
		t.Errorf("after the removal the identity has %d bindings, expected 1", bindings)
	}
	h.do(http.MethodDelete, "/api/v1/principals/"+id+"/roles/viewer", map[string]any{
		"site": "other", "environment": "test", "reason": hardeningReason,
	}, nil, http.StatusNotFound)

	// Disabling ends the remaining token and takes the identity off the
	// list; the row stays for the trail.
	h.do(http.MethodDelete, "/api/v1/principals/"+id+"?reason="+url.QueryEscape(hardeningReason),
		nil, nil, http.StatusNoContent)
	second.do(http.MethodGet, "/api/v1/whoami", nil, nil, http.StatusUnauthorized)
	if id, _, _ := find(); id != "" {
		t.Error("the disabled identity is still listed")
	}
	var trail struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?target_id="+id+"&action=principal.disable", &trail)
	if len(trail.Items) == 0 {
		t.Error("the disabling left no audit event")
	}
}

// TestAnIdentityCannotDisableItself: the last administrator locking the
// door from the outside is a recovery nobody wants.
func TestAnIdentityCannotDisableItself(t *testing.T) {
	h := newHarness(t)
	var me struct {
		Subject string `json:"subject"`
	}
	h.get("/api/v1/whoami", &me)
	var listing struct {
		Items []struct {
			ID      string `json:"id"`
			Subject string `json:"subject"`
		} `json:"items"`
	}
	h.get("/api/v1/principals", &listing)
	for _, item := range listing.Items {
		if item.Subject == me.Subject {
			h.do(http.MethodDelete, "/api/v1/principals/"+item.ID+"?reason="+url.QueryEscape(hardeningReason),
				nil, nil, http.StatusConflict)
			return
		}
	}
	t.Skip("the test identity is not on the list of principals")
}

// TestEnrollmentDoorIsThrottledPerMachine: the public endpoint answers a
// machine three times a minute, then refuses without looking at the token.
func TestEnrollmentDoorIsThrottledPerMachine(t *testing.T) {
	h := newHarness(t)
	machine := uniqueSubject("throttled-machine")
	csr := testCSR(t, machine)

	// Four knocks: the burst of three and one over it.
	statuses := make([]int, 0, 4)
	for i := 0; i < 4; i++ {
		status, _ := h.enrollAttempt(t, "flte_not-a-token", machine, csr)
		statuses = append(statuses, status)
	}
	// The refusal of a bad token and the refusal of the door differ in the
	// status alone: permission denied and too many requests.
	for i, status := range statuses[:3] {
		if status != http.StatusForbidden {
			t.Errorf("attempt %d: status %d, expected a token refusal", i+1, status)
		}
	}
	for i, status := range statuses[3:] {
		if status != http.StatusTooManyRequests {
			t.Errorf("attempt %d: status %d, expected the door to be closed", i+4, status)
		}
	}
	var trail struct {
		Items []struct {
			Detail struct {
				Reason string `json:"reason"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?actor="+machine+"&outcome=denied", &trail)
	throttled := 0
	for _, item := range trail.Items {
		if item.Detail.Reason == "rate_limited" {
			throttled++
		}
	}
	if throttled != 1 {
		t.Errorf("the throttling left %d events on the trail, expected one a minute", throttled)
	}
}

// TestEnrollmentOrderHasABoundOnUses: an order good for thousands of hosts
// is a standing door rather than an order.
func TestEnrollmentOrderHasABoundOnUses(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "too many uses", "site": "lab", "environment": "test",
		"max_uses": 501, "reason": hardeningReason,
	}, nil, http.StatusBadRequest)
}

// TestEnrollmentRefusesAWeakKey: the key is the one thing the requester
// decides, so it is the one thing the policy refuses.
func TestEnrollmentRefusesAWeakKey(t *testing.T) {
	h := newHarness(t)
	var order struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "weak key", "site": "lab", "environment": "test",
	}, &order, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+order.ID+"/revoke",
			map[string]any{"reason": hardeningReason}, nil, 0)
	})

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	machine := uniqueSubject("weak-key-machine")
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: machine}}, key)
	if err != nil {
		t.Fatal(err)
	}
	weak := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	status, body := h.enrollAttempt(t, order.Token, machine, weak)
	if status != http.StatusBadRequest {
		t.Fatalf("a 2048-bit RSA key was answered with %d: %s", status, body)
	}
	var trail struct {
		Items []struct {
			Detail struct {
				Reason string `json:"reason"`
				Error  string `json:"error"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?actor="+machine+"&outcome=failure", &trail)
	found := false
	for _, item := range trail.Items {
		if item.Detail.Reason == "invalid_csr" && len(item.Detail.Error) >= len("csr_key_policy") &&
			item.Detail.Error[:len("csr_key_policy")] == "csr_key_policy" {
			found = true
		}
	}
	if !found {
		t.Errorf("the trail does not name the key policy: %+v", trail.Items)
	}
}

// TestSupersededCertificateIsRevokedWhenTheNewOneConnects: a host has one
// identity at a time.
func TestSupersededCertificateIsRevokedWhenTheNewOneConnects(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	ctx := context.Background()
	db := h.database(ctx)

	staged := uuid.NewString()
	serial := fmt.Sprintf("staged-%d", time.Now().UnixNano())
	fingerprint := []byte(uuid.NewString())
	if _, err := db.Exec(ctx, `
		insert into agent_certificates
			(id, host_id, serial, fingerprint_sha256, subject_common_name,
			 not_before, not_after, created_at)
		values ($1, $2::uuid, $3, $4, $5,
		        now() - interval '2 days', now() + interval '20 days', now() - interval '2 days')`,
		staged, host.ID, serial, fingerprint, host.Hostname); err != nil {
		t.Fatalf("staging the older certificate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `delete from agent_certificates where id = $1::uuid`, staged)
		var state struct {
			LifecycleState string `json:"lifecycle_state"`
		}
		h.get("/api/v1/hosts/"+host.ID, &state)
		if state.LifecycleState == "quarantined" {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
				map[string]any{"reason": hardeningReason}, nil, http.StatusOK)
		}
		h.awaitConnection(host.ID, 2*time.Minute)
	})

	// The session the host holds now: the revocation happens when a new one
	// opens, so the test waits for a different session rather than for the
	// host to look connected, which it never stopped doing.
	previous, _, _ := openSession(ctx, db, host.ID)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{"reason": hardeningReason}, nil, http.StatusOK)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
		map[string]any{"reason": hardeningReason}, nil, http.StatusOK)
	awaitNewSession(ctx, t, db, host.ID, previous, 3*time.Minute)
	h.awaitConnection(host.ID, 2*time.Minute)

	var revokedReason *string
	if err := db.QueryRow(ctx, `select revocation_reason from agent_certificates where id = $1::uuid`,
		staged).Scan(&revokedReason); err != nil {
		t.Fatal(err)
	}
	if revokedReason == nil || *revokedReason != "replaced" {
		t.Fatalf("the older certificate was not revoked as replaced: %v", revokedReason)
	}
	// The certificate the host connected with is still the live one.
	var live int
	if err := db.QueryRow(ctx, `
		select count(*) from agent_certificates
		where host_id = $1::uuid and revoked_at is null and not_after > now()`, host.ID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Errorf("the host has %d live certificates after the reconnect, expected exactly one", live)
	}
}

// TestInventoryHistoryIsCapped: the revisions of a host are kept for the diff
// of the last few reports, not as an archive.
func TestInventoryHistoryIsCapped(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	ctx := context.Background()
	db := h.database(ctx)

	for i := 0; i < 30; i++ {
		if _, err := db.Exec(ctx, `
			insert into inventory_revisions
				(id, host_id, revision, is_full, schema_version, payload, observed_at, created_at)
			values ($1, $2::uuid, $3, true, 'staged', '{}'::jsonb,
			        now() - make_interval(days => 1, secs => $4), now() - make_interval(days => 1, secs => $4))`,
			uuid.NewString(), host.ID, fmt.Sprintf("staged-%d-%d", time.Now().UnixNano(), i), i); err != nil {
			t.Fatalf("staging the revisions: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `delete from inventory_revisions where host_id = $1::uuid and schema_version = 'staged'`, host.ID)
	})
	// The current revision goes, so the agent's next report is new to the
	// table; the host row still names it, and the report writes it back.
	if _, err := db.Exec(ctx, `
		delete from inventory_revisions r using hosts h
		where h.id = $1::uuid and r.host_id = h.id and r.revision = h.current_inventory_revision`,
		host.ID); err != nil {
		t.Fatal(err)
	}

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "inventory.refresh", "reason": hardeningReason,
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("refresh: state = %s, %s", job.State, lastMessage(attempts))
	}
	var count int
	if err := db.QueryRow(ctx, `select count(*) from inventory_revisions where host_id = $1::uuid`,
		host.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count > 20 {
		t.Errorf("the host keeps %d revisions after a new report, the cap is 20", count)
	}
	if count == 0 {
		t.Error("the new report was not written")
	}
	// The newest revision is the one the host row names: pruning never
	// takes the current one.
	var current, newest string
	if err := db.QueryRow(ctx, `
		select h.current_inventory_revision,
		       (select revision from inventory_revisions where host_id = h.id order by observed_at desc limit 1)
		from hosts h where h.id = $1::uuid`, host.ID).Scan(&current, &newest); err != nil {
		t.Fatal(err)
	}
	if current != newest {
		t.Errorf("the host names revision %s, the newest kept is %s", current, newest)
	}
}

// TestSecretChangesAskForAReason: a secret can land on every host, so a change
// to it is a change of the highest weight - with a reason on the trail, like
// the access rules.
func TestSecretChangesAskForAReason(t *testing.T) {
	h := newHarness(t)
	var problem struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/secrets", map[string]any{
		"name": fmt.Sprintf("integration.noreason.%d", time.Now().UnixNano()), "value": "x",
	}, &problem, http.StatusBadRequest)
	if problem.Code != "reason_required" {
		t.Errorf("creating without a reason: code = %q", problem.Code)
	}
	secret := newSecret(t, h, "value")
	h.do(http.MethodPost, "/api/v1/secrets/"+secret.Name+"/rotate",
		map[string]any{"value": "next"}, &problem, http.StatusBadRequest)
	if problem.Code != "reason_required" {
		t.Errorf("rotating without a reason: code = %q", problem.Code)
	}
	// An operator of one site has no business with a fleet-wide value.
	scoped := h.withToken(h.createPrincipal(uniqueSubject("site-admin"), []map[string]string{
		{"role": "platform_admin", "site": "lab", "environment": "test"},
	}))
	scoped.do(http.MethodPost, "/api/v1/secrets/"+secret.Name+"/rotate",
		map[string]any{"value": "next", "reason": hardeningReason}, nil, http.StatusForbidden)
}

// TestBudgetScopeFollowsTheKey: a site administrator changes the budget of
// their site and not the fleet-wide one.
func TestBudgetScopeFollowsTheKey(t *testing.T) {
	h := newHarness(t)
	// A site budget spans the environments of the site, so the binding is
	// the site's as a whole.
	scoped := h.withToken(h.createPrincipal(uniqueSubject("site-budgets"), []map[string]string{
		{"role": "platform_admin", "site": "lab"},
	}))
	scoped.do(http.MethodPut, "/api/v1/budgets/global:mutations",
		map[string]any{"capacity": 5, "note": hardeningReason}, nil, http.StatusForbidden)
	scoped.do(http.MethodPut, "/api/v1/budgets/site:other:packages",
		map[string]any{"capacity": 5, "note": hardeningReason}, nil, http.StatusForbidden)

	const key = "site:lab:integration-hardening"
	scoped.do(http.MethodPut, "/api/v1/budgets/"+key,
		map[string]any{"capacity": 5, "note": hardeningReason}, nil, http.StatusOK)
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.database(ctx).Exec(ctx, `delete from budget_limits where key = $1`, key)
	})
}

// TestAGroupWithHiddenMembersIsNotRewritten: replacing the member list of a
// group means removing the members left out, and members the caller cannot see
// they cannot mean to remove.
func TestAGroupWithHiddenMembersIsNotRewritten(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) == 0 {
		t.Skip("the test needs a host in the lab")
	}
	group := h.createGroup(map[string]any{
		"name": uniqueName("hidden-members"), "kind": "static",
		"description": hardeningReason, "host_ids": []string{lab[0].ID},
	})
	outsider := h.withToken(h.createPrincipal(uniqueSubject("group-outsider"), []map[string]string{
		{"role": "operator", "site": "other-site", "environment": "other-environment"},
	}))
	var problem struct {
		Code string `json:"code"`
	}
	outsider.do(http.MethodPut, "/api/v1/host-groups/"+group.ID+"/members",
		map[string]any{"host_ids": []string{}}, &problem, http.StatusForbidden)
	if problem.Code != "members_out_of_scope" {
		t.Errorf("code = %q, expected members_out_of_scope", problem.Code)
	}
	if got := idsOf(h.groupHosts(group.ID)); !sameIDs(got, []string{lab[0].ID}) {
		t.Errorf("the refused write changed the group to %v", got)
	}
}
