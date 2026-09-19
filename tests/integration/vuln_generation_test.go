//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
)

// fleetVulnerabilityAnswer is the part of the fleet screen this test reads.
type fleetVulnerabilityAnswer struct {
	Items []struct {
		HostID         string `json:"host_id"`
		Hostname       string `json:"hostname"`
		Provider       string `json:"provider"`
		SnapshotDigest string `json:"snapshot_digest"`
		GenerationID   string `json:"generation_id"`
		GenerationAt   string `json:"generation_at"`
		EvaluatedAt    string `json:"evaluated_at"`
	} `json:"items"`
	Sources []struct {
		Provider     string `json:"provider"`
		Digest       string `json:"digest"`
		Advisories   int    `json:"advisories"`
		GenerationID string `json:"generation_id"`
		GenerationAt string `json:"generation_at"`
	} `json:"sources"`
	Candidates []struct {
		ID               string `json:"id"`
		Provider         string `json:"provider"`
		Reason           string `json:"reason"`
		Advisories       int    `json:"advisories"`
		ActiveAdvisories int    `json:"active_advisories"`
	} `json:"candidates"`
}

// TestAHostVerdictNamesTheGenerationThatProducedIt guards what chapter 11 asks
// for: a verdict has to say which feed snapshot judged the host.
func TestAHostVerdictNamesTheGenerationThatProducedIt(t *testing.T) {
	h := newHarness(t)
	var fleet fleetVulnerabilityAnswer
	h.get("/api/v1/vulnerabilities?limit=100", &fleet)

	generations := map[string]string{}
	for _, source := range fleet.Sources {
		if source.GenerationID != "" {
			generations[source.Provider] = source.GenerationID
		}
	}
	if len(generations) == 0 {
		t.Skip("no feed snapshot in this fleet carries a generation yet")
	}

	judged := 0
	for _, item := range fleet.Items {
		if item.EvaluatedAt == "" || generations[item.Provider] == "" {
			// A host nobody has assessed, or one whose findings come from its own
			// repository metadata, where there is no central generation to name.
			continue
		}
		judged++
		if item.GenerationID == "" {
			t.Fatalf("the verdict of %s names no generation although %s has one",
				item.Hostname, item.Provider)
		}
		if item.GenerationAt == "" {
			t.Fatalf("the verdict of %s names a generation without saying when it was taken",
				item.Hostname)
		}
	}
	if judged == 0 {
		t.Skip("no host of this fleet is assessed against a feed with a generation")
	}

	// The same snapshot always produces the same generation.
	perSnapshot := map[string]string{}
	for _, item := range fleet.Items {
		if item.GenerationID == "" || item.SnapshotDigest == "" {
			continue
		}
		key := item.Provider + "/" + item.SnapshotDigest
		if seen, ok := perSnapshot[key]; ok && seen != item.GenerationID {
			t.Fatalf("two hosts judged against the same snapshot of %s name different generations: %s and %s",
				item.Provider, seen, item.GenerationID)
		}
		perSnapshot[key] = item.GenerationID
	}

	// The panel's own record says the same: the verdict of a host carries
	// the generation of the snapshot in force for its provider.
	ctx := context.Background()
	var mismatched int
	if err := h.database(ctx).QueryRow(ctx, `
		select count(*)
		from vuln_host_state s
		join vuln_snapshots f on f.provider = s.provider and f.active
		where s.snapshot_digest = f.digest and s.generation_id is distinct from f.generation_id`).
		Scan(&mismatched); err != nil {
		t.Fatal(err)
	}
	if mismatched > 0 {
		t.Fatalf("%d verdicts name a generation other than the one of the snapshot they were made with", mismatched)
	}
}

// TestTheSanityGateHoldsAShrunkenFetchUntilItIsAccepted guards the second half
// of chapter 11.
func TestTheSanityGateHoldsAShrunkenFetchUntilItIsAccepted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	const provider = "integration-test-feed"

	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`delete from vuln_snapshots where provider = $1`, provider); err != nil {
			t.Logf("the test feed was not cleaned up: %v", err)
		}
	})
	if _, err := pool.Exec(ctx, `delete from vuln_snapshots where provider = $1`, provider); err != nil {
		t.Fatal(err)
	}

	var inForceID, candidateID string
	if err := pool.QueryRow(ctx, `
		insert into vuln_snapshots (provider, digest, releases, advisory_count, active, checked_at)
		values ($1, 'in-force', array['trixie'], 12000, true, now())
		returning id::text`, provider).Scan(&inForceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		insert into vuln_snapshots (provider, digest, releases, advisory_count, active,
		                            checked_at, candidate_reason, candidate_at)
		values ($1, 'shrunken', array['trixie'], 900, false, now(), 'feed_shrank', now())
		returning id::text`, provider).Scan(&candidateID); err != nil {
		t.Fatal(err)
	}

	// The screen that shows the numbers is the screen that shows the fetch being
	// held back: a held-back feed is the reason those numbers have stopped
	// moving.
	var fleet fleetVulnerabilityAnswer
	h.get("/api/v1/vulnerabilities?limit=1", &fleet)
	var listed bool
	for _, candidate := range fleet.Candidates {
		if candidate.ID != candidateID {
			continue
		}
		listed = true
		if candidate.Reason != "feed_shrank" {
			t.Fatalf("the candidate carries the reason %q", candidate.Reason)
		}
		// Both counts, because that comparison is the whole decision.
		if candidate.Advisories != 900 || candidate.ActiveAdvisories != 12000 {
			t.Fatalf("the candidate does not show both counts: %+v", candidate)
		}
	}
	if !listed {
		t.Fatalf("the held-back fetch is not on the fleet screen: %+v", fleet.Candidates)
	}

	// An acceptance without a reason is not an acceptance: the trail has
	// to say what was checked.
	h.do(http.MethodPost, "/api/v1/vulnerabilities/snapshots/"+candidateID+"/accept",
		map[string]any{"reason": ""}, nil, http.StatusBadRequest)

	// A snapshot the gate never held back cannot be accepted: there is
	// nothing to decide about it.
	h.do(http.MethodPost, "/api/v1/vulnerabilities/snapshots/"+inForceID+"/accept",
		map[string]any{"reason": "the vendor retired the findings of the release"},
		nil, http.StatusConflict)

	// Until it is accepted, the fetch in force stays in force. That is the point:
	// older data that say they are older beat newer data nobody has looked at.
	var activeDigest string
	if err := pool.QueryRow(ctx,
		`select digest from vuln_snapshots where provider = $1 and active`, provider).
		Scan(&activeDigest); err != nil {
		t.Fatal(err)
	}
	if activeDigest != "in-force" {
		t.Fatalf("the held-back fetch took force by itself: the active digest is %q", activeDigest)
	}

	var accepted struct {
		Snapshot struct {
			ID              string `json:"id"`
			Digest          string `json:"digest"`
			Active          bool   `json:"active"`
			AdvisoryCount   int    `json:"advisory_count"`
			GenerationID    string `json:"generation_id"`
			CandidateReason string `json:"candidate_reason"`
		} `json:"snapshot"`
	}
	h.do(http.MethodPost, "/api/v1/vulnerabilities/snapshots/"+candidateID+"/accept",
		map[string]any{"reason": "the vendor retired the findings of the release"},
		&accepted, http.StatusOK)
	if accepted.Snapshot.ID != candidateID || !accepted.Snapshot.Active ||
		accepted.Snapshot.AdvisoryCount != 900 {
		t.Fatalf("the accepted fetch is not the one in force: %+v", accepted.Snapshot)
	}
	if accepted.Snapshot.CandidateReason != "" {
		t.Fatalf("the accepted fetch is still a candidate: %+v", accepted.Snapshot)
	}
	// A generation was assigned when the row was written, so the verdicts
	// made with it can be told from the ones made before.
	if accepted.Snapshot.GenerationID == "" {
		t.Fatalf("the accepted fetch carries no generation: %+v", accepted.Snapshot)
	}

	// Exactly one snapshot of a provider is in force, and it is the one
	// that was accepted.
	var active int
	if err := pool.QueryRow(ctx,
		`select count(*) from vuln_snapshots where provider = $1 and active`, provider).
		Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("%d snapshots of the test feed are in force", active)
	}
	if err := pool.QueryRow(ctx,
		`select digest from vuln_snapshots where provider = $1 and active`, provider).
		Scan(&activeDigest); err != nil {
		t.Fatal(err)
	}
	if activeDigest != "shrunken" {
		t.Fatalf("the accepted fetch did not take force: the active digest is %q", activeDigest)
	}

	// The decision is on the trail: it changes what the panel will say
	// about every host of that distribution.
	var trail int
	if err := pool.QueryRow(ctx, `
		select count(*) from audit_events
		where action = 'vulnerability.snapshot.accept' and target_id = $1`, candidateID).
		Scan(&trail); err != nil {
		t.Fatal(err)
	}
	if trail == 0 {
		t.Fatal("accepting a held-back fetch left no entry on the audit trail")
	}
}
