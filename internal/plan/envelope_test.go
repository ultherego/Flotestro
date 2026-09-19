package plan

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func sample() Envelope {
	return Envelope{
		SchemaVersion:     SchemaVersion,
		PlannerVersion:    "packages/1",
		ActionType:        "packages.upgrade",
		HostID:            "3f2b9d1e-5c1a-4b7e-9e0d-1a2b3c4d5e6f",
		InventoryRevision: "0123456789abcdef0123456789abcdef",
		ResourceRevision:  "apt:9f86d081884c7d659a2feaa0c55ad015",
		Preconditions: []Precondition{
			{Kind: "metadata_revision", Subject: "apt", Expected: "9f86d081884c7d659a2feaa0c55ad015"},
			{Kind: "lock_free", Subject: "/var/lib/dpkg/lock-frontend", Expected: "not held"},
		},
		Steps: []Step{
			{Kind: "upgrade", Subject: "openssl", Spec: "openssl=3.0.16-1~deb12u1"},
			{Kind: "upgrade", Subject: "libssl3", Spec: "libssl3=3.0.16-1~deb12u1"},
		},
		Effects: Effects{
			Expected: []Effect{
				{Kind: EffectPackageVersion, Subject: "openssl", Value: "3.0.16-1~deb12u1"},
				{Kind: EffectPackageVersion, Subject: "libssl3", Value: "3.0.16-1~deb12u1"},
			},
			ServicesRestart: []string{},
			DownloadBytes:   3456789,
			DownloadKnown:   true,
		},
		Artifacts: []Artifact{
			{Kind: "package", Name: "openssl", Version: "3.0.16-1~deb12u1", Architecture: "amd64", Origin: "Debian-Security:12/stable-security"},
			{Kind: "package", Name: "libssl3", Version: "3.0.16-1~deb12u1", Architecture: "amd64", Origin: "Debian-Security:12/stable-security"},
		},
		Rollback:    RollbackPlan{Mechanism: "none", Available: false, Reason: "apt keeps no transaction to undo"},
		ExpiresAt:   time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC),
		Description: "2 packages will be upgraded (apt)",
	}
}

// The digest covers every field but the description: a change of the
// architecture or of the origin of one artifact is another plan, the wording
// of the description is not.
func TestHashCoversArchitectureAndOriginButNotTheDescription(t *testing.T) {
	base := sample()
	reference := base.HashHex()
	if reference == "" {
		t.Fatal("the sample cannot be hashed")
	}

	other := sample()
	other.Artifacts[0].Architecture = "i386"
	if other.HashHex() == reference {
		t.Error("a change of the architecture did not change the digest")
	}

	other = sample()
	other.Artifacts[0].Origin = "Debian:12/stable"
	if other.HashHex() == reference {
		t.Error("a change of the origin did not change the digest")
	}

	other = sample()
	other.ResourceRevision = "apt:moved"
	if other.HashHex() == reference {
		t.Error("a change of the resource revision did not change the digest")
	}

	other = sample()
	other.Description = "another wording"
	if other.HashHex() != reference {
		t.Error("the description entered the digest")
	}
	// The identity header is outside the digest: the same state on another host,
	// under another picture of it, read an hour later, is the same plan.
	other = sample()
	other.HostID = "another-host"
	other.InventoryRevision = "another-revision"
	other.ExpiresAt = other.ExpiresAt.Add(time.Hour)
	if other.HashHex() != reference {
		t.Error("the identity header entered the digest")
	}
}

// The order of the collections is not a decision of the planner, and a
// nil collection is the same plan as an empty one.
func TestHashIsIndependentOfOrderAndOfNilCollections(t *testing.T) {
	base := sample()
	shuffled := sample()
	shuffled.Artifacts[0], shuffled.Artifacts[1] = shuffled.Artifacts[1], shuffled.Artifacts[0]
	shuffled.Steps[0], shuffled.Steps[1] = shuffled.Steps[1], shuffled.Steps[0]
	shuffled.Preconditions[0], shuffled.Preconditions[1] = shuffled.Preconditions[1], shuffled.Preconditions[0]
	shuffled.Effects.Expected[0], shuffled.Effects.Expected[1] = shuffled.Effects.Expected[1], shuffled.Effects.Expected[0]
	if shuffled.HashHex() != base.HashHex() {
		t.Error("the order of the collections changed the digest")
	}
	shuffled.Effects.ServicesRestart = nil
	if shuffled.HashHex() != base.HashHex() {
		t.Error("a nil list hashed differently from an empty one")
	}
	// The canonical body keeps the header, spelled in UTC to the second.
	local := sample()
	local.ExpiresAt = local.ExpiresAt.In(time.FixedZone("east", 2*3600))
	body, err := local.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"expires_at":"2026-09-18T10:00:00Z"`) ||
		!strings.Contains(string(body), `"host_id":"3f2b9d1e-5c1a-4b7e-9e0d-1a2b3c4d5e6f"`) {
		t.Errorf("the canonical body lost the header: %s", body)
	}
}

// Verify answers the questions in order: the planner first, the expiry
// second, the content last.
func TestVerifyTellsTheRefusalsApart(t *testing.T) {
	current := sample()
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	good := Reference{Hash: current.Hash(), SchemaVersion: SchemaVersion,
		PlannerVersion: current.PlannerVersion, ExpiresAt: current.ExpiresAt}
	if err := current.Verify(good, now); err != nil {
		t.Fatalf("the same plan was refused: %v", err)
	}

	moved := good
	moved.PlannerVersion = "packages/0"
	if err := current.Verify(moved, now); !errors.Is(err, ErrReplanRequired) {
		t.Errorf("another planner version: %v, want replan_required", err)
	}
	if code, _ := CodeOf(current.Verify(moved, now)); code != ErrorReplanRequired {
		t.Errorf("code = %q", code)
	}

	if err := current.Verify(good, current.ExpiresAt.Add(time.Minute)); !errors.Is(err, ErrPlanExpired) {
		t.Errorf("past the expiry: %v, want plan_expired", err)
	}

	changed := sample()
	changed.Artifacts[1].Origin = "Debian:12/stable"
	if err := changed.Verify(good, now); !errors.Is(err, ErrStalePlan) {
		t.Errorf("another origin: %v, want stale_plan", err)
	}

	// A planner mismatch is reported as such even when the content moved too: the
	// operator is to look for a new planner, not for a change of the host.
	if err := changed.Verify(moved, now); !errors.Is(err, ErrReplanRequired) {
		t.Errorf("planner and content moved: %v, want replan_required first", err)
	}

	// No digest at all is never a match.
	if err := current.Verify(Reference{}, now); !errors.Is(err, ErrStalePlan) {
		t.Errorf("an empty reference: %v, want stale_plan", err)
	}
}

func TestSettleListsEveryEffect(t *testing.T) {
	effects := Effects{Expected: []Effect{
		{Kind: EffectPackageVersion, Subject: "openssl", Value: "3.0.16-1"},
		{Kind: EffectPackageVersion, Subject: "libssl3", Value: "3.0.16-1"},
		{Kind: EffectPackageAbsent, Subject: "old-tool"},
	}}
	achieved, missed := effects.Settle(map[string]string{
		"openssl": "3.0.16-1", "libssl3": "3.0.15-1", "old-tool": "1.0",
	})
	if len(achieved) != 1 || achieved[0].Effect.Subject != "openssl" {
		t.Errorf("achieved = %+v", achieved)
	}
	if len(missed) != 2 || missed[0].Effect.Subject != "old-tool" || missed[1].Effect.Subject != "libssl3" {
		t.Errorf("missed = %+v", missed)
	}
	if missed[1].Observed != "3.0.15-1" || missed[0].Observed != "1.0" {
		t.Errorf("the observed values are missing: %+v", missed)
	}
	err := Partial(missed)
	if !errors.Is(err, ErrEffectsPartial) {
		t.Fatalf("Partial = %v", err)
	}
	if !strings.Contains(err.Error(), "libssl3 (expected 3.0.16-1, found 3.0.15-1)") ||
		!strings.Contains(err.Error(), "old-tool (expected absent, found 1.0)") {
		t.Errorf("the message does not name the misses: %v", err)
	}
	if Partial(nil) != nil {
		t.Error("nothing missed is a partial result")
	}
}

func TestParseHash(t *testing.T) {
	if sum, err := ParseHash(""); err != nil || sum != nil {
		t.Errorf("an empty digest: %v, %v", sum, err)
	}
	if _, err := ParseHash("zz"); err == nil {
		t.Error("a non-hexadecimal digest was accepted")
	}
	if _, err := ParseHash("abcd"); err == nil {
		t.Error("a short digest was accepted")
	}
	sum, err := ParseHash(strings.ToUpper(sample().HashHex()))
	if err != nil || hex.EncodeToString(sum) != sample().HashHex() {
		t.Errorf("a valid digest: %v, %v", sum, err)
	}
}

// The vectors are the contract: the agent, the helper and the panel have to
// produce these bytes and these digests for these envelopes, and so has any
// other implementation of the scheme.
func TestEnvelopeVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("reading the vectors: %v", err)
	}
	var vectors struct {
		Envelopes []struct {
			Name      string   `json:"name"`
			Envelope  Envelope `json:"envelope"`
			Canonical string   `json:"canonical"`
			SHA256    string   `json:"sha256"`
		} `json:"envelopes"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decoding the vectors: %v", err)
	}
	if len(vectors.Envelopes) == 0 {
		t.Fatal("the vector file is empty")
	}
	for _, vector := range vectors.Envelopes {
		t.Run(vector.Name, func(t *testing.T) {
			sum, normalized, err := vector.Envelope.Sum()
			if err != nil {
				t.Fatalf("Sum: %v", err)
			}
			if string(normalized) != vector.Canonical {
				t.Errorf("canonical form:\n got %s\nwant %s", normalized, vector.Canonical)
			}
			if got := hex.EncodeToString(sum[:]); got != vector.SHA256 {
				t.Errorf("digest: got %s, want %s", got, vector.SHA256)
			}
		})
	}
}
