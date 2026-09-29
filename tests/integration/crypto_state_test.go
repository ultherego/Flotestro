//go:build integration

package integration

import (
	"context"
	"regexp"
	"testing"
	"time"
)

var uuidShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// TestTheInstallationHasARecordedCryptographicState checks that the panel
// started through the startup guard: the status screen shows the installation
// identifier, the active key and the issuer, and the sentinel row agrees.
func TestTheInstallationHasARecordedCryptographicState(t *testing.T) {
	h := newHarness(t)
	var status struct {
		Blocks map[string]struct {
			OK        *bool          `json:"ok"`
			Reason    string         `json:"reason"`
			Attention string         `json:"attention"`
			Facts     map[string]any `json:"facts"`
		} `json:"blocks"`
	}
	h.get("/api/v1/status", &status)
	block, ok := status.Blocks["crypto"]
	if !ok {
		t.Fatal("the status lacks the crypto block")
	}
	if block.OK == nil || !*block.OK {
		t.Fatalf("the cryptographic state is not fine: %q", block.Reason)
	}
	installationID, _ := block.Facts["installation_id"].(string)
	activeKey, _ := block.Facts["active_key_id"].(string)
	issuerID, _ := block.Facts["issuer_id"].(string)
	if !uuidShape.MatchString(installationID) {
		t.Errorf("installation_id = %q, want a UUID", installationID)
	}
	if !uuidShape.MatchString(issuerID) {
		t.Errorf("issuer_id = %q, want a UUID", issuerID)
	}
	if activeKey == "" {
		t.Error("the block names no active key")
	}
	// Either arrangement is a correct installation, and which one this is is
	// the deployment's choice; what must hold is that the block describes one
	// of them and not a mixture. A panel whose keys are rows names the key
	// encryption key they are wrapped with, and one whose keys are files names
	// none - that pair is what says the block is talking about the provider
	// this panel actually runs.
	provider, _ := block.Facts["provider"].(string)
	kekID, _ := block.Facts["kek_id"].(string)
	switch provider {
	case "local-sealed":
		if kekID != "" {
			t.Errorf("the keys are files and the block names the key encryption key %q", kekID)
		}
	case "db-sealed":
		if kekID == "" {
			t.Error("the keys are rows of the database and the block names no key encryption key")
		}
	default:
		t.Errorf("provider = %q, want local-sealed or db-sealed", provider)
	}
	if recorded, _ := block.Facts["recorded_provider"].(string); recorded != "" {
		t.Errorf("the record names the provider %q and this panel runs %q; it was not restarted after a migration",
			recorded, provider)
	}
	keys, _ := block.Facts["keys"].([]any)
	if len(keys) == 0 {
		t.Error("the block lists no keys")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db := h.database(ctx)
	var rows int
	var recordedInstallation, recordedKey, recordedIssuer string
	if err := db.QueryRow(ctx, `
		select count(*) over (), installation_id::text, active_secrets_key_id, active_agent_ca_id::text
		  from crypto_installation_state`).
		Scan(&rows, &recordedInstallation, &recordedKey, &recordedIssuer); err != nil {
		t.Fatalf("reading the sentinel row: %v", err)
	}
	if rows != 1 {
		t.Fatalf("the sentinel table holds %d rows", rows)
	}
	if recordedInstallation != installationID || recordedKey != activeKey || recordedIssuer != issuerID {
		t.Errorf("the row (%s, %s, %s) and the status (%s, %s, %s) disagree",
			recordedInstallation, recordedKey, recordedIssuer, installationID, activeKey, issuerID)
	}

	// The certificates of the fleet name their issuer by identifier: the
	// guard fills it in for the CAs it holds.
	var withoutIssuer int
	if err := db.QueryRow(ctx, `
		select count(*) from agent_certificates
		 where revoked_at is null and not_after > now() and issuer_id is null
		   and issuer_subject is not null`).Scan(&withoutIssuer); err != nil {
		t.Fatal(err)
	}
	if withoutIssuer > 0 {
		t.Errorf("%d live certificates of a known CA carry no issuer id", withoutIssuer)
	}

	// A secret written now goes into the store as an envelope under the
	// active key.
	secret := newSecret(t, h, "sealed-under-the-active-key")
	name := secret.Name
	var envelopeVersion int
	var keyID string
	var wrappedLength int
	if err := db.QueryRow(ctx, `
		select v.envelope_version, coalesce(v.key_id, ''), coalesce(length(v.wrapped_dek), 0)
		  from secret_versions v join secrets s on s.id = v.secret_id
		 where s.name = $1 and v.version = 1`, name).Scan(&envelopeVersion, &keyID, &wrappedLength); err != nil {
		t.Fatalf("reading the version row: %v", err)
	}
	if envelopeVersion != 2 || keyID != activeKey || wrappedLength == 0 {
		t.Errorf("the new version is (envelope %d, key %q, wrapped %d bytes); want envelope 2 under %s",
			envelopeVersion, keyID, wrappedLength, activeKey)
	}
	// The API shows the form of every version next to its size, so a
	// rotation can be followed without the database.
	var shown struct {
		Versions []struct {
			Version         int    `json:"version"`
			EnvelopeVersion int    `json:"envelope_version"`
			KeyID           string `json:"key_id"`
		} `json:"versions"`
	}
	h.get("/api/v1/secrets/"+name, &shown)
	if len(shown.Versions) != 1 || shown.Versions[0].EnvelopeVersion != 2 || shown.Versions[0].KeyID != activeKey {
		t.Errorf("the API shows the version as %+v", shown.Versions)
	}
}
