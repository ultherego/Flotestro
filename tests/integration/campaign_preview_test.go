//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// The binding between a campaign preview and the order placed from it.

// previewAnswer is the part of a preview the order carries back.
type previewAnswer struct {
	Count      int    `json:"count"`
	Eligible   int    `json:"eligible"`
	PreviewID  string `json:"preview_id"`
	Digest     string `json:"preview_digest"`
	Targets    int    `json:"targets"`
	Permission string `json:"permission"`
	Mode       string `json:"mode"`
	ExpiresAt  string `json:"expires_at"`
}

// campaignRefusal is a refusal of an order, by code.
type campaignRefusal struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Title  string `json:"title"`
}

func restartPreview(t *testing.T, h *harness) previewAnswer {
	t.Helper()
	var answer previewAnswer
	h.get("/api/v1/campaigns/preview?action=unit.restart", &answer)
	if answer.Eligible == 0 {
		t.Skip("no host of the laboratory is ready for a unit restart")
	}
	return answer
}

// restartOrder is a campaign order for the whole ready fleet, named so two
// tests do not collide on one name.
func restartOrder(name string, token previewAnswer) map[string]any {
	order := map[string]any{
		"action":    "unit.restart",
		"name":      name,
		"reason":    "integration test of the preview binding",
		"payload":   map[string]any{"unit": map[string]any{"unit": "cron.service"}},
		"selector":  map[string]any{},
		"wave_size": 1,
	}
	if token.PreviewID != "" {
		order["preview_id"] = token.PreviewID
		order["preview_digest"] = token.Digest
	}
	return order
}

// TestAnOrderPlacedFromAPreviewCarriesItsTokenAndSpendsIt walks the ordinary
// path: the preview answers with a token, the order names it and is accepted,
// and the same token orders nothing a second time.
func TestAnOrderPlacedFromAPreviewCarriesItsTokenAndSpendsIt(t *testing.T) {
	h := newHarness(t)
	answer := restartPreview(t, h)
	if answer.PreviewID == "" || answer.Digest == "" {
		t.Fatalf("the preview answered without a token: %+v", answer)
	}
	if answer.Targets != answer.Eligible {
		t.Errorf("the token names %d hosts and the preview qualified %d", answer.Targets, answer.Eligible)
	}
	if answer.Permission != "unit.restart" {
		t.Errorf("the token was issued for the permission %q", answer.Permission)
	}
	if answer.ExpiresAt == "" {
		t.Error("the token does not say when it stops standing")
	}

	campaign := h.createCampaign(restartOrder("preview binding", answer))
	if campaign.ID == "" {
		t.Fatal("the campaign was not created")
	}

	// The second order names a preview that already created a campaign.
	var refusal campaignRefusal
	h.do(http.MethodPost, "/api/v1/campaigns", restartOrder("preview binding again", answer),
		&refusal, http.StatusConflict)
	if refusal.Code != "preview_consumed" {
		t.Errorf("a spent preview was refused as %q: %s", refusal.Code, refusal.Detail)
	}
}

// TestAPreviewOfOneSelectorDoesNotOrderAnother reproduces the gap itself: the
// operator reads a count for the whole fleet and the order names something
// else.
func TestAPreviewOfOneSelectorDoesNotOrderAnother(t *testing.T) {
	h := newHarness(t)
	answer := restartPreview(t, h)
	host := h.hostByFamily("debian")

	order := restartOrder("preview of another selector", answer)
	order["selector"] = map[string]any{"host_ids": []string{host.ID}}
	var refusal campaignRefusal
	h.do(http.MethodPost, "/api/v1/campaigns", order, &refusal, http.StatusConflict)
	switch refusal.Code {
	case "preview_selector_changed", "preview_targets_changed":
	default:
		t.Errorf("an order naming other hosts than the preview was refused as %q: %s",
			refusal.Code, refusal.Detail)
	}
}

// TestATokenWithAnotherFingerprintIsRefused guards the digest: the identifier
// alone says nothing about what was shown with it, so an order naming one
// preview and the fingerprint of another is refused.
func TestATokenWithAnotherFingerprintIsRefused(t *testing.T) {
	h := newHarness(t)
	answer := restartPreview(t, h)
	order := restartOrder("preview with a wrong fingerprint", answer)
	order["preview_digest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	var refusal campaignRefusal
	h.do(http.MethodPost, "/api/v1/campaigns", order, &refusal, http.StatusConflict)
	if refusal.Code != "preview_digest_mismatch" {
		t.Errorf("a swapped fingerprint was refused as %q: %s", refusal.Code, refusal.Detail)
	}
}

// TestAPreviewIsNotTransferable: a preview is taken by an identity, and
// the rights that counted the hosts are the rights that may order them.
func TestAPreviewIsNotTransferable(t *testing.T) {
	h := newHarness(t)
	operator := h.labOperator(t, "preview-operator")
	answer := restartPreview(t, operator)

	var refusal campaignRefusal
	h.do(http.MethodPost, "/api/v1/campaigns", restartOrder("somebody else's preview", answer),
		&refusal, http.StatusConflict)
	if refusal.Code != "preview_principal_mismatch" {
		t.Errorf("another operator's preview was refused as %q: %s", refusal.Code, refusal.Detail)
	}
}

// TestAPreviewOfAnotherOperationDoesNotOrderThisOne: what qualifies a host
// depends on the operation, so the eligible hosts of one are not those of
// another.
func TestAPreviewOfAnotherOperationDoesNotOrderThisOne(t *testing.T) {
	h := newHarness(t)
	var answer previewAnswer
	h.get("/api/v1/campaigns/preview?action=packages.upgrade", &answer)
	if answer.PreviewID == "" {
		t.Skip("no host is ready for a package upgrade, so there is no token to misuse")
	}

	var refusal campaignRefusal
	h.do(http.MethodPost, "/api/v1/campaigns", restartOrder("preview of another operation", answer),
		&refusal, http.StatusConflict)
	switch refusal.Code {
	case "preview_permission_mismatch", "preview_action_mismatch", "preview_targets_changed":
	default:
		t.Errorf("a preview of another operation was refused as %q: %s", refusal.Code, refusal.Detail)
	}
}

// TestAnOrderWithoutAPreviewIsStillAccepted: the rollout stands at prefer,
// where a client from before the binding keeps working and one that previews
// gets the binding.
func TestAnOrderWithoutAPreviewIsStillAccepted(t *testing.T) {
	h := newHarness(t)
	restartPreview(t, h)
	campaign := h.createCampaign(restartOrder("order without a preview", previewAnswer{}))
	if campaign.ID == "" {
		t.Fatal("an order without a token was refused under prefer")
	}
}
