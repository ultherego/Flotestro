package adminapi

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The binding between a campaign preview and the order placed from it.
//
// The operator reads a count on the screen and approves a change on that
// many machines. Between the reading and the order the fleet moves and so
// do the operator's own rights, and the order used to resolve the fleet
// again without anybody noticing the difference. The preview now leaves a
// record of what it showed; the order names it; the creation resolves the
// fleet itself, as before, and compares the two. What differs is named -
// the selector, the scopes, the set of hosts - and the operator previews
// again.
//
// The token authorises nothing. Every permission is checked at the order,
// host by host, exactly as it was before this existed.

// campaignPreviewChecks counts what the check did with an order: matched,
// absent for an order placed without a token, and one outcome per refusal
// code. The share of orders arriving without a token is what says when the
// mode can move to enforce.
var campaignPreviewChecks = metrics.Default.NewCounter("flotestro_campaign_preview_total",
	"Campaign orders by what the preview binding decided.", "outcome", "mode")

// previewScopes describes the scopes that answered a question, one line
// per live binding. The lines are the fingerprint's material: a binding
// granted or withdrawn changes the set, and with it the hash.
//
// An expired binding is left out because it grants nothing - the same rule
// every decision goes by - so a binding that simply ran out between the
// preview and the order changes the answer and says so.
func previewScopes(principal authz.Principal, now time.Time) []string {
	lines := make([]string, 0, len(principal.Bindings))
	for _, binding := range principal.Bindings {
		if !binding.Active(now) {
			continue
		}
		lines = append(lines, string(binding.Role)+"@"+binding.Scope.Site+"/"+binding.Scope.Environment)
	}
	sort.Strings(lines)
	return lines
}

// previewBinding builds what a preview promises, or what an order has to
// match, from the same material in both places: the identity, the
// permission the fleet was narrowed by, the operation, the selector and
// the hosts that qualified.
func previewBinding(principal authz.Principal, permission authz.Permission, action opspec.ActionType,
	chosen campaigns.Selector, ready []hosts.Host, now time.Time) (campaigns.PreviewBinding, error) {
	selectorHash, err := campaigns.SelectorHash(chosen)
	if err != nil {
		return campaigns.PreviewBinding{}, err
	}
	identifiers := make([]string, 0, len(ready))
	for _, host := range ready {
		identifiers = append(identifiers, host.ID)
	}
	return campaigns.PreviewBinding{
		PrincipalID:  principal.ID,
		Principal:    principal.Subject,
		Permission:   string(permission),
		Action:       string(action),
		SelectorHash: selectorHash,
		ScopeHash:    campaigns.ScopeHash(previewScopes(principal, now)),
		SnapshotHash: campaigns.SnapshotHash(identifiers),
		TargetCount:  len(identifiers),
		ExpiresAt:    now.Add(campaigns.PreviewLifetime).UTC(),
	}, nil
}

// issuePreviewToken records what the preview showed and returns the token
// for the answer. A panel without the campaign store - there is no such
// installation, but the field is a pointer - simply issues none, and the
// order is then the unbound order it always was.
func (s *Server) issuePreviewToken(w http.ResponseWriter, r *http.Request, principal authz.Principal,
	permission authz.Permission, action opspec.ActionType, chosen campaigns.Selector,
	ready []hosts.Host) (map[string]any, bool) {
	if s.campaigns == nil {
		return nil, true
	}
	binding, err := previewBinding(principal, permission, action, chosen, ready, time.Now().UTC())
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	digest, err := binding.Digest()
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	preview, err := s.campaigns.RecordPreview(r.Context(), binding)
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return map[string]any{
		"preview_id":           preview.ID,
		"preview_digest":       digest,
		"principal_id":         binding.PrincipalID,
		"permission":           binding.Permission,
		"selector_hash":        binding.SelectorHash,
		"scope_hash":           binding.ScopeHash,
		"target_snapshot_hash": binding.SnapshotHash,
		"targets":              binding.TargetCount,
		"expires_at":           binding.ExpiresAt,
		"mode":                 string(s.previewMode),
	}, true
}

// checkPreviewToken holds an order to the preview it names.
//
// The order is refused when the token does not describe what the order
// resolved, and - under enforce - when there is no token at all. Under
// observe the same comparison runs and is counted, and the order goes
// through either way: that is how an installation learns whether its
// clients preview before they order, before the refusals start.
func (s *Server) checkPreviewToken(w http.ResponseWriter, r *http.Request, request createCampaignRequest,
	principal authz.Principal, permission authz.Permission, action opspec.ActionType,
	chosen campaigns.Selector, ready []hosts.Host, unattended bool) bool {
	mode := s.previewMode
	if mode == "" {
		mode = campaigns.PreviewPrefer
	}
	// An order nobody is watching - a schedule firing at four in the
	// morning, a retry of a campaign that already ran - has no preview
	// behind it by its nature. Requiring one would mean refusing the
	// unattended work of a correctly configured panel.
	if s.campaigns == nil || unattended {
		return true
	}
	if request.PreviewID == "" {
		campaignPreviewChecks.Inc("absent", string(mode))
		if mode != campaigns.PreviewEnforce {
			return true
		}
		problem(w, http.StatusConflict, "preview_required",
			"this panel requires a campaign to be ordered from a preview; preview the selector and order from its answer")
		return false
	}

	order, err := previewBinding(principal, permission, action, chosen, ready, time.Now().UTC())
	if err != nil {
		s.fail(w, err)
		return false
	}
	// The expiry is the preview's own, so the order's copy of the binding
	// carries the stored one: what is compared is the picture of the
	// fleet, not the clock.
	stored, err := s.campaigns.ConsumePreview(r.Context(), request.PreviewID, order, time.Now().UTC())
	if err == nil && request.PreviewDigest != "" {
		// The digest catches a token that was swapped for another the panel
		// also issued: the identifier alone says nothing about what was
		// shown with it.
		expected, digestErr := stored.PreviewBinding.Digest()
		if digestErr != nil {
			s.fail(w, digestErr)
			return false
		}
		if expected != request.PreviewDigest {
			err = &campaigns.PreviewMismatch{Code: "preview_digest_mismatch",
				Message: "the preview named by this order is not the preview it was answered with; preview again"}
		}
	}
	if err == nil {
		campaignPreviewChecks.Inc("matched", string(mode))
		return true
	}
	code := campaigns.PreviewRefusalCode(err)
	campaignPreviewChecks.Inc(code, string(mode))
	if mode == campaigns.PreviewObserve {
		// Observe records the difference and lets the order through, so an
		// installation can see what enforcing would refuse before it
		// refuses anything.
		s.log.Warn("the campaign order does not match its preview",
			"code", code, "preview_id", request.PreviewID, "principal", principal.Subject)
		return true
	}
	var mismatch *campaigns.PreviewMismatch
	if errors.As(err, &mismatch) || errors.Is(err, campaigns.ErrPreviewUnknown) ||
		errors.Is(err, campaigns.ErrPreviewConsumed) || errors.Is(err, campaigns.ErrPreviewExpired) {
		problem(w, http.StatusConflict, code, err.Error())
		return false
	}
	s.fail(w, err)
	return false
}
