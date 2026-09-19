package campaigns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/canonical"
)

// The preview token binds an order to the picture of the fleet the operator
// approved.

// PreviewLifetime is how long a preview stands.
const PreviewLifetime = 15 * time.Minute

// PreviewMode is the stage of the rollout, in the pattern the rest of the
// panel uses: observe records, prefer checks a token that is given and allows
// an order without one, enforce requires one.
type PreviewMode string

const (
	// PreviewObserve records what the check would have decided and lets
	// every order through, including one carrying a stale token.
	PreviewObserve PreviewMode = "observe"
	// PreviewPrefer refuses an order whose token does not match, and lets an
	// order without a token through.
	PreviewPrefer PreviewMode = "prefer"
	// PreviewEnforce additionally refuses an order that carries no token.
	PreviewEnforce PreviewMode = "enforce"
)

// ParsePreviewMode reads the configured stage.
func ParsePreviewMode(value string) (PreviewMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return PreviewPrefer, nil
	case string(PreviewObserve):
		return PreviewObserve, nil
	case string(PreviewPrefer):
		return PreviewPrefer, nil
	case string(PreviewEnforce):
		return PreviewEnforce, nil
	}
	return "", fmt.Errorf("unknown preview mode %q; use observe, prefer or enforce", value)
}

// PreviewBinding is what a preview showed and an order has to match.
type PreviewBinding struct {
	// PrincipalID identifies the person or token that previewed.
	PrincipalID string
	Principal   string
	// Permission is the right the preview counted by, which is the right
	// the order asks for.
	Permission string
	Action     string
	// SelectorHash fingerprints the selector as it was resolved, after the
	// panel's own normalisation, so a preview of one selector cannot order
	// another.
	SelectorHash string
	// ScopeHash fingerprints the scopes that answered the preview. A
	// binding granted or withdrawn in the meantime changes it.
	ScopeHash string
	// SnapshotHash fingerprints the hosts the preview qualified.
	SnapshotHash string
	TargetCount  int
	ExpiresAt    time.Time
}

// Preview is a recorded preview.
type Preview struct {
	ID string
	PreviewBinding
	CreatedAt  time.Time
	ConsumedAt *time.Time
	CampaignID string
}

// Digest is the fingerprint of the whole binding, which the client carries
// back with the identifier.
func (b PreviewBinding) Digest() (string, error) {
	sum, _, err := canonical.SHA256(map[string]any{
		"principal_id":  b.PrincipalID,
		"permission":    b.Permission,
		"action":        b.Action,
		"selector_hash": b.SelectorHash,
		"scope_hash":    b.ScopeHash,
		"snapshot_hash": b.SnapshotHash,
		"target_count":  b.TargetCount,
		"expires_at":    b.ExpiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// SelectorHash fingerprints a selector.
func SelectorHash(chosen Selector) (string, error) {
	normalized := Selector{
		Site:        chosen.Site,
		Environment: chosen.Environment,
		OSFamily:    chosen.OSFamily,
		HostIDs:     sortedUnique(chosen.HostIDs),
		Expression:  chosen.Expression,
		Exclude:     sortedUnique(chosen.Exclude),
	}
	sum, _, err := canonical.SHA256(normalized)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ScopeHash fingerprints the scopes an answer was computed in.
func ScopeHash(scopes []string) string {
	return listHash(scopes)
}

// SnapshotHash fingerprints a set of hosts by identifier.
func SnapshotHash(hostIDs []string) string {
	return listHash(hostIDs)
}

func listHash(values []string) string {
	sum := sha256.New()
	for _, value := range sortedUnique(values) {
		sum.Write([]byte(value))
		sum.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

// The refusals of a preview token. Each names what changed, because
// "preview invalid" tells the operator nothing about what to do next.
var (
	// ErrPreviewUnknown means no such preview: never issued, or swept
	// after it expired.
	ErrPreviewUnknown = errors.New("this preview is not one the panel issued")
	// ErrPreviewConsumed means the preview already created a campaign. One
	// approved picture of the fleet orders one campaign.
	ErrPreviewConsumed = errors.New("this preview was already used to create a campaign")
	// ErrPreviewExpired means the preview stood too long.
	ErrPreviewExpired = errors.New("this preview is older than a preview stands; preview again")
)

// PreviewMismatch says which part of the binding differs, in the words the
// API answers with.
type PreviewMismatch struct {
	Code    string
	Message string
}

func (m *PreviewMismatch) Error() string { return m.Message }

// PreviewRefusalCode turns any refusal of a token into its API code.
func PreviewRefusalCode(err error) string {
	var mismatch *PreviewMismatch
	switch {
	case errors.As(err, &mismatch):
		return mismatch.Code
	case errors.Is(err, ErrPreviewUnknown):
		return "preview_unknown"
	case errors.Is(err, ErrPreviewConsumed):
		return "preview_consumed"
	case errors.Is(err, ErrPreviewExpired):
		return "preview_expired"
	}
	return "preview_invalid"
}

// RecordPreview stores what a preview showed and returns it with its
// identifier.
func (s *Store) RecordPreview(ctx context.Context, binding PreviewBinding) (Preview, error) {
	preview := Preview{ID: uuid.NewString(), PreviewBinding: binding}
	if err := s.pool.QueryRow(ctx, `
		insert into campaign_previews
		    (id, principal_id, principal, permission, action, selector_hash,
		     scope_hash, snapshot_hash, target_count, expires_at)
		values ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		returning created_at`,
		preview.ID, binding.PrincipalID, binding.Principal, binding.Permission, binding.Action,
		binding.SelectorHash, binding.ScopeHash, binding.SnapshotHash, binding.TargetCount,
		binding.ExpiresAt.UTC(),
	).Scan(&preview.CreatedAt); err != nil {
		return Preview{}, fmt.Errorf("recording the preview: %w", err)
	}
	return preview, nil
}

// ConsumePreview checks an order against the preview it names and marks the
// preview used.
func (s *Store) ConsumePreview(ctx context.Context, id string, order PreviewBinding, now time.Time) (Preview, error) {
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return Preview{}, err
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	var stored Preview
	stored.ID = id
	err = transaction.QueryRow(ctx, `
		select principal_id, principal, permission, action, selector_hash, scope_hash,
		       snapshot_hash, target_count, created_at, expires_at, consumed_at
		from campaign_previews
		where id = $1::uuid
		for update`, id).Scan(
		&stored.PrincipalID, &stored.Principal, &stored.Permission, &stored.Action,
		&stored.SelectorHash, &stored.ScopeHash, &stored.SnapshotHash, &stored.TargetCount,
		&stored.CreatedAt, &stored.ExpiresAt, &stored.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, ErrPreviewUnknown
	}
	if err != nil {
		return Preview{}, err
	}
	if stored.ConsumedAt != nil {
		return stored, ErrPreviewConsumed
	}
	if !stored.ExpiresAt.After(now) {
		return stored, ErrPreviewExpired
	}
	if err := stored.PreviewBinding.compare(order); err != nil {
		return stored, err
	}
	if _, err := transaction.Exec(ctx,
		`update campaign_previews set consumed_at = $2 where id = $1::uuid`, id, now.UTC()); err != nil {
		return stored, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return stored, err
	}
	consumed := now.UTC()
	stored.ConsumedAt = &consumed
	return stored, nil
}

// compare says in what way an order differs from what was previewed.
func (b PreviewBinding) compare(order PreviewBinding) error {
	switch {
	case b.PrincipalID != order.PrincipalID:
		return &PreviewMismatch{Code: "preview_principal_mismatch",
			Message: "this preview was taken by somebody else; preview the campaign yourself"}
	case b.Permission != order.Permission:
		return &PreviewMismatch{Code: "preview_permission_mismatch",
			Message: "this preview was taken for the permission " + b.Permission +
				" and the order asks for " + order.Permission + "; preview the operation you are ordering"}
	case b.Action != order.Action:
		return &PreviewMismatch{Code: "preview_action_mismatch",
			Message: "this preview was taken for the operation " + describeAction(b.Action) +
				" and the order is for " + describeAction(order.Action) + "; preview the operation you are ordering"}
	case b.SelectorHash != order.SelectorHash:
		return &PreviewMismatch{Code: "preview_selector_changed",
			Message: "the order names a different set of hosts than the preview did; preview again"}
	case b.ScopeHash != order.ScopeHash:
		return &PreviewMismatch{Code: "preview_scope_changed",
			Message: "your permissions changed after the preview, so what it counted is not what you may order; preview again"}
	case b.SnapshotHash != order.SnapshotHash || b.TargetCount != order.TargetCount:
		return &PreviewMismatch{Code: "preview_targets_changed",
			Message: fmt.Sprintf("the fleet changed after the preview: it showed %d hosts and the order resolves %d; preview again",
				b.TargetCount, order.TargetCount)}
	}
	return nil
}

func describeAction(action string) string {
	if action == "" {
		return "no operation"
	}
	return action
}

// AttachPreview names the campaign a preview created, once it exists.
func (s *Store) AttachPreview(ctx context.Context, id, campaignID string) error {
	_, err := s.pool.Exec(ctx,
		`update campaign_previews set campaign_id = $2::uuid where id = $1::uuid`, id, campaignID)
	return err
}

// SweepPreviews removes the previews that expired long enough ago to be of no
// interest to anybody.
func (s *Store) SweepPreviews(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`delete from campaign_previews where expires_at < $1`, before.UTC())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
