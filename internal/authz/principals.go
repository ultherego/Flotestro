package authz

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// The lifecycle of an identity has two ends and a way back.

// DisabledPrincipal is an identity taken off the list, with the moment it
// happened. The bindings are the ones it would hold again once enabled.
type DisabledPrincipal struct {
	Principal
	DisabledAt time.Time `json:"disabled_at"`
}

// ListDisabledPrincipals returns the identities that were disabled, the most
// recently disabled first: the one somebody is looking for is usually the one
// whose access ended last.
func (s *Store) ListDisabledPrincipals(ctx context.Context) ([]DisabledPrincipal, error) {
	const query = `
		select id, subject, display_name, kind, disabled_at
		from principals
		where disabled_at is not null
		order by disabled_at desc, subject`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	principals := []DisabledPrincipal{}
	for rows.Next() {
		var principal DisabledPrincipal
		if err := rows.Scan(&principal.ID, &principal.Subject, &principal.DisplayName,
			&principal.Kind, &principal.DisabledAt); err != nil {
			rows.Close()
			return nil, err
		}
		principals = append(principals, principal)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range principals {
		bindings, err := s.allBindingsOf(ctx, principals[i].ID)
		if err != nil {
			return nil, err
		}
		if bindings == nil {
			bindings = []Binding{}
		}
		principals[i].Bindings = bindings
	}
	return principals, nil
}

// EnablePrincipal gives a disabled identity its access back.
func (s *Store) EnablePrincipal(ctx context.Context, tx pgx.Tx, principalID string) error {
	tag, err := tx.Exec(ctx, `
		update principals set disabled_at = null, updated_at = now()
		where id = $1 and disabled_at is not null`, principalID)
	if err != nil {
		return fmt.Errorf("enabling the identity: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
