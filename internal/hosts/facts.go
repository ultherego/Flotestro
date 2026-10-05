package hosts

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// The hand-recorded facts of a host: what an operator writes about the
// machine, and what every write of one of them is conditional on.

// Facts are those facts as a writer read them. The panel's entity tag for a
// host names exactly this state, and a write carries it, so two operators who
// read one version cannot both land: the second is told the record moved
// instead of quietly dropping the first one's change.
type Facts struct {
	Owner                   string
	ManagementAddress       string
	ManagementAddressSource string
	FailureDomain           string
	Site                    string
	Environment             string
	Notes                   string
	Tags                    []string
}

// FactsOf reads the hand-recorded facts of a host as they stand.
func FactsOf(host *Host) Facts {
	tags := host.Tags
	if tags == nil {
		tags = []string{}
	}
	return Facts{
		Owner: host.Owner, ManagementAddress: host.ManagementAddress,
		ManagementAddressSource: host.ManagementAddressSource,
		FailureDomain:           host.FailureDomain, Site: host.Site,
		Environment: host.Environment, Notes: host.Notes, Tags: tags,
	}
}

// ErrChanged means the host moved between the read a write was decided on and
// the write itself: somebody else wrote it first, and this write would have
// taken their change away.
var ErrChanged = errors.New("the host changed since it was read")

// factsColumns are the text columns Facts covers, in the order args gives
// their values. The tags are the one column that is not text and are compared
// after them.
var factsColumns = []string{
	"owner", "management_address", "management_address_source",
	"failure_domain", "site", "environment", "notes",
}

// args are the values of the facts for factsUnchanged, in the order it
// compares them.
func (f Facts) args() []any {
	return []any{
		f.Owner, f.ManagementAddress, f.ManagementAddressSource,
		f.FailureDomain, f.Site, f.Environment, f.Notes, f.Tags,
	}
}

// factsUnchanged renders "the row still holds the facts that were read", with
// the values as the parameters from the number given. A null column and an
// empty value are one state here, as every reader of a host already treats
// them.
func factsUnchanged(first int) string {
	parts := make([]string, 0, len(factsColumns)+1)
	for i, column := range factsColumns {
		parts = append(parts, fmt.Sprintf("coalesce(%s, '') = $%d", column, first+i))
	}
	parts = append(parts, fmt.Sprintf("coalesce(tags, '{}') = $%d", first+len(factsColumns)))
	return "\n		   and " + strings.Join(parts, "\n		   and ")
}

// writeFacts makes one write of the hand-recorded facts, conditional on the
// facts the writer read. The comparison is part of the update rather than a
// read before it, so the window between deciding and writing is closed and
// the audit entry of the write describes the state it really started from.
func (s *Store) writeFacts(ctx context.Context, hostID string, read Facts,
	assignments string, values ...any) (*Host, error) {
	args := append([]any{hostID}, values...)
	query := `update hosts ` + assignments + ` where id = $1` + factsUnchanged(len(args)+1)
	args = append(args, read.args()...)
	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("writing the facts of the host: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, s.missingOrChanged(ctx, hostID)
	}
	return s.Get(ctx, hostID)
}

// missingOrChanged tells the two reasons a conditional write lands on no row
// apart: there is no such host, or somebody wrote it first. A write that
// refuses has to say which, because the two call for different answers.
func (s *Store) missingOrChanged(ctx context.Context, hostID string) error {
	var found bool
	err := s.pool.QueryRow(ctx, `select true from hosts where id = $1`, hostID).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return ErrChanged
}
