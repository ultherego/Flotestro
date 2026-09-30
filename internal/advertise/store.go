package advertise

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// refreshInterval is how often a replica re-reads the choice. An administrator
// confirms an address on one replica and the other has to follow; it does not
// get to go on advertising the previous one.
const refreshInterval = 30 * time.Second

// Record is the confirmed choice as it is kept. A record that is not Present is
// an installation that has confirmed nothing, which is not the same as one that
// confirmed an empty address: unknown is not zero here either.
type Record struct {
	Present     bool
	Names       []string
	Superseded  []string
	ConfirmedAt time.Time
	ConfirmedBy string
	Revision    int64
}

// Records is where the confirmed choice lives. The panel keeps it in the
// database, which is the only place every replica reads the same answer from; a
// test keeps it in memory.
type Records interface {
	Read(ctx context.Context) (Record, error)
	// Write stores the names and returns the record as it stands afterwards. The
	// names the panel was seen under before move to Superseded, and a name
	// confirmed again leaves it.
	Write(ctx context.Context, names []string, actor string) (Record, error)
}

// ErrEnvironmentInForce refuses a confirmation on an installation whose address
// is declared in the environment of the control plane. Storing a choice that
// would not take effect is worse than refusing it: the screen would show an
// address the fleet is not being told.
var ErrEnvironmentInForce = errors.New("advertised_address_from_environment")

// Store holds the address in force and answers the four questions the choice
// decides. It is the only Source a running panel has.
type Store struct {
	records Records
	log     *slog.Logger
	// baseline is what this process was started with: the environment's value,
	// the flag's, or the default.
	baseline Set
	// live is what the certificate, the enrolment door, the installation screen
	// and the CA read. It is replaced whole, so nothing sees half a change.
	live atomic.Pointer[inForce]
	// writes serialises the confirmations this replica makes, so two of them
	// cannot both compute the generation from the same value.
	writes sync.Mutex
}

// inForce is one consistent answer to all four questions.
type inForce struct {
	set        Set
	reserved   []string
	generation uint64
	record     Record
}

// NewStore takes what the process was started with. Nothing is read from the
// database yet: Load does that, and until it has, the baseline is in force.
func NewStore(records Records, log *slog.Logger, baseline Set) *Store {
	store := &Store{records: records, log: log, baseline: baseline}
	store.live.Store(&inForce{set: baseline, reserved: reservedFor(baseline, Record{}), generation: 1})
	return store
}

// NewRecords is the database side.
func NewRecords(pool *pgxpool.Pool) Records { return postgresRecords{pool: pool} }

// Load reads the confirmed choice and puts the resulting value in force. It is
// called before the panel issues its own certificate, so the first handshake
// already carries the confirmed name rather than the default.
func (s *Store) Load(ctx context.Context) error { return s.refresh(ctx, true) }

// Refresh re-reads the choice; a confirmation made on another replica arrives
// here.
func (s *Store) Refresh(ctx context.Context) error { return s.refresh(ctx, false) }

func (s *Store) refresh(ctx context.Context, first bool) error {
	record, err := s.records.Read(ctx)
	if err != nil {
		return err
	}
	s.writes.Lock()
	defer s.writes.Unlock()
	previous := s.current()
	next := s.put(record)
	switch {
	case first:
		s.log.Info("the address the agents reach this panel at",
			"advertised", next.set.String(), "source", s.sourceOf(record),
			"reserved", strings.Join(next.reserved, ","))
	case !previous.set.Equal(next.set):
		s.log.Warn("the address the agents reach this panel at was changed by an administrator; "+
			"the panel issues its own certificate again for the new names",
			"advertised", next.set.String(), "previous", previous.set.String(),
			"confirmed_by", record.ConfirmedBy)
	}
	if mismatch := s.mismatchOf(record); mismatch != "" && (first || !previous.record.Present) {
		s.log.Warn(mismatch, "environment", s.baseline.String(),
			"confirmed", strings.Join(record.Names, ","))
	}
	return nil
}

// put computes the value in force from the record and the baseline and installs
// it. The caller holds writes.
func (s *Store) put(record Record) *inForce {
	previous := s.current()
	set := s.resolve(record)
	next := &inForce{set: set, reserved: reservedFor(set, record), generation: previous.generation, record: record}
	if !previous.set.Equal(set) {
		next.generation = previous.generation + 1
	}
	s.live.Store(next)
	return next
}

// resolve settles the precedence. An environment that names something a host on
// another machine can reach is a declaration by whoever deployed this panel -
// they arranged the DNS and the firewall for that name - and it wins: an
// upgrade must not move a running fleet's rendezvous point because a row exists.
// An environment that names loopback, or nothing, is only a default, and the
// confirmed choice takes force over it.
func (s *Store) resolve(record Record) Set {
	if !s.baseline.LoopbackOnly() {
		return s.baseline
	}
	if record.Present {
		return Of(record.Names)
	}
	return s.baseline
}

// reservedFor is what a relay may not be issued a certificate for: the names in
// force, and every name this panel was seen under earlier.
//
// The previous name stays reserved. The hazard is not symmetric: a relay refused
// a name is an error an administrator reads and can act on, while a relay handed
// the panel's previous name answers in the panel's place to every agent that has
// not been reconfigured yet - and an agent certificate lives thirty days, so the
// fleet does not move off an address in an instant.
func reservedFor(set Set, record Record) []string {
	seen := map[string]bool{}
	var names []string
	add := func(list []string) {
		for _, name := range list {
			name = strings.TrimSpace(name)
			if name == "" || seen[canonical(name)] {
				continue
			}
			seen[canonical(name)] = true
			names = append(names, name)
		}
	}
	add(set.Names())
	// The confirmed names count even when the environment overrides them: this
	// panel was seen under them, whichever value is in force now.
	add(record.Names)
	add(record.Superseded)
	return names
}

func (s *Store) current() *inForce { return s.live.Load() }

// InForce is the set the fleet is being told to dial.
func (s *Store) InForce() Set { return s.current().set }

// Baseline is what the process was started with; the screen shows it as what a
// cleared choice falls back to.
func (s *Store) Baseline() Set { return s.baseline }

// EnvironmentInForce says the environment of the control plane decides this
// installation's address, so a confirmation would not take effect.
func (s *Store) EnvironmentInForce() bool { return !s.baseline.LoopbackOnly() }

// CertificateNames, LoopbackOnly, Reachable and ReservedNames are the Source:
// one read of the value in force, four answers that cannot disagree.
func (s *Store) CertificateNames() ([]string, []net.IP, uint64) {
	live := s.current()
	dnsNames, ips := live.set.CertificateNames()
	return dnsNames, ips, live.generation
}

func (s *Store) LoopbackOnly() bool { return s.current().set.LoopbackOnly() }

func (s *Store) Reachable() []string { return s.current().set.Reachable() }

func (s *Store) ReservedNames() []string {
	return append([]string(nil), s.current().reserved...)
}

// State is what the screen reads.
type State struct {
	// InForce is what the fleet is being told to dial right now.
	InForce []string `json:"in_force"`
	// Source is where that came from: "environment" for a value declared in the
	// environment of the control plane, "confirmed" for an administrator's
	// choice, "default" for the loopback the panel starts with.
	Source       string   `json:"source"`
	LoopbackOnly bool     `json:"loopback_only"`
	Reachable    []string `json:"reachable,omitempty"`
	// Reserved are the names no relay may be issued a certificate for.
	Reserved []string `json:"reserved,omitempty"`
	// Environment is what FLOTESTRO_ADVERTISE names, and EnvironmentInForce says
	// it decides. An installation that declares its address there is configured
	// declaratively and the screen says so rather than offering a choice that
	// would not take effect.
	Environment        []string `json:"environment,omitempty"`
	EnvironmentInForce bool     `json:"environment_in_force"`
	// Confirmed is the administrator's stored choice, present whether or not it
	// is what is in force.
	Confirmed   []string   `json:"confirmed,omitempty"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
	ConfirmedBy string     `json:"confirmed_by,omitempty"`
	Superseded  []string   `json:"superseded,omitempty"`
	Revision    int64      `json:"revision,omitempty"`
	// Mismatch is a sentence naming a stored choice the environment overrides.
	// Empty when there is none; a disagreement is never left silent.
	Mismatch string `json:"mismatch,omitempty"`
}

// State reports the value in force together with where it came from.
func (s *Store) State() State {
	live := s.current()
	record := live.record
	state := State{
		InForce:            live.set.Names(),
		Source:             s.sourceOf(record),
		LoopbackOnly:       live.set.LoopbackOnly(),
		Reachable:          live.set.Reachable(),
		Reserved:           append([]string(nil), live.reserved...),
		Environment:        s.baseline.Names(),
		EnvironmentInForce: s.EnvironmentInForce(),
		Mismatch:           s.mismatchOf(record),
	}
	if record.Present {
		confirmedAt := record.ConfirmedAt
		state.Confirmed, state.ConfirmedAt = record.Names, &confirmedAt
		state.ConfirmedBy, state.Superseded, state.Revision =
			record.ConfirmedBy, record.Superseded, record.Revision
	}
	return state
}

func (s *Store) sourceOf(record Record) string {
	switch {
	case s.EnvironmentInForce():
		return "environment"
	case record.Present:
		return "confirmed"
	default:
		return "default"
	}
}

// mismatchOf names a disagreement between the environment and the stored
// choice. Two answers to "where is the panel" with nothing said about it is how
// an installation ends up issuing certificates for one name and telling the
// agents another.
func (s *Store) mismatchOf(record Record) string {
	if !s.EnvironmentInForce() || !record.Present {
		return ""
	}
	if Of(record.Names).Equal(s.baseline) {
		return ""
	}
	return fmt.Sprintf("the environment of the control plane advertises %s and an administrator "+
		"confirmed %s; the environment decides, so the confirmed choice is not in force - remove "+
		"FLOTESTRO_ADVERTISE from the deployment to let the panel be set up from the screen, or "+
		"confirm the same value to end the disagreement",
		s.baseline.String(), strings.Join(record.Names, ","))
}

// Confirm stores an administrator's choice and puts it in force. It is the only
// way a network address enters the panel's certificate: a detected address is a
// proposal until it comes back through here.
func (s *Store) Confirm(ctx context.Context, set Set, actor string) (State, error) {
	if err := set.Validate(); err != nil {
		return State{}, err
	}
	if s.EnvironmentInForce() {
		return State{}, fmt.Errorf("%w: this installation declares %s in the environment of the "+
			"control plane, which decides; change it there", ErrEnvironmentInForce, s.baseline.String())
	}
	record, err := s.records.Write(ctx, set.Names(), actor)
	if err != nil {
		return State{}, err
	}
	s.writes.Lock()
	defer s.writes.Unlock()
	previous := s.current().set
	next := s.put(record)
	if !previous.Equal(next.set) {
		s.log.Warn("an administrator confirmed the address the agents reach this panel at; "+
			"the panel issues its own certificate again and every new agent configuration "+
			"names it from now on",
			"advertised", next.set.String(), "previous", previous.String(), "confirmed_by", actor,
			"reserved", strings.Join(next.reserved, ","))
	}
	return s.State(), nil
}

// Run re-reads the choice until the context ends.
func (s *Store) Run(ctx context.Context) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("the advertised address of this installation could not be re-read; "+
					"this replica goes on with the value it holds", "err", err)
			}
		}
	}
}

// The singleton row. One panel, one address it is seen under.
const (
	recordRead = `
		select names, superseded_names, confirmed_at, confirmed_by, revision
		  from advertised_address
		 where singleton`
	// The row is locked for the length of the confirmation: the names that move
	// to superseded are computed from what is there, and two administrators
	// confirming at once must not each compute them from the same value.
	recordLock  = recordRead + ` for update`
	recordWrite = `
		insert into advertised_address (singleton, names, superseded_names, confirmed_at,
		    confirmed_by, revision)
		values (true, $1, $2, now(), $3, 1)
		on conflict (singleton) do update set
		    names = excluded.names,
		    superseded_names = excluded.superseded_names,
		    confirmed_at = now(),
		    confirmed_by = excluded.confirmed_by,
		    revision = advertised_address.revision + 1
		returning names, superseded_names, confirmed_at, confirmed_by, revision`
)

type postgresRecords struct{ pool *pgxpool.Pool }

func (p postgresRecords) Read(ctx context.Context) (Record, error) {
	return scanRecord(p.pool.QueryRow(ctx, recordRead))
}

// row is what pgx returns for a single-row query, narrowed to what is used
// here so a transaction and a pool are read the same way.
type row interface {
	Scan(dest ...any) error
}

func scanRecord(r row) (Record, error) {
	var record Record
	err := r.Scan(&record.Names, &record.Superseded,
		&record.ConfirmedAt, &record.ConfirmedBy, &record.Revision)
	switch {
	case errors.Is(err, pgx.ErrNoRows), isUndefinedTable(err):
		return Record{}, nil
	case err != nil:
		return Record{}, err
	}
	record.Present = true
	sort.Strings(record.Superseded)
	return record, nil
}

func (p postgresRecords) Write(ctx context.Context, names []string, actor string) (Record, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := scanRecord(tx.QueryRow(ctx, recordLock))
	if err != nil {
		return Record{}, err
	}
	stored, err := scanRecord(tx.QueryRow(ctx, recordWrite, names,
		SupersededAfter(current, names), actor))
	if err != nil {
		return Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Record{}, err
	}
	stored.Present = true
	return stored, nil
}

// SupersededAfter is the reserved history the row carries once these names are
// in force: what it held before plus the names being replaced, minus any name
// that is being confirmed again - that one is in force and not a memory.
func SupersededAfter(current Record, names []string) []string {
	confirmed := map[string]bool{}
	for _, name := range names {
		confirmed[canonical(name)] = true
	}
	seen := map[string]bool{}
	superseded := []string{}
	for _, name := range append(append([]string(nil), current.Superseded...), current.Names...) {
		key := canonical(name)
		if key == "" || confirmed[key] || seen[key] {
			continue
		}
		seen[key] = true
		superseded = append(superseded, name)
	}
	sort.Strings(superseded)
	return superseded
}

// isUndefinedTable recognises a schema from before the table: a replica rolled
// back to the previous release has one, and that is not an error to report
// every half minute.
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}
