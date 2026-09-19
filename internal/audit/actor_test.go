package audit

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeTables answers the lookups the snapshot makes from fixed rows, so the
// resolution is tested without a database: which table an identifier is looked
// up in, and what is kept when the row is not there.
type fakeTables struct {
	principals map[string][3]string // subject -> id, display name, kind
	hosts      map[string][2]string // id -> hostname, address
	relaysByID map[string]string    // id -> name
	relayNames map[string]string    // name -> id
	campaigns  map[string]string    // id -> name
	queries    []string
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, value := range r.values {
		switch target := dest[i].(type) {
		case *string:
			*target = value.(string)
		}
	}
	return nil
}

func (f *fakeTables) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (f *fakeTables) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	key, _ := args[0].(string)
	// The query is remembered with its argument, so a test can say which
	// identifier was looked up where.
	f.queries = append(f.queries, sql+" -- "+key)
	switch {
	case strings.Contains(sql, "from principals"):
		if row, ok := f.principals[key]; ok {
			return fakeRow{values: []any{row[0], row[1], row[2]}}
		}
	case strings.Contains(sql, "from hosts"):
		if row, ok := f.hosts[key]; ok {
			return fakeRow{values: []any{row[0], row[1]}}
		}
	case strings.Contains(sql, "from relays where id"):
		if name, ok := f.relaysByID[key]; ok {
			return fakeRow{values: []any{name}}
		}
	case strings.Contains(sql, "from relays where name"):
		if id, ok := f.relayNames[key]; ok {
			return fakeRow{values: []any{id}}
		}
	case strings.Contains(sql, "from campaigns"):
		if name, ok := f.campaigns[key]; ok {
			return fakeRow{values: []any{name}}
		}
	}
	return fakeRow{err: pgx.ErrNoRows}
}

func testRecorder() *Recorder {
	return &Recorder{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

const (
	hostID    = "377802f9-a0e9-4afa-ad68-293a0873bcf3"
	relayID   = "9b6c1a2e-1f3d-4c5b-8a7e-2d4f6a8c0e1b"
	machineID = "2cd1131243654fe6b49ee4d704ea2c5a"
)

func tables() *fakeTables {
	return &fakeTables{
		principals: map[string][3]string{
			"alice": {"6f1d2c3b-4a5e-4f60-8b71-9c8d7e6f5a4b", "Alice Kowalska", "user"},
			"ci":    {"0a1b2c3d-4e5f-4a6b-8c7d-9e8f7a6b5c4d", "CI pipeline", "service"},
		},
		hosts:      map[string][2]string{hostID: {"agent-arch", "192.168.56.60"}},
		relaysByID: map[string]string{relayID: "relay-warsaw"},
		relayNames: map[string]string{"relay-warsaw": relayID},
		campaigns:  map[string]string{"b9aa09ed-534f-48d5-89fb-12750d0560b6": "kernel rollout"},
	}
}

// The identity the request authenticated is what the trail keeps: its
// immutable identifier, its name and its kind at that moment, plus the
// credential the request came with - without a read of the tables.
func TestTheRequestsOwnIdentityIsSnapshottedWithoutALookup(t *testing.T) {
	db := tables()
	ctx := WithActor(context.Background(), Actor{
		PrincipalID: "6f1d2c3b-4a5e-4f60-8b71-9c8d7e6f5a4b", Subject: "alice",
		DisplayName: "Alice Kowalska", Kind: "user",
		CredentialID: "c0ffee00-0000-4000-8000-000000000001",
	})
	got := testRecorder().actorSnapshot(ctx, db, requestFromContext(ctx),
		Event{ActorType: ActorUser, ActorID: "alice"})
	want := ActorSnapshot{
		PrincipalID: "6f1d2c3b-4a5e-4f60-8b71-9c8d7e6f5a4b", Subject: "alice",
		DisplayName: "Alice Kowalska", Kind: ActorKindUser,
		CredentialID: "c0ffee00-0000-4000-8000-000000000001",
	}
	if got != want {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
	if len(db.queries) != 0 {
		t.Fatalf("the request's own identity was looked up: %v", db.queries)
	}
}

// An event written away from the request that authenticated the actor - a
// worker carrying out an earlier order - resolves the identity by its subject,
// once per request, and carries no credential: the worker holds none.
func TestAnIdentityIsResolvedBySubjectOncePerRequest(t *testing.T) {
	db := tables()
	ctx := WithActor(context.Background(), Actor{RequestID: "r1"})
	recorder := testRecorder()
	for i := 0; i < 3; i++ {
		got := recorder.actorSnapshot(ctx, db, requestFromContext(ctx),
			Event{ActorType: ActorUser, ActorID: "ci"})
		want := ActorSnapshot{
			PrincipalID: "0a1b2c3d-4e5f-4a6b-8c7d-9e8f7a6b5c4d", Subject: "ci",
			DisplayName: "CI pipeline", Kind: ActorKindService,
		}
		if got != want {
			t.Fatalf("snapshot = %+v, want %+v", got, want)
		}
	}
	if len(db.queries) != 1 {
		t.Fatalf("the identity was read %d times under one request", len(db.queries))
	}

	// An identity the panel no longer has keeps its subject and its kind:
	// the trail says who acted even when the row is gone.
	got := recorder.actorSnapshot(context.Background(), db, nil,
		Event{ActorType: ActorUser, ActorID: "removed-operator"})
	if got != (ActorSnapshot{Subject: "removed-operator", Kind: ActorKindUser}) {
		t.Fatalf("a removed identity reads as %+v", got)
	}
	anonymous := recorder.actorSnapshot(context.Background(), db, nil,
		Event{ActorType: ActorUser, ActorID: "anonymous"})
	if anonymous != (ActorSnapshot{Subject: "anonymous", Kind: ActorKindAnonymous}) {
		t.Fatalf("an anonymous request reads as %+v", anonymous)
	}
}

// What acts as an agent is told apart by the spelling and the tables: a dashed
// identifier is a host or a relay, a bare name is a relay at its enrollment,
// and thirty-two hex digits are a machine - which is a row of nothing and must
func TestAnAgentActorNamesItsHostRelayOrMachine(t *testing.T) {
	db := tables()
	recorder := testRecorder()
	resolve := func(id string) ActorSnapshot {
		return recorder.actorSnapshot(context.Background(), db, nil, Event{ActorType: ActorAgent, ActorID: id})
	}
	cases := []struct {
		id   string
		want ActorSnapshot
	}{
		{hostID, ActorSnapshot{Subject: hostID, Kind: ActorKindAgent,
			ResourceType: "host", ResourceID: hostID, ResourceName: "agent-arch"}},
		{relayID, ActorSnapshot{Subject: relayID, Kind: ActorKindRelay,
			ResourceType: "relay", ResourceID: relayID, ResourceName: "relay-warsaw"}},
		{"relay-warsaw", ActorSnapshot{Subject: "relay-warsaw", Kind: ActorKindRelay,
			ResourceType: "relay", ResourceID: relayID, ResourceName: "relay-warsaw"}},
		{machineID, ActorSnapshot{Subject: machineID, Kind: ActorKindMachine,
			ResourceType: "machine", ResourceName: machineID}},
		// A host the panel does not know any more: the identifier stays,
		// the name is not invented.
		{"11111111-2222-4333-8444-555555555555", ActorSnapshot{
			Subject: "11111111-2222-4333-8444-555555555555", Kind: ActorKindAgent,
			ResourceType: "host", ResourceID: "11111111-2222-4333-8444-555555555555"}},
	}
	for _, tc := range cases {
		if got := resolve(tc.id); got != tc.want {
			t.Errorf("%s: snapshot = %+v, want %+v", tc.id, got, tc.want)
		}
	}
	// The machine identifier was never looked up as a host.
	for _, sql := range db.queries {
		if strings.Contains(sql, "from hosts") && strings.Contains(sql, machineID) {
			t.Fatal("a machine identifier was looked up as a host")
		}
	}
}

// The panel acting by itself names the part that acted; a campaign keeps the
// name it had, because campaigns get renamed and the list is where a reviewer
// goes next.
func TestASystemActorNamesItsPart(t *testing.T) {
	db := tables()
	recorder := testRecorder()
	resolve := func(id string) ActorSnapshot {
		return recorder.actorSnapshot(context.Background(), db, nil, Event{ActorType: ActorSystem, ActorID: id})
	}
	campaign := resolve("campaign:b9aa09ed-534f-48d5-89fb-12750d0560b6")
	if campaign != (ActorSnapshot{Subject: "campaign:b9aa09ed-534f-48d5-89fb-12750d0560b6",
		Kind: ActorKindSystem, ResourceType: "campaign",
		ResourceID: "b9aa09ed-534f-48d5-89fb-12750d0560b6", ResourceName: "kernel rollout"}) {
		t.Fatalf("a campaign reads as %+v", campaign)
	}
	policy := resolve("policy:0b1c2d3e-4f50-4617-8283-94a5b6c7d8e9")
	if policy.ResourceType != "policy" || policy.ResourceID != "0b1c2d3e-4f50-4617-8283-94a5b6c7d8e9" || policy.ResourceName != "" {
		t.Fatalf("a policy reads as %+v", policy)
	}
	sweep := resolve("session-group-refresh")
	if sweep != (ActorSnapshot{Subject: "session-group-refresh", Kind: ActorKindSystem}) {
		t.Fatalf("a sweep reads as %+v", sweep)
	}
	// A prefix the panel does not know stays a plain system actor rather
	// than a resource of a made-up type.
	other := resolve("gateway-1:something")
	if other.ResourceType != "" {
		t.Fatalf("an unknown prefix became a resource: %+v", other)
	}
}

// A value that is not an identifier must not fail the insert: the uuid
// columns take null and the text of actor_id still says what it was.
func TestOnlyAnIdentifierGoesIntoAUUIDColumn(t *testing.T) {
	if nullableUUID("") != nil || nullableUUID("relay-warsaw") != nil {
		t.Fatal("a non-identifier was handed to a uuid column")
	}
	if nullableUUID(hostID) != hostID {
		t.Fatal("an identifier was dropped")
	}
}
