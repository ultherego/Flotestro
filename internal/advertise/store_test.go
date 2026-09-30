package advertise

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"testing"
	"time"
)

// memoryRecords is the database's part played by a map. The panel keeps the
// choice in PostgreSQL; what the tests need of it is that two Stores read the
// same row, which is the whole point of keeping it there.
type memoryRecords struct{ record Record }

func (m *memoryRecords) Read(context.Context) (Record, error) { return m.record, nil }

func (m *memoryRecords) Write(_ context.Context, names []string, actor string) (Record, error) {
	m.record = Record{
		Present: true, Names: names, Superseded: SupersededAfter(m.record, names),
		ConfirmedAt: time.Now().UTC(), ConfirmedBy: actor,
		Revision: m.record.Revision + 1,
	}
	return m.record, nil
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The loopback default is what a compose file starts with, and it must not be
// what the fleet is told forever. The choice is the installation's, so it lives
// where the installation does and a new process finds it there.
func TestTheConfirmedChoiceSurvivesARestart(t *testing.T) {
	records := &memoryRecords{}
	first := NewStore(records, quiet(), Parse("127.0.0.1"))
	if err := first.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !first.LoopbackOnly() {
		t.Fatal("a panel that has confirmed nothing claims to be reachable")
	}
	if _, err := first.Confirm(context.Background(),
		Parse("panel.example.test"), "admin@example.test"); err != nil {
		t.Fatal(err)
	}

	// The restart, or the second replica: another Store over the same row, with
	// the same environment the deployment carries.
	second := NewStore(records, quiet(), Parse("127.0.0.1"))
	if err := second.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := second.InForce().String(); got != "panel.example.test" {
		t.Errorf("after the restart the panel advertises %q", got)
	}
	if second.LoopbackOnly() {
		t.Error("the confirmed address did not reopen the enrolment door after the restart")
	}
	dnsNames, _, _ := second.CertificateNames()
	if !slices.Contains(dnsNames, "panel.example.test") {
		t.Errorf("the certificate of the restarted panel names %v", dnsNames)
	}
	if !slices.Contains(second.ReservedNames(), "panel.example.test") {
		t.Errorf("the reserved names of the restarted panel = %v", second.ReservedNames())
	}
	state := second.State()
	if state.Source != "confirmed" || state.ConfirmedBy != "admin@example.test" {
		t.Errorf("the restarted panel says the address came from %q, confirmed by %q",
			state.Source, state.ConfirmedBy)
	}
}

// The four consequences of the choice move together because they are four reads
// of one value. This is the test of that: one confirmation, then a second, and
// every one of them follows both times.
func TestOneChoiceMovesAllFourConsequences(t *testing.T) {
	records := &memoryRecords{}
	store := NewStore(records, quiet(), Parse("127.0.0.1"))
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, firstGeneration := store.CertificateNames()

	if _, err := store.Confirm(context.Background(), Parse("panel.example.test"), "admin"); err != nil {
		t.Fatal(err)
	}
	dnsNames, ips, generation := store.CertificateNames()
	switch {
	case generation == firstGeneration:
		t.Error("the address changed and the certificate was not issued again")
	case !slices.Contains(dnsNames, "panel.example.test"):
		t.Errorf("the certificate names %v", dnsNames)
	case store.LoopbackOnly():
		t.Error("the enrolment door is still shut on a reachable address")
	case !slices.Equal(store.Reachable(), []string{"panel.example.test"}):
		t.Errorf("a new agent would be told to dial %v", store.Reachable())
	case !slices.Contains(store.ReservedNames(), "panel.example.test"):
		t.Errorf("a relay may take the panel's own name: reserved = %v", store.ReservedNames())
	}
	if len(ips) != 1 {
		t.Errorf("the certificate carries %d addresses, want loopback alone", len(ips))
	}

	// The second change. The previous name stays reserved: an agent that has not
	// been reconfigured yet still dials it, and a relay holding a certificate for
	// it would answer in the panel's place.
	if _, err := store.Confirm(context.Background(), Parse("192.0.2.20"), "admin"); err != nil {
		t.Fatal(err)
	}
	dnsNames, ips, second := store.CertificateNames()
	switch {
	case second <= generation:
		t.Error("the second change of address did not reach the certificate")
	case slices.Contains(dnsNames, "panel.example.test"):
		t.Errorf("the certificate still names the address the panel left: %v", dnsNames)
	case !slices.ContainsFunc(ips, func(ip net.IP) bool { return ip.Equal(net.ParseIP("192.0.2.20")) }):
		t.Errorf("the certificate does not name the address in force: %v", ips)
	case !slices.Equal(store.Reachable(), []string{"192.0.2.20"}):
		t.Errorf("a new agent would be told to dial %v", store.Reachable())
	}
	reserved := store.ReservedNames()
	if !slices.Contains(reserved, "192.0.2.20") || !slices.Contains(reserved, "panel.example.test") {
		t.Errorf("reserved = %v, want the address in force and the one it replaced", reserved)
	}

	// Confirming a name again takes it back out of the memory: it is in force,
	// not a thing the panel used to be called.
	if _, err := store.Confirm(context.Background(), Parse("panel.example.test"), "admin"); err != nil {
		t.Fatal(err)
	}
	if state := store.State(); slices.Contains(state.Superseded, "panel.example.test") {
		t.Errorf("the address in force is listed as superseded: %v", state.Superseded)
	}
}

// A certificate is the fleet's trust anchor for this panel; issuing a new one
// for the same names buys nothing and invalidates what every open connection
// negotiated against.
func TestConfirmingTheSameChoiceIssuesNoNewCertificate(t *testing.T) {
	store := NewStore(&memoryRecords{}, quiet(), Parse("127.0.0.1"))
	if _, err := store.Confirm(context.Background(), Parse("panel.example.test"), "admin"); err != nil {
		t.Fatal(err)
	}
	_, _, first := store.CertificateNames()
	if _, err := store.Confirm(context.Background(),
		Parse("Panel.Example.TEST"), "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, again := store.CertificateNames(); again != first {
		t.Error("the same address written in another case counted as a change")
	}
}

// The detected addresses are a proposal. Nothing may adopt one, not even on the
// first start of an installation that has confirmed nothing at all.
func TestADetectedAddressIsNeverInForceByItself(t *testing.T) {
	store := NewStore(&memoryRecords{}, quiet(), Parse("127.0.0.1"))
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	inForce := store.InForce().Names()
	for _, candidate := range Detect() {
		if candidate.Loopback {
			continue
		}
		if slices.Contains(inForce, candidate.Name) {
			t.Errorf("the panel adopted %q, an address it detected on this machine", candidate.Name)
		}
	}
	if !store.LoopbackOnly() {
		t.Errorf("the panel that confirmed nothing advertises %v", inForce)
	}
	if got := store.State().Source; got != "default" {
		t.Errorf("the panel says its address came from %q", got)
	}
}

// An installation that names a reachable address in the environment of the
// control plane declares it there: whoever deployed it arranged the DNS and the
// firewall for that name, and an upgrade must not move a running fleet's
// rendezvous point because a row exists. The disagreement is said out loud
// rather than resolved in silence.
func TestTheEnvironmentDecidesWhenItNamesAReachableAddress(t *testing.T) {
	records := &memoryRecords{}
	confirming := NewStore(records, quiet(), Parse("127.0.0.1"))
	if _, err := confirming.Confirm(context.Background(),
		Parse("confirmed.example.test"), "admin"); err != nil {
		t.Fatal(err)
	}

	declared := NewStore(records, quiet(), Parse("declared.example.test"))
	if err := declared.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := declared.InForce().String(); got != "declared.example.test" {
		t.Errorf("the panel advertises %q, want what the deployment declares", got)
	}
	state := declared.State()
	if state.Source != "environment" || !state.EnvironmentInForce {
		t.Errorf("the panel says its address came from %q", state.Source)
	}
	if state.Mismatch == "" {
		t.Error("two answers to where the panel is, and nothing said about it")
	}
	if !slices.Equal(state.Confirmed, []string{"confirmed.example.test"}) {
		t.Errorf("the stored choice is not reported: %v", state.Confirmed)
	}
	// The name the panel was seen under stays refused to a relay even while the
	// environment overrides it: this panel was reachable there.
	if !slices.Contains(declared.ReservedNames(), "confirmed.example.test") {
		t.Errorf("reserved = %v", declared.ReservedNames())
	}
	// And the screen may not offer a choice that would not take effect.
	if _, err := declared.Confirm(context.Background(),
		Parse("other.example.test"), "admin"); !errors.Is(err, ErrEnvironmentInForce) {
		t.Errorf("a confirmation was stored where it does not decide: %v", err)
	}
}

// A loopback value in the environment is a default and not a declaration; the
// confirmed choice takes force over it. This is the flow the product ships:
// compose starts with no questions in the terminal.
func TestALoopbackEnvironmentIsOnlyADefault(t *testing.T) {
	store := NewStore(&memoryRecords{}, quiet(), Parse("127.0.0.1,localhost"))
	if store.EnvironmentInForce() {
		t.Fatal("a loopback default claims to decide the installation's address")
	}
	if _, err := store.Confirm(context.Background(), Parse("panel.example.test"), "admin"); err != nil {
		t.Fatal(err)
	}
	if got := store.InForce().String(); got != "panel.example.test" {
		t.Errorf("the panel advertises %q", got)
	}
	if store.State().Mismatch != "" {
		t.Errorf("a default that was replaced is reported as a disagreement: %s",
			store.State().Mismatch)
	}
}

// A confirmation made on another replica reaches this one without a restart.
func TestARefreshPicksUpAConfirmationFromAnotherReplica(t *testing.T) {
	records := &memoryRecords{}
	here := NewStore(records, quiet(), Parse("127.0.0.1"))
	if err := here.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, before := here.CertificateNames()

	elsewhere := NewStore(records, quiet(), Parse("127.0.0.1"))
	if _, err := elsewhere.Confirm(context.Background(),
		Parse("panel.example.test"), "admin"); err != nil {
		t.Fatal(err)
	}
	if !here.LoopbackOnly() {
		t.Fatal("the replica saw the confirmation before it read the row")
	}
	if err := here.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := here.InForce().String(); got != "panel.example.test" {
		t.Errorf("after the refresh this replica advertises %q", got)
	}
	if _, _, after := here.CertificateNames(); after == before {
		t.Error("the replica did not issue its own certificate for the confirmed name")
	}
}

// The refusals are what the screen shows, so they go back as codes rather than
// as prose to be matched on.
func TestConfirmRefusesAnUnusableChoice(t *testing.T) {
	store := NewStore(&memoryRecords{}, quiet(), Parse("127.0.0.1"))
	if _, err := store.Confirm(context.Background(), Of(nil), "admin"); !errors.Is(err, ErrNoName) {
		t.Errorf("an empty confirmation: %v", err)
	}
	if _, err := store.Confirm(context.Background(),
		Parse("panel.example.test:8443"), "admin"); !errors.Is(err, ErrInvalidName) {
		t.Errorf("a name carrying a port: %v", err)
	}
	if !store.LoopbackOnly() {
		t.Error("a refused confirmation changed what the panel advertises")
	}
}
