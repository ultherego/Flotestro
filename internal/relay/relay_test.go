package relay

import (
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// heartbeat buduje wiadomosc rozpoznawalna po znaczniku czasu: sluzy on tu
// wylacznie do sprawdzenia, czyja wiadomosc wrocila w czyjej sesji.
func heartbeat(znacznik int64) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Heartbeat{
			Heartbeat: &agentv1.Heartbeat{SentAt: timestamppb.New(time.Unix(znacznik, 0))},
		},
	}
}

// TestBuforMaGranice pilnuje wymogu dokumentu: bufor relaya jest ograniczony.
// Relay w odcietej lokalizacji nie moze rosnac do wyczerpania dysku, bo wtedy
// zabiera lokalizacji takze to, co dziala lokalnie.
func TestBuforMaGranice(t *testing.T) {
	bufor := NewBuffer(200)

	zmiescilo := 0
	for i := 0; i < 100; i++ {
		if err := bufor.Add("host-1", heartbeat(1)); err != nil {
			break
		}
		zmiescilo++
	}
	if zmiescilo == 0 {
		t.Fatal("bufor nie przyjal ani jednej wiadomosci")
	}

	stan := bufor.Stats()
	if stan.Bytes > stan.MaxBytes {
		t.Errorf("bufor przekroczyl limit: %d > %d", stan.Bytes, stan.MaxBytes)
	}
	if err := bufor.Add("host-1", heartbeat(1)); err == nil {
		t.Error("pelny bufor przyjal kolejna wiadomosc")
	}
	// Odrzucenie musi byc policzone: cicha utrata wynikow wyglada dla panelu
	// jak zadania, ktore nadal trwaja.
	if bufor.Stats().Dropped == 0 {
		t.Error("odrzucenie nie zostalo odnotowane")
	}
}

// TestBuforOdsylaWSesjiHosta sprawdza, ze wiadomosci wracaja do wlasciwej
// sesji. Centrala wiaze strumien z jedna tozsamoscia, wiec wynik jednego hosta
// nie moze pojsc w sesji drugiego.
func TestBuforOdsylaWSesjiHosta(t *testing.T) {
	bufor := NewBuffer(1 << 20)
	for _, wpis := range []struct {
		host     string
		znacznik int64
	}{{"host-1", 1}, {"host-2", 2}, {"host-1", 3}} {
		if err := bufor.Add(wpis.host, heartbeat(wpis.znacznik)); err != nil {
			t.Fatal(err)
		}
	}

	pobrane := 0
	for {
		message, ok := bufor.TakeFor("host-1")
		if !ok {
			break
		}
		if znacznik := message.GetHeartbeat().GetSentAt().AsTime().Unix(); znacznik == 2 {
			t.Error("w sesji host-1 pojawila sie wiadomosc innego hosta")
		}
		bufor.CommitFor("host-1")
		pobrane++
	}
	if pobrane != 2 {
		t.Errorf("odeslano %d wiadomosci host-1, oczekiwano 2", pobrane)
	}
	// Wiadomosc drugiego hosta czeka na jego wlasna sesje.
	if stan := bufor.Stats(); stan.Messages != 1 {
		t.Errorf("w buforze zostalo %d wiadomosci, oczekiwano 1", stan.Messages)
	}
}

// TestWiadomoscZnikaDopieroPoWyslaniu pilnuje kolejnosci: podgladniecie nie
// usuwa wiadomosci, bo zerwanie lacza w polowie oznaczaloby utrate wyniku.
func TestWiadomoscZnikaDopieroPoWyslaniu(t *testing.T) {
	bufor := NewBuffer(1 << 20)
	if err := bufor.Add("host-1", heartbeat(1)); err != nil {
		t.Fatal(err)
	}
	if _, ok := bufor.TakeFor("host-1"); !ok {
		t.Fatal("brak wiadomosci w buforze")
	}
	if bufor.Stats().Messages != 1 {
		t.Error("podgladniecie usunelo wiadomosc przed potwierdzeniem wyslania")
	}
	bufor.CommitFor("host-1")
	if bufor.Stats().Messages != 0 {
		t.Error("potwierdzona wiadomosc zostala w buforze")
	}
}

// TestZadaniePoTTLNieJestPrzekazywane odpowiada wymogowi z dokumentu: relay
// buforuje wyniki, ale nie wykonuje zadania po TTL. Przekazanie
// przeterminowanego zadania jest zleceniem pracy, o ktora nikt juz nie prosi -
// a host wykonalby ja, bo sam nie wie, ze czekala na polce.
func TestZadaniePoTTLNieJestPrzekazywane(t *testing.T) {
	przeterminowane := &agentv1.TaskEnvelope{
		TaskId:    "zadanie-1",
		ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)),
	}
	if !wygaslo(przeterminowane) {
		t.Error("zadanie po terminie nie zostalo rozpoznane")
	}

	wazne := &agentv1.TaskEnvelope{
		TaskId:    "zadanie-2",
		ExpiresAt: timestamppb.New(time.Now().Add(10 * time.Minute)),
	}
	if wygaslo(wazne) {
		t.Error("wazne zadanie zostalo uznane za przeterminowane")
	}

	// Zadanie bez terminu nie jest przeterminowane: brak terminu to brak
	// wymagania, a nie termin w przeszlosci.
	if wygaslo(&agentv1.TaskEnvelope{TaskId: "zadanie-3"}) {
		t.Error("zadanie bez terminu zostalo pominiete")
	}
}
