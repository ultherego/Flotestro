package helper

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

func testServer() *Server {
	return NewServer(1000, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func unitRequest(unit string, mutate func(*helperv1.HelperRequest)) *helperv1.HelperRequest {
	request := &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "task-1",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  30,
		MaxOutputBytes:  4096,
		Action: &helperv1.HelperRequest_UnitAction{
			UnitAction: &helperv1.UnitActionRequest{
				Unit:      unit,
				Operation: helperv1.UnitActionRequest_OPERATION_RESTART,
			},
		},
	}
	if mutate != nil {
		mutate(request)
	}
	return request
}

func TestHelperOdrzucaNieznanaWersjeProtokolu(t *testing.T) {
	// Helper dziala jako root: nieznana wersja oznacza, ze nie rozumie
	// znaczenia pol, wiec nie wolno mu zgadywac.
	request := unitRequest("nginx.service", func(r *helperv1.HelperRequest) {
		r.ProtocolVersion = ProtocolVersion + 1
	})
	response := testServer().handle(context.Background(), request)
	if response.GetAccepted() {
		t.Fatal("przyjeto zadanie w nieznanej wersji protokolu")
	}
	if response.GetErrorCode() != ErrorUnsupportedVersion {
		t.Fatalf("kod = %q, oczekiwano %q", response.GetErrorCode(), ErrorUnsupportedVersion)
	}
}

func TestHelperOdrzucaZadaniePoTerminie(t *testing.T) {
	// TTL sprawdza takze helper, nie tylko agent. Zadanie, ktore dotarlo po
	// powrocie sieci, nie moze zostac wykonane.
	request := unitRequest("nginx.service", func(r *helperv1.HelperRequest) {
		r.ExpiresAt = timestamppb.New(time.Now().Add(-time.Second))
	})
	response := testServer().handle(context.Background(), request)
	if response.GetAccepted() {
		t.Fatal("wykonano zadanie po terminie")
	}
	if response.GetErrorCode() != ErrorExpired {
		t.Fatalf("kod = %q, oczekiwano %q", response.GetErrorCode(), ErrorExpired)
	}
}

func TestHelperChroniKrytyczneJednostki(t *testing.T) {
	// Walidacja jest powtorzona po stronie roota: helper nie ufa temu, ze
	// agent sprawdzil polityke ochrony.
	for _, unit := range []string{"flotestro-agent.service", "sshd.service", "NetworkManager.service"} {
		response := testServer().handle(context.Background(), unitRequest(unit, nil))
		if response.GetAccepted() {
			t.Errorf("dopuszczono operacje na jednostce chronionej %q", unit)
			continue
		}
		if response.GetErrorCode() != ErrorProtectedUnit {
			t.Errorf("dla %q kod = %q, oczekiwano %q", unit, response.GetErrorCode(), ErrorProtectedUnit)
		}
	}
}

func TestHelperOdrzucaNieprawidlowaNazweJednostki(t *testing.T) {
	for _, unit := range []string{"nginx.service; reboot", "../../x.service", "nginx"} {
		response := testServer().handle(context.Background(), unitRequest(unit, nil))
		if response.GetAccepted() {
			t.Errorf("dopuszczono nazwe %q", unit)
			continue
		}
		if response.GetErrorCode() != ErrorInvalidUnit {
			t.Errorf("dla %q kod = %q, oczekiwano %q", unit, response.GetErrorCode(), ErrorInvalidUnit)
		}
	}
}

func TestHelperOdrzucaBrakAkcji(t *testing.T) {
	request := &helperv1.HelperRequest{ProtocolVersion: ProtocolVersion, TaskId: "task-2"}
	response := testServer().handle(context.Background(), request)
	if response.GetAccepted() || response.GetErrorCode() != ErrorUnknownAction {
		t.Fatalf("kod = %q, oczekiwano %q", response.GetErrorCode(), ErrorUnknownAction)
	}
}

func TestHelperOdrzucaNieznanaOperacje(t *testing.T) {
	request := unitRequest("nginx.service", func(r *helperv1.HelperRequest) {
		r.GetUnitAction().Operation = helperv1.UnitActionRequest_OPERATION_UNSPECIFIED
	})
	response := testServer().handle(context.Background(), request)
	if response.GetAccepted() || response.GetErrorCode() != ErrorUnknownAction {
		t.Fatalf("kod = %q, oczekiwano %q", response.GetErrorCode(), ErrorUnknownAction)
	}
}

func TestRamkowanieWiadomosci(t *testing.T) {
	var buffer bytes.Buffer
	original := unitRequest("nginx.service", nil)
	if err := WriteMessage(&buffer, original); err != nil {
		t.Fatalf("zapis: %v", err)
	}

	var decoded helperv1.HelperRequest
	if err := ReadMessage(&buffer, &decoded); err != nil {
		t.Fatalf("odczyt: %v", err)
	}
	if decoded.GetTaskId() != original.GetTaskId() {
		t.Fatalf("task_id = %q, oczekiwano %q", decoded.GetTaskId(), original.GetTaskId())
	}
	if decoded.GetUnitAction().GetUnit() != "nginx.service" {
		t.Fatalf("unit = %q", decoded.GetUnitAction().GetUnit())
	}
}

func TestOdczytOdrzucaZbytDuzaRamke(t *testing.T) {
	// Rozmowca helpera nie moze wymusic dowolnej alokacji w procesie roota.
	header := []byte{0xff, 0xff, 0xff, 0xff}
	var decoded helperv1.HelperRequest
	err := ReadMessage(bytes.NewReader(header), &decoded)
	if err == nil {
		t.Fatal("przyjeto ramke ponad limitem")
	}
}

func TestClampPrzycinaOutput(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 100)
	clamped, truncated := clamp(data, 10)
	if len(clamped) != 10 || !truncated {
		t.Fatalf("len=%d truncated=%v, oczekiwano 10/true", len(clamped), truncated)
	}
	short, truncated := clamp([]byte("abc"), 10)
	if len(short) != 3 || truncated {
		t.Fatalf("krotki output zostal obciety")
	}
}
