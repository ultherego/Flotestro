package agent

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

func kopertaJednostki(id, unit string) *agentv1.TaskEnvelope {
	return &agentv1.TaskEnvelope{
		TaskId: id,
		Action: &agentv1.TaskEnvelope_UnitAction{
			UnitAction: &agentv1.UnitAction{
				Operation: agentv1.UnitAction_OPERATION_RESTART, Unit: unit,
			},
		},
	}
}

// TestKolidujaceMutacjeSaSerializowane pilnuje wlasciwosci, dla ktorej te
// blokady istnieja: dwie zmiany tego samego zasobu nie moga isc obok siebie,
// nawet jesli obie miesza sie w limicie zadan hosta.
func TestKolidujaceMutacjeSaSerializowane(t *testing.T) {
	z := noweZamki()
	ctx := context.Background()

	pierwsze, powod := z.zajmij(ctx, "zadanie-1", "unit.restart", []string{"units"})
	if pierwsze == nil {
		t.Fatalf("pierwsze zadanie nie dostalo zasobu: %s", powod)
	}

	drugie := make(chan struct{})
	go func() {
		oddaj, _ := z.zajmij(ctx, "zadanie-2", "unit.stop", []string{"units"})
		if oddaj != nil {
			oddaj()
		}
		close(drugie)
	}()

	select {
	case <-drugie:
		t.Fatal("drugie zadanie weszlo na zajety zasob")
	case <-time.After(50 * time.Millisecond):
	}

	pierwsze()
	select {
	case <-drugie:
	case <-time.After(2 * time.Second):
		t.Fatal("drugie zadanie nie ruszylo po zwolnieniu zasobu")
	}
}

// TestRozneZasobyIdaObokSiebie pilnuje drugiej polowy tej samej zasady:
// blokada ma serializowac kolizje, a nie caly host.
func TestRozneZasobyIdaObokSiebie(t *testing.T) {
	z := noweZamki()
	ctx := context.Background()

	siec, _ := z.zajmij(ctx, "zadanie-1", "network.profile.apply", []string{"network"})
	if siec == nil {
		t.Fatal("zadanie sieciowe nie dostalo zasobu")
	}
	defer siec()

	pakiety, powod := z.zajmij(ctx, "zadanie-2", "packages.upgrade", []string{"packages"})
	if pakiety == nil {
		t.Fatalf("operacja pakietowa czekala na siec: %s", powod)
	}
	pakiety()
}

// TestRestartZabieraCalyHost pilnuje granicy, ktorej nie widac w klasach
// zasobow: zmiana, ktora zaczela sie tuz przed restartem, nie ma jak sie
// skonczyc.
func TestRestartZabieraCalyHost(t *testing.T) {
	z := noweZamki()
	ctx := context.Background()

	restart, _ := z.zajmij(ctx, "zadanie-1", "system.reboot", []string{RoszczenieHosta})
	if restart == nil {
		t.Fatal("restart nie dostal hosta")
	}

	krotki, anuluj := context.WithTimeout(ctx, 50*time.Millisecond)
	defer anuluj()
	inne, powod := z.zajmij(krotki, "zadanie-2", "unit.restart", []string{"units"})
	if inne != nil {
		t.Fatal("operacja weszla obok trwajacego restartu hosta")
	}
	if !strings.Contains(powod, "system.reboot") {
		t.Errorf("odmowa nie nazywa blokujacej operacji: %q", powod)
	}
	restart()
}

// TestHostCzekaNaTrwajaceMutacje pilnuje tej samej granicy z drugiej strony.
func TestHostCzekaNaTrwajaceMutacje(t *testing.T) {
	z := noweZamki()
	ctx := context.Background()

	pakiety, _ := z.zajmij(ctx, "zadanie-1", "packages.upgrade", []string{"packages"})
	if pakiety == nil {
		t.Fatal("operacja pakietowa nie dostala zasobu")
	}

	krotki, anuluj := context.WithTimeout(ctx, 50*time.Millisecond)
	defer anuluj()
	restart, powod := z.zajmij(krotki, "zadanie-2", "system.reboot", []string{RoszczenieHosta})
	if restart != nil {
		t.Fatal("restart wszedl w trakcie transakcji pakietowej")
	}
	if !strings.Contains(powod, "packages") {
		t.Errorf("odmowa nie nazywa zajetego zasobu: %q", powod)
	}
	pakiety()
}

// TestOdczytNieZajmujeZasobu pilnuje, ze blokady dotycza mutacji. Dwa odczyty
// stanu moga isc obok siebie, a ich koszt ogranicza budzet zadan.
func TestOdczytNieZajmujeZasobu(t *testing.T) {
	odczyt := &agentv1.TaskEnvelope{
		TaskId: "odczyt",
		Action: &agentv1.TaskEnvelope_ReadUnitStatus{
			ReadUnitStatus: &agentv1.ReadUnitStatus{Units: []string{"cron.service"}},
		},
	}
	if roszczenia := roszczeniaZadania(odczyt); len(roszczenia) != 0 {
		t.Fatalf("odczyt zajmuje zasoby %v", roszczenia)
	}
}

// TestMutacjaJednostkiZajmujeKlaseZasobu pilnuje, ze roszczenia biora sie
// z rejestru operacji, a nie z osobnej listy w agencie.
func TestMutacjaJednostkiZajmujeKlaseZasobu(t *testing.T) {
	roszczenia := roszczeniaZadania(kopertaJednostki("zadanie", "cron.service"))
	if len(roszczenia) != 1 || roszczenia[0] != "units" {
		t.Fatalf("roszczenia = %v", roszczenia)
	}
}

// TestZmianaJadraBierzeTakzeSiec pilnuje zaleznosci, ktorej nie widac
// w klasie zasobu: sysctl przestawia stos sieciowy, wiec nie moze isc
// rownolegle ze zmiana adresu.
func TestZmianaJadraBierzeTakzeSiec(t *testing.T) {
	sysctl := &agentv1.TaskEnvelope{
		TaskId: "sysctl",
		Action: &agentv1.TaskEnvelope_Kernel{
			Kernel: &agentv1.KernelAction{
				Operation: agentv1.KernelAction_OPERATION_SYSCTL_ENSURE,
				Settings:  map[string]string{"net.ipv4.ip_forward": "1"},
			},
		},
	}
	roszczenia := roszczeniaZadania(sysctl)
	if len(roszczenia) != 2 || roszczenia[0] != "kernel" || roszczenia[1] != "network" {
		t.Fatalf("roszczenia = %v", roszczenia)
	}
}

// TestPlikiSaOsobnymiZasobami pilnuje, ze dwie zmiany roznych plikow nie maja
// powodu na siebie czekac, a dwie zmiany tego samego pliku maja.
func TestPlikiSaOsobnymiZasobami(t *testing.T) {
	plik := func(sciezka string) *agentv1.TaskEnvelope {
		return &agentv1.TaskEnvelope{
			TaskId: "plik-" + sciezka,
			Action: &agentv1.TaskEnvelope_File{
				File: &agentv1.FileAction{
					Operation: agentv1.FileAction_OPERATION_ENSURE,
					Path:      sciezka, Content: []byte("x"), Mode: "0644",
				},
			},
		}
	}
	pierwszy := roszczeniaZadania(plik("/etc/a.conf"))
	drugi := roszczeniaZadania(plik("/etc/b.conf"))
	if len(pierwszy) != 1 || pierwszy[0] != "file:/etc/a.conf" {
		t.Fatalf("roszczenia pierwszego pliku = %v", pierwszy)
	}
	if len(drugi) != 1 || drugi[0] != "file:/etc/b.conf" {
		t.Fatalf("roszczenia drugiego pliku = %v", drugi)
	}
}

// TestPayloadNaprawyMaTenSamHashCoWPanelu pilnuje wlasciwosci, ktora laczy
// panel z agentem: koperta musi odtworzyc dokladnie ten payload, z ktorego
// panel policzyl hash planu. Pusta lista zapisuje sie w JSON inaczej niz jej
// brak, wiec naprawa bez odpowiedzi konczyla sie odmowa payload_hash_mismatch.
func TestPayloadNaprawyMaTenSamHashCoWPanelu(t *testing.T) {
	wPanelu := opspec.Payload{PackageRepair: &opspec.PackageRepairPayload{}}
	oczekiwany, err := opspec.PayloadHash(opspec.ActionPackageRepair, opspec.ActionVersion, wPanelu)
	if err != nil {
		t.Fatal(err)
	}

	koperta := &agentv1.TaskEnvelope{
		TaskId: "naprawa",
		Action: &agentv1.TaskEnvelope_PackagesRepair{
			PackagesRepair: &agentv1.PackagesRepair{},
		},
	}
	action, payload, err := decodeAction(koperta)
	if err != nil {
		t.Fatalf("dekodowanie koperty: %v", err)
	}
	uAgenta, err := opspec.PayloadHash(action, opspec.ActionVersion, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oczekiwany, uAgenta) {
		t.Fatalf("hash planu rozjezdza sie: panel %x, agent %x", oczekiwany, uAgenta)
	}
}
