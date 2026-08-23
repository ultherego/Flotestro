package processes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Nazwa procesu jest w nawiasach i moze zawierac spacje oraz same nawiasy.
// Podzial calej linii po spacjach dawalby zle pola dla takich nazw - a od
// nich zalezy czas startu, ktory chroni przed ponownym uzyciem PID.
func TestParsujStatRadziSobieZNazwaZeSpacjami(t *testing.T) {
	linia := "1234 (moj program (test)) S 1 1234 1234 0 -1 4194304 100 0 0 0 " +
		"11 22 0 0 20 0 7 0 987654 12345678 1000 " + strings.Repeat("0 ", 20)

	proces, ok := parsujStat(linia)
	if !ok {
		t.Fatal("nie odczytano stanu procesu")
	}
	if proces.Name != "moj program (test)" {
		t.Errorf("nazwa = %q", proces.Name)
	}
	if proces.State != "S" || proces.PPID != 1 {
		t.Errorf("stan = %q, ppid = %d", proces.State, proces.PPID)
	}
	if proces.CPUTicks != 33 {
		t.Errorf("czas procesora = %d, oczekiwano 33 (11 + 22)", proces.CPUTicks)
	}
	if proces.Threads != 7 {
		t.Errorf("watkow = %d", proces.Threads)
	}
	if proces.StartTimeTicks != 987654 {
		t.Errorf("czas startu = %d", proces.StartTimeTicks)
	}
}

// Sam PID nie identyfikuje procesu: jadro uzywa numerow ponownie. Sygnal
// wyslany po obejrzeniu listy moglby trafic w cos zupelnie innego.
func TestSygnalOdmawiaPrzyInnymCzasieStartu(t *testing.T) {
	root := zrobProc(t, 4242, 111111)

	err := Wyslij(root, 4242, 999999, SignalTERM, Chronione{})
	if err == nil {
		t.Fatal("sygnal poszedl mimo innego czasu startu")
	}
	if !strings.Contains(err.Error(), "inny proces") {
		t.Errorf("blad = %v", err)
	}
}

// Lista sygnalow jest zamknieta: nie istnieje operacja "wyslij dowolny sygnal".
func TestNieznanySygnalJestOdrzucany(t *testing.T) {
	root := zrobProc(t, 4242, 111111)
	for _, sygnal := range []string{"STOP", "SEGV", "USR1", "", "9"} {
		if ZnanySygnal(sygnal) {
			t.Errorf("sygnal %q uznany za obslugiwany", sygnal)
		}
		if err := Wyslij(root, 4242, 111111, sygnal, Chronione{}); err == nil {
			t.Errorf("sygnal %q zostal wyslany", sygnal)
		}
	}
}

// Ubicie procesu inicjujacego konczy prace hosta, a ubicie agenta odcina go
// od panelu - a wiec takze od naprawy tego, co wlasnie zostalo zepsute.
func TestProcesyChronioneSaOdrzucane(t *testing.T) {
	root := zrobProc(t, 4242, 111111)

	if err := Wyslij(root, 1, 0, SignalTERM, Chronione{}); err == nil {
		t.Error("wyslano sygnal do PID 1")
	}
	if err := Wyslij(root, 4242, 111111, SignalKILL, Chronione{Wlasne: []int32{4242}}); err == nil {
		t.Error("wyslano sygnal do wlasnego procesu agenta")
	}
}

// Cgroup mowi, co zarzadza procesem. Operator widzacy sam PID musialby
// zgadywac, czyj on jest.
func TestWlascicielZCgroup(t *testing.T) {
	unit, container := wlascicielZCgroup("0::/system.slice/nginx.service\n")
	if unit != "nginx.service" || container != "" {
		t.Errorf("unit = %q, container = %q", unit, container)
	}

	unit, container = wlascicielZCgroup(
		"0::/system.slice/docker-5c5b63d3119a59ac7a7a7f2a18342dbd.scope\n")
	if container != "5c5b63d3119a59ac7a7a7f2a18342dbd" {
		t.Errorf("container = %q", container)
	}
	if unit != "" {
		t.Errorf("kontener zostal takze uznany za jednostke: %q", unit)
	}
}

// Snapshot ma gorna granice, ale musi powiedziec, ilu procesow nie pokazuje.
func TestSnapshotMowiOUrwaniu(t *testing.T) {
	root := t.TempDir()
	for pid := 100; pid < 110; pid++ {
		zapiszProc(t, root, pid, uint64(pid*1000))
	}

	snapshot := Collect(root, SortByPID, 4)
	if snapshot.Total != 10 {
		t.Errorf("total = %d, oczekiwano 10", snapshot.Total)
	}
	if len(snapshot.Processes) != 4 {
		t.Errorf("zwrocono %d procesow, oczekiwano 4", len(snapshot.Processes))
	}
	if !snapshot.Truncated {
		t.Error("urwanie nie zostalo zaznaczone")
	}
	if snapshot.Processes[0].PID != 100 {
		t.Errorf("sortowanie po PID nie zadzialalo: %d", snapshot.Processes[0].PID)
	}
}

func zrobProc(t *testing.T, pid int, start uint64) string {
	t.Helper()
	root := t.TempDir()
	zapiszProc(t, root, pid, start)
	return root
}

func zapiszProc(t *testing.T, root string, pid int, start uint64) {
	t.Helper()
	katalog := filepath.Join(root, itoa(pid))
	if err := os.MkdirAll(katalog, 0o755); err != nil {
		t.Fatal(err)
	}
	linia := itoa(pid) + " (test) S 1 1 1 0 -1 0 0 0 0 0 1 2 0 0 20 0 1 0 " +
		utoa(start) + " 0 100 " + strings.Repeat("0 ", 20)
	if err := os.WriteFile(filepath.Join(katalog, "stat"), []byte(linia), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(wartosc int) string { return utoa(uint64(wartosc)) }
func utoa(wartosc uint64) string {
	if wartosc == 0 {
		return "0"
	}
	var cyfry []byte
	for wartosc > 0 {
		cyfry = append([]byte{byte('0' + wartosc%10)}, cyfry...)
		wartosc /= 10
	}
	return string(cyfry)
}
