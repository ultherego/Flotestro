package packages

import (
	"os"
	"path/filepath"
	"testing"
)

// Katalog modulow podstawiony pustym katalogiem to sygnatura namespace'u
// z ProtectKernelModules. Transakcja w takim srodowisku produkuje initramfs
// bez sterownikow, wiec musi zostac odrzucona przed startem.
func TestUkryteModulyJadraSaWykrywane(t *testing.T) {
	root := t.TempDir()
	proc := zapiszProc(t, root, "dm_mod 200704 1 - Live 0x0000000000000000\n")

	pusty := filepath.Join(root, "modules")
	if err := os.MkdirAll(filepath.Join(pusty, "6.12.48"), 0o755); err != nil {
		t.Fatal(err)
	}
	if hidden, dir := modulesHiddenAt(proc, pusty, "6.12.48"); !hidden {
		t.Fatalf("pusty katalog modulow nie zostal uznany za ukryty (%q)", dir)
	}

	brak := filepath.Join(root, "brak")
	if hidden, _ := modulesHiddenAt(proc, brak, "6.12.48"); !hidden {
		t.Fatal("brakujacy katalog modulow nie zostal uznany za ukryty")
	}
}

// Widoczne drzewo modulow nie moze blokowac aktualizacji.
func TestWidoczneModulyNieBlokujaTransakcji(t *testing.T) {
	root := t.TempDir()
	proc := zapiszProc(t, root, "dm_mod 200704 1 - Live 0x0000000000000000\n")

	modules := filepath.Join(root, "modules", "6.12.48", "kernel")
	if err := os.MkdirAll(modules, 0o755); err != nil {
		t.Fatal(err)
	}
	if hidden, dir := modulesHiddenAt(proc, filepath.Join(root, "modules"), "6.12.48"); hidden {
		t.Fatalf("widoczne moduly uznano za ukryte (%q)", dir)
	}
}

// Jadro bez modulow jest poprawnym srodowiskiem - obraz kontenerowy albo
// jadro monolityczne. Blokowanie takiego hosta byloby falszywym alarmem.
func TestJadroBezModulowNieJestBlokowane(t *testing.T) {
	root := t.TempDir()
	proc := zapiszProc(t, root, "")

	if hidden, _ := modulesHiddenAt(proc, filepath.Join(root, "brak"), "6.12.48"); hidden {
		t.Fatal("jadro monolityczne zostalo potraktowane jak srodowisko z ukrytymi modulami")
	}
}

// Nieznana wersja jadra nie jest dowodem na ukryte moduly.
func TestNieznanaWersjaJadraNieBlokuje(t *testing.T) {
	root := t.TempDir()
	proc := zapiszProc(t, root, "dm_mod 200704 1 - Live 0x0000000000000000\n")

	if hidden, _ := modulesHiddenAt(proc, filepath.Join(root, "modules"), ""); hidden {
		t.Fatal("brak wersji jadra zablokowal transakcje")
	}
}

func zapiszProc(t *testing.T, root, content string) string {
	t.Helper()
	path := filepath.Join(root, "proc-modules")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
