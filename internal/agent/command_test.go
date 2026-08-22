package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunCommandOdrozniaWynikOdBleduWykonania(t *testing.T) {
	ctx := context.Background()

	t.Run("proces zakonczony sukcesem", func(t *testing.T) {
		result := runCommand(ctx, 5*time.Second, "/bin/true")
		if !result.Ran || result.ExitCode != 0 {
			t.Fatalf("Ran=%v ExitCode=%d, oczekiwano true/0", result.Ran, result.ExitCode)
		}
	})

	t.Run("proces zwrocil kod bledu", func(t *testing.T) {
		// Niezerowy kod z dzialajacego procesu jest wynikiem, nie awaria.
		result := runCommand(ctx, 5*time.Second, "/bin/false")
		if !result.Ran {
			t.Fatal("proces sie wykonal, a Ran=false")
		}
		if result.ExitCode != 1 {
			t.Fatalf("ExitCode=%d, oczekiwano 1", result.ExitCode)
		}
	})

	t.Run("brak binarki", func(t *testing.T) {
		result := runCommand(ctx, 5*time.Second, "/nie/ma/takiego/programu")
		if result.Ran {
			t.Fatal("nieistniejacy program zostal uznany za wykonany")
		}
		if result.Err == nil {
			t.Fatal("brak bledu dla nieistniejacego programu")
		}
	})

	t.Run("przekroczony timeout", func(t *testing.T) {
		// Timeout nie jest wynikiem merytorycznym, choc proces zwroci kod.
		result := runCommand(ctx, 100*time.Millisecond, "/bin/sleep", "5")
		if result.Ran {
			t.Fatal("przerwany timeoutem proces zostal uznany za wykonany")
		}
	})
}

func TestRunCommandUstawiaZapisywalneHome(t *testing.T) {
	dir := t.TempDir()
	if err := SetRuntimeDir(dir); err != nil {
		t.Fatalf("katalog roboczy: %v", err)
	}
	t.Cleanup(func() { runtimeDir = os.TempDir() })

	// Narzedzia takie jak dnf tworza pliki w HOME i XDG. Agent nie ma katalogu
	// domowego, wiec brak tych zmiennych konczyl sie bledem branym za wynik.
	result := runCommand(context.Background(), 5*time.Second, "/usr/bin/env")
	if !result.Ran {
		t.Skip("brak /usr/bin/env")
	}
	for _, want := range []string{
		"HOME=" + dir,
		"XDG_STATE_HOME=" + filepath.Join(dir, "state"),
		"XDG_CACHE_HOME=" + filepath.Join(dir, "cache"),
	} {
		if !strings.Contains(result.Stdout, want) {
			t.Errorf("brak %s w srodowisku procesu", want)
		}
	}
	for _, sub := range []string{"state", "cache", "config"} {
		if info, err := os.Stat(filepath.Join(dir, sub)); err != nil || !info.IsDir() {
			t.Errorf("nie utworzono katalogu %s", sub)
		}
	}
}

func TestInterpretNeedsRestarting(t *testing.T) {
	cases := []struct {
		name   string
		result commandResult
		want   *bool
	}{
		{
			name:   "kod 0 oznacza brak potrzeby restartu",
			result: commandResult{Ran: true, ExitCode: 0, Stdout: "Reboot should not be necessary.\n"},
			want:   boolPtr(false),
		},
		{
			name:   "kod 1 z odpowiedzia oznacza wymagany restart",
			result: commandResult{Ran: true, ExitCode: 1, Stdout: "Core libraries or services have been updated.\n"},
			want:   boolPtr(true),
		},
		{
			// To jest regresja: dnf bez zapisywalnego HOME konczy sie kodem 1
			// i milczy na stdout. Wczesniej bylo to raportowane jako
			// "wymagany restart" na kazdym hoscie Fedory.
			name: "kod 1 bez odpowiedzi to blad, nie wynik",
			result: commandResult{
				Ran: true, ExitCode: 1, Stdout: "",
				Stderr: "filesystem error: cannot create directories: Permission denied",
			},
			want: nil,
		},
		{
			name:   "proces sie nie wykonal",
			result: commandResult{Ran: false, ExitCode: -1},
			want:   nil,
		},
		{
			name:   "nieznany kod wyjscia",
			result: commandResult{Ran: true, ExitCode: 127, Stdout: "cos"},
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := interpretNeedsRestarting(tc.result)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("oczekiwano stanu nieustalonego, otrzymano %v", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("oczekiwano %v, otrzymano stan nieustalony", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("otrzymano %v, oczekiwano %v", *got, *tc.want)
			}
		})
	}
}

func TestCommandResultReasonOpisujeBlad(t *testing.T) {
	result := commandResult{
		Ran: true, ExitCode: 1,
		Stderr: "filesystem error: cannot create directories: Permission denied\ndalsza linia",
	}
	reason := result.Reason()
	if !strings.Contains(reason, "kod 1") {
		t.Errorf("powod nie zawiera kodu wyjscia: %q", reason)
	}
	if !strings.Contains(reason, "Permission denied") {
		t.Errorf("powod nie zawiera tresci bledu: %q", reason)
	}
	if strings.Contains(reason, "dalsza linia") {
		t.Errorf("powod powinien byc jednolinijkowy: %q", reason)
	}
}
