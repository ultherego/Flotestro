package helper

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Bezczynnosc liczy sie od zamkniecia ostatniego polaczenia: helper nie
// moze zakonczyc pracy w trakcie zadania, ktore trwa dluzej niz okno.
func TestBezczynnoscNieKonczyPracyWTrakciePolaczenia(t *testing.T) {
	sciezka := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", sciezka)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(uint32(os.Getuid()), slog.New(slog.NewTextHandler(os.Stderr, nil)))
	server.IdleTimeout = 150 * time.Millisecond

	koniec := make(chan error, 1)
	go func() { koniec <- server.Serve(context.Background(), listener) }()

	conn, err := net.Dial("unix", sciezka)
	if err != nil {
		t.Fatal(err)
	}
	// Polaczenie trwa dluzej niz okno bezczynnosci i nic nie wysyla.
	select {
	case err := <-koniec:
		t.Fatalf("helper zakonczyl prace w trakcie polaczenia: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	_ = conn.Close()

	select {
	case err := <-koniec:
		if err != nil {
			t.Fatalf("serwer zakonczyl sie bledem: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("helper nie zakonczyl pracy po zamknieciu ostatniego polaczenia")
	}
}
