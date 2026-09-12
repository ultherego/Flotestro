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

// Idleness is counted from the closing of the last connection: the helper
// must not end its work in the middle of a task that takes longer than the
// window.
func TestIdlenessDoesNotEndTheWorkDuringAConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(uint32(os.Getuid()), slog.New(slog.NewTextHandler(os.Stderr, nil)))
	server.IdleTimeout = 150 * time.Millisecond

	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), listener) }()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// The connection lasts longer than the idle window and sends nothing.
	select {
	case err := <-done:
		t.Fatalf("the helper ended its work during a connection: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	_ = conn.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the server ended with an error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the helper did not end its work after the last connection closed")
	}
}
