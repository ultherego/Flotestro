package local

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A file address answers like the remote feed: the content with a tag, a
// repeat with the tag answers 304, and a missing file is a 404 rather than
// an error - the sources treat those the way they treat the vendor's.
func TestFileAddressAnswersLikeAFeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(path, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	client := Client(time.Second)

	response, err := client.Get("file://" + path)
	if err != nil {
		t.Fatalf("reading the file: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("answer %d %q", response.StatusCode, body)
	}
	tag := response.Header.Get("ETag")
	if tag == "" || response.Header.Get("Last-Modified") == "" {
		t.Fatalf("the answer carries no tag or time: %v", response.Header)
	}

	request, _ := http.NewRequest(http.MethodGet, "file://"+path, nil)
	request.Header.Set("If-None-Match", tag)
	again, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	again.Body.Close()
	if again.StatusCode != http.StatusNotModified {
		t.Fatalf("an unchanged file answered %d", again.StatusCode)
	}

	missing, err := client.Get("file://" + filepath.Join(dir, "nothing.json"))
	if err != nil {
		t.Fatal(err)
	}
	missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("a missing file answered %d", missing.StatusCode)
	}

	listing, err := client.Get("file://" + dir)
	if err != nil {
		t.Fatal(err)
	}
	names, _ := io.ReadAll(listing.Body)
	listing.Body.Close()
	if string(names) != "feed.json\n" {
		t.Fatalf("the directory listed %q", names)
	}
}
