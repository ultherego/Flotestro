//go:build integration

package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The support bundle of the panel (security remediation, chapter 14.6): it is
// asked for with a reason and fresh authentication, fetched through a link
// that expires and is spent once, and it lies encrypted while it waits.

type supportBundleView struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	Reason        string `json:"reason"`
	RequestedBy   string `json:"requested_by"`
	ErrorCode     string `json:"error_code"`
	Files         int    `json:"files"`
	SizeBytes     int64  `json:"size_bytes"`
	ArchiveSHA256 string `json:"archive_sha256"`
	Scanned       bool   `json:"scanned"`
	Downloadable  bool   `json:"downloadable"`
	Downloads     int    `json:"downloads"`
}

type supportLink struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// askForBundle orders a bundle and waits until it is sealed.
func askForBundle(t *testing.T, h *harness, reason string) supportBundleView {
	t.Helper()
	var bundle supportBundleView
	h.do(http.MethodPost, "/api/v1/support/bundles", map[string]any{"reason": reason},
		&bundle, http.StatusAccepted)
	if bundle.ID == "" {
		t.Fatal("the panel accepted the request without naming a bundle")
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		var current supportBundleView
		h.get("/api/v1/support/bundles/"+bundle.ID, &current)
		switch current.State {
		case "ready":
			return current
		case "failed":
			t.Fatalf("the bundle was refused: %s", current.ErrorCode)
		}
		time.Sleep(time.Second)
	}
	t.Fatal("the bundle was still being assembled after 90 seconds")
	return bundle
}

// fetch follows a link and returns what came back.
func (h *harness) fetch(path string) (int, []byte) {
	h.t.Helper()
	request, err := http.NewRequest(http.MethodGet, h.api+path, nil)
	if err != nil {
		h.t.Fatalf("building the request: %v", err)
	}
	if h.token != "" {
		request.Header.Set("Authorization", "Bearer "+h.token)
	}
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, body
}

// TestASupportBundleNeedsAReasonAndAnExpiringLink is the negative of the gap:
// without the change there is no panel-side bundle at all, and with it there
// is none that can be fetched without a link the panel issued.
func TestASupportBundleNeedsAReasonAndAnExpiringLink(t *testing.T) {
	h := newHarness(t)

	// A request without a reason is refused before anything is read: the
	// step-up of the panel demands one.
	h.do(http.MethodPost, "/api/v1/support/bundles", map[string]any{}, nil, http.StatusBadRequest)

	bundle := askForBundle(t, h, "a support case was opened for this panel")
	if bundle.Files == 0 || bundle.SizeBytes == 0 || !bundle.Scanned || bundle.ArchiveSHA256 == "" {
		t.Fatalf("the bundle does not describe itself: %+v", bundle)
	}
	if !bundle.Downloadable {
		t.Fatalf("a ready bundle is not offered for download: %+v", bundle)
	}

	// The archive is not fetched by naming it: the link is the authorisation.
	if status, _ := h.fetch("/api/v1/support/bundles/" + bundle.ID + "/archive"); status != http.StatusUnauthorized {
		t.Fatalf("the archive was served without a link: status %d", status)
	}
	if status, _ := h.fetch("/api/v1/support/bundles/" + bundle.ID + "/archive?token=fltsb_invented"); status != http.StatusUnauthorized {
		t.Fatalf("an invented link was accepted: status %d", status)
	}

	// Asking for a link is a step-up of its own.
	h.do(http.MethodPost, "/api/v1/support/bundles/"+bundle.ID+"/download",
		map[string]any{}, nil, http.StatusBadRequest)

	var link supportLink
	h.do(http.MethodPost, "/api/v1/support/bundles/"+bundle.ID+"/download",
		map[string]any{"reason": "handing the bundle to support"}, &link, http.StatusCreated)
	if link.URL == "" {
		t.Fatal("the panel issued no link")
	}
	if window := time.Until(link.ExpiresAt); window <= 0 || window > 15*time.Minute {
		t.Fatalf("the link lasts %s, which is not a short window", window)
	}

	status, archive := h.fetch(link.URL)
	if status != http.StatusOK {
		t.Fatalf("the link did not open the bundle: status %d", status)
	}
	files := readSupportArchive(t, archive)
	if _, present := files["manifest.json"]; !present {
		t.Fatalf("the archive has no manifest; it holds %d file(s)", len(files))
	}
	for name, content := range files {
		if strings.Contains(string(content), "-----BEGIN") {
			t.Fatalf("%s carries a key block", name)
		}
	}

	// One link, one fetch.
	if status, _ := h.fetch(link.URL); status != http.StatusUnauthorized {
		t.Fatalf("the same link opened the bundle twice: status %d", status)
	}
}

// TestASupportBundleLinkExpires ages a link in the database rather than
// waiting for it: what matters is that the panel refuses one whose window has
// passed, not how long the window is.
func TestASupportBundleLinkExpires(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	bundle := askForBundle(t, h, "checking that a stale link opens nothing")
	var link supportLink
	h.do(http.MethodPost, "/api/v1/support/bundles/"+bundle.ID+"/download",
		map[string]any{"reason": "handing the bundle to support"}, &link, http.StatusCreated)

	if _, err := pool.Exec(ctx, `
		update support_bundle_tokens set expires_at = now() - interval '1 minute'
		 where bundle_id = $1::uuid and redeemed_at is null`, bundle.ID); err != nil {
		t.Fatalf("ageing the link: %v", err)
	}
	if status, body := h.fetch(link.URL); status != http.StatusUnauthorized {
		t.Fatalf("an expired link opened the bundle: status %d, body %s", status, truncate(body, 200))
	}
}

// TestASupportBundleAtRestIsNotAnArchive reads the row the way a copy of the
// database would: there is no column holding a readable bundle.
func TestASupportBundleAtRestIsNotAnArchive(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	bundle := askForBundle(t, h, "checking that the bundle rests encrypted")

	var ciphertext []byte
	var keyID string
	var envelope int
	if err := pool.QueryRow(ctx, `
		select ciphertext, key_id, envelope_version from support_bundles where id = $1::uuid`,
		bundle.ID).Scan(&ciphertext, &keyID, &envelope); err != nil {
		t.Fatalf("reading the row: %v", err)
	}
	if len(ciphertext) == 0 || keyID == "" || envelope == 0 {
		t.Fatalf("the row carries no envelope: %d bytes under key %q, version %d", len(ciphertext), keyID, envelope)
	}
	if _, err := gzip.NewReader(bytes.NewReader(ciphertext)); err == nil {
		t.Fatal("the bundle lies in the database as a plain archive")
	}
	if bytes.Contains(ciphertext, []byte("manifest.json")) {
		t.Fatal("the names of the files in the bundle are readable in the database")
	}
}

// readSupportArchive unpacks a downloaded bundle.
func readSupportArchive(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	uncompressed, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("the downloaded bundle is not a gzip archive: %v", err)
	}
	defer uncompressed.Close()
	files := map[string][]byte{}
	reader := tar.NewReader(uncompressed)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatalf("reading the archive: %v", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("reading %s: %v", header.Name, err)
		}
		name := header.Name
		if _, rest, found := strings.Cut(name, "/"); found {
			name = rest
		}
		files[name] = content
	}
}
