// Package local lets a feed be read from the panel's own disk. An installation
// cut off from the Internet still has to assess its hosts.
package local

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Transport answers file:// requests from the filesystem and hands every
// other scheme to the wrapped transport (the default one when nil).
type Transport struct {
	Next http.RoundTripper
}

// Client builds an HTTP client that understands file:// on top of the
// usual schemes.
func Client(limit time.Duration) *http.Client {
	return &http.Client{Timeout: limit, Transport: &Transport{}}
}

func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "file" {
		next := t.Next
		if next == nil {
			next = http.DefaultTransport
		}
		return next.RoundTrip(request)
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return reply(request, http.StatusMethodNotAllowed, nil, nil), nil
	}

	// A file address keeps its path in the URL; a host part, as in
	// file://localhost/.
	path := filepath.Clean(request.URL.Path)
	if path == "" || path == "." {
		return reply(request, http.StatusNotFound, nil, nil), nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return reply(request, http.StatusNotFound, nil, nil), nil
		}
		return nil, err
	}
	if info.IsDir() {
		// A directory answers like a plain listing of names, one per line: the
		// sources that walk a tree read the index the vendor serves, and a copied
		// tree has none.
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		var listing bytes.Buffer
		for _, entry := range entries {
			listing.WriteString(entry.Name())
			listing.WriteString("\n")
		}
		return reply(request, http.StatusOK, listing.Bytes(), map[string]string{
			"Content-Type": "text/plain; charset=utf-8",
		}), nil
	}

	// The tag is the size and the modification time: the same file gives the same
	// tag, so a conditional fetch of an unchanged copy costs nothing, exactly as
	// with the remote feed.
	tag := fmt.Sprintf(`"%x-%x"`, info.Size(), info.ModTime().UnixNano())
	if match := request.Header.Get("If-None-Match"); match != "" && match == tag {
		return reply(request, http.StatusNotModified, nil, map[string]string{"ETag": tag}), nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		"ETag":          tag,
		"Last-Modified": info.ModTime().UTC().Format(http.TimeFormat),
		"Content-Type":  contentType(path),
	}
	response := reply(request, http.StatusOK, nil, headers)
	response.Body = file
	response.ContentLength = info.Size()
	return response, nil
}

// contentType guesses from the name; the sources decide by content anyway.
func contentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".bz2":
		return "application/x-bzip2"
	case ".gz":
		return "application/gzip"
	}
	return "application/octet-stream"
}

func reply(request *http.Request, status int, body []byte, headers map[string]string) *http.Response {
	response := &http.Response{
		StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)), Request: request,
	}
	for name, value := range headers {
		response.Header.Set(name, value)
	}
	return response
}
