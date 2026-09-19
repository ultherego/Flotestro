package ctl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RelayStateFileName is the file in which the relay writes what is
// happening with it.
const RelayStateFileName = "status.json"

// RelayState is the picture of the work of a relay as seen from outside the
// process.
type RelayState struct {
	RelayVersion string `json:"relay_version"`
	RelayID      string `json:"relay_id,omitempty"`
	// Gateway is the address of the centre the relay speaks to now.
	Gateway string `json:"gateway,omitempty"`
	Listen  string `json:"listen,omitempty"`
	// Sessions counts the agents connected to the relay.
	Sessions int `json:"sessions"`
	// The buffer of results waiting for the link to come back.
	BufferBytes    int64 `json:"buffer_bytes"`
	BufferMaxBytes int64 `json:"buffer_max_bytes"`
	BufferedItems  int   `json:"buffered_items"`
	BufferDropped  int64 `json:"buffer_dropped"`
	// BufferingSince says when the buffer last went from empty to holding
	// something.
	BufferingSince *time.Time `json:"buffering_since,omitempty"`
	// UpstreamOK says whether the last contact with the centre succeeded.
	UpstreamOK bool `json:"upstream_ok"`
	// LastUpstreamAt is the last confirmed contact with the centre.
	LastUpstreamAt      *time.Time `json:"last_upstream_at,omitempty"`
	LastUpstreamError   string     `json:"last_upstream_error,omitempty"`
	LastUpstreamErrorAt *time.Time `json:"last_upstream_error_at,omitempty"`
	// CentreSessions is how many sessions the centre sees through this relay, as
	// reported at the last contact.
	CentreSessions      *int      `json:"centre_sessions,omitempty"`
	CertificateNotAfter time.Time `json:"certificate_not_after"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// RelayStateWriter persists the state of the relay between events.
type RelayStateWriter struct {
	path  string
	mu    sync.Mutex
	state RelayState
}

// NewRelayStateWriter creates a writer in the state directory of the relay.
// An empty directory turns the write off.
func NewRelayStateWriter(stateDir, relayID, version string) *RelayStateWriter {
	if stateDir == "" {
		return nil
	}
	return &RelayStateWriter{
		path:  filepath.Join(stateDir, RelayStateFileName),
		state: RelayState{RelayVersion: version, RelayID: relayID},
	}
}

// Update changes the state under the lock and writes it.
func (w *RelayStateWriter) Update(change func(*RelayState)) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	change(&w.state)
	w.write()
}

// Snapshot returns a copy of the state as last written.
func (w *RelayStateWriter) Snapshot() RelayState {
	if w == nil {
		return RelayState{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

// write persists the state through a temporary file and a rename.
func (w *RelayStateWriter) write() {
	w.state.UpdatedAt = time.Now().UTC()
	content, err := json.MarshalIndent(w.state, "", "  ")
	if err != nil {
		return
	}
	temporary := w.path + ".tmp"
	if err := os.WriteFile(temporary, append(content, '\n'), 0o640); err != nil {
		return
	}
	_ = os.Rename(temporary, w.path)
}

// ReadRelayState reads the state written by the relay.
func ReadRelayState(stateDir string) (RelayState, error) {
	var state RelayState
	content, err := os.ReadFile(filepath.Join(stateDir, RelayStateFileName))
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(content, &state); err != nil {
		return state, err
	}
	return state, nil
}
