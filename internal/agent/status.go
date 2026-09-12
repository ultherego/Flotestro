package agent

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ultherego/flotestro/internal/identitystore"
)

// StateFileName is the file in which the agent writes what is happening with
// it.
const StateFileName = "status.json"

// AgentState is the picture of the work of the agent as seen from outside the
// process.
//
// Without it a diagnostic tool can say only as much as the file system shows:
// that the certificate exists and that the service is running. An operator on
// the host without the panel needs an answer to a different question - whether
// the agent really talks to the panel and when it last sent anything.
type AgentState struct {
	AgentVersion string `json:"agent_version"`
	HostID       string `json:"host_id,omitempty"`
	// Gateway is the address the agent talks to in this session.
	Gateway string `json:"gateway,omitempty"`
	// ConnectedAt is empty when there is no session. LastError is what counts
	// then.
	ConnectedAt       *time.Time `json:"connected_at,omitempty"`
	DisconnectedAt    *time.Time `json:"disconnected_at,omitempty"`
	LastInventoryAt   *time.Time `json:"last_inventory_at,omitempty"`
	InventoryRevision string     `json:"inventory_revision,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// StateWriter persists the state of the agent between session events.
type StateWriter struct {
	path  string
	mu    sync.Mutex
	state AgentState
}

// NewStateWriter creates a writer in the state directory of the agent. An empty
// directory turns the write off: the fleet simulator has no reason to write a
// thousand files.
func NewStateWriter(stateDir, hostID string) *StateWriter {
	if stateDir == "" {
		return nil
	}
	return &StateWriter{
		path:  filepath.Join(stateDir, StateFileName),
		state: AgentState{AgentVersion: Version, HostID: hostID},
	}
}

// Connected records an established session.
func (w *StateWriter) Connected(gateway string, moment time.Time) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	momentUTC := moment.UTC()
	w.state.Gateway = gateway
	w.state.ConnectedAt = &momentUTC
	w.state.DisconnectedAt = nil
	w.state.LastError = ""
	w.write()
}

// Disconnected records the end of a session together with the reason.
func (w *StateWriter) Disconnected(reason string, moment time.Time) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	momentUTC := moment.UTC()
	w.state.ConnectedAt = nil
	w.state.DisconnectedAt = &momentUTC
	w.state.LastError = reason
	w.write()
}

// Inventory records a report that was sent.
func (w *StateWriter) Inventory(revision string, moment time.Time) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	momentUTC := moment.UTC()
	w.state.LastInventoryAt = &momentUTC
	w.state.InventoryRevision = revision
	w.write()
}

// write persists the state through a temporary file and a rename.
//
// An interrupted write must not leave half a file: a diagnostic tool would then
// read a syntax error instead of a state, and that would look like a failure of
// the agent that is not there.
func (w *StateWriter) write() {
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

// ReadState reads the state written by the agent.
func ReadState(stateDir string) (AgentState, error) {
	var state AgentState
	content, err := os.ReadFile(filepath.Join(stateDir, StateFileName))
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(content, &state); err != nil {
		return state, err
	}
	return state, nil
}

// StoredIdentity describes the identity stored on the host.
//
// Also when the certificate has expired or is unreadable: the status is to say
// so and not to fall silent. Silence looks the same as a host without a
// problem.
type StoredIdentity struct {
	Paths    IdentityPaths
	Present  bool
	HostID   string
	NotAfter time.Time
	Expired  bool
	Err      string
}

// ReadIdentity reads the identity from the state directory without any
// connection.
//
// First the generation store, then the old file layout: the tool on the host is
// to answer the same way before a migration and after it.
func ReadIdentity(stateDir string) StoredIdentity {
	store := identitystore.New(stateDir)
	if identity, err := store.Current(); err == nil {
		return StoredIdentity{
			Paths: IdentityPaths{
				Key:  filepath.Join(identity.Dir, identitystore.KeyName),
				Cert: filepath.Join(identity.Dir, identitystore.CertificateName),
				CA:   filepath.Join(identity.Dir, identitystore.TrustName),
			},
			Present:  true,
			HostID:   identity.HostID,
			NotAfter: identity.NotAfter,
			Expired:  time.Now().After(identity.NotAfter),
		}
	}

	identityPaths := paths(stateDir)
	state := StoredIdentity{Paths: identityPaths}

	certPEM, err := os.ReadFile(identityPaths.Cert)
	if err != nil {
		state.Err = err.Error()
		return state
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		state.Err = "the certificate is not valid PEM"
		return state
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		state.Err = err.Error()
		return state
	}
	state.Present = true
	state.HostID = certificate.Subject.CommonName
	state.NotAfter = certificate.NotAfter
	state.Expired = time.Now().After(certificate.NotAfter)
	return state
}
