package agentconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// Fingerprint digests the effective configuration: what the agent runs on
// once the defaults filled in what the file left out and the durations
// were read.
//
// The digest is of the meaning, not of the bytes. Two files that differ in
// comments, in the order of their keys, in spacing, or in writing a
// default out against leaving it to the parser configure the same agent
// and get the same fingerprint, so the panel groups hosts by what they
// run on rather than by how somebody typed it. The canonical form is a
// fixed sequence of the effective fields; a field added to the
// configuration changes the fingerprint of every host, which is the
// truth - they run on a different configuration than before.
func (c Config) Fingerprint() string {
	canonical := struct {
		SchemaVersion      int      `json:"schema_version"`
		EnrollmentURL      string   `json:"enrollment_url"`
		GatewayURLs        []string `json:"gateway_urls"`
		BootstrapCA        string   `json:"bootstrap_ca_file"`
		ConnectTimeout     string   `json:"connect_timeout"`
		ReconnectMin       string   `json:"reconnect_min"`
		ReconnectMax       string   `json:"reconnect_max"`
		StateDir           string   `json:"state_dir"`
		InventoryInterval  string   `json:"inventory_interval"`
		MaxConcurrentTasks int      `json:"max_concurrent_tasks"`
		Mode               string   `json:"mode"`
		HelperSocket       string   `json:"helper_socket"`
	}{
		SchemaVersion: c.SchemaVersion,
		EnrollmentURL: c.Connection.EnrollmentURL,
		// The gateways keep their order: it is the order of priority, and
		// a list turned around configures a different first choice.
		GatewayURLs:        append([]string{}, c.Connection.GatewayURLs...),
		BootstrapCA:        c.Connection.BootstrapCA,
		ConnectTimeout:     c.Connection.ConnectTimeout.String(),
		ReconnectMin:       c.Connection.ReconnectMin.String(),
		ReconnectMax:       c.Connection.ReconnectMax.String(),
		StateDir:           c.Agent.StateDir,
		InventoryInterval:  c.Agent.InventoryInterval.String(),
		MaxConcurrentTasks: c.Agent.MaxConcurrentTasks,
		Mode:               c.Agent.Mode,
		HelperSocket:       c.Helper.Socket,
	}
	// A struct of strings, ints and a string slice always marshals; the
	// error is left unread rather than turned into a fingerprint of
	// nothing.
	encoded, _ := json.Marshal(canonical)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// Loaded describes the configuration file the agent runs on, as the agent
// reports it to the panel: the schema of the file on disk and the
// fingerprint of the effective configuration.
type Loaded struct {
	Path          string
	SchemaVersion int
	Fingerprint   string
}

var (
	loadedMu sync.RWMutex
	loaded   *Loaded
)

// Current returns the configuration file this process loaded. False means
// no file was loaded: the agent runs on the environment variables of the
// old flow, and has no file to fingerprint and no schema to report.
//
// The record is kept here rather than passed down, because the file is
// read once at the start, in the command, and the session that reports it
// opens and closes many times over the life of the process.
func Current() (Loaded, bool) {
	loadedMu.RLock()
	defer loadedMu.RUnlock()
	if loaded == nil {
		return Loaded{}, false
	}
	return *loaded, true
}

// remember records the file Load read, for Current.
func remember(path string, cfg Config) {
	loadedMu.Lock()
	loaded = &Loaded{Path: path, SchemaVersion: cfg.SchemaVersion, Fingerprint: cfg.Fingerprint()}
	loadedMu.Unlock()
}
