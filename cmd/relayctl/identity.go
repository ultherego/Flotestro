package main

import (
	"crypto/x509"
	"flag"
	"io"
	"time"

	"github.com/ultherego/flotestro/internal/identitystore"
	"github.com/ultherego/flotestro/internal/relayconfig"
)

// storedIdentity describes the identity of the relay stored on the machine.
//
// Also when the certificate has expired or is unreadable: the status is to
// say so and not to fall silent. Silence looks the same as a relay without a
// problem.
type storedIdentity struct {
	Present bool
	RelayID string
	// Subject is the common name of the certificate: the name the relay was
	// registered under.
	Subject string
	// Serial is the decimal serial of the certificate, the form the panel
	// shows next to the relay.
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	Expired   bool
	// Names are the network names the certificate is valid for.
	Names    []string
	TrustPEM []byte
	Dir      string
	Err      string
}

// readIdentity reads the identity from the state directory without any
// connection.
func readIdentity(stateDir string) storedIdentity {
	return readIdentityAt(stateDir, time.Now())
}

func readIdentityAt(stateDir string, now time.Time) storedIdentity {
	identity, err := identitystore.New(stateDir).Current()
	if err != nil {
		return storedIdentity{Err: err.Error()}
	}
	state := storedIdentity{
		Present:   true,
		RelayID:   identity.HostID,
		NotBefore: identity.NotBefore,
		NotAfter:  identity.NotAfter,
		Expired:   now.After(identity.NotAfter),
		TrustPEM:  identity.TrustPEM,
		Dir:       identity.Dir,
	}
	if len(identity.Certificate.Certificate) > 0 {
		if leaf, parseErr := x509.ParseCertificate(identity.Certificate.Certificate[0]); parseErr == nil {
			state.Subject = leaf.Subject.CommonName
			state.Serial = leaf.SerialNumber.String()
			state.Names = append(state.Names, leaf.DNSNames...)
			for _, address := range leaf.IPAddresses {
				state.Names = append(state.Names, address.String())
			}
		}
	}
	return state
}

// configurationPath reads the shared --config flag.
func configurationPath(name string, args []string, errOut io.Writer) (string, bool) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", relayconfig.DefaultPath, "the configuration file of the relay")
	if err := flags.Parse(args); err != nil {
		return "", false
	}
	return *path, true
}
