package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// certificateFrom creates a certificate with the given validity period.
func certificateFrom(t *testing.T, from, to time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay"},
		NotBefore:    from,
		NotAfter:     to,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestRenewalBeforeTheLastThird guards the property this threshold exists for
// at all: the relay has time for retries while the centre is unreachable
// rather than one attempt in the last hour of validity.
func TestRenewalBeforeTheLastThird(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		from, to time.Time
		expected bool
	}{
		{"fresh", now.Add(-time.Hour), now.Add(7 * 24 * time.Hour), false},
		{"half its life", now.Add(-84 * time.Hour), now.Add(84 * time.Hour), false},
		{"the last third", now.Add(-6 * 24 * time.Hour), now.Add(24 * time.Hour), true},
		{"expired", now.Add(-8 * 24 * time.Hour), now.Add(-time.Hour), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			identity := Identity{
				Certificate: certificateFrom(t, c.from, c.to),
				NotAfter:    c.to,
			}
			if got := needsRenewal(identity); got != c.expected {
				t.Fatalf("needsRenewal = %v, expected %v", got, c.expected)
			}
		})
	}
}

// TestAnUnknownDeadlineIsAReason guards the rule that unknown is not zero: a
// certificate without a readable deadline must not mean "still a long way
// off".
func TestAnUnknownDeadlineIsAReason(t *testing.T) {
	if !needsRenewal(Identity{}) {
		t.Fatal("an identity without a deadline does not need a renewal")
	}
}

// TestTheSwapIsVisibleAtOnce guards what this identity is live for: the
// listener reaches for the certificate at every handshake, so a renewal
// requires no restart of the process and does not tear down the sessions of
// the agents of the site.
func TestTheSwapIsVisibleAtOnce(t *testing.T) {
	old := certificateFrom(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	fresh := certificateFrom(t, time.Now(), time.Now().Add(7*24*time.Hour))
	live := NewLive(Identity{RelayID: "r1", Certificate: old})

	before, err := live.Certificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	live.Swap(Identity{RelayID: "r1", Certificate: fresh})
	after, err := live.Certificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(before.Certificate[0]) == string(after.Certificate[0]) {
		t.Fatal("the listener still hands out the old certificate")
	}
}

// TestTheIntervalStaysWithinTheLimits guards that the jitter spreads the
// relays out without letting the checking outside sensible limits.
func TestTheIntervalStaysWithinTheLimits(t *testing.T) {
	now := time.Now()
	identity := Identity{
		Certificate: certificateFrom(t, now, now.Add(7*24*time.Hour)),
		NotAfter:    now.Add(7 * 24 * time.Hour),
	}
	for i := 0; i < 50; i++ {
		interval := checkInterval(identity)
		if interval < minCheckInterval || interval > maxCheckInterval {
			t.Fatalf("the interval %s is outside the limits", interval)
		}
	}
}

// TestTheNetworkNames guards that an IP address lands in the SAN as an
// address. Written as a DNS name it would look correct, and an agent
// connecting by the address would reject the certificate anyway.
func TestTheNetworkNames(t *testing.T) {
	dns, addresses := splitNames([]string{"relay-waw-01.example.com", "192.168.56.70"})
	if len(dns) != 1 || dns[0] != "relay-waw-01.example.com" {
		t.Fatalf("DNS names = %v", dns)
	}
	if len(addresses) != 1 || addresses[0].String() != "192.168.56.70" {
		t.Fatalf("addresses = %v", addresses)
	}
}
