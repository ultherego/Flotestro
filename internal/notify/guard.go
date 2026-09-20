package notify

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ultherego/flotestro/internal/config"
)

// CodeAddressNotAllowed: the channel leads where the panel does not send - its
// own loopback, a metadata service, the network the installation runs in.
const CodeAddressNotAllowed = "channel_address_not_allowed"

// AllowEnv names the networks a channel may reach although the guard refuses
// them by default, as a comma-separated list of CIDRs.
const AllowEnv = "FLOTESTRO_NOTIFY_ALLOW"

// maxRedirects bounds the hops of one delivery.
const maxRedirects = 5

// reservedCIDRs are the ranges the stdlib predicates do not name: carrier-grade
// NAT, protocol assignments, documentation, and the IPv6 ways into IPv4.
var reservedCIDRs = parseNetworks(
	"100.64.0.0/10,192.0.0.0/24,192.0.2.0/24,198.18.0.0/15,198.51.100.0/24," +
		"203.0.113.0/24,240.0.0.0/4,64:ff9b::/96,2002::/16")

// allowedNetworks is the installation's exception list, read once.
var allowedNetworks = sync.OnceValue(func() []*net.IPNet {
	return parseNetworks(config.Env(AllowEnv, ""))
})

// parseNetworks reads a comma-separated list of CIDRs; an entry that does not
// read is dropped rather than widening the guard.
func parseNetworks(list string) []*net.IPNet {
	var networks []*net.IPNet
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			networks = append(networks, network)
		}
	}
	return networks
}

// allowedAddress says whether the installation declared this address its own
// receiver's.
func allowedAddress(ip net.IP) bool {
	for _, network := range allowedNetworks() {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// addressRefusal names why a notification may not go to the address, and is
// empty for one the panel may reach.
func addressRefusal(ip net.IP) string {
	if ip == nil {
		return "not an address"
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsUnspecified():
		return "the unspecified address"
	case ip.IsLoopback():
		return "a loopback address, which is the panel itself"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "a link-local address, where the cloud metadata service answers"
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return "a multicast address"
	case ip.IsPrivate():
		return "a private address inside the installation's own network"
	}
	for _, network := range reservedCIDRs {
		if network.Contains(ip) {
			return "an address of a reserved range"
		}
	}
	return ""
}

// checkDialAddress judges the address about to be connected to. It runs on the
// dialer's Control hook, so it sees what was resolved, not what was typed.
func checkDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return SendError{Code: CodeAddressNotAllowed, Err: errors.New("the connection has no address to judge")}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return SendError{Code: CodeAddressNotAllowed, Err: errors.New("the address of the channel did not resolve to an IP")}
	}
	if allowedAddress(ip) {
		return nil
	}
	if reason := addressRefusal(ip); reason != "" {
		// The sentence names the kind of address and never the address: the
		// address of an incoming webhook is the credential.
		return SendError{Code: CodeAddressNotAllowed,
			Err: errors.New("the channel leads to " + reason + "; a receiver of this installation is declared in " + AllowEnv)}
	}
	return nil
}

// checkRedirect follows the receiver's own redirect and no further: a hop to
// another host would carry the signed body somewhere nobody wrote down.
func checkRedirect(request *http.Request, previous []*http.Request) error {
	if len(previous) >= maxRedirects {
		return SendError{Code: CodeAddressNotAllowed, Err: errors.New("the receiver redirects in a loop")}
	}
	if len(previous) > 0 && request.URL.Host != previous[0].URL.Host {
		return SendError{Code: CodeAddressNotAllowed, Err: errors.New("the receiver redirects to another host")}
	}
	return nil
}

// guardedClient is the client every channel is delivered through.
func guardedClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   sendTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddress(address)
		},
	}
	return &http.Client{
		Timeout: sendTimeout,
		Transport: &http.Transport{
			// The proxy of the environment stays in use: it is the installation's
			// declared way out, and removing it would silently strand a delivery.
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: checkRedirect,
	}
}

// defaultClient is what a sender built without one delivers through: guarded,
// because an unguarded fallback is the hole this file closes.
var defaultClient = sync.OnceValue(guardedClient)
