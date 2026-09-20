package notify

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The guard names the addresses a notification never goes to: the panel
// itself, the metadata services, the network the installation runs in.
func TestTheGuardRefusesTheAddressesInsideTheInstallation(t *testing.T) {
	refused := []string{
		"127.0.0.1", "::1", "0.0.0.0", "::",
		"169.254.169.254", "fe80::1", // the metadata service of AWS, GCP, Azure
		"100.100.100.200", // the metadata service of Alibaba
		"10.1.2.3", "192.168.1.5", "172.16.0.9", "fd00::1",
		"::ffff:127.0.0.1", "::ffff:10.1.2.3", // the same addresses written as IPv6
		"224.0.0.1", "255.255.255.255", "192.0.0.1", "198.18.0.1",
	}
	for _, address := range refused {
		if reason := addressRefusal(net.ParseIP(address)); reason == "" {
			t.Errorf("%s is reachable", address)
		}
	}
	for _, address := range []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"} {
		if reason := addressRefusal(net.ParseIP(address)); reason != "" {
			t.Errorf("the public address %s is refused as %s", address, reason)
		}
	}
}

// An installation declares the network its own receivers sit on, and nothing
// else is opened by it.
func TestTheDeclaredNetworkIsTheOnlyWayIn(t *testing.T) {
	restore := allowedNetworks
	allowedNetworks = func() []*net.IPNet { return parseNetworks("10.0.0.0/8, not-a-cidr") }
	defer func() { allowedNetworks = restore }()

	if err := checkDialAddress("10.4.5.6:443"); err != nil {
		t.Errorf("the declared network was refused: %v", err)
	}
	var failure SendError
	if err := checkDialAddress("192.168.1.5:443"); !asSendError(err, &failure) || failure.Code != CodeAddressNotAllowed {
		t.Errorf("a private address outside the declared network was typed as %v", err)
	}
	if err := checkDialAddress("169.254.169.254:80"); !asSendError(err, &failure) || failure.Code != CodeAddressNotAllowed {
		t.Errorf("the metadata address was typed as %v", err)
	}
	// The sentence reaches the delivery log, which is read by people the
	// address of an incoming webhook is kept from.
	if strings.Contains(failure.Error(), "169.254") {
		t.Errorf("the refusal carries the address: %s", failure.Error())
	}
}

// The client the router delivers through carries the guard: a channel
// pointed at the panel's own loopback sends nothing.
func TestTheDeliveryClientRefusesTheLoopback(t *testing.T) {
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer server.Close()

	channel := Channel{ID: "c", Name: "hook", Kind: KindWebhook,
		Config: json.RawMessage(`{"url":"` + server.URL + `","secret":"secret"}`)}
	err := (WebhookSender{Client: guardedClient()}).Send(context.Background(), channel, Message{Title: "x"})
	var failure SendError
	if !asSendError(err, &failure) || failure.Code != CodeAddressNotAllowed {
		t.Fatalf("a channel pointed at the loopback was typed as %v", err)
	}
	if reached {
		t.Error("the request reached the receiver")
	}
	if outcome := Classify(err, 1, 20); outcome.State != StateDeadLetter {
		t.Errorf("the refusal was left to be retried: %+v", outcome)
	}
}

// A redirect is the second hop of the same address, not a way to another
// one: the signed body stays with the receiver it was written for.
func TestARedirectStaysWithTheReceiver(t *testing.T) {
	first := &http.Request{URL: mustURL(t, "https://hooks.example.com/a")}
	if err := checkRedirect(&http.Request{URL: mustURL(t, "https://hooks.example.com/b")},
		[]*http.Request{first}); err != nil {
		t.Errorf("a hop within the receiver was refused: %v", err)
	}
	var failure SendError
	err := checkRedirect(&http.Request{URL: mustURL(t, "http://169.254.169.254/latest/meta-data/")},
		[]*http.Request{first})
	if !asSendError(err, &failure) || failure.Code != CodeAddressNotAllowed {
		t.Errorf("a hop to another host was typed as %v", err)
	}
	hops := make([]*http.Request, maxRedirects)
	for i := range hops {
		hops[i] = first
	}
	if err := checkRedirect(first, hops); err == nil {
		t.Error("a redirect loop was followed")
	}
}

// What can be judged where it is typed is refused there: the panel says no to
// the address rather than writing a channel that only ever dead-letters.
func TestValidationRefusesAnAddressInsideTheInstallation(t *testing.T) {
	refused := []string{
		`{"url":"http://127.0.0.1:9000/hook","secret":"s"}`,
		`{"url":"http://localhost:9000/hook","secret":"s"}`,
		`{"url":"http://panel.localhost/hook","secret":"s"}`,
		`{"url":"http://169.254.169.254/latest/meta-data/","secret":"s"}`,
		`{"url":"http://[::1]:9000/hook","secret":"s"}`,
		`{"url":"http://10.1.2.3/hook","secret":"s"}`,
	}
	for _, config := range refused {
		channel := Channel{Name: "hook", Kind: KindWebhook, Config: json.RawMessage(config)}
		var refusal Error
		if _, err := channel.Validate(); !asError(err, &refusal) || refusal.Code != CodeAddressNotAllowed {
			t.Errorf("%s was refused as %v", config, err)
		}
	}
	// A name is not judged here: what it answers is only true at the dial.
	channel := Channel{Name: "hook", Kind: KindWebhook,
		Config: json.RawMessage(`{"url":"https://hooks.example.com/a","secret":"s"}`)}
	if _, err := channel.Validate(); err != nil {
		t.Errorf("a sound webhook was refused: %v", err)
	}
}

// A webhook is signed or it is not written: an empty key is a legal key, and
// the header it produces is one anybody can compute.
func TestAWebhookWithoutASigningSecretIsRefused(t *testing.T) {
	channel := Channel{Name: "hook", Kind: KindWebhook,
		Config: json.RawMessage(`{"url":"https://hooks.example.com/a"}`)}
	var refusal Error
	if _, err := channel.Validate(); !asError(err, &refusal) || refusal.Code != CodeWebhookSecretRequired {
		t.Errorf("a secretless webhook was refused as %v", err)
	}
	// An edit that keeps the stored secret types none, and is not a
	// secretless channel.
	kept := Channel{Name: "hook", Kind: KindWebhook,
		Config: json.RawMessage(`{"url":"https://hooks.example.com/a","secret_set":true}`)}
	if _, err := kept.Validate(); err != nil {
		t.Errorf("an edit that keeps the stored secret was refused: %v", err)
	}
}

func mustURL(t *testing.T, address string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(address)
	if err != nil {
		t.Fatalf("the test address %q does not parse: %v", address, err)
	}
	return parsed
}
