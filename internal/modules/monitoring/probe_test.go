package monitoring

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTheRequestValidatesTheTarget(t *testing.T) {
	good := []Request{
		{Kind: ProbeHTTP, Target: "https://service.example.test/health"},
		{Kind: ProbeHTTP, Target: "http://10.0.0.5:8080/", ExpectStatus: 204},
		{Kind: ProbeTCP, Target: "database.example.test:5432"},
	}
	for _, request := range good {
		if err := request.Validate(); err != nil {
			t.Errorf("a valid request %+v was rejected: %v", request, err)
		}
	}

	bad := map[string]Request{
		// The probe speaks HTTP; "file://" is not a check of a service but a
		// read of the host with somebody else's hands.
		"a local file":           {Kind: ProbeHTTP, Target: "file:///etc/shadow"},
		"another protocol":       {Kind: ProbeHTTP, Target: "gopher://service.example.test"},
		"an empty target":        {Kind: ProbeHTTP, Target: ""},
		"tcp without a port":     {Kind: ProbeTCP, Target: "database.example.test"},
		"an unknown kind":        {Kind: "icmp", Target: "10.0.0.1"},
		"a code out of range":    {Kind: ProbeHTTP, Target: "https://a.test", ExpectStatus: 9000},
		"a timeout out of range": {Kind: ProbeTCP, Target: "a.test:1", TimeoutSeconds: 3600},
		"a target with a space":  {Kind: ProbeTCP, Target: "a.test:1 b"},
	}
	for name, request := range bad {
		if err := request.Validate(); err == nil {
			t.Errorf("%s: the request was accepted", name)
		}
	}
}

func TestTheHTTPProbeTellsReachabilityFromExpectations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte("everything works"))
	}))
	defer server.Close()

	// The service answers as expected.
	result := Run(context.Background(), Request{
		Kind: ProbeHTTP, Target: server.URL, ExpectBody: "works",
	})
	if !result.Reachable || !result.Passed {
		t.Fatalf("a valid answer was described as %+v", result)
	}
	if result.StatusCode == nil || *result.StatusCode != 200 {
		t.Fatalf("response code = %v", result.StatusCode)
	}

	// The service answers, but not as expected - these are two different things
	// and have to be told apart, because they lead to different decisions.
	badCode := Run(context.Background(), Request{Kind: ProbeHTTP, Target: server.URL + "/error"})
	if !badCode.Reachable {
		t.Fatal("a 500 answer was described as no answer")
	}
	if badCode.Passed || badCode.Error == "" {
		t.Fatalf("a 500 answer was described as valid: %+v", badCode)
	}

	missingFragment := Run(context.Background(), Request{
		Kind: ProbeHTTP, Target: server.URL, ExpectBody: "there is nothing like that there",
	})
	if missingFragment.Passed {
		t.Fatal("an answer without the expected fragment was taken for valid")
	}
	if missingFragment.BodyMatched == nil || *missingFragment.BodyMatched {
		t.Fatalf("the body match was described as %v", missingFragment.BodyMatched)
	}
}

func TestTheHTTPProbeDoesNotTrustACertificateOutsideTheStore(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	// The probe does not switch the certificate check off: a service with a
	// certificate the host does not trust is a service this host will not use.
	result := Run(context.Background(), Request{Kind: ProbeHTTP, Target: server.URL})
	if result.Reachable || result.Passed {
		t.Fatalf("a certificate outside the trust store was accepted: %+v", result)
	}
	if result.Error == "" {
		t.Fatal("the refusal has no reason")
	}
}

func TestTheTCPProbeSaysWhetherTheConnectionCameAbout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()

	result := Run(context.Background(), Request{Kind: ProbeTCP, Target: listener.Addr().String()})
	if !result.Reachable || !result.Passed {
		t.Fatalf("an open port was described as %+v", result)
	}

	// A closed port: the probe ends with the answer "it does not work" and not
	// with an execution error - that is a measurement result, not a failure of
	// the panel.
	closed := listener.Addr().String()
	listener.Close()
	time.Sleep(20 * time.Millisecond)
	closedResult := Run(context.Background(), Request{
		Kind: ProbeTCP, Target: closed, TimeoutSeconds: 2,
	})
	if closedResult.Reachable {
		t.Fatalf("a closed port was described as reachable: %+v", closedResult)
	}
	if closedResult.Error == "" {
		t.Fatal("the missing connection has no reason")
	}
}
