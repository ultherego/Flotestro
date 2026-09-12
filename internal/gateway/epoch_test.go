package gateway

import "testing"

func TestSplitTheNotificationAboutAnEpoch(t *testing.T) {
	hostID, epoch, gateway, ok := splitNotification(
		"2768b885-6d58-4844-ba2e-4d6dc37a8d6f 7 gateway-b")
	if !ok {
		t.Fatal("a correct notification was rejected")
	}
	if hostID != "2768b885-6d58-4844-ba2e-4d6dc37a8d6f" || epoch != 7 || gateway != "gateway-b" {
		t.Fatalf("read %q %d %q", hostID, epoch, gateway)
	}
}

// TestADamagedNotificationDoesNotCloseASession guards that rubbish in the
// channel does not end the session of a host: closing it on the basis of an
// unreadable notification would be cutting a host off without a reason.
func TestADamagedNotificationDoesNotCloseASession(t *testing.T) {
	cases := []string{"", "host", "host epoch gateway", "host 7", "host 7 gateway extra"}
	for _, payload := range cases {
		t.Run(payload, func(t *testing.T) {
			_, _, _, ok := splitNotification(payload)
			if payload == "host 7 gateway extra" {
				// The third part is the identifier of the gateway and may
				// contain spaces; this is a correct notification.
				if !ok {
					t.Fatal("a notification with a gateway name containing a space was rejected")
				}
				return
			}
			if ok {
				t.Fatalf("the damaged notification %q was accepted", payload)
			}
		})
	}
}
