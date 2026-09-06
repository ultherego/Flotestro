package gateway

import "testing"

func TestRozbijPowiadomienieOEpoce(t *testing.T) {
	hostID, epoka, brama, ok := rozbijPowiadomienie(
		"2768b885-6d58-4844-ba2e-4d6dc37a8d6f 7 gateway-b")
	if !ok {
		t.Fatal("poprawne powiadomienie odrzucone")
	}
	if hostID != "2768b885-6d58-4844-ba2e-4d6dc37a8d6f" || epoka != 7 || brama != "gateway-b" {
		t.Fatalf("odczytano %q %d %q", hostID, epoka, brama)
	}
}

// TestUszkodzonePowiadomienieNieZamykaSesji pilnuje, ze smiec w kanale nie
// konczy sesji hosta: zamkniecie na podstawie nieczytelnego powiadomienia
// bylo by odcieciem hosta bez powodu.
func TestUszkodzonePowiadomienieNieZamykaSesji(t *testing.T) {
	przypadki := []string{"", "host", "host epoka brama", "host 7", "host 7 brama nadmiar"}
	for _, payload := range przypadki {
		t.Run(payload, func(t *testing.T) {
			_, _, _, ok := rozbijPowiadomienie(payload)
			if payload == "host 7 brama nadmiar" {
				// Trzecia czesc jest identyfikatorem bramy i moze zawierac
				// spacje; to jest poprawne powiadomienie.
				if !ok {
					t.Fatal("powiadomienie z nazwa bramy ze spacja odrzucone")
				}
				return
			}
			if ok {
				t.Fatalf("uszkodzone powiadomienie %q przyjete", payload)
			}
		})
	}
}
