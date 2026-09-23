package notify

import "testing"

// The receiver deduplicates by the identifier the delivery carries. Naming
// the event gave two channels pointing at one receiver the same identifier,
// so the second channel's message was dropped as a repeat of the first.
func TestTwoChannelsOfOneEventCarryDifferentIdentifiers(t *testing.T) {
	first := Message{EventID: 42, DeliveryID: "delivery-a"}
	second := Message{EventID: 42, DeliveryID: "delivery-b"}
	if deliveryIdentifier(first) == deliveryIdentifier(second) {
		t.Fatalf("both channels carry %q", deliveryIdentifier(first))
	}
	// Every attempt of one delivery keeps its identifier, which is what makes
	// the receiver's deduplication right rather than merely different.
	if deliveryIdentifier(first) != deliveryIdentifier(Message{EventID: 42, DeliveryID: "delivery-a"}) {
		t.Error("two attempts of one delivery carry different identifiers")
	}
}
