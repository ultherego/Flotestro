package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The generated catalogue has to be what the registry says. A copy of the
// catalogue kept by hand is a copy that disagrees, and it disagrees silently:
// the interface hides a control whose name the API no longer serves, or offers
// one it never served.
func TestTheGeneratedCatalogueIsCurrent(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	found, err := os.ReadFile(filepath.Join(root, Target))
	if err != nil {
		t.Fatalf("%s: %v (run go run ./cmd/tools/contractgen)", Target, err)
	}
	if string(found) != string(Generate()) {
		t.Fatalf("%s is not what the registry says; run go run ./cmd/tools/contractgen", Target)
	}
}

// And the catalogue has to hold both kinds of order, or a green run means only
// that an empty file matches an empty registry.
func TestTheCatalogueHoldsOperationsAndLifecycleOrders(t *testing.T) {
	entries := Catalogue()
	if len(entries) < 100 {
		t.Fatalf("the catalogue names %d orders, which is too few to be the real one", len(entries))
	}
	var lifecycle int
	for _, e := range entries {
		if e.Lifecycle {
			lifecycle++
		}
		if e.Action == "" || e.Permission == "" || e.Risk == "" {
			t.Errorf("an order is described incompletely: %+v", e)
		}
	}
	if lifecycle == 0 {
		t.Error("the catalogue holds no lifecycle order, so the panel's own screens are not covered")
	}
}
