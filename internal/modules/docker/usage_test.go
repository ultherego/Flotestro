package docker

import (
	"errors"
	"strings"
	"testing"
)

// testState assembles a host with two networks and two volumes, one of
// which is mounted by a stopped container.
func testState() Snapshot {
	return Snapshot{
		Containers: []Container{
			{
				ID: "aaaa000000000000", Name: "shop-web-1", State: "running",
				Networks: []ContainerNetwork{{Name: "shop_default", ID: "net-shop", IPv4: "172.18.0.2"}},
				Mounts:   []Mount{{Type: "volume", Name: "shop_data", Destination: "/var/lib/data"}},
			},
			{
				ID: "bbbb000000000000", Name: "shop-db-1", State: "exited",
				Networks: []ContainerNetwork{{Name: "shop_default", ID: "net-shop"}},
				Mounts:   []Mount{{Type: "volume", Name: "shop_db", Destination: "/var/lib/postgresql"}},
			},
		},
		Networks: []Network{
			{ID: "net-bridge", Name: "bridge", Driver: "bridge", Predefined: true},
			{ID: "net-shop", Name: "shop_default", Driver: "bridge"},
			{ID: "net-old", Name: "old_network", Driver: "bridge"},
		},
		Volumes: []Volume{
			{Name: "shop_data", Driver: "local"},
			{Name: "shop_db", Driver: "local"},
			{Name: "abandoned", Driver: "local"},
		},
	}
}

// TestNetworkUsageComesFromContainers guards the most important property
// of this view: the engine returns an empty container map in the network
// list, so without the derivation from containers every network would look
// abandoned - and would go under the prune.
func TestNetworkUsageComesFromContainers(t *testing.T) {
	state := testState()
	linkUsage(&state)

	shop := networkByID(state.Networks, "net-shop")
	if !shop.InUse {
		t.Fatal("a network with two containers reported as unused")
	}
	if len(shop.Containers) != 2 {
		t.Fatalf("containers in the network = %d", len(shop.Containers))
	}
	// The order is fixed, because the list goes straight to the view.
	if shop.Containers[0].Name != "shop-db-1" {
		t.Errorf("first container = %s", shop.Containers[0].Name)
	}
	if state.Networks[2].InUse {
		t.Error("a network without containers reported as used")
	}
}

// TestVolumeOfStoppedContainerIsInUse guards the prune boundary: the volume
// of a container that is not running now is not nobody's volume.
func TestVolumeOfStoppedContainerIsInUse(t *testing.T) {
	state := testState()
	linkUsage(&state)

	db := volumeByName(state.Volumes, "shop_db")
	if !db.InUse {
		t.Fatal("the volume of a stopped container treated as abandoned")
	}
	if len(db.UsedBy) != 1 || db.UsedBy[0].State != "exited" {
		t.Fatalf("volume usage = %+v", db.UsedBy)
	}
	if volumeByName(state.Volumes, "abandoned").InUse {
		t.Error("a volume without containers reported as used")
	}
}

// TestSummaryCountsPruneCandidates guards that the counter talks about
// objects that can really be removed: a predefined network is not a
// candidate, so it must not bump the counter on every host.
func TestSummaryCountsPruneCandidates(t *testing.T) {
	state := testState()
	linkUsage(&state)
	summary := summarise(state, Summary{})

	if summary.NetworksUnused != 1 {
		t.Errorf("unused networks = %d, want 1", summary.NetworksUnused)
	}
	if summary.VolumesUnused != 1 {
		t.Errorf("unused volumes = %d, want 1", summary.VolumesUnused)
	}
}

// TestPruneRefusesObjectInUse guards that the host refuses itself before
// anything vanishes - and says who uses the object.
func TestPruneRefusesObjectInUse(t *testing.T) {
	state := testState()
	linkUsage(&state)

	err := checkPrune(state, []string{"shop_db"}, nil)
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("removing a volume in use gave %v", err)
	}
	if !strings.Contains(err.Error(), "shop-db-1") {
		t.Errorf("the refusal does not name the container: %v", err)
	}

	err = checkPrune(state, nil, []string{"net-shop"})
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("removing a network in use gave %v", err)
	}
}

func TestPruneRefusesPredefinedNetwork(t *testing.T) {
	state := testState()
	linkUsage(&state)
	if err := checkPrune(state, nil, []string{"net-bridge"}); !errors.Is(err, ErrPredefinedNetwork) {
		t.Fatalf("removing a predefined network gave %v", err)
	}
}

// TestPruneRefusesMissing guards that the operator does not see the success
// of an operation that removed nothing.
func TestPruneRefusesMissing(t *testing.T) {
	state := testState()
	linkUsage(&state)
	if err := checkPrune(state, []string{"no-such-thing"}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing a missing volume gave %v", err)
	}
}

// TestPruneChecksWholeListUpFront guards that a busy object at the end of
// the list stops the operation before the first one vanishes: a half-way
// prune would leave the host in a state nobody asked for.
func TestPruneChecksWholeListUpFront(t *testing.T) {
	state := testState()
	linkUsage(&state)
	err := checkPrune(state, []string{"abandoned", "shop_data"}, nil)
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("a list with a busy volume at the end gave %v", err)
	}
}
