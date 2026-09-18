package docker

import (
	"strings"
	"testing"
)

// The compact words an operator writes are read in one place, and the
// panel and the host read them with this code. So these tests are about
// one thing: that the text means on the host what it looked like on the
// screen - and that text which means nothing is refused by name rather
// than turned into a container nobody described.

func TestAPublishedPortIsReadTheWayItIsWritten(t *testing.T) {
	cases := map[string]PortSpec{
		"80":                {ContainerPort: 80},
		"8080:80":           {HostPort: 8080, ContainerPort: 80},
		"8080:80/udp":       {HostPort: 8080, ContainerPort: 80, Protocol: "udp"},
		"127.0.0.1:8080:80": {HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80},
		"[::1]:8080:80/tcp": {HostIP: "::1", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		":8080:80":          {HostPort: 8080, ContainerPort: 80},
		"0.0.0.0::80":       {HostIP: "0.0.0.0", ContainerPort: 80},
	}
	for text, want := range cases {
		got, err := ParsePort(text)
		if err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		if got != want {
			t.Errorf("%q gives %+v, want %+v", text, got, want)
		}
	}
}

func TestTextThatIsNotAPortIsRefusedByName(t *testing.T) {
	for _, text := range []string{"", "http", "8080:", "8080:0", "70000:80", "8080:80:70:60"} {
		if port, err := ParsePort(text); err == nil {
			t.Errorf("%q was read as %+v instead of being refused", text, port)
		}
	}
}

func TestAMountSaysWhatKindItIsBeforeAnythingElse(t *testing.T) {
	volume, err := ParseMount("volume:storefront-data:/var/lib/data:ro")
	if err != nil {
		t.Fatalf("a volume mount: %v", err)
	}
	if volume != (MountSpec{Type: "volume", Source: "storefront-data", Target: "/var/lib/data", ReadOnly: true}) {
		t.Errorf("a volume mount reads as %+v", volume)
	}
	bind, err := ParseMount("bind:/srv/www:/usr/share/nginx/html")
	if err != nil {
		t.Fatalf("a bind mount: %v", err)
	}
	if bind.Type != "bind" || bind.Source != "/srv/www" || bind.ReadOnly {
		t.Errorf("a bind mount reads as %+v", bind)
	}
	tmpfs, err := ParseMount("tmpfs:/run:67108864")
	if err != nil {
		t.Fatalf("a tmpfs mount: %v", err)
	}
	if tmpfs.Type != "tmpfs" || tmpfs.Target != "/run" || tmpfs.SizeBytes != 67108864 {
		t.Errorf("a tmpfs mount reads as %+v", tmpfs)
	}
	// A path that is not marked as one of the three kinds is not guessed
	// at: a volume name and a host path look alike enough that a guess
	// would sooner or later bind-mount a directory nobody meant to share.
	if mount, err := ParseMount("/srv/www:/usr/share/nginx/html"); err == nil {
		t.Errorf("a mount without a kind was read as %+v", mount)
	}
}

func TestANetworkAttachmentCarriesItsAliasesAndItsAddress(t *testing.T) {
	plain, err := ParseAttachment("internal")
	if err != nil || plain.Name != "internal" || len(plain.Aliases) != 0 || plain.IPv4 != "" {
		t.Fatalf("a plain attachment reads as %+v (%v)", plain, err)
	}
	full, err := ParseAttachment("internal=api,api.internal@10.0.1.5")
	if err != nil {
		t.Fatalf("a full attachment: %v", err)
	}
	if full.Name != "internal" || full.IPv4 != "10.0.1.5" ||
		strings.Join(full.Aliases, ",") != "api,api.internal" {
		t.Errorf("a full attachment reads as %+v", full)
	}
	if bad, err := ParseAttachment("internal@not-an-address"); err == nil {
		t.Errorf("an attachment with a word for an address was read as %+v", bad)
	}
}

func TestAnOrderBecomesTheDescriptionTheEngineTakes(t *testing.T) {
	order := ContainerRequest{
		Name:          "storefront",
		Image:         "nginx:1.27",
		Env:           map[string]string{"MODE": "production"},
		Ports:         []string{"8080:80"},
		Mounts:        []string{"volume:storefront-data:/var/lib/data"},
		Networks:      []string{"internal=api"},
		RestartPolicy: "unless-stopped",
		Labels:        map[string]string{"team": "platform"},
		HealthTest:    []string{"CMD", "curl", "-f", "http://localhost/"},
	}
	spec, err := order.Spec(map[string]string{"DB_PASSWORD": "storefront.db#3"})
	if err != nil {
		t.Fatalf("the description: %v", err)
	}
	if len(spec.Ports) != 1 || spec.Ports[0].ContainerPort != 80 {
		t.Errorf("the ports read as %+v", spec.Ports)
	}
	if len(spec.Mounts) != 1 || spec.Mounts[0].Target != "/var/lib/data" {
		t.Errorf("the mounts read as %+v", spec.Mounts)
	}
	if len(spec.Networks) != 1 || spec.Networks[0].Name != "internal" {
		t.Errorf("the networks read as %+v", spec.Networks)
	}
	if spec.Health == nil || spec.Health.Test[0] != "CMD" {
		t.Errorf("the health check reads as %+v", spec.Health)
	}
	// The reference of the secret is in the description, and no value is:
	// that is what makes a rotated secret a changed description.
	if spec.EnvSecrets["DB_PASSWORD"] != "storefront.db#3" {
		t.Errorf("the secret references read as %+v", spec.EnvSecrets)
	}
	// The same description twice gives the same digest, or an approval
	// could never be carried out.
	again, err := order.Spec(map[string]string{"DB_PASSWORD": "storefront.db#3"})
	if err != nil {
		t.Fatalf("the description a second time: %v", err)
	}
	if SpecDigest(spec) != SpecDigest(again) {
		t.Error("the digest of the same description differs between two readings")
	}
	rotated, err := order.Spec(map[string]string{"DB_PASSWORD": "storefront.db#4"})
	if err != nil {
		t.Fatalf("the description with the rotated secret: %v", err)
	}
	if SpecDigest(spec) == SpecDigest(rotated) {
		t.Error("a secret rotated to another version leaves the description unchanged")
	}
}

// An order the engine would refuse is refused here, where the field can be
// named: the operator gets the field back and not a status from a daemon.
func TestAnOrderTheEngineWouldRefuseIsRefusedHere(t *testing.T) {
	base := ContainerRequest{Name: "storefront", Image: "nginx:1.27"}
	cases := map[string]ContainerRequest{
		"a name the engine does not allow": {Name: "store front", Image: "nginx:1.27"},
		"a retry count without on-failure": {
			Name: base.Name, Image: base.Image, RestartPolicy: "always", RestartMaxRetries: 3,
		},
		"a reservation above the limit": {
			Name: base.Name, Image: base.Image, MemoryBytes: 1 << 20, MemoryReservationBytes: 1 << 21,
		},
		"a port that is not one": {Name: base.Name, Image: base.Image, Ports: []string{"http"}},
		"a mount without a kind": {Name: base.Name, Image: base.Image, Mounts: []string{"/srv:/srv"}},
		"a credential written into the order": {
			Name: base.Name, Image: base.Image, Env: map[string]string{"DB_PASSWORD": "hunter2"},
		},
	}
	for what, order := range cases {
		if _, err := order.Spec(nil); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
}
