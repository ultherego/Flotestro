package hosts

import "testing"

func TestTheSameRegistryIsRecognisedWhateverTheOrderAndTheEmptyFeatures(t *testing.T) {
	held := Capabilities{
		{Name: "systemd", Version: 1, Available: true},
		{Name: "packages.apt", Version: 1, Available: true, Features: map[string]bool{"repair": true}},
	}
	reported := Capabilities{
		{Name: "packages.apt", Version: 1, Available: true, Features: map[string]bool{"repair": true}},
		{Name: "systemd", Version: 1, Available: true, Features: map[string]bool{}},
	}
	if !sameRegistry(held, reported) {
		t.Fatal("the registry a host left was not recognised when it came back")
	}
}

func TestARegistryThatChangedInAnyWayIsNotTheSame(t *testing.T) {
	held := Capabilities{{Name: "systemd", Version: 1, Available: true, Features: map[string]bool{"a": true}}}
	for name, reported := range map[string]Capabilities{
		"another version":  {{Name: "systemd", Version: 2, Available: true, Features: map[string]bool{"a": true}}},
		"no longer there":  {{Name: "systemd", Version: 1, Available: false, Features: map[string]bool{"a": true}}},
		"read only now":    {{Name: "systemd", Version: 1, Available: true, ReadOnly: true, Features: map[string]bool{"a": true}}},
		"another reason":   {{Name: "systemd", Version: 1, Available: true, Reason: "x", Features: map[string]bool{"a": true}}},
		"another feature":  {{Name: "systemd", Version: 1, Available: true, Features: map[string]bool{"b": true}}},
		"an adapter added": {{Name: "systemd", Version: 1, Available: true, Features: map[string]bool{"a": true}}, {Name: "docker", Version: 1, Available: true}},
		"an adapter gone":  {},
		"another adapter":  {{Name: "docker", Version: 1, Available: true, Features: map[string]bool{"a": true}}},
	} {
		if sameRegistry(held, reported) {
			t.Errorf("%s: taken for the registry that was there", name)
		}
	}
	if sameRegistry(nil, nil) {
		t.Error("nothing held is not a registry that can be kept: the rows have to be written")
	}
}
