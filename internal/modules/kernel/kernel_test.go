package kernel

import (
	"strings"
	"testing"
)

// /proc/sys holds switches that disable kernel protections or stop the
// host. The panel changes what can be described and reverted.
func TestKeysOutsideScopeAreRejected(t *testing.T) {
	for _, key := range []string{
		"kernel.sysrq",
		"kernel.core_pattern",
		"kernel.modprobe",
		"dev.raid.speed_limit_max",
		"../etc/passwd",
		"NET.IPV4.IP_FORWARD",
	} {
		if err := ValidateKey(key); err == nil {
			t.Errorf("accepted key %q", key)
		}
	}
	for _, key := range []string{"vm.swappiness", "net.ipv4.ip_forward",
		"fs.inotify.max_user_watches", "net.ipv4.conf.all.rp_filter"} {
		if err := ValidateKey(key); err != nil {
			t.Errorf("rejected key %q: %v", key, err)
		}
	}
	// "net.ipv4" is a branch, not a setting, but syntactically it looks the
	// same as "vm.swappiness". The host settles it by checking before the
	// write whether the key exists at all - and that is how it should be,
	// because the key list depends on the kernel version and the loaded
	// modules.
	if err := ValidateKey("net.ipv4"); err != nil {
		t.Errorf("branch syntax rejected by the validator: %v", err)
	}
}

func TestSysctlValueRejectsNewline(t *testing.T) {
	for _, value := range []string{"", "10\nkernel.sysrq = 1", "$(reboot)", "yes;no"} {
		if err := ValidateValue(value); err == nil {
			t.Errorf("accepted value %q", value)
		}
	}
	for _, value := range []string{"1", "60", "4096 87380 6291456", "0.0.0.0/0"} {
		if err := ValidateValue(value); err != nil {
			t.Errorf("rejected value %q: %v", value, err)
		}
	}
}

func TestSysctlFileIsOrdered(t *testing.T) {
	content, err := ComposeSysctlFile(map[string]string{
		"vm.swappiness":       "10",
		"net.ipv4.ip_forward": "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(content, FileHeader) {
		t.Errorf("file without header: %q", content)
	}
	// Stable order: a file written twice with the same set must be the same
	// file, otherwise every write would look like a change.
	if strings.Index(content, "net.ipv4") > strings.Index(content, "vm.swappiness") {
		t.Errorf("order = %q", content)
	}
	parsed := ParseSysctlFile(content)
	if parsed["vm.swappiness"] != "10" || len(parsed) != 2 {
		t.Errorf("parsed = %v", parsed)
	}
	if _, err := ComposeSysctlFile(map[string]string{"kernel.sysrq": "1"}); err == nil {
		t.Error("accepted a key outside the scope")
	}
}

// The kernel separates values with tabs; without normalisation the
// comparison with the written value would depend on whitespace.
func TestKernelValuesAreNormalised(t *testing.T) {
	values := ParseValues("net.ipv4.tcp_rmem = 4096\t87380\t6291456\nvm.swappiness = 60\n")
	if values["net.ipv4.tcp_rmem"] != "4096 87380 6291456" {
		t.Errorf("value = %q", values["net.ipv4.tcp_rmem"])
	}
	if values["vm.swappiness"] != "60" {
		t.Errorf("value = %q", values["vm.swappiness"])
	}
}

const procModulesContent = `xt_nat 12288 1 - Live 0x0000000000000000
veth 40960 0 - Live 0x0000000000000000
bridge 421888 1 br_netfilter, Live 0x0000000000000000`

func TestModulesAreReadFromKernel(t *testing.T) {
	modules := ParseModules(procModulesContent)
	if len(modules) != 3 {
		t.Fatalf("modules = %d", len(modules))
	}
	if modules[2].Name != "bridge" || modules[2].SizeBytes != 421888 {
		t.Errorf("module = %+v", modules[2])
	}
	if len(modules[2].UsedBy) != 1 || modules[2].UsedBy[0] != "br_netfilter" {
		t.Errorf("dependencies = %v", modules[2].UsedBy)
	}
	// A dash means no dependencies and is not a module name.
	if len(modules[0].UsedBy) != 0 {
		t.Errorf("dependencies = %v", modules[0].UsedBy)
	}
}

// Blocking a module without which the host does not boot is not an
// operation that is meant to succeed.
func TestBlockingProtectedModuleIsRejected(t *testing.T) {
	for _, name := range []string{"ext4", "dm_mod", "virtio_net", "Bad Module", "../x"} {
		if err := ValidateModule(name); err == nil {
			t.Errorf("accepted module %q", name)
		}
	}
	content, err := ComposeBlacklist([]string{"pcspkr", "floppy"})
	if err != nil {
		t.Fatal(err)
	}
	// The blacklist alone is not enough when the module is a dependency of
	// another.
	if !strings.Contains(content, "install pcspkr /bin/false") {
		t.Errorf("file = %q", content)
	}
	if len(ParseBlacklist(content)) != 2 {
		t.Errorf("parsed = %v", ParseBlacklist(content))
	}
}

// A loaded module does not vanish once the block is written: the operator
// is meant to read why the entry in modprobe.d has changed nothing yet.
func TestBlockingLoadedModuleMentionsInitramfs(t *testing.T) {
	if reason := InitramfsRequired("pcspkr", true); reason == "" {
		t.Error("block of a loaded module without a warning")
	} else if !strings.Contains(reason, "initramfs") {
		t.Errorf("reason = %q", reason)
	}
	if InitramfsRequired("pcspkr", false) != "" {
		t.Error("a module not loaded got a warning")
	}
}
