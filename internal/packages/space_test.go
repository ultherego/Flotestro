package packages

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mib = 1 << 20

// The judgement is per file system, with the headroom, and never on a fact
// whose need was not measured: a full /boot refuses a kernel while "/" has
// room, two paths on one file system share its free bytes, and a host whose
func TestSpaceShortfallJudgesPerFilesystem(t *testing.T) {
	cases := []struct {
		name    string
		facts   []SpaceFact
		refused string
	}{
		{name: "everything fits", facts: []SpaceFact{
			{Path: "/var/cache/apt/archives", Filesystem: "/", AvailableBytes: 10 * 1024 * mib, NeededBytes: 100 * mib, Basis: BasisDownloadSize},
			{Path: "/usr", Filesystem: "/", AvailableBytes: 10 * 1024 * mib, NeededBytes: 300 * mib, Basis: BasisInstalledSize},
		}},
		{name: "a full /boot refuses a kernel while / has room", facts: []SpaceFact{
			{Path: "/usr", Filesystem: "/", AvailableBytes: 10 * 1024 * mib, NeededBytes: 300 * mib, Basis: BasisInstalledSize},
			{Path: "/boot", Filesystem: "/boot", AvailableBytes: 90 * mib, NeededBytes: 120 * mib, Basis: BasisBootFiles},
		}, refused: "/boot"},
		{name: "paths on one file system share its bytes", facts: []SpaceFact{
			{Path: "/var/cache/apt/archives", Filesystem: "/", AvailableBytes: 500 * mib, NeededBytes: 200 * mib, Basis: BasisDownloadSize},
			{Path: "/usr", Filesystem: "/", AvailableBytes: 500 * mib, NeededBytes: 250 * mib, Basis: BasisInstalledSize},
		}, refused: "on / (/var/cache/apt/archives, /usr)"},
		{name: "the headroom floor counts", facts: []SpaceFact{
			{Path: "/usr", Filesystem: "/", AvailableBytes: 70 * mib, NeededBytes: 10 * mib, Basis: BasisInstalledSize},
		}, refused: "on /"},
		{name: "the headroom grows with the change", facts: []SpaceFact{
			{Path: "/usr", Filesystem: "/", AvailableBytes: 4100 * mib, NeededBytes: 4000 * mib, Basis: BasisInstalledSize},
		}, refused: "on /"},
		{name: "an unknown need is reported and not judged", facts: []SpaceFact{
			{Path: "/var/cache/libdnf5", Filesystem: "/var", AvailableBytes: 1 * mib, Basis: BasisUnknown},
			{Path: "/usr", Filesystem: "/", AvailableBytes: 10 * 1024 * mib, NeededBytes: 300 * mib, Basis: BasisInstalledSize},
		}},
		{name: "no facts at all", facts: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := SpaceShortfall(tc.facts)
			if tc.refused == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("the change was not refused")
			}
			if !errors.Is(err, ErrNoSpace) {
				t.Fatalf("the refusal does not wrap ErrNoSpace: %v", err)
			}
			if !strings.Contains(err.Error(), tc.refused) {
				t.Fatalf("the refusal %q does not name %q", err, tc.refused)
			}
			if code, ok := ErrorCodeOf(err); !ok || code != ErrorNoSpace {
				t.Fatalf("code = %q (%v), expected %q", code, ok, ErrorNoSpace)
			}
			if !Refused(err) {
				t.Fatal("a lack of space is a refusal: nothing was attempted")
			}
		})
	}
}

// The refusal names the bytes the way a person reads them.
func TestSpaceShortfallNamesTheBytes(t *testing.T) {
	err := SpaceShortfall([]SpaceFact{
		{Path: "/boot", Filesystem: "/boot", AvailableBytes: 40 * mib, NeededBytes: 120 * mib, Basis: BasisBootFiles},
	})
	if err == nil {
		t.Fatal("the change was not refused")
	}
	for _, want := range []string{"184.0 MiB needed", "40.0 MiB available", "/boot"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}
}

// The headroom is the larger of five percent and 64 MiB.
func TestSpaceHeadroom(t *testing.T) {
	if got := spaceHeadroom(10 * mib); got != 64*mib {
		t.Errorf("headroom of 10 MiB = %d, expected the floor of 64 MiB", got)
	}
	if got := spaceHeadroom(4000 * mib); got != 200*mib {
		t.Errorf("headroom of 4000 MiB = %d, expected 200 MiB", got)
	}
}

// A kernel is recognised by the naming of its family; the headers, the
// modules and the tools are not kernels.
func TestKernelPackagePerFamily(t *testing.T) {
	cases := []struct {
		manager, name string
		kernel        bool
	}{
		{"apt", "linux-image-6.1.0-25-amd64", true},
		{"apt", "linux-image-amd64", true},
		{"apt", "linux-image-generic", true},
		{"apt", "linux-headers-6.1.0-25-amd64", false},
		{"apt", "linux-libc-dev", false},
		{"dnf", "kernel", true},
		{"dnf", "kernel-core", true},
		{"dnf", "kernel-rt-core", true},
		{"dnf", "kernel-64k-core", true},
		{"dnf", "kernel-modules", false},
		{"dnf", "kernel-headers", false},
		{"dnf", "kernel-devel", false},
		{"pacman", "linux", true},
		{"pacman", "linux-lts", true},
		{"pacman", "linux-zen", true},
		{"pacman", "linux-headers", false},
		{"pacman", "linux-firmware", false},
		{"pacman", "linux-api-headers", false},
		{"zypper", "kernel-default", false},
	}
	for _, tc := range cases {
		if got := KernelPackage(tc.manager, tc.name); got != tc.kernel {
			t.Errorf("%s/%s: kernel = %v, expected %v", tc.manager, tc.name, got, tc.kernel)
		}
	}
	if !anyKernel("apt", []Change{{Name: "libc6"}, {Name: "linux-image-amd64"}}) {
		t.Error("a kernel among the changes was not seen")
	}
	if anyKernel("apt", []Change{{Name: "libc6"}}) {
		t.Error("a kernel was seen where there is none")
	}
}

// The growth is the sum of what grows; a package that shrinks is no credit
// for the others, and a candidate without a size makes the whole sum unknown.
func TestGrowthSumsWhatGrows(t *testing.T) {
	candidate := map[string]uint64{"a": 300 * mib, "b": 50 * mib, "c": 10 * mib}
	current := map[string]uint64{"a": 200 * mib, "b": 80 * mib}
	grown, known := growth([]string{"a", "b", "c"}, candidate, current)
	if !known || grown != 110*mib {
		t.Fatalf("growth = %d (%v), expected 110 MiB", grown, known)
	}
	if _, known := growth([]string{"a", "unknown"}, candidate, current); known {
		t.Fatal("a candidate without a size gave a known sum")
	}
}

// Without the installed sizes the archives stand in, and without those the
// need is unknown rather than zero.
func TestInstallNeedsStateTheirBasis(t *testing.T) {
	needs := spaceNeeds{download: 40 * mib, downloadKnown: true}
	installNeeds(&needs, 100*mib, true)
	if needs.installBasis != BasisInstalledSize || needs.install != 100*mib {
		t.Errorf("measured growth: %+v", needs)
	}
	needs = spaceNeeds{download: 40 * mib, downloadKnown: true}
	installNeeds(&needs, 0, false)
	if needs.installBasis != BasisDownloadOnly || needs.install != 40*mib {
		t.Errorf("growth from the archives: %+v", needs)
	}
	needs = spaceNeeds{}
	installNeeds(&needs, 0, false)
	if needs.installBasis != BasisUnknown || needs.install != 0 {
		t.Errorf("nothing measured: %+v", needs)
	}
	if (SpaceFact{Basis: BasisUnknown}).Known() || (SpaceFact{}).Known() {
		t.Error("an unknown basis counts as known")
	}
}

// The facts are assembled from the paths of the family and the needs; the
// paths need not exist, and a database on the same file system as /usr is
// covered by the install fact.
func TestSpaceFactsAssemble(t *testing.T) {
	root := t.TempDir()
	facts := spaceFacts(filepath.Join(root, "cache", "never-created"), filepath.Join(root, "db"),
		spaceNeeds{download: 5 * mib, downloadKnown: true, install: 7 * mib, installBasis: BasisInstalledSize})
	byPurpose := map[string]SpaceFact{}
	for _, fact := range facts {
		byPurpose[fact.Purpose+" "+fact.Path] = fact
	}
	download, ok := byPurpose[SpaceDownload+" "+filepath.Join(root, "cache", "never-created")]
	if !ok || download.Basis != BasisDownloadSize || download.NeededBytes != 5*mib {
		t.Fatalf("download fact: %+v (%v)", download, ok)
	}
	if download.Filesystem == "" || download.AvailableBytes == 0 {
		t.Fatalf("a path that does not exist yet was not measured through its parent: %+v", download)
	}
	install, ok := byPurpose[SpaceInstall+" "+installRoot]
	if !ok || install.Basis != BasisInstalledSize || install.NeededBytes != 7*mib {
		t.Fatalf("install fact: %+v (%v)", install, ok)
	}
	for _, fact := range facts {
		if fact.Purpose == SpaceBoot {
			t.Fatalf("a boot fact without a kernel in the plan: %+v", fact)
		}
	}
}

// The mount point of a path is the highest ancestor on the same device;
// "/" is its own mount point.
func TestMountPointOf(t *testing.T) {
	if got := mountPointOf("/"); got != "/" {
		t.Errorf("mount point of / = %q", got)
	}
	dir := t.TempDir()
	mount := mountPointOf(dir)
	if mount == "" || !strings.HasPrefix(dir, mount) {
		t.Errorf("mount point of %s = %q", dir, mount)
	}
	if got := nearestExisting(filepath.Join(dir, "a", "b", "c")); got != dir {
		t.Errorf("nearest existing = %q, expected %q", got, dir)
	}
}

// The boot files of the running kernel are its image, its initramfs and its
// symbol map; a directory without them gives no number.
func TestBootFilesSize(t *testing.T) {
	boot := t.TempDir()
	for name, size := range map[string]int{
		"vmlinuz-6.1.0-25-amd64":    10 * 1024,
		"initrd.img-6.1.0-25-amd64": 60 * 1024,
		"config-6.1.0-25-amd64":     1024,
		"vmlinuz-6.1.0-24-amd64":    10 * 1024,
		"grub":                      0,
	} {
		path := filepath.Join(boot, name)
		if size == 0 {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	size, known := bootFilesSize(boot, "6.1.0-25-amd64")
	if !known || size != 71*1024 {
		t.Fatalf("size = %d (%v), expected 71 KiB", size, known)
	}
	if _, known := bootFilesSize(boot, "5.10.0-1-amd64"); known {
		t.Fatal("a kernel without files in /boot gave a size")
	}
	if _, known := bootFilesSize(boot, ""); known {
		t.Fatal("an unknown release gave a size")
	}
}

// The sizes the tools print for people are read back with binary units,
// whatever letter follows the number.
func TestParseHumanSize(t *testing.T) {
	cases := map[string]uint64{
		"12 M":       12 * mib,
		"1.5 GiB":    1536 * mib,
		"345 k":      345 * 1024,
		"143.39 MiB": 150355312,
		"512 B":      512,
		"0 B":        0,
		"7.4M":       7759462,
		"2 kB":       2048,
	}
	for text, want := range cases {
		got, ok := ParseHumanSize(text)
		if !ok || got != want {
			t.Errorf("%q = %d (%v), expected %d", text, got, ok, want)
		}
	}
	for _, bad := range []string{"", "lots", "12 parsecs", "-3 M"} {
		if _, ok := ParseHumanSize(bad); ok {
			t.Errorf("%q was read as a size", bad)
		}
	}
}

// FormatBytes writes the unit a person expects.
func TestFormatBytes(t *testing.T) {
	cases := map[uint64]string{
		512:            "512 B",
		1536:           "1.5 KiB",
		184 * mib:      "184.0 MiB",
		3 * 1024 * mib: "3.0 GiB",
	}
	for size, want := range cases {
		if got := FormatBytes(size); got != want {
			t.Errorf("%d = %q, expected %q", size, got, want)
		}
	}
}

// The installed sizes of apt-cache and dpkg-query are in KiB and keyed by
// the package; a record without a size is skipped.
func TestParseAPTSizes(t *testing.T) {
	show := strings.Join([]string{
		"Package: linux-image-6.1.0-25-amd64",
		"Version: 6.1.106-3",
		"Installed-Size: 409600",
		"Depends: kmod",
		"",
		"Package: libc6",
		"Installed-Size: 13000",
		"",
		"Package: nosize",
		"Version: 1",
		"",
	}, "\n")
	sizes := ParseAPTCacheSizes(show)
	if sizes["linux-image-6.1.0-25-amd64"] != 409600*1024 || sizes["libc6"] != 13000*1024 {
		t.Errorf("apt-cache sizes = %v", sizes)
	}
	if _, ok := sizes["nosize"]; ok {
		t.Error("a record without a size got one")
	}

	query := "libc6\t12800\nlinux-image-6.1.0-25-amd64\t\nfoo:i386\t42\n"
	installed := ParseInstalledSizeLines(query)
	if installed["libc6"] != 12800*1024 || installed["foo:i386"] != 42*1024 {
		t.Errorf("dpkg-query sizes = %v", installed)
	}
	if _, ok := installed["linux-image-6.1.0-25-amd64"]; ok {
		t.Error("a package without a size got one")
	}
}

// Both spellings of the dnf summary are read, and an upgrade summary of
// dnf4 gives the download alone.
func TestParseDNFTransactionSizes(t *testing.T) {
	dnf4Install := "Transaction Summary\n===\nInstall  2 Packages\n\nTotal download size: 12 M\nInstalled size: 40 M\nOperation aborted.\n"
	sizes := ParseDNFTransactionSizes(dnf4Install)
	if !sizes.DownloadKnown || sizes.Download != 12*mib || !sizes.InstallKnown || sizes.Install != 40*mib {
		t.Errorf("dnf4 install: %+v", sizes)
	}

	dnf4Upgrade := "Upgrade  3 Packages\n\nTotal download size: 145 M\nOperation aborted.\n"
	sizes = ParseDNFTransactionSizes(dnf4Upgrade)
	if !sizes.DownloadKnown || sizes.Download != 145*mib || sizes.InstallKnown {
		t.Errorf("dnf4 upgrade: %+v", sizes)
	}

	dnf4Cached := "Install  1 Package\n\nTotal size: 3.2 M\nInstalled size: 9.1 M\n"
	sizes = ParseDNFTransactionSizes(dnf4Cached)
	if !sizes.DownloadKnown || sizes.Download != 0 || !sizes.InstallKnown {
		t.Errorf("dnf4 cached: %+v", sizes)
	}

	dnf5 := "Transaction Summary:\n Upgrading:         3 packages\n\n" +
		"Total size of inbound packages is 12 MiB. Need to download 12 MiB.\n" +
		"After this operation, 3 MiB extra will be used (install 45 MiB, remove 42 MiB).\n" +
		"Operation aborted.\n"
	sizes = ParseDNFTransactionSizes(dnf5)
	if !sizes.DownloadKnown || sizes.Download != 12*mib || !sizes.InstallKnown || sizes.Install != 45*mib {
		t.Errorf("dnf5: %+v", sizes)
	}

	if sizes := ParseDNFTransactionSizes("Nothing to do.\n"); sizes.DownloadKnown || sizes.InstallKnown {
		t.Errorf("an empty summary gave sizes: %+v", sizes)
	}
}

// The installed sizes of pacman -Si and -Qi are keyed by the Name line that
// precedes them.
func TestParsePacmanInfoSizes(t *testing.T) {
	output := strings.Join([]string{
		"Repository      : core",
		"Name            : linux",
		"Version         : 6.16.6.arch1-1",
		"URL             : https://github.com/archlinux/linux",
		"Download Size   : 140.00 MiB",
		"Installed Size  : 143.39 MiB",
		"",
		"Name            : glibc",
		"Installed Size  : 47.42 MiB",
		"",
	}, "\n")
	sizes := ParsePacmanInfoSizes(output)
	if sizes["linux"] != 150355312 || sizes["glibc"] != 49723473 {
		t.Errorf("pacman sizes = %v", sizes)
	}
	if len(sizes) != 2 {
		t.Errorf("%d packages read, expected 2: %v", len(sizes), sizes)
	}
}

// Every code of the adapter maps to itself and nothing else.
func TestErrorCodeOfNoSpace(t *testing.T) {
	wrapped := fmt.Errorf("%w on /boot (/boot): 184.0 MiB needed with the headroom, 40.0 MiB available", ErrNoSpace)
	if code, ok := ErrorCodeOf(wrapped); !ok || code != ErrorNoSpace {
		t.Fatalf("code = %q (%v), expected %q", code, ok, ErrorNoSpace)
	}
	if code, ok := ErrorCodeOf(errors.New("something else")); ok {
		t.Fatalf("an unknown error got the code %q", code)
	}
}
