package kernel

import (
	"strings"
	"testing"
)

// /proc/sys zawiera przelaczniki, ktore wylaczaja ochrony jadra albo
// zatrzymuja host. Panel zmienia to, co da sie opisac i cofnac.
func TestKluczePozaZakresemSaOdrzucane(t *testing.T) {
	for _, klucz := range []string{
		"kernel.sysrq",
		"kernel.core_pattern",
		"kernel.modprobe",
		"dev.raid.speed_limit_max",
		"../etc/passwd",
		"NET.IPV4.IP_FORWARD",
	} {
		if err := WalidujKlucz(klucz); err == nil {
			t.Errorf("przyjeto klucz %q", klucz)
		}
	}
	for _, klucz := range []string{"vm.swappiness", "net.ipv4.ip_forward",
		"fs.inotify.max_user_watches", "net.ipv4.conf.all.rp_filter"} {
		if err := WalidujKlucz(klucz); err != nil {
			t.Errorf("odrzucono klucz %q: %v", klucz, err)
		}
	}
	// "net.ipv4" jest galezia, a nie ustawieniem, ale skladniowo wyglada
	// tak samo jak "vm.swappiness". Rozstrzyga to host, sprawdzajac przed
	// zapisem, czy klucz w ogole istnieje - i tak ma byc, bo lista kluczy
	// zalezy od wersji jadra i zaladowanych modulow.
	if err := WalidujKlucz("net.ipv4"); err != nil {
		t.Errorf("skladnia galezi odrzucona w walidatorze: %v", err)
	}
}

func TestWartoscSysctlNieWpuszczaNowejLinii(t *testing.T) {
	for _, wartosc := range []string{"", "10\nkernel.sysrq = 1", "$(reboot)", "tak;nie"} {
		if err := WalidujWartosc(wartosc); err == nil {
			t.Errorf("przyjeto wartosc %q", wartosc)
		}
	}
	for _, wartosc := range []string{"1", "60", "4096 87380 6291456", "0.0.0.0/0"} {
		if err := WalidujWartosc(wartosc); err != nil {
			t.Errorf("odrzucono wartosc %q: %v", wartosc, err)
		}
	}
}

func TestPlikSysctlJestUporzadkowany(t *testing.T) {
	tresc, err := SkladajPlikSysctl(map[string]string{
		"vm.swappiness":       "10",
		"net.ipv4.ip_forward": "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tresc, NaglowekPliku) {
		t.Errorf("plik bez naglowka: %q", tresc)
	}
	// Stala kolejnosc: plik zapisany dwa razy z tym samym zestawem ma byc
	// tym samym plikiem, inaczej kazdy zapis wygladalby na zmiane.
	if strings.Index(tresc, "net.ipv4") > strings.Index(tresc, "vm.swappiness") {
		t.Errorf("kolejnosc = %q", tresc)
	}
	odczytane := ParsujPlikSysctl(tresc)
	if odczytane["vm.swappiness"] != "10" || len(odczytane) != 2 {
		t.Errorf("odczyt = %v", odczytane)
	}
	if _, err := SkladajPlikSysctl(map[string]string{"kernel.sysrq": "1"}); err == nil {
		t.Error("przyjeto klucz spoza zakresu")
	}
}

// Jadro rozdziela wartosci tabulatorami; bez normalizacji porownanie
// z zapisana wartoscia zalezaloby od bialych znakow.
func TestWartosciZJadraSaNormalizowane(t *testing.T) {
	wartosci := ParsujWartosci("net.ipv4.tcp_rmem = 4096\t87380\t6291456\nvm.swappiness = 60\n")
	if wartosci["net.ipv4.tcp_rmem"] != "4096 87380 6291456" {
		t.Errorf("wartosc = %q", wartosci["net.ipv4.tcp_rmem"])
	}
	if wartosci["vm.swappiness"] != "60" {
		t.Errorf("wartosc = %q", wartosci["vm.swappiness"])
	}
}

const trescProcModules = `xt_nat 12288 1 - Live 0x0000000000000000
veth 40960 0 - Live 0x0000000000000000
bridge 421888 1 br_netfilter, Live 0x0000000000000000`

func TestModulyCzytaneZJadra(t *testing.T) {
	moduly := ParsujModuly(trescProcModules)
	if len(moduly) != 3 {
		t.Fatalf("modulow = %d", len(moduly))
	}
	if moduly[2].Name != "bridge" || moduly[2].SizeBytes != 421888 {
		t.Errorf("modul = %+v", moduly[2])
	}
	if len(moduly[2].UsedBy) != 1 || moduly[2].UsedBy[0] != "br_netfilter" {
		t.Errorf("zaleznosci = %v", moduly[2].UsedBy)
	}
	// Myslnik oznacza brak zaleznosci i nie jest nazwa modulu.
	if len(moduly[0].UsedBy) != 0 {
		t.Errorf("zaleznosci = %v", moduly[0].UsedBy)
	}
}

// Zablokowanie modulu, bez ktorego host nie wstanie, nie jest operacja,
// ktora ma sie udac.
func TestBlokadaChronionegoModuluJestOdrzucana(t *testing.T) {
	for _, nazwa := range []string{"ext4", "dm_mod", "virtio_net", "Zly Modul", "../x"} {
		if err := WalidujModul(nazwa); err == nil {
			t.Errorf("przyjeto modul %q", nazwa)
		}
	}
	tresc, err := SkladajBlacklist([]string{"pcspkr", "floppy"})
	if err != nil {
		t.Fatal(err)
	}
	// Sama blokada nie wystarczy, gdy modul jest zaleznoscia innego.
	if !strings.Contains(tresc, "install pcspkr /bin/false") {
		t.Errorf("plik = %q", tresc)
	}
	if len(ParsujBlacklist(tresc)) != 2 {
		t.Errorf("odczyt = %v", ParsujBlacklist(tresc))
	}
}

// Modul zaladowany nie znika po zapisaniu blokady: operator ma przeczytac,
// dlaczego wpis w modprobe.d jeszcze nic nie zmienil.
func TestBlokadaZaladowanegoModuluMowiOInitramfs(t *testing.T) {
	if powod := InitramfsWymagany("pcspkr", true); powod == "" {
		t.Error("blokada zaladowanego modulu bez ostrzezenia")
	} else if !strings.Contains(powod, "initramfs") {
		t.Errorf("powod = %q", powod)
	}
	if InitramfsWymagany("pcspkr", false) != "" {
		t.Error("modul niezaladowany dostal ostrzezenie")
	}
}
