package network

import (
	"os"
	"path/filepath"
	"testing"
)

// Wyjscie przepisane z hosta floty testowej: interfejs fizyczny z adresem
// statycznym i adresem link-local, oraz most dockera.
const wyjscieInterfejsow = `[
 {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback","address":"00:00:00:00:00:00",
  "addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","valid_life_time":4294967295}]},
 {"ifindex":3,"ifname":"eth1","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:9d:b0:1a",
  "addr_info":[
   {"family":"inet","local":"192.168.56.30","prefixlen":24,"scope":"global","valid_life_time":4294967295},
   {"family":"inet6","local":"fe80::a00:27ff:fe9d:b01a","prefixlen":64,"scope":"link","protocol":"kernel_ll","valid_life_time":4294967295}]},
 {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"08:00:27:11:22:33",
  "addr_info":[{"family":"inet","local":"10.0.2.15","prefixlen":24,"scope":"global","dynamic":true,"valid_life_time":85846}]},
 {"ifindex":4,"ifname":"docker0","flags":["BROADCAST","MULTICAST","UP"],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"02:42:1a:2b:3c:4d",
  "linkinfo":{"info_kind":"bridge"},
  "addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global","valid_life_time":4294967295}]}]`

const wyjscieTras = `[
 {"dst":"default","gateway":"10.0.2.2","dev":"eth0","protocol":"dhcp","prefsrc":"10.0.2.15","metric":1002,"flags":[]},
 {"dst":"192.168.56.0/24","dev":"eth1","protocol":"kernel","scope":"link","prefsrc":"192.168.56.30","flags":[]}]`

func TestInterfejsyMajaAdresyZMaskami(t *testing.T) {
	interfejsy, err := ParsujInterfejsy(wyjscieInterfejsow)
	if err != nil {
		t.Fatal(err)
	}
	if len(interfejsy) != 4 {
		t.Fatalf("interfejsow = %d", len(interfejsy))
	}
	po := map[string]Interface{}
	for _, interfejs := range interfejsy {
		po[interfejs.Name] = interfejs
	}

	// Adres bez maski nie mowi, jaka siec host uwaza za lokalna.
	if po["eth1"].Addresses[0].Address != "192.168.56.30/24" {
		t.Errorf("adres eth1 = %q", po["eth1"].Addresses[0].Address)
	}
	// Adres z DHCP zniknie razem z dzierzawa; adres staly nie.
	if !po["eth1"].Addresses[0].Permanent {
		t.Error("adres statyczny uznany za tymczasowy")
	}
	if po["eth0"].Addresses[0].Permanent {
		t.Error("adres z DHCP uznany za staly")
	}
	// Host z dockerem ma kilkanascie interfejsow i tylko czesc z nich cos
	// znaczy dla operatora: rodzaj jest tym, co je rozroznia.
	if po["docker0"].Kind != "bridge" || po["eth1"].Kind != "ethernet" || po["lo"].Kind != "loopback" {
		t.Errorf("rodzaje = %q %q %q", po["docker0"].Kind, po["eth1"].Kind, po["lo"].Kind)
	}
	// Stan "unknown" zostaje slowem: tak raportuja interfejsy wirtualne
	// i nie wolno go zamieniac w "down".
	if po["lo"].OperState != "unknown" {
		t.Errorf("stan lo = %q", po["lo"].OperState)
	}
}

func TestTrasyZachowujaProtokolIMetryke(t *testing.T) {
	trasy, err := ParsujTrasy(wyjscieTras, FamilyIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if len(trasy) != 2 {
		t.Fatalf("tras = %d", len(trasy))
	}
	if trasy[0].Destination != "default" || trasy[0].Gateway != "10.0.2.2" ||
		trasy[0].Protocol != "dhcp" || trasy[0].Metric != 1002 {
		t.Errorf("trasa domyslna = %+v", trasy[0])
	}
	if trasy[1].Family != FamilyIPv4 {
		t.Errorf("rodzina = %q", trasy[1].Family)
	}
}

// Kanal zarzadzania jest wskazywany po adresie, ktorym agent naprawde
// rozmawia z panelem. Zgadywanie z pierwszej pozycji listy skonczyloby sie
// zmiana interfejsu, przez ktory wlasnie przyszlo polecenie.
func TestKanalZarzadzaniaWskazujeInterfejsPolaczenia(t *testing.T) {
	interfejsy, err := ParsujInterfejsy(wyjscieInterfejsow)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{Interfaces: interfejsy}
	OznaczKanalZarzadzania(&snapshot, "192.168.56.30:48212")

	if snapshot.ManagementInterface != "eth1" {
		t.Errorf("interfejs zarzadzania = %q", snapshot.ManagementInterface)
	}
	if snapshot.ManagementAddress != "192.168.56.30/24" {
		t.Errorf("adres zarzadzania = %q", snapshot.ManagementAddress)
	}
	if !snapshot.Interfejs("eth1").Management || snapshot.Interfejs("eth0").Management {
		t.Error("oznaczono niewlasciwy interfejs")
	}

	// Adres spoza hosta nie moze oznaczyc niczego "na wszelki wypadek".
	pusty := Snapshot{Interfaces: interfejsy}
	OznaczKanalZarzadzania(&pusty, "10.9.9.9")
	if pusty.ManagementInterface != "" {
		t.Errorf("oznaczono interfejs dla obcego adresu: %q", pusty.ManagementInterface)
	}
}

func TestDaneZSysUzupelniajaLacze(t *testing.T) {
	katalog := t.TempDir()
	eth := filepath.Join(katalog, "eth1")
	if err := os.MkdirAll(eth, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(eth, "carrier"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Jadro zwraca -1 dla lacza bez nosnej. Predkosc nieznana ma zostac
	// nieznana, a nie stac sie zerem.
	if err := os.WriteFile(filepath.Join(eth, "speed"), []byte("-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	interfejsy := []Interface{{Name: "eth1"}, {Name: "brak"}}
	UzupelnijZSys(katalog, interfejsy)

	if interfejsy[0].Carrier == nil || !*interfejsy[0].Carrier {
		t.Errorf("nosna = %v", interfejsy[0].Carrier)
	}
	if interfejsy[0].SpeedMbps != nil {
		t.Errorf("predkosc = %v", *interfejsy[0].SpeedMbps)
	}
	// Interfejs bez katalogu w /sys nie moze dostac wartosci udajacych fakt.
	if interfejsy[1].Carrier != nil || interfejsy[1].SpeedMbps != nil {
		t.Errorf("interfejs bez /sys = %+v", interfejsy[1])
	}
}

// Host bez mechanizmu zapisu ma to powiedziec wprost, a nie milczec.
func TestBrakAdapteraZapisuMaPowod(t *testing.T) {
	if adapter := WykryjAdapter(func(string) bool { return false }); adapter != "" {
		t.Errorf("adapter = %q", adapter)
	}
	if PowodBrakuZapisu("") == "" {
		t.Error("brak adaptera bez powodu")
	}
	if PowodBrakuZapisu(AdapterNetworkManager) != "" {
		t.Error("host z adapterem podaje powod niedostepnosci")
	}
	obecne := map[string]bool{"/usr/bin/nmcli": true, "/run/NetworkManager": true}
	if adapter := WykryjAdapter(func(s string) bool { return obecne[s] }); adapter != AdapterNetworkManager {
		t.Errorf("adapter = %q", adapter)
	}
}
