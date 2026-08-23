package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Wyjscie przepisane z hosta floty testowej.
const wyjscieLsblk = `{
 "blockdevices": [
  {"name":"sda","path":"/dev/sda","type":"disk","size":68719476736,"fstype":null,"label":null,
   "uuid":null,"partuuid":null,"mountpoints":[null],"model":"VBOX HARDDISK ","serial":"VB0808c8f2",
   "wwn":null,"rota":true,"ro":false,"pkname":null,"fssize":null,"fsused":null,"fsavail":null,
   "children":[
     {"name":"sda1","path":"/dev/sda1","type":"part","size":1023410176,"fstype":"ext4","label":null,
      "uuid":"c856d851-66da-4c31-a17a-b53a4afdd1f0","partuuid":"06901e8d-01","mountpoints":["/boot"],
      "rota":true,"ro":false,"pkname":"sda","fssize":988057600,"fsused":123404288,"fsavail":793923584},
     {"name":"sda5","path":"/dev/sda5","type":"part","size":67692920832,"fstype":"LVM2_member",
      "mountpoints":[null],"rota":true,"ro":false,"pkname":"sda",
      "children":[
        {"name":"debian--13--vg-root","path":"/dev/mapper/debian--13--vg-root","type":"lvm",
         "size":64470646784,"fstype":"ext4","uuid":"11111111-2222-3333-4444-555555555555",
         "mountpoints":["/"],"rota":true,"ro":false,"pkname":"sda5",
         "fssize":63256395776,"fsused":8571781120,"fsavail":51442851840}]}]}]}`

func TestTopologiaSplaszczaDrzewoZOdsylaczemDoRodzica(t *testing.T) {
	urzadzenia, err := ParsujUrzadzenia(wyjscieLsblk)
	if err != nil {
		t.Fatal(err)
	}
	if len(urzadzenia) != 4 {
		t.Fatalf("urzadzen = %d", len(urzadzenia))
	}
	po := map[string]Device{}
	for _, urzadzenie := range urzadzenia {
		po[urzadzenie.Path] = urzadzenie
	}

	if po["/dev/sda"].Type != TypDysk || po["/dev/sda"].Parent != "" {
		t.Errorf("dysk = %+v", po["/dev/sda"])
	}
	if po["/dev/sda1"].Parent != "/dev/sda" {
		t.Errorf("partycja bez rodzica: %+v", po["/dev/sda1"])
	}
	// Wolumen logiczny siedzi na partycji, a nie na dysku: to jest cala
	// tresc topologii przy planowaniu rozszerzenia.
	if po["/dev/mapper/debian--13--vg-root"].Parent != "/dev/sda5" {
		t.Errorf("wolumen = %+v", po["/dev/mapper/debian--13--vg-root"])
	}
	// Identyfikacja idzie po UUID i serialu, bo /dev/sdX zalezy od kolejnosci
	// wykrywania i po restarcie potrafi wskazac inny dysk.
	if po["/dev/sda1"].UUID == "" || po["/dev/sda"].Serial == "" {
		t.Errorf("brak stabilnych identyfikatorow: %+v %+v", po["/dev/sda1"], po["/dev/sda"])
	}
	// Model przychodzi z odstepami na koncu; zostawiony wygladalby na
	// dwie rozne wartosci przy porownaniu z planem.
	if po["/dev/sda"].Model != "VBOX HARDDISK" {
		t.Errorf("model = %q", po["/dev/sda"].Model)
	}
	// Rozmiar filesystemu bywa mniejszy niz partycja - to wlasnie ta roznica
	// widac przed rozszerzeniem.
	root := po["/dev/mapper/debian--13--vg-root"]
	if root.FSSizeBytes == nil || *root.FSSizeBytes >= root.SizeBytes {
		t.Errorf("filesystem wolumenu = %v z %d", root.FSSizeBytes, root.SizeBytes)
	}
	// Urzadzenie bez filesystemu nie moze udawac, ze ma zero bajtow zajete.
	if po["/dev/sda"].FSUsedBytes != nil {
		t.Errorf("dysk bez filesystemu dostal zajetosc: %v", po["/dev/sda"].FSUsedBytes)
	}
	// Punkt montowania "null" z lsblk nie jest punktem montowania.
	if len(po["/dev/sda"].Mountpoints) != 0 {
		t.Errorf("dysk zamontowany: %v", po["/dev/sda"].Mountpoints)
	}
}

const wyjscieVGS = `{"report":[{"vg":[{"vg_name":"debian-13-vg","pv_count":"1","lv_count":"2","vg_size":"67691872256B","vg_free":"0B"}]}]}`
const wyjscieLVS = `{"report":[{"lv":[{"lv_name":"root","vg_name":"debian-13-vg","lv_size":"64470646784B","lv_path":"/dev/debian-13-vg/root"}]}]}`

func TestLVMCzytaRozmiaryWBajtach(t *testing.T) {
	grupy, err := ParsujGrupy(wyjscieVGS)
	if err != nil {
		t.Fatal(err)
	}
	if len(grupy) != 1 || grupy[0].SizeBytes != 67691872256 {
		t.Fatalf("grupy = %+v", grupy)
	}
	// Grupa bez wolnego miejsca to fakt, ktory rozstrzyga o mozliwosci
	// rozszerzenia - i ma byc zerem, a nie brakiem wartosci.
	if grupy[0].FreeBytes != 0 || grupy[0].LVCount != 2 {
		t.Errorf("grupa = %+v", grupy[0])
	}

	wolumeny, err := ParsujWolumeny(wyjscieLVS)
	if err != nil {
		t.Fatal(err)
	}
	if len(wolumeny) != 1 || wolumeny[0].Path != "/dev/debian-13-vg/root" {
		t.Errorf("wolumeny = %+v", wolumeny)
	}
}

const wyjscieMountinfo = `23 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw
30 28 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/debian--13--vg-root rw,errors=remount-ro
36 30 8:1 / /boot rw,relatime shared:25 - ext4 /dev/sda1 rw
41 30 0:35 / /srv/flotestro ro,relatime shared:30 - vboxsf srv_flotestro ro
44 30 8:16 / /mnt/kopie\040zapasowe rw,relatime shared:33 - ext4 /dev/sdb1 rw`

const trescFstab = `# /etc/fstab
/dev/mapper/debian--13--vg-root /               ext4    errors=remount-ro 0       1
UUID=c856d851 /boot           ext4    defaults        0       2
# flotestro: kopie zapasowe
/dev/sdb1 /mnt/kopie\040zapasowe ext4 defaults 0 2
UUID=aaaa /mnt/archiwum ext4 defaults 0 2`

func TestMontowaniaLaczaStanJadraZFstab(t *testing.T) {
	zJadra := ParsujMountinfo(wyjscieMountinfo)
	// Montowania jadra nie sa przestrzenia dyskowa hosta; pokazane
	// zaslanialyby obraz.
	for _, montowanie := range zJadra {
		if montowanie.FSType == "sysfs" {
			t.Errorf("systemowe montowanie w wyniku: %+v", montowanie)
		}
	}

	polaczone := PolaczMontowania(zJadra, ParsujFstab(trescFstab))
	po := map[string]Mount{}
	for _, montowanie := range polaczone {
		po[montowanie.Target] = montowanie
	}

	if !po["/"].Mounted || !po["/"].InFstab {
		t.Errorf("korzen = %+v", po["/"])
	}
	// Montowanie bez wpisu w fstab zniknie po restarcie - i to jest
	// odpowiedz, po ktora operator tu przychodzi.
	if po["/srv/flotestro"].InFstab {
		t.Errorf("montowanie spoza fstab uznane za wpis: %+v", po["/srv/flotestro"])
	}
	// Wpis w fstab, ktorego nikt nie zamontowal, tez musi byc widoczny.
	if !po["/mnt/archiwum"].InFstab || po["/mnt/archiwum"].Mounted {
		t.Errorf("wpis niezamontowany = %+v", po["/mnt/archiwum"])
	}
	// Sciezka ze spacja jest zapisana osemkowo; bez odkodowania rozpadlaby
	// sie na dwa pola i nie dopasowala do wpisu fstab.
	kopie := po["/mnt/kopie zapasowe"]
	if !kopie.Mounted || !kopie.InFstab || !kopie.Managed {
		t.Errorf("montowanie ze spacja = %+v", kopie)
	}
}

// Znacznik panelu stoi nad wpisem, ktory panel zalozyl: wpis zastany nalezy
// do administratora hosta.
func TestWpisyFstabRozrozniajaWlasnosc(t *testing.T) {
	wpisy := ParsujFstab(trescFstab)
	if len(wpisy) != 4 {
		t.Fatalf("wpisow = %d", len(wpisy))
	}
	var zarzadzane int
	for _, wpis := range wpisy {
		if wpis.Managed {
			zarzadzane++
			if wpis.Target != "/mnt/kopie zapasowe" {
				t.Errorf("zly wpis uznany za wlasny: %+v", wpis)
			}
		}
	}
	if zarzadzane != 1 {
		t.Errorf("wpisow wlasnych = %d", zarzadzane)
	}
}

// Zrodlo montowania ma byc identyfikatorem trwalym albo sciezka w /dev:
// nazwa urzadzenia zalezy od kolejnosci wykrywania.
func TestZrodloIcelMontowaniaSaSprawdzane(t *testing.T) {
	for _, zle := range []string{"", "sdb1", "//serwer/udzial", "UUID=$(reboot)", "/etc/passwd"} {
		if err := WalidujZrodlo(zle); err == nil {
			t.Errorf("przyjeto zrodlo %q", zle)
		}
	}
	for _, dobre := range []string{"UUID=c856d851-66da-4c31-a17a-b53a4afdd1f0",
		"LABEL=kopie", "/dev/sdb1", "/dev/mapper/vg-lv"} {
		if err := WalidujZrodlo(dobre); err != nil {
			t.Errorf("odrzucono zrodlo %q: %v", dobre, err)
		}
	}

	// Przeslonienie katalogu systemowego odcina host od samego siebie.
	for _, chroniony := range []string{"/", "/etc", "/usr", "/var/log", "/boot"} {
		if err := WalidujCel(chroniony); err == nil {
			t.Errorf("przyjeto montowanie na %q", chroniony)
		}
	}
	for _, zly := range []string{"mnt/dane", "/mnt/../etc", "/mnt/dane/"} {
		if err := WalidujCel(zly); err == nil {
			t.Errorf("przyjeto cel %q", zly)
		}
	}
	if err := WalidujCel("/mnt/kopie zapasowe"); err != nil {
		t.Errorf("odrzucono poprawny cel: %v", err)
	}
}

// Sciezka ze spacja zapisana wprost rozpadlaby sie na dwa pola, a wpis
// wskazywalby zupelnie inne miejsce.
func TestWierszFstabZapisujeZnakiSpecjalneOsemkowo(t *testing.T) {
	wiersz := WierszFstab("/dev/sdb1", "/mnt/kopie zapasowe", "ext4", "")
	if !strings.Contains(wiersz, `/mnt/kopie\040zapasowe`) {
		t.Errorf("wiersz = %q", wiersz)
	}
	// Brak opcji nie moze dac pustego pola: fstab ma wtedy piec kolumn
	// zamiast szesciu i wpis staje sie bledny.
	if !strings.Contains(wiersz, "ext4 defaults 0 0") {
		t.Errorf("wiersz bez opcji = %q", wiersz)
	}
}

func TestWpisPanelaJestZastepowanyANieDublowany(t *testing.T) {
	katalog := t.TempDir()
	sciezka := filepath.Join(katalog, "fstab")
	poczatek := "# /etc/fstab\nUUID=aaa / ext4 defaults 0 1\n"
	if err := os.WriteFile(sciezka, []byte(poczatek), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ZapiszWpisFstab(sciezka, "/dev/sdb1", "/mnt/dane", "ext4", "defaults"); err != nil {
		t.Fatal(err)
	}
	if err := ZapiszWpisFstab(sciezka, "LABEL=dane", "/mnt/dane", "xfs", "noatime"); err != nil {
		t.Fatal(err)
	}
	tresc, err := os.ReadFile(sciezka)
	if err != nil {
		t.Fatal(err)
	}
	wpisy := ParsujFstab(string(tresc))
	var dane int
	for _, wpis := range wpisy {
		if wpis.Target == "/mnt/dane" {
			dane++
			if wpis.Source != "LABEL=dane" || wpis.FSType != "xfs" || !wpis.Managed {
				t.Errorf("wpis po zmianie = %+v", wpis)
			}
		}
	}
	if dane != 1 {
		t.Errorf("wpisow dla /mnt/dane = %d", dane)
	}
	// Wpis administratora hosta zostaje nietkniety.
	if !strings.Contains(string(tresc), "UUID=aaa / ext4") {
		t.Errorf("zgubiono cudzy wpis:\n%s", tresc)
	}

	if err := UsunWpisFstab(sciezka, "/mnt/dane"); err != nil {
		t.Fatal(err)
	}
	tresc, _ = os.ReadFile(sciezka)
	for _, wpis := range ParsujFstab(string(tresc)) {
		if wpis.Target == "/mnt/dane" {
			t.Errorf("wpis przetrwal usuniecie:\n%s", tresc)
		}
	}
}
