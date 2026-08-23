package storage

import (
	"strings"
	"testing"
)

// Sama sciezka nie wystarczy: /dev/sdb po restarcie potrafi byc innym dyskiem
// niz ten, ktory operator ogladal.
func TestTozsamoscUrzadzeniaMusiSieZgadzac(t *testing.T) {
	urzadzenie := &Device{Path: "/dev/sdb", Serial: "VB1234", SizeBytes: 2147483648}

	if err := (TozsamoscUrzadzenia{Path: "/dev/sdb", Serial: "VB1234", SizeBytes: 2147483648}).
		Zgadza(urzadzenie); err != nil {
		t.Errorf("odrzucono zgodne urzadzenie: %v", err)
	}
	if err := (TozsamoscUrzadzenia{Path: "/dev/sdb", Serial: "INNY"}).Zgadza(urzadzenie); err == nil {
		t.Error("przyjeto urzadzenie o innym serialu")
	}
	if err := (TozsamoscUrzadzenia{Path: "/dev/sdb", SizeBytes: 1024}).Zgadza(urzadzenie); err == nil {
		t.Error("przyjeto urzadzenie o innym rozmiarze")
	}
	if err := (TozsamoscUrzadzenia{Path: "/dev/sdz"}).Zgadza(nil); err == nil {
		t.Error("przyjeto urzadzenie, ktorego nie ma")
	}
}

// Formatowanie dysku, na ktorym cos stoi, nie jest operacja, ktora ma sie udac.
func TestUrzadzenieWUzyciuJestRozpoznawanePrzezPotomkow(t *testing.T) {
	snapshot := Snapshot{Devices: []Device{
		{Path: "/dev/sda", Type: TypDysk},
		{Path: "/dev/sda1", Type: TypPartycja, Parent: "/dev/sda", Mountpoints: []string{"/boot"}},
		{Path: "/dev/sdb", Type: TypDysk},
	}}
	if punkt := WUzyciu(snapshot, "/dev/sda"); punkt != "/boot" {
		t.Errorf("dysk z zamontowana partycja = %q", punkt)
	}
	if punkt := WUzyciu(snapshot, "/dev/sdb"); punkt != "" {
		t.Errorf("pusty dysk uznany za zajety: %q", punkt)
	}
}

// Rozszerzamy wylacznie w gore: lvextend zmniejszajacy wolumen ucina dane,
// ktore filesystem uwaza za swoje.
func TestRozszerzenieWolumenuTylkoWGore(t *testing.T) {
	for _, zly := range []string{"10G", "-10G", "100%", "duzo", "+10X"} {
		if _, err := ArgumentyRozszerzeniaLV("/dev/vg/lv", zly, true); err == nil {
			t.Errorf("przyjeto rozmiar %q", zly)
		}
	}
	argumenty, err := ArgumentyRozszerzeniaLV("/dev/vg/lv", "+512M", true)
	if err != nil {
		t.Fatal(err)
	}
	polecenie := strings.Join(argumenty, " ")
	// Wolumen wiekszy od filesystemu nie daje ani bajta miejsca, wiec
	// rozszerzenie idzie razem.
	if !strings.Contains(polecenie, "--resizefs") {
		t.Errorf("polecenie = %q", polecenie)
	}
	if !strings.HasSuffix(polecenie, "/dev/vg/lv") {
		t.Errorf("polecenie = %q", polecenie)
	}
}

func TestFormatowanieIczyszczenieSprawdzajaArgumenty(t *testing.T) {
	if _, err := ArgumentyFormatowania("/dev/sdb1", "btrfs", ""); err == nil {
		t.Error("przyjeto nieobslugiwany filesystem")
	}
	if _, err := ArgumentyFormatowania("sdb1", "ext4", ""); err == nil {
		t.Error("przyjeto urzadzenie bez sciezki")
	}
	if _, err := ArgumentyFormatowania("/dev/sdb1", "ext4", "zla etykieta"); err == nil {
		t.Error("przyjeto etykiete z odstepem")
	}
	argumenty, err := ArgumentyFormatowania("/dev/sdb1", "ext4", "dane")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argumenty, " ") != SciezkaMkfsExt4+" -q -L dane /dev/sdb1" {
		t.Errorf("polecenie = %v", argumenty)
	}

	czyszczenie, err := ArgumentyCzyszczenia("/dev/sdb")
	if err != nil {
		t.Fatal(err)
	}
	// Czyscimy sygnatury, a nie dwa terabajty zerami: to drugie trwa
	// godziny i nie jest tym, o co operator prosi.
	if !strings.Contains(strings.Join(czyszczenie, " "), "--all") {
		t.Errorf("polecenie = %v", czyszczenie)
	}
}

func TestRozszerzenieFilesystemuZalezyOdTypu(t *testing.T) {
	ext, err := ArgumentyRozszerzeniaFS("/dev/vg/lv", "ext4", "/dane")
	if err != nil {
		t.Fatal(err)
	}
	if ext[len(ext)-1] != "/dev/vg/lv" {
		t.Errorf("ext4 = %v", ext)
	}
	// xfs_growfs przyjmuje punkt montowania, a nie urzadzenie.
	xfs, err := ArgumentyRozszerzeniaFS("/dev/vg/lv", "xfs", "/dane")
	if err != nil {
		t.Fatal(err)
	}
	if xfs[len(xfs)-1] != "/dane" {
		t.Errorf("xfs = %v", xfs)
	}
	if _, err := ArgumentyRozszerzeniaFS("/dev/vg/lv", "xfs", ""); err == nil {
		t.Error("przyjeto rozszerzenie xfs bez punktu montowania")
	}
	if _, err := ArgumentyRozszerzeniaFS("/dev/vg/lv", "vfat", "/dane"); err == nil {
		t.Error("przyjeto nieobslugiwany filesystem")
	}
}

// Ten sam wolumen ma dwie nazwy, a myslnik w nazwie grupy jest w postaci
// mapper podwojony. Porownanie napisow rozjezdza sie dokladnie tam, gdzie
// operator patrzy.
func TestWolumenRozpoznawanyPoObuNazwach(t *testing.T) {
	wolumen := LogicalVolume{Name: "root", Group: "debian-13-vg", Path: "/dev/debian-13-vg/root"}

	for _, sciezka := range []string{
		"/dev/debian-13-vg/root",
		"/dev/mapper/debian--13--vg-root",
	} {
		if !PasujeWolumen(wolumen, sciezka) {
			t.Errorf("nie rozpoznano wolumenu po sciezce %q", sciezka)
		}
	}
	for _, obca := range []string{"", "/dev/sdb", "/dev/mapper/debian--13--vg-swap_1"} {
		if PasujeWolumen(wolumen, obca) {
			t.Errorf("rozpoznano cudza sciezke %q", obca)
		}
	}
}
