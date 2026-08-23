package storage

import (
	"fmt"
	"regexp"
	"strings"
)

// Sciezki narzedzi zmieniajacych przestrzen dyskowa.
const (
	SciezkaLVExtend  = "/usr/sbin/lvextend"
	SciezkaResize2fs = "/usr/sbin/resize2fs"
	SciezkaXFSGrow   = "/usr/sbin/xfs_growfs"
	SciezkaMkfsExt4  = "/usr/sbin/mkfs.ext4"
	SciezkaMkfsXFS   = "/usr/sbin/mkfs.xfs"
	SciezkaWipefs    = "/usr/sbin/wipefs"
)

var (
	rozmiarLVM = regexp.MustCompile(`^\+?\d{1,9}[KMGTkmgt]$|^\+?\d{1,3}%(FREE|VG|PVS)$`)
	etykietaFS = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,16}$`)
)

// TozsamoscUrzadzenia opisuje, czego operacja spodziewa sie na hoscie.
//
// Sama sciezka nie wystarczy: /dev/sdb po restarcie potrafi byc innym dyskiem
// niz ten, ktory operator ogladal. Przy formatowaniu i czyszczeniu to jest
// roznica miedzy pustym dyskiem a cudzymi danymi, wiec host sprawdza
// wszystko, co panel podal - i odmawia przy pierwszej niezgodnosci.
type TozsamoscUrzadzenia struct {
	Path      string
	Serial    string
	UUID      string
	SizeBytes uint64
}

// Zgadza porownuje oczekiwana tozsamosc ze stanem hosta.
func (t TozsamoscUrzadzenia) Zgadza(urzadzenie *Device) error {
	if urzadzenie == nil {
		return fmt.Errorf("urzadzenie %s nie istnieje na tym hoscie", t.Path)
	}
	if t.Serial != "" && urzadzenie.Serial != t.Serial {
		return fmt.Errorf("urzadzenie %s ma serial %q, a plan zaklada %q",
			t.Path, urzadzenie.Serial, t.Serial)
	}
	if t.UUID != "" && urzadzenie.UUID != t.UUID {
		return fmt.Errorf("urzadzenie %s ma UUID %q, a plan zaklada %q",
			t.Path, urzadzenie.UUID, t.UUID)
	}
	// Rozmiar rozstrzyga tam, gdzie dysk nie ma ani serialu, ani UUID.
	if t.SizeBytes != 0 && urzadzenie.SizeBytes != t.SizeBytes {
		return fmt.Errorf("urzadzenie %s ma %d bajtow, a plan zaklada %d",
			t.Path, urzadzenie.SizeBytes, t.SizeBytes)
	}
	return nil
}

// WUzyciu mowi, czy urzadzenie albo cokolwiek pod nim jest zamontowane.
//
// Sprawdzenie jest zachowawcze i obejmuje urzadzenia potomne: dysk
// sformatowany razem z partycja rootowa jest tym samym wypadkiem co dysk
// systemowy sformatowany wprost. Zwracamy punkt montowania, bo to on
// tlumaczy odmowe operatorowi lepiej niz samo "urzadzenie jest zajete".
func WUzyciu(snapshot Snapshot, sciezka string) string {
	var sprawdz func(sciezka string) string
	sprawdz = func(sciezka string) string {
		for _, urzadzenie := range snapshot.Devices {
			if urzadzenie.Path == sciezka && len(urzadzenie.Mountpoints) > 0 {
				return urzadzenie.Mountpoints[0]
			}
		}
		for _, urzadzenie := range snapshot.Devices {
			if urzadzenie.Parent != sciezka {
				continue
			}
			if punkt := sprawdz(urzadzenie.Path); punkt != "" {
				return punkt
			}
		}
		return ""
	}
	return sprawdz(sciezka)
}

// PasujeWolumen mowi, czy sciezka wskazuje ten wolumen logiczny.
//
// Ten sam wolumen ma dwie nazwy: /dev/<grupa>/<wolumen> podawana przez lvs
// i /dev/mapper/<grupa>-<wolumen> widoczna w lsblk i w fstab. Myslnik w nazwie
// grupy jest w tej drugiej podwojony, bo pojedynczy oddziela grupe od
// wolumenu. Porownanie samych napisow rozjezdza sie wiec dokladnie tam, gdzie
// operator patrzy - w tabeli montowan.
func PasujeWolumen(wolumen LogicalVolume, sciezka string) bool {
	if sciezka == "" {
		return false
	}
	if wolumen.Path == sciezka {
		return true
	}
	if sciezka == "/dev/"+wolumen.Group+"/"+wolumen.Name {
		return true
	}
	podwojony := func(nazwa string) string { return strings.ReplaceAll(nazwa, "-", "--") }
	return sciezka == "/dev/mapper/"+podwojony(wolumen.Group)+"-"+podwojony(wolumen.Name)
}

// ArgumentyRozszerzeniaLV sklada polecenie powiekszenia wolumenu.
//
// Rozszerzamy wylacznie w gore: lvextend zmniejszajacy wolumen ucina dane,
// ktore filesystem uwaza za swoje. Zmniejszanie jest osobna operacja i
// wymaga wczesniejszego zmniejszenia filesystemu, wiec panel go tu nie robi.
func ArgumentyRozszerzeniaLV(sciezka, rozmiar string, rozszerzFS bool) ([]string, error) {
	if !strings.HasPrefix(sciezka, "/dev/") || !sciezkaUrzadzenia.MatchString(sciezka) {
		return nil, fmt.Errorf("wolumen %q nie jest sciezka w /dev", sciezka)
	}
	if !rozmiarLVM.MatchString(rozmiar) {
		return nil, fmt.Errorf("rozmiar %q ma byc przyrostem (+10G) albo udzialem (+100%%FREE)", rozmiar)
	}
	if !strings.HasPrefix(rozmiar, "+") {
		return nil, fmt.Errorf("panel rozszerza wolumen o zadana wielkosc; rozmiar musi zaczynac sie od +")
	}
	argumenty := []string{SciezkaLVExtend, "--size", rozmiar}
	if rozszerzFS {
		// Filesystem powiekszony razem z wolumenem to jedna operacja, a nie
		// dwie: wolumen wiekszy od filesystemu nie daje ani bajta miejsca.
		argumenty = append(argumenty, "--resizefs")
	}
	return append(argumenty, sciezka), nil
}

// ArgumentyRozszerzeniaFS sklada polecenie powiekszenia filesystemu.
func ArgumentyRozszerzeniaFS(sciezka, typ, punktMontowania string) ([]string, error) {
	if !sciezkaUrzadzenia.MatchString(sciezka) {
		return nil, fmt.Errorf("urzadzenie %q nie jest sciezka w /dev", sciezka)
	}
	switch typ {
	case "ext2", "ext3", "ext4":
		return []string{SciezkaResize2fs, sciezka}, nil
	case "xfs":
		// xfs_growfs pracuje na zamontowanym filesystemie i przyjmuje punkt
		// montowania, a nie urzadzenie - inaczej niz reszta.
		if punktMontowania == "" {
			return nil, fmt.Errorf("xfs rozszerza sie tylko zamontowany")
		}
		return []string{SciezkaXFSGrow, punktMontowania}, nil
	}
	return nil, fmt.Errorf("panel nie rozszerza filesystemu %q", typ)
}

// ArgumentyFormatowania sklada polecenie zalozenia filesystemu.
func ArgumentyFormatowania(sciezka, typ, etykieta string) ([]string, error) {
	if !sciezkaUrzadzenia.MatchString(sciezka) {
		return nil, fmt.Errorf("urzadzenie %q nie jest sciezka w /dev", sciezka)
	}
	if !etykietaFS.MatchString(etykieta) {
		return nil, fmt.Errorf("etykieta %q zawiera niedozwolony znak", etykieta)
	}
	switch typ {
	case "ext4":
		argumenty := []string{SciezkaMkfsExt4, "-q"}
		if etykieta != "" {
			argumenty = append(argumenty, "-L", etykieta)
		}
		return append(argumenty, sciezka), nil
	case "xfs":
		argumenty := []string{SciezkaMkfsXFS, "-q"}
		if etykieta != "" {
			argumenty = append(argumenty, "-L", etykieta)
		}
		return append(argumenty, sciezka), nil
	}
	return nil, fmt.Errorf("panel zaklada filesystem ext4 albo xfs, nie %q", typ)
}

// ArgumentyCzyszczenia sklada polecenie usuniecia sygnatur filesystemu.
//
// Czyscimy sygnatury, a nie cala zawartosc: nadpisanie dwoch terabajtow
// zerami trwa godziny i nie jest tym, o co operator prosi, gdy chce oddac
// dysk do ponownego uzycia. To, ze dane sa nadal fizycznie na plytach, jest
// faktem, ktory panel ma powiedziec wprost.
func ArgumentyCzyszczenia(sciezka string) ([]string, error) {
	if !sciezkaUrzadzenia.MatchString(sciezka) {
		return nil, fmt.Errorf("urzadzenie %q nie jest sciezka w /dev", sciezka)
	}
	return []string{SciezkaWipefs, "--all", "--force", sciezka}, nil
}
