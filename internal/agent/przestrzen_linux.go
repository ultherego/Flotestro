//go:build linux

package agent

import (
	"syscall"

	"github.com/ultherego/flotestro/internal/modules/storage"
)

// uzupelnijZajetosc dopisuje zajetosc miejsca i i-wezlow.
//
// Wyczerpane i-wezly wygladaja jak dysk pelny, choc miejsce jeszcze jest -
// i odwrotnie. To dwie rozne awarie i panel ma je rozroznic, zamiast
// pokazywac jedna liczbe.
func uzupelnijZajetosc(montowania []storage.Mount) {
	for i := range montowania {
		if !montowania[i].Mounted {
			continue
		}
		var stat syscall.Statfs_t
		if err := syscall.Statfs(montowania[i].Target, &stat); err != nil {
			// Filesystem, ktorego nie dalo sie odpytac, zostaje bez liczb:
			// zero wygladaloby jak filesystem pusty.
			continue
		}
		rozmiar := stat.Blocks * uint64(stat.Bsize)
		dostepne := stat.Bavail * uint64(stat.Bsize)
		wolne := stat.Bfree * uint64(stat.Bsize)
		if rozmiar > 0 && wolne <= rozmiar {
			zajete := rozmiar - wolne
			procent := uint32(zajete * 100 / rozmiar)
			montowania[i].UsedPercent = &procent
			montowania[i].SizeBytes = &rozmiar
			montowania[i].AvailBytes = &dostepne
		}
		// Filesystemy sieciowe i wspoldzielone podaja liczbe i-wezlow
		// wymyslona: vboxsf zglasza wiecej wolnych niz wszystkich. Odejmowanie
		// dalo by wtedy liczbe bez znaczenia, wiec zostawiamy stan nieznany -
		// bo taki naprawde jest.
		if stat.Files > 0 && stat.Ffree <= stat.Files {
			zajete := stat.Files - stat.Ffree
			procent := uint32(zajete * 100 / stat.Files)
			montowania[i].InodesUsedPercent = &procent
		}
	}
}
