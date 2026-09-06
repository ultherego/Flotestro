package gateway

import (
	"testing"

	"github.com/ultherego/flotestro/internal/enrollment"
)

// TestTrasaZgloszeniaJestCzesciaZakresu pilnuje wlasciwosci, dla ktorej
// zamowienie w ogole niesie relay_id: token wyniesiony z izolowanej
// lokalizacji nie moze zarejestrowac hosta gdzie indziej.
//
// Relay jest terminatorem TLS i widzi token swojej lokalizacji. To jest cena
// za rejestracje w izolowanym site i dlatego zakres tokenu ma byc waski.
func TestTrasaZgloszeniaJestCzesciaZakresu(t *testing.T) {
	przypadki := []struct {
		nazwa   string
		scope   enrollment.Scope
		relay   poswiadczenieRelaya
		przejdz bool
	}{
		{
			nazwa:   "zwykly token bezposrednio",
			scope:   enrollment.Scope{Site: "lab"},
			przejdz: true,
		},
		{
			nazwa:   "token zwiazany z relayem nie przejdzie bezposrednio",
			scope:   enrollment.Scope{Site: "lab", RelayID: "r1"},
			przejdz: false,
		},
		{
			nazwa:   "token zwiazany z relayem przez ten relay",
			scope:   enrollment.Scope{Site: "lab", RelayID: "r1"},
			relay:   poswiadczenieRelaya{ID: "r1", Site: "lab"},
			przejdz: true,
		},
		{
			nazwa:   "token zwiazany z relayem przez inny relay",
			scope:   enrollment.Scope{Site: "lab", RelayID: "r1"},
			relay:   poswiadczenieRelaya{ID: "r2", Site: "lab"},
			przejdz: false,
		},
		{
			nazwa:   "token innej lokalizacji przez relay",
			scope:   enrollment.Scope{Site: "warsaw"},
			relay:   poswiadczenieRelaya{ID: "r1", Site: "lab"},
			przejdz: false,
		},
		{
			nazwa:   "token bez zwiazku przez relay swojej lokalizacji",
			scope:   enrollment.Scope{Site: "lab"},
			relay:   poswiadczenieRelaya{ID: "r1", Site: "lab"},
			przejdz: true,
		},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.nazwa, func(t *testing.T) {
			err := sprawdzTrase(przypadek.scope, przypadek.relay)
			if przejdz := err == nil; przejdz != przypadek.przejdz {
				t.Fatalf("sprawdzTrase = %v, oczekiwano przejscia = %v",
					err, przypadek.przejdz)
			}
		})
	}
}
