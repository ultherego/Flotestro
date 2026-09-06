package agent

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ultherego/flotestro/internal/identitystore"
)

// NazwaPlikuStanu jest plikiem, w ktorym agent zapisuje, co sie z nim dzieje.
const NazwaPlikuStanu = "status.json"

// StanAgenta jest obrazem pracy agenta widocznym z zewnatrz procesu.
//
// Bez niego narzedzie diagnostyczne moze powiedziec tylko tyle, co widac
// w systemie plikow: ze certyfikat istnieje i ze usluga jest uruchomiona.
// Operator na hoscie bez panelu potrzebuje odpowiedzi na inne pytanie -
// czy agent naprawde rozmawia z panelem i kiedy ostatnio cos wyslal.
type StanAgenta struct {
	AgentVersion string `json:"agent_version"`
	HostID       string `json:"host_id,omitempty"`
	// Gateway jest adresem, z ktorym agent rozmawia w tej sesji.
	Gateway string `json:"gateway,omitempty"`
	// ConnectedAt jest pusty, gdy sesji nie ma. Wtedy liczy sie LastError.
	ConnectedAt       *time.Time `json:"connected_at,omitempty"`
	DisconnectedAt    *time.Time `json:"disconnected_at,omitempty"`
	LastInventoryAt   *time.Time `json:"last_inventory_at,omitempty"`
	InventoryRevision string     `json:"inventory_revision,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// PisarzStanu utrwala stan agenta miedzy zdarzeniami sesji.
type PisarzStanu struct {
	sciezka string
	mu      sync.Mutex
	stan    StanAgenta
}

// NowyPisarzStanu tworzy pisarza w katalogu stanu agenta. Pusty katalog
// wylacza zapis: symulator floty nie ma po co pisac tysiaca plikow.
func NowyPisarzStanu(stateDir, hostID string) *PisarzStanu {
	if stateDir == "" {
		return nil
	}
	return &PisarzStanu{
		sciezka: filepath.Join(stateDir, NazwaPlikuStanu),
		stan:    StanAgenta{AgentVersion: Version, HostID: hostID},
	}
}

// Polaczony odnotowuje nawiazana sesje.
func (p *PisarzStanu) Polaczony(gateway string, chwila time.Time) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	chwilaUTC := chwila.UTC()
	p.stan.Gateway = gateway
	p.stan.ConnectedAt = &chwilaUTC
	p.stan.DisconnectedAt = nil
	p.stan.LastError = ""
	p.zapisz()
}

// Rozlaczony odnotowuje koniec sesji razem z powodem.
func (p *PisarzStanu) Rozlaczony(powod string, chwila time.Time) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	chwilaUTC := chwila.UTC()
	p.stan.ConnectedAt = nil
	p.stan.DisconnectedAt = &chwilaUTC
	p.stan.LastError = powod
	p.zapisz()
}

// Inwentarz odnotowuje wyslany raport.
func (p *PisarzStanu) Inwentarz(rewizja string, chwila time.Time) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	chwilaUTC := chwila.UTC()
	p.stan.LastInventoryAt = &chwilaUTC
	p.stan.InventoryRevision = rewizja
	p.zapisz()
}

// zapisz utrwala stan przez plik tymczasowy i zmiane nazwy.
//
// Przerwany zapis nie moze zostawic polowy pliku: narzedzie diagnostyczne
// czytaloby wtedy blad skladni zamiast stanu i wygladaloby to jak awaria
// agenta, ktorej nie ma.
func (p *PisarzStanu) zapisz() {
	p.stan.UpdatedAt = time.Now().UTC()
	tresc, err := json.MarshalIndent(p.stan, "", "  ")
	if err != nil {
		return
	}
	tymczasowy := p.sciezka + ".tmp"
	if err := os.WriteFile(tymczasowy, append(tresc, '\n'), 0o640); err != nil {
		return
	}
	_ = os.Rename(tymczasowy, p.sciezka)
}

// OdczytajStan czyta stan zapisany przez agenta.
func OdczytajStan(stateDir string) (StanAgenta, error) {
	var stan StanAgenta
	tresc, err := os.ReadFile(filepath.Join(stateDir, NazwaPlikuStanu))
	if err != nil {
		return stan, err
	}
	if err := json.Unmarshal(tresc, &stan); err != nil {
		return stan, err
	}
	return stan, nil
}

// StanTozsamosci opisuje tozsamosc zapisana na hoscie.
//
// Takze wtedy, gdy certyfikat wygasl albo jest nieczytelny: status ma o tym
// powiedziec, a nie zamilknac. Cisza wyglada tak samo jak host bez problemu.
type StanTozsamosci struct {
	Sciezki  IdentityPaths
	Obecna   bool
	HostID   string
	NotAfter time.Time
	Wygasl   bool
	Blad     string
}

// OdczytajTozsamosc czyta tozsamosc z katalogu stanu bez zadnego polaczenia.
//
// Najpierw magazyn generacji, potem stary uklad plikow: narzedzie na hoscie
// ma odpowiadac tak samo przed migracja i po niej.
func OdczytajTozsamosc(stateDir string) StanTozsamosci {
	magazyn := identitystore.Nowy(stateDir)
	if tozsamosc, err := magazyn.Biezaca(); err == nil {
		return StanTozsamosci{
			Sciezki: IdentityPaths{
				Key:  filepath.Join(tozsamosc.Katalog, identitystore.NazwaKlucza),
				Cert: filepath.Join(tozsamosc.Katalog, identitystore.NazwaCertyfikatu),
				CA:   filepath.Join(tozsamosc.Katalog, identitystore.NazwaZaufania),
			},
			Obecna:   true,
			HostID:   tozsamosc.HostID,
			NotAfter: tozsamosc.NotAfter,
			Wygasl:   time.Now().After(tozsamosc.NotAfter),
		}
	}

	sciezki := paths(stateDir)
	stan := StanTozsamosci{Sciezki: sciezki}

	certPEM, err := os.ReadFile(sciezki.Cert)
	if err != nil {
		stan.Blad = err.Error()
		return stan
	}
	blok, _ := pem.Decode(certPEM)
	if blok == nil {
		stan.Blad = "certyfikat nie jest poprawnym PEM"
		return stan
	}
	certyfikat, err := x509.ParseCertificate(blok.Bytes)
	if err != nil {
		stan.Blad = err.Error()
		return stan
	}
	stan.Obecna = true
	stan.HostID = certyfikat.Subject.CommonName
	stan.NotAfter = certyfikat.NotAfter
	stan.Wygasl = time.Now().After(certyfikat.NotAfter)
	return stan
}
