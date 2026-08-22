package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Trust jest zbiorem CA floty: jednym podpisujacym i dowolna liczba
// wycofywanych, ktore nadal sa uznawane.
//
// Wymiana CA nie moze zerwac floty. Nowe CA musi byc uznawane przez panel
// zanim zacznie podpisywac, a stare musi byc uznawane jeszcze przez caly
// okres waznosci wydanych nim certyfikatow agentow. Zbior obowiazuje wiec
// w obu kierunkach: panel ufa wszystkim wpisom, a agent dostaje je wszystkie
// w bundlu przy enrollmencie i przy kazdym odnowieniu.
type Trust struct {
	mu sync.RWMutex
	// active podpisuje nowe certyfikaty.
	active *CA
	// pending jest juz uznawane i rozsylane w bundlu, ale jeszcze nic nie
	// podpisuje. Ten stan jest istota bezpiecznej wymiany: gdyby nowe CA od
	// razu podpisywalo, panel po restarcie przedstawialby certyfikat serwera,
	// ktorego nie uznaje zaden agent poza tymi, ktore zdazyly sie odnowic.
	pending *CA
	// pendingAt jest chwila przygotowania; od niej liczy sie, ktore hosty
	// zdazyly dostac nowy bundle.
	pendingAt time.Time
	// retired sa nadal uznawane, ale juz nic nie podpisuja.
	retired []*CA
	dir     string
}

// retiredDir trzyma CA wycofane z podpisywania.
const retiredDir = "ca-retired"

// pendingCertFile i pendingKeyFile trzymaja CA przygotowane do przejecia.
const (
	pendingCertFile = "ca-pending.pem"
	pendingKeyFile  = "ca-pending.key"
	// pendingAtFile zapisuje chwile przygotowania CA. Nie wystarczy data
	// poczatku waznosci certyfikatu: jest ona celowo cofnieta o godzine na
	// poczet rozjazdu zegarow, wiec host odnowiony przed samym przygotowaniem
	// wygladalby na taki, ktory nowe CA juz zna.
	pendingAtFile = "ca-pending.at"
)

// EnsureTrust wczytuje zbior CA z katalogu stanu, tworzac pierwsze CA przy
// pierwszym starcie.
func EnsureTrust(dir string) (*Trust, error) {
	active, err := EnsureCA(dir)
	if err != nil {
		return nil, err
	}
	trust := &Trust{active: active, dir: dir}

	certPEM, certErr := os.ReadFile(filepath.Join(dir, pendingCertFile))
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, pendingKeyFile))
	if certErr == nil && keyErr == nil {
		pending, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pendingCertFile, err)
		}
		trust.pending = pending
		// Brak albo uszkodzenie znacznika nie moze zatrzymac panelu. Przyjmujemy
		// wtedy chwile biezaca, czyli zalozenie, ze zaden host jeszcze nowego CA
		// nie zna: przejecie podpisywania zostanie wstrzymane do czasu odnowienia
		// certyfikatow. Blad w te strone kosztuje czekanie, blad w druga -
		// odciecie floty.
		trust.pendingAt = time.Now().UTC()
		if stamp, err := os.ReadFile(filepath.Join(dir, pendingAtFile)); err == nil {
			if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(string(stamp))); err == nil {
				trust.pendingAt = parsed
			}
		}
		if err := writeFileAtomic(filepath.Join(dir, pendingAtFile),
			[]byte(trust.pendingAt.Format(time.RFC3339)), 0o644); err != nil {
			return nil, err
		}
	} else if certErr != nil && !os.IsNotExist(certErr) {
		return nil, certErr
	}

	entries, err := os.ReadDir(filepath.Join(dir, retiredDir))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("katalog wycofanych CA: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}
		path := filepath.Join(dir, retiredDir, entry.Name())
		certPEM, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		// Wycofane CA nie ma przy sobie klucza: nie ma juz nic podpisywac,
		// a trzymanie klucza bez potrzeby tylko powieksza ryzyko.
		cert, err := parseCertificateOnly(certPEM)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		trust.retired = append(trust.retired, &CA{Certificate: cert, PEM: certPEM})
	}
	return trust, nil
}

// Active zwraca CA podpisujace nowe certyfikaty.
func (t *Trust) Active() *CA {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.active
}

// Pool buduje zbior zaufania do weryfikacji certyfikatow agentow.
func (t *Trust) Pool() *x509.CertPool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pool := x509.NewCertPool()
	pool.AddCert(t.active.Certificate)
	if t.pending != nil {
		pool.AddCert(t.pending.Certificate)
	}
	for _, ca := range t.retired {
		pool.AddCert(ca.Certificate)
	}
	return pool
}

// Bundle zwraca wszystkie uznawane CA w formacie PEM. Agent zapisuje go
// u siebie, wiec musi zawierac takze CA, ktore dopiero zacznie podpisywac.
func (t *Trust) Bundle() []byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	bundle := make([]byte, 0, len(t.active.PEM))
	bundle = append(bundle, t.active.PEM...)
	if t.pending != nil {
		bundle = append(bundle, t.pending.PEM...)
	}
	for _, ca := range t.retired {
		bundle = append(bundle, ca.PEM...)
	}
	return bundle
}

// Authority opisuje jedno CA na potrzeby przegladu i metryk.
type Authority struct {
	Subject     string    `json:"subject"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	// State: active podpisuje, pending czeka na przejecie, retired jest
	// jeszcze uznawane. Sam znacznik "active" nie odroznilby dwoch ostatnich.
	State string `json:"state"`
	// PreparedAt jest chwila przygotowania CA. Od niej liczy sie, ktore hosty
	// zdazyly juz dostac nowy bundle.
	PreparedAt time.Time `json:"prepared_at,omitempty"`
}

// Authorities wypisuje zbior zaufania, zaczynajac od CA podpisujacego.
func (t *Trust) Authorities() []Authority {
	t.mu.RLock()
	defer t.mu.RUnlock()

	list := []Authority{describe(t.active, "active")}
	if t.pending != nil {
		przygotowane := describe(t.pending, "pending")
		przygotowane.PreparedAt = t.pendingAt
		list = append(list, przygotowane)
	}
	for _, ca := range t.retired {
		list = append(list, describe(ca, "retired"))
	}
	sort.SliceStable(list[1:], func(i, j int) bool {
		return list[1+i].NotAfter.Before(list[1+j].NotAfter)
	})
	return list
}

func describe(ca *CA, state string) Authority {
	authority := Authority{
		Subject:     ca.Certificate.Subject.CommonName,
		Serial:      ca.Certificate.SerialNumber.String(),
		Fingerprint: fingerprintHex(ca.Certificate.Raw),
		NotBefore:   ca.Certificate.NotBefore,
		NotAfter:    ca.Certificate.NotAfter,
		State:       state,
	}
	return authority
}

// Prepare tworzy nowe CA i wlacza je do zbioru zaufania, ale jeszcze nie
// pozwala mu podpisywac.
//
// To pierwsza z dwoch faz wymiany. Od tej chwili panel uznaje nowe CA, a kazdy
// agent dostaje je w bundlu przy najblizszym odnowieniu certyfikatu. Dopiero
// gdy cala flota ma juz nowe CA u siebie, wolno mu zaczac podpisywac.
//
// Jednofazowa wymiana wygladalaby na dzialajaca do pierwszego restartu panelu:
// certyfikat serwera wystawiony nowym CA nie zostalby uznany przez zadnego
// agenta, ktory nie zdazyl sie odnowic, i cala flota stracilaby lacznosc.
func (t *Trust) Prepare() (Authority, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pending != nil {
		return Authority{}, fmt.Errorf("CA przygotowane do przejecia juz istnieje")
	}
	nowe, certPEM, keyPEM, err := newCA()
	if err != nil {
		return Authority{}, err
	}
	nowe.AgentTTL = t.active.AgentTTL

	if err := writeFileAtomic(filepath.Join(t.dir, pendingCertFile), certPEM, 0o644); err != nil {
		return Authority{}, err
	}
	// Klucz CA jest najbardziej wrazliwym materialem w systemie.
	if err := writeFileAtomic(filepath.Join(t.dir, pendingKeyFile), keyPEM, 0o600); err != nil {
		return Authority{}, err
	}
	teraz := time.Now().UTC()
	if err := writeFileAtomic(filepath.Join(t.dir, pendingAtFile),
		[]byte(teraz.Format(time.RFC3339)), 0o644); err != nil {
		return Authority{}, err
	}
	t.pending = nowe
	t.pendingAt = teraz

	przygotowane := describe(nowe, "pending")
	przygotowane.PreparedAt = teraz
	return przygotowane, nil
}

// Activate przekazuje podpisywanie przygotowanemu CA, a dotychczasowe
// przenosi do uznawanych.
//
// Wywolujacy sprawdza wczesniej, ze kazdy host ma juz nowe CA u siebie;
// tutaj pilnujemy tylko spojnosci samego zbioru.
func (t *Trust) Activate() (Authority, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pending == nil {
		return Authority{}, fmt.Errorf("nie ma CA przygotowanego do przejecia")
	}

	// Dotychczasowe CA zapisujemy jako wycofane, zanim nowe stanie sie
	// podpisujacym: przerwanie w tym miejscu zostawia flote z CA, ktore
	// panel nadal uznaje.
	if err := os.MkdirAll(filepath.Join(t.dir, retiredDir), 0o700); err != nil {
		return Authority{}, err
	}
	poprzednie := filepath.Join(t.dir, retiredDir,
		t.active.Certificate.SerialNumber.String()+".pem")
	if err := os.WriteFile(poprzednie, t.active.PEM, 0o644); err != nil {
		return Authority{}, err
	}

	pendingKey, err := os.ReadFile(filepath.Join(t.dir, pendingKeyFile))
	if err != nil {
		return Authority{}, err
	}
	if err := writeFileAtomic(filepath.Join(t.dir, "ca.pem"), t.pending.PEM, 0o644); err != nil {
		return Authority{}, err
	}
	if err := writeFileAtomic(filepath.Join(t.dir, "ca.key"), pendingKey, 0o600); err != nil {
		return Authority{}, err
	}
	_ = os.Remove(filepath.Join(t.dir, pendingCertFile))
	_ = os.Remove(filepath.Join(t.dir, pendingKeyFile))
	_ = os.Remove(filepath.Join(t.dir, pendingAtFile))

	t.retired = append(t.retired, &CA{Certificate: t.active.Certificate, PEM: t.active.PEM})
	t.active = t.pending
	t.pending = nil
	return describe(t.active, "active"), nil
}

// Pending zwraca CA przygotowane do przejecia wraz z chwila przygotowania.
func (t *Trust) Pending() (*CA, time.Time) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.pending, t.pendingAt
}

// Retire usuwa wycofane CA ze zbioru zaufania.
//
// Operacja jest nieodwracalna dla hostow, ktore nadal maja certyfikat wydany
// tym CA: przestana byc wpuszczane. Dlatego panel odmawia, dopoki takie hosty
// istnieja - decyzje o ich odcieciu podejmuje sie osobno, przez odwolanie
// certyfikatu albo kwarantanne hosta.
func (t *Trust) Retire(fingerprint string, hostsUsing int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if hostsUsing > 0 {
		return fmt.Errorf("z tego CA korzysta jeszcze %d hostow", hostsUsing)
	}
	if fingerprintHex(t.active.Certificate.Raw) == fingerprint {
		return fmt.Errorf("nie mozna usunac CA, ktore podpisuje nowe certyfikaty")
	}
	if t.pending != nil && fingerprintHex(t.pending.Certificate.Raw) == fingerprint {
		// Porzucenie przygotowanego CA jest dozwolone: nic nim jeszcze nie
		// podpisano, a agenci, ktorzy je dostali, poprostu przestana je znac
		// przy nastepnym odnowieniu.
		_ = os.Remove(filepath.Join(t.dir, pendingCertFile))
		_ = os.Remove(filepath.Join(t.dir, pendingKeyFile))
		_ = os.Remove(filepath.Join(t.dir, pendingAtFile))
		t.pending = nil
		t.pendingAt = time.Time{}
		return nil
	}

	for index, ca := range t.retired {
		if fingerprintHex(ca.Certificate.Raw) != fingerprint {
			continue
		}
		path := filepath.Join(t.dir, retiredDir, ca.Certificate.SerialNumber.String()+".pem")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		t.retired = append(t.retired[:index], t.retired[index+1:]...)
		return nil
	}
	return fmt.Errorf("nie znaleziono CA o odcisku %s", fingerprint)
}

// NotAfter zwraca termin CA podpisujacego; metryki pilnuja wlasnie jego.
func (t *Trust) NotAfter() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.active.NotAfter()
}

// parseCertificateOnly wczytuje certyfikat bez klucza prywatnego.
func parseCertificateOnly(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("brak bloku PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func fingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// writeFileAtomic podmienia plik przez plik tymczasowy i zmiane nazwy.
// Przerwanie w polowie zapisu klucza CA zostawiloby panel bez tozsamosci
// calej floty.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".nowy"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
