package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	sshmodul "github.com/ultherego/flotestro/internal/modules/ssh"
)

// Sciezki narzedzi sshd.
const (
	sciezkaSshd      = "/usr/sbin/sshd"
	sciezkaSshKeygen = "/usr/bin/ssh-keygen"
)

// applySSH obsluguje operacje na serwerze sshd.
func (s *Server) applySSH(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.SshRequest) *helperv1.HelperResponse {
	if !s.unitMutex.TryLock() {
		return reject(ErrorLocked, "inna operacja na jednostkach jest w toku")
	}
	defer s.unitMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if !exists(sciezkaSshd) {
		return reject(ErrorUnsupported, "ten host nie ma serwera sshd")
	}

	switch action.GetOperation() {
	case helperv1.SshRequest_OPERATION_READ:
		return odpowiedzSSH(s.czytajSSH(actionCtx), "", nil)
	case helperv1.SshRequest_OPERATION_APPLY:
		return s.zapiszKonfiguracjeSSH(actionCtx, action)
	case helperv1.SshRequest_OPERATION_ROTATE_HOSTKEY:
		return s.wymienKluczHosta(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "nieznana operacja na sshd")
}

// zapiszKonfiguracjeSSH zapisuje plik panelu i przeladowuje serwer.
//
// Kolejnosc jest tu cala trescia operacji: zapis, sprawdzenie skladni przez
// sam sshd, dopiero potem przeladowanie. Serwer przeladowany z bledna
// konfiguracja nie wstaje, a wtedy nie ma juz czym go naprawic zdalnie.
func (s *Server) zapiszKonfiguracjeSSH(ctx context.Context, action *helperv1.SshRequest) *helperv1.HelperResponse {
	ustawienia := ustawieniaZZadania(action)
	stan := s.czytajSSH(ctx)

	// Serwer, do ktorego nie da sie zalogowac zadna metoda, nie jest
	// zabezpieczony - jest niedostepny.
	if !action.GetAllowLockout() && sshmodul.OdcinaWszystkieMetody(ustawienia, stan) {
		return reject(ErrorUnsupported,
			"po tej zmianie nie zostalaby zadna dzialajaca metoda uwierzytelnienia; "+
				"swiadome odciecie wymaga jawnej zgody operatora")
	}

	tresc, err := sshmodul.SkladajDropIn(ustawienia)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	poprzednia, bylaWczesniej := poprzedniDropIn()
	if err := zapiszDropIn(tresc); err != nil {
		return reject(ErrorExecFailed, "zapis konfiguracji: "+err.Error())
	}

	// sshd -t czyta cala konfiguracje razem z dolaczanymi plikami, wiec
	// sprawdza dokladnie to, co zaraz przeczyta serwer.
	if wyjscie, err := uruchomNarzedzie(ctx, []string{sciezkaSshd, "-t"}); err != nil {
		przywrocDropIn(poprzednia, bylaWczesniej)
		return reject(ErrorMalformed, "sshd odrzucil konfiguracje: "+wyjscie)
	}

	jednostka := stan.Unit
	if jednostka == "" {
		jednostka = jednostkaSSH()
	}
	// Przeladowanie, a nie restart: sesje, ktore juz trwaja, maja przezyc
	// zmiane. Operator siedzacy na tym hoscie po ssh jest jedna z nich.
	if wyjscie, err := uruchomNarzedzie(ctx,
		[]string{"/usr/bin/systemctl", "reload", jednostka}); err != nil {
		przywrocDropIn(poprzednia, bylaWczesniej)
		_, _ = uruchomNarzedzie(ctx, []string{"/usr/bin/systemctl", "reload", jednostka})
		return reject(ErrorExecFailed, "przeladowanie "+jednostka+": "+wyjscie)
	}

	po := s.czytajSSH(ctx)
	// W sshd wygrywa pierwsza wartosc, a pliki dolaczane maja kolejnosc
	// alfabetyczna: wczesniejszy plik administratora hosta przeslania nasz.
	// Cisza w tym miejscu bylaby falszywym sukcesem.
	rozbiezne := sshmodul.RozbiezneUstawienia(ustawienia, po)
	komunikat := "konfiguracja zapisana i przeladowana"
	if len(rozbiezne) > 0 {
		komunikat = "konfiguracja zapisana, ale czesc ustawien nie doszla do skutku"
	}
	return odpowiedzSSH(po, komunikat, rozbiezne)
}

// wymienKluczHosta generuje nowy klucz hosta wskazanego typu.
//
// Wymiana klucza zmienia tozsamosc hosta widziana przez wszystkich klientow:
// kazdy z nich zobaczy ostrzezenie o zmianie known_hosts, a automatyzacja
// oparta o odcisk przestanie dzialac. Dlatego stary klucz zostaje obok,
// z data w nazwie - zeby dalo sie go przywrocic recznie.
func (s *Server) wymienKluczHosta(ctx context.Context, action *helperv1.SshRequest) *helperv1.HelperResponse {
	typ := action.GetKeyType()
	if typ != "ed25519" && typ != "rsa" && typ != "ecdsa" {
		return reject(ErrorMalformed, "panel wymienia klucze ed25519, rsa albo ecdsa, nie "+typ)
	}
	if !exists(sciezkaSshKeygen) {
		return reject(ErrorUnsupported, "ten host nie ma ssh-keygen")
	}
	sciezka := "/etc/ssh/ssh_host_" + typ + "_key"
	kopia := sciezka + ".flotestro-" + time.Now().UTC().Format("20060102T150405")

	if exists(sciezka) {
		if err := os.Rename(sciezka, kopia); err != nil {
			return reject(ErrorExecFailed, "odlozenie starego klucza: "+err.Error())
		}
		if exists(sciezka + ".pub") {
			_ = os.Rename(sciezka+".pub", kopia+".pub")
		}
	}

	if wyjscie, err := uruchomNarzedzie(ctx, []string{sciezkaSshKeygen,
		"-q", "-t", typ, "-N", "", "-f", sciezka}); err != nil {
		// Bez klucza serwer nie wstanie, wiec wracamy do poprzedniego.
		if exists(kopia) {
			_ = os.Rename(kopia, sciezka)
			_ = os.Rename(kopia+".pub", sciezka+".pub")
		}
		return reject(ErrorExecFailed, "generowanie klucza: "+wyjscie)
	}

	jednostka := jednostkaSSH()
	if wyjscie, err := uruchomNarzedzie(ctx,
		[]string{"/usr/bin/systemctl", "reload", jednostka}); err != nil {
		return reject(ErrorExecFailed, "przeladowanie "+jednostka+": "+wyjscie)
	}
	return odpowiedzSSH(s.czytajSSH(ctx),
		"klucz "+typ+" wymieniony; stary zostal jako "+kopia+
			"; kazdy klient zobaczy zmiane odcisku w known_hosts", nil)
}

// czytajSSH sklada obraz konfiguracji serwera.
func (s *Server) czytajSSH(ctx context.Context) sshmodul.Snapshot {
	snapshot := sshmodul.Snapshot{ObservedAt: time.Now().UTC(), ManagedPath: sshmodul.SciezkaDropIn}

	wyjscie, err := wyjscieNarzedzia(ctx, sciezkaSshd, "-T")
	if err != nil {
		snapshot.UnavailableReason = "sshd -T: " + err.Error()
		return snapshot
	}
	efektywna := sshmodul.ParsujEffective(wyjscie)
	efektywna.ObservedAt = snapshot.ObservedAt
	efektywna.ManagedPath = snapshot.ManagedPath
	snapshot = efektywna

	if tresc, err := os.ReadFile(sshmodul.SciezkaDropIn); err == nil {
		snapshot.Managed = string(tresc)
		snapshot.ManagedPresent = true
	}
	snapshot.Unit = jednostkaSSH()
	snapshot.HostKeys = odciskiKluczy(ctx)
	return snapshot
}

// odciskiKluczy zbiera odciski kluczy hosta.
func odciskiKluczy(ctx context.Context) []sshmodul.HostKey {
	if !exists(sciezkaSshKeygen) {
		return nil
	}
	pliki, err := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	if err != nil {
		return nil
	}
	var klucze []sshmodul.HostKey
	for _, plik := range pliki {
		wyjscie, err := wyjscieNarzedzia(ctx, sciezkaSshKeygen, "-l", "-f", plik)
		if err != nil {
			continue
		}
		if klucz, ok := sshmodul.ParsujOdcisk(wyjscie, plik); ok {
			klucze = append(klucze, klucz)
		}
	}
	return klucze
}

// jednostkaSSH nazywa jednostke systemd serwera.
//
// Debian ma ssh.service, Fedora sshd.service. Przeladowanie niewlasciwej nie
// robi nic i nie zglasza bledu, wiec nazwa nie moze byc zgadywana na stale.
func jednostkaSSH() string {
	for _, nazwa := range []string{"sshd.service", "ssh.service"} {
		if exists("/usr/lib/systemd/system/"+nazwa) || exists("/lib/systemd/system/"+nazwa) {
			return nazwa
		}
	}
	return "sshd.service"
}

func ustawieniaZZadania(action *helperv1.SshRequest) sshmodul.Ustawienia {
	return sshmodul.Ustawienia{
		Port:                   action.GetPort(),
		PermitRootLogin:        action.GetPermitRootLogin(),
		PasswordAuthentication: action.GetPasswordAuthentication(),
		PubkeyAuthentication:   action.GetPubkeyAuthentication(),
		KbdInteractive:         action.GetKbdInteractiveAuthentication(),
		MaxAuthTries:           action.GetMaxAuthTries(),
		AllowUsers:             action.GetAllowUsers(),
		AllowGroups:            action.GetAllowGroups(),
		DenyUsers:              action.GetDenyUsers(),
	}
}

func poprzedniDropIn() (string, bool) {
	tresc, err := os.ReadFile(sshmodul.SciezkaDropIn)
	if err != nil {
		return "", false
	}
	return string(tresc), true
}

func zapiszDropIn(tresc string) error {
	if err := os.MkdirAll(sshmodul.KatalogDropIn, 0o755); err != nil {
		return err
	}
	// Plik tymczasowy nie moze konczyc sie na .conf: katalog jest dolaczany
	// wzorcem i sshd przeczytalby polowe zapisu jako konfiguracje.
	tymczasowy := sshmodul.SciezkaDropIn + ".nowy"
	if err := os.WriteFile(tymczasowy, []byte(tresc), 0o600); err != nil {
		return err
	}
	return os.Rename(tymczasowy, sshmodul.SciezkaDropIn)
}

func przywrocDropIn(tresc string, byla bool) {
	if !byla {
		_ = os.Remove(sshmodul.SciezkaDropIn)
		return
	}
	_ = zapiszDropIn(tresc)
}

func odpowiedzSSH(snapshot sshmodul.Snapshot, komunikat string, rozbiezne []string) *helperv1.HelperResponse {
	zakodowane, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		SshResult: &helperv1.SshResult{
			Snapshot: zakodowane, Message: komunikat, Mismatches: rozbiezne,
		},
	}
}
