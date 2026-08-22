package helper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// readLocalAccounts odczytuje te dane o kontach, ktore wymagaja roota: stan
// blokady z /etc/shadow i klucze SSH z katalogow domowych.
//
// Agent nie ma i nie powinien miec dostepu do tych plikow: /etc/shadow zawiera
// skroty hasel, a katalogi domowe naleza do uzytkownikow.
func (s *Server) readLocalAccounts(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.LocalAccountsRequest) *helperv1.HelperResponse {
	result := &helperv1.LocalAccountsResult{}
	var problems []string

	shadow, err := readShadowStates()
	if err != nil {
		problems = append(problems, "shadow: "+err.Error())
	}

	for _, name := range action.GetNames() {
		if !localUserNamePattern.MatchString(name) {
			continue
		}
		detail := &helperv1.LocalAccountDetail{Name: name}
		if state, known := shadow[name]; known {
			locked, password := state.locked, state.passwordSet
			detail.Locked = &locked
			detail.PasswordSet = &password
		}
		keys, keyErr := readAuthorizedKeys(ctx, name)
		if keyErr != nil {
			problems = append(problems, name+": "+keyErr.Error())
		}
		detail.SshKeys = keys
		result.Accounts = append(result.Accounts, detail)
	}

	if len(problems) > 0 {
		// Brak czesci danych jest raportowany, a nie przemilczany: pusty
		// wynik wygladalby jak konto bez kluczy.
		result.UnavailableReason = strings.Join(problems, "; ")
	}
	s.log.Debug("odczytano konta lokalne",
		"task_id", request.GetTaskId(), "kont", len(result.Accounts))
	return &helperv1.HelperResponse{Accepted: true, AccountsResult: result}
}

// shadowState opisuje stan uwierzytelniania haslem. Blokada i brak hasla to
// dwa rozne stany: konto zalozone przez panel nie ma hasla, ale nie jest
// odciete, bo loguje sie kluczem SSH.
type shadowState struct {
	locked      bool
	passwordSet bool
}

// readShadowStates czyta stan hasel kont. Skroty hasel nie opuszczaja pliku:
// interesuje nas wylacznie to, czy haslo istnieje i czy jest zablokowane.
func readShadowStates() (map[string]shadowState, error) {
	return parseShadow("/etc/shadow")
}

// parseShadow czyta stan hasel z podanego pliku. Sciezka jest parametrem,
// zeby semantyke prefiksow dalo sie sprawdzic bez dostepu do /etc/shadow.
func parseShadow(path string) (map[string]shadowState, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	states := map[string]shadowState{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		hash := fields[1]
		// Wykrzyknik na poczatku wstawia usermod -L; to jedyny znacznik
		// blokady administracyjnej. Gwiazdka oznacza wylaczone logowanie
		// haslem i jest normalnym stanem konta obslugiwanego kluczem SSH.
		state := shadowState{locked: strings.HasPrefix(hash, "!")}
		remaining := strings.TrimLeft(hash, "!")
		state.passwordSet = remaining != "" && remaining != "*"
		states[fields[0]] = state
	}
	return states, scanner.Err()
}

// readAuthorizedKeys zwraca odciski kluczy publicznych konta. Sama tresc
// klucza nie jest zwracana: do identyfikacji wystarcza odcisk.
func readAuthorizedKeys(ctx context.Context, name string) ([]*helperv1.LocalSSHKey, error) {
	home, err := homeDirectory(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".ssh", "authorized_keys")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Brak pliku to normalny stan, a nie blad.
			return nil, nil
		}
		// Plik niewidoczny dla helpera to co innego niz konto bez kluczy.
		// Milczace zwrocenie pustej listy zglaszaloby panelowi, ze konto nie
		// ma dostepu, podczas gdy stanu po prostu nie udalo sie ustalic.
		return nil, fmt.Errorf("odczyt %s: %w", path, err)
	}

	stdout, _, err := runIdentityTool(ctx, 15*time.Second, "ssh-keygen", "-l", "-f", path)
	if err != nil {
		return nil, fmt.Errorf("odczyt kluczy: %v", err)
	}

	var keys []*helperv1.LocalSSHKey
	for _, line := range strings.Split(stdout, "\n") {
		// Format: <bity> <odcisk> <komentarz> (<typ>)
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		typ := strings.Trim(fields[len(fields)-1], "()")
		comment := strings.Join(fields[2:len(fields)-1], " ")
		keys = append(keys, &helperv1.LocalSSHKey{
			Fingerprint: fields[1], Type: typ, Comment: comment,
		})
	}
	return keys, nil
}

func homeDirectory(name string) (string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 6 && fields[0] == name {
			return fields[5], nil
		}
	}
	return "", fmt.Errorf("konto nie ma wpisu w /etc/passwd")
}
