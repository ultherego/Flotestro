package helper

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// localUserNamePattern odrzuca nazwy, ktore nie moga byc kontem POSIX.
// Nazwa nigdy nie trafia do powloki, ale walidacja jest druga linia obrony.
var localUserNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)

// Stabilne kody bledow operacji na kontach lokalnych.
const (
	ErrorInvalidAccount   = "invalid_account"
	ErrorShadowsDirectory = "shadows_directory_account"
	ErrorSystemAccount    = "system_account"
	ErrorAccountExists    = "account_exists"
	ErrorAccountMissing   = "account_missing"
)

// systemUIDCeiling oddziela konta uslug od kont ludzi. Konta ponizej tej
// granicy naleza do systemu i panel ich nie zmienia.
const systemUIDCeiling = 1000

// applyLocalUserAction zmienia konto lokalne na hoscie.
//
// Panel nie zarzadza haslami: konta powstaja zablokowane, a dostep daje sie
// kluczem SSH. Haslo w kopercie zadania byloby sekretem w bazie i w logach.
func (s *Server) applyLocalUserAction(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.LocalUserActionRequest) *helperv1.HelperResponse {
	name := action.GetName()
	if !localUserNamePattern.MatchString(name) {
		return reject(ErrorInvalidAccount, fmt.Sprintf("nieprawidlowa nazwa konta %q", name))
	}

	s.accountMutex.Lock()
	defer s.accountMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = 60 * time.Second
	}
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.LocalUserActionRequest_OPERATION_CREATE:
		return s.createLocalUser(operationCtx, request, action)
	case helperv1.LocalUserActionRequest_OPERATION_LOCK:
		return s.setLocalUserLock(operationCtx, name, true)
	case helperv1.LocalUserActionRequest_OPERATION_UNLOCK:
		return s.setLocalUserLock(operationCtx, name, false)
	case helperv1.LocalUserActionRequest_OPERATION_SET_SSH_KEYS:
		return s.setLocalUserKeys(operationCtx, name, action.GetSshKeys())
	default:
		return reject(ErrorUnknownAction, "nieznana operacja na koncie lokalnym")
	}
}

func (s *Server) createLocalUser(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.LocalUserActionRequest) *helperv1.HelperResponse {
	name := action.GetName()

	if existing, err := user.Lookup(name); err == nil {
		// Konto rozwiazywane przez NSS, ale nieobecne w /etc/passwd, pochodzi
		// z katalogu. Utworzenie lokalnej kopii przeslonilo by tozsamosc
		// z katalogu i rozjechalo UID miedzy hostami.
		if !inPasswdFile(name) {
			return reject(ErrorShadowsDirectory, fmt.Sprintf(
				"konto %s pochodzi z katalogu (UID %s); lokalna kopia przeslonilaby je",
				name, existing.Uid))
		}
		return reject(ErrorAccountExists, fmt.Sprintf("konto %s juz istnieje lokalnie", name))
	}

	args := []string{"--shell", shellOrDefault(action.GetShell())}
	if gecos := action.GetGecos(); gecos != "" {
		args = append(args, "--comment", gecos)
	}
	for _, group := range action.GetGroups() {
		if !localUserNamePattern.MatchString(group) {
			return reject(ErrorInvalidAccount, fmt.Sprintf("nieprawidlowa nazwa grupy %q", group))
		}
	}
	if groups := action.GetGroups(); len(groups) > 0 {
		args = append(args, "--groups", strings.Join(groups, ","))
	}
	if action.GetCreateHome() {
		args = append(args, "--create-home")
	}
	// Konto powstaje z wylaczonym logowaniem haslem, a nie zablokowane.
	// useradd zostawia w shadow wykrzyknik, ktory znaczy "zablokowane przez
	// administratora"; dla konta obslugiwanego kluczem SSH to falszywy stan,
	// a do tego uniemozliwia pozniejsze odblokowanie.
	args = append(args, "--password", "*")
	args = append(args, name)

	if _, stderr, err := runIdentityTool(ctx, 60*time.Second, "useradd", args...); err != nil {
		return reject(ErrorExecFailed, "useradd: "+firstLineOf(stderr))
	}

	if keys := action.GetSshKeys(); len(keys) > 0 {
		if response := s.setLocalUserKeys(ctx, name, keys); !response.GetAccepted() {
			return response
		}
	}

	s.log.Info("utworzono konto lokalne",
		"task_id", request.GetTaskId(), "konto", name, "grup", len(action.GetGroups()))
	return &helperv1.HelperResponse{Accepted: true}
}

func (s *Server) setLocalUserLock(ctx context.Context, name string, lock bool) *helperv1.HelperResponse {
	if response := s.requireLocalAccount(name); response != nil {
		return response
	}
	flag := "--unlock"
	if lock {
		flag = "--lock"
	}
	if _, stderr, err := runIdentityTool(ctx, 30*time.Second, "usermod", flag, name); err != nil {
		return reject(ErrorExecFailed, "usermod: "+firstLineOf(stderr))
	}
	s.log.Info("zmieniono stan konta lokalnego", "konto", name, "zablokowane", lock)
	return &helperv1.HelperResponse{Accepted: true}
}

// setLocalUserKeys ustawia komplet kluczy publicznych konta.
func (s *Server) setLocalUserKeys(ctx context.Context, name string, keys []string) *helperv1.HelperResponse {
	if response := s.requireLocalAccount(name); response != nil {
		return response
	}
	for _, key := range keys {
		if err := validatePublicKey(key); err != nil {
			return reject(ErrorInvalidAccount, err.Error())
		}
	}

	account, err := user.Lookup(name)
	if err != nil {
		return reject(ErrorAccountMissing, err.Error())
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)

	sshDir := filepath.Join(account.HomeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if err := os.Chown(sshDir, uid, gid); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}

	path := filepath.Join(sshDir, "authorized_keys")
	content := ""
	for _, key := range keys {
		content += strings.TrimSpace(key) + "\n"
	}

	// Zapis atomowy: przerwany zapis nie moze zostawic pliku, ktory odcina
	// dostep albo daje go czesciowo.
	temporary := path + ".flotestro-tmp"
	if err := os.WriteFile(temporary, []byte(content), 0o600); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if err := os.Chown(temporary, uid, gid); err != nil {
		_ = os.Remove(temporary)
		return reject(ErrorExecFailed, err.Error())
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return reject(ErrorExecFailed, err.Error())
	}

	s.log.Info("ustawiono klucze SSH konta lokalnego", "konto", name, "kluczy", len(keys))
	return &helperv1.HelperResponse{Accepted: true}
}

// requireLocalAccount odrzuca operacje na kontach systemowych i na kontach
// pochodzacych z katalogu.
func (s *Server) requireLocalAccount(name string) *helperv1.HelperResponse {
	account, err := user.Lookup(name)
	if err != nil {
		return reject(ErrorAccountMissing, fmt.Sprintf("konto %s nie istnieje", name))
	}
	if !inPasswdFile(name) {
		return reject(ErrorShadowsDirectory, fmt.Sprintf(
			"konto %s pochodzi z katalogu; zmiany naleza do katalogu, nie do hosta", name))
	}
	if uid, convErr := strconv.Atoi(account.Uid); convErr == nil && uid < systemUIDCeiling {
		// Konta uslug naleza do pakietow, ktore je utworzyly.
		return reject(ErrorSystemAccount, fmt.Sprintf(
			"konto %s jest kontem systemowym (UID %s)", name, account.Uid))
	}
	return nil
}

// inPasswdFile mowi, czy konto pochodzi z pliku, a nie z katalogu przez NSS.
func inPasswdFile(name string) bool {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if before, _, found := strings.Cut(line, ":"); found && before == name {
			return true
		}
	}
	return false
}

func shellOrDefault(shell string) string {
	switch shell {
	case "/bin/bash", "/bin/sh", "/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/zsh":
		return shell
	default:
		return "/bin/bash"
	}
}

// validatePublicKey odrzuca material, ktory nie jest kluczem publicznym.
func validatePublicKey(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("pusty klucz SSH")
	}
	if strings.Contains(trimmed, "PRIVATE KEY") {
		return fmt.Errorf("podano klucz prywatny; na hosta trafia wylacznie klucz publiczny")
	}
	if strings.ContainsAny(trimmed, "\n\r") {
		// Wiele linii w jednym kluczu pozwolilo by dopisac dodatkowy wpis.
		return fmt.Errorf("klucz zawiera znak nowej linii")
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return fmt.Errorf("klucz SSH nie ma postaci <typ> <material>")
	}
	switch fields[0] {
	case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return nil
	default:
		return fmt.Errorf("nieobslugiwany typ klucza SSH %q", fields[0])
	}
}
