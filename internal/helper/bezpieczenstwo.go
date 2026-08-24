package helper

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/security"
)

// nazwyFaktow tlumaczy wyliczenie z protokolu na nazwy faktow modulu.
//
// Tlumaczenie istnieje po to, zeby helper nie przyjmowal dowolnego napisu:
// zakres jego pracy jest zamknieta lista, a nie tekstem od agenta.
var nazwyFaktow = map[helperv1.SecurityRequest_Fact]string{
	helperv1.SecurityRequest_FACT_APPARMOR_PROFILES: security.FaktProfileAppArmor,
	helperv1.SecurityRequest_FACT_AUDIT_RULES:       security.FaktRegulyAudytu,
	helperv1.SecurityRequest_FACT_SECURE_BOOT:       security.FaktSecureBoot,
	helperv1.SecurityRequest_FACT_SOCKET_OWNERS:     security.FaktWlascicieleGniazd,
}

// applySecurity obsluguje operacje modulu bezpieczenstwa.
func (s *Server) applySecurity(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.SecurityRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 2 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.SecurityRequest_OPERATION_FACTS:
		return zbierzFakty(actionCtx, action.GetFacts())
	case helperv1.SecurityRequest_OPERATION_SELINUX_MODE:
		return ustawTrybMAC(actionCtx, action.GetMode())
	case helperv1.SecurityRequest_OPERATION_AUDIT_RELOAD:
		return przeladujReguly(actionCtx)
	}
	return reject(ErrorUnknownAction, "nieznana operacja modulu bezpieczenstwa")
}

// zbierzFakty odczytuje wylacznie te fakty, o ktore agent poprosil.
//
// Modul nie idzie przez roota w calosci: wiekszosc obrazu agent czyta sam,
// a tutaj trafia tylko to, czego bez roota nie widac - profile AppArmora
// w securityfs, reguly audytu, zmienna EFI i wlasciciele gniazd.
func zbierzFakty(ctx context.Context, zadane []helperv1.SecurityRequest_Fact) *helperv1.HelperResponse {
	if len(zadane) == 0 {
		return reject(ErrorMalformed, "zlecenie nie wskazuje zadnego faktu")
	}
	nazwy := make([]string, 0, len(zadane))
	for _, fakt := range zadane {
		nazwa, znany := nazwyFaktow[fakt]
		if !znany {
			return reject(ErrorMalformed, "nieznany fakt "+fakt.String())
		}
		nazwy = append(nazwy, nazwa)
	}

	dodatki := security.ZbierzUzupelnienie(ctx, wyjscieNarzedzia, nazwy)
	zakodowane, err := json.Marshal(dodatki)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:       true,
		SecurityResult: &helperv1.SecurityResult{Facts: zakodowane},
	}
}

// ustawTrybMAC przelacza SELinuksa miedzy enforcing i permissive.
func ustawTrybMAC(ctx context.Context, tryb string) *helperv1.HelperResponse {
	if err := security.WalidujTryb(tryb); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	stan := security.StanMAC()
	if stan.System != security.SystemSELinux {
		return reject(ErrorUnsupported, "ten host nie ma SELinuksa")
	}
	if stan.Mode == security.TrybDisabled {
		return reject(ErrorPreconditionFailed,
			"SELinux jest wylaczony w jadrze; wlaczenie wymaga przeetykietowania systemu plikow i restartu")
	}
	if !exists(security.SciezkaSetenforce) {
		return reject(ErrorUnsupported, "ten host nie ma narzedzia setenforce")
	}

	wartosc := "0"
	if tryb == security.TrybEnforcing {
		wartosc = "1"
	}
	if wyjscie, err := wyjscieNarzedzia(ctx, security.SciezkaSetenforce, wartosc); err != nil {
		return reject(ErrorExecFailed, "setenforce: "+err.Error()+" "+wyjscie)
	}

	// Zmiana od reki nie przetrwa restartu, wiec zapisujemy ja takze
	// w konfiguracji. Panel zmienia jedna linie i nie przepisuje reszty pliku.
	komunikat := "tryb " + tryb + " obowiazuje od teraz"
	if err := zapiszTrybWKonfiguracji(tryb); err != nil {
		komunikat += "; nie zapisano do konfiguracji (" + err.Error() +
			"), wiec po restarcie host wroci do " + stan.ConfiguredMode
	} else {
		komunikat += " i po restarcie"
	}

	// Zapis nie znaczy skutek: pytamy jadro, w jakim trybie jest teraz.
	po := security.StanMAC()
	if po.Mode != tryb {
		return &helperv1.HelperResponse{
			Accepted: true,
			SecurityResult: &helperv1.SecurityResult{
				Message: "polecenie wykonane, ale jadro zglasza tryb " + po.Mode,
			},
		}
	}
	return &helperv1.HelperResponse{
		Accepted:       true,
		SecurityResult: &helperv1.SecurityResult{Message: komunikat},
	}
}

// przeladujReguly wczytuje reguly audytu z plikow do jadra.
//
// Idziemy przez augenrules, a nie przez restart jednostki: auditd na czesci
// dystrybucji ma RefuseManualStop i restart konczy sie odmowa, ktora wyglada
// jak blad panelu, a jest polityka dystrybucji.
func przeladujReguly(ctx context.Context) *helperv1.HelperResponse {
	if !exists(security.SciezkaAugenrules) {
		return reject(ErrorUnsupported, "ten host nie ma narzedzia augenrules")
	}
	wyjscie, err := wyjscieNarzedzia(ctx, security.SciezkaAugenrules, "--load")
	if err != nil {
		return reject(ErrorExecFailed, "augenrules: "+err.Error()+" "+wyjscie)
	}

	// Zapis nie znaczy skutek: pytamy jadro, ile regul zna teraz.
	komunikat := "reguly przeladowane"
	if wynik, err := wyjscieNarzedzia(ctx, security.SciezkaAuditctl, "-l"); err == nil {
		komunikat += "; jadro zna " + strconv.Itoa(security.ParsujReguly(wynik)) + " regul"
	}
	return &helperv1.HelperResponse{
		Accepted:       true,
		SecurityResult: &helperv1.SecurityResult{Message: komunikat},
	}
}

// zapiszTrybWKonfiguracji podmienia wartosc SELINUX= w pliku konfiguracyjnym.
func zapiszTrybWKonfiguracji(tryb string) error {
	tresc, err := os.ReadFile(security.KonfiguracjaMAC)
	if err != nil {
		return err
	}
	linie := strings.Split(string(tresc), "\n")
	zmieniono := false
	for i, linia := range linie {
		if strings.HasPrefix(strings.TrimSpace(linia), "SELINUX=") {
			linie[i] = "SELINUX=" + tryb
			zmieniono = true
		}
	}
	if !zmieniono {
		linie = append(linie, "SELINUX="+tryb)
	}
	return zapiszPlikJadra(security.KonfiguracjaMAC, strings.Join(linie, "\n"), 0o644)
}
