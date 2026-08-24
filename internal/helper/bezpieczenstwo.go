package helper

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/security"
	"github.com/ultherego/flotestro/internal/systemd"
)

// jednostkaAudytu jest jednostka demona audytu. Nazwa jest ta sama na obu
// rodzinach systemow, wiec nie ma tu czego wykrywac.
const jednostkaAudytu = "auditd.service"

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
	case helperv1.SecurityRequest_OPERATION_READ:
		return odpowiedzBezpieczenstwa(zbierzBezpieczenstwo(actionCtx), "")
	case helperv1.SecurityRequest_OPERATION_SELINUX_MODE:
		return ustawTrybMAC(actionCtx, action.GetMode())
	}
	return reject(ErrorUnknownAction, "nieznana operacja modulu bezpieczenstwa")
}

// zbierzBezpieczenstwo czyta stan ochronny hosta.
//
// Odczyt idzie przez helpera, bo prawie wszystko w nim wymaga roota: profile
// AppArmora leza w securityfs, reguly audytu czyta tylko auditctl, zmienne EFI
// sa dostepne wylacznie dla roota, a wlascicieli gniazd nasluchujacych widzi
// tylko ten, kto widzi cudze procesy.
func zbierzBezpieczenstwo(ctx context.Context) security.Snapshot {
	snapshot := security.Snapshot{ObservedAt: time.Now().UTC()}
	snapshot.MAC = stanMAC()
	snapshot.Audit = stanAudytu(ctx)

	if tresc, err := os.ReadFile(security.PlikFIPS); err == nil {
		wlaczony := strings.TrimSpace(string(tresc)) == "1"
		snapshot.FIPSEnabled = &wlaczony
	}
	if tresc, err := os.ReadFile(security.PlikLockdown); err == nil {
		snapshot.Lockdown = security.ParsujLockdown(string(tresc))
	}
	snapshot.SecureBoot, snapshot.SecureBootReason = stanSecureBoot()
	snapshot.Listening, snapshot.ListeningKnown = gniazdaNasluchujace(ctx)
	return snapshot
}

// stanMAC ustala, ktory system obowiazkowej kontroli dostepu chroni host.
func stanMAC() security.Mandatory {
	// SELinux rozpoznajemy po jego systemie plikow, a nie po pliku
	// konfiguracyjnym: konfiguracja bywa zostawiona na hoscie, na ktorym
	// SELinux jest wylaczony w jadrze, i wygladalaby na ochrone.
	konfiguracja, _ := os.ReadFile(security.KonfiguracjaMAC)
	trybZKonfiguracji, polityka := security.ParsujKonfiguracjeSELinux(string(konfiguracja))

	if exists(security.KatalogSELinux) {
		mac := security.Mandatory{
			System:         security.SystemSELinux,
			ConfiguredMode: trybZKonfiguracji,
			Policy:         polityka,
		}
		if tresc, err := os.ReadFile(security.PlikWymuszania); err == nil {
			mac.Mode = security.ParsujTrybWymuszania(string(tresc))
		} else {
			mac.Reason = "nie odczytano trybu: " + err.Error()
		}
		return mac
	}
	if trybZKonfiguracji != "" {
		// Konfiguracja mowi "enforcing", a jadro nie ma SELinuksa w ogole.
		// To jest dokladnie ten przypadek, ktory wyglada na ochrone.
		return security.Mandatory{
			System: security.SystemSELinux, Mode: security.TrybDisabled,
			ConfiguredMode: trybZKonfiguracji, Policy: polityka,
			Reason: "SELinux jest wylaczony w jadrze mimo wpisu w konfiguracji",
		}
	}

	if tresc, err := os.ReadFile(security.PlikAppArmor); err == nil {
		if strings.TrimSpace(string(tresc)) != "Y" {
			return security.Mandatory{
				System: security.SystemAppArmor, Mode: security.TrybDisabled,
				Reason: "AppArmor jest obecny, ale wylaczony w jadrze",
			}
		}
		mac := security.Mandatory{System: security.SystemAppArmor, Mode: security.TrybEnforcing}
		profile, err := os.ReadFile(security.ProfileAppArmor)
		if err != nil {
			mac.Reason = "nie odczytano profili: " + err.Error()
			return mac
		}
		wymuszane, skargi := security.ParsujProfileAppArmor(string(profile))
		mac.ProfilesEnforcing = &wymuszane
		mac.ProfilesComplain = &skargi
		return mac
	}
	return security.Mandatory{Reason: "ten host nie ma ani SELinuksa, ani AppArmora"}
}

// stanAudytu opisuje demona audytu.
func stanAudytu(ctx context.Context) security.Audyt {
	audyt := security.Audyt{Present: exists(security.SciezkaAuditctl)}
	stan, err := systemd.Show(ctx, jednostkaAudytu)
	if err == nil && stan.LoadState != "not-found" {
		aktywny := stan.ActiveState == "active"
		audyt.Active = &aktywny
		audyt.Present = true
	}
	if !audyt.Present {
		audyt.Reason = "ten host nie ma demona audytu"
		return audyt
	}
	if audyt.Active == nil || !*audyt.Active {
		// Reguly czyta jadro przez auditctl; zatrzymany demon nie znaczy
		// jeszcze, ze regul nie ma, ale ich odczyt bywa wtedy pusty.
		return audyt
	}
	wyjscie, err := wyjscieNarzedzia(ctx, security.SciezkaAuditctl, "-l")
	if err != nil {
		audyt.Reason = "nie odczytano regul: " + err.Error()
		return audyt
	}
	reguly := security.ParsujReguly(wyjscie)
	audyt.Rules = &reguly
	return audyt
}

// stanSecureBoot czyta zmienna EFI albo mowi, dlaczego jej nie ma.
func stanSecureBoot() (*bool, string) {
	if !exists(security.KatalogEFI) {
		// Pytanie o secure boot na hoscie startujacym w trybie BIOS nie ma
		// odpowiedzi. "Wylaczony" bylby tu falszem.
		return nil, "host wstaje w trybie BIOS, wiec secure boot nie ma zastosowania"
	}
	dane, err := os.ReadFile(security.KatalogEFIVars + "/" + security.ZmiennaSecureBoot)
	if err != nil {
		return nil, "nie odczytano zmiennej EFI: " + err.Error()
	}
	stan := security.ParsujSecureBoot(dane)
	if stan == nil {
		return nil, "zmienna EFI ma nieoczekiwany rozmiar"
	}
	return stan, ""
}

// gniazdaNasluchujace wylicza to, czym host wystaje na zewnatrz.
func gniazdaNasluchujace(ctx context.Context) ([]security.Nasluch, bool) {
	sciezka := security.SciezkaSS
	if !exists(sciezka) {
		sciezka = security.SciezkaSSAlt
	}
	if !exists(sciezka) {
		return nil, false
	}
	// -H pomija naglowek, -p dokłada wlasciciela gniazda, -n zostawia porty
	// liczbami: nazwa uslugi z /etc/services opisuje zwyczaj, a nie fakt.
	wyjscie, err := wyjscieNarzedzia(ctx, sciezka, "-tulpnH")
	if err != nil {
		return nil, false
	}
	return security.ParsujNasluch(wyjscie), true
}

// ustawTrybMAC przelacza SELinuksa miedzy enforcing i permissive.
func ustawTrybMAC(ctx context.Context, tryb string) *helperv1.HelperResponse {
	if err := security.WalidujTryb(tryb); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	stan := stanMAC()
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

	po := zbierzBezpieczenstwo(ctx)
	// Zapis nie znaczy skutek: pytamy jadro, w jakim trybie jest teraz.
	if po.MAC.Mode != tryb {
		return odpowiedzBezpieczenstwa(po, "polecenie wykonane, ale jadro zglasza tryb "+po.MAC.Mode)
	}
	return odpowiedzBezpieczenstwa(po, komunikat)
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

func odpowiedzBezpieczenstwa(snapshot security.Snapshot, komunikat string) *helperv1.HelperResponse {
	zakodowany, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:       true,
		SecurityResult: &helperv1.SecurityResult{Snapshot: zakodowany, Message: komunikat},
	}
}
