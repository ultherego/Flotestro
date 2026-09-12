package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Plan opisuje roznice miedzy konfiguracja sshd, ktora host stosuje, a
// zadana.
//
// Ta sama zmiana zamowiona na dwoch hostach prawie nigdy nie jest ta sama
// zmiana: jeden juz ma PasswordAuthentication no, drugi ma je w pliku
// administratora, ktory przeslania plik panelu, trzeci po zmianie nie
// mialby zadnej metody logowania. Zgoda operatora ma dotyczyc tych roznic.
type Plan struct {
	// Action nazywa to, co by sie stalo: update albo no_change.
	Action string `json:"action"`

	// Current niesie wartosci, ktore serwer stosuje dla ustawien z
	// zamowienia; Desired - zamowienie.
	Current map[string]string `json:"current,omitempty"`
	Desired Ustawienia        `json:"desired"`
	// Changes wylicza po ludzku, co sie zmieni.
	Changes []string `json:"changes,omitempty"`

	// ManagedPresent i ManagedHash opisuja plik panelu na hoscie: zapis
	// nadpisuje go w calosci, wiec plik zmieniony po planowaniu jest inna
	// zmiana niz ogladana.
	ManagedPresent bool   `json:"managed_present"`
	ManagedHash    string `json:"managed_hash,omitempty"`

	// Refusal nazywa powod, dla ktorego zmiana nie wejdzie na ten host:
	// brak sshd, konfiguracja, ktorej serwer nie przyjmie, albo odciecie
	// wszystkich metod logowania bez jawnej zgody.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Nazwy dzialan planu.
const (
	PlanZmienia  = "update"
	PlanBezZmian = "no_change"
)

// Zaplanuj liczy roznice miedzy stanem serwera a zamowieniem.
func Zaplanuj(stan Snapshot, chciane Ustawienia, allowLockout bool) Plan {
	plan := Plan{Desired: chciane, ManagedPresent: stan.ManagedPresent}
	if stan.ManagedPresent {
		plan.ManagedHash = textFingerprint(stan.Managed)
	}
	if stan.UnavailableReason != "" {
		return plan.zOdmowa(stan.UnavailableReason)
	}
	tresc, err := SkladajDropIn(chciane)
	if err != nil {
		return plan.zOdmowa(err.Error())
	}
	if !allowLockout && OdcinaWszystkieMetody(chciane, stan) {
		return plan.zOdmowa("po tej zmianie nie zostalaby zadna dzialajaca metoda uwierzytelnienia; " +
			"swiadome odciecie wymaga jawnej zgody operatora")
	}

	plan.Current = map[string]string{}
	porownaj := func(nazwa, chciana, obecna string) {
		if chciana == "" {
			return
		}
		plan.Current[nazwa] = obecna
		if !strings.EqualFold(chciana, obecna) {
			plan.Changes = append(plan.Changes, fmt.Sprintf("%s z %s na %s",
				nazwa, lubBrak(obecna), chciana))
		}
	}
	porownaj("PermitRootLogin", chciane.PermitRootLogin, stan.PermitRootLogin)
	porownaj("PasswordAuthentication", chciane.PasswordAuthentication, stan.PasswordAuthentication)
	porownaj("PubkeyAuthentication", chciane.PubkeyAuthentication, stan.PubkeyAuthentication)
	porownaj("KbdInteractiveAuthentication", chciane.KbdInteractive, stan.KbdInteractive)
	if chciane.MaxAuthTries != "" {
		porownaj("MaxAuthTries", chciane.MaxAuthTries, strconv.Itoa(stan.MaxAuthTries))
	}
	if chciane.Port != "" {
		obecny := ""
		if len(stan.Ports) > 0 {
			obecny = stan.Ports[0]
		}
		porownaj("Port", chciane.Port, obecny)
	}
	porownajListe := func(nazwa string, chciana, obecna []string) {
		if len(chciana) == 0 {
			return
		}
		plan.Current[nazwa] = strings.Join(obecna, " ")
		if !tenSamZbior(chciana, obecna) {
			plan.Changes = append(plan.Changes, fmt.Sprintf("%s z %s na %s",
				nazwa, lubBrak(strings.Join(obecna, " ")), strings.Join(chciana, " ")))
		}
	}
	porownajListe("AllowUsers", chciane.AllowUsers, stan.AllowUsers)
	porownajListe("AllowGroups", chciane.AllowGroups, stan.AllowGroups)
	porownajListe("DenyUsers", chciane.DenyUsers, stan.DenyUsers)

	// Plik panelu jest nadpisywany w calosci: inna tresc jest zmiana nawet
	// wtedy, gdy serwer juz stosuje zadane wartosci - bo po zapisie stosuje
	// je z innego powodu, a ustawienia z poprzedniego pliku znikaja.
	switch {
	case !stan.ManagedPresent:
		plan.Changes = append(plan.Changes, "plik panelu powstanie")
	case stan.Managed != tresc:
		plan.Changes = append(plan.Changes, "plik panelu zostanie nadpisany")
	}

	plan.Action = PlanZmienia
	if len(plan.Changes) == 0 {
		plan.Action = PlanBezZmian
	}
	plan.PlanHash = odciskPlanu(plan)
	return plan
}

// Odmow wpisuje powod odmowy poznany po policzeniu roznic i liczy odcisk
// na nowo: plan z odmowa jest inna odpowiedzia niz plan bez niej.
func (p *Plan) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanu(*p)
}

func (p Plan) zOdmowa(powod string) Plan {
	p.Refusal = powod
	p.PlanHash = odciskPlanu(p)
	return p
}

// OpisujeZmiane mowi, czy ustawienia niosa cokolwiek do zapisania.
func (u Ustawienia) OpisujeZmiane() bool {
	return u.Port != "" || u.PermitRootLogin != "" || u.PasswordAuthentication != "" ||
		u.PubkeyAuthentication != "" || u.KbdInteractive != "" || u.MaxAuthTries != "" ||
		len(u.AllowUsers) > 0 || len(u.AllowGroups) > 0 || len(u.DenyUsers) > 0
}

func tenSamZbior(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

func lubBrak(wartosc string) string {
	if wartosc == "" {
		return "brak"
	}
	return wartosc
}

func textFingerprint(tekst string) string {
	suma := sha256.Sum256([]byte(tekst))
	return hex.EncodeToString(suma[:])
}

// odciskPlanu liczy odcisk planu poza samym odciskiem. Obejmuje stan
// zastany razem z zadanym: host zmieniony od planowania daje inny odcisk.
func odciskPlanu(plan Plan) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}
