package adminapi

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
)

func sesja(auth authz.Authentication) *authz.Session {
	return &authz.Session{ID: "sesja", PrincipalID: "podmiot", Auth: auth}
}

func TestStepUpWymagaPowodu(t *testing.T) {
	polityka := stepUpPolicy{MaxAge: 5 * time.Minute}

	for nazwa, powod := range map[string]string{
		"pusty":     "",
		"spacje":    "      ",
		"za krotki": "bo tak",
	} {
		_, odmowa := polityka.evaluate(powod, sesja(authz.Authentication{At: time.Now()}))
		if odmowa == nil {
			t.Errorf("%s: powod %q zostal przyjety", nazwa, powod)
			continue
		}
		if odmowa.Code != "reason_required" {
			t.Errorf("%s: kod odmowy = %q", nazwa, odmowa.Code)
		}
	}
}

func TestStepUpWymagaSwiezegoUwierzytelnienia(t *testing.T) {
	polityka := stepUpPolicy{MaxAge: 5 * time.Minute}
	powod := "nadanie roli nowemu zespolowi dyzurnemu"

	if _, odmowa := polityka.evaluate(powod, sesja(authz.Authentication{
		At: time.Now().Add(-time.Minute), ACR: "1",
	})); odmowa != nil {
		t.Fatalf("swieze uwierzytelnienie odrzucone: %+v", odmowa)
	}

	_, odmowa := polityka.evaluate(powod, sesja(authz.Authentication{
		At: time.Now().Add(-time.Hour),
	}))
	if odmowa == nil {
		t.Fatal("stare uwierzytelnienie zostalo przyjete")
	}
	if odmowa.Code != "reauthentication_required" {
		t.Errorf("kod odmowy = %q", odmowa.Code)
	}
	if odmowa.Detail["authentication_age_seconds"] == nil {
		t.Error("odmowa nie mowi, jak stare jest uwierzytelnienie")
	}

	// Brak auth_time to stan nieustalony. Przepuszczenie takiej sesji
	// oznaczaloby uznanie nieznanego czasu za "przed chwila".
	if _, odmowa := polityka.evaluate(powod, sesja(authz.Authentication{})); odmowa == nil {
		t.Error("sesja bez czasu uwierzytelnienia zostala przyjeta")
	}

	// Wylaczona swiezosc nie moze odrzucac sesji, o ktorej dostawca nic nie
	// powiedzial: instalacja swiadomie zrezygnowala z tego warunku.
	bezWymogu := stepUpPolicy{}
	if _, odmowa := bezWymogu.evaluate(powod, sesja(authz.Authentication{})); odmowa != nil {
		t.Errorf("wylaczony wymog swiezosci nadal odrzuca: %+v", odmowa)
	}
}

func TestStepUpSprawdzaPoziomUwierzytelnienia(t *testing.T) {
	polityka := stepUpPolicy{MaxAge: time.Hour, ACR: "gold"}
	powod := "zmiana mapowania grup po reorganizacji"

	if _, odmowa := polityka.evaluate(powod, sesja(authz.Authentication{
		At: time.Now(), ACR: "1",
	})); odmowa == nil {
		t.Error("sesja o nizszym poziomie zostala przyjeta")
	}

	dowod, odmowa := polityka.evaluate(powod, sesja(authz.Authentication{
		At: time.Now(), ACR: "gold", AMR: []string{"pwd", "otp"},
	}))
	if odmowa != nil {
		t.Fatalf("sesja o wymaganym poziomie odrzucona: %+v", odmowa)
	}
	// Panel zapisuje to, co podal dostawca, i nie tlumaczy tego na wlasne
	// "mfa: tak" - MFA nalezy do dostawcy tozsamosci.
	if dowod["acr"] != "gold" {
		t.Errorf("dowod nie niesie poziomu: %+v", dowod)
	}
	if dowod["purpose"] != powod {
		t.Errorf("dowod nie niesie powodu: %+v", dowod)
	}
	if dowod["reauthenticated"] != true {
		t.Errorf("dowod nie potwierdza ponownego uwierzytelnienia: %+v", dowod)
	}
}

// TestStepUpTozsamosciAutomatycznej pilnuje, ze za tokenem API nie jest
// dopisywane uwierzytelnienie, ktorego nie bylo.
func TestStepUpTozsamosciAutomatycznej(t *testing.T) {
	polityka := stepUpPolicy{MaxAge: 5 * time.Minute, ACR: "gold"}

	dowod, odmowa := polityka.evaluate("wdrozenie floty testowej", nil)
	if odmowa != nil {
		t.Fatalf("tozsamosc automatyczna zostala zablokowana: %+v", odmowa)
	}
	if dowod["authentication"] != "api_token" || dowod["reauthenticated"] != false {
		t.Errorf("dowod nie odroznia tokenu od sesji: %+v", dowod)
	}
	if _, obecny := dowod["acr"]; obecny {
		t.Errorf("dowod przypisuje tokenowi poziom uwierzytelnienia: %+v", dowod)
	}
	// Powod jest wymagany takze od automatu: bez niego slad audytowy nie
	// mowi, po co zmieniono regule dostepu.
	if _, odmowa := polityka.evaluate("", nil); odmowa == nil {
		t.Error("tozsamosc automatyczna przeszla bez powodu")
	}
}

// Brak powodu jest brakiem w zadaniu, nie w sesji. Odeslanie klienta do
// ponownego logowania kazaloby mu naprawiac nie to, co jest zepsute.
func TestBrakPowoduJestBledemZadania(t *testing.T) {
	polityka := stepUpPolicy{}
	_, odmowa := polityka.evaluate("krotko", nil)
	if odmowa == nil {
		t.Fatal("zbyt krotki powod zostal przyjety")
	}
	if odmowa.Code != "reason_required" {
		t.Errorf("kod = %q", odmowa.Code)
	}
	if !odmowa.BladZadania {
		t.Error("brak powodu zostal oznaczony jako brak uwierzytelnienia")
	}
}
