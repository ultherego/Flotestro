package agent

import (
	"testing"
	"time"
)

// TestProgOdnowienia pilnuje zapasu na awarie centrali. Odnowienie ma sie
// zaczac na dlugo przed wygasnieciem, a nie w ostatniej godzinie: agent bez
// waznego certyfikatu nie ma jak wrocic do floty, bo tokenu enrollmentu juz
// na hoscie nie ma.
func TestProgOdnowienia(t *testing.T) {
	teraz := time.Now()
	wydany := teraz.Add(-20 * 24 * time.Hour)
	wygasa := teraz.Add(10 * 24 * time.Hour)

	// Swiezy certyfikat: dwie trzecie okresu jeszcze przed nami.
	if needsRenewal(teraz.Add(25*24*time.Hour), teraz.Add(-5*24*time.Hour)) {
		t.Error("swiezy certyfikat nie wymaga odnowienia")
	}
	// Zostala mniej niz jedna trzecia okresu.
	if !needsRenewal(wygasa, wydany.Add(-10*24*time.Hour)) {
		t.Error("certyfikat po dwoch trzecich okresu wymaga odnowienia")
	}
	// Certyfikat juz wygasly tym bardziej.
	if !needsRenewal(teraz.Add(-time.Hour), wydany) {
		t.Error("wygasly certyfikat wymaga odnowienia")
	}
	// Nieznany termin nie moze znaczyc "jeszcze dlugo".
	if !needsRenewal(time.Time{}, time.Time{}) {
		t.Error("nieustalony termin wymaga proby odnowienia")
	}
}

// TestOdstepSprawdzaniaSkaluje sie do dlugosci zycia certyfikatu: staly odstep
// bylby bezuzyteczny przy krotkim terminie i niepotrzebnie czesty przy dlugim.
func TestOdstepSprawdzaniaSkaluje(t *testing.T) {
	teraz := time.Now()

	dlugi := checkInterval(teraz.Add(365*24*time.Hour), teraz)
	if dlugi != maxRenewalCheckInterval {
		t.Errorf("dla certyfikatu rocznego odstep = %s, oczekiwano %s", dlugi, maxRenewalCheckInterval)
	}

	krotki := checkInterval(teraz.Add(20*time.Minute), teraz)
	if krotki != minRenewalCheckInterval {
		t.Errorf("dla certyfikatu 20-minutowego odstep = %s, oczekiwano %s", krotki, minRenewalCheckInterval)
	}

	sredni := checkInterval(teraz.Add(24*time.Hour), teraz)
	if sredni != 24*time.Hour/20 {
		t.Errorf("dla certyfikatu dobowego odstep = %s", sredni)
	}

	// Termin sprzed chwili nie moze dac odstepu zerowego i petli odpytywania.
	if zerowy := checkInterval(teraz, teraz); zerowy < minRenewalCheckInterval {
		t.Errorf("odstep %s grozi odpytywaniem w petli", zerowy)
	}
}
