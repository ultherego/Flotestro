package opspec

import "testing"

// TestBrakDeklaracjiZnaczyOdmowe pilnuje zasady, ktora chroni flote przed
// wlasnym rejestrem: dopisanie operacji nie moze samo z siebie otworzyc jej
// dla wszystkich hostow.
func TestBrakDeklaracjiZnaczyOdmowe(t *testing.T) {
	if tryb := ActionType("czegos.takiego.nie.ma").CampaignMode(); tryb != CampaignNone {
		t.Fatalf("nieznana operacja dostala tryb %q", tryb)
	}
	// Operacja realna, ale bez deklaracji, tez jest odmowa.
	if tryb := ActionDiskWipe.CampaignMode(); tryb != CampaignNone {
		t.Fatalf("wyczyszczenie dysku dostalo tryb %q", tryb)
	}
	if TrybWykonywalny(ActionDiskWipe) {
		t.Fatal("wyczyszczenie dysku dopuszczone masowo")
	}
}

// TestOperacjeNieodwracalneNieDzialajaMasowo pilnuje, ze granica z pojedynczego
// hosta obowiazuje takze flote: operacja, ktora wymaga wpisania nazwy celu,
// nie ma jednego celu do wpisania w kampanii.
func TestOperacjeNieodwracalneNieDzialajaMasowo(t *testing.T) {
	for _, action := range AllActions() {
		if !action.RequiresTargetConfirmation() {
			continue
		}
		if action.CampaignMode() != CampaignNone {
			t.Errorf("%s wymaga nazwy celu, a ma tryb masowy %q", action, action.CampaignMode())
		}
	}
}

// TestOperacjaZPlanemNieJestSamymPayloadem pilnuje najgrozniejszego bledu
// kampanii: operacja, ktora liczy diff na kazdym hoscie osobno, nie moze
// jechac jednym zatwierdzonym payloadem.
func TestOperacjaZPlanemNieJestSamymPayloadem(t *testing.T) {
	for _, action := range AllActions() {
		if !action.RequiresPlan() {
			continue
		}
		if action.CampaignMode() == CampaignSamePayload {
			t.Errorf("%s wymaga planu, a jest zadeklarowana jako same_payload", action)
		}
		// Kampania moze prowadzic taka operacje tylko wtedy, gdy ma czym
		// policzyc plan na kazdym hoscie osobno.
		if TrybWykonywalny(action) && AkcjaPlanowania(action) == "" {
			t.Errorf("%s wymaga planu, a kampania nie ma czym go policzyc", action)
		}
	}
}

// TestOdczytyNieSaKampania pilnuje, ze kampania jest mechanizmem zmiany.
// Odczyt na stu hostach jest czyms innym i ma swoja droge.
func TestOdczytyNieSaKampania(t *testing.T) {
	for _, action := range AllActions() {
		if action.Mutating() {
			continue
		}
		if action.CampaignMode() != CampaignNone {
			t.Errorf("odczyt %s ma tryb masowy %q", action, action.CampaignMode())
		}
	}
}

// TestWykonywalneTrybyToSamPayloadIRestart pilnuje granicy miedzy tym, czym
// operacja jest, a tym, co panel dzisiaj umie przeprowadzic.
func TestWykonywalneTrybyToSamPayloadIRestart(t *testing.T) {
	if !TrybWykonywalny(ActionUnitRestart) {
		t.Error("restart jednostki nie jest wykonywalny masowo")
	}
	if !TrybWykonywalny(ActionSystemReboot) {
		t.Error("restart hosta nie jest wykonywalny masowo, choc ma wlasna faze")
	}
	// Aktualizacja pakietow liczy inny plan na kazdym hoscie, wiec kampania
	// prowadzi ja przez faze planowania - i tylko dlatego jest dopuszczona.
	if ActionPackageUpgrade.CampaignMode() != CampaignPerHostPlan {
		t.Errorf("aktualizacja pakietow ma tryb %q", ActionPackageUpgrade.CampaignMode())
	}
	if AkcjaPlanowania(ActionPackageUpgrade) != ActionPackagePlan {
		t.Errorf("aktualizacja pakietow planuje sie operacja %q",
			AkcjaPlanowania(ActionPackageUpgrade))
	}
	if !TrybWykonywalny(ActionPackageUpgrade) {
		t.Error("aktualizacja pakietow nie jest prowadzona mimo fazy planowania")
	}
	// Zmiana pliku takze liczy plan na kazdym hoscie, ale panel nie ma
	// jeszcze czym go policzyc masowo - i dlatego odmawia.
	if TrybWykonywalny(ActionFileEnsure) {
		t.Error("zapis pliku dopuszczony bez planow per host")
	}
}
