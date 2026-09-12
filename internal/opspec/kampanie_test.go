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
	// Wdrozenie Compose liczy plan na kazdym hoscie tak samo jak pakiety: digest
	// powstaje z manifestu i z digestow obrazow, ktore ten host naprawde
	// widzi, i wraca do niego razem ze zmiana.
	for zmiana, planer := range map[ActionType]ActionType{
		ActionComposeDeploy:          ActionComposePlan,
		ActionFileEnsure:             ActionFilePlan,
		ActionFileRemove:             ActionFilePlan,
		ActionFileRollback:           ActionFilePlan,
		ActionFirewallRuleEnsure:     ActionFirewallPlan,
		ActionFirewallRuleRemove:     ActionFirewallPlan,
		ActionFirewallZonePort:       ActionFirewallPlan,
		ActionFirewallZoneService:    ActionFirewallPlan,
		ActionMountEnsure:            ActionStoragePlan,
		ActionMountRemove:            ActionStoragePlan,
		ActionNetworkMTUSet:          ActionNetworkPlan,
		ActionNetworkRouteEnsure:     ActionNetworkPlan,
		ActionNetworkProfileApply:    ActionNetworkPlan,
		ActionDNSHostApply:           ActionDNSPlan,
		ActionSSHConfigApply:         ActionSSHConfigPlan,
		ActionKernelModuleBlacklist:  ActionKernelModulePlan,
		ActionTimeConfigApply:        ActionTimePlan,
		ActionFilesystemCheck:        ActionStoragePlan,
		ActionFilesystemResize:       ActionStoragePlan,
		ActionLVMExtend:              ActionStoragePlan,
		ActionPackageInstall:         ActionPackagePlan,
		ActionCertificateDeploy:      ActionCertificatePlan,
		ActionCertificateRenew:       ActionCertificatePlan,
		ActionCertificateTrustEnsure: ActionCertificateTrustPlan,
		ActionCertificateTrustRemove: ActionCertificateTrustPlan,
		ActionBackupRun:              ActionBackupPlan,
		ActionBackupVerify:           ActionBackupPlan,
	} {
		if AkcjaPlanowania(zmiana) != planer {
			t.Errorf("%s planuje sie operacja %q, oczekiwano %q",
				zmiana, AkcjaPlanowania(zmiana), planer)
		}
		if !TrybWykonywalny(zmiana) {
			t.Errorf("%s odmowiona mimo istniejacego planera", zmiana)
		}
	}

	// Kazda rodzina zadeklarowana jako plan per host ma planera: brak
	// planera oznaczalby kampanie, ktora deklaruje planowanie i nie umie
	// go zrobic. Nowa rodzina bez planera ma tu odpasc, a nie w produkcji.
	for _, action := range AllActions() {
		if action.CampaignMode() != CampaignPerHostPlan {
			continue
		}
		if AkcjaPlanowania(action) == "" {
			t.Errorf("%s deklaruje plan per host, a nie ma planera", action)
		}
		if !TrybWykonywalny(action) {
			t.Errorf("%s odmowiona mimo planera", action)
		}
	}
	// Bramka nadal istnieje: operacja wyspecjalizowana bez wlasnej fazy
	// w silniku jest odmawiana z powodem, a nie udawana.
	for _, zmiana := range []ActionType{ActionDomainEnroll, ActionPackageRepair} {
		if TrybWykonywalny(zmiana) {
			t.Errorf("%s dopuszczona bez wlasnej fazy w silniku", zmiana)
		}
	}
}

// TestOdtworzenieNieIdzieMasowo pilnuje granicy, ktora nie jest brakiem
// funkcji: odtworzenie rozpakowuje stary stan na dzialajacym systemie i ma
// wymagac obecnosci operatora przy kazdym hoscie.
func TestOdtworzenieNieIdzieMasowo(t *testing.T) {
	if PowodWykluczeniaZKampanii(ActionBackupRestore) == "" {
		t.Error("odtworzenie nie jest wykluczone z kampanii")
	}
	if PowodWykluczeniaZKampanii(ActionBackupRun) != "" {
		t.Error("kopia wykluczona z kampanii razem z odtworzeniem")
	}
}

// TestWycofanieUrzeduWymagaPelnejFloty pilnuje granicy, ktorej nie widac
// w pojedynczym hoscie: wycofanie urzedu jest poprawne dopiero wtedy, gdy
// obejmie kazdy cel. Host pominiety zostaje z zaufaniem, ktorego reszta
// floty juz nie ma.
func TestWycofanieUrzeduWymagaPelnejFloty(t *testing.T) {
	if PowodPelnegoPokrycia(ActionCertificateTrustRemove) == "" {
		t.Error("wycofanie urzedu wolno prowadzic na czesci floty")
	}
	// Rozdanie zaufania jest bezpieczne czesciowo: host, ktory je dostanie
	// pozniej, do tego czasu ufa temu, czemu ufal.
	if PowodPelnegoPokrycia(ActionCertificateTrustEnsure) != "" {
		t.Error("rozdanie zaufania wymaga pelnej floty")
	}
	if PowodPelnegoPokrycia(ActionPackageUpgrade) != "" {
		t.Error("aktualizacja pakietow wymaga pelnej floty")
	}
}
