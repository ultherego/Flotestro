package opspec

// trybyMasowe jest rejestrem trybow pracy masowej.
//
// Rejestr jest jawna lista, a nie wlasciwoscia wyliczana z ryzyka: to, ze
// operacja jest bezpieczna na jednym hoscie, nie znaczy, ze jej intencja
// jest przenosna na sto. Operacja spoza tej mapy nie dziala masowo - brak
// deklaracji jest odmowa, a nie zgoda przez pominiecie.
//
// Zrodlem podzialu jest macierz z dokumentu multitaskingu: same_payload dla
// operacji, ktorych payload znaczy to samo wszedzie; per_host_plan dla zmian,
// ktore na kazdym hoscie licza inny diff; specialized dla operacji z wlasna
// maszyna stanow. Reszta zostaje przy jednym hoscie.
var trybyMasowe = map[ActionType]CampaignMode{
	// Jednostki systemd: nazwa jednostki znaczy to samo na kazdym hoscie,
	// a stan przed i po sprawdza sie osobno.
	ActionUnitStart:     CampaignSamePayload,
	ActionUnitStop:      CampaignSamePayload,
	ActionUnitRestart:   CampaignSamePayload,
	ActionUnitReload:    CampaignSamePayload,
	ActionUnitEnableSet: CampaignSamePayload,
	ActionUnitMaskSet:   CampaignSamePayload,

	// Zadania cykliczne: wpis jest deklaracja, a nie diffem stanu.
	ActionScheduleEnsure:  CampaignSamePayload,
	ActionScheduleDisable: CampaignSamePayload,
	ActionScheduleRemove:  CampaignSamePayload,
	ActionScheduleRunNow:  CampaignSamePayload,

	// Konta lokalne: nazwa konta i klucz sa przenosne, a host i tak
	// sprawdza, czy konto istnieje.
	ActionLocalUserCreate: CampaignSamePayload,
	ActionLocalUserLock:   CampaignSamePayload,
	ActionLocalUserUnlock: CampaignSamePayload,
	ActionLocalSSHKeysSet: CampaignSamePayload,

	// Blokada wersji pakietu jest deklaracja o nazwie, a nie o diffie.
	ActionPackageHoldSet: CampaignSamePayload,

	// Kontenery: identyfikator kontenera jest lokalny, ale operacja idzie
	// przez preflight na kazdym hoscie osobno.
	ActionDockerStart:   CampaignSamePayload,
	ActionDockerStop:    CampaignSamePayload,
	ActionDockerRestart: CampaignSamePayload,
	ActionDockerPull:    CampaignSamePayload,

	// Jadro i czas: wartosc jest deklaracja, nie diffem.
	ActionKernelModuleLoad: CampaignSamePayload,
	ActionSysctlEnsure:     CampaignSamePayload,
	ActionSELinuxModeSet:   CampaignSamePayload,
	ActionTimezoneSet:      CampaignSamePayload,

	// Zmiany, ktore na kazdym hoscie licza inny diff. Zatwierdzenie musi
	// dotyczyc zestawu planow, a nie jednego payloadu - dopoki panel tego nie
	// umie, planer kampanii odmawia z wlasnym kodem.
	ActionPackageInstall:        CampaignPerHostPlan,
	ActionPackageUpgrade:        CampaignPerHostPlan,
	ActionFileEnsure:            CampaignPerHostPlan,
	ActionFileRemove:            CampaignPerHostPlan,
	ActionFileRollback:          CampaignPerHostPlan,
	ActionMountEnsure:           CampaignPerHostPlan,
	ActionMountRemove:           CampaignPerHostPlan,
	ActionFilesystemCheck:       CampaignPerHostPlan,
	ActionFilesystemResize:      CampaignPerHostPlan,
	ActionLVMExtend:             CampaignPerHostPlan,
	ActionNetworkProfileApply:   CampaignPerHostPlan,
	ActionNetworkRouteEnsure:    CampaignPerHostPlan,
	ActionNetworkMTUSet:         CampaignPerHostPlan,
	ActionDNSHostApply:          CampaignPerHostPlan,
	ActionFirewallRuleEnsure:    CampaignPerHostPlan,
	ActionFirewallRuleRemove:    CampaignPerHostPlan,
	ActionFirewallZonePort:      CampaignPerHostPlan,
	ActionFirewallZoneService:   CampaignPerHostPlan,
	ActionSSHConfigApply:        CampaignPerHostPlan,
	ActionTimeConfigApply:       CampaignPerHostPlan,
	ActionComposeDeploy:         CampaignPerHostPlan,
	ActionKernelModuleBlacklist: CampaignPerHostPlan,

	// Operacje z wlasna maszyna stanow. Restart rozlicza sie powrotem hosta
	// z nowym boot ID, a nie wyslaniem polecenia.
	ActionSystemReboot:           CampaignSpecialized,
	ActionDomainEnroll:           CampaignSpecialized,
	ActionPackageRepair:          CampaignSpecialized,
	ActionNetworkRollback:        CampaignSpecialized,
	ActionFirewallRulesetRestore: CampaignSpecialized,
}

// AkcjaPlanowania mowi, ktora operacja liczy plan dla operacji zmieniajacej.
//
// Plan jest odczytem i ma wlasny typ operacji: to on chodzi po hoscie, liczy
// diff i zwraca jego odcisk. Kampania w trybie per_host_plan uruchamia go
// najpierw na kazdym hoscie, a dopiero zestaw tych planow idzie do
// zatwierdzenia.
//
// Pusta wartosc znaczy, ze panel nie umie zaplanowac tej zmiany masowo.
func AkcjaPlanowania(action ActionType) ActionType {
	switch action {
	// Transakcja pakietowa: plan liczy diff i zwraca wlasny odcisk, ktory
	// wraca do hosta razem ze zmiana.
	case ActionPackageUpgrade:
		return ActionPackagePlan

	// Plik: plan liczy roznice miedzy trescia zastana a zadana i zwraca odcisk
	// tresci, ktora host mial w tej chwili. Zapis wraca z tym odciskiem, wiec
	// plik zmieniony po planowaniu zatrzymuje zmiane zamiast nadpisac cudza.
	case ActionFileEnsure, ActionFileRemove, ActionFileRollback:
		return ActionFilePlan

	// Zapora: plan liczy roznice wobec rejestru regul panelu i zwraca odcisk
	// calego zestawu, jaki host ma teraz. Zmiana wraca z tym odciskiem, wiec
	// zestaw zmieniony po planowaniu zatrzymuje ja zamiast wejsc w cudze
	// sasiedztwo regul. Strefa firewalld jest zbiorem wpisow, wiec jej plan
	// mowi, czy wpis w nim jest - i wiaze sie tym samym odciskiem zestawu,
	// bo firewalld przepisuje nftables przy kazdej zmianie strefy.
	case ActionFirewallRuleEnsure, ActionFirewallRuleRemove,
		ActionFirewallZonePort, ActionFirewallZoneService:
		return ActionFirewallPlan

	// Montowanie: plan rozwiazuje zrodlo do UUID filesystemu, ktory ten host
	// ma, i to UUID jedzie w zmianie. Sciezka /dev/sdX po restarcie wskazuje
	// co innego; UUID wskazuje ten sam filesystem albo zaden.
	case ActionMountEnsure, ActionMountRemove:
		return ActionStoragePlan

	// Siec: plan liczy roznice miedzy profilem NetworkManagera, ktory host
	// ma, a zadanym - i zwraca odcisk tej roznicy. Zmiana wraca z odciskiem,
	// a host liczy plan jeszcze raz: profil zmieniony po planowaniu
	// zatrzymuje zmiane. DNS hosta idzie osobna operacja i czeka na planer.
	case ActionNetworkProfileApply, ActionNetworkRouteEnsure, ActionNetworkMTUSet:
		return ActionNetworkPlan

	// Compose: plan liczy digest z manifestu i z digestow obrazow, a wdrozenie
	// niesie go z powrotem. Wdrozenie z cudzym digestem trafiloby na host,
	// ktory tego planu nigdy nie widzial.
	case ActionComposeDeploy:
		return ActionComposePlan
	}
	// Pozostale rodziny odmawiaja i warto wiedziec, dlaczego. Ich operacje
	// "*.plan" - dla LVM i filesystemow storage.plan - czytaja
	// stan hosta, a nie licza diffu wobec stanu docelowego. Nazwanie ich planerem
	// dalo by kampanii faze planowania, ktora niczego nie planuje, i zgode
	// odnoszaca sie do odczytu zamiast do zmiany. Planer per host dla tych
	// rodzin jest osobna praca, a nie mapowaniem nazw - tak jak byla nia
	// dla plikow.
	return ""
}

// TrybyWykonywalne wylicza tryby, ktore silnik kampanii naprawde umie
// przeprowadzic.
//
// Lista jest wezsza niz rejestr trybow i to jest celowe: deklaracja mowi,
// czym operacja jest, a ta lista - co panel potrafi dzisiaj bezpiecznie
// wykonac. Kampania w trybie per_host_plan bez zestawu planow zatwierdzalaby
// zmiane, ktorej nikt nie widzial.
func TrybWykonywalny(action ActionType) bool {
	switch action.CampaignMode() {
	case CampaignSamePayload:
		return true
	case CampaignPerHostPlan:
		// Plan per host musi miec czym powstac. Bez operacji planujacej
		// kampania zatwierdzalaby zmiane, ktorej diffu nikt nie policzyl.
		return AkcjaPlanowania(action) != ""
	case CampaignSpecialized:
		// Restart ma w silniku wlasna faze: nowy boot ID i sprawdzenie
		// jednostek po powrocie. Pozostale specjalizacje jeszcze jej nie maja.
		return action == ActionSystemReboot
	}
	return false
}

// OdciskZPlanowania jest znacznikiem w miejsce odcisku, ktorego jeszcze nie ma.
//
// Nie jedzie na zaden host: sluzy wylacznie walidacji zamowienia kampanii,
// a orkiestrator zastepuje go odciskiem planu policzonego na tym hoscie.
const OdciskZPlanowania = "pending-per-host-plan"

// ValidateZamowienieKampanii sprawdza payload zamowienia kampanii.
//
// Rozni sie od Validate jedna rzecza: operacja liczona per host nie moze miec
// odcisku planu w chwili zamowienia, bo plan powstanie dopiero na hostach.
// Reszta wymagan zostaje bez zmian, a sam odcisk jest egzekwowany dwa razy:
// orkiestrator wklada do zadania odcisk planu tego hosta, a host odmawia, gdy
// odcisk nie pasuje do stanu, ktory ma teraz.
func ValidateZamowienieKampanii(action ActionType, payload Payload) error {
	if AkcjaPlanowania(action) != "" {
		payload = zPlaceholderemPlanu(payload)
	}
	return Validate(action, payload)
}

// zPlaceholderemPlanu wstawia znacznik tam, gdzie walidacja wymaga odcisku.
func zPlaceholderemPlanu(payload Payload) Payload {
	if payload.Compose != nil && payload.Compose.PlanDigest == "" {
		kopia := *payload.Compose
		kopia.PlanDigest = OdciskZPlanowania
		payload.Compose = &kopia
	}
	return payload
}
