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
	case CampaignSpecialized:
		// Restart ma w silniku wlasna faze: nowy boot ID i sprawdzenie
		// jednostek po powrocie. Pozostale specjalizacje jeszcze jej nie maja.
		return action == ActionSystemReboot
	}
	return false
}
