// Package authz zawiera model autoryzacji: uprawnienia, role i zakresy.
// Uprawnienie to zawsze para operacja + zakres, nigdy sama operacja.
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Permission jest pojedynczym uprawnieniem. Operacje na hostach maja wlasne
// uprawnienia pochodzace z opspec, zeby restart uslugi nie byl tym samym
// poziomem zaufania co odczyt inwentarza.
type Permission string

const (
	PermHostRead        Permission = "host.read"
	PermInventoryRead   Permission = "inventory.read"
	PermAuditRead       Permission = "audit.read"
	PermJobRead         Permission = "job.read"
	PermJobCreate       Permission = "job.create"
	PermJobApprove      Permission = "job.approve"
	PermJobCancel       Permission = "job.cancel"
	PermEnrollmentToken Permission = "enrollment_token.create"
	PermPrincipalManage Permission = "principal.manage"

	PermUnitStart   Permission = "unit.start"
	PermUnitStop    Permission = "unit.stop"
	PermUnitRestart Permission = "unit.restart"
	PermUnitReload  Permission = "unit.reload"
	PermJournalRead Permission = "journal.read"

	PermPackagesPlan    Permission = "packages.plan"
	PermPackagesUpgrade Permission = "packages.upgrade"
	// Naprawa dotyka pakietow, ktore moga decydowac o starcie hosta,
	// wiec jest osobnym uprawnieniem, a nie czescia aktualizacji.
	PermPackagesRepair Permission = "packages.repair"
	PermSystemReboot   Permission = "system.reboot"
	PermUnitStatus     Permission = "unit.status"
	// Wlaczenie jednostki zmienia zachowanie hosta po kazdym restarcie,
	// a zamaskowanie odbiera mozliwosc jej uruchomienia takze recznie.
	PermUnitEnableWrite Permission = "unit.enable.write"
	PermUnitMaskWrite   Permission = "unit.mask.write"
	// Odczyt pliku logu siega poza dziennik systemowy.
	PermLogFileRead Permission = "logfile.read"
	// Podglad na zywo trzyma proces na hoscie przez caly czas trwania, wiec
	// jest oddzielony od jednorazowego odczytu dziennika.
	PermJournalFollow Permission = "journal.follow"
	// Odczyt procesow jest diagnostyka; wyslanie sygnalu zatrzymuje czyjas
	// prace i nie da sie go cofnac.
	PermProcessRead   Permission = "process.read"
	PermProcessSignal Permission = "process.signal"
	// Pelny cykl zycia pakietow. Instalacja i usuwanie sa oddzielone od
	// aktualizacji: to trzy rozne decyzje o tym samym hoscie.
	PermPackagesInstall Permission = "packages.install"
	PermPackagesRemove  Permission = "packages.remove"
	PermPackagesHold    Permission = "packages.hold.write"
	// Zrodlo pakietow jest decyzja o zaufaniu, a nie o wersji: od jego
	// dopisania host bierze oprogramowanie takze stamtad, razem ze skryptami
	// pakietow, ktore chodza jako root. Stad uprawnienie osobne od instalacji.
	PermPackagesRepository Permission = "packages.repository.write"
	// Zadania cykliczne uruchamiaja sie bez udzialu operatora, takze wtedy,
	// gdy nikt nie patrzy - zalozenie wpisu jest osobna decyzja od jego
	// wylaczenia czy usuniecia.
	PermScheduleWrite   Permission = "schedule.write"
	PermScheduleDisable Permission = "schedule.disable"
	PermScheduleRemove  Permission = "schedule.remove"
	PermScheduleRun     Permission = "schedule.run"
	// Siec. Odczyt profili jest przygotowaniem do zmiany, wiec jest tani;
	// zmiana adresu albo trasy potrafi odciac host od panelu i wtedy zaden
	// nastepny rozkaz juz nie dojdzie. Trasy maja wlasne uprawnienie, bo
	// zmiana trasy domyslnej przekierowuje caly ruch hosta, nie tylko
	// jego adres.
	PermNetworkRead       Permission = "network.read"
	PermNetworkWrite      Permission = "network.write"
	PermNetworkRouteWrite Permission = "network.route.write"
	// MTU i wycofanie sa oddzielone od przepisania adresu: zle MTU psuje duze
	// pakiety, zly adres odcina host, a wycofanie wraca do stanu, ktorego
	// operator moze juz nie pamietac.
	PermNetworkMTUWrite Permission = "network.mtu.write"
	PermNetworkRollback Permission = "network.rollback"
	// DNS hosta jest oddzielony od rekordow w katalogu: wpis w strefie widza
	// wszyscy klienci domeny, a resolver hosta - tylko ten host.
	PermDNSRead      Permission = "dns.read"
	PermDNSHostWrite Permission = "dns.host.write"
	// Zapora. Odczyt zestawu regul jest przygotowaniem do zmiany; zla regula
	// odcina panel od hosta i nie ma czym cofnac zmiany. Usuniecie reguly,
	// zmiana strefy i przywrocenie stanu maja wlasne uprawnienia, bo to trzy
	// rozne decyzje o tym samym hoscie.
	PermFirewallRead         Permission = "firewall.read"
	PermFirewallWrite        Permission = "firewall.write"
	PermFirewallRuleRemove   Permission = "firewall.rule.remove"
	PermFirewallZoneWrite    Permission = "firewall.zone.write"
	PermFirewallServiceWrite Permission = "firewall.service.write"
	PermFirewallRestore      Permission = "firewall.restore"
	// Przestrzen dyskowa. Odczyt topologii jest diagnostyka; montowanie
	// decyduje o tym, czy host wstanie po restarcie tak, jak stoi teraz,
	// a sprawdzenie filesystemu wymaga, zeby nikt go nie uzywal.
	PermStorageRead        Permission = "storage.read"
	PermStorageMountWrite  Permission = "storage.mount.write"
	PermStorageMountRemove Permission = "storage.mount.remove"
	PermStorageFsck        Permission = "storage.fsck"
	// Rozszerzenie i formatowanie to dwie rozne decyzje: pierwsza dodaje
	// miejsce, druga kasuje wszystko, co na nim bylo.
	PermStorageLVMWrite        Permission = "storage.lvm.write"
	PermStorageFilesystemWrite Permission = "storage.filesystem.write"
	PermStorageDestructive     Permission = "storage.destructive"
	PermStorageWipe            Permission = "storage.wipe"
	// Serwer sshd. Zla konfiguracja odcina administracje hosta, a wymiana
	// klucza zmienia jego tozsamosc widziana przez wszystkich klientow.
	PermSSHRead          Permission = "ssh.read"
	PermSSHConfigWrite   Permission = "ssh.config.write"
	PermSSHHostKeyRotate Permission = "ssh.hostkey.rotate"
	// Bezpieczenstwo. Skan zbiera material rozpoznawczy o hoscie, wiec ma
	// wlasne uprawnienie osobne od odczytu ustalen. Naprawa nie ma wlasnej
	// operacji na hoscie: wykonuje ja modul, ktory za dana rzecz odpowiada,
	// wiec uprawnienie do naprawy nie zastepuje uprawnien tych modulow.
	PermSecurityRead      Permission = "security.read"
	PermSecurityScan      Permission = "security.scan"
	PermSecurityRemediate Permission = "security.remediate"
	PermSecurityMACWrite  Permission = "security.mac.write"
	// Przeladowanie regul audytu zmienia to, co host notuje.
	PermSecurityAuditReload Permission = "security.audit.reload"
	// Backup. Odczyt stanu repozytorium jest czescia dyzuru - backup, o ktorym
	// nikt nie wie, ze nie dziala, jest gorszy niz jego brak. Odtworzenie ma
	// wlasne uprawnienie i najwyzsze ryzyko: rozpakowuje stary stan na
	// dzialajacym systemie.
	PermBackupRead    Permission = "backup.read"
	PermBackupRun     Permission = "backup.run"
	PermBackupVerify  Permission = "backup.verify"
	PermBackupRestore Permission = "backup.restore"

	// Okno serwisowe nalezy do prowadzenia ruchu, a nie do zmiany hosta:
	// deklaruje je ten, kto pilnuje kampanii i dyzuru.
	PermHostMaintenanceWrite Permission = "host.maintenance.write"
	// Wylaczenie hosta ma wlasne uprawnienie, osobne od restartu: po
	// restarcie host wraca sam, po wylaczeniu ktos musi do niego pojsc.
	PermSystemShutdown Permission = "system.shutdown"
	// Czas. Odczyt i test zrodel sa czescia diagnozy - przesuniety zegar
	// wyglada z zewnatrz jak zepsuty Kerberos albo zepsuty mTLS. Zmiana
	// zrodel potrafi przestawic zegar skokiem, wiec ma wlasne uprawnienie.
	PermTimeRead  Permission = "time.read"
	PermTimeWrite Permission = "time.write"
	// Strefa ma wlasne uprawnienie, bo jest inna decyzja niz zrodla czasu:
	// zmienia to, co host pokazuje ludziom i pisze do dziennika, ale nie
	// rusza chwili, w ktorej host zyje.
	PermTimezoneWrite Permission = "time.timezone.write"
	// Jadro. Ustawienie sysctl da sie cofnac tak samo, jak zostalo
	// ustawione; blokada modulu ujawnia skutek dopiero przy starcie hosta,
	// wiec ma osobne uprawnienie.
	PermKernelRead            Permission = "kernel.read"
	PermKernelSysctlWrite     Permission = "kernel.sysctl.write"
	PermKernelModuleWrite     Permission = "kernel.module.write"
	PermKernelModuleBlacklist Permission = "kernel.module.blacklist"
	// Pliki konfiguracyjne. Odczyt tresci jest oddzielony od planu, bo tresc
	// bywa wrazliwa nawet wtedy, gdy plik nie jest sekretem.
	PermFileRead     Permission = "file.read"
	PermFilePlan     Permission = "file.plan"
	PermFileWrite    Permission = "file.write"
	PermFileRemove   Permission = "file.remove"
	PermFileRollback Permission = "file.rollback"
	// PermDockerRead pozwala odczytac stan silnika kontenerow. Odczyt jest
	// oddzielony od zmian: ogladanie kontenerow nalezy do pracy kazdego, kto
	// diagnozuje host, a zatrzymywanie ich juz nie.
	PermDockerRead Permission = "docker.read"
	// Operacje na kontenerach maja osobne uprawnienia: uruchomienie uslugi
	// i jej usuniecie to dwie rozne decyzje, takze co do tego, kto moze je
	// podjac.
	PermDockerStart   Permission = "docker.container.start"
	PermDockerStop    Permission = "docker.container.stop"
	PermDockerRestart Permission = "docker.container.restart"
	PermDockerRemove  Permission = "docker.container.remove"
	PermDockerPull    Permission = "docker.image.pull"
	PermDockerPrune   Permission = "docker.prune"
	// Wdrozenie projektu uruchamia na hoscie obrazy wskazane przez operatora,
	// wiec jest oddzielone od reszty operacji kontenerowych.
	PermComposePlan   Permission = "docker.compose.plan"
	PermComposeDeploy Permission = "docker.compose.deploy"

	PermCampaignRead    Permission = "campaign.read"
	PermCampaignCreate  Permission = "campaign.create"
	PermCampaignApprove Permission = "campaign.approve"
	PermCampaignControl Permission = "campaign.control"

	// Uprawnienia warstwy tozsamosci. Zarzadzanie sudo i HBAC jest oddzielone
	// od reszty, bo blad w tych regulach otwiera dostep do calej floty.
	PermIdentityRead Permission = "identity.read"
	// Reguly HBAC i sudo opisuja, kto moze uzyskac dostep i podniesc
	// uprawnienia. To material rozpoznawczy, wiec ich odczyt jest osobnym
	// uprawnieniem, a nie czescia zwyklego wgladu w katalog.
	PermIdentityPolicyRead  Permission = "identity.policy.read"
	PermIdentityUserWrite   Permission = "identity.user.write"
	PermIdentityGroupWrite  Permission = "identity.group.write"
	PermIdentityPolicyWrite Permission = "identity.policy.write"
	PermIdentityHostEnroll  Permission = "identity.host.enroll"

	// Konta lokalne sa osobna sciezka dostepu do hosta, niezalezna od katalogu.
	// Zalozenie konta i zmiana kluczy SSH to nadanie dostepu do systemu, wiec
	// maja wlasne uprawnienia; odczyt listy kont miesci sie w inventory.
	PermLocalUserRead    Permission = "localuser.read"
	PermLocalUserCreate  Permission = "localuser.create"
	PermLocalUserLock    Permission = "localuser.lock"
	PermLocalUserUnlock  Permission = "localuser.unlock"
	PermLocalSSHKeyWrite Permission = "localuser.sshkeys.write"

	// Metryki opisuja flote: liczbe hostow, stany zadan i waznosc CA.
	// To material rozpoznawczy, wiec ma wlasne uprawnienie, a nie jest
	// dostepny kazdemu, kto zna adres panelu.
	PermMetricsRead Permission = "metrics.read"

	// Magazyn sekretow. Odczyt dotyczy metadanych - wartosci nie da sie
	// odczytac przez API w ogole. Zniszczenie wersji jest nieodwracalne,
	// wiec ma wlasne uprawnienie, osobne od zakladania i obracania.
	PermSecretRead    Permission = "secret.read"
	PermSecretWrite   Permission = "secret.write"
	PermSecretDestroy Permission = "secret.destroy"

	// Certyfikaty na hostach. Odczyt terminow i nazw jest czescia dyzuru -
	// wygasly certyfikat wyglada jak awaria uslugi. Wdrozenie i odnowienie
	// podmieniaja tozsamosc, ktora usluga pokazuje swiatu, wiec maja wlasne
	// uprawnienia. Wskazanie panelowi pliku do obserwacji nie zmienia hosta
	// i jest osobna, lzejsza decyzja.
	PermCertificateRead   Permission = "certificate.read"
	PermCertificateWatch  Permission = "certificate.watch"
	PermCertificateDeploy Permission = "certificate.deploy"
	PermCertificateRenew  Permission = "certificate.renew"

	// CA floty jest korzeniem zaufania dla kazdego hosta. Jego wymiana ma
	// wlasne uprawnienie, osobne od reszty administracji: blad w tym miejscu
	// odcina cala flote.
	PermPKIRead   Permission = "pki.read"
	PermPKIRotate Permission = "pki.rotate"
)

// Role grupuje uprawnienia. Podzial odpowiada rolom z dokumentu: platform
// admin, operator, auditor i approver.
type Role string

const (
	RoleViewer        Role = "viewer"
	RoleAuditor       Role = "auditor"
	RoleOperator      Role = "operator"
	RoleApprover      Role = "approver"
	RoleIdentityAdmin Role = "identity_admin"
	RolePlatformAdmin Role = "platform_admin"
)

// rolePermissions opisuje, co wolno kazdej roli. Rozdzielenie operatora
// od approvera jest celowe: kto zleca zmiane, nie powinien jej zatwierdzac.
var rolePermissions = map[Role][]Permission{
	RoleViewer: {
		PermHostRead, PermInventoryRead, PermJobRead, PermCampaignRead, PermUnitStatus,
		PermIdentityRead, PermLocalUserRead, PermDockerRead, PermProcessRead,
		PermNetworkRead, PermDNSRead, PermFirewallRead, PermStorageRead, PermSSHRead, PermKernelRead,
		PermTimeRead, PermSecurityRead, PermFilePlan, PermCertificateRead,
		PermBackupRead,
	},
	RoleAuditor: {
		PermHostRead, PermInventoryRead, PermJobRead, PermAuditRead, PermCampaignRead,
		PermIdentityRead, PermIdentityPolicyRead, PermLocalUserRead, PermDockerRead,
		// Auditor patrzy na stan systemu, wiec metryki i przeglad CA naleza
		// do jego pracy; wymiana CA juz nie.
		PermMetricsRead, PermPKIRead,
		// Audytor patrzy na stan ochronny hosta i na wyniki sprawdzen -
		// to material jego pracy; naprawiac go nie musi.
		PermSecurityRead, PermSecurityScan,
		// Terminy certyfikatow sa materialem audytu tak samo jak stan
		// ochronny: wygasajacy certyfikat jest ustaleniem, a nie awaria.
		PermCertificateRead,
		// Backup, ktorego nikt nie sprawdzil, jest ustaleniem audytu,
		// a nie awaria dyzuru.
		PermBackupRead,
		// Metadane sekretow sa czescia obrazu instalacji: co istnieje, kto
		// zalozyl, kiedy obrocono. Wartosci nie widzi nikt.
		PermSecretRead,
	},
	RoleOperator: {
		PermHostRead, PermInventoryRead, PermJobRead,
		PermJobCreate, PermJobCancel,
		PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload, PermJournalRead,
		// Operator prowadzi kontenery, ale ich nie kasuje: usuwanie
		// i sprzatanie sa nieodwracalne i naleza do administratora.
		PermDockerRead, PermDockerStart, PermDockerStop, PermDockerRestart, PermDockerPull,
		// Operator planuje wdrozenia projektow, ale ich nie wykonuje.
		PermComposePlan,
		// Operator planuje aktualizacje, ale ich nie wykonuje: transakcja
		// pakietowa jest operacja najwyzszego ryzyka i wymaga osobnego prawa.
		PermPackagesPlan,
		// Operator planuje i prowadzi kampanie, ale ich nie zatwierdza.
		PermCampaignRead, PermCampaignCreate, PermCampaignControl,
		// Okno serwisowe jest narzedziem prowadzenia ruchu: to operator wie,
		// ze ten host jest wlasnie w naprawie.
		PermHostMaintenanceWrite,
		// Operator widzi konta lokalne, ale ich nie zaklada: nadanie dostepu
		// do hosta jest decyzja administracyjna, a nie czescia obslugi awarii.
		PermLocalUserRead,
		// Operator czyta konfiguracje sieci, ale jej nie zmienia: zla zmiana
		// odcina host i nie da sie jej naprawic zdalnie.
		PermNetworkRead, PermDNSRead, PermFirewallRead, PermStorageRead, PermSSHRead, PermKernelRead,
		// Przesuniety zegar wyglada jak awaria katalogu albo certyfikatow,
		// wiec test zrodel czasu nalezy do pierwszej diagnozy.
		PermTimeRead, PermSecurityRead, PermSecurityScan, PermFilePlan,
		// Operator oglada certyfikaty i wskazuje panelowi, ktorych plikow
		// pilnowac; wdrozenie nowego jest juz decyzja administratora.
		PermCertificateRead, PermCertificateWatch,
		// Operator robi i sprawdza kopie; odtworzenie jest osobna decyzja,
		// bo rozpakowuje stary stan na dzialajacym systemie.
		PermBackupRead, PermBackupRun, PermBackupVerify,
	},
	RoleApprover: {
		PermHostRead, PermInventoryRead, PermJobRead, PermAuditRead,
		PermJobApprove, PermCampaignRead, PermCampaignApprove,
		PermIdentityRead, PermIdentityPolicyRead, PermLocalUserRead,
	},
	// identity_admin zarzadza katalogiem, ale nie prowadzi operacji na hostach.
	RoleIdentityAdmin: {
		PermHostRead, PermInventoryRead, PermJobRead, PermCampaignRead,
		PermIdentityRead, PermIdentityPolicyRead, PermIdentityUserWrite,
		PermIdentityGroupWrite, PermIdentityPolicyWrite, PermIdentityHostEnroll,
		PermUnitStatus,
		// Konta lokalne sa alternatywa dla katalogu, wiec naleza do tej samej
		// roli: to ona odpowiada za to, kto ma dostep do hostow.
		PermLocalUserRead, PermLocalUserCreate, PermLocalUserLock,
		PermLocalUserUnlock, PermLocalSSHKeyWrite,
	},
	RolePlatformAdmin: {
		PermHostRead, PermInventoryRead, PermJobRead, PermAuditRead,
		PermJobCreate, PermJobApprove, PermJobCancel,
		PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload, PermJournalRead,
		// Administrator ma takze operacje nieodwracalne na kontenerach.
		PermDockerRead, PermDockerStart, PermDockerStop, PermDockerRestart,
		PermDockerPull, PermDockerRemove, PermDockerPrune,
		PermComposePlan, PermComposeDeploy,
		PermUnitStatus, PermUnitEnableWrite, PermUnitMaskWrite,
		PermJournalFollow, PermLogFileRead, PermProcessRead, PermProcessSignal,
		PermPackagesInstall, PermPackagesRemove, PermPackagesHold,
		PermPackagesRepository,
		PermScheduleWrite, PermScheduleDisable, PermScheduleRemove, PermScheduleRun,
		PermNetworkRead, PermNetworkWrite, PermNetworkRouteWrite,
		PermNetworkMTUWrite, PermNetworkRollback,
		PermDNSRead, PermDNSHostWrite,
		PermFirewallRead, PermFirewallWrite, PermFirewallRuleRemove,
		PermFirewallZoneWrite, PermFirewallServiceWrite, PermFirewallRestore,
		PermStorageRead, PermStorageMountWrite, PermStorageMountRemove, PermStorageFsck,
		PermStorageLVMWrite, PermStorageFilesystemWrite,
		PermStorageDestructive, PermStorageWipe,
		PermSSHRead, PermSSHConfigWrite, PermSSHHostKeyRotate,
		PermKernelRead, PermKernelSysctlWrite,
		PermKernelModuleWrite, PermKernelModuleBlacklist,
		PermTimeRead, PermTimeWrite, PermTimezoneWrite,
		PermSecurityRead, PermSecurityScan, PermSecurityRemediate,
		PermSecurityMACWrite, PermSecurityAuditReload,
		PermFileRead, PermFilePlan, PermFileWrite, PermFileRemove, PermFileRollback,
		PermPackagesPlan, PermPackagesUpgrade, PermPackagesRepair,
		PermSystemReboot, PermSystemShutdown, PermHostMaintenanceWrite,
		PermCampaignRead, PermCampaignCreate, PermCampaignApprove, PermCampaignControl,
		PermIdentityRead, PermIdentityPolicyRead, PermIdentityUserWrite,
		PermIdentityGroupWrite, PermIdentityPolicyWrite, PermIdentityHostEnroll,
		PermEnrollmentToken, PermPrincipalManage,
		PermLocalUserRead, PermLocalUserCreate, PermLocalUserLock,
		PermLocalUserUnlock, PermLocalSSHKeyWrite, PermMetricsRead,
		PermPKIRead, PermPKIRotate,
		PermSecretRead, PermSecretWrite, PermSecretDestroy,
		PermCertificateRead, PermCertificateWatch,
		PermCertificateDeploy, PermCertificateRenew,
		PermBackupRead, PermBackupRun, PermBackupVerify, PermBackupRestore,
	},
}

// KnownRole sprawdza, czy rola istnieje.
func KnownRole(role Role) bool {
	_, ok := rolePermissions[role]
	return ok
}

// Permissions zwraca posortowana liste uprawnien roli.
func (r Role) Permissions() []Permission {
	permissions := append([]Permission(nil), rolePermissions[r]...)
	sort.Slice(permissions, func(i, j int) bool { return permissions[i] < permissions[j] })
	return permissions
}

// Has sprawdza, czy rola ma uprawnienie.
func (r Role) Has(permission Permission) bool {
	for _, granted := range rolePermissions[r] {
		if granted == permission {
			return true
		}
	}
	return false
}

// AllRoles zwraca posortowana liste rol.
func AllRoles() []Role {
	roles := make([]Role, 0, len(rolePermissions))
	for role := range rolePermissions {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return roles
}

// Scope ogranicza uprawnienie do czesci floty. Gwiazdka oznacza dowolna wartosc.
type Scope struct {
	Site        string `json:"site"`
	Environment string `json:"environment"`
}

// Wildcard jest wartoscia oznaczajaca dowolny zakres.
const Wildcard = "*"

// Matches sprawdza, czy zakres uprawnienia obejmuje zakres celu.
// Gwiazdka po stronie uprawnienia pasuje do wszystkiego. Pusty zakres celu nie
// jest dopasowywany przez waskie uprawnienie: brak wiedzy o celu nie moze
// rozszerzac uprawnien.
func (s Scope) Matches(target Scope) bool {
	return matchesValue(s.Site, target.Site) && matchesValue(s.Environment, target.Environment)
}

func matchesValue(granted, target string) bool {
	if granted == Wildcard {
		return true
	}
	return granted != "" && granted == target
}

// String zwraca czytelny opis zakresu.
func (s Scope) String() string {
	return fmt.Sprintf("site=%s env=%s", orWildcard(s.Site), orWildcard(s.Environment))
}

func orWildcard(value string) string {
	if strings.TrimSpace(value) == "" {
		return Wildcard
	}
	return value
}

// Binding to rola przypisana w zakresie.
type Binding struct {
	Role  Role  `json:"role"`
	Scope Scope `json:"scope"`
}

// Principal jest uwierzytelniona tozsamoscia wraz z jej rolami.
type Principal struct {
	ID          string    `json:"id"`
	Subject     string    `json:"subject"`
	DisplayName string    `json:"display_name,omitempty"`
	Kind        string    `json:"kind"`
	Bindings    []Binding `json:"bindings"`
}

// Can sprawdza, czy tozsamosc ma uprawnienie w zakresie celu.
func (p Principal) Can(permission Permission, target Scope) bool {
	for _, binding := range p.Bindings {
		if binding.Role.Has(permission) && binding.Scope.Matches(target) {
			return true
		}
	}
	return false
}

// CanAnywhere sprawdza, czy tozsamosc ma uprawnienie w jakimkolwiek zakresie.
//
// Sluzy kolekcjom: lista hostow czy kampanii nie ma jednego zakresu, wiec
// pytanie "czy wolno ci to widziec globalnie" jest dla niej zle postawione.
// Operator jednego srodowiska ma zobaczyc swoja czesc floty, a nie odmowe.
func (p Principal) CanAnywhere(permission Permission) bool {
	for _, binding := range p.Bindings {
		if binding.Role.Has(permission) {
			return true
		}
	}
	return false
}

// Permissions zwraca posortowana liste uprawnien, ktore tozsamosc ma
// w jakimkolwiek zakresie.
//
// Interfejs uzywa jej do ukrycia sekcji, ktorych i tak nie wolno otworzyc.
// Zrodlem jest serwer, a nie zgadywanie po nazwach rol po stronie przegladarki:
// polityka moze sie zmienic bez przebudowy panelu.
func (p Principal) Permissions() []string {
	unikalne := map[string]bool{}
	for _, binding := range p.Bindings {
		for _, permission := range binding.Role.Permissions() {
			unikalne[string(permission)] = true
		}
	}
	lista := make([]string, 0, len(unikalne))
	for permission := range unikalne {
		lista = append(lista, permission)
	}
	sort.Strings(lista)
	return lista
}

// ScopesFor zwraca zakresy, w ktorych tozsamosc ma dane uprawnienie.
// Pusty wynik oznacza brak uprawnienia gdziekolwiek.
func (p Principal) ScopesFor(permission Permission) []Scope {
	var scopes []Scope
	for _, binding := range p.Bindings {
		if binding.Role.Has(permission) {
			scopes = append(scopes, binding.Scope)
		}
	}
	return scopes
}

// Roles zwraca nazwy przypisanych rol, do audytu i diagnostyki.
func (p Principal) Roles() []string {
	seen := map[Role]bool{}
	var roles []string
	for _, binding := range p.Bindings {
		if !seen[binding.Role] {
			seen[binding.Role] = true
			roles = append(roles, string(binding.Role))
		}
	}
	sort.Strings(roles)
	return roles
}

// ScopeSQL buduje warunek SQL zawezajacy wiersze do podanych zakresow.
//
// Semantyka jest ta sama co w Matches i to jest cel istnienia tej funkcji:
// zawezanie list rozjechalo sie kiedys z autoryzacja, bo powstalo osobno.
// Gwiazdka oznacza dowolny zakres i znosi warunek. Wartosc pusta nie pasuje
// do niczego - brak wiedzy o zakresie nie moze rozszerzac widocznosci.
//
// Pusta lista zakresow daje warunek falszywy: tozsamosc bez zadnego zakresu
// nie widzi nic. Zwrocenie warunku pustego oznaczaloby dostep do wszystkiego,
// czyli blad w najgorsza mozliwa strone.
//
// offset jest liczba parametrow juz uzytych w zapytaniu; funkcja numeruje
// wlasne od nastepnego.
func ScopeSQL(scopes []Scope, siteColumn, envColumn string, offset int) (string, []any) {
	if len(scopes) == 0 {
		return "false", nil
	}

	var warunki []string
	var args []any
	for _, scope := range scopes {
		if scope.Site == Wildcard && scope.Environment == Wildcard {
			// Zakres globalny obejmuje wszystko, wiec dalsze warunki nie maja
			// juz znaczenia.
			return "", nil
		}
		czesci := make([]string, 0, 2)
		for _, wymiar := range []struct {
			kolumna string
			wartosc string
		}{{siteColumn, scope.Site}, {envColumn, scope.Environment}} {
			switch wymiar.wartosc {
			case Wildcard:
				// Dowolna wartosc w tym wymiarze.
			case "":
				czesci = append(czesci, "false")
			default:
				args = append(args, wymiar.wartosc)
				czesci = append(czesci, fmt.Sprintf("%s = $%d", wymiar.kolumna, offset+len(args)))
			}
		}
		if len(czesci) == 0 {
			return "", nil
		}
		warunki = append(warunki, "("+strings.Join(czesci, " and ")+")")
	}
	return "(" + strings.Join(warunki, " or ") + ")", args
}
