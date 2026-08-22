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
	PermSystemReboot    Permission = "system.reboot"
	PermUnitStatus      Permission = "unit.status"

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
		PermIdentityRead, PermLocalUserRead,
	},
	RoleAuditor: {
		PermHostRead, PermInventoryRead, PermJobRead, PermAuditRead, PermCampaignRead,
		PermIdentityRead, PermIdentityPolicyRead, PermLocalUserRead,
		// Auditor patrzy na stan systemu, wiec metryki naleza do jego pracy.
		PermMetricsRead,
	},
	RoleOperator: {
		PermHostRead, PermInventoryRead, PermJobRead,
		PermJobCreate, PermJobCancel,
		PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload, PermJournalRead,
		// Operator planuje aktualizacje, ale ich nie wykonuje: transakcja
		// pakietowa jest operacja najwyzszego ryzyka i wymaga osobnego prawa.
		PermPackagesPlan,
		// Operator planuje i prowadzi kampanie, ale ich nie zatwierdza.
		PermCampaignRead, PermCampaignCreate, PermCampaignControl,
		// Operator widzi konta lokalne, ale ich nie zaklada: nadanie dostepu
		// do hosta jest decyzja administracyjna, a nie czescia obslugi awarii.
		PermLocalUserRead,
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
		PermUnitStatus, PermPackagesPlan, PermPackagesUpgrade, PermSystemReboot,
		PermCampaignRead, PermCampaignCreate, PermCampaignApprove, PermCampaignControl,
		PermIdentityRead, PermIdentityPolicyRead, PermIdentityUserWrite,
		PermIdentityGroupWrite, PermIdentityPolicyWrite, PermIdentityHostEnroll,
		PermEnrollmentToken, PermPrincipalManage,
		PermLocalUserRead, PermLocalUserCreate, PermLocalUserLock,
		PermLocalUserUnlock, PermLocalSSHKeyWrite, PermMetricsRead,
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
