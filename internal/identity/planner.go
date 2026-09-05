package identity

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// Planner buduje podglad wplywu zmiany. Plan pokazuje wynikowe czlonkostwo,
// hosty osiagalne przez HBAC i reguly sudo, zanim cokolwiek sie wydarzy.
type Planner struct {
	directory *freeipa.Client
}

func NewPlanner(directory *freeipa.Client) *Planner {
	return &Planner{directory: directory}
}

// Build liczy plan dla zmiany.
func (p *Planner) Build(ctx context.Context, action ActionType, payload Payload) (Plan, error) {
	switch action {
	case ActionUserCreate:
		return p.planUserCreate(ctx, payload.User)
	case ActionUserDisable:
		return p.planUserAccess(ctx, payload.Reference.UID, false)
	case ActionUserEnable:
		return p.planUserAccess(ctx, payload.Reference.UID, true)
	case ActionGroupMembers:
		return p.planGroupMembers(ctx, payload.Group)
	case ActionSSHKeys:
		return p.planSSHKeys(ctx, payload.SSHKeys)
	case ActionDNSRecordEnsure:
		return p.planRekord(ctx, payload.DNS, true)
	case ActionDNSRecordRemove:
		return p.planRekord(ctx, payload.DNS, false)
	default:
		return Plan{}, fmt.Errorf("nieznany typ zmiany %q", action)
	}
}

func (p *Planner) planUserCreate(ctx context.Context, spec *UserPayload) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Utworzenie konta %s", spec.UID),
		AffectedUsers: []string{spec.UID},
		Steps:         []string{"utworzenie konta w katalogu"},
	}
	if len(spec.Groups) > 0 {
		plan.Steps = append(plan.Steps, "dodanie do grup: "+strings.Join(spec.Groups, ", "))
		plan.ResultingGroups = spec.Groups
	}
	if len(spec.SSHKeys) > 0 {
		plan.Steps = append(plan.Steps, fmt.Sprintf("ustawienie %d kluczy SSH", len(spec.SSHKeys)))
	}

	// Konflikt nazwy zatrzymuje wykonanie: katalog nie scala kont
	// automatycznie, a panel nie moze tego robic za niego.
	users, err := p.directory.Users(ctx)
	if err != nil {
		return plan, err
	}
	for _, user := range users {
		if user.UID == spec.UID {
			plan.Conflicts = append(plan.Conflicts,
				fmt.Sprintf("konto %s juz istnieje (UID %s)", user.UID, user.UIDNumber))
		}
	}

	groups, err := p.directory.Groups(ctx)
	if err != nil {
		return plan, err
	}
	known := map[string]bool{}
	for _, group := range groups {
		known[group.Name] = true
	}
	for _, wanted := range spec.Groups {
		if !known[wanted] {
			plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("grupa %s nie istnieje", wanted))
		}
	}

	access, err := p.accessFor(ctx, spec.Groups, spec.UID)
	if err != nil {
		return plan, err
	}
	plan.ReachableHosts = access.hosts
	plan.SudoRules = access.sudo
	plan.Warnings = append(plan.Warnings, access.warnings...)
	return plan, nil
}

// planUserAccess pokazuje dostep, ktory zostanie odebrany albo przywrocony.
func (p *Planner) planUserAccess(ctx context.Context, uid string, enabling bool) (Plan, error) {
	verb := "Zablokowanie"
	if enabling {
		verb = "Odblokowanie"
	}
	plan := Plan{
		Summary:       fmt.Sprintf("%s konta %s", verb, uid),
		AffectedUsers: []string{uid},
	}

	users, err := p.directory.Users(ctx)
	if err != nil {
		return plan, err
	}
	var found *freeipa.User
	for index := range users {
		if users[index].UID == uid {
			found = &users[index]
			break
		}
	}
	if found == nil {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("konto %s nie istnieje w katalogu", uid))
		return plan, nil
	}
	plan.CurrentGroups = found.Groups

	if enabling {
		plan.Steps = []string{"odblokowanie konta w katalogu"}
	} else {
		// Kolejnosc ma znaczenie: lokalny znacznik odmowy dziala natychmiast,
		// zanim zmiana w katalogu zdazy sie rozpropagowac do hostow.
		plan.Steps = []string{
			"lokalny znacznik odmowy w panelu",
			"uniewaznienie sesji panelu",
			"zablokowanie konta w katalogu",
		}
	}

	access, err := p.accessFor(ctx, found.Groups, uid)
	if err != nil {
		return plan, err
	}
	plan.ReachableHosts = access.hosts
	plan.SudoRules = access.sudo
	if !enabling && len(access.sudo) > 0 {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("konto traci %d regul sudo", len(access.sudo)))
	}
	if !enabling && found.Disabled {
		plan.Warnings = append(plan.Warnings, "konto jest juz zablokowane w katalogu")
	}
	return plan, nil
}

func (p *Planner) planGroupMembers(ctx context.Context, spec *GroupPayload) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Zmiana czlonkostwa w grupie %s", spec.Group),
		AffectedUsers: append(append([]string{}, spec.Add...), spec.Remove...),
	}
	if len(spec.Add) > 0 {
		plan.Steps = append(plan.Steps, "dodanie: "+strings.Join(spec.Add, ", "))
	}
	if len(spec.Remove) > 0 {
		plan.Steps = append(plan.Steps, "usuniecie: "+strings.Join(spec.Remove, ", "))
	}

	groups, err := p.directory.Groups(ctx)
	if err != nil {
		return plan, err
	}
	var target *freeipa.Group
	for index := range groups {
		if groups[index].Name == spec.Group {
			target = &groups[index]
			break
		}
	}
	if target == nil {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("grupa %s nie istnieje", spec.Group))
		return plan, nil
	}

	plan.CurrentGroups = target.Members
	resulting := append([]string{}, target.Members...)
	for _, user := range spec.Add {
		if !slices.Contains(resulting, user) {
			resulting = append(resulting, user)
		}
	}
	resulting = slices.DeleteFunc(resulting, func(user string) bool {
		return slices.Contains(spec.Remove, user)
	})
	slices.Sort(resulting)
	plan.ResultingGroups = resulting

	access, err := p.accessFor(ctx, []string{spec.Group}, "")
	if err != nil {
		return plan, err
	}
	plan.ReachableHosts = access.hosts
	plan.SudoRules = access.sudo
	plan.Warnings = append(plan.Warnings, access.warnings...)

	// Dodanie do grupy uprzywilejowanej jest zmiana wysokiego ryzyka.
	if len(access.sudo) > 0 && len(spec.Add) > 0 {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("grupa daje dostep do %d regul sudo", len(access.sudo)))
	}
	return plan, nil
}

func (p *Planner) planSSHKeys(ctx context.Context, spec *SSHKeysPayload) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Ustawienie kluczy SSH konta %s", spec.UID),
		AffectedUsers: []string{spec.UID},
		Steps:         []string{fmt.Sprintf("ustawienie %d kluczy publicznych", len(spec.Keys))},
	}
	if len(spec.Keys) == 0 {
		plan.Warnings = append(plan.Warnings,
			"pusta lista usuwa wszystkie klucze konta i moze odciac logowanie po SSH")
	}

	user, err := p.directory.ShowUser(ctx, spec.UID)
	if err != nil {
		plan.Conflicts = append(plan.Conflicts, err.Error())
		return plan, nil
	}
	if len(user.SSHKeyFingerprints) > 0 {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("konto ma obecnie %d kluczy; zostana zastapione", len(user.SSHKeyFingerprints)))
	}
	return plan, nil
}

// access opisuje dostep wynikajacy z czlonkostwa w grupach.
type access struct {
	hosts    []string
	sudo     []string
	warnings []string
}

// accessFor liczy, do jakich hostow i regul sudo prowadzi czlonkostwo.
func (p *Planner) accessFor(ctx context.Context, groups []string, uid string) (access, error) {
	var result access
	if len(groups) == 0 && uid == "" {
		return result, nil
	}

	rules, err := p.directory.HBACRules(ctx)
	if err != nil {
		return result, err
	}
	for _, rule := range rules {
		if !rule.Enabled || !matchesSubject(rule.Users, rule.UserGroups, uid, groups) {
			continue
		}
		if rule.AllowsEverything {
			result.hosts = append(result.hosts, "wszystkie hosty (regula "+rule.Name+")")
			result.warnings = append(result.warnings,
				"dostep wynika z reguly "+rule.Name+" obejmujacej cala flote")
			continue
		}
		result.hosts = append(result.hosts, rule.Hosts...)
		for _, group := range rule.HostGroups {
			result.hosts = append(result.hosts, "grupa hostow "+group)
		}
	}

	sudoRules, err := p.directory.SudoRules(ctx)
	if err != nil {
		return result, err
	}
	for _, rule := range sudoRules {
		if !rule.Enabled || !matchesSubject(rule.Users, rule.UserGroups, uid, groups) {
			continue
		}
		label := rule.Name
		if rule.Critical {
			label += " (krytyczna: " + strings.Join(rule.CriticalReasons, ", ") + ")"
			result.warnings = append(result.warnings, "regula sudo "+rule.Name+" jest krytyczna")
		}
		result.sudo = append(result.sudo, label)
	}

	slices.Sort(result.hosts)
	result.hosts = slices.Compact(result.hosts)
	return result, nil
}

// matchesSubject mowi, czy regula obejmuje konto albo ktoras z jego grup.
func matchesSubject(ruleUsers, ruleGroups []string, uid string, groups []string) bool {
	if uid != "" && slices.Contains(ruleUsers, uid) {
		return true
	}
	for _, group := range groups {
		if slices.Contains(ruleGroups, group) {
			return true
		}
	}
	return false
}

// planRekord opisuje, co stanie sie z rekordem w katalogu.
//
// Rekord odwrotny jest osobnym krokiem planu, a nie szczegolem zapisu: to on
// decyduje, co odpowie zapytanie o adres, i najczesciej to o nim sie zapomina.
func (p *Planner) planRekord(ctx context.Context, spec *DNSRecordPayload, dopisanie bool) (Plan, error) {
	czasownik := "Dopisanie"
	krok := "dopisanie rekordu"
	if !dopisanie {
		czasownik = "Usuniecie"
		krok = "usuniecie rekordu"
	}
	pelna := spec.Name + "." + strings.TrimSuffix(spec.Zone, ".")
	if spec.Name == "@" {
		pelna = strings.TrimSuffix(spec.Zone, ".")
	}
	plan := Plan{
		Summary: fmt.Sprintf("%s rekordu %s %s %s", czasownik, spec.Type, pelna, spec.Value),
		Steps:   []string{krok + " " + spec.Type + " " + pelna + " -> " + spec.Value},
	}

	strefaOdwrotna, nazwaOdwrotna := "", ""
	if spec.Reverse {
		strefaOdwrotna, nazwaOdwrotna = spec.ReverseZone, ""
		wyliczona, nazwa, err := freeipa.StrefaOdwrotna(spec.Value)
		if err != nil {
			return plan, err
		}
		nazwaOdwrotna = nazwa
		if strefaOdwrotna == "" {
			strefaOdwrotna = wyliczona
		}
		plan.Steps = append(plan.Steps, krok+" odwrotnego PTR "+nazwaOdwrotna+"."+strefaOdwrotna+
			" -> "+pelna)
	}

	strefy, err := p.directory.Zones(ctx)
	if err != nil {
		return plan, err
	}
	znane := map[string]bool{}
	for _, strefa := range strefy {
		znane[strefa.Name] = true
	}
	if !znane[strings.TrimSuffix(spec.Zone, ".")] {
		// Strefy panel nie zaklada: to decyzja o podziale przestrzeni nazw,
		// a nie o jednym wpisie.
		plan.Conflicts = append(plan.Conflicts,
			fmt.Sprintf("katalog nie ma strefy %s", spec.Zone))
	}
	if spec.Reverse && !znane[strings.TrimSuffix(strefaOdwrotna, ".")] {
		plan.Conflicts = append(plan.Conflicts,
			fmt.Sprintf("katalog nie ma strefy odwrotnej %s", strefaOdwrotna))
	}

	// Stan biezacy rekordu: czy taki wpis juz jest i z jaka wartoscia.
	rekordy, err := p.directory.Records(ctx, strings.TrimSuffix(spec.Zone, "."))
	if err != nil {
		// Brak dostepu do strefy nie uniewaznia planu, ale operator ma
		// wiedziec, ze panel nie porownal go ze stanem katalogu.
		plan.Conflicts = append(plan.Conflicts,
			"nie odczytano rekordow strefy: "+err.Error())
		return plan, nil
	}
	for _, rekord := range rekordy {
		if rekord.Name != spec.Name || rekord.Type != spec.Type {
			continue
		}
		if slices.Contains(rekord.Values, spec.Value) {
			if dopisanie {
				plan.Conflicts = append(plan.Conflicts,
					fmt.Sprintf("rekord %s %s ma juz wartosc %s", spec.Type, pelna, spec.Value))
			}
			continue
		}
		// Rekord z inna wartoscia nie jest bledem: nazwa moze wskazywac
		// kilka adresow. Ale operator ma to zobaczyc przed zapisem.
		plan.Steps = append(plan.Steps, fmt.Sprintf("uwaga: %s %s wskazuje juz %s",
			spec.Type, pelna, strings.Join(rekord.Values, ", ")))
		if !dopisanie && !slices.Contains(rekord.Values, spec.Value) {
			plan.Conflicts = append(plan.Conflicts,
				fmt.Sprintf("rekord %s %s nie ma wartosci %s", spec.Type, pelna, spec.Value))
		}
	}
	return plan, nil
}
