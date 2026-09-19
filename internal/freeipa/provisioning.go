package freeipa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The provisioning of the one directory right a preserve needs.

const (
	// PreservePermission is the directory's own permission that carries the ACI
	// allowing the move from the active accounts into the container of preserved
	// ones.
	PreservePermission = "System: Preserve User"
	// A preserve needs three rights, not one, and the laboratory proved each of
	// them the hard way.
	PreserveRDNPermission  = "System: Modify User RDN"
	PreserveReadPermission = "System: Read Preserved Users"
	// And the fourth: the directory's own command clears the password of the
	// entry it preserves, so without the write on the container the move happens
	// and the call fails afterwards - the account ends up preserved while the
	PreserveModifyPermission = "System: Modify Preserved Users"
	// PreservePrivilege is the privilege the connector's role holds.
	PreservePrivilege = "Flotestro Preserve Users"
	// PreserveRole is the role the connector's own service account is a
	// member of.
	PreserveRole = "Flotestro Directory Connector"

	privilegeDescription = "Moving an account into the container of preserved accounts"
	roleDescription      = "The Flotestro panel's directory connector"
)

// What one step of the provisioning found or did.
const (
	// ProvisionCreated: the step created the object or the membership now.
	ProvisionCreated = "created"
	// ProvisionAlreadyPresent: the directory already held it, and the step
	// changed nothing. A second run reports this for every step.
	ProvisionAlreadyPresent = "already_present"
	// ProvisionNotPermitted: the directory refused the connector's own account
	// this change.
	ProvisionNotPermitted = "not_permitted"
	// ProvisionMissing: the directory does not hold something the step
	// needs and cannot create it through the API.
	ProvisionMissing = "missing"
)

// provisioningMethods are the directory commands that change the directory's
// own configuration.
var provisioningMethods = map[string]bool{
	"permission_show":          true,
	"privilege_show":           true,
	"privilege_add":            true,
	"privilege_add_permission": true,
	"role_show":                true,
	"role_add":                 true,
	"role_add_privilege":       true,
	"role_add_member":          true,
}

// provision runs one of the configuration commands. It is the second door
// into the directory beside call, and it opens only for the commands above.
func (c *Client) provision(ctx context.Context, method string, args []string,
	options map[string]any) (json.RawMessage, error) {
	if !provisioningMethods[method] {
		return nil, fmt.Errorf("the command %q is not a provisioning command of the adapter", method)
	}
	return c.invoke(ctx, method, args, options)
}

// ProvisioningStep is one object or membership the step had to settle.
type ProvisioningStep struct {
	// Object is what was settled, named the way an operator would name it.
	Object  string `json:"object"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// ProvisioningReport is the whole answer of one run: what it created, what
// was already there, and what it would need that it may not do itself.
type ProvisioningReport struct {
	Principal  string `json:"principal"`
	Permission string `json:"permission"`
	Privilege  string `json:"privilege"`
	Role       string `json:"role"`

	Steps []ProvisioningStep `json:"steps"`
	// Changed says whether this run changed anything in the directory.
	Changed bool `json:"changed"`
	// Complete says whether the connector's account now holds the right
	// through the objects named above.
	Complete bool `json:"complete"`
	// OperatorActions are the commands a directory administrator runs when the
	// connector's own account may not do it.
	OperatorActions []string `json:"operator_actions,omitempty"`
	// Verified is the directory's own answer about the move afterwards, read with
	// the same preflight a preserve runs.
	Verified     bool      `json:"verified"`
	VerifyDetail string    `json:"verify_detail,omitempty"`
	RanAt        time.Time `json:"ran_at"`
}

func (r *ProvisioningReport) record(object, outcome, detail string) {
	r.Steps = append(r.Steps, ProvisioningStep{Object: object, Outcome: outcome, Detail: detail})
	if outcome == ProvisionCreated {
		r.Changed = true
	}
}

// refuse records a directory that would not let the connector do this step
// and hands the operator the command to run instead.
func (r *ProvisioningReport) refuse(object string, err error, command string) {
	outcome := ProvisionNotPermitted
	if !isAccessDenied(err) {
		// A refusal that is not about access is still a refusal, and it is
		// reported with the directory's own words rather than translated.
		outcome = ProvisionMissing
	}
	r.record(object, outcome, err.Error())
	r.action(command)
}

func (r *ProvisioningReport) action(command string) {
	if command == "" {
		return
	}
	for _, existing := range r.OperatorActions {
		if existing == command {
			return
		}
	}
	r.OperatorActions = append(r.OperatorActions, command)
}

// settle decides whether the run left the connector able to move an entry.
func (r *ProvisioningReport) settle() {
	r.Complete = true
	for _, step := range r.Steps {
		if step.Outcome != ProvisionCreated && step.Outcome != ProvisionAlreadyPresent {
			r.Complete = false
		}
	}
	if !r.Complete && len(r.OperatorActions) > 0 {
		r.action("run the commands above with a Kerberos ticket of a directory administrator, " +
			"then run this step again to confirm")
	}
}

// Summary is the one line an operator reads in the job log.
func (r ProvisioningReport) Summary() string {
	created, present, open := 0, 0, 0
	for _, step := range r.Steps {
		switch step.Outcome {
		case ProvisionCreated:
			created++
		case ProvisionAlreadyPresent:
			present++
		default:
			open++
		}
	}
	summary := fmt.Sprintf("%d created, %d already there, %d left to a directory administrator",
		created, present, open)
	switch {
	case r.Verified:
		return summary + "; the directory reports that the move is allowed"
	case r.Complete:
		return summary + "; " + r.VerifyDetail
	default:
		return summary + "; the connector still cannot move an entry"
	}
}

// ProvisionPreserveRights gives the connector's own service account the right
// to move an entry into the container of preserved accounts, and nothing more.
func (c *Client) ProvisionPreserveRights(ctx context.Context) (ProvisioningReport, error) {
	report := ProvisioningReport{
		Principal:  c.config.Principal,
		Permission: PreservePermission,
		Privilege:  PreservePrivilege,
		Role:       PreserveRole,
		Steps:      []ProvisioningStep{},
		RanAt:      time.Now().UTC(),
	}
	commands := operatorCommands(c.config.Principal)

	// The permission is the directory's own and carries the ACI.
	found, showErr := c.findPreservePermission(ctx)
	if found != "" {
		report.Permission = found
	}
	permission := "the permission " + report.Permission
	if err := showErr; err != nil {
		switch {
		case isNotFound(err):
			// A directory hides what a bind may not read, so "there is no such
			// permission" and "this account may not see it" arrive as the same answer.
			report.record(permission, ProvisionMissing,
				"the connector cannot read it: either the directory does not publish it, "+
					"or this service account may not read permissions. It cannot be created "+
					"through the API either way: a permission knows the rights read, search, "+
					"compare, write, add and delete, and the move is a moddn")
			report.action(manualACI(c.config.Principal, c.config.Realm))
			// The step goes on rather than stopping here.
			for _, command := range commands {
				report.action(command)
			}
		case isAccessDenied(err):
			// An account that may not even read the permission will not be able to bind
			// anything to it either, so the whole sequence goes to the administrator
			// rather than the first command.
			report.refuse(permission, err, "")
			for _, command := range commands {
				report.action(command)
			}
		default:
			report.settle()
			return report, fmt.Errorf("reading %s: %w", permission, err)
		}
		report.settle()
		return report, nil
	}
	report.record(permission, ProvisionAlreadyPresent,
		"the directory publishes it; it carries the ACI that allows the move")

	if !c.ensureObject(ctx, &report, "privilege", PreservePrivilege, "privilege_show", "privilege_add",
		map[string]any{"description": privilegeDescription}, commands[0]) {
		report.settle()
		return report, nil
	}
	for _, name := range append([]string{report.Permission}, preserveCompanions...) {
		if !c.ensureMember(ctx, &report,
			"the permission "+name+" in the privilege "+PreservePrivilege,
			"privilege_add_permission", PreservePrivilege, "permission", name,
			`ipa privilege-add-permission "`+PreservePrivilege+`" --permissions="`+name+`"`) {
			report.settle()
			return report, nil
		}
	}
	if !c.ensureObject(ctx, &report, "role", PreserveRole, "role_show", "role_add",
		map[string]any{"description": roleDescription}, commands[2]) {
		report.settle()
		return report, nil
	}
	if !c.ensureMember(ctx, &report,
		"the privilege "+PreservePrivilege+" in the role "+PreserveRole,
		"role_add_privilege", PreserveRole, "privilege", PreservePrivilege, commands[3]) {
		report.settle()
		return report, nil
	}
	kind, member := principalMember(c.config.Principal)
	if !c.ensureMember(ctx, &report,
		"the connector's account "+member+" in the role "+PreserveRole,
		"role_add_member", PreserveRole, kind, member, commands[4]) {
		report.settle()
		return report, nil
	}

	report.settle()
	if report.Changed {
		// The rights the panel cached were read before this run granted
		// them; the next read asks the directory again.
		c.invalidate()
	}
	if report.Complete {
		capabilities, err := c.Capabilities(ctx)
		switch {
		case err != nil:
			report.VerifyDetail = "the directory could not be asked afterwards: " + err.Error()
		case capabilities.UserModDN:
			report.Verified = true
			report.VerifyDetail = "the directory reports the move as allowed"
		default:
			report.VerifyDetail = "the directory does not report the move as allowed: " +
				strings.Join(capabilities.ReasonCodes, ", ")
		}
	}
	return report, nil
}

// ensureObject settles one named object: it is read first, created only where
// the directory says it is not there, and a directory that refuses the
// creation is reported with the command an administrator runs instead.
func (c *Client) ensureObject(ctx context.Context, report *ProvisioningReport,
	kind, name, show, add string, options map[string]any, command string) bool {
	object := "the " + kind + " " + name
	_, err := c.provision(ctx, show, []string{name}, map[string]any{})
	switch {
	case err == nil:
		report.record(object, ProvisionAlreadyPresent, "it was already there")
		return true
	case !isNotFound(err):
		report.refuse(object, err, command)
		return false
	}
	if _, err := c.provision(ctx, add, []string{name}, options); err != nil {
		if isDuplicate(err) {
			// Two runs at once: the object exists, which is the wanted state, and the
			// one that lost the race says so rather than failing.
			report.record(object, ProvisionAlreadyPresent, "another run created it first")
			return true
		}
		report.refuse(object, err, command)
		return false
	}
	report.record(object, ProvisionCreated, "created with nothing in it but the one right it carries")
	return true
}

// ensureMember puts one member into one holder and reads the directory's own
// account of what happened.
func (c *Client) ensureMember(ctx context.Context, report *ProvisioningReport,
	object, method, holder, kind, member, command string) bool {
	result, err := c.provision(ctx, method, []string{holder}, map[string]any{kind: []string{member}})
	if err != nil {
		report.refuse(object, err, command)
		return false
	}
	var decoded struct {
		Completed int `json:"completed"`
	}
	_ = json.Unmarshal(result, &decoded)
	problems := failedMembers(result)
	switch {
	case decoded.Completed > 0:
		report.record(object, ProvisionCreated, "the directory added it now")
		return true
	case len(problems) == 0 || alreadyMember(problems):
		report.record(object, ProvisionAlreadyPresent, "the directory already held it")
		return true
	default:
		report.record(object, ProvisionMissing, "the directory did not add it: "+strings.Join(problems, "; "))
		report.action(command)
		return false
	}
}

// alreadyMember reads the directory's way of saying the membership is the
// one that was asked for.
func alreadyMember(problems []string) bool {
	for _, problem := range problems {
		if !strings.Contains(strings.ToLower(problem), "already a member") {
			return false
		}
	}
	return len(problems) > 0
}

// isAccessDenied recognises the directory refusing a change to the account
// the connector uses, rather than refusing the change itself.
func isAccessDenied(err error) bool {
	var refusal *DirectoryError
	if errors.As(err, &refusal) && refusal.Name == "ACIError" {
		return true
	}
	return strings.Contains(err.Error(), "Insufficient access")
}

// isDuplicate recognises an object that is already there.
func isDuplicate(err error) bool {
	var refusal *DirectoryError
	if errors.As(err, &refusal) && refusal.Name == "DuplicateEntry" {
		return true
	}
	return strings.Contains(err.Error(), "already exists")
}

// principalMember says how the directory knows the connector's own account: a
// principal with a host in it is a service, anything else is a user.
func principalMember(principal string) (string, string) {
	name, _, _ := strings.Cut(principal, "@")
	if strings.Contains(name, "/") {
		return "service", principal
	}
	return "user", name
}

// ProvisioningInstruction is the sentence every refusal about the move
// carries: what to run, and what it grants.
func ProvisioningInstruction() string {
	return "run the directory provisioning step for preserving accounts " +
		"(the identity screen, \"prepare the directory for preserving accounts\"), " +
		"which gives the connector's service account the permission " + PreservePermission +
		" through the privilege " + PreservePrivilege + " and the role " + PreserveRole +
		", and nothing else. It is safe to repeat: a second run changes nothing."
}

// operatorCommands are the five commands a directory administrator runs when
// the connector's own account may not create these objects.
func operatorCommands(principal string) []string {
	kind, member := principalMember(principal)
	flag := "--services="
	if kind == "user" {
		flag = "--users="
	}
	return []string{
		`ipa privilege-add "` + PreservePrivilege + `" --desc="` + privilegeDescription + `"`,
		`ipa privilege-add-permission "` + PreservePrivilege + `" --permissions="` + PreservePermission +
			`" --permissions="` + PreserveRDNPermission + `" --permissions="` + PreserveReadPermission +
			`" --permissions="` + PreserveModifyPermission + `"`,
		`ipa role-add "` + PreserveRole + `" --desc="` + roleDescription + `"`,
		`ipa role-add-privilege "` + PreserveRole + `" --privileges="` + PreservePrivilege + `"`,
		`ipa role-add-member "` + PreserveRole + `" ` + flag + member,
	}
}

// manualACI is what an administrator adds when the directory does not publish
// the permission at all - an older directory, or one whose permission was
// removed.
func manualACI(principal, realm string) string {
	base := baseDN(principal, realm)
	kind, member := principalMember(principal)
	memberDN := "uid=" + member + ",cn=users,cn=accounts," + base
	if kind == "service" {
		memberDN = "krbprincipalname=" + member + ",cn=services,cn=accounts," + base
	}
	return "the directory does not publish " + PreservePermission + ", so the move is granted by an ACI " +
		"a directory administrator adds with an LDAP client (the base below follows the realm by the " +
		"usual convention - check it against the directory's own base):\n" +
		"ldapmodify -Y GSSAPI <<'EOF'\n" +
		"dn: cn=accounts," + base + "\n" +
		"changetype: modify\n" +
		"add: aci\n" +
		"aci: (target_from = \"ldap:///uid=*,cn=users,cn=accounts," + base + "\")" +
		"(target_to = \"ldap:///uid=*,cn=deleted users,cn=accounts,cn=provisioning," + base + "\")" +
		"(version 3.0; acl \"Flotestro: preserve accounts\"; allow (moddn) " +
		"userdn = \"ldap:///" + memberDN + "\";)\n" +
		"EOF"
}

// baseDN writes the directory's base the way the realm spells it.
func baseDN(principal, realm string) string {
	if realm == "" {
		if _, after, found := strings.Cut(principal, "@"); found {
			realm = after
		}
	}
	if realm == "" {
		return "$SUFFIX"
	}
	parts := strings.Split(strings.ToLower(realm), ".")
	for i, part := range parts {
		parts[i] = "dc=" + part
	}
	return strings.Join(parts, ",")
}

// preservePermissionNames are the spellings FreeIPA has published this
// permission under.
var preservePermissionNames = []string{"System: Preserve User", "System: Preserve Users"}

// findPreservePermission reads the directory's own preserve permission under
// whichever name this release publishes it.
func (c *Client) findPreservePermission(ctx context.Context) (string, error) {
	var lastErr error
	for _, name := range preservePermissionNames {
		if _, err := c.provision(ctx, "permission_show", []string{name}, map[string]any{}); err == nil {
			return name, nil
		} else if !isNotFound(err) {
			// A refusal that is not "there is no such permission" is about this
			// connector's rights, not about the spelling, so it stops the search and is
			// reported as it came.
			return "", err
		} else {
			lastErr = err
		}
	}
	return "", lastErr
}

// preserveCompanions are the three rights the move needs beside the moddn
// itself: the change of the entry's relative name, the read of the container
// it lands in, and the write on that container - the directory's own command
var preserveCompanions = []string{
	PreserveRDNPermission, PreserveReadPermission, PreserveModifyPermission,
}
