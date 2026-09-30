package release

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// absent emits the classification the release gate reads out of a skipped test,
// exactly as the integration harness does. These tests are the regression tests
// for a panel that did not come back after a reboot, for a pre-flight check that
// performed the migration it was asked about, and for two descriptions of one
// deployment drifting apart; a silent skip of any of them reads like a pass.
func absent(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf("FLOTESTRO-SKIP class=%s reason=%q", SkipAbsent, fmt.Sprintf(format, args...))
}

// A compose file as both things the tests need it as: the text, because some
// properties are about how it is written, and the parsed document, because most
// are about what it says.
type composeDeployment struct {
	file      string
	text      string
	top       map[string]any
	services  map[string]map[string]any
	exception map[string]string
}

// The field the two variants declare their differences in. "x-" is the prefix
// compose reserves for extensions: both engines ignore it, so the declaration
// travels in the file it is about and costs the deployment nothing.
const variantField = "x-compose-variant"

func parseCompose(t *testing.T, file, text string) composeDeployment {
	t.Helper()
	deployment := composeDeployment{
		file:      file,
		text:      text,
		top:       map[string]any{},
		services:  map[string]map[string]any{},
		exception: map[string]string{},
	}
	if err := yaml.Unmarshal([]byte(text), &deployment.top); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if services, ok := deployment.top["services"].(map[string]any); ok {
		for name, body := range services {
			service, ok := body.(map[string]any)
			if !ok {
				t.Fatalf("%s: the service %s is not a mapping", file, name)
			}
			deployment.services[name] = service
		}
	}
	if declared, ok := deployment.top[variantField].(map[string]any); ok {
		for key, why := range declared {
			reason, ok := why.(string)
			if !ok {
				t.Errorf("%s: the %s entry for %s is not a sentence", file, variantField, key)
				continue
			}
			deployment.exception[key] = strings.Join(strings.Fields(reason), " ")
		}
	}
	return deployment
}

// A deployment file is one that names a project and starts an image of its own;
// an overlay such as compose.external-db.yaml names no project and only amends
// what another file declares.
func (d composeDeployment) isDeployment() bool {
	if name, _ := d.top["name"].(string); name == "" {
		return false
	}
	for _, service := range d.services {
		if _, ok := service["image"]; ok {
			return true
		}
	}
	return false
}

// A complete panel deployment: one a control plane can be brought up from with
// no other file. There are two - the Docker daemon's and rootless Podman's -
// and the point of the comparison below is that there are never two that differ
// in anything nobody declared.
func (d composeDeployment) isCompletePanel() bool {
	if !d.isDeployment() {
		return false
	}
	panel, ok := d.services["control-plane"]
	if !ok {
		return false
	}
	_, ok = panel["image"]
	return ok
}

// Every compose file in the tree, and never a list written here: the panel is
// described more than once now, and a variant added later has to be caught by
// these tests on the day it appears rather than on the day somebody remembers
// to name it.
func composeFiles(t *testing.T) []composeDeployment {
	t.Helper()
	dir := filepath.Join("..", "..", "docker")
	paths, err := filepath.Glob(filepath.Join(dir, "compose*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		absent(t, "%s holds no compose file, so nothing about the deployment was read", dir)
	}
	sort.Strings(paths)
	files := make([]composeDeployment, 0, len(paths))
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, parseCompose(t, filepath.Base(path), string(content)))
	}
	return files
}

func composeDeployments(t *testing.T) []composeDeployment {
	t.Helper()
	var found []composeDeployment
	for _, file := range composeFiles(t) {
		if file.isDeployment() {
			found = append(found, file)
		}
	}
	return found
}

func completePanels(t *testing.T) []composeDeployment {
	t.Helper()
	var found []composeDeployment
	for _, file := range composeFiles(t) {
		if file.isCompletePanel() {
			found = append(found, file)
		}
	}
	return found
}

// The restart policy is not a preference. Rootless Podman replays the policies
// at boot with the unit it ships, and that unit runs
//
//	podman start --all --filter restart-policy=always
//
// so a service that says "unless-stopped" is skipped by it: the unit reports
// success, starts nothing, and the panel is down after every reboot of the
// host with nothing saying why. That is how it was for a while, and a test is
// cheaper than finding it again.
func TestEveryServiceThatMustSurviveARebootSaysAlways(t *testing.T) {
	for _, deployment := range composeDeployments(t) {
		found := 0
		for name, service := range deployment.services {
			policy, declared := service["restart"]
			if !declared {
				continue
			}
			found++
			switch scalar(policy) {
			case "no":
				// A one-shot: init, the migrator, the tools. Nothing should bring
				// these back on their own.
			case "always":
			default:
				t.Errorf("%s: the service %s says restart: %v; the unit podman ships starts only "+
					"restart-policy=always, so this service would not come back after a reboot",
					deployment.file, name, policy)
			}
		}
		if found == 0 {
			t.Errorf("%s declares no restart policy at all", deployment.file)
		}
	}
}

// The question an upgrade asks before it decides anything has to cost nothing.
// "run" starts what the named service depends on, so asking it through the
// control plane - which depends on migrate - performs the migration it is
// about and then reports that nothing needs migrating. That was the documented
// procedure once, and it was measured doing exactly this on both engines: an
// empty database came back at the head of the schema, exit 0. --no-deps is no
// answer either, because podman-compose puts the dependency on the one-off
// container itself with --requires and podman honours it.
func TestThePreFlightSchemaCheckDependsOnNothing(t *testing.T) {
	for _, deployment := range completePanels(t) {
		service, ok := deployment.services["schema-check"]
		if !ok {
			t.Errorf("%s declares no schema-check service; the upgrade has nothing to ask "+
				"that does not first migrate the database it is asking about", deployment.file)
			continue
		}
		if _, ok := service["depends_on"]; ok {
			t.Errorf("%s: the schema-check service declares depends_on; a pre-flight check that "+
				"starts anything can start the migration it was asked to look for", deployment.file)
		}
		if got := normalise("command", service["command"]); !reflect.DeepEqual(got, []any{"schema-check"}) {
			t.Errorf("%s: the schema-check service runs %v and not the schema-check command",
				deployment.file, service["command"])
		}
		if got := normalise("profiles", service["profiles"]); !reflect.DeepEqual(got, []string{"check"}) {
			t.Errorf("%s: the schema-check service carries the profiles %v, so an ordinary up may "+
				"run it and leave a refusal behind before the migration has had its turn",
				deployment.file, service["profiles"])
		}
	}
}

// The port the operator's browser reaches. The quickstart is opened from another
// machine, so the shipped default is every address of the host - and it stays a
// substitution, because an installation that puts TLS in front of the panel
// narrows it back to the loopback without editing the deployment. Comparing the
// variants with each other catches neither property: a change that moved both
// files off the host's addresses at once, or wrote the address in as a literal in
// both, would compare equal. So the value is pinned here, and the variants are
// also required to agree on it, which is the property the comparison would lose
// if this port ever became a declared difference.
func TestThePanelPublishesItsApiOnEveryAddressOfTheHostByDefault(t *testing.T) {
	substitution := regexp.MustCompile(`^\$\{FLOTESTRO_API_PUBLISH:-([^}]*)\}$`)
	const hostAddresses = "0.0.0.0"
	agreed := map[string][]string{}
	for _, deployment := range completePanels(t) {
		published := normalise("ports", deployment.services["control-plane"]["ports"]).([]string)
		found := 0
		for _, port := range published {
			field := strings.Split(port, "|")
			if len(field) != 4 || field[2] != "8080" {
				continue
			}
			found++
			agreed[field[0]] = append(agreed[field[0]], deployment.file)
			match := substitution.FindStringSubmatch(field[0])
			if match == nil {
				t.Errorf("%s: the panel publishes its API on %q, which no setting can change; "+
					"the host address is FLOTESTRO_API_PUBLISH so that an installation "+
					"behind a proxy can narrow it back to the loopback",
					deployment.file, field[0])
				continue
			}
			if match[1] != hostAddresses {
				t.Errorf("%s: FLOTESTRO_API_PUBLISH defaults to %q; the quickstart is opened "+
					"from another machine, so the shipped default is %s and a narrower "+
					"bind is the installation's own choice",
					deployment.file, match[1], hostAddresses)
			}
		}
		switch found {
		case 1:
		case 0:
			t.Errorf("%s: the panel publishes no port 8080, so the operator reaches nothing",
				deployment.file)
		default:
			t.Errorf("%s: the panel publishes port 8080 %d times, and only one of them can be "+
				"the one FLOTESTRO_API_PUBLISH governs", deployment.file, found)
		}
	}
	if len(agreed) > 1 {
		t.Errorf("the variants publish the panel's API differently: %v. One of them would put "+
			"the first-run screen somewhere the other does not", agreed)
	}
}

// And nothing may tell an operator to ask it the old way again. The service
// that answers writes nothing; the one that used to be named drags migrate in
// behind it.
func TestNoDocumentAsksTheControlPlaneForASchemaCheck(t *testing.T) {
	asked := regexp.MustCompile(`run\s+(?:--rm\s+)?control-plane\s+schema-check`)
	for _, file := range []string{
		filepath.Join("..", "..", "docker", "README.md"),
		filepath.Join("..", "..", "docs", "runbooks", "install.md"),
		filepath.Join("..", "..", "docs", "site", "docs", "installation.html"),
		filepath.Join("..", "..", "docs", "site", "pl", "docs", "installation.html"),
	} {
		content, err := os.ReadFile(file)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			if asked.MatchString(line) {
				t.Errorf("%s: %q asks the control plane for the schema check, which starts "+
					"migrate first; the command is "+
					"\"docker compose --profile check run --rm schema-check\"",
					file, strings.TrimSpace(line))
			}
		}
	}
}

// One deployment, described twice, because rootless Podman needs a network mode
// where the daemon takes a network and can be given one in no overlay:
// podman-compose 1.3.0 reads a file with yaml.safe_load, so a !reset tag is a
// parse error, and extends and network_mode both merge the base's networks back
// in. Two descriptions of one thing are a defect waiting for the edit that
// reaches only one of them - a variable, a secret, a mount, a capability - and
// that edit is invisible in review, because the file being reviewed is right.
//
// So the whole service definitions are compared, not a list of properties worth
// watching: a property list only ever catches what somebody thought of. Every
// difference the comparison finds has to be declared in the file that differs,
// in x-compose-variant, with the reason; and an entry that no longer matches a
// difference fails too, so the list cannot rot into a blanket permission.
func TestTheComposeVariantsDescribeOneDeployment(t *testing.T) {
	panels := completePanels(t)
	if len(panels) < 2 {
		t.Fatalf("docker/ holds %d complete panel deployment, and there are two - the Docker "+
			"daemon's and rootless Podman's. Either a variant was deleted or this test no "+
			"longer finds it, and in both cases nothing is comparing them", len(panels))
	}
	for i := 1; i < len(panels); i++ {
		for _, complaint := range composeDrift(panels[0], panels[i]) {
			t.Error(complaint)
		}
	}
}

// How much of a reason is a reason. Long enough that the shortest way past the
// test is to write the sentence rather than to type a word into the field.
const shortestVariantReason = 24

// composeDrift returns what the two files say differently and nobody declared,
// and what they declare and no longer say differently.
func composeDrift(left, right composeDeployment) []string {
	declared := map[string]string{}
	for _, file := range []composeDeployment{left, right} {
		for key, why := range file.exception {
			declared[key] = why
		}
	}
	used := map[string]bool{}
	var drift []string

	// allowed reports whether the difference at key is one the files declare with
	// a reason. It records the consultation either way, so that an entry which
	// stops matching anything is found below.
	allowed := func(key string) bool {
		why, ok := declared[key]
		if !ok {
			return false
		}
		used[key] = true
		if len([]rune(why)) < shortestVariantReason {
			drift = append(drift, fmt.Sprintf("%s and %s differ in %s, and %s says only %q. "+
				"Write what the difference is for, so that the next reader does not have to "+
				"work it out from the two files", left.file, right.file, key, variantField, why))
			return false
		}
		return true
	}
	report := func(key, detail string) {
		drift = append(drift, fmt.Sprintf("%s and %s differ in %s: %s. Either make them agree, "+
			"or declare it in the file that differs:\n\t%s:\n\t  %s: <what the difference is for>",
			left.file, right.file, key, detail, variantField, key))
	}
	// What differs and not both values in full: a service definition printed twice
	// buries the one variable that moved.
	difference := func(leftValue, rightValue any) string {
		leftNormal, rightNormal := leftValue, rightValue
		if leftMap, ok := leftNormal.(map[string]string); ok {
			if rightMap, ok := rightNormal.(map[string]string); ok {
				var parts []string
				for _, key := range unionKeys(anyMap(leftMap), anyMap(rightMap)) {
					leftEntry, inLeft := leftMap[key]
					rightEntry, inRight := rightMap[key]
					if inLeft == inRight && leftEntry == rightEntry {
						continue
					}
					parts = append(parts, fmt.Sprintf("%s is %s in %s and %s in %s",
						key, quoteOrAbsent(leftEntry, inLeft), left.file,
						quoteOrAbsent(rightEntry, inRight), right.file))
				}
				return strings.Join(parts, "; ")
			}
		}
		return fmt.Sprintf("%s has %v and %s has %v", left.file, leftValue, right.file, rightValue)
	}

	// The deployment outside the services: the project name, which decides which
	// volumes the two files address, and the networks and volumes themselves.
	// Extension fields are not compared - they carry this very declaration.
	for _, key := range unionKeys(left.top, right.top) {
		if key == "services" || strings.HasPrefix(key, "x-") {
			continue
		}
		leftValue, inLeft := left.top[key]
		rightValue, inRight := right.top[key]
		if inLeft == inRight && reflect.DeepEqual(normalise(key, leftValue), normalise(key, rightValue)) {
			continue
		}
		if allowed("." + key) {
			continue
		}
		report("."+key, fmt.Sprintf("%s has %v and %s has %v", left.file, leftValue, right.file, rightValue))
	}

	for _, name := range unionServiceNames(left, right) {
		leftService, inLeft := left.services[name]
		rightService, inRight := right.services[name]
		if inLeft != inRight {
			has, lacks := left.file, right.file
			if inRight {
				has, lacks = right.file, left.file
			}
			if !allowed(name) {
				report(name, fmt.Sprintf("%s declares the service and %s does not", has, lacks))
			}
			continue
		}
		for _, key := range unionKeys(leftService, rightService) {
			leftValue, hasLeft := leftService[key]
			rightValue, hasRight := rightService[key]
			if hasLeft == hasRight && reflect.DeepEqual(normalise(key, leftValue), normalise(key, rightValue)) {
				continue
			}
			if allowed(name + "." + key) {
				continue
			}
			switch {
			case !hasRight:
				report(name+"."+key, fmt.Sprintf("only %s declares it, as %v", left.file, leftValue))
			case !hasLeft:
				report(name+"."+key, fmt.Sprintf("only %s declares it, as %v", right.file, rightValue))
			default:
				report(name+"."+key, difference(normalise(key, leftValue), normalise(key, rightValue)))
			}
		}
	}

	for _, key := range sortedKeysOfStrings(declared) {
		if used[key] {
			continue
		}
		drift = append(drift, fmt.Sprintf("%s declares a difference at %s - %q - and the two files "+
			"do not differ there any more. Take the entry out: an exception nobody checks is a "+
			"permission for the next difference to pass unread",
			variantField, key, declared[key]))
	}
	return drift
}

// The shapes compose accepts for one meaning, brought to one of them, so that a
// difference this test reports is a difference in the deployment and not in how
// it was typed. What is covered:
//
//   - a mapping written as a list of KEY=VALUE, and the other way round:
//     environment, labels, sysctls, annotations. A bare KEY keeps its meaning,
//     which is "whatever the host has".
//   - the short and the long port syntax, reduced to host address, published
//     port, container port and protocol, and compared as a set: the order two
//     ports are published in says nothing.
//   - the short and the long mount syntax, reduced to source, target and the
//     options as a set, with read_only folded into them, and compared as a set
//     ordered by target.
//   - depends_on as a list and as a mapping, with the condition compose defaults
//     to written out.
//   - networks as a list and as a mapping.
//   - ulimits given as one number and as a soft/hard pair.
//   - the lists whose order is not part of their meaning: cap_add, cap_drop,
//     security_opt, profiles, tmpfs, dns, expose, extra_hosts, group_add.
//   - a scalar written as a number, a boolean or the string of either, at every
//     depth: "true" and true, 256 and "256".
//
// What is deliberately not covered: command and healthcheck.test, where a string
// and a list mean different things - a shell and an exec - and a file that
// changed one into the other changed the deployment.
func normalise(key string, value any) any {
	switch key {
	case "environment", "labels", "sysctls", "annotations":
		return keyValues(value)
	case "ports":
		return portSet(value)
	case "volumes":
		return mountSet(value)
	case "depends_on":
		return dependencies(value)
	case "networks":
		return membership(value)
	case "ulimits":
		return limits(value)
	case "cap_add", "cap_drop", "security_opt", "profiles", "tmpfs", "dns",
		"dns_search", "expose", "extra_hosts", "group_add", "device_cgroup_rules":
		return stringSet(value)
	default:
		return scalars(value)
	}
}

// scalars renders every leaf as the text it means, at every depth, so that 256
// and "256" are one value and true and "true" are one value.
func scalars(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			out[key] = scalars(inner)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, inner := range typed {
			out = append(out, scalars(inner))
		}
		return out
	default:
		return scalar(value)
	}
}

func scalar(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case bool:
		return strconv.FormatBool(typed)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64)
	case string:
		// The strings compose treats as the booleans they read as.
		switch strings.ToLower(typed) {
		case "true":
			return "true"
		case "false":
			return "false"
		}
		return typed
	default:
		return fmt.Sprint(typed)
	}
}

// keyValues takes the two ways compose lets a mapping be written to the mapping.
// A list entry with no "=" names a variable to be passed through from the host,
// which is what a mapping key with no value means.
func keyValues(value any) map[string]string {
	out := map[string]string{}
	switch typed := value.(type) {
	case nil:
		return out
	case map[string]any:
		for key, inner := range typed {
			out[key] = scalar(inner)
		}
	case []any:
		for _, entry := range typed {
			text := scalar(entry)
			if name, rest, ok := strings.Cut(text, "="); ok {
				out[name] = rest
			} else {
				out[text] = ""
			}
		}
	}
	return out
}

func stringSet(value any) []string {
	var out []string
	switch typed := value.(type) {
	case nil:
		return nil
	case []any:
		for _, entry := range typed {
			out = append(out, scalar(entry))
		}
	case map[string]any:
		// extra_hosts is accepted in both shapes, and "host: address" means the
		// same as the entry "host:address".
		for key, inner := range typed {
			out = append(out, key+":"+scalar(inner))
		}
	default:
		out = append(out, scalar(typed))
	}
	sort.Strings(out)
	return out
}

var variableReference = regexp.MustCompile(`\$\{[^}]*\}`)

// maskVariables hides ${VAR:-default} from a split on ":", because the default
// of the panel's own published address holds one. The references go back in
// before anything is compared.
func maskVariables(value string) (string, func(string) string) {
	var found []string
	masked := variableReference.ReplaceAllStringFunc(value, func(reference string) string {
		found = append(found, reference)
		return fmt.Sprintf("\x01%d\x01", len(found)-1)
	})
	return masked, func(text string) string {
		for i, reference := range found {
			text = strings.ReplaceAll(text, fmt.Sprintf("\x01%d\x01", i), reference)
		}
		return text
	}
}

// portSet reduces both port syntaxes to "host address|published|target|protocol".
func portSet(value any) []string {
	entries, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		switch typed := entry.(type) {
		case map[string]any:
			protocol := scalar(typed["protocol"])
			if protocol == "" {
				protocol = "tcp"
			}
			out = append(out, strings.Join([]string{
				scalar(typed["host_ip"]), scalar(typed["published"]),
				scalar(typed["target"]), protocol,
			}, "|"))
		default:
			masked, restore := maskVariables(scalar(typed))
			protocol := "tcp"
			if body, named, ok := strings.Cut(masked, "/"); ok {
				masked, protocol = body, named
			}
			field := strings.Split(masked, ":")
			host, published, target := "", "", ""
			switch len(field) {
			case 1:
				target = field[0]
			case 2:
				published, target = field[0], field[1]
			default:
				host = strings.Join(field[:len(field)-2], ":")
				published, target = field[len(field)-2], field[len(field)-1]
			}
			out = append(out, restore(strings.Join([]string{host, published, target, protocol}, "|")))
		}
	}
	sort.Strings(out)
	return out
}

// mountSet reduces both mount syntaxes to "target|source|options", the options
// as a set, so that ":ro,z" and ":z,ro" are one mount and read_only: true in the
// long syntax is the same ":ro".
func mountSet(value any) []string {
	entries, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		var source, target string
		var options []string
		switch typed := entry.(type) {
		case map[string]any:
			source, target = scalar(typed["source"]), scalar(typed["target"])
			if scalar(typed["read_only"]) == "true" {
				options = append(options, "ro")
			}
		default:
			masked, restore := maskVariables(scalar(typed))
			field := strings.Split(masked, ":")
			switch len(field) {
			case 1:
				target = restore(field[0])
			case 2:
				source, target = restore(field[0]), restore(field[1])
			default:
				source, target = restore(field[0]), restore(field[1])
				options = strings.Split(restore(field[2]), ",")
			}
		}
		sort.Strings(options)
		out = append(out, strings.Join([]string{target, source, strings.Join(options, ",")}, "|"))
	}
	sort.Strings(out)
	return out
}

// dependencies takes the list and the mapping shape to the mapping, with the
// condition compose applies when none is named written out.
func dependencies(value any) map[string]string {
	out := map[string]string{}
	switch typed := value.(type) {
	case nil:
		return out
	case []any:
		for _, entry := range typed {
			out[scalar(entry)] = "service_started"
		}
	case map[string]any:
		for name, inner := range typed {
			condition := "service_started"
			if body, ok := inner.(map[string]any); ok {
				if named := scalar(body["condition"]); named != "" {
					condition = named
				}
			}
			out[name] = condition
		}
	}
	return out
}

// membership takes a service's networks, and the deployment's, in either shape
// to a mapping. A member with nothing to say about the network is an empty entry
// either way.
func membership(value any) map[string]any {
	out := map[string]any{}
	switch typed := value.(type) {
	case nil:
		return out
	case []any:
		for _, entry := range typed {
			out[scalar(entry)] = map[string]any{}
		}
	case map[string]any:
		for name, inner := range typed {
			if body, ok := inner.(map[string]any); ok {
				out[name] = scalars(body)
				continue
			}
			out[name] = map[string]any{}
		}
	}
	return out
}

// limits writes one number out as the soft and hard limit it stands for.
func limits(value any) map[string]any {
	out := map[string]any{}
	typed, ok := value.(map[string]any)
	if !ok {
		return out
	}
	for name, inner := range typed {
		if pair, ok := inner.(map[string]any); ok {
			out[name] = scalars(pair)
			continue
		}
		out[name] = map[string]any{"soft": scalar(inner), "hard": scalar(inner)}
	}
	return out
}

func anyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for key, value := range m {
		out[key] = value
	}
	return out
}

func quoteOrAbsent(value string, present bool) string {
	if !present {
		return "not set"
	}
	return strconv.Quote(value)
}

func unionKeys(maps ...map[string]any) []string {
	seen := map[string]bool{}
	var keys []string
	for _, m := range maps {
		for key := range m {
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

func unionServiceNames(files ...composeDeployment) []string {
	seen := map[string]bool{}
	var names []string
	for _, file := range files {
		for name := range file.services {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func sortedKeysOfStrings(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// The comparison is only worth what its own mechanism is worth, and the shipped
// files declare four differences and no missing service - so the cases that
// matter most are the ones the tree does not currently exercise. They are
// exercised here instead, on files written for it.
func TestTheVariantExceptionMechanismHoldsItsEnd(t *testing.T) {
	const base = `name: flotestro
services:
  control-plane:
    image: panel
    restart: always
    read_only: true
    environment:
      FLOTESTRO_DATABASE_URL_FILE: /run/flotestro/database-url
`
	declare := func(key, why string) string {
		return fmt.Sprintf("%s:\n  %s: %s\n", variantField, key, why)
	}
	const goodReason = "the rootless variant reaches its database by address"

	for _, probe := range []struct {
		what    string
		left    string
		right   string
		drifted bool
	}{
		{what: "the same file twice", left: base, right: base, drifted: false},
		{
			what:    "a variable added to one variant only",
			left:    base,
			right:   base + "      FLOTESTRO_HELPER_CAPABILITY_MODE: prefer\n",
			drifted: true,
		},
		{
			what:    "a mount added to one variant only",
			left:    base,
			right:   base + "    volumes:\n      - shared_secrets:/run/flotestro:ro\n",
			drifted: true,
		},
		{
			what:    "a restart policy changed in one variant only",
			left:    base,
			right:   strings.Replace(base, "restart: always", `restart: "no"`, 1),
			drifted: true,
		},
		{
			what:    "read_only turned off in one variant only",
			left:    base,
			right:   strings.Replace(base, "read_only: true", "read_only: false", 1),
			drifted: true,
		},
		{
			what:    "a service in one variant only",
			left:    base,
			right:   base + "  extra:\n    image: extra\n    restart: always\n",
			drifted: true,
		},
		{
			what:    "a service in one variant only, declared with a reason",
			left:    base,
			right:   declare("extra", goodReason) + base + "  extra:\n    image: extra\n    restart: always\n",
			drifted: false,
		},
		{
			what:    "a service in one variant only, declared with a word",
			left:    base,
			right:   declare("extra", "podman") + base + "  extra:\n    image: extra\n    restart: always\n",
			drifted: true,
		},
		{
			what:  "a key declared with a reason",
			left:  base,
			right: declare("control-plane.network_mode", goodReason) + base + "    network_mode: pasta\n",
		},
		{
			what:    "a declaration that no longer matches a difference",
			left:    base,
			right:   declare("control-plane.network_mode", goodReason) + base,
			drifted: true,
		},
		{
			what:    "the two shapes of the same environment",
			left:    base,
			right:   strings.Replace(base, "    environment:\n      FLOTESTRO_DATABASE_URL_FILE: /run/flotestro/database-url\n", "    environment:\n      - FLOTESTRO_DATABASE_URL_FILE=/run/flotestro/database-url\n", 1),
			drifted: false,
		},
	} {
		left := parseCompose(t, "compose.yaml", probe.left)
		right := parseCompose(t, "compose.podman.yaml", probe.right)
		drift := composeDrift(left, right)
		if probe.drifted && len(drift) == 0 {
			t.Errorf("%s: the comparison found nothing, so nothing would have caught it", probe.what)
		}
		if !probe.drifted && len(drift) != 0 {
			t.Errorf("%s: the comparison complained about %v", probe.what, drift)
		}
	}
}

// The two shapes of a published port and of a mount are one deployment, and a
// variant written in the other shape has to compare equal or the exception list
// fills up with differences that are not differences.
func TestTheShapesOfOnePortAndOneMountCompareEqual(t *testing.T) {
	for _, probe := range []struct {
		key         string
		one, other  any
		shouldMatch bool
	}{
		{
			key:         "ports",
			one:         []any{"127.0.0.1:5432:5432"},
			other:       []any{map[string]any{"host_ip": "127.0.0.1", "published": 5432, "target": 5432, "protocol": "tcp"}},
			shouldMatch: true,
		},
		{
			key:         "ports",
			one:         []any{"8443:8443", "8444:8444"},
			other:       []any{"8444:8444", "8443:8443"},
			shouldMatch: true,
		},
		{
			key:         "ports",
			one:         []any{"127.0.0.1:5432:5432"},
			other:       []any{"5432:5432"},
			shouldMatch: false,
		},
		{
			key:         "volumes",
			one:         []any{"shared_secrets:/run/flotestro:ro"},
			other:       []any{map[string]any{"source": "shared_secrets", "target": "/run/flotestro", "read_only": true}},
			shouldMatch: true,
		},
		{
			key:         "volumes",
			one:         []any{"./secrets:/import:ro,z"},
			other:       []any{"./secrets:/import:z,ro"},
			shouldMatch: true,
		},
		{
			key:         "volumes",
			one:         []any{"control_plane_state:/var/lib/flotestro:ro"},
			other:       []any{"control_plane_state:/var/lib/flotestro"},
			shouldMatch: false,
		},
		{
			key:         "depends_on",
			one:         []any{"init"},
			other:       map[string]any{"init": map[string]any{"condition": "service_started"}},
			shouldMatch: true,
		},
		{
			key:         "ports",
			one:         []any{"${FLOTESTRO_API_PUBLISH:-0.0.0.0}:8080:8080"},
			other:       []any{"${FLOTESTRO_API_PUBLISH:-0.0.0.0}:8080:8080"},
			shouldMatch: true,
		},
	} {
		matched := reflect.DeepEqual(normalise(probe.key, probe.one), normalise(probe.key, probe.other))
		if matched != probe.shouldMatch {
			t.Errorf("%s: %v and %v normalise to %v and %v", probe.key, probe.one, probe.other,
				normalise(probe.key, probe.one), normalise(probe.key, probe.other))
		}
	}
}
