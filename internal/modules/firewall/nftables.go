package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// NftPath points at the nftables tool. The path is fixed, not searched in
// PATH: the helper runs only known binaries.
const NftPath = "/usr/sbin/nft"

var (
	tableHeader  = regexp.MustCompile(`^table\s+(\S+)\s+(\S+)\s*\{(?:\s*#\s*handle\s+(\d+))?`)
	chainHeader  = regexp.MustCompile(`^chain\s+(\S+)\s*\{(?:\s*#\s*handle\s+(\d+))?`)
	hookLine     = regexp.MustCompile(`^type\s+(\S+)\s+hook\s+(\S+)\s+priority\s+([^;]+);(?:\s*policy\s+(\S+);)?`)
	ruleHandle   = regexp.MustCompile(`\s*#\s*handle\s+(\d+)\s*$`)
	ruleCounters = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)
	ruleComment  = regexp.MustCompile(`comment "([^"]*)"`)
	// The nft warning ends with a comma and the advice "do not touch", so
	// the owner name stops at the first punctuation character.
	warning = regexp.MustCompile(`^#\s*Warning:\s*table\s+(\S+)\s+(\S+)\s+is managed by ([A-Za-z0-9_.-]+)`)
)

// ParseRuleset reads the output of "nft -a list ruleset".
//
// The text form is read, not JSON, because the rule text is meant to be
// exactly the one the operator knows from the command line. Assembling the
// text from an expression tree ourselves would drift from what the host
// really has - and with a firewall that is the difference between "passes"
// and "rejects".
func ParseRuleset(output string) Snapshot {
	snapshot := Snapshot{Adapter: AdapterNftables}
	owners := map[string]string{}

	var table *Table
	var chain *Chain

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		// nft itself warns that a table belongs to another program.
		if fields := warning.FindStringSubmatch(line); fields != nil {
			owners[fields[1]+" "+fields[2]] = fields[3]
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line == "}" {
			if chain != nil {
				chain = nil
			} else {
				table = nil
			}
			continue
		}

		if fields := tableHeader.FindStringSubmatch(line); fields != nil {
			snapshot.Tables = append(snapshot.Tables, Table{
				Family: fields[1],
				Name:   fields[2],
				Handle: number(fields[3]),
			})
			table = &snapshot.Tables[len(snapshot.Tables)-1]
			continue
		}
		if table == nil {
			continue
		}

		if fields := chainHeader.FindStringSubmatch(line); fields != nil {
			snapshot.Chains = append(snapshot.Chains, Chain{
				Family: table.Family,
				Table:  table.Name,
				Name:   fields[1],
				Handle: number(fields[2]),
			})
			chain = &snapshot.Chains[len(snapshot.Chains)-1]
			continue
		}
		if chain == nil {
			continue
		}

		if fields := hookLine.FindStringSubmatch(line); fields != nil {
			chain.Type = fields[1]
			chain.Hook = fields[2]
			chain.Priority = strings.TrimSpace(fields[3])
			// The policy concerns base chains only; its absence stays an
			// absence, because "accept" written just in case would be false.
			chain.Policy = fields[4]
			continue
		}

		snapshot.Rules = append(snapshot.Rules, ruleFromLine(line, *chain))
	}

	markOrigin(&snapshot, owners)
	snapshot.Hash = Fingerprint(output)
	return snapshot
}

// ruleFromLine assembles a rule from one row of the nft output.
func ruleFromLine(line string, chain Chain) Rule {
	rule := Rule{
		Family: chain.Family,
		Table:  chain.Table,
		Chain:  chain.Name,
		Text:   line,
	}
	if fields := ruleHandle.FindStringSubmatch(line); fields != nil {
		rule.Handle = number(fields[1])
		rule.Text = strings.TrimSpace(ruleHandle.ReplaceAllString(line, ""))
	}
	if fields := ruleCounters.FindStringSubmatch(line); fields != nil {
		packets := unsignedNumber(fields[1])
		bytes := unsignedNumber(fields[2])
		rule.Packets = &packets
		rule.Bytes = &bytes
	}
	if fields := ruleComment.FindStringSubmatch(line); fields != nil {
		rule.Comment = fields[1]
	}
	return rule
}

// markOrigin separates the panel rules from foreign ones.
//
// A table belonging to docker or firewalld is rewritten without the panel's
// participation, so a rule in it is neither ours nor durable - and the
// operator is meant to see that before starting to fix it.
func markOrigin(snapshot *Snapshot, owners map[string]string) {
	origin := func(family, name string) (string, string) {
		if owner, foreign := owners[family+" "+name]; foreign {
			return SourceForeign, owner
		}
		if family == FlotestroFamily && name == FlotestroTable {
			return SourceManaged, ""
		}
		if name == "firewalld" || strings.HasPrefix(name, "docker") {
			return SourceForeign, name
		}
		return SourceManual, ""
	}

	for i := range snapshot.Tables {
		source, owner := origin(snapshot.Tables[i].Family, snapshot.Tables[i].Name)
		snapshot.Tables[i].Source = source
		snapshot.Tables[i].Owner = owner
	}
	for i := range snapshot.Chains {
		source, _ := origin(snapshot.Chains[i].Family, snapshot.Chains[i].Table)
		snapshot.Chains[i].Source = source
	}
	for i := range snapshot.Rules {
		source, _ := origin(snapshot.Rules[i].Family, snapshot.Rules[i].Table)
		snapshot.Rules[i].Source = source
	}
}

// Fingerprint computes the digest of a ruleset.
//
// A change ordered against a different ruleset is not the same change the
// operator viewed: the counters are skipped, because they grow on their own
// and every read would give a different fingerprint of the same ruleset.
func Fingerprint(ruleset string) string {
	withoutCounters := ruleCounters.ReplaceAllString(ruleset, "counter")
	sum := sha256.Sum256([]byte(withoutCounters))
	return hex.EncodeToString(sum[:12])
}

func number(value string) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}

func unsignedNumber(value string) uint64 {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
