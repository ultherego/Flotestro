package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Where the tools that report the layering live. The paths are fixed and
// not looked up in PATH: the agent and the helper run only known binaries.
var (
	// IPPaths lists the places iproute2 puts the "ip" tool.
	IPPaths = []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"}
	// BridgePaths lists the places it puts the "bridge" tool, which is the
	// only one that says which VLAN a bridge port carries.
	BridgePaths = []string{"/usr/sbin/bridge", "/sbin/bridge", "/usr/bin/bridge"}
)

// ProcBondingDir is where the bonding driver publishes what "ip" does not:
// which member carries the traffic now and what the driver thinks of each of
// them.
const ProcBondingDir = "/proc/net/bonding"

// ToolPath returns the first of the given paths present on the host, or an
// empty string.
func ToolPath(paths []string, exists func(string) bool) string {
	for _, path := range paths {
		if exists(path) {
			return path
		}
	}
	return ""
}

// LinkArguments reads the links with everything the kernel knows about them.
func LinkArguments(binary string) []string {
	return []string{binary, "-details", "-json", "link", "show"}
}

// BridgeVLANArguments reads the VLANs of every bridge port.
func BridgeVLANArguments(binary string) []string {
	return []string{binary, "-json", "vlan", "show"}
}

// rawLink maps one entry of "ip -details -json link".
type rawLink struct {
	Index int    `json:"ifindex"`
	Name  string `json:"ifname"`
	// Link is the lower interface of a VLAN: the one the tagged traffic
	// runs on. The kernel calls it "link" here and "base-iface" elsewhere.
	Link string `json:"link"`
	// Master is the layer that owns this interface.
	Master   string `json:"master"`
	MTU      int    `json:"mtu"`
	LinkInfo struct {
		Kind     string          `json:"info_kind"`
		Data     json.RawMessage `json:"info_data"`
		PortKind string          `json:"info_slave_kind"`
	} `json:"linkinfo"`
}

// rawBond maps the info_data of a bond.
type rawBond struct {
	Mode           string `json:"mode"`
	MIIMon         int    `json:"miimon"`
	Primary        string `json:"primary"`
	LACPRate       string `json:"ad_lacp_rate"`
	XmitHashPolicy string `json:"xmit_hash_policy"`
}

// rawBridge maps the info_data of a bridge.
type rawBridge struct {
	STPState      int    `json:"stp_state"`
	VLANFiltering int    `json:"vlan_filtering"`
	VLANProtocol  string `json:"vlan_protocol"`
}

// rawVLAN maps the info_data of a VLAN interface.
type rawVLAN struct {
	ID       int    `json:"id"`
	Protocol string `json:"protocol"`
}

// ParseLinks reads the output of "ip -details -json link" into the layering of
// each interface.
func ParseLinks(output string) ([]Interface, error) {
	var raw []rawLink
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return nil, fmt.Errorf("reading the link layering: %w", err)
	}
	links := make([]Interface, 0, len(raw))
	for _, entry := range raw {
		link := Interface{Name: entry.Name, Index: entry.Index, MTU: entry.MTU, Master: entry.Master}
		switch entry.LinkInfo.Kind {
		case LinkBond:
			bond := rawBond{}
			_ = json.Unmarshal(entry.LinkInfo.Data, &bond)
			link.Bond = &BondDetails{
				Mode: bond.Mode, MIIMonMS: bond.MIIMon, Primary: bond.Primary,
				LACPRate: bond.LACPRate, XmitHashPolicy: bond.XmitHashPolicy,
			}
		case "bridge":
			bridge := rawBridge{}
			_ = json.Unmarshal(entry.LinkInfo.Data, &bridge)
			link.Bridge = &BridgeDetails{
				STP: bridge.STPState != 0, VLANFiltering: bridge.VLANFiltering != 0,
				VLANProtocol: bridge.VLANProtocol,
			}
		case LinkVLAN:
			vlan := rawVLAN{}
			_ = json.Unmarshal(entry.LinkInfo.Data, &vlan)
			link.VLAN = &VLANDetails{Parent: entry.Link, ID: vlan.ID, Protocol: vlan.Protocol}
		}
		links = append(links, link)
	}
	return links, nil
}

// MergeLayering puts the layering onto the interfaces read from the addresses,
// and fills in the members of every bond and bridge from the interfaces that
// name it as their master.
func MergeLayering(interfaces []Interface, links []Interface) {
	byName := map[string]*Interface{}
	for i := range interfaces {
		byName[interfaces[i].Name] = &interfaces[i]
	}
	for _, link := range links {
		target, ok := byName[link.Name]
		if !ok {
			continue
		}
		target.Master = link.Master
		target.Bond = link.Bond
		target.Bridge = link.Bridge
		target.VLAN = link.VLAN
	}
	for i := range interfaces {
		master := interfaces[i].Master
		if master == "" {
			continue
		}
		owner, ok := byName[master]
		if !ok {
			continue
		}
		switch {
		case owner.Bond != nil:
			owner.Bond.Members = append(owner.Bond.Members, interfaces[i].Name)
		case owner.Bridge != nil:
			owner.Bridge.Members = append(owner.Bridge.Members, interfaces[i].Name)
		}
	}
}

// ParseBondStatus reads one file of /proc/net/bonding.
func ParseBondStatus(content string) BondDetails {
	details := BondDetails{MemberStates: map[string]string{}}
	member := ""
	for _, line := range strings.Split(content, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "Bonding Mode":
			details.Mode = bondModeWord(value)
		case "Transmit Hash Policy":
			// The driver writes it as "layer2 (0)"; the word is the part
			// before the number it repeats.
			details.XmitHashPolicy = strings.TrimSpace(strings.Split(value, " ")[0])
		case "MII Polling Interval (ms)":
			if number, err := strconv.Atoi(value); err == nil {
				details.MIIMonMS = number
			}
		case "LACP rate":
			details.LACPRate = value
		case "Primary Slave", "Primary Port":
			// The driver appends "(primary_reselect ...)" to the name.
			details.Primary = strings.TrimSpace(strings.Split(value, " ")[0])
		case "Currently Active Slave", "Currently Active Port":
			details.ActiveMember = value
		case "Slave Interface", "Port Interface":
			member = value
			details.Members = append(details.Members, member)
		case "MII Status":
			// The first MII Status in the file belongs to the bond; the ones
			// after a member's name belong to that member.
			if member != "" {
				details.MemberStates[member] = value
			}
		}
	}
	if len(details.MemberStates) == 0 {
		details.MemberStates = nil
	}
	return details
}

// bondModeWord turns the driver's sentence into the mode name the kernel takes
// when the bond is created.
func bondModeWord(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "802.3ad"):
		return "802.3ad"
	case strings.Contains(lower, "fault-tolerance") && strings.Contains(lower, "active-backup"):
		return "active-backup"
	case strings.Contains(lower, "active-backup"):
		return "active-backup"
	case strings.Contains(lower, "round-robin"):
		return "balance-rr"
	case strings.Contains(lower, "xor"):
		return "balance-xor"
	case strings.Contains(lower, "broadcast"):
		return "broadcast"
	case strings.Contains(lower, "adaptive load balancing"):
		return "balance-alb"
	case strings.Contains(lower, "transmit load balancing"):
		return "balance-tlb"
	}
	return value
}

// SupplementBonds fills in from /proc/net/bonding what the kernel does not
// report through "ip": the active member and the state of each member.
func SupplementBonds(dir string, interfaces []Interface) {
	for i := range interfaces {
		if interfaces[i].Bond == nil {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, interfaces[i].Name))
		if err != nil {
			continue
		}
		status := ParseBondStatus(string(content))
		bond := interfaces[i].Bond
		bond.ActiveMember = status.ActiveMember
		bond.MemberStates = status.MemberStates
		if bond.Mode == "" {
			bond.Mode = status.Mode
		}
		if bond.Primary == "" {
			bond.Primary = status.Primary
		}
		if bond.LACPRate == "" {
			bond.LACPRate = status.LACPRate
		}
		if bond.XmitHashPolicy == "" {
			bond.XmitHashPolicy = status.XmitHashPolicy
		}
		if len(bond.Members) == 0 {
			bond.Members = status.Members
		}
	}
}

// rawBridgeVLAN maps one entry of "bridge -json vlan show".
type rawBridgeVLAN struct {
	Name  string `json:"ifname"`
	VLANs []struct {
		VLAN    int      `json:"vlan"`
		VLANEnd int      `json:"vlanEnd"`
		Flags   []string `json:"flags"`
	} `json:"vlans"`
}

// ParseBridgeVLANs reads the output of "bridge -json vlan show" into the VLANs
// of each port.
func ParseBridgeVLANs(output string) ([]BridgePortVLAN, error) {
	var raw []rawBridgeVLAN
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return nil, fmt.Errorf("reading the bridge VLANs: %w", err)
	}
	var vlans []BridgePortVLAN
	for _, port := range raw {
		for _, entry := range port.VLANs {
			last := entry.VLANEnd
			if last < entry.VLAN {
				last = entry.VLAN
			}
			if last > 4094 {
				last = 4094
			}
			for vid := entry.VLAN; vid <= last; vid++ {
				vlans = append(vlans, BridgePortVLAN{
					Port: port.Name, VID: vid,
					PVID:     hasFlag(entry.Flags, "PVID"),
					Untagged: hasFlag(entry.Flags, "Egress Untagged"),
				})
			}
		}
	}
	return vlans, nil
}

func hasFlag(flags []string, wanted string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, wanted) {
			return true
		}
	}
	return false
}

// AttachBridgeVLANs puts the VLANs of each port onto the bridge that owns the
// port.
func AttachBridgeVLANs(interfaces []Interface, vlans []BridgePortVLAN) {
	owner := map[string]string{}
	for i := range interfaces {
		if interfaces[i].Bridge != nil {
			owner[interfaces[i].Name] = interfaces[i].Name
		}
		if interfaces[i].Master != "" {
			owner[interfaces[i].Name] = interfaces[i].Master
		}
	}
	byName := map[string]*Interface{}
	for i := range interfaces {
		byName[interfaces[i].Name] = &interfaces[i]
	}
	for _, vlan := range vlans {
		bridge, ok := byName[owner[vlan.Port]]
		if !ok || bridge.Bridge == nil {
			continue
		}
		bridge.Bridge.VLANs = append(bridge.Bridge.VLANs, vlan)
	}
}

// ToolRunner runs one of the host's tools and returns its output.
type ToolRunner func(arguments []string) (string, error)

// ReadLayering fills in the layering of a snapshot whose interfaces have
// already been read: which interface is a bond, a bridge or a VLAN, what it is
// made of, and which VLAN every bridge port carries.
func ReadLayering(snapshot *Snapshot, run ToolRunner) {
	binary := ToolPath(IPPaths, Exists)
	if binary == "" {
		snapshot.LayeringUnavailableReason = "this host has no iproute2 (ip) binary"
		return
	}
	output, err := run(LinkArguments(binary))
	if err != nil {
		snapshot.LayeringUnavailableReason = "ip -details link: " + err.Error()
		return
	}
	links, err := ParseLinks(output)
	if err != nil {
		snapshot.LayeringUnavailableReason = err.Error()
		return
	}
	MergeLayering(snapshot.Interfaces, links)
	SupplementBonds(ProcBondingDir, snapshot.Interfaces)

	// The VLANs of the bridge ports come from a second tool, and its absence is
	// not the absence of the layering: the bridges are already read, only what
	// each port carries stays unknown.
	bridgeBinary := ToolPath(BridgePaths, Exists)
	if bridgeBinary == "" {
		return
	}
	output, err = run(BridgeVLANArguments(bridgeBinary))
	if err != nil {
		return
	}
	if vlans, err := ParseBridgeVLANs(output); err == nil {
		AttachBridgeVLANs(snapshot.Interfaces, vlans)
	}
}

// ReadIPv6 fills in what the kernel says about the second family: whether the
// host has it at all, and what each interface does with it.
func ReadIPv6(snapshot *Snapshot) {
	snapshot.IPv6Disabled = HostIPv6Disabled(IPv6ConfDir)
	all := ReadIPv6Settings(IPv6ConfDir, "all")
	for i := range snapshot.Interfaces {
		settings := CombineIPv6(all, ReadIPv6Settings(IPv6ConfDir, snapshot.Interfaces[i].Name))
		if settings.Disabled == nil && settings.AcceptRA == nil && settings.Privacy == nil {
			continue
		}
		snapshot.Interfaces[i].IPv6 = &settings
	}
}
