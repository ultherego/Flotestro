package network

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// rawInterface maps one entry of "ip -j addr show".
type rawInterface struct {
	Index     int      `json:"ifindex"`
	Name      string   `json:"ifname"`
	Flags     []string `json:"flags"`
	MTU       int      `json:"mtu"`
	OperState string   `json:"operstate"`
	LinkType  string   `json:"link_type"`
	Address   string   `json:"address"`
	LinkInfo  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
		Protocol  string `json:"protocol"`
		Dynamic   bool   `json:"dynamic"`
		ValidLife *int64 `json:"valid_life_time"`
	} `json:"addr_info"`
}

// rawRoute maps one entry of "ip -j route show".
type rawRoute struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	PrefSrc  string `json:"prefsrc"`
	Protocol string `json:"protocol"`
	Scope    string `json:"scope"`
	Metric   int    `json:"metric"`
	Table    string `json:"table"`
}

// infiniteLifetime is the value the kernel reports for an address without
// a lifetime.
const infiniteLifetime = 4294967295

// ParseInterfaces reads the output of "ip -j addr show".
func ParseInterfaces(output string) ([]Interface, error) {
	var raw []rawInterface
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return nil, fmt.Errorf("reading the interfaces: %w", err)
	}
	interfaces := make([]Interface, 0, len(raw))
	for _, entry := range raw {
		iface := Interface{
			Name:      entry.Name,
			Index:     entry.Index,
			Kind:      kind(entry),
			MAC:       entry.Address,
			MTU:       entry.MTU,
			OperState: strings.ToLower(entry.OperState),
		}
		for _, address := range entry.AddrInfo {
			// An address without the prefix does not say which network the
			// host considers local.
			iface.Addresses = append(iface.Addresses, Address{
				Family:  address.Family,
				Address: address.Local + "/" + strconv.Itoa(address.PrefixLen),
				Scope:   address.Scope,
				Source:  address.Protocol,
				// A dynamic address has a finite lifetime. The same address
				// may belong to somebody else tomorrow.
				Permanent: !address.Dynamic &&
					(address.ValidLife == nil || *address.ValidLife == infiniteLifetime),
			})
		}
		interfaces = append(interfaces, iface)
	}
	return interfaces, nil
}

// kind names the interface type. The kernel reports it only for virtual
// ones, so no information means a physical interface or the loopback.
func kind(entry rawInterface) string {
	if entry.LinkInfo.Kind != "" {
		return entry.LinkInfo.Kind
	}
	if entry.Name == "lo" {
		return "loopback"
	}
	if entry.LinkType == "ether" {
		return "ethernet"
	}
	return entry.LinkType
}

// ParseRoutes reads the output of "ip -j route show".
func ParseRoutes(output, family string) ([]Route, error) {
	var raw []rawRoute
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return nil, fmt.Errorf("reading the routes: %w", err)
	}
	routes := make([]Route, 0, len(raw))
	for _, entry := range raw {
		routes = append(routes, Route{
			Destination: entry.Dst,
			Gateway:     entry.Gateway,
			Interface:   entry.Dev,
			Source:      entry.PrefSrc,
			Protocol:    entry.Protocol,
			Scope:       entry.Scope,
			Metric:      entry.Metric,
			Table:       entry.Table,
			Family:      family,
		})
	}
	return routes, nil
}

// SupplementFromSys adds what "ip" does not report: the link speed and the
// driver name. Reading /sys is cheap and does not require starting a
// process.
func SupplementFromSys(dir string, interfaces []Interface) {
	for i := range interfaces {
		path := filepath.Join(dir, interfaces[i].Name)
		if value, ok := numberFromFile(filepath.Join(path, "carrier")); ok {
			carrier := value == 1
			interfaces[i].Carrier = &carrier
		}
		// The kernel reports the speed only for some drivers, and for a
		// link without a carrier returns -1. Unknown stays unknown.
		if value, ok := numberFromFile(filepath.Join(path, "speed")); ok && value > 0 {
			speed := int(value)
			interfaces[i].SpeedMbps = &speed
		}
		if target, err := os.Readlink(filepath.Join(path, "device", "driver")); err == nil {
			interfaces[i].Driver = filepath.Base(target)
		}
	}
}

func numberFromFile(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// MarkManagementChannel points at the interface and the address the host
// talks to the panel through.
//
// The address comes from the agent's actual connection, not from the first
// position of the list: the host usually has several addresses, and only
// one of them is the one the panel sees it through. A mistake in this
// direction ends in changing the configuration of the interface the order
// has just arrived through.
func MarkManagementChannel(snapshot *Snapshot, localAddress string) {
	if localAddress == "" {
		return
	}
	address := localAddress
	if host, _, err := net.SplitHostPort(localAddress); err == nil {
		address = host
	}
	parsed := net.ParseIP(address)
	if parsed == nil {
		return
	}
	for i := range snapshot.Interfaces {
		for _, assigned := range snapshot.Interfaces[i].Addresses {
			own, _, err := net.ParseCIDR(assigned.Address)
			if err != nil || !own.Equal(parsed) {
				continue
			}
			snapshot.Interfaces[i].Management = true
			snapshot.ManagementInterface = snapshot.Interfaces[i].Name
			snapshot.ManagementAddress = assigned.Address
			return
		}
	}
}
