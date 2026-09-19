package network

import (
	"os"
	"path/filepath"
)

// IPv6ConfDir is where the kernel publishes the per-interface settings of the
// second family.
const IPv6ConfDir = "/proc/sys/net/ipv6/conf"

// The sysctls the module reads.
const (
	sysctlDisableIPv6 = "disable_ipv6"
	sysctlAcceptRA    = "accept_ra"
	sysctlUseTempAddr = "use_tempaddr"
)

// Off says the second family is switched off for certain.
func (s IPv6Settings) Off() bool {
	return s.Disabled != nil && *s.Disabled
}

// ReadIPv6Settings reads the second family's settings for one interface. The
// name "all" reads the host-wide values.
func ReadIPv6Settings(dir, iface string) IPv6Settings {
	settings := IPv6Settings{}
	base := filepath.Join(dir, iface)
	if value, ok := numberFromFile(filepath.Join(base, sysctlDisableIPv6)); ok {
		disabled := value != 0
		settings.Disabled = &disabled
	}
	if value, ok := numberFromFile(filepath.Join(base, sysctlAcceptRA)); ok {
		accept := int(value)
		settings.AcceptRA = &accept
	}
	if value, ok := numberFromFile(filepath.Join(base, sysctlUseTempAddr)); ok {
		privacy := int(value)
		settings.Privacy = &privacy
	}
	return settings
}

// CombineIPv6 folds the host-wide settings into the ones of an interface.
func CombineIPv6(all, iface IPv6Settings) IPv6Settings {
	combined := iface
	if all.Off() {
		disabled := true
		combined.Disabled = &disabled
	} else if combined.Disabled == nil && all.Disabled != nil {
		combined.Disabled = all.Disabled
	}
	if combined.AcceptRA == nil {
		combined.AcceptRA = all.AcceptRA
	}
	if combined.Privacy == nil {
		combined.Privacy = all.Privacy
	}
	return combined
}

// HostIPv6Disabled says whether the host has the second family switched off
// for everything, or lacks it entirely.
func HostIPv6Disabled(dir string) *bool {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			off := true
			return &off
		}
		return nil
	}
	return ReadIPv6Settings(dir, "all").Disabled
}

// The values the panel speaks about the second family in.
const (
	AcceptRAOff        = "off"
	AcceptRAOn         = "on"
	AcceptRAForwarding = "on-forwarding"

	PrivacyOff             = "off"
	PrivacyPreferPublic    = "prefer-public"
	PrivacyPreferTemporary = "prefer-temporary"
)

// AcceptRAWord turns the kernel's accept_ra number into the panel's word.
func AcceptRAWord(value int) string {
	switch value {
	case 0:
		return AcceptRAOff
	case 2:
		return AcceptRAForwarding
	default:
		return AcceptRAOn
	}
}

// PrivacyWord turns the kernel's use_tempaddr number into the panel's word.
func PrivacyWord(value int) string {
	switch value {
	case 0:
		return PrivacyOff
	case 2:
		return PrivacyPreferTemporary
	default:
		return PrivacyPreferPublic
	}
}

// ValidAcceptRA and ValidPrivacy check the words an order may carry. An
// empty value is valid and means "leave it as the host has it".
func ValidAcceptRA(value string) bool {
	switch value {
	case "", AcceptRAOff, AcceptRAOn, AcceptRAForwarding:
		return true
	}
	return false
}

func ValidPrivacy(value string) bool {
	switch value {
	case "", PrivacyOff, PrivacyPreferPublic, PrivacyPreferTemporary:
		return true
	}
	return false
}
