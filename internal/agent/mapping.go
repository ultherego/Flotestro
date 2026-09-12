package agent

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The mapping between the model of the agent and the contract of the protocol
// lives in one place, so a change of the contract does not spill over the logic
// of collecting facts.

// capabilitiesToProto sends the registry and - for an older server - the
// boolean fields
// from before the registry. A fleet upgrades gradually, so both sides have to
// understand each other for a while.
func capabilitiesToProto(c Capabilities) *agentv1.Capabilities {
	registry := make([]*agentv1.Capability, 0, len(c))
	for _, cap := range c {
		registry = append(registry, &agentv1.Capability{
			Name:      cap.Name,
			Version:   cap.Version,
			Available: cap.Available,
			ReadOnly:  cap.ReadOnly,
			Reason:    cap.Reason,
			Features:  cap.Features,
		})
	}
	return &agentv1.Capabilities{
		Systemd:  c.Available(CapSystemd),
		Apt:      c.Available(CapAPT),
		Dnf:      c.Available(CapDNF),
		Docker:   c.Available(CapDocker),
		Journald: c.Available(CapJournald),
		Registry: registry,
	}
}

// Values that were not determined are not sent: a missing field in the message
// means "I do not know" and not zero.
func healthToProto(h Health) *agentv1.HealthSignals {
	return &agentv1.HealthSignals{
		FailedUnits:            h.FailedUnits,
		RebootRequired:         h.RebootRequired,
		Load1Milli:             h.Load1Milli,
		RootFsUsedPercent:      h.RootFSUsedPercent,
		UptimeSeconds:          h.UptimeSeconds,
		PendingUpdates:         h.PendingUpdates,
		PendingSecurityUpdates: h.PendingSecurityUpdates,
	}
}

func inventoryToProto(f Facts, revision string, rawJSON []byte) *agentv1.InventoryReport {
	// An error while splitting into modules must not take the whole report away
	// from the server: the full content is in raw_json and is sent either way.
	fragments, _ := f.Fragments()
	return &agentv1.InventoryReport{
		Revision:      revision,
		Full:          true,
		SchemaVersion: SchemaVersion,
		Os: &agentv1.OsInfo{
			Family:       f.OS.Family,
			Distribution: f.OS.Distribution,
			Version:      f.OS.Version,
			Kernel:       f.OS.Kernel,
			Architecture: f.OS.Architecture,
			PrettyName:   f.OS.PrettyName,
		},
		Hardware: &agentv1.HardwareInfo{
			CpuCores:        f.Hardware.CPUCores,
			MemoryBytes:     f.Hardware.MemoryBytes,
			RootFsBytes:     f.Hardware.RootFSBytes,
			RootFsFreeBytes: f.Hardware.RootFSFreeByte,
			Virtualization:  f.Hardware.Virtualization,
		},
		Packages: &agentv1.PackageSummary{
			Installed:          f.Packages.Installed,
			Upgradable:         f.Packages.Upgradable,
			SecurityUpgradable: f.Packages.SecurityUpgradable,
			Manager:            f.Packages.Manager,
			UnavailableReason:  f.Packages.UnavailableReason,
		},
		Identity:      identityToProto(f.Identity),
		LocalAccounts: localAccountsToProto(f.LocalAccounts),
		RawJson:       rawJSON,
		Fragments:     fragmentsToProto(fragments),
	}
}

func identityToProto(state IdentityState) *agentv1.IdentityState {
	return &agentv1.IdentityState{
		Enrolled:          state.Enrolled,
		Domain:            state.Domain,
		Realm:             state.Realm,
		Servers:           state.Servers,
		SssdInstalled:     state.SSSDInstalled,
		SssdRunning:       state.SSSDRunning,
		SssdOnline:        state.SSSDOnline,
		CacheAgeSeconds:   state.CacheAgeSeconds,
		HostPrincipal:     state.HostPrincipal,
		KeytabKvno:        state.KeytabKVNO,
		ClockSkewSeconds:  state.ClockSkewSeconds,
		TimeSynchronized:  state.TimeSynchronized,
		ConfigIssues:      state.ConfigIssues,
		UnavailableReason: state.UnavailableReason,
	}
}

func timestampNow() *timestamppb.Timestamp {
	return timestamppb.New(time.Now().UTC())
}

func fragmentsToProto(fragments []Fragment) []*agentv1.InventoryFragment {
	result := make([]*agentv1.InventoryFragment, 0, len(fragments))
	for _, fragment := range fragments {
		result = append(result, &agentv1.InventoryFragment{
			Module:            fragment.Module,
			Revision:          fragment.Revision,
			Source:            fragment.Source,
			Payload:           fragment.Payload,
			UnavailableReason: fragment.UnavailableReason,
			ObservedAt:        timestamppb.New(fragment.ObservedAt),
		})
	}
	return result
}
