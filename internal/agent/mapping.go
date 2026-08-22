package agent

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// Mapowanie miedzy modelem agenta a kontraktem protokolu jest w jednym miejscu,
// dzieki czemu zmiana kontraktu nie rozlewa sie po logice zbierania faktow.

func capabilitiesToProto(c Capabilities) *agentv1.Capabilities {
	return &agentv1.Capabilities{
		Systemd:  c.Systemd,
		Apt:      c.APT,
		Dnf:      c.DNF,
		Docker:   c.Docker,
		Journald: c.Journald,
	}
}

// Wartosci nieustalone nie sa wysylane: brak pola w wiadomosci oznacza
// "nie wiem", a nie zero.
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
