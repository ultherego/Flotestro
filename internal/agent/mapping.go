package agent

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// Mapowanie miedzy modelem agenta a kontraktem protokolu jest w jednym miejscu,
// dzieki czemu zmiana kontraktu nie rozlewa sie po logice zbierania faktow.

// capabilitiesToProto wysyla rejestr i - dla starszego serwera - pola logiczne
// sprzed rejestru. Flota aktualizuje sie stopniowo, wiec obie strony przez
// jakis czas musza sie rozumiec.
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
	// Blad rozbicia na moduly nie moze zabrac serwerowi calego raportu:
	// pelna tresc jest w raw_json i zostaje wyslana tak czy inaczej.
	fragmenty, _ := f.Fragments()
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
		Fragments:     fragmentsToProto(fragmenty),
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

func fragmentsToProto(fragmenty []Fragment) []*agentv1.InventoryFragment {
	wynik := make([]*agentv1.InventoryFragment, 0, len(fragmenty))
	for _, fragment := range fragmenty {
		wynik = append(wynik, &agentv1.InventoryFragment{
			Module:            fragment.Module,
			Revision:          fragment.Revision,
			Source:            fragment.Source,
			Payload:           fragment.Payload,
			UnavailableReason: fragment.UnavailableReason,
			ObservedAt:        timestamppb.New(fragment.ObservedAt),
		})
	}
	return wynik
}
