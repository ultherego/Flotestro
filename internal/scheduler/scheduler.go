// Package scheduler pobiera zatwierdzone zadania z kolejki i dostarcza je
// agentom. Nie podejmuje decyzji biznesowych poza limitami wykonania.
package scheduler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/gateway"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// EnrollmentCredentials wystawia jednorazowe poswiadczenie dolaczenia hosta
// do domeny. Poswiadczenie powstaje w chwili wysylki i nie jest przechowywane
// w bazie razem z zadaniem.
type EnrollmentCredentials interface {
	EnsureHostWithOTP(ctx context.Context, fqdn string) (string, error)
}

// Options konfiguruje petle schedulera.
type Options struct {
	GatewayID string
	// Interval jest podstawowym odstepem miedzy przebiegami. Okresowy skan
	// gwarantuje postep nawet wtedy, gdy powiadomienie zaginie.
	Interval time.Duration
	// LeaseDuration musi byc dluzszy niz najdluzsza operacja, inaczej lease
	// wygasnie w trakcie poprawnego wykonania.
	LeaseDuration time.Duration
	// BatchSize ogranicza liczbe zadan pobieranych w jednym przebiegu.
	BatchSize int
	// SendTimeout ogranicza czekanie na przyjecie zadania przez sesje.
	SendTimeout time.Duration
}

// Scheduler laczy kolejke zadan z aktywnymi sesjami agentow.
type Scheduler struct {
	store       *jobs.Store
	registry    *gateway.Registry
	audit       *audit.Recorder
	credentials EnrollmentCredentials
	log         *slog.Logger
	options     Options
}

func New(store *jobs.Store, registry *gateway.Registry, recorder *audit.Recorder,
	credentials EnrollmentCredentials, log *slog.Logger, options Options) *Scheduler {
	if options.Interval <= 0 {
		options.Interval = 2 * time.Second
	}
	if options.LeaseDuration <= 0 {
		options.LeaseDuration = 5 * time.Minute
	}
	if options.BatchSize <= 0 {
		options.BatchSize = 32
	}
	if options.SendTimeout <= 0 {
		options.SendTimeout = 5 * time.Second
	}
	return &Scheduler{store: store, registry: registry, audit: recorder,
		credentials: credentials, log: log, options: options}
}

// Run utrzymuje petle dostarczania do zamkniecia kontekstu.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.options.Interval)
	defer ticker.Stop()

	housekeeping := time.NewTicker(30 * time.Second)
	defer housekeeping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-housekeeping.C:
			s.housekeep(ctx)
		case <-ticker.C:
			s.dispatchOnce(ctx)
		}
	}
}

// housekeep zwraca do kolejki zadania po wygaslym lease i konczy zadania
// po TTL. Bez tego zadanie utracone razem z gatewayem zostaloby na zawsze.
func (s *Scheduler) housekeep(ctx context.Context) {
	if count, err := s.store.ReclaimExpiredLeases(ctx); err != nil {
		s.log.Error("nie odzyskano wygaslych lease", "err", err)
	} else if count > 0 {
		s.log.Warn("zadania wrocily do kolejki po wygasnieciu lease", "liczba", count)
	}
	if count, err := s.store.ExpireOverdue(ctx); err != nil {
		s.log.Error("nie oznaczono zadan po TTL", "err", err)
	} else if count > 0 {
		s.log.Info("zadania wygasly przed uruchomieniem", "liczba", count)
	}
}

func (s *Scheduler) dispatchOnce(ctx context.Context) {
	hosts := s.registry.ConnectedHosts()
	if len(hosts) == 0 {
		return
	}

	leased, err := s.store.Lease(ctx, s.options.GatewayID, hosts, s.options.BatchSize, s.options.LeaseDuration)
	if err != nil {
		s.log.Error("nie pobrano zadan z kolejki", "err", err)
		return
	}
	for _, item := range leased {
		s.deliver(ctx, item)
	}
}

func (s *Scheduler) deliver(ctx context.Context, item jobs.LeasedJob) {
	envelope, err := s.buildEnvelopeFor(ctx, item)
	if err != nil {
		s.log.Error("nie zbudowano koperty zadania", "job_id", item.Job.ID, "err", err)
		_ = s.store.ReleaseLease(ctx, item.Job.ID, item.AttemptID, "invalid_envelope")
		return
	}

	sessionID, err := s.registry.Dispatch(item.Job.HostID,
		&agentv1.ServerMessage{Payload: &agentv1.ServerMessage_Task{Task: envelope}},
		s.options.SendTimeout)
	if err != nil {
		// Host rozlaczyl sie miedzy pobraniem a wysylka. Zadanie wraca do
		// kolejki i zostanie dostarczone przy nastepnym polaczeniu.
		s.log.Info("nie dostarczono zadania, powrot do kolejki",
			"job_id", item.Job.ID, "host_id", item.Job.HostID, "powod", err)
		if releaseErr := s.store.ReleaseLease(ctx, item.Job.ID, item.AttemptID, err.Error()); releaseErr != nil {
			s.log.Error("nie zwrocono zadania do kolejki", "job_id", item.Job.ID, "err", releaseErr)
		}
		return
	}

	if err := s.store.MarkDispatched(ctx, item.Job.ID, item.AttemptID, sessionID); err != nil {
		s.log.Error("nie odnotowano dostarczenia", "job_id", item.Job.ID, "err", err)
		return
	}

	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: s.options.GatewayID,
		Action: "job.dispatch", TargetType: "job", TargetID: item.Job.ID,
		RequestID: item.Job.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": item.Job.HostID, "attempt": item.Attempt,
			"action_type": item.Job.ActionType, "session_id": sessionID,
		},
	})
	s.log.Info("zadanie dostarczone",
		"job_id", item.Job.ID, "host_id", item.Job.HostID,
		"action", item.Job.ActionType, "attempt", item.Attempt)
}

// buildEnvelopeFor buduje koperte i uzupelnia ja o poswiadczenia, ktore
// celowo nie sa przechowywane w bazie.
func (s *Scheduler) buildEnvelopeFor(ctx context.Context, item jobs.LeasedJob) (*agentv1.TaskEnvelope, error) {
	envelope, err := buildEnvelope(item)
	if err != nil {
		return nil, err
	}

	enroll, ok := envelope.GetAction().(*agentv1.TaskEnvelope_DomainEnroll)
	if !ok || enroll.DomainEnroll.GetPreflightOnly() {
		return envelope, nil
	}
	if s.credentials == nil {
		return nil, errUnknownAction("brak zrodla poswiadczen dolaczenia do domeny")
	}

	hostname := enroll.DomainEnroll.GetHostname()
	if hostname == "" {
		return nil, errUnknownAction("dolaczenie wymaga nazwy FQDN hosta")
	}
	// Haslo powstaje teraz i jest wazne do pierwszego uzycia; nie trafia
	// do bazy ani do audytu.
	password, err := s.credentials.EnsureHostWithOTP(ctx, hostname)
	if err != nil {
		return nil, err
	}
	enroll.DomainEnroll.OneTimePassword = password
	return envelope, nil
}

// buildEnvelope zamienia zadanie z bazy na koperte protokolu agenta.
// task_id wskazuje konkretna probe, a idempotency_key cala operacje - dzieki
// temu ponowne dostarczenie tej samej operacji zwraca poprzedni wynik.
func buildEnvelope(item jobs.LeasedJob) (*agentv1.TaskEnvelope, error) {
	var payload opspec.Payload
	if err := json.Unmarshal(item.Job.Payload, &payload); err != nil {
		return nil, err
	}
	var preconditions jobs.Preconditions
	if len(item.Job.Preconditions) > 0 {
		if err := json.Unmarshal(item.Job.Preconditions, &preconditions); err != nil {
			return nil, err
		}
	}
	hash, err := opspec.PayloadHash(opspec.ActionType(item.Job.ActionType),
		item.Job.ActionVersion, payload)
	if err != nil {
		return nil, err
	}

	envelope := &agentv1.TaskEnvelope{
		TaskId:         item.AttemptID,
		IdempotencyKey: item.Job.IdempotencyKey,
		CreatedAt:      timestamppb.New(item.Job.CreatedAt),
		ExpiresAt:      timestamppb.New(item.Job.ExpiresAt),
		PayloadHash:    hash,
		Preconditions: &agentv1.Preconditions{
			OsFamily:             preconditions.OSFamily,
			RequiredCapabilities: preconditions.RequiredCapabilities,
			ExpectedBootId:       preconditions.ExpectedBootID,
		},
		Limits: &agentv1.Limits{
			TimeoutSeconds: uint32(item.Job.TimeoutSeconds),
			MaxOutputBytes: uint32(item.Job.MaxOutputBytes),
		},
		ActorContext: &agentv1.ActorContext{
			ActorId:   item.Job.CreatedBy,
			RequestId: item.Job.RequestID,
			Approvals: approvalsOf(item.Job),
		},
	}
	if item.Job.CampaignID != nil {
		envelope.CampaignId = *item.Job.CampaignID
	}

	action := opspec.ActionType(item.Job.ActionType)
	switch action {
	case opspec.ActionPackagePlan:
		envelope.Action = &agentv1.TaskEnvelope_PackagePlan{
			PackagePlan: &agentv1.PackagePlan{
				Mode:            payload.PackagePlan.Mode,
				RefreshMetadata: payload.PackagePlan.RefreshMetadata,
				OnlyPackages:    payload.PackagePlan.OnlyPackages,
				SecurityOnly:    payload.PackagePlan.SecurityOnly,
			},
		}

	case opspec.ActionPackageUpgrade:
		request := &agentv1.PackageUpgrade{
			Packages:     payload.PackageUpgrade.Packages,
			SecurityOnly: payload.PackageUpgrade.SecurityOnly,
		}
		if payload.PackageUpgrade.PlanHash != "" {
			hash, err := hex.DecodeString(payload.PackageUpgrade.PlanHash)
			if err != nil {
				return nil, fmt.Errorf("nieprawidlowy hash planu: %w", err)
			}
			request.PlanHash = hash
		}
		envelope.Action = &agentv1.TaskEnvelope_PackageUpgrade{PackageUpgrade: request}

	case opspec.ActionDomainEnroll, opspec.ActionDomainPreflight:
		envelope.Action = &agentv1.TaskEnvelope_DomainEnroll{
			DomainEnroll: &agentv1.DomainEnroll{
				Domain:        payload.DomainEnroll.Domain,
				Realm:         payload.DomainEnroll.Realm,
				Server:        payload.DomainEnroll.Server,
				Hostname:      payload.DomainEnroll.Hostname,
				PreflightOnly: action == opspec.ActionDomainPreflight,
			},
		}

	case opspec.ActionLocalUserCreate, opspec.ActionLocalUserLock,
		opspec.ActionLocalUserUnlock, opspec.ActionLocalSSHKeysSet:
		envelope.Action = &agentv1.TaskEnvelope_LocalUserAction{
			LocalUserAction: &agentv1.LocalUserAction{
				Operation:  localUserOperations[action],
				Name:       payload.LocalUser.Name,
				Gecos:      payload.LocalUser.Gecos,
				Shell:      payload.LocalUser.Shell,
				Groups:     payload.LocalUser.Groups,
				SshKeys:    payload.LocalUser.SSHKeys,
				CreateHome: payload.LocalUser.CreateHome,
			},
		}

	case opspec.ActionPackageRepair:
		odpowiedzi := make([]*agentv1.DebconfAnswer, 0, len(payload.PackageRepair.Answers))
		for _, answer := range payload.PackageRepair.Answers {
			odpowiedzi = append(odpowiedzi, &agentv1.DebconfAnswer{
				Package:  answer.Package,
				Question: answer.Question,
				Type:     answer.Type,
				Value:    answer.Value,
			})
		}
		envelope.Action = &agentv1.TaskEnvelope_PackagesRepair{
			PackagesRepair: &agentv1.PackagesRepair{Answers: odpowiedzi},
		}

	case opspec.ActionDockerRead:
		envelope.Action = &agentv1.TaskEnvelope_DockerRead{DockerRead: &agentv1.DockerRead{}}

	case opspec.ActionPackageInstall, opspec.ActionPackageRemove, opspec.ActionPackageHoldSet:
		operacja := agentv1.PackageLifecycle_OPERATION_INSTALL
		switch action {
		case opspec.ActionPackageRemove:
			operacja = agentv1.PackageLifecycle_OPERATION_REMOVE
		case opspec.ActionPackageHoldSet:
			operacja = agentv1.PackageLifecycle_OPERATION_HOLD
		}
		envelope.Action = &agentv1.TaskEnvelope_PackageLifecycle{
			PackageLifecycle: &agentv1.PackageLifecycle{
				Operation:        operacja,
				Packages:         payload.PackageChange.Packages,
				ExpectedRemovals: payload.PackageChange.ExpectedRemovals,
				Hold:             payload.PackageChange.Hold,
			},
		}

	case opspec.ActionFilePlan, opspec.ActionFileRead, opspec.ActionFileEnsure,
		opspec.ActionFileRemove, opspec.ActionFileRollback:
		operacja := agentv1.FileAction_OPERATION_LIST
		switch action {
		case opspec.ActionFileRead:
			operacja = agentv1.FileAction_OPERATION_READ
		case opspec.ActionFileEnsure:
			operacja = agentv1.FileAction_OPERATION_ENSURE
		case opspec.ActionFileRollback:
			operacja = agentv1.FileAction_OPERATION_ROLLBACK
		case opspec.ActionFileRemove:
			operacja = agentv1.FileAction_OPERATION_REMOVE
		}
		plik := &agentv1.FileAction{Operation: operacja}
		if payload.File != nil {
			plik.Path = payload.File.Path
			plik.Content = []byte(payload.File.Content)
			plik.Mode = payload.File.Mode
			plik.Owner = payload.File.Owner
			plik.Group = payload.File.Group
			plik.ExpectedSha256 = payload.File.ExpectedSHA256
			plik.Validator = payload.File.Validator
		}
		envelope.Action = &agentv1.TaskEnvelope_File{File: plik}

	case opspec.ActionSystemShutdown:
		wylaczenie := &agentv1.SystemShutdown{}
		if payload.Power != nil {
			wylaczenie.DelaySeconds = payload.Power.DelaySeconds
			wylaczenie.Reason = payload.Power.Reason
			wylaczenie.Mode = payload.Power.Mode
			wylaczenie.IgnoreInhibitors = payload.Power.IgnoreInhibitors
		}
		envelope.Action = &agentv1.TaskEnvelope_SystemShutdown{SystemShutdown: wylaczenie}

	case opspec.ActionTimeSyncTest, opspec.ActionTimeConfigApply, opspec.ActionTimezoneSet:
		operacja := agentv1.TimeAction_OPERATION_SYNC_TEST
		switch action {
		case opspec.ActionTimeConfigApply:
			operacja = agentv1.TimeAction_OPERATION_CONFIG_APPLY
		case opspec.ActionTimezoneSet:
			operacja = agentv1.TimeAction_OPERATION_TIMEZONE_SET
		}
		zegar := &agentv1.TimeAction{Operation: operacja}
		if payload.Time != nil {
			zegar.Servers = payload.Time.Servers
			zegar.Probe = payload.Time.Probe
			zegar.Timezone = payload.Time.Timezone
			zegar.AllowStep = payload.Time.AllowStep
			zegar.EnableDropin = payload.Time.EnableDropIn
		}
		envelope.Action = &agentv1.TaskEnvelope_Time{Time: zegar}

	case opspec.ActionSysctlPlan, opspec.ActionSysctlEnsure,
		opspec.ActionKernelModuleLoad, opspec.ActionKernelModuleBlacklist:
		operacja := agentv1.KernelAction_OPERATION_READ
		switch action {
		case opspec.ActionSysctlEnsure:
			operacja = agentv1.KernelAction_OPERATION_SYSCTL_ENSURE
		case opspec.ActionKernelModuleLoad:
			operacja = agentv1.KernelAction_OPERATION_MODULE_LOAD
		case opspec.ActionKernelModuleBlacklist:
			operacja = agentv1.KernelAction_OPERATION_MODULE_BLACKLIST
		}
		jadro := &agentv1.KernelAction{Operation: operacja}
		if payload.Kernel != nil {
			jadro.Settings = payload.Kernel.Settings
			jadro.Keys = payload.Kernel.Keys
			jadro.Module = payload.Kernel.Module
			jadro.Blacklist = payload.Kernel.Blacklist
		}
		envelope.Action = &agentv1.TaskEnvelope_Kernel{Kernel: jadro}

	case opspec.ActionSSHConfigPlan, opspec.ActionSSHConfigApply,
		opspec.ActionSSHHostKeyRotate:
		operacja := agentv1.SshAction_OPERATION_READ
		switch action {
		case opspec.ActionSSHConfigApply:
			operacja = agentv1.SshAction_OPERATION_APPLY
		case opspec.ActionSSHHostKeyRotate:
			operacja = agentv1.SshAction_OPERATION_ROTATE_HOSTKEY
		}
		serwer := &agentv1.SshAction{Operation: operacja}
		if payload.SSH != nil {
			serwer.Port = payload.SSH.Port
			serwer.PermitRootLogin = payload.SSH.PermitRootLogin
			serwer.PasswordAuthentication = payload.SSH.PasswordAuthentication
			serwer.PubkeyAuthentication = payload.SSH.PubkeyAuthentication
			serwer.KbdInteractiveAuthentication = payload.SSH.KbdInteractive
			serwer.MaxAuthTries = payload.SSH.MaxAuthTries
			serwer.AllowUsers = payload.SSH.AllowUsers
			serwer.AllowGroups = payload.SSH.AllowGroups
			serwer.DenyUsers = payload.SSH.DenyUsers
			serwer.AllowLockout = payload.SSH.AllowLockout
			serwer.KeyType = payload.SSH.KeyType
		}
		envelope.Action = &agentv1.TaskEnvelope_Ssh{Ssh: serwer}

	case opspec.ActionStoragePlan, opspec.ActionMountEnsure,
		opspec.ActionMountRemove, opspec.ActionFilesystemCheck,
		opspec.ActionLVMExtend, opspec.ActionFilesystemResize,
		opspec.ActionFilesystemCreate, opspec.ActionDiskWipe:
		operacja := agentv1.StorageAction_OPERATION_MOUNT_ENSURE
		switch action {
		case opspec.ActionStoragePlan:
			operacja = agentv1.StorageAction_OPERATION_READ
		case opspec.ActionMountRemove:
			operacja = agentv1.StorageAction_OPERATION_MOUNT_REMOVE
		case opspec.ActionFilesystemCheck:
			operacja = agentv1.StorageAction_OPERATION_FS_CHECK
		case opspec.ActionLVMExtend:
			operacja = agentv1.StorageAction_OPERATION_LVM_EXTEND
		case opspec.ActionFilesystemResize:
			operacja = agentv1.StorageAction_OPERATION_FS_RESIZE
		case opspec.ActionFilesystemCreate:
			operacja = agentv1.StorageAction_OPERATION_FS_CREATE
		case opspec.ActionDiskWipe:
			operacja = agentv1.StorageAction_OPERATION_DISK_WIPE
		}
		przestrzen := &agentv1.StorageAction{Operation: operacja}
		if payload.Storage != nil {
			przestrzen.Source = payload.Storage.Source
			przestrzen.Target = payload.Storage.Target
			przestrzen.FsType = payload.Storage.FSType
			przestrzen.Options = payload.Storage.Options
			przestrzen.Persist = payload.Storage.Persist
			przestrzen.Device = payload.Storage.Device
			przestrzen.ExpectedUuid = payload.Storage.ExpectedUUID
			przestrzen.Repair = payload.Storage.Repair
			przestrzen.ExpectedSerial = payload.Storage.ExpectedSerial
			przestrzen.ExpectedSizeBytes = payload.Storage.ExpectedSizeBytes
			przestrzen.Size = payload.Storage.Size
			przestrzen.Label = payload.Storage.Label
		}
		envelope.Action = &agentv1.TaskEnvelope_Storage{Storage: przestrzen}

	case opspec.ActionFirewallPlan, opspec.ActionFirewallRuleEnsure,
		opspec.ActionFirewallRuleRemove, opspec.ActionFirewallZonePort,
		opspec.ActionFirewallZoneService, opspec.ActionFirewallRulesetRestore:
		operacja := agentv1.FirewallAction_OPERATION_RULE_ENSURE
		switch action {
		case opspec.ActionFirewallPlan:
			operacja = agentv1.FirewallAction_OPERATION_READ
		case opspec.ActionFirewallRuleRemove:
			operacja = agentv1.FirewallAction_OPERATION_RULE_REMOVE
		case opspec.ActionFirewallZonePort:
			operacja = agentv1.FirewallAction_OPERATION_ZONE_PORT
		case opspec.ActionFirewallZoneService:
			operacja = agentv1.FirewallAction_OPERATION_ZONE_SERVICE
		case opspec.ActionFirewallRulesetRestore:
			operacja = agentv1.FirewallAction_OPERATION_RESTORE
		}
		zapora := &agentv1.FirewallAction{Operation: operacja}
		if payload.Firewall != nil {
			zapora.RuleId = payload.Firewall.RuleID
			zapora.Chain = payload.Firewall.Chain
			zapora.Action = payload.Firewall.Action
			zapora.Protocol = payload.Firewall.Protocol
			zapora.Ports = payload.Firewall.Ports
			zapora.Sources = payload.Firewall.Sources
			zapora.Interface = payload.Firewall.Interface
			zapora.Comment = payload.Firewall.Comment
			zapora.Zone = payload.Firewall.Zone
			zapora.Service = payload.Firewall.Service
			zapora.Enable = payload.Firewall.Enable
			zapora.BreakGlass = payload.Firewall.BreakGlass
			zapora.RollbackSeconds = payload.Firewall.RollbackSeconds
			zapora.RollbackId = payload.Firewall.RollbackID
			zapora.ExpectedHash = payload.Firewall.ExpectedHash
		}
		envelope.Action = &agentv1.TaskEnvelope_Firewall{Firewall: zapora}

	case opspec.ActionDNSResolveTest, opspec.ActionDNSHostApply:
		operacja := agentv1.DnsAction_OPERATION_APPLY
		if action == opspec.ActionDNSResolveTest {
			operacja = agentv1.DnsAction_OPERATION_RESOLVE_TEST
		}
		resolver := &agentv1.DnsAction{Operation: operacja}
		if payload.DNS != nil {
			resolver.Interface = payload.DNS.Interface
			resolver.Servers = payload.DNS.Servers
			resolver.SearchDomains = payload.DNS.SearchDomains
			resolver.IgnoreAutoDns = payload.DNS.IgnoreAutoDNS
			resolver.RollbackSeconds = payload.DNS.RollbackSeconds
			resolver.Names = payload.DNS.Names
		}
		envelope.Action = &agentv1.TaskEnvelope_Dns{Dns: resolver}

	case opspec.ActionNetworkPlan, opspec.ActionNetworkMTUSet,
		opspec.ActionNetworkRouteEnsure, opspec.ActionNetworkProfileApply,
		opspec.ActionNetworkRollback:
		operacja := agentv1.NetworkAction_OPERATION_APPLY_PROFILE
		switch action {
		case opspec.ActionNetworkPlan:
			operacja = agentv1.NetworkAction_OPERATION_READ
		case opspec.ActionNetworkMTUSet:
			operacja = agentv1.NetworkAction_OPERATION_SET_MTU
		case opspec.ActionNetworkRouteEnsure:
			operacja = agentv1.NetworkAction_OPERATION_ENSURE_ROUTES
		case opspec.ActionNetworkRollback:
			operacja = agentv1.NetworkAction_OPERATION_ROLLBACK
		}
		siec := &agentv1.NetworkAction{Operation: operacja}
		if payload.Network != nil {
			siec.Interface = payload.Network.Interface
			siec.Mtu = payload.Network.MTU
			siec.Routes = payload.Network.Routes
			siec.Method = payload.Network.Method
			siec.Addresses = payload.Network.Addresses
			siec.Gateway = payload.Network.Gateway
			siec.Dns = payload.Network.DNS
			siec.RollbackSeconds = payload.Network.RollbackSeconds
			siec.RollbackId = payload.Network.RollbackID
		}
		envelope.Action = &agentv1.TaskEnvelope_Network{Network: siec}

	case opspec.ActionScheduleEnsure, opspec.ActionScheduleDisable,
		opspec.ActionScheduleRemove, opspec.ActionScheduleRunNow:
		operacja := agentv1.ScheduleAction_OPERATION_ENSURE
		switch action {
		case opspec.ActionScheduleDisable:
			operacja = agentv1.ScheduleAction_OPERATION_DISABLE
		case opspec.ActionScheduleRemove:
			operacja = agentv1.ScheduleAction_OPERATION_REMOVE
		case opspec.ActionScheduleRunNow:
			operacja = agentv1.ScheduleAction_OPERATION_RUN_NOW
		}
		envelope.Action = &agentv1.TaskEnvelope_Schedule{
			Schedule: &agentv1.ScheduleAction{
				Operation:  operacja,
				Id:         payload.Schedule.ID,
				Expression: payload.Schedule.Expression,
				Command:    payload.Schedule.Command,
				User:       payload.Schedule.User,
				Comment:    payload.Schedule.Comment,
				Enabled:    payload.Schedule.Enabled,
				Adopt:      payload.Schedule.Adopt,
			},
		}

	case opspec.ActionProcessList:
		envelope.Action = &agentv1.TaskEnvelope_ListProcesses{
			ListProcesses: &agentv1.ListProcesses{
				SortBy: payload.ProcessList.SortBy,
				Limit:  payload.ProcessList.Limit,
			},
		}

	case opspec.ActionProcessSignal:
		envelope.Action = &agentv1.TaskEnvelope_SignalProcess{
			SignalProcess: &agentv1.SignalProcess{
				Pid:                payload.ProcessSignal.PID,
				ExpectedStartTicks: payload.ProcessSignal.ExpectedStart,
				Signal:             payload.ProcessSignal.Signal,
				Command:            payload.ProcessSignal.Command,
			},
		}

	case opspec.ActionFollowJournal:
		envelope.Action = &agentv1.TaskEnvelope_FollowJournal{
			FollowJournal: &agentv1.FollowJournal{
				Unit:          payload.Journal.Unit,
				MaxPriority:   payload.Journal.MaxPriority,
				BacklogLines:  payload.Journal.Lines,
				FollowSeconds: payload.Journal.FollowSeconds,
			},
		}

	case opspec.ActionReadLogFile:
		envelope.Action = &agentv1.TaskEnvelope_ReadLogFile{
			ReadLogFile: &agentv1.ReadLogFile{
				Path:  payload.LogFile.Path,
				Lines: payload.LogFile.Lines,
			},
		}

	case opspec.ActionUnitEnableSet, opspec.ActionUnitMaskSet:
		wlasciwosc := agentv1.UnitToggle_PROPERTY_ENABLED
		if action == opspec.ActionUnitMaskSet {
			wlasciwosc = agentv1.UnitToggle_PROPERTY_MASKED
		}
		envelope.Action = &agentv1.TaskEnvelope_UnitToggle{
			UnitToggle: &agentv1.UnitToggle{
				Unit:     payload.UnitToggle.Unit,
				Property: wlasciwosc,
				Value:    payload.UnitToggle.Enabled,
			},
		}

	case opspec.ActionComposePlan, opspec.ActionComposeDeploy:
		operacja := agentv1.ComposeAction_OPERATION_PLAN
		if action == opspec.ActionComposeDeploy {
			operacja = agentv1.ComposeAction_OPERATION_DEPLOY
		}
		envelope.Action = &agentv1.TaskEnvelope_Compose{
			Compose: &agentv1.ComposeAction{
				Operation:  operacja,
				Project:    payload.Compose.Project,
				Manifest:   payload.Compose.Manifest,
				PlanDigest: payload.Compose.PlanDigest,
			},
		}

	case opspec.ActionDockerStart, opspec.ActionDockerStop, opspec.ActionDockerRestart,
		opspec.ActionDockerRemove, opspec.ActionDockerPull, opspec.ActionDockerPrune:
		envelope.Action = &agentv1.TaskEnvelope_DockerAction{
			DockerAction: kopertaDockera(action, payload),
		}

	case opspec.ActionUnitStatus:
		envelope.Action = &agentv1.TaskEnvelope_ReadUnitStatus{
			ReadUnitStatus: &agentv1.ReadUnitStatus{
				Units: payload.UnitStatus.Units,
				All:   payload.UnitStatus.All,
			},
		}

	case opspec.ActionSystemReboot:
		envelope.Action = &agentv1.TaskEnvelope_SystemReboot{
			SystemReboot: &agentv1.SystemReboot{
				DelaySeconds: payload.Reboot.DelaySeconds,
				Reason:       payload.Reboot.Reason,
			},
		}

	case opspec.ActionReadJournal:
		request := &agentv1.ReadJournal{
			Unit:  payload.Journal.Unit,
			Lines: payload.Journal.Lines,
			Since: payload.Journal.Since,
		}
		if payload.Journal.MaxPriority != nil {
			request.MaxPriority = payload.Journal.MaxPriority
		}
		envelope.Action = &agentv1.TaskEnvelope_ReadJournal{ReadJournal: request}
	default:
		operation, ok := unitOperations[action]
		if !ok {
			return nil, errUnknownAction(item.Job.ActionType)
		}
		envelope.Action = &agentv1.TaskEnvelope_UnitAction{
			UnitAction: &agentv1.UnitAction{Unit: payload.Unit.Unit, Operation: operation},
		}
	}
	return envelope, nil
}

var unitOperations = map[opspec.ActionType]agentv1.UnitAction_Operation{
	opspec.ActionUnitStart:   agentv1.UnitAction_OPERATION_START,
	opspec.ActionUnitStop:    agentv1.UnitAction_OPERATION_STOP,
	opspec.ActionUnitRestart: agentv1.UnitAction_OPERATION_RESTART,
	opspec.ActionUnitReload:  agentv1.UnitAction_OPERATION_RELOAD,
}

// localUserOperations tlumaczy typ operacji na wartosc kontraktu. Mapa jest
// jawna, wiec dodanie akcji bez odwzorowania nie przechodzi przez testy.
var localUserOperations = map[opspec.ActionType]agentv1.LocalUserAction_Operation{
	opspec.ActionLocalUserCreate: agentv1.LocalUserAction_OPERATION_CREATE,
	opspec.ActionLocalUserLock:   agentv1.LocalUserAction_OPERATION_LOCK,
	opspec.ActionLocalUserUnlock: agentv1.LocalUserAction_OPERATION_UNLOCK,
	opspec.ActionLocalSSHKeysSet: agentv1.LocalUserAction_OPERATION_SET_SSH_KEYS,
}

func approvalsOf(job jobs.Job) []string {
	if job.ApprovedBy == "" {
		return nil
	}
	return []string{job.ApprovedBy}
}

type unknownActionError string

func (e unknownActionError) Error() string { return "nieznany typ operacji: " + string(e) }

func errUnknownAction(action string) error { return unknownActionError(action) }

// Jitter rozklada start pierwszej petli, zeby restart wielu replik nie
// wywolal jednoczesnego uderzenia w baze.
func Jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(base)))
}

// kopertaDockera sklada koperte operacji kontenerowej. Kazdy typ operacji ma
// wlasny payload, wiec tlumaczenie jest jawne, a nie po nazwie pola.
func kopertaDockera(action opspec.ActionType, payload opspec.Payload) *agentv1.DockerAction {
	koperta := &agentv1.DockerAction{}
	if kontener := payload.DockerContainer; kontener != nil {
		koperta.ContainerId = kontener.ContainerID
		koperta.ContainerName = kontener.Name
		koperta.TimeoutSeconds = kontener.TimeoutSeconds
		koperta.RemoveVolumes = kontener.RemoveVolumes
	}
	if obraz := payload.DockerImage; obraz != nil {
		koperta.ImageReference = obraz.Reference
	}
	if sprzatanie := payload.DockerPrune; sprzatanie != nil {
		koperta.ImageIds = sprzatanie.ImageIDs
		koperta.VolumeNames = sprzatanie.VolumeName
		koperta.NetworkIds = sprzatanie.NetworkIDs
	}
	switch action {
	case opspec.ActionDockerStart:
		koperta.Operation = agentv1.DockerAction_OPERATION_START
	case opspec.ActionDockerStop:
		koperta.Operation = agentv1.DockerAction_OPERATION_STOP
	case opspec.ActionDockerRestart:
		koperta.Operation = agentv1.DockerAction_OPERATION_RESTART
	case opspec.ActionDockerRemove:
		koperta.Operation = agentv1.DockerAction_OPERATION_REMOVE
	case opspec.ActionDockerPull:
		koperta.Operation = agentv1.DockerAction_OPERATION_PULL_IMAGE
	case opspec.ActionDockerPrune:
		koperta.Operation = agentv1.DockerAction_OPERATION_PRUNE
	}
	return koperta
}
