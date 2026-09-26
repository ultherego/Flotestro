package helper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/systemd"
)

// Server handles mutating tasks on behalf of the agent.
type Server struct {
	// allowedUID is the only identifier allowed to issue commands. The check
	// goes through the kernel's SO_PEERCRED, not through the message body.
	allowedUID uint32
	log        *slog.Logger

	// At most one mutation of a resource class runs at a time: a concurrent start
	// and stop of the same unit, or two transactions on the same package
	// database, give an unpredictable result.
	guards guards

	// Idleness is counted from the closing of the last connection, not from the
	// start of the process.
	IdleTimeout time.Duration
	active      sync.WaitGroup
	// inFlight counts the connections being handled.
	inFlight atomic.Int64
	traffic  chan struct{}

	// The account and hostname handlers reach the system through these seams, so
	// they can be checked without an account on the machine running the tests.
	lookupAccount func(name string) (accountRecord, error)
	accountTool   accountTool
	hostsFile     string
	// agentStateDir is the directory the final wipe clears. Empty means the
	// agent's real one; a test points it at a directory of its own.
	agentStateDir string
	// scopes wraps the tools of a heavy operation in a transient resource
	// scope. A test stands in a host without systemd-run through it.
	scopes scopeRunner

	// policy decides whether a mutating request is authorized by the panel's
	// capability, and what to do with one that carries none.
	policy *helpercap.Policy
	// trust is the root-owned keyring and host identity the trust update
	// writes.
	trust helpercap.TrustStore
	// packageManager stands in for the detection of the package manager.
	packageManager func() (packages.Manager, error)
}

func NewServer(allowedUID uint32, log *slog.Logger) *Server {
	return &Server{allowedUID: allowedUID, log: log, traffic: make(chan struct{}, 1),
		scopes: newScopeRunner(log), policy: helpercap.NewPolicy(helpercap.ModePrefer, nil)}
}

// SetCapabilityPolicy installs the capability policy and the trust store
// it verifies against.
func (s *Server) SetCapabilityPolicy(policy *helpercap.Policy, trust helpercap.TrustStore) {
	s.policy = policy
	s.trust = trust
}

// CapabilityMode is the mode the server runs in.
func (s *Server) CapabilityMode() helpercap.Mode {
	if s.policy == nil {
		return helpercap.ModePrefer
	}
	return s.policy.Mode
}

// Serve accepts connections until the context is closed or until the idle
// window elapses, when IdleTimeout is set.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	if s.IdleTimeout > 0 {
		go s.watchIdleness(ctx, cancel)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// Connections in flight finish their work: closing the socket
				// is not an interruption of the task.
				s.active.Wait()
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}
		s.active.Add(1)
		s.inFlight.Add(1)
		go func() {
			defer s.active.Done()
			defer s.inFlight.Add(-1)
			defer s.markTraffic()
			s.handleConnection(context.WithoutCancel(ctx), conn)
		}()
	}
}

// watchIdleness ends the work when no connection has closed for IdleTimeout
// and none is in flight.
func (s *Server) watchIdleness(ctx context.Context, cancel context.CancelFunc) {
	timer := time.NewTimer(s.IdleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.traffic:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(s.IdleTimeout)
		case <-timer.C:
			if inFlight := s.connectionsInFlight(); inFlight {
				// The task takes longer than the idle window; count from scratch.
				timer.Reset(s.IdleTimeout)
				continue
			}
			s.log.Info("work ended after an idle period", "timeout", s.IdleTimeout.String())
			cancel()
			return
		}
	}
}

// connectionsInFlight says whether some connection is being handled right now.
func (s *Server) connectionsInFlight() bool {
	return s.inFlight.Load() > 0
}

func (s *Server) markTraffic() {
	select {
	case s.traffic <- struct{}{}:
	default:
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		s.log.Warn("rejected a connection from outside a unix socket")
		return
	}
	uid, pid, err := peerCredentials(unixConn)
	if err != nil {
		s.log.Error("the identity of the peer was not read", "err", err)
		return
	}
	// The peer identity comes from the kernel. The message cannot swap it.
	if uid != s.allowedUID {
		s.log.Warn("rejected a connection from a foreign user", "uid", uid, "pid", pid)
		return
	}

	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))

	var request helperv1.HelperRequest
	if err := ReadMessage(conn, &request); err != nil {
		s.log.Error("unreadable request", "err", err)
		_ = WriteMessage(conn, reject(ErrorMalformed, err.Error()))
		return
	}
	// The socket deadline covers the whole operation, not a fixed window: a
	// package transaction or a backup takes longer than ten minutes, and its
	// result must still find an open socket at the end.
	limit := timeLimit(&request, 10*time.Minute, longestOperation) + time.Minute
	_ = conn.SetDeadline(time.Now().Add(limit))

	// The progress of a long operation travels in separate messages, before the
	// final answer arrives.
	var sendMu sync.Mutex
	var progress func(*helperv1.TaskProgress)
	if request.GetWantProgress() {
		progress = func(p *helperv1.TaskProgress) {
			sendMu.Lock()
			defer sendMu.Unlock()
			if err := WriteMessage(conn, &helperv1.HelperResponse{Progress: p}); err != nil {
				// A broken progress send must not interrupt the operation: the
				// transaction itself matters more than its preview.
				s.log.Debug("progress was not sent", "task_id", request.GetTaskId(), "err", err)
			}
		}
	}

	response := s.handle(ctx, &request, progress)
	response.Final = true
	// Every answer says which mode the helper runs in, so the agent can
	// tell the panel what this host does with a capability.
	response.CapabilityMode = string(s.CapabilityMode())
	sendMu.Lock()
	defer sendMu.Unlock()
	if err := WriteMessage(conn, response); err != nil {
		s.log.Error("the answer was not sent back", "task_id", request.GetTaskId(), "err", err)
	}
}

// handle validates the request and performs the operation. Every refusal has a
// stable machine code, so that the agent can report it without parsing text.
func (s *Server) handle(ctx context.Context, request *helperv1.HelperRequest,
	progress func(*helperv1.TaskProgress)) *helperv1.HelperResponse {
	if request.GetProtocolVersion() != ProtocolVersion {
		return reject(ErrorUnsupportedVersion,
			fmt.Sprintf("version %d, supported %d", request.GetProtocolVersion(), ProtocolVersion))
	}
	// The helper checks the TTL on its own. The agent may be delayed or wrong,
	// and a task past its deadline must not be performed.
	if expires := request.GetExpiresAt(); expires != nil && time.Now().After(expires.AsTime()) {
		return reject(ErrorExpired,
			fmt.Sprintf("the task expired at %s", expires.AsTime().Format(time.RFC3339)))
	}

	// The keyring update proves itself with the bundle's own signature and goes
	// before the capability check: it is how the keys the check needs reach the
	// host in the first place.
	if update, ok := request.GetAction().(*helperv1.HelperRequest_TrustUpdate); ok {
		return s.applyTrustUpdate(request, update.TrustUpdate)
	}
	// The capability: the panel's proof that this operation was approved
	// for this host. A refusal here runs nothing.
	refused, decision := s.authorize(request)
	if refused != nil {
		return refused
	}
	// This very request already ran under this capability: the answer it gave
	// is repeated and the effect is not. A capability covers a whole task and
	// the agent may ask twice - after a lost answer, or because somebody made
	// it ask - and a schedule, a signal or a restore must not happen twice for
	// one order.
	if len(decision.Kept) > 0 {
		kept := &helperv1.HelperResponse{}
		if err := proto.Unmarshal(decision.Kept, kept); err != nil {
			s.log.Error("the kept answer of a repeated request does not read; the request is refused rather than carried out again",
				"task_id", request.GetTaskId(), "err", err)
			return reject(helpercap.ErrorCapabilityPerformed,
				"this request already ran under this capability and the answer kept for it does not read")
		}
		s.log.Info("a repeated request was answered from what it answered before",
			"task_id", request.GetTaskId(), "kind", helpercap.Expect(request).Kind)
		kept.CapabilityId = decision.CapabilityID
		return kept
	}

	response := s.perform(ctx, request, progress)
	// The verified capability travels back with the answer, so the agent
	// can put it next to the task on its own side of the audit trail.
	response.CapabilityId = decision.CapabilityID
	if decision.Complete != nil {
		encoded, err := proto.Marshal(response)
		if err == nil {
			err = decision.Complete(encoded)
		}
		if err != nil {
			// The effect happened. What is lost is the ability to answer a
			// repeat without doing it again, so it is said out loud.
			s.log.Error("the answer of this request was not recorded; asked again it would be carried out a second time",
				"task_id", request.GetTaskId(), "err", err)
		}
	}
	return response
}

// authorize applies the capability policy to a request and hands the decision
// back: what the capability was, and what the store already knows about this
// very request under it.
func (s *Server) authorize(request *helperv1.HelperRequest) (*helperv1.HelperResponse, helpercap.Decision) {
	if s.policy == nil {
		return nil, helpercap.Decision{}
	}
	decision := s.policy.Decide(request)
	switch decision.Outcome {
	case helpercap.OutcomeLegacy:
		legacy, verified, refused, observed := s.policy.Counters()
		s.log.Warn("legacy_helper_request: a mutating request without a capability of the panel",
			"task_id", request.GetTaskId(), "kind", helpercap.Expect(request).Kind,
			"mode", string(s.policy.Mode),
			"legacy_total", legacy, "verified_total", verified, "refused_total", refused, "observed_total", observed)
	case helpercap.OutcomeObserved:
		s.log.Warn("the capability failed verification; observe mode lets the request through",
			"task_id", request.GetTaskId(), "capability_id", decision.CapabilityID,
			"code", decision.Code, "reason", decision.Message)
	case helpercap.OutcomeRefused:
		s.log.Warn("the request was refused by the capability policy",
			"task_id", request.GetTaskId(), "capability_id", decision.CapabilityID,
			"kind", helpercap.Expect(request).Kind, "mode", string(s.policy.Mode),
			"code", decision.Code, "reason", decision.Message)
		return reject(decision.Code, decision.Message), helpercap.Decision{}
	case helpercap.OutcomeVerified:
		s.log.Info("the capability of the panel was verified",
			"task_id", request.GetTaskId(), "capability_id", decision.CapabilityID,
			"action", request.GetCapability().GetActionType(), "key_id", request.GetCapability().GetKeyId())
	}
	return nil, decision
}

// applyTrustUpdate writes the panel's keyring and the host identity.
func (s *Server) applyTrustUpdate(request *helperv1.HelperRequest,
	update *helperv1.HelperTrustUpdateRequest) *helperv1.HelperResponse {
	if s.trust.Dir == "" || s.trust.HostIDPath == "" {
		return reject(ErrorUnsupported, "this helper keeps no keyring")
	}
	result, err := s.trust.Apply(update.GetBundle())
	if err != nil {
		if code := helpercap.CodeOf(err); code != "" {
			s.log.Warn("the trust bundle was refused", "code", code, "reason", err.Error())
			return reject(code, err.Error())
		}
		s.log.Error("the trust bundle was not written", "err", err)
		return reject(ErrorExecFailed, err.Error())
	}
	if result.Changed {
		s.log.Info("the keyring of the helper was updated",
			"host_id", result.HostID, "key_ids", result.KeyIDs, "bootstrap", result.Bootstrap,
			"signed_by", update.GetBundle().GetSignedByKeyId())
	}
	return &helperv1.HelperResponse{Accepted: true, TrustResult: &helperv1.HelperTrustResult{
		HostId: result.HostID, KeyIds: result.KeyIDs, Changed: result.Changed}}
}

// perform carries the request out. Every check that can refuse it without
// touching the host is behind.
func (s *Server) perform(ctx context.Context, request *helperv1.HelperRequest,
	progress func(*helperv1.TaskProgress)) *helperv1.HelperResponse {
	switch action := request.GetAction().(type) {
	case *helperv1.HelperRequest_UnitAction:
		return s.applyUnitAction(ctx, request, action.UnitAction)
	case *helperv1.HelperRequest_PackageAction:
		return s.applyPackageAction(ctx, request, action.PackageAction, progress)
	case *helperv1.HelperRequest_File:
		return s.applyFile(ctx, request, action.File)

	case *helperv1.HelperRequest_Kernel:
		return s.applyKernel(ctx, request, action.Kernel)
	case *helperv1.HelperRequest_Time:
		return s.applyTime(ctx, request, action.Time)
	case *helperv1.HelperRequest_Shutdown:
		return s.applyShutdown(ctx, request, action.Shutdown)
	case *helperv1.HelperRequest_Security:
		return s.applySecurity(ctx, request, action.Security)
	case *helperv1.HelperRequest_Certificate:
		return s.applyCertificate(ctx, request, action.Certificate)
	case *helperv1.HelperRequest_Repository:
		return s.applyRepository(ctx, request, action.Repository)
	case *helperv1.HelperRequest_Backup:
		return s.applyBackup(ctx, request, action.Backup, progress)

	case *helperv1.HelperRequest_Ssh:
		return s.applySSH(ctx, request, action.Ssh)

	case *helperv1.HelperRequest_Storage:
		return s.applyStorage(ctx, request, action.Storage)

	case *helperv1.HelperRequest_Firewall:
		return s.applyFirewall(ctx, request, action.Firewall)

	case *helperv1.HelperRequest_Dns:
		return s.applyDNS(ctx, request, action.Dns)

	case *helperv1.HelperRequest_Network:
		return s.applyNetwork(ctx, request, action.Network)

	case *helperv1.HelperRequest_Schedule:
		return s.applySchedule(ctx, request, action.Schedule)

	case *helperv1.HelperRequest_ProcessSignal:
		return s.signalProcess(ctx, request, action.ProcessSignal)

	case *helperv1.HelperRequest_LogFile:
		return s.readLogFile(ctx, request, action.LogFile)

	case *helperv1.HelperRequest_Compose:
		return s.applyCompose(ctx, request, action.Compose)

	case *helperv1.HelperRequest_DockerAction:
		return s.applyDocker(ctx, request, action.DockerAction)

	case *helperv1.HelperRequest_DockerRead:
		return s.readDocker(ctx, request, action.DockerRead)

	case *helperv1.HelperRequest_DockerEvents:
		return s.readDockerEvents(ctx, request, action.DockerEvents)

	case *helperv1.HelperRequest_DockerLogs:
		return s.readDockerLogs(ctx, request, action.DockerLogs)

	case *helperv1.HelperRequest_DockerEnsure:
		return s.ensureDocker(ctx, request, action.DockerEnsure)

	case *helperv1.HelperRequest_Hostname:
		return s.applyHostname(ctx, request, action.Hostname)

	case *helperv1.HelperRequest_FinalWipe:
		return s.applyFinalWipe(ctx, request, action.FinalWipe)

	case *helperv1.HelperRequest_PackageRepair:
		return s.repairPackages(ctx, request, action.PackageRepair)
	case *helperv1.HelperRequest_Reboot:
		return s.applyReboot(ctx, request, action.Reboot)
	case *helperv1.HelperRequest_IdentityProbe:
		return s.probeIdentity(ctx, request, action.IdentityProbe)
	case *helperv1.HelperRequest_DomainEnroll:
		return s.enrollDomain(ctx, request, action.DomainEnroll)
	case *helperv1.HelperRequest_DomainLeave:
		return s.leaveDomain(ctx, request, action.DomainLeave)
	case *helperv1.HelperRequest_KeytabRenew:
		return s.renewKeytab(ctx, request, action.KeytabRenew)
	case *helperv1.HelperRequest_LocalAccounts:
		return s.readLocalAccounts(ctx, request, action.LocalAccounts)
	case *helperv1.HelperRequest_LocalUserAction:
		return s.applyLocalUserAction(ctx, request, action.LocalUserAction)
	case *helperv1.HelperRequest_System:
		return s.readSystem(ctx, request, action.System)
	default:
		return reject(ErrorUnknownAction, "no supported action")
	}
}

// applyPackageAction refreshes the metadata or performs a package transaction.
func (s *Server) applyPackageAction(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.PackageActionRequest, progress func(*helperv1.TaskProgress)) *helperv1.HelperResponse {
	manager, err := s.detectPackages()
	if err != nil {
		return reject(packages.ErrorUnsupported, err.Error())
	}

	release, busy := s.hold(GuardPackages, request)
	if busy != nil {
		return busy
	}
	defer release()

	// The manager lock is checked explicitly and never worked around. Manual
	// work by the administrator takes precedence over a task from the panel.
	if held, path := manager.LockHeld(); held {
		return reject(packages.ErrorLocked,
			fmt.Sprintf("the package manager is busy (%s)", path))
	}

	operationCtx, cancel := deadline(ctx, request, 30*time.Minute, 2*time.Hour)
	defer cancel()
	// Every operation of the manager - a refresh as much as a transaction - runs
	// in the scope of the package family: the manager starts its tools itself,
	// and reads the scope out of the context.
	operationCtx = s.scopeContext(operationCtx, request.GetTaskId(), opspec.FamilyPackages)

	options := packages.Options{
		Packages:     action.GetPackages(),
		SecurityOnly: action.GetSecurityOnly(),
	}

	if progress != nil {
		options.Progress = func(p packages.Progress) {
			progress(&helperv1.TaskProgress{
				Step: p.Step, Total: p.Total, Percent: p.Percent, Message: p.Message,
			})
		}
	}

	// An order bound to an approved plan runs that plan and nothing else: the
	// plan is computed again here, under the lock, and compared before the
	// transaction.
	if _, _, bound := approvedPlan(action); bound {
		switch action.GetOperation() {
		case helperv1.PackageActionRequest_OPERATION_UPGRADE, helperv1.PackageActionRequest_OPERATION_REMOVE:
			return s.executeApproved(operationCtx, request, manager, action, options)
		case helperv1.PackageActionRequest_OPERATION_INSTALL:
			if _, selfReplacement := agentReplacement(options.Packages); !selfReplacement {
				return s.executeApproved(operationCtx, request, manager, action, options)
			}
		}
	}

	// A change that does not fit on the disk is refused here, before the lock is
	// taken and the first archive lands.
	if refusal := s.packageSpacePreflight(operationCtx, request, manager, action, options); refusal != nil {
		return refusal
	}

	switch action.GetOperation() {
	case helperv1.PackageActionRequest_OPERATION_INSTALL,
		helperv1.PackageActionRequest_OPERATION_REMOVE,
		helperv1.PackageActionRequest_OPERATION_HOLD:
		return s.packageLifecycle(operationCtx, manager, action, options)

	case helperv1.PackageActionRequest_OPERATION_REFRESH:
		if err := manager.Refresh(operationCtx); err != nil {
			return packageFailure(manager.Name(), err)
		}
		s.log.Info("repository metadata refreshed",
			"task_id", request.GetTaskId(), "manager", manager.Name())
		return &helperv1.HelperResponse{
			Accepted:      true,
			PackageResult: &helperv1.PackageActionResult{Manager: manager.Name()},
		}

	case helperv1.PackageActionRequest_OPERATION_UPGRADE:
		apply, err := manager.Upgrade(operationCtx, options)
		response := &helperv1.HelperResponse{
			PackageResult: packageResultToProto(apply),
		}
		if err != nil {
			// A partial result is returned on failure as well: the administrator
			// has to know what managed to change before the breakdown.
			response.Accepted = false
			response.ErrorCode = packageErrorCode(err)
			response.Message = err.Error()
			response.ExitCode = -1
			s.log.Error("the package transaction failed",
				"task_id", request.GetTaskId(), "manager", manager.Name(),
				"changed", len(apply.Applied), "database_broken", apply.DatabaseBroken,
				"err", err)
			return response
		}
		response.Accepted = true
		s.log.Info("package transaction finished",
			"task_id", request.GetTaskId(), "manager", manager.Name(),
			"changed", len(apply.Applied), "reboot", apply.RebootRequired)
		return response

	default:
		return reject(ErrorUnknownAction, "unknown package operation")
	}
}

// packageSpacePreflight computes the plan of an upgrade or an installation and
// judges its space facts.
func (s *Server) packageSpacePreflight(ctx context.Context, request *helperv1.HelperRequest,
	manager packages.Manager, action *helperv1.PackageActionRequest,
	options packages.Options) *helperv1.HelperResponse {
	switch action.GetOperation() {
	case helperv1.PackageActionRequest_OPERATION_INSTALL:
		options.Mode = packages.ModeInstall
	case helperv1.PackageActionRequest_OPERATION_UPGRADE:
		options.Mode = packages.ModeUpgrade
	default:
		// A removal frees space and a hold writes one line; a refresh writes
		// the lists, whose size nobody publishes.
		return nil
	}
	plan, err := manager.Plan(ctx, options)
	if err != nil {
		s.log.Warn("the space of the package change could not be measured",
			"task_id", request.GetTaskId(), "manager", manager.Name(), "err", err)
		return nil
	}
	if err := packages.SpaceShortfall(plan.Space); err != nil {
		s.log.Warn("the package change was refused for lack of space",
			"task_id", request.GetTaskId(), "manager", manager.Name(), "err", err)
		return packageFailure(manager.Name(), err)
	}
	return nil
}

// applyReboot orders a delayed restart.
func (s *Server) applyReboot(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.RebootRequest) *helperv1.HelperResponse {
	delay := action.GetDelaySeconds()
	if delay == 0 {
		delay = 10
	}
	if delay > 3600 {
		return reject(ErrorUnknownAction, "the restart delay exceeds an hour")
	}

	reason := action.GetReason()
	if reason == "" {
		reason = "Flotestro: controlled restart"
	}

	// Scheduling is a short talk with systemd, but a manager that does not
	// answer must not hold the connection until the socket gives up.
	scheduleCtx, cancel := deadline(ctx, request, 2*time.Minute, 10*time.Minute)
	defer cancel()

	// A restart interrupts work on the host exactly as a shutdown does, and it
	// used to be the one power operation that never asked.
	inhibitors, known := powerInhibitors(scheduleCtx, "shutdown")
	if !known && !action.GetIgnoreInhibitors() {
		return reject(ErrorInhibitorsUnknown, "this host could not be asked whether anything is holding a restart back, "+
			"so the restart was not ordered on an unread answer")
	}
	if len(inhibitors) > 0 && !action.GetIgnoreInhibitors() {
		refusal := reject(ErrorPreconditionFailed,
			"the restart was held back by inhibitors: "+describeInhibitors(inhibitors))
		refusal.PowerResult = &helperv1.PowerResult{
			Message:    refusal.Message,
			Inhibitors: encodeInhibitors(inhibitors),
		}
		return refusal
	}

	// shutdown -r takes time in minutes or the word now, so short delays are
	// carried out through a transient systemd timer.
	stdout, stderr, exitCode, err := systemd.ScheduleReboot(scheduleCtx, time.Duration(delay)*time.Second, reason)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if exitCode != 0 {
		response := reject(ErrorExecFailed, strings.TrimSpace(stderr))
		response.ExitCode = int32(exitCode)
		return response
	}

	s.log.Warn("a host restart was scheduled",
		"task_id", request.GetTaskId(), "in_seconds", delay, "reason", reason)

	limit := int(request.GetMaxOutputBytes())
	out, truncated := clamp([]byte(stdout), limit)
	return &helperv1.HelperResponse{
		Accepted: true, ExitCode: 0, Stdout: out, OutputTruncated: truncated,
	}
}

func packageFailure(manager string, err error) *helperv1.HelperResponse {
	response := reject(packageErrorCode(err), err.Error())
	response.PackageResult = &helperv1.PackageActionResult{Manager: manager}
	return response
}

// packageErrorCode turns an adapter error into a stable machine code.
func packageErrorCode(err error) string {
	if code, ok := packages.ErrorCodeOf(err); ok {
		return code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorTimeout
	}
	return packages.ErrorTransaction
}

func packageResultToProto(apply packages.Apply) *helperv1.PackageActionResult {
	changes := make([]*helperv1.PackageVersionChange, 0, len(apply.Applied))
	for _, change := range apply.Applied {
		changes = append(changes, &helperv1.PackageVersionChange{
			Name:          change.Name,
			VersionBefore: change.CurrentVersion,
			VersionAfter:  change.CandidateVersion,
		})
	}
	return &helperv1.PackageActionResult{
		Manager:                  apply.Manager,
		Applied:                  changes,
		RebootRequired:           apply.RebootRequired,
		ServicesNeedingRestart:   apply.ServicesNeedingRestart,
		PackageDatabaseBroken:    apply.DatabaseBroken,
		PackagesNeedingAttention: apply.PackagesNeedingAttention,
		SelfRepair:               apply.SelfRepair,
		Output:                   apply.Output,
		ScriptletErrors:          apply.ScriptletErrors,
		EffectsAchieved:          effectOutcomesToProto(apply.EffectsAchieved),
		EffectsMissed:            effectOutcomesToProto(apply.EffectsMissed),
	}
}

func (s *Server) applyUnitAction(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.UnitActionRequest) *helperv1.HelperResponse {
	operation, ok := unitOperations[action.GetOperation()]
	if !ok {
		return reject(ErrorUnknownAction, fmt.Sprintf("operation %s", action.GetOperation()))
	}
	unit := action.GetUnit()

	// Validation repeated on the root side: the helper does not trust that the
	// agent checked the name and the protection policy.
	if err := systemd.ValidateUnit(unit); err != nil {
		switch {
		case errors.Is(err, systemd.ErrProtectedUnit):
			return reject(ErrorProtectedUnit, err.Error())
		default:
			return reject(ErrorInvalidUnit, err.Error())
		}
	}

	release, busy := s.hold(GuardUnits, request)
	if busy != nil {
		return busy
	}
	defer release()

	// The state reads before and after stay outside the limit: each has its own
	// short one, and the state after an operation that used up its whole time is
	// still worth reporting.
	timeout := timeLimit(request, 60*time.Second, 10*time.Minute)
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	before, _ := systemd.Show(ctx, unit)
	stdout, stderr, exitCode, err := systemd.Apply(operationCtx, unit, operation, timeout)
	if err != nil {
		code := ErrorExecFailed
		if errors.Is(err, context.DeadlineExceeded) {
			code = ErrorTimeout
		}
		response := reject(code, err.Error())
		response.StateBefore = toProtoState(before)
		return response
	}
	after, _ := systemd.Show(ctx, unit)

	limit := int(request.GetMaxOutputBytes())
	outBytes, outTruncated := clamp([]byte(stdout), limit)
	errBytes, errTruncated := clamp([]byte(stderr), limit)

	s.log.Info("a unit operation was performed",
		"task_id", request.GetTaskId(), "unit", unit, "operation", operation,
		"exit_code", exitCode, "active_before", before.ActiveState, "active_after", after.ActiveState)

	return &helperv1.HelperResponse{
		Accepted:        true,
		ExitCode:        int32(exitCode),
		Stdout:          outBytes,
		Stderr:          errBytes,
		OutputTruncated: outTruncated || errTruncated,
		StateBefore:     toProtoState(before),
		StateAfter:      toProtoState(after),
	}
}

var unitOperations = map[helperv1.UnitActionRequest_Operation]systemd.Operation{
	helperv1.UnitActionRequest_OPERATION_START:   systemd.OperationStart,
	helperv1.UnitActionRequest_OPERATION_STOP:    systemd.OperationStop,
	helperv1.UnitActionRequest_OPERATION_RESTART: systemd.OperationRestart,
	helperv1.UnitActionRequest_OPERATION_RELOAD:  systemd.OperationReload,
	// Enabling and masking change what the host will do after a restart.
	helperv1.UnitActionRequest_OPERATION_ENABLE:  systemd.OperationEnable,
	helperv1.UnitActionRequest_OPERATION_DISABLE: systemd.OperationDisable,
	helperv1.UnitActionRequest_OPERATION_MASK:    systemd.OperationMask,
	helperv1.UnitActionRequest_OPERATION_UNMASK:  systemd.OperationUnmask,
	// Clearing the failed state touches no process, only the record.
	helperv1.UnitActionRequest_OPERATION_RESET_FAILED: systemd.OperationResetFail,
}

func reject(code, message string) *helperv1.HelperResponse {
	return &helperv1.HelperResponse{Accepted: false, ErrorCode: code, Message: message, ExitCode: -1}
}

// clamp trims the output to the limit and signals the cut. A task result must
// not grow to an arbitrary size.
func clamp(data []byte, limit int) ([]byte, bool) {
	if limit <= 0 {
		limit = 64 << 10
	}
	if len(data) <= limit {
		return data, false
	}
	return data[:limit], true
}

func toProtoState(state systemd.UnitState) *helperv1.UnitState {
	return &helperv1.UnitState{
		Name:          state.Name,
		LoadState:     state.LoadState,
		ActiveState:   state.ActiveState,
		SubState:      state.SubState,
		UnitFileState: state.UnitFileState,
		Result:        state.Result,
		MainPid:       state.MainPID,
		NRestarts:     state.NRestarts,
	}
}

// peerCredentials reads the peer identity from the kernel through SO_PEERCRED.
func peerCredentials(conn *net.UnixConn) (uid uint32, pid int32, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var credentials *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return credentials.Uid, credentials.Pid, nil
}

// ListenerFromSystemd returns the socket passed through socket activation.
func ListenerFromSystemd() (net.Listener, bool, error) {
	if os.Getenv("LISTEN_PID") != fmt.Sprint(os.Getpid()) {
		return nil, false, nil
	}
	if os.Getenv("LISTEN_FDS") != "1" {
		return nil, false, nil
	}
	const firstSocketFD = 3
	file := os.NewFile(firstSocketFD, "flotestro-helper.socket")
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, false, fmt.Errorf("socket from systemd: %w", err)
	}
	return listener, true, nil
}

// repairPackages unblocks package operations on the host.
func (s *Server) repairPackages(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.PackageRepairRequest) *helperv1.HelperResponse {
	manager, err := s.detectPackages()
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	// pacman has no configuration questions: its repair removes the lock a
	// crashed pacman left behind and checks the local database.
	if pacman, ok := manager.(*packages.Pacman); ok {
		return s.repairPacman(ctx, request, pacman)
	}
	apt, ok := manager.(*packages.APT)
	if !ok {
		// On other system families the block looks different and the repair would
		// look different too; pretending the operation works would be worse than a
		// clear refusal.
		return reject(ErrorUnsupported,
			"package repair is supported only for the apt and pacman managers")
	}

	answers := make([]packages.Answer, 0, len(action.GetAnswers()))
	for _, answer := range action.GetAnswers() {
		answers = append(answers, packages.Answer{
			Package:  answer.GetPackage(),
			Question: answer.GetQuestion(),
			Type:     answer.GetType(),
			Value:    answer.GetValue(),
		})
	}

	// A repair is a package transaction like any other: it must not run next
	// to an upgrade on the same database.
	release, busy := s.hold(GuardPackages, request)
	if busy != nil {
		return busy
	}
	defer release()

	repairCtx, cancel := deadline(ctx, request, 30*time.Minute, 2*time.Hour)
	defer cancel()
	repairCtx = s.scopeContext(repairCtx, request.GetTaskId(), opspec.FamilyPackages)

	answered, remaining, err := apt.Repair(repairCtx, answers)
	response := &helperv1.PackageRepairResponse{
		Manager:      apt.Name(),
		Answered:     answered,
		StillBlocked: blockedToProto(remaining),
		Repaired:     len(remaining) == 0,
	}
	if err != nil {
		s.log.Warn("the package repair failed",
			"task_id", request.GetTaskId(), "err", err, "remaining", len(remaining))
		return &helperv1.HelperResponse{
			Accepted:     false,
			ErrorCode:    ErrorExecFailed,
			Message:      err.Error(),
			RepairResult: response,
		}
	}

	s.log.Info("packages unblocked",
		"task_id", request.GetTaskId(), "answers", len(answered))
	return &helperv1.HelperResponse{Accepted: true, RepairResult: response}
}

// repairPacman unblocks package operations on Arch.
func (s *Server) repairPacman(ctx context.Context, request *helperv1.HelperRequest,
	pacman *packages.Pacman) *helperv1.HelperResponse {
	release, busy := s.hold(GuardPackages, request)
	if busy != nil {
		return busy
	}
	defer release()

	repairCtx, cancel := deadline(ctx, request, 30*time.Minute, 2*time.Hour)
	defer cancel()
	repairCtx = s.scopeContext(repairCtx, request.GetTaskId(), opspec.FamilyPackages)

	steps, remaining, err := pacman.Repair(repairCtx)
	response := &helperv1.PackageRepairResponse{
		Manager:      pacman.Name(),
		Answered:     steps,
		StillBlocked: blockedToProto(remaining),
		Repaired:     err == nil && len(remaining) == 0,
	}
	if err != nil {
		s.log.Warn("the package repair failed",
			"task_id", request.GetTaskId(), "err", err, "remaining", len(remaining))
		return &helperv1.HelperResponse{
			Accepted:     false,
			ErrorCode:    packageErrorCode(err),
			Message:      err.Error(),
			RepairResult: response,
		}
	}
	s.log.Info("the package database was checked",
		"task_id", request.GetTaskId(), "steps", len(steps))
	return &helperv1.HelperResponse{Accepted: true, RepairResult: response}
}

func blockedToProto(blocked []packages.Blocked) []*helperv1.BlockedPackageDetail {
	result := make([]*helperv1.BlockedPackageDetail, 0, len(blocked))
	for _, pkg := range blocked {
		questions := make([]*helperv1.DebconfQuestionDetail, 0, len(pkg.Questions))
		for _, question := range pkg.Questions {
			questions = append(questions, &helperv1.DebconfQuestionDetail{
				Name: question.Name, Value: question.Value, Answered: question.Answered,
			})
		}
		result = append(result, &helperv1.BlockedPackageDetail{
			Name: pkg.Name, Status: pkg.Status, Kind: pkg.Kind, Questions: questions,
		})
	}
	return result
}

// packageLifecycle performs an installation, a removal or a hold. Each of
// these operations exists only for managers that support it.
func (s *Server) packageLifecycle(ctx context.Context, manager packages.Manager,
	action *helperv1.PackageActionRequest, options packages.Options) *helperv1.HelperResponse {
	lifecycle, ok := manager.(packages.Lifecycle)
	if !ok {
		return reject(ErrorUnsupported,
			"the manager "+manager.Name()+" does not support the full package lifecycle")
	}

	var apply packages.Apply
	var err error
	switch action.GetOperation() {
	case helperv1.PackageActionRequest_OPERATION_INSTALL:
		options.AllowDowngrade = action.GetAllowDowngrade()
		// Replacing the agent itself must not run in the helper's control group: the
		// scripts of that package stop the helper, and with it the package manager
		// in the middle of the transaction.
		if spec, selfReplacement := agentReplacement(options.Packages); selfReplacement {
			return s.orderAgentReplacement(ctx, manager, spec, action)
		}
		apply, err = lifecycle.Install(ctx, options)
	case helperv1.PackageActionRequest_OPERATION_REMOVE:
		apply, err = lifecycle.Remove(ctx, options, action.GetExpectedRemovals())
	case helperv1.PackageActionRequest_OPERATION_HOLD:
		apply, err = lifecycle.SetHold(ctx, options.Packages, action.GetHold())
	}
	if err != nil {
		response := packageFailure(manager.Name(), err)
		response.PackageResult = packageResultToProto(apply)
		response.PackageResult.Manager = manager.Name()
		return response
	}
	return &helperv1.HelperResponse{
		Accepted:      true,
		PackageResult: packageResultToProto(apply),
	}
}
