package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/opspec"
)

// certificateProbe assembles the picture of the certificates of the host for
// the inventory.
var certificateProbe func(context.Context) (certificates.Snapshot, error)

// SetCertificateProbe points at the function that assembles the picture of the
// certificates.
func SetCertificateProbe(probe func(context.Context) (certificates.Snapshot, error)) {
	certificateProbe = probe
}

// certificateFactCodes translates the fact names of the module into the
// enumeration of the protocol.
var certificateFactCodes = map[string]helperv1.CertificateRequest_Fact{
	certificates.FaktMetadaneKluczy: helperv1.CertificateRequest_FACT_KEY_METADATA,
	certificates.FaktSledzenie:      helperv1.CertificateRequest_FACT_RENEWAL_TRACKING,
	certificates.FaktTrescPliku:     helperv1.CertificateRequest_FACT_CERTIFICATE_FILES,
}

// CollectCertificates assembles the picture of the certificates of the host.
//
// The order follows from where the knowledge comes from. First the helper is
// asked what the host watches on its own and which files the panel asked about
// earlier - because only that sets the scope. Then the files are read without
// root privileges, because a certificate is public. Finally the helper is asked
// for what cannot be seen without root: the permissions of the keys and the
// files closed to everyone but the service.
func (e *TaskExecutor) CollectCertificates(ctx context.Context,
	targets []certificates.Cel, fullList bool) certificates.Snapshot {
	scope, tracking := e.certificateScope(ctx, targets, fullList)

	snapshot := certificates.Skanuj(scope)
	missing := snapshot.Brakujace()
	if len(missing) > 0 {
		supplement, err := e.certificateFacts(ctx, missing, scope, false)
		if err != nil {
			for _, name := range missing {
				snapshot.Missing[name] = "helper: " + err.Error()
			}
		} else {
			snapshot = snapshot.Uzupelnij(supplement)
		}
	}
	// The state of the certmonger requests is already known from the first
	// question: it is not asked a second time only because the scan reported it
	// as missing.
	if tracking != nil {
		snapshot = snapshot.Uzupelnij(*tracking)
	}
	// The trust store is read by the agent: the anchor directory is readable by
	// everyone, so there is no reason to go to root for it. Without that read a
	// rotation of the authority is invisible from the panel.
	store := certificates.CzytajKotwice(certificates.WykryjMagazyn(certificates.Istnieje))
	snapshot.Trust = &store
	return snapshot
}

// certificateScope decides which files to look at.
func (e *TaskExecutor) certificateScope(ctx context.Context,
	targets []certificates.Cel, fullList bool) ([]certificates.Cel, *certificates.Uzupelnienie) {
	supplement, err := e.certificateFacts(ctx,
		[]string{certificates.FaktSledzenie}, targets, fullList)
	if err != nil {
		return targets, nil
	}
	scope := supplement.Targets
	if len(scope) == 0 {
		scope = targets
	}
	// The certificates under the care of certmonger are added to the scope,
	// because the host knows about them itself. Without that the tab would show
	// emptiness on a host that has its own domain certificate and has been
	// renewing it for months.
	scope = certificates.DodajSledzone(scope, supplement.Tracking)
	return scope, &supplement
}

// certificateFacts orders the enumerated facts from the helper.
func (e *TaskExecutor) certificateFacts(ctx context.Context, names []string,
	targets []certificates.Cel, fullList bool) (certificates.Uzupelnienie, error) {
	requested := make([]helperv1.CertificateRequest_Fact, 0, len(names))
	for _, name := range names {
		if fact, known := certificateFactCodes[name]; known {
			requested = append(requested, fact)
		}
	}
	if len(requested) == 0 {
		return certificates.Uzupelnienie{}, nil
	}

	request := &helperv1.CertificateRequest{
		Operation:     helperv1.CertificateRequest_OPERATION_FACTS,
		Facts:         requested,
		Authoritative: fullList,
	}
	for _, target := range targets {
		request.Targets = append(request.Targets, &helperv1.CertificateTarget{
			Path: target.Path, KeyPath: target.KeyPath, Service: target.Service,
		})
	}

	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action:         &helperv1.HelperRequest_Certificate{Certificate: request},
	}, time.Minute)
	if err != nil {
		return certificates.Uzupelnienie{}, err
	}
	if !response.GetAccepted() {
		return certificates.Uzupelnienie{}, errors.New("helper: " + response.GetMessage())
	}
	var supplement certificates.Uzupelnienie
	data := response.GetCertificateResult().GetFacts()
	if len(data) == 0 {
		return supplement, nil
	}
	if err := json.Unmarshal(data, &supplement); err != nil {
		return certificates.Uzupelnienie{}, err
	}
	return supplement, nil
}

// ProbeCertificates reads the picture of the certificates for the inventory.
//
// The inventory brings no list of the panel with it: the scope comes from what
// the host already knows - from the registry of the helper and from the
// certmonger requests. That is why the list here is not the full list of the
// panel and erases nothing in the registry.
func (e *TaskExecutor) ProbeCertificates(ctx context.Context) (certificates.Snapshot, error) {
	return e.CollectCertificates(ctx, nil, false), nil
}

// applyCertificate performs the operations of the certificate module.
func (e *TaskExecutor) applyCertificate(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.CertificatePayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	if action == opspec.ActionCertificateScan {
		targets := make([]certificates.Cel, 0)
		if payload != nil {
			for _, target := range payload.Targets {
				targets = append(targets, certificates.Cel{
					Path: target.Path, KeyPath: target.KeyPath, Service: target.Service,
				})
			}
		}
		// A scan ordered by the panel carries its full list of targets, so the
		// host remembers exactly that one: a target deleted in the panel is to
		// disappear from the inventory as well and not stay in it forever.
		snapshot := e.CollectCertificates(callCtx, targets, true)
		return certificateResult(task, snapshot, "the certificates were read", nil)
	}

	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the certificate payload is missing")
	}

	request := &helperv1.CertificateRequest{
		Operation:   helperv1.CertificateRequest_OPERATION_RENEW,
		AnchorId:    payload.AnchorID,
		Path:        payload.Path,
		KeyPath:     payload.KeyPath,
		Owner:       payload.Owner,
		Group:       payload.Group,
		Mode:        payload.Mode,
		KeyMode:     payload.KeyMode,
		ReloadUnit:  payload.ReloadUnit,
		ProbeTarget: payload.ProbeTarget,
		Request:     payload.Request,
	}
	switch action {
	case opspec.ActionCertificateTrustPlan:
		request.Operation = helperv1.CertificateRequest_OPERATION_TRUST_PLAN
		request.Certificate = []byte(payload.Certificate)
	case opspec.ActionCertificateTrustEnsure:
		// An anchor is public material: it travels in the order in the clear, and
		// the plan shows it to the operator before the consent.
		request.Operation = helperv1.CertificateRequest_OPERATION_TRUST_ENSURE
		request.Certificate = []byte(payload.Certificate)
		request.PlanHash = payload.PlanHash
	case opspec.ActionCertificateTrustRemove:
		request.Operation = helperv1.CertificateRequest_OPERATION_TRUST_REMOVE
		request.PlanHash = payload.PlanHash
	}

	if action == opspec.ActionCertificateRenew {
		request.PlanHash = payload.PlanHash
	}
	if action == opspec.ActionCertificatePlan {
		// The plan does not reach for the private key: it describes a deployment
		// that has not happened yet, and the plan itself lands in the panel
		// database.
		request.Operation = helperv1.CertificateRequest_OPERATION_PLAN
		request.Certificate = []byte(payload.Certificate)
		if !payload.KeySecret.Empty() {
			request.KeySecretRef = payload.KeySecret.String()
		}
	}
	if action == opspec.ActionCertificateDeploy {
		request.Operation = helperv1.CertificateRequest_OPERATION_DEPLOY
		request.Certificate = []byte(payload.Certificate)
		request.PlanHash = payload.PlanHash
		if !payload.KeySecret.Empty() {
			request.KeySecretRef = payload.KeySecret.String()
		}
		// The key is fetched only now, right before the swap. The value lives
		// for a moment in the memory of the agent and of the helper - it is not
		// in the envelope of the task, in the journal or in the result.
		if !payload.KeySecret.Empty() {
			if e.secrets == nil {
				return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError,
					"the agent has no connection through which a secret could be fetched")
			}
			value, err := e.secrets(callCtx, task.GetTaskId(),
				payload.KeySecret.Name, payload.KeySecret.Version)
			if err != nil {
				// The reason for the refusal is the content of the result; the
				// value is not in it.
				return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition,
					"the secret "+payload.KeySecret.Name+" was not fetched: "+err.Error())
			}
			request.Key = value
		}
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action:         &helperv1.HelperRequest_Certificate{Certificate: request},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	result := response.GetCertificateResult()
	details := &agentv1.CertificateResult{
		Message:           result.GetMessage(),
		FingerprintSha256: result.GetFingerprintSha256(),
		NotAfter:          result.GetNotAfter(),
		Probe:             result.GetProbe(),
		RolledBack:        result.GetRolledBack(),
		Plan:              result.GetPlan(),
		Trust:             result.GetTrust(),
	}
	if !response.GetAccepted() {
		refused := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		refused.TaskId = task.GetTaskId()
		refused.CertificateResult = details
		return refused
	}

	// The picture after the operation is assembled by the agent, exactly as with
	// an ordinary scan: the panel is to see the file that really lies on the
	// host, not the one it sent.
	snapshot := e.CollectCertificates(callCtx, nil, false)
	return certificateResult(task, snapshot, result.GetMessage(), details)
}

// certificateResult assembles the result of the task together with the picture
// after the operation.
func certificateResult(task *agentv1.TaskEnvelope, snapshot certificates.Snapshot,
	message string, details *agentv1.CertificateResult) *agentv1.TaskResult {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	if details == nil {
		details = &agentv1.CertificateResult{}
	}
	details.Snapshot = encoded
	if details.Message == "" {
		details.Message = message
	}
	return &agentv1.TaskResult{
		TaskId:            task.GetTaskId(),
		Status:            agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:           message,
		CertificateResult: details,
	}
}
