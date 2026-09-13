package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/files"
)

// CertificateRegistryPath holds the targets the panel asked about on this host.
//
// The registry is local for the same reason as with managed files: it is the
// host that has to be able to say what the certificates of its services look
// like now - also when the panel is not asking. Without it the tab would show
// the state from before the last scan, and an expiring certificate would be
// noticed only by whoever asks about it.
const CertificateRegistryPath = "/var/lib/flotestro-helper/certificates.json"

// certificateFactNames translates the protocol enumeration into fact names.
//
// The translation exists so that the helper does not accept an arbitrary
// string: the scope of its work is a closed list, not a text from the agent.
var certificateFactNames = map[helperv1.CertificateRequest_Fact]string{
	helperv1.CertificateRequest_FACT_KEY_METADATA:      certificates.FactKeyMetadata,
	helperv1.CertificateRequest_FACT_RENEWAL_TRACKING:  certificates.FactTracking,
	helperv1.CertificateRequest_FACT_CERTIFICATE_FILES: certificates.FactCertificateFiles,
}

// applyCertificate handles the operations of the certificate module.
func (s *Server) applyCertificate(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.CertificateRequest_OPERATION_FACTS:
		return s.certificateFacts(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_PLAN:
		// A plan without material is a renewal plan: a deployment always carries
		// a certificate, a renewal never - the host daemon goes for the new one.
		if len(action.GetCertificate()) == 0 {
			return s.planRenewal(actionCtx, action)
		}
		return s.planCertificate(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_TRUST_PLAN:
		return s.planTrust(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_TRUST_ENSURE,
		helperv1.CertificateRequest_OPERATION_TRUST_REMOVE:
		return s.changeTrust(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_DEPLOY:
		return s.deployCertificate(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_RENEW:
		return s.renewCertificate(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "unknown operation of the certificate module")
}

// requestTargets reads the targets from the order and checks every path with
// its own rule.
func requestTargets(action *helperv1.CertificateRequest) ([]certificates.Target, *helperv1.HelperResponse) {
	targets := make([]certificates.Target, 0, len(action.GetTargets()))
	for _, target := range action.GetTargets() {
		if err := certificates.ValidatePath(target.GetPath()); err != nil {
			return nil, reject(ErrorMalformed, err.Error())
		}
		if target.GetKeyPath() != "" {
			if err := certificates.ValidatePath(target.GetKeyPath()); err != nil {
				return nil, reject(ErrorMalformed, err.Error())
			}
		}
		targets = append(targets, certificates.Target{
			Path: target.GetPath(), KeyPath: target.GetKeyPath(), Service: target.GetService(),
		})
	}
	return targets, nil
}

// certificateFacts reads only the facts the agent asked for.
func (s *Server) certificateFacts(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	requested := action.GetFacts()
	if len(requested) == 0 {
		return reject(ErrorMalformed, "the order names no fact")
	}
	names := make([]string, 0, len(requested))
	for _, fact := range requested {
		name, known := certificateFactNames[fact]
		if !known {
			return reject(ErrorMalformed, "unknown fact "+fact.String())
		}
		names = append(names, name)
	}

	targets, refusal := requestTargets(action)
	if refusal != nil {
		return refusal
	}
	// The list from the panel replaces the registry only when the panel says it
	// is complete. An ordinary inventory read erases nothing: the agent then
	// asks for facts without targets and gets what the host already knows.
	if action.GetAuthoritative() {
		s.writeCertificateRegistry(targets)
	}
	knownTargets := mergeTargets(s.certificateRegistry(), targets)
	// The registry remembers deployment targets, and their files are sometimes
	// deleted outside the panel. A target without a file is not knowledge - it
	// is litter that takes up room in the read and pushes out of it the
	// certificates the host really has. It is forgotten only when the file is
	// gone: an unreadable file is a different answer than a missing one.
	if alive := targetsWithAnExistingFile(knownTargets); len(alive) != len(knownTargets) {
		knownTargets = alive
		s.writeCertificateRegistry(alive)
	}

	supplement := certificates.CollectSupplement(ctx, toolOutput, names, knownTargets)
	supplement.Targets = knownTargets
	encoded, err := json.Marshal(supplement)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:          true,
		CertificateResult: &helperv1.CertificateResult{Facts: encoded},
	}
}

// planCertificate computes the difference between the certificate the host has
// under the path and the one from the order. It touches no files and does not
// reach for the private key: the plan lands in the panel database, so it must
// not carry any material.
func (s *Server) planCertificate(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	plan := s.certificatePlan(action)
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the deployment will not enter this host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == certificates.PlanNoChange:
		message = "the host already has this certificate under " + plan.Path
	default:
		message = strings.Join(plan.Changes, "; ")
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		CertificateResult: &helperv1.CertificateResult{
			Message: message, Plan: encoded,
			FingerprintSha256: plan.DesiredFingerprint,
		},
	}
}

// certificatePlan assembles the deployment plan against the file the host has
// now.
func (s *Server) certificatePlan(action *helperv1.CertificateRequest) certificates.Plan {
	current := certificates.Certificate{}
	if err := certificates.ValidatePath(action.GetPath()); err == nil {
		snapshot := certificates.Scan([]certificates.Target{{
			Path: action.GetPath(), KeyPath: action.GetKeyPath(),
			Service: action.GetReloadUnit(),
		}})
		if len(snapshot.Certificates) > 0 {
			current = snapshot.Certificates[0]
		}
	}
	return certificates.Compute(current, certificates.Order{
		Path:        action.GetPath(),
		KeyPath:     action.GetKeyPath(),
		Certificate: string(action.GetCertificate()),
		KeySecret:   action.GetKeySecretRef(),
		Unit:        action.GetReloadUnit(),
		Target:      action.GetProbeTarget(),
		HasKey:      action.GetKeySecretRef() != "" || len(action.GetKey()) > 0,
	}, time.Now())
}

// deployCertificate replaces the certificate and the key, and then checks the
// effect.
//
// The order is the whole content here: everything that can be checked without
// touching the disk is checked before the first write; the previous content is
// kept in memory; and if the service does not show the new certificate after a
// reload, the previous one comes back and this is said directly. A deployment
// that leaves a service dead is not a deployment.
func (s *Server) deployCertificate(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	// A deployment approved on the basis of a plan is to enter the state the
	// operator looked at: a different certificate under that path than at
	// planning time is a refusal, not a warning.
	if expected := action.GetPlanHash(); expected != "" {
		if now := s.certificatePlan(action); now.PlanHash != expected {
			return reject(ErrorPreconditionFailed,
				"the certificate under "+action.GetPath()+" changed since the planning; the deployment needs a new plan")
		}
	}
	deployment := certificates.Deployment{
		Path:        action.GetPath(),
		KeyPath:     action.GetKeyPath(),
		Certificate: action.GetCertificate(),
		Key:         action.GetKey(),
		Owner:       action.GetOwner(),
		Group:       action.GetGroup(),
		Mode:        action.GetMode(),
		KeyMode:     action.GetKeyMode(),
		Unit:        action.GetReloadUnit(),
		Target:      action.GetProbeTarget(),
	}
	parsed, err := certificates.Check(deployment, time.Now())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	fingerprint := certificates.Fingerprint(parsed[0])

	uid, gid, err := files.Ownership(deployment.Owner, deployment.Group)
	if err != nil {
		return reject(ErrorPreconditionFailed, err.Error())
	}

	certificateCopy, err := certificates.Remember(deployment.Path)
	if err != nil {
		return reject(ErrorExecFailed, "the previous certificate was not read: "+err.Error())
	}
	keyCopy, err := certificates.Remember(deployment.KeyPath)
	if err != nil {
		return reject(ErrorExecFailed, "the previous key was not read: "+err.Error())
	}
	undo := func() bool {
		certificateErr := certificateCopy.Restore()
		keyErr := keyCopy.Restore()
		if deployment.Unit != "" {
			_, _ = runTool(ctx,
				[]string{"/usr/bin/systemctl", "reload-or-restart", deployment.Unit})
		}
		return certificateErr == nil && keyErr == nil
	}

	if err := certificates.Write(deployment, uid, gid); err != nil {
		undo()
		return reject(ErrorExecFailed, "the certificate was not written: "+err.Error())
	}

	message := "the certificate was written"
	if deployment.Unit != "" {
		// A reload and not a restart wherever the service supports one: the
		// connections already running are to survive the certificate swap.
		if output, err := runTool(ctx,
			[]string{"/usr/bin/systemctl", "reload-or-restart", deployment.Unit}); err != nil {
			undone := undo()
			return deploymentRefusal(fingerprint, parsed[0].NotAfter,
				"reloading "+deployment.Unit+" failed: "+output, undone)
		}
		message += "; " + deployment.Unit + " was reloaded"
	}

	var probe certificates.ProbeResult
	if deployment.Target != "" {
		probe = certificates.Probe(ctx, deployment.Target)
		if !probe.Confirms(fingerprint) {
			reason := probe.Error
			if reason == "" {
				reason = "the service presents a different certificate than the deployed one"
			}
			undone := undo()
			response := deploymentRefusal(fingerprint, parsed[0].NotAfter,
				"the probe "+deployment.Target+": "+reason, undone)
			response.CertificateResult.Probe = encodeProbe(probe)
			return response
		}
		message += "; the service shows the new certificate"
	}

	s.rememberCertificate(certificates.Target{
		Path: deployment.Path, KeyPath: deployment.KeyPath, Service: deployment.Unit,
	})
	return &helperv1.HelperResponse{
		Accepted: true,
		CertificateResult: &helperv1.CertificateResult{
			Message:           message,
			FingerprintSha256: fingerprint,
			NotAfter:          parsed[0].NotAfter.UTC().Format(time.RFC3339),
			Probe:             encodeProbe(probe),
		},
	}
}

// renewCertificate asks certmonger for a new certificate on the same request.
//
// The panel gives no material here: the renewal is done by the host daemon,
// which has its own key and its own arrangement with the authority. The job of
// the panel is to ask and to check whether anything came of it.
func (s *Server) renewCertificate(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	tool := certificates.ToolPath()
	if tool == "" {
		return reject(ErrorUnsupported, "this host has no certmonger")
	}
	// A renewal approved on the basis of a plan is to concern the request the
	// operator looked at: a different request under that path than at planning
	// time is a refusal, not a silent renewal of something else.
	if expected := action.GetPlanHash(); expected != "" {
		if now := s.renewalPlan(ctx, action); now.PlanHash != expected {
			return reject(ErrorPreconditionFailed,
				"the certmonger request under "+action.GetPath()+
					" changed since the planning; the renewal needs a new plan")
		}
	}

	// The panel names the request by an identifier or by a file path. The
	// identifier differs on every host, so a campaign renewing the same
	// certificate across the whole fleet can give only the path - and the host
	// finds the request itself.
	request := action.GetRequest()
	if request == "" {
		path := action.GetPath()
		if err := certificates.ValidatePath(path); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		output, err := toolOutput(ctx, tool, "list")
		if err != nil {
			return reject(ErrorExecFailed, "getcert list: "+err.Error()+" "+output)
		}
		tracking, watched := certificates.ParseGetcert(output)[path]
		if !watched || tracking.Request == "" {
			return reject(ErrorPreconditionFailed,
				"certmonger does not watch the file "+path+", so there is nothing to renew")
		}
		request = tracking.Request
	}
	if err := certificates.ValidateRequest(request); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	if output, err := toolOutput(ctx, tool,
		"resubmit", "-i", request, "-w"); err != nil {
		return reject(ErrorExecFailed, "getcert resubmit: "+err.Error()+" "+output)
	}

	// A request sent is not a certificate renewed: the daemon is asked what
	// state it is in now and what lies on the disk.
	state := certificates.Tracking{}
	if output, err := toolOutput(ctx, tool, "list", "-i", request); err == nil {
		for _, tracking := range certificates.ParseGetcert(output) {
			state = tracking
			break
		}
	}
	message := "the renewal was requested"
	if state.Status != "" {
		message += "; certmonger reports " + state.Status
	}

	result := &helperv1.CertificateResult{Message: message}
	if state.Expires != nil {
		result.NotAfter = state.Expires.UTC().Format(time.RFC3339)
	}

	if unit := action.GetReloadUnit(); unit != "" {
		if err := certificates.ValidateUnit(unit); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if output, err := runTool(ctx,
			[]string{"/usr/bin/systemctl", "reload-or-restart", unit}); err != nil {
			return reject(ErrorExecFailed, "reloading "+unit+": "+output)
		}
		result.Message += "; " + unit + " was reloaded"
	}
	if target := action.GetProbeTarget(); target != "" {
		probe := certificates.Probe(ctx, target)
		result.Probe = encodeProbe(probe)
		result.FingerprintSha256 = probe.FingerprintSHA256
		if !probe.Reachable {
			result.Message += "; the probe " + target + " does not answer"
		}
	}
	return &helperv1.HelperResponse{Accepted: true, CertificateResult: result}
}

// deploymentRefusal assembles the answer about a failed deployment together
// with whether the host went back to its previous state.
func deploymentRefusal(fingerprint string, deadline time.Time, reason string, undone bool) *helperv1.HelperResponse {
	message := reason
	if undone {
		message += "; the previous certificate was restored"
	} else {
		// A failed return is worse news than a failed deployment and must not
		// get lost in the same sentence.
		message += "; the previous certificate was NOT restored"
	}
	return &helperv1.HelperResponse{
		Accepted:  false,
		ErrorCode: ErrorPreconditionFailed,
		Message:   message,
		CertificateResult: &helperv1.CertificateResult{
			Message:           message,
			FingerprintSha256: fingerprint,
			NotAfter:          deadline.UTC().Format(time.RFC3339),
			RolledBack:        undone,
		},
	}
}

func encodeProbe(probe certificates.ProbeResult) []byte {
	if probe.Target == "" {
		return nil
	}
	data, err := json.Marshal(probe)
	if err != nil {
		return nil
	}
	return data
}

// mergeTargets merges the list from the registry with the list from the order,
// without repetitions.
func mergeTargets(registry, targets []certificates.Target) []certificates.Target {
	result := make([]certificates.Target, 0, len(registry)+len(targets))
	positions := map[string]int{}
	add := func(target certificates.Target) {
		if i, known := positions[target.Path]; known {
			// Newer knowledge wins: the panel can add a key or a service to a
			// target the host knew earlier from the path alone.
			if target.KeyPath != "" {
				result[i].KeyPath = target.KeyPath
			}
			if target.Service != "" {
				result[i].Service = target.Service
			}
			return
		}
		positions[target.Path] = len(result)
		result = append(result, target)
	}
	for _, target := range registry {
		add(target)
	}
	for _, target := range targets {
		add(target)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

func (s *Server) certificateRegistry() []certificates.Target {
	data, err := os.ReadFile(CertificateRegistryPath)
	if err != nil {
		return nil
	}
	var targets []certificates.Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil
	}
	return targets
}

func (s *Server) rememberCertificate(target certificates.Target) {
	s.writeCertificateRegistry(mergeTargets(s.certificateRegistry(), []certificates.Target{target}))
}

func (s *Server) writeCertificateRegistry(targets []certificates.Target) {
	data, err := json.Marshal(targets)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(CertificateRegistryPath), 0o700)
	temporary := CertificateRegistryPath + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(temporary, CertificateRegistryPath)
}

// trustStore reads the anchors the host has now.
func (s *Server) trustStore() certificates.TrustStore {
	return certificates.ReadAnchors(certificates.DetectStore(exists))
}

// trustPlan assembles the plan of a rotation step against the state of the
// store.
//
// A removal also looks at the host certificates: an authority that still signs
// something must not disappear from the store, because that would break the
// trust of clients who changed nothing.
func (s *Server) trustPlan(ctx context.Context, action *helperv1.CertificateRequest,
	store certificates.TrustStore) certificates.TrustPlan {
	// A plan without material is a withdrawal plan: trust always carries the
	// certificate of the authority, a withdrawal never does. The planning
	// operation is one for both rotation steps, so the kind is recognized by the
	// fields.
	removal := action.GetOperation() == helperv1.CertificateRequest_OPERATION_TRUST_REMOVE ||
		(action.GetOperation() == helperv1.CertificateRequest_OPERATION_TRUST_PLAN &&
			len(action.GetCertificate()) == 0)
	if removal {
		return certificates.ComputeAnchorRemoval(store, action.GetAnchorId(),
			s.hostCertificates(ctx))
	}
	return certificates.ComputeAnchor(store, action.GetAnchorId(),
		string(action.GetCertificate()), time.Now())
}

// hostCertificates reads the certificates the host keeps under the observation
// of the panel.
func (s *Server) hostCertificates(ctx context.Context) []certificates.Certificate {
	targets := s.certificateRegistry()
	if len(targets) == 0 {
		return nil
	}
	snapshot := certificates.Scan(targets)
	snapshot = snapshot.Supplemented(certificates.CollectSupplement(ctx, toolOutput,
		snapshot.MissingFacts(), targets))
	return snapshot.Certificates
}

// planTrust computes a rotation step without touching the store.
func (s *Server) planTrust(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	store := s.trustStore()
	plan := s.trustPlan(ctx, action, store)
	return trustResponse(store, plan, describeTrustPlan(plan), nil)
}

// changeTrust adds or withdraws a panel anchor and recomputes the store.
//
// The order is the whole content here: the file enters the anchor directory,
// the tool recomputes the bundle, and only the finished bundle is the answer.
// The file alone without the recomputation changes nothing - and would look
// like a change that is not there.
func (s *Server) changeTrust(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	store := s.trustStore()
	if store.UnavailableReason != "" {
		return reject(ErrorUnsupported, store.UnavailableReason)
	}
	plan := s.trustPlan(ctx, action, store)
	if plan.Refusal != "" {
		return reject(ErrorPreconditionFailed, plan.Refusal)
	}
	// A change approved on the basis of a plan is to enter the state the
	// operator looked at: a different anchor under that name than at planning
	// time is a refusal.
	if expected := action.GetPlanHash(); expected != "" && plan.PlanHash != expected {
		return reject(ErrorPreconditionFailed,
			"the trust store changed since the planning; the step needs a new plan")
	}

	removal := action.GetOperation() == helperv1.CertificateRequest_OPERATION_TRUST_REMOVE
	path := certificates.AnchorPath(store, action.GetAnchorId())
	if path == "" {
		return reject(ErrorMalformed, "the path of the anchor cannot be assembled")
	}
	previous, err := certificates.Remember(path)
	if err != nil {
		return reject(ErrorExecFailed, "the previous anchor was not read: "+err.Error())
	}

	switch {
	case removal:
		if plan.Action == certificates.PlanRemoveAbsent {
			return trustResponse(s.trustStore(), plan,
				"the host did not trust this authority, so there is nothing to withdraw", nil)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return reject(ErrorExecFailed, "removing the anchor: "+err.Error())
		}
	default:
		if plan.Action == certificates.PlanNoChange {
			return trustResponse(store, plan,
				"the host already trusts this authority", nil)
		}
		material, _, err := certificates.ComposeAnchor(string(action.GetCertificate()), time.Now())
		if err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if err := writeKernelFile(path, string(material), 0o644); err != nil {
			return reject(ErrorExecFailed, "writing the anchor: "+err.Error())
		}
	}

	if output, err := runTool(ctx, recomputeCommand(store)); err != nil {
		// A store that cannot be recomputed would leave the host with the bundle
		// from before the change and an anchor nobody saw. The previous file
		// comes back and the recomputation is tried once more.
		_ = previous.Restore()
		_, _ = runTool(ctx, recomputeCommand(store))
		return reject(ErrorExecFailed, "recomputing the trust store: "+err.Error()+": "+output)
	}

	message := "the host trusts the authority " + plan.DesiredSubject
	if removal {
		message = "the host stopped trusting the authority " + plan.AnchorID
	}
	return trustResponse(s.trustStore(), plan, message, nil)
}

// recomputeCommand assembles the invocation of the store tool.
func recomputeCommand(store certificates.TrustStore) []string {
	if store.Adapter == certificates.AdapterRHEL {
		return []string{store.Tool, "extract"}
	}
	return []string{store.Tool}
}

// describeTrustPlan sums the plan up in one sentence for the operation journal.
func describeTrustPlan(plan certificates.TrustPlan) string {
	switch {
	case plan.Refusal != "":
		return "the step will not enter this host: " + plan.Refusal
	case plan.Action == certificates.PlanNoChange:
		return "the host already trusts this authority"
	case plan.Action == certificates.PlanRemoveAbsent:
		return "the host does not trust this authority, so there is nothing to withdraw"
	default:
		return strings.Join(plan.Changes, "; ")
	}
}

func trustResponse(store certificates.TrustStore, plan certificates.TrustPlan,
	message string, _ error) *helperv1.HelperResponse {
	encodedPlan, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	encodedStore, err := json.Marshal(store)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		CertificateResult: &helperv1.CertificateResult{
			Message: message, Plan: encodedPlan, Trust: encodedStore,
			FingerprintSha256: plan.DesiredFingerprint,
		},
	}
}

// planRenewal computes the renewal plan without asking the authority for
// anything.
func (s *Server) planRenewal(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	plan := s.renewalPlan(ctx, action)
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the renewal will not enter this host: " + plan.Refusal
	if plan.Refusal == "" {
		message = strings.Join(plan.Changes, "; ")
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		CertificateResult: &helperv1.CertificateResult{
			Message: message, Plan: encoded,
			FingerprintSha256: plan.CurrentFingerprint,
		},
	}
}

// renewalPlan assembles the plan against what the host has and what watches the
// certificate.
func (s *Server) renewalPlan(ctx context.Context,
	action *helperv1.CertificateRequest) certificates.RenewalPlan {
	path := action.GetPath()
	tool := certificates.ToolPath()

	current := certificates.Certificate{}
	if err := certificates.ValidatePath(path); err == nil {
		snapshot := certificates.Scan([]certificates.Target{{
			Path: path, KeyPath: action.GetKeyPath(), Service: action.GetReloadUnit(),
		}})
		if len(snapshot.Certificates) > 0 {
			current = snapshot.Certificates[0]
		}
	}

	var tracking *certificates.Tracking
	if tool != "" {
		if output, err := toolOutput(ctx, tool, "list"); err == nil {
			if entry, watched := certificates.ParseGetcert(output)[path]; watched {
				found := entry
				tracking = &found
			}
		}
	}
	return certificates.ComputeRenewal(current, tracking, tool != "",
		path, action.GetReloadUnit(), time.Now())
}

// targetsWithAnExistingFile filters out the targets whose file is gone.
//
// A missing file is decided by the ENOENT error and not by every read error: a
// file in a directory closed to the helper still exists and is still a target.
func targetsWithAnExistingFile(targets []certificates.Target) []certificates.Target {
	alive := make([]certificates.Target, 0, len(targets))
	for _, target := range targets {
		if _, err := os.Lstat(target.Path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		alive = append(alive, target)
	}
	return alive
}
