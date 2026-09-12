package helper

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/docker"
)

// readDocker reads the state of the container engine.
//
// The Docker socket belongs to root, and membership in the docker group is
// equivalent to root - an agent running without privileges cannot get it. That
// is why the conversation with the engine happens here, and the helper accepts
// only an enumerated read scope, not a path into the Engine API.
func (s *Server) readDocker(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DockerReadRequest) *helperv1.HelperResponse {
	client, err := docker.New()
	if err != nil {
		return &helperv1.HelperResponse{
			Accepted: true,
			DockerResult: &helperv1.DockerReadResult{
				UnavailableReason: err.Error(),
			},
		}
	}

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = time.Minute
	}
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	snapshot := docker.Collect(readCtx, client)
	// The summary scope carries no full lists: the inventory is to stay light,
	// and the container list of a build host can have hundreds of entries.
	if action.GetScope() != helperv1.DockerReadRequest_SCOPE_FULL {
		snapshot.Containers = nil
		snapshot.Images = nil
		snapshot.Networks = nil
		snapshot.Volumes = nil
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		DockerResult: &helperv1.DockerReadResult{
			Snapshot:          encoded,
			UnavailableReason: snapshot.Summary.UnavailableReason,
		},
	}
}

// readDockerEvents reads the event journal of the engine within a closed
// window.
//
// The task ends on its own: the window and the limits are closed in the module
// and not taken from the message at its word. A read "until further notice"
// would stay on the host forever, also when the panel stopped listening to it
// long ago.
func (s *Server) readDockerEvents(ctx context.Context,
	action *helperv1.DockerEventsRequest) *helperv1.HelperResponse {
	client, err := docker.New()
	if err != nil {
		return &helperv1.HelperResponse{
			Accepted: true,
			DockerEventsResult: &helperv1.DockerEventsResult{
				UnavailableReason: err.Error(),
			},
		}
	}

	snapshot, err := docker.Events(ctx, client, docker.EventsOptions{
		Since:  time.Duration(action.GetSinceSeconds()) * time.Second,
		Follow: time.Duration(action.GetFollowSeconds()) * time.Second,
		Types:  action.GetTypes(),
		Max:    int(action.GetMaxEvents()),
	})
	if err != nil {
		return &helperv1.HelperResponse{
			Accepted: true,
			DockerEventsResult: &helperv1.DockerEventsResult{
				UnavailableReason: err.Error(),
			},
		}
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		DockerEventsResult: &helperv1.DockerEventsResult{
			Events:          encoded,
			Truncated:       snapshot.Truncated,
			TruncatedReason: snapshot.Reason,
		},
	}
}

// applyDocker performs an operation on the container engine.
//
// The container identifier is checked again even though the panel already
// checked it. The helper runs as root and cannot trust the content of the
// message: the identifier lands in the query path of the Engine API.
func (s *Server) applyDocker(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DockerActionRequest) *helperv1.HelperResponse {
	client, err := docker.New()
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}

	// At most one container mutation runs at a time: a concurrent restart and
	// removal of the same container give an unpredictable result.
	if !s.containerMutex.TryLock() {
		return reject(ErrorLocked, "another container operation is in flight")
	}
	defer s.containerMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > time.Hour {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	identifier := action.GetContainerId()
	if needsContainer(action.GetOperation()) {
		if !containerIdentifier.MatchString(identifier) {
			return reject(ErrorMalformed, "invalid container identifier")
		}
	}

	result := docker.Result{}
	if needsContainer(action.GetOperation()) {
		result.Before = client.ContainerByID(actionCtx, identifier)
		if result.Before == nil {
			return reject(ErrorUnsupported, "the container does not exist on this host")
		}
	}

	switch action.GetOperation() {
	case helperv1.DockerActionRequest_OPERATION_START:
		err = client.StartContainer(actionCtx, identifier)
	case helperv1.DockerActionRequest_OPERATION_STOP:
		err = client.StopContainer(actionCtx, identifier, action.GetTimeoutSeconds())
	case helperv1.DockerActionRequest_OPERATION_RESTART:
		err = client.RestartContainer(actionCtx, identifier, action.GetTimeoutSeconds())
	case helperv1.DockerActionRequest_OPERATION_REMOVE:
		err = client.RemoveContainer(actionCtx, identifier, action.GetRemoveVolumes())
	case helperv1.DockerActionRequest_OPERATION_PULL_IMAGE:
		var digest string
		digest, err = client.PullImage(actionCtx, action.GetImageReference())
		result.ImageDigest = digest
	case helperv1.DockerActionRequest_OPERATION_PRUNE:
		// The names and identifiers land in the query path of the Engine API,
		// and the helper runs as root: the panel already checked them, but the
		// helper cannot trust the content of the message.
		if reason := checkCleanupList(action); reason != "" {
			return reject(ErrorMalformed, reason)
		}
		result, err = docker.Prune(actionCtx, client,
			action.GetImageIds(), action.GetVolumeNames(), action.GetNetworkIds())
	default:
		return reject(ErrorUnknownAction, "unknown container operation")
	}

	// The state after the operation is read also when the operation failed:
	// without it there is no telling whether the change managed to take hold.
	if needsContainer(action.GetOperation()) {
		result.After = client.ContainerByID(actionCtx, identifier)
	}

	actionResult := &helperv1.DockerActionResult{
		Before:         encodeContainer(result.Before),
		After:          encodeContainer(result.After),
		Removed:        result.Removed,
		ReclaimedBytes: result.ReclaimedBytes,
		ImageDigest:    result.ImageDigest,
	}
	if err != nil {
		response := reject(dockerErrorCode(err), err.Error())
		response.DockerActionResult = actionResult
		return response
	}
	return &helperv1.HelperResponse{Accepted: true, DockerActionResult: actionResult}
}

// checkCleanupList repeats the validation of the panel for cleanup objects.
// It returns an empty text when the list is fine.
func checkCleanupList(action *helperv1.DockerActionRequest) string {
	for _, id := range action.GetImageIds() {
		if !imageIdentifier.MatchString(id) {
			return "invalid image identifier"
		}
	}
	for _, name := range action.GetVolumeNames() {
		if !volumeName.MatchString(name) {
			return "invalid volume name"
		}
	}
	for _, id := range action.GetNetworkIds() {
		if !containerIdentifier.MatchString(id) {
			return "invalid network identifier"
		}
	}
	return ""
}

// dockerErrorCode separates a refusal from a failure. An operator who asked to
// remove a volume in use is to see that the host refused - not that the
// execution failed.
func dockerErrorCode(err error) string {
	switch {
	case errors.Is(err, docker.ErrWUzyciu):
		return ErrorDockerInUse
	case errors.Is(err, docker.ErrSiecWbudowana):
		return ErrorDockerPredefined
	case errors.Is(err, docker.ErrNieIstnieje):
		return ErrorDockerObjectMissing
	}
	return ErrorExecFailed
}

// needsContainer says whether the operation concerns one concrete container.
func needsContainer(operation helperv1.DockerActionRequest_Operation) bool {
	switch operation {
	case helperv1.DockerActionRequest_OPERATION_START,
		helperv1.DockerActionRequest_OPERATION_STOP,
		helperv1.DockerActionRequest_OPERATION_RESTART,
		helperv1.DockerActionRequest_OPERATION_REMOVE:
		return true
	}
	return false
}

// The patterns repeat the validation of the panel. The helper does not trust
// the content of the message, because it runs as root and these values land in
// the query path of the Engine API.
var (
	containerIdentifier = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	imageIdentifier     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	volumeName          = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$`)
)

// encodeContainer turns the container state into JSON. A missing container
// stays empty: a removed container has no state after the operation and it
// must not be invented.
func encodeContainer(container *docker.Container) []byte {
	if container == nil {
		return nil
	}
	encoded, err := json.Marshal(container)
	if err != nil {
		return nil
	}
	return encoded
}
