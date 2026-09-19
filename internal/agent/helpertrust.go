package agent

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// The session and the renewal talk to the root helper about trust - the
// panel's capability keys go down to it, its capability mode comes up to the
// panel - through the one helper client the executor was built with.
var (
	sessionHelper       atomic.Pointer[HelperClient]
	helperProbeDisabled atomic.Bool
	// probeFailedAt is when the helper last failed to answer the question about
	// its mode; the question is not repeated for a while, so a host without a
	// helper does not stall every inventory cycle on it.
	probeFailedAt atomic.Int64
)

// probeRetryInterval is how long a failed probe of the helper's mode is
// remembered before the helper is asked again.
const probeRetryInterval = 10 * time.Minute

// registerSessionHelper makes a helper client the one the session reports
// on and delivers trust to.
func registerSessionHelper(client *HelperClient) {
	if client != nil {
		sessionHelper.Store(client)
	}
}

// helperCapabilityMode is what the helper on this host does with a capability:
// observe, prefer or enforce.
func helperCapabilityMode(ctx context.Context) string {
	client := sessionHelper.Load()
	if client == nil {
		return ""
	}
	if mode := client.CapabilityMode(); mode != "" {
		return mode
	}
	if helperProbeDisabled.Load() {
		return ""
	}
	if failed := probeFailedAt.Load(); failed != 0 && time.Since(time.Unix(failed, 0)) < probeRetryInterval {
		return ""
	}
	mode := client.ProbeCapabilityMode(ctx)
	if mode == "" {
		probeFailedAt.Store(time.Now().Unix())
	}
	return mode
}

// deliverHelperTrust hands the panel's trust bundle to the helper.
func deliverHelperTrust(ctx context.Context, bundle *helperv1.HelperTrustBundle, log *slog.Logger) {
	if bundle == nil || helperProbeDisabled.Load() {
		return
	}
	client := sessionHelper.Load()
	if client == nil {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := client.DeliverTrust(ctx, bundle)
	switch {
	case errors.Is(err, ErrHelperWithoutTrust):
		log.Warn("the helper on this host is from before the capability keyring; upgrade the helper package",
			"err", err)
	case err != nil:
		log.Warn("the helper did not take the trust bundle of the panel",
			"host_id", bundle.GetHostId(), "signed_by", bundle.GetSignedByKeyId(), "err", err)
	case result.GetChanged():
		log.Info("the helper took the trust bundle of the panel",
			"host_id", result.GetHostId(), "key_ids", result.GetKeyIds())
	}
}
