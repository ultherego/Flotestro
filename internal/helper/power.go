package helper

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/systemd"
)

// applyShutdown powers the host off after the given delay.
//
// The delay is necessary for the same reason as with a restart: without it the
// host disappears before the agent sends the result back, and the operation
// would look broken instead of done. There is one difference from a restart,
// but a fundamental one - after this operation nobody will see the host come
// back.
func (s *Server) applyShutdown(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.ShutdownRequest) *helperv1.HelperResponse {
	if err := power.WalidujPowodWylaczenia(action.GetReason()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := power.WalidujOpoznienie(action.GetDelaySeconds()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	mode := action.GetMode()
	switch mode {
	case "":
		mode = power.TrybWylaczyc
	case power.TrybWylaczyc, power.TrybZatrzymac:
	default:
		return reject(ErrorMalformed, "unsupported shutdown mode "+mode)
	}

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 2 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// A logind inhibitor is the answer of the host to the question "is it
	// allowed now": an update in flight or a session with open work. The panel
	// does not go around it without an operator decision.
	inhibitors := shutdownInhibitors(actionCtx)
	if len(inhibitors) > 0 && !action.GetIgnoreInhibitors() {
		refusal := reject(ErrorPreconditionFailed,
			"the shutdown was held back by inhibitors: "+describeInhibitors(inhibitors))
		refusal.PowerResult = &helperv1.PowerResult{
			Message:    refusal.Message,
			Inhibitors: encodeInhibitors(inhibitors),
		}
		return refusal
	}

	delay := action.GetDelaySeconds()
	if delay == 0 {
		delay = 15
	}
	stdout, stderr, exitCode, err := systemd.SchedulePower(actionCtx,
		time.Duration(delay)*time.Second, "Flotestro: "+action.GetReason(), mode)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if exitCode != 0 {
		response := reject(ErrorExecFailed, strings.TrimSpace(stderr))
		response.ExitCode = int32(exitCode)
		return response
	}

	deadline := time.Now().UTC().Add(time.Duration(delay) * time.Second)
	message := "the shutdown was scheduled for " + deadline.Format(time.RFC3339)
	if len(inhibitors) > 0 {
		message += "; the inhibitors were skipped by an operator decision: " + describeInhibitors(inhibitors)
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		Stdout:   []byte(stdout),
		PowerResult: &helperv1.PowerResult{
			Message:     message,
			Inhibitors:  encodeInhibitors(inhibitors),
			ScheduledAt: deadline.Format(time.RFC3339),
		},
	}
}

// shutdownInhibitors returns the inhibitors that do not allow a shutdown.
//
// A delay is not an obstacle: logind waits it out on its own. A block is, and
// it is the one that has to stop the operation.
func shutdownInhibitors(ctx context.Context) []power.Blokada {
	if !exists(power.SciezkaInhibit) {
		return nil
	}
	output, _, _ := outputWithWarnings(ctx, power.SciezkaInhibit, "--list", "--no-pager")
	all, known := power.ParsujInhibitory(output)
	if !known {
		return nil
	}
	var blocking []power.Blokada
	for _, inhibitor := range all {
		if inhibitor.Blokuje() && (inhibitor.What == "" || strings.Contains(inhibitor.What, "shutdown")) {
			blocking = append(blocking, inhibitor)
		}
	}
	return blocking
}

func describeInhibitors(inhibitors []power.Blokada) string {
	descriptions := make([]string, 0, len(inhibitors))
	for _, inhibitor := range inhibitors {
		description := inhibitor.Who
		if inhibitor.Why != "" {
			description += " (" + inhibitor.Why + ")"
		}
		descriptions = append(descriptions, description)
	}
	return strings.Join(descriptions, ", ")
}

func encodeInhibitors(inhibitors []power.Blokada) []byte {
	if len(inhibitors) == 0 {
		return nil
	}
	encoded, err := json.Marshal(inhibitors)
	if err != nil {
		return nil
	}
	return encoded
}
