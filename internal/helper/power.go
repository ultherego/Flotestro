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
func (s *Server) applyShutdown(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.ShutdownRequest) *helperv1.HelperResponse {
	if err := power.ValidateShutdownReason(action.GetReason()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := power.ValidateDelay(action.GetDelaySeconds()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	mode := action.GetMode()
	switch mode {
	case "":
		mode = power.ModePoweroff
	case power.ModePoweroff, power.ModeHalt:
	default:
		return reject(ErrorMalformed, "unsupported shutdown mode "+mode)
	}

	actionCtx, cancel := deadline(ctx, request, 2*time.Minute, 10*time.Minute)
	defer cancel()

	// A logind inhibitor is the answer of the host to the question "is it allowed
	// now": an update in flight or a session with open work.
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

// shutdownInhibitors returns the inhibitors that do not allow a shutdown. A
// delay is not an obstacle: logind waits it out on its own.
func shutdownInhibitors(ctx context.Context) []power.Inhibitor {
	if !exists(power.InhibitPath) {
		return nil
	}
	output, _, _ := outputWithWarnings(ctx, power.InhibitPath, "--list", "--no-pager")
	all, known := power.ParseInhibitors(output)
	if !known {
		return nil
	}
	var blocking []power.Inhibitor
	for _, inhibitor := range all {
		if inhibitor.Blocks() && (inhibitor.What == "" || strings.Contains(inhibitor.What, "shutdown")) {
			blocking = append(blocking, inhibitor)
		}
	}
	return blocking
}

func describeInhibitors(inhibitors []power.Inhibitor) string {
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

func encodeInhibitors(inhibitors []power.Inhibitor) []byte {
	if len(inhibitors) == 0 {
		return nil
	}
	encoded, err := json.Marshal(inhibitors)
	if err != nil {
		return nil
	}
	return encoded
}
