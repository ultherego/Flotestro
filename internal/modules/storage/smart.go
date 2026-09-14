package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// SmartctlPath is where the SMART tool lives. Fixed, not looked up in PATH.
const SmartctlPath = "/usr/sbin/smartctl"

// smartDevice allows only a device node path. The value lands on the
// command line of a root tool, so the shape is a security boundary rather
// than cosmetics: no spaces, no options, no path outside /dev.
var smartDevice = regexp.MustCompile(`^/dev/[a-z0-9/]+$`)

// ValidateSmartDevice rejects a device path the SMART read must not take.
func ValidateSmartDevice(device string) error {
	if !smartDevice.MatchString(device) {
		return fmt.Errorf("invalid device path %q; expected /dev/<name>", device)
	}
	if strings.Contains(device, "..") || strings.Contains(device, "//") {
		return fmt.Errorf("invalid device path %q", device)
	}
	return nil
}

// The health verdicts of a SMART read. Unknown is a verdict too: it says the
// tool ran and did not answer the question, and carries the reason.
const (
	SmartPassed  = "passed"
	SmartFailed  = "failed"
	SmartUnknown = "unknown"
)

// SmartReport is what the panel shows of one device's SMART state.
//
// Every number comes from the tool. A field the tool did not report stays
// nil: a device without a temperature sensor is not a device at zero
// degrees, and a virtual disk has no wear to report.
type SmartReport struct {
	Device string `json:"device"`
	Model  string `json:"model,omitempty"`
	Serial string `json:"serial,omitempty"`
	// Health is passed, failed or unknown. Unknown carries HealthReason.
	Health             string  `json:"health"`
	HealthReason       string  `json:"health_reason,omitempty"`
	TemperatureC       *int32  `json:"temperature_c,omitempty"`
	PowerOnHours       *uint64 `json:"power_on_hours,omitempty"`
	ReallocatedSectors *uint64 `json:"reallocated_sectors,omitempty"`
	PendingSectors     *uint64 `json:"pending_sectors,omitempty"`
	// WearPercent is the NVMe percentage used. ATA wear indicators stay in
	// the attribute table under their own names, because vendors disagree
	// on what they mean.
	WearPercent *uint32          `json:"wear_percent,omitempty"`
	Attributes  []SmartAttribute `json:"attributes,omitempty"`
	// Unsupported marks a device the tool cannot read: a virtual disk, a
	// USB bridge without passthrough, a device the tool does not know. The
	// reason is the tool's own message.
	Unsupported       bool   `json:"unsupported,omitempty"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
	// Output is the beginning of what the tool printed when its JSON could
	// not be read.
	Output string `json:"output,omitempty"`
}

// SmartAttribute is one row of the ATA attribute table.
type SmartAttribute struct {
	ID        uint32 `json:"id"`
	Name      string `json:"name"`
	Value     uint32 `json:"value"`
	Worst     uint32 `json:"worst"`
	Threshold uint32 `json:"threshold"`
	Raw       uint64 `json:"raw"`
	RawString string `json:"raw_string,omitempty"`
	// Failing marks an attribute at or below its threshold now.
	Failing bool `json:"failing,omitempty"`
}

// SmartRunner runs the SMART tool and returns its output together with the
// exit code. The exit code matters: smartctl encodes what went wrong in
// bits, and a non-zero code with a full JSON is a device with findings, not
// a failed read.
type SmartRunner func(ctx context.Context, path string, args ...string) (stdout string, exitCode int, err error)

// The bits of smartctl's exit status (see smartctl(8), EXIT STATUS).
const (
	smartExitCommandLine  = 1 << 0
	smartExitDeviceOpen   = 1 << 1
	smartExitCommandFail  = 1 << 2
	smartExitDiskFailing  = 1 << 3
	smartExitPrefail      = 1 << 4
	smartExitPastPrefail  = 1 << 5
	smartExitErrorsLogged = 1 << 6
	smartExitSelfTestFail = 1 << 7
)

// ReadSmart runs smartctl on the device and turns its JSON into a report.
//
// The tool is asked for the health and the attributes in JSON. Its exit
// status is read bit by bit: a device the tool cannot open or talk to
// reports unsupported with the tool's message, a device that is failing
// reports failed - and only a device the tool vouched for reports passed.
func ReadSmart(ctx context.Context, run SmartRunner, device string) SmartReport {
	report := SmartReport{Device: device, Health: SmartUnknown}
	if err := ValidateSmartDevice(device); err != nil {
		report.HealthReason = err.Error()
		return report
	}
	stdout, code, err := run(ctx, SmartctlPath, "-H", "-A", "-j", device)
	if err != nil && strings.TrimSpace(stdout) == "" {
		// The tool did not run at all: missing binary, permission, timeout.
		// That is not a device without SMART; it is an unread device.
		report.HealthReason = "smartctl did not run: " + err.Error()
		return report
	}
	return ParseSmart(device, stdout, code)
}

// smartctlOutput is the part of the tool's JSON the report reads. The tool
// prints more; what is not listed here is not carried, so an unknown field
// cannot be mistaken for a fact.
type smartctlOutput struct {
	Smartctl struct {
		ExitStatus int `json:"exit_status"`
		Messages   []struct {
			String   string `json:"string"`
			Severity string `json:"severity"`
		} `json:"messages"`
	} `json:"smartctl"`
	Device struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelName    string `json:"model_name"`
	SerialNumber string `json:"serial_number"`
	SmartSupport *struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
		NVMe   *struct {
			Value int `json:"value"`
		} `json:"nvme"`
	} `json:"smart_status"`
	Temperature *struct {
		Current *int32 `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours *uint64 `json:"hours"`
	} `json:"power_on_time"`
	ATAAttributes *struct {
		Table []struct {
			ID     uint32 `json:"id"`
			Name   string `json:"name"`
			Value  uint32 `json:"value"`
			Worst  uint32 `json:"worst"`
			Thresh uint32 `json:"thresh"`
			// WhenFailed is "now", "past" or empty.
			WhenFailed string `json:"when_failed"`
			Raw        struct {
				Value  uint64 `json:"value"`
				String string `json:"string"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMeHealth *struct {
		PercentageUsed *uint32 `json:"percentage_used"`
		Temperature    *int32  `json:"temperature"`
		PowerOnHours   *uint64 `json:"power_on_hours"`
		MediaErrors    *uint64 `json:"media_errors"`
	} `json:"nvme_smart_health_information_log"`
}

// ParseSmart reads the tool's JSON and its exit status into a report.
//
// The two are read together: the JSON says what the tool saw, the status
// says whether it could see at all. A status with the "device open" or
// "command failed" bit means unsupported even when some JSON came out,
// because the tool prints the header before it gives up.
func ParseSmart(device, stdout string, exitCode int) SmartReport {
	report := SmartReport{Device: device, Health: SmartUnknown}

	var parsed smartctlOutput
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		report.HealthReason = "the output of smartctl is not JSON"
		report.Output = head(stdout, 512)
		if exitCode&(smartExitCommandLine|smartExitDeviceOpen|smartExitCommandFail) != 0 {
			report.Unsupported = true
			report.UnsupportedReason = strings.TrimSpace(head(stdout, 512))
			if report.UnsupportedReason == "" {
				report.UnsupportedReason = fmt.Sprintf("smartctl exited with status %d", exitCode)
			}
		}
		return report
	}
	if parsed.Smartctl.ExitStatus != 0 && exitCode == 0 {
		// The JSON carries its own copy of the status; when the runner did
		// not report one (a fake, an unusual wrapper) the copy is the truth.
		exitCode = parsed.Smartctl.ExitStatus
	}

	report.Model = parsed.ModelName
	report.Serial = parsed.SerialNumber

	var messages []string
	for _, message := range parsed.Smartctl.Messages {
		if text := strings.TrimSpace(message.String); text != "" {
			messages = append(messages, text)
		}
	}
	reason := strings.Join(messages, "; ")

	if exitCode&(smartExitCommandLine|smartExitDeviceOpen|smartExitCommandFail) != 0 {
		report.Unsupported = true
		report.UnsupportedReason = reason
		if report.UnsupportedReason == "" {
			report.UnsupportedReason = fmt.Sprintf("smartctl could not read the device (exit status %d)", exitCode)
		}
		report.HealthReason = report.UnsupportedReason
		return report
	}
	if parsed.SmartSupport != nil && (!parsed.SmartSupport.Available || !parsed.SmartSupport.Enabled) {
		report.Unsupported = true
		report.UnsupportedReason = "SMART is not available or not enabled on this device"
		if reason != "" {
			report.UnsupportedReason += ": " + reason
		}
		report.HealthReason = report.UnsupportedReason
		return report
	}

	switch {
	case parsed.SmartStatus == nil:
		report.HealthReason = "smartctl reported no health verdict"
		if reason != "" {
			report.HealthReason += ": " + reason
		}
	case parsed.SmartStatus.Passed && exitCode&smartExitDiskFailing == 0:
		report.Health = SmartPassed
	default:
		report.Health = SmartFailed
		report.HealthReason = reason
	}

	if parsed.Temperature != nil && parsed.Temperature.Current != nil {
		report.TemperatureC = parsed.Temperature.Current
	}
	if parsed.PowerOnTime != nil && parsed.PowerOnTime.Hours != nil {
		report.PowerOnHours = parsed.PowerOnTime.Hours
	}
	if nvme := parsed.NVMeHealth; nvme != nil {
		if nvme.PercentageUsed != nil {
			report.WearPercent = nvme.PercentageUsed
		}
		if report.TemperatureC == nil && nvme.Temperature != nil {
			report.TemperatureC = nvme.Temperature
		}
		if report.PowerOnHours == nil && nvme.PowerOnHours != nil {
			report.PowerOnHours = nvme.PowerOnHours
		}
	}
	if parsed.ATAAttributes != nil {
		for _, row := range parsed.ATAAttributes.Table {
			attribute := SmartAttribute{
				ID: row.ID, Name: row.Name, Value: row.Value, Worst: row.Worst,
				Threshold: row.Thresh, Raw: row.Raw.Value, RawString: row.Raw.String,
				Failing: row.WhenFailed == "now",
			}
			report.Attributes = append(report.Attributes, attribute)
			raw := row.Raw.Value
			switch row.ID {
			case 5:
				report.ReallocatedSectors = &raw
			case 197:
				report.PendingSectors = &raw
			case 194:
				if report.TemperatureC == nil {
					// The raw value packs the current temperature in the
					// low byte; the rest is the min/max history.
					current := int32(raw & 0xff)
					report.TemperatureC = &current
				}
			case 9:
				if report.PowerOnHours == nil {
					// Some vendors count minutes or pack the hours with the
					// milliseconds; the low 32 bits are the hours on the
					// devices that follow the common convention.
					hours := raw & 0xffffffff
					report.PowerOnHours = &hours
				}
			}
		}
	}
	return report
}

// head returns the beginning of a text for a message.
func head(text string, limit int) string {
	text = strings.TrimSpace(text)
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…"
}
