package storage

import (
	"context"
	"errors"
	"testing"
)

const ataSmartJSON = `{
  "smartctl": {"exit_status": 0, "messages": []},
  "device": {"name": "/dev/sda", "type": "sat", "protocol": "ATA"},
  "model_name": "Samsung SSD 870 EVO 1TB",
  "serial_number": "S6PTNX0T123456A",
  "smart_support": {"available": true, "enabled": true},
  "smart_status": {"passed": true},
  "power_on_time": {"hours": 12345},
  "temperature": {"current": 31},
  "ata_smart_attributes": {"table": [
    {"id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "worst": 100, "thresh": 10,
     "when_failed": "", "raw": {"value": 0, "string": "0"}},
    {"id": 9, "name": "Power_On_Hours", "value": 97, "worst": 97, "thresh": 0,
     "when_failed": "", "raw": {"value": 12345, "string": "12345"}},
    {"id": 197, "name": "Current_Pending_Sector", "value": 100, "worst": 100, "thresh": 0,
     "when_failed": "", "raw": {"value": 3, "string": "3"}}
  ]}
}`

func TestParseSmartReadsAnATADevice(t *testing.T) {
	report := ParseSmart("/dev/sda", ataSmartJSON, 0)
	if report.Unsupported {
		t.Fatalf("a readable device was reported unsupported: %s", report.UnsupportedReason)
	}
	if report.Health != SmartPassed {
		t.Errorf("health = %q (%s), expected passed", report.Health, report.HealthReason)
	}
	if report.Model != "Samsung SSD 870 EVO 1TB" || report.Serial != "S6PTNX0T123456A" {
		t.Errorf("identity = %q / %q", report.Model, report.Serial)
	}
	if report.TemperatureC == nil || *report.TemperatureC != 31 {
		t.Errorf("temperature = %v", report.TemperatureC)
	}
	if report.PowerOnHours == nil || *report.PowerOnHours != 12345 {
		t.Errorf("power-on hours = %v", report.PowerOnHours)
	}
	if report.ReallocatedSectors == nil || *report.ReallocatedSectors != 0 {
		t.Errorf("reallocated sectors = %v", report.ReallocatedSectors)
	}
	if report.PendingSectors == nil || *report.PendingSectors != 3 {
		t.Errorf("pending sectors = %v", report.PendingSectors)
	}
	// An ATA device has no NVMe wear counter; the field must stay absent
	// rather than read as zero wear.
	if report.WearPercent != nil {
		t.Errorf("an ATA device reported wear %d", *report.WearPercent)
	}
	if len(report.Attributes) != 3 {
		t.Errorf("attributes = %d, expected 3", len(report.Attributes))
	}
}

func TestParseSmartReadsAnNVMeDevice(t *testing.T) {
	output := `{
	  "smartctl": {"exit_status": 0},
	  "device": {"name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe"},
	  "model_name": "WD Black SN850",
	  "serial_number": "21123X0",
	  "smart_status": {"passed": true, "nvme": {"value": 0}},
	  "nvme_smart_health_information_log": {
	    "percentage_used": 7, "temperature": 42, "power_on_hours": 900, "media_errors": 0
	  }
	}`
	report := ParseSmart("/dev/nvme0", output, 0)
	if report.Health != SmartPassed || report.Unsupported {
		t.Fatalf("report = %+v", report)
	}
	if report.WearPercent == nil || *report.WearPercent != 7 {
		t.Errorf("wear = %v", report.WearPercent)
	}
	if report.TemperatureC == nil || *report.TemperatureC != 42 {
		t.Errorf("temperature = %v", report.TemperatureC)
	}
	if report.PowerOnHours == nil || *report.PowerOnHours != 900 {
		t.Errorf("power-on hours = %v", report.PowerOnHours)
	}
	// NVMe devices have no ATA sector counters; they stay absent.
	if report.ReallocatedSectors != nil || report.PendingSectors != nil {
		t.Error("an NVMe device reported ATA sector counters")
	}
}

// A virtual disk answers with a message and the "device open" bit. That is
// unsupported with the tool's own words, and no number is invented.
func TestParseSmartReportsAVirtualDiskAsUnsupported(t *testing.T) {
	output := `{
	  "smartctl": {"exit_status": 2, "messages": [
	    {"string": "/dev/sda: Unable to detect device type", "severity": "error"}
	  ]},
	  "device": {"name": "/dev/sda"}
	}`
	report := ParseSmart("/dev/sda", output, 2)
	if !report.Unsupported {
		t.Fatalf("a virtual disk was not reported unsupported: %+v", report)
	}
	if report.UnsupportedReason != "/dev/sda: Unable to detect device type" {
		t.Errorf("reason = %q", report.UnsupportedReason)
	}
	if report.Health != SmartUnknown {
		t.Errorf("health = %q, expected unknown", report.Health)
	}
	if report.TemperatureC != nil || report.PowerOnHours != nil || len(report.Attributes) != 0 {
		t.Error("an unsupported device carries numbers")
	}
}

// A device that is failing is reported failed, even though the tool printed
// a full attribute table: the exit status carries the verdict.
func TestParseSmartReadsAFailingVerdict(t *testing.T) {
	output := `{
	  "smartctl": {"exit_status": 8},
	  "model_name": "Old Disk",
	  "smart_support": {"available": true, "enabled": true},
	  "smart_status": {"passed": false},
	  "ata_smart_attributes": {"table": [
	    {"id": 5, "name": "Reallocated_Sector_Ct", "value": 1, "worst": 1, "thresh": 10,
	     "when_failed": "now", "raw": {"value": 4096, "string": "4096"}}
	  ]}
	}`
	report := ParseSmart("/dev/sdb", output, 8)
	if report.Health != SmartFailed {
		t.Fatalf("health = %q, expected failed", report.Health)
	}
	if len(report.Attributes) != 1 || !report.Attributes[0].Failing {
		t.Errorf("the failing attribute was not marked: %+v", report.Attributes)
	}
	if report.ReallocatedSectors == nil || *report.ReallocatedSectors != 4096 {
		t.Errorf("reallocated sectors = %v", report.ReallocatedSectors)
	}
}

func TestParseSmartWithoutJSONStaysUnknown(t *testing.T) {
	report := ParseSmart("/dev/sda", "smartctl 7.3: something went wrong", 0)
	if report.Health != SmartUnknown || report.Unsupported {
		t.Fatalf("report = %+v", report)
	}
	if report.Output == "" {
		t.Error("the tool's text was dropped")
	}
}

func TestReadSmartRunsTheToolWithFixedArguments(t *testing.T) {
	var got []string
	run := func(_ context.Context, path string, args ...string) (string, int, error) {
		got = append([]string{path}, args...)
		return ataSmartJSON, 0, nil
	}
	report := ReadSmart(context.Background(), run, "/dev/sda")
	if report.Health != SmartPassed {
		t.Fatalf("health = %q", report.Health)
	}
	expected := []string{SmartctlPath, "-H", "-A", "-j", "/dev/sda"}
	if len(got) != len(expected) {
		t.Fatalf("arguments = %v", got)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("arguments = %v, expected %v", got, expected)
		}
	}
}

// The device path lands on the command line of a root tool. A path outside
// /dev or with anything but a node name never reaches the tool.
func TestReadSmartRefusesABadDevicePath(t *testing.T) {
	called := false
	run := func(context.Context, string, ...string) (string, int, error) {
		called = true
		return "", 0, nil
	}
	for _, device := range []string{"", "sda", "/dev/sda; reboot", "/dev/../etc/passwd", "/dev/SDA", "/dev/sda -x"} {
		report := ReadSmart(context.Background(), run, device)
		if called {
			t.Fatalf("the tool ran for %q", device)
		}
		if report.Health != SmartUnknown || report.HealthReason == "" {
			t.Errorf("%q: report = %+v", device, report)
		}
	}
}

// A tool that did not run is an unread device, not a device without SMART.
func TestReadSmartTellsAMissingToolFromAnUnsupportedDevice(t *testing.T) {
	run := func(context.Context, string, ...string) (string, int, error) {
		return "", -1, errors.New("the tool smartctl is missing")
	}
	report := ReadSmart(context.Background(), run, "/dev/sda")
	if report.Unsupported {
		t.Error("a missing tool was reported as an unsupported device")
	}
	if report.Health != SmartUnknown || report.HealthReason == "" {
		t.Errorf("report = %+v", report)
	}
}
