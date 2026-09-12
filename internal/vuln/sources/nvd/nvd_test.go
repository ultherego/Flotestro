package nvd

import (
	"testing"
	"time"
)

// nvdSample has the shape of an API answer in version 2.0.
const nvdSample = `{
  "resultsPerPage": 2,
  "startIndex": 0,
  "totalResults": 2,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-1111",
        "published": "2026-07-21T16:15:00.000",
        "lastModified": "2026-08-02T09:10:11.123",
        "vulnStatus": "Analyzed",
        "descriptions": [
          {"lang": "es", "value": "Un fallo en accountsservice."},
          {"lang": "en", "value": "A flaw in AccountsService allows local privilege escalation."}
        ],
        "metrics": {
          "cvssMetricV2": [
            {"type": "Primary", "baseSeverity": "MEDIUM",
             "cvssData": {"version": "2.0", "baseScore": 4.6,
             "vectorString": "AV:L/AC:L/Au:N/C:P/I:P/A:P"}}
          ],
          "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 7.0,
             "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"}},
            {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.8,
             "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}
          ]
        }
      }
    },
    {
      "cve": {
        "id": "CVE-2026-2222",
        "published": "2026-08-01T00:00:00.000",
        "lastModified": "2026-08-01T00:00:00.000",
        "vulnStatus": "Awaiting Analysis",
        "descriptions": [{"lang": "en", "value": "A vulnerability not scored yet."}],
        "metrics": {}
      }
    }
  ]
}`

func TestParseTakesTheScoreAndTheDescription(t *testing.T) {
	details, total, err := Parse([]byte(nvdSample))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if total != 2 || len(details) != 2 {
		t.Fatalf("entries = %d of %d", len(details), total)
	}

	first := details[0]
	if first.CVSSScore == nil || *first.CVSSScore != 7.8 {
		t.Fatalf("score = %v - the newer CVSS version and the primary score are to win", first.CVSSScore)
	}
	if first.CVSSVersion != "3.1" || first.CVSSSeverity != "high" {
		t.Fatalf("version = %q, severity = %q", first.CVSSVersion, first.CVSSSeverity)
	}
	if first.Source != Provider {
		t.Fatalf("source = %q", first.Source)
	}
	if first.Summary == "" || first.Summary[:6] != "A flaw" {
		t.Fatalf("description = %q - we take the English one", first.Summary)
	}
	// NVD timestamps arrive without a zone and are in UTC.
	if first.ModifiedAt == nil ||
		!first.ModifiedAt.Equal(time.Date(2026, 8, 2, 9, 10, 11, 123000000, time.UTC)) {
		t.Fatalf("change timestamp = %v", first.ModifiedAt)
	}
}

func TestAVulnerabilityWithoutAScoreKeepsTheDescription(t *testing.T) {
	details, _, err := Parse([]byte(nvdSample))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	second := details[1]
	// A missing score is not a score of zero: the field stays empty.
	if second.CVSSScore != nil {
		t.Fatalf("an unscored vulnerability got the score %v", *second.CVSSScore)
	}
	if second.Summary == "" {
		t.Fatal("an entry without a description")
	}
}

func TestTheSeverityOfVersionTwoStandsNextToTheData(t *testing.T) {
	// In CVSS 2 the severity sits with the metric rather than in the data of
	// the score. Without that older vulnerabilities would carry a number and
	// not a word next to it.
	metrics := map[string][]metric{"cvssMetricV2": {{
		Type: "Primary", BaseSeverity: "MEDIUM",
		CVSSData: struct {
			Version      string  `json:"version"`
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		}{Version: "2.0", BaseScore: 4.6, VectorString: "AV:L/AC:L/Au:N/C:P/I:P/A:P"},
	}}}
	score, version, severity, vector, ok := BestScore(metrics)
	if !ok || score != 4.6 || version != "2.0" || severity != "MEDIUM" || vector == "" {
		t.Fatalf("score = %v %q %q %q (%v)", score, version, severity, vector, ok)
	}
}

func TestTimestamp(t *testing.T) {
	moment := time.Date(2026, 9, 6, 12, 30, 45, 0, time.UTC)
	if got := Timestamp(moment); got != "2026-09-06T12:30:45.000Z" {
		t.Fatalf("timestamp = %q", got)
	}
}

func TestTheIntervalDependsOnTheKey(t *testing.T) {
	// Without a key NVD allows five requests per thirty seconds; faster means
	// being cut off, and being cut off means no descriptions.
	if interval := New("", "", 0).interval(); interval != IntervalWithoutKey {
		t.Fatalf("interval without a key = %s", interval)
	}
	if interval := New("", "key", 0).interval(); interval != IntervalWithKey {
		t.Fatalf("interval with a key = %s", interval)
	}
}
