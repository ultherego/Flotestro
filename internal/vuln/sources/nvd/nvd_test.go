package nvd

import (
	"testing"
	"time"
)

// przykladNVD ma ksztalt odpowiedzi API w wersji 2.0.
const przykladNVD = `{
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
        "descriptions": [{"lang": "en", "value": "Nieoceniona jeszcze podatnosc."}],
        "metrics": {}
      }
    }
  ]
}`

func TestParsujBierzeOceneIOpis(t *testing.T) {
	szczegoly, wszystkich, err := Parsuj([]byte(przykladNVD))
	if err != nil {
		t.Fatalf("parsowanie: %v", err)
	}
	if wszystkich != 2 || len(szczegoly) != 2 {
		t.Fatalf("wpisow = %d z %d", len(szczegoly), wszystkich)
	}

	pierwszy := szczegoly[0]
	if pierwszy.CVSSScore == nil || *pierwszy.CVSSScore != 7.8 {
		t.Fatalf("ocena = %v - nowsza wersja CVSS i ocena glowna maja wygrywac", pierwszy.CVSSScore)
	}
	if pierwszy.CVSSVersion != "3.1" || pierwszy.CVSSSeverity != "high" {
		t.Fatalf("wersja = %q, waga = %q", pierwszy.CVSSVersion, pierwszy.CVSSSeverity)
	}
	if pierwszy.Source != Dostawca {
		t.Fatalf("zrodlo = %q", pierwszy.Source)
	}
	if pierwszy.Summary == "" || pierwszy.Summary[:6] != "A flaw" {
		t.Fatalf("opis = %q - bierzemy angielski", pierwszy.Summary)
	}
	// Znaczniki NVD przychodza bez strefy i sa w UTC.
	if pierwszy.ModifiedAt == nil ||
		!pierwszy.ModifiedAt.Equal(time.Date(2026, 8, 2, 9, 10, 11, 123000000, time.UTC)) {
		t.Fatalf("znacznik zmiany = %v", pierwszy.ModifiedAt)
	}
}

func TestPodatnoscBezOcenyMaSamOpis(t *testing.T) {
	szczegoly, _, err := Parsuj([]byte(przykladNVD))
	if err != nil {
		t.Fatalf("parsowanie: %v", err)
	}
	drugi := szczegoly[1]
	// Brak oceny nie jest ocena zero: pole zostaje puste.
	if drugi.CVSSScore != nil {
		t.Fatalf("nieoceniona podatnosc dostala ocene %v", *drugi.CVSSScore)
	}
	if drugi.Summary == "" {
		t.Fatal("wpis bez opisu")
	}
}

func TestWagaWersjiDrugiejStoiObokDanych(t *testing.T) {
	// W CVSS 2 waga jest przy metryce, a nie w danych oceny. Bez tego
	// starsze podatnosci mialyby liczbe i zadnego slowa obok niej.
	metryki := map[string][]metryka{"cvssMetricV2": {{
		Type: "Primary", BaseSeverity: "MEDIUM",
		CVSSData: struct {
			Version      string  `json:"version"`
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		}{Version: "2.0", BaseScore: 4.6, VectorString: "AV:L/AC:L/Au:N/C:P/I:P/A:P"},
	}}}
	ocena, wersja, waga, wektor, ok := NajlepszaOcena(metryki)
	if !ok || ocena != 4.6 || wersja != "2.0" || waga != "MEDIUM" || wektor == "" {
		t.Fatalf("ocena = %v %q %q %q (%v)", ocena, wersja, waga, wektor, ok)
	}
}

func TestZnacznikNVD(t *testing.T) {
	chwila := time.Date(2026, 9, 6, 12, 30, 45, 0, time.UTC)
	if mamy := ZnacznikNVD(chwila); mamy != "2026-09-06T12:30:45.000Z" {
		t.Fatalf("znacznik = %q", mamy)
	}
}

func TestOdstepZalezyOdKlucza(t *testing.T) {
	// Bez klucza NVD pozwala na piec zadan na trzydziesci sekund; szybciej
	// znaczy odciecie, a odciecie znaczy brak opisow.
	if odstep := Nowy("", "", 0).odstep(); odstep != OdstepBezKlucza {
		t.Fatalf("odstep bez klucza = %s", odstep)
	}
	if odstep := Nowy("", "klucz", 0).odstep(); odstep != OdstepZKluczem {
		t.Fatalf("odstep z kluczem = %s", odstep)
	}
}
