package ubuntu

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/vuln"
)

// przykladOVAL jest wycinkiem danych Canonical o ksztalcie takim jak zrzut
// produkcyjny: definicje przed testami, testy przed stanami.
const przykladOVAL = `<?xml version="1.0" encoding="utf-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
  xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition id="oval:com.ubuntu.noble:def:100" class="inventory" version="1">
      <metadata><title>Check that Ubuntu 24.04 LTS (noble) is installed.</title></metadata>
      <criteria><criterion test_ref="oval:com.ubuntu.noble:tst:100" comment="unix" /></criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:1" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2026-1111 on Ubuntu 24.04 LTS (noble) - high</title>
        <reference source="CVE" ref_id="CVE-2026-1111" ref_url="https://www.cve.org/CVERecord?id=CVE-2026-1111" />
        <reference source="USN" ref_id="USN-1000-1" ref_url="https://ubuntu.com/security/notices/USN-1000-1" />
        <description>Dziura w accountsservice.  Update Instructions:  Run ` + "`sudo pro fix`" + ` accountsservice - 23.13.9-2ubuntu6.1</description>
        <advisory from="security@ubuntu.com">
          <severity>High</severity>
          <public_date>2026-07-21T16:00:00Z</public_date>
          <cve href="https://ubuntu.com/security/CVE-2026-1111" priority="high">CVE-2026-1111</cve>
        </advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="noble" />
        <criterion test_ref="oval:com.ubuntu.noble:tst:1" comment="accountsservice source package in noble, is affected and has been fixed (note: '23.13.9-2ubuntu6.1')." />
        <criterion test_ref="oval:com.ubuntu.noble:tst:2" comment="accountsservice source package in esm-apps/noble, is affected and has been fixed (note: '23.13.9-2ubuntu6.1~esm1')." />
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:2" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2026-2222 on Ubuntu 24.04 LTS (noble) - medium</title>
        <reference source="CVE" ref_id="CVE-2026-2222" ref_url="https://www.cve.org/CVERecord?id=CVE-2026-2222" />
        <description>Dziura w curl bez poprawki.</description>
        <advisory from="security@ubuntu.com">
          <severity>Medium</severity>
          <public_date>2026-08-01T00:00:00Z</public_date>
          <cve href="https://ubuntu.com/security/CVE-2026-2222" priority="untriaged">CVE-2026-2222</cve>
        </advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.noble:tst:3" comment="curl source package in noble, might be affected and may need fixing." />
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:3" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2026-3333 on Ubuntu 24.04 LTS (noble) - high</title>
        <reference source="CVE" ref_id="CVE-2026-3333" ref_url="https://www.cve.org/CVERecord?id=CVE-2026-3333" />
        <description>Dziura w jadrze.</description>
        <advisory from="security@ubuntu.com">
          <severity>High</severity>
          <public_date>2026-08-02T00:00:00Z</public_date>
          <cve href="https://ubuntu.com/security/CVE-2026-3333" priority="high">CVE-2026-3333</cve>
        </advisory>
      </metadata>
      <criteria>
        <criteria operator="AND">
          <criterion test_ref="oval:com.ubuntu.noble:tst:10" comment="Is kernel 'linux' running?" />
          <criterion test_ref="oval:com.ubuntu.noble:tst:11" comment="'linux' kernel in noble was vulnerable but has been fixed (note: '6.8.0-35.35')." />
        </criteria>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <ind-def:family_test id="oval:com.ubuntu.noble:tst:100" version="1" comment="Is the host part of the unix family?" />
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:1" version="1" comment="Does the 'accountsservice' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:1" />
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:1" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:2" version="1" comment="Does the 'accountsservice' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:1" />
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:2" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:3" version="1" comment="Does the 'curl' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:3" />
    </linux-def:dpkginfo_test>
    <unix-def:uname_test id="oval:com.ubuntu.noble:tst:10" version="1" comment="Is kernel 'linux' running?">
      <unix-def:object object_ref="oval:com.ubuntu.noble:obj:200" />
    </unix-def:uname_test>
    <ind-def:variable_test id="oval:com.ubuntu.noble:tst:11" version="1" comment="kernel 'linux' version comparison">
      <ind-def:object object_ref="oval:com.ubuntu.noble:obj:210" />
      <ind-def:state state_ref="oval:com.ubuntu.noble:ste:11" />
    </ind-def:variable_test>
  </tests>
  <states>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:1" version="1" comment="mniej niz">
      <linux-def:evr datatype="debian_evr_string" operation="less than">23.13.9-2ubuntu6.1</linux-def:evr>
    </linux-def:dpkginfo_state>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:2" version="1" comment="mniej niz">
      <linux-def:evr datatype="debian_evr_string" operation="less than">23.13.9-2ubuntu6.1~esm1</linux-def:evr>
    </linux-def:dpkginfo_state>
    <ind-def:variable_state id="oval:com.ubuntu.noble:ste:11" version="1" comment="'linux' kernel version">
      <ind-def:value datatype="debian_evr_string" operation="less than">6.8.0-35.35</ind-def:value>
    </ind-def:variable_state>
  </states>
</oval_definitions>
`

func ustaleniaTestowe(t *testing.T) map[string]vuln.Advisory {
	t.Helper()
	ustalenia, err := Parsuj(strings.NewReader(przykladOVAL), "noble")
	if err != nil {
		t.Fatalf("parsowanie: %v", err)
	}
	wedlug := map[string]vuln.Advisory{}
	for _, ustalenie := range ustalenia {
		wedlug[ustalenie.AdvisoryID+"/"+ustalenie.SourcePackage] = ustalenie
	}
	return wedlug
}

func TestPoprawkaMaWersjeZrodlowaIWydanie(t *testing.T) {
	ustalenie := ustaleniaTestowe(t)["CVE-2026-1111/accountsservice"]
	if ustalenie.Status != vuln.StatusNaprawione {
		t.Fatalf("status = %q, chcemy %q", ustalenie.Status, vuln.StatusNaprawione)
	}
	// Z dwoch kieszeni wygrywa nizsza wersja: od niej pakiet ma poprawke,
	// wiec host z wersja glowna nie moze wyjsc jako podatny.
	if ustalenie.FixedVersion != "23.13.9-2ubuntu6.1~esm1" {
		t.Fatalf("wersja naprawiona = %q", ustalenie.FixedVersion)
	}
	if ustalenie.Release != "noble" || ustalenie.Distribution != "ubuntu" {
		t.Fatalf("wydanie = %q, dystrybucja = %q", ustalenie.Release, ustalenie.Distribution)
	}
	if ustalenie.VendorSeverity != "high" {
		t.Fatalf("waga = %q", ustalenie.VendorSeverity)
	}
	if strings.Contains(ustalenie.Title, "Update Instructions") {
		t.Fatalf("tytul niesie instrukcje aktualizacji: %q", ustalenie.Title)
	}
	if ustalenie.PublishedAt == nil {
		t.Fatal("ustalenie bez daty publikacji")
	}
}

func TestPakietBezPoprawkiJestOtwarty(t *testing.T) {
	ustalenie := ustaleniaTestowe(t)["CVE-2026-2222/curl"]
	if ustalenie.Status != vuln.StatusOtwarte {
		t.Fatalf("status = %q, chcemy %q", ustalenie.Status, vuln.StatusOtwarte)
	}
	if ustalenie.FixedVersion != "" {
		t.Fatalf("ustalenie bez poprawki ma wersje %q", ustalenie.FixedVersion)
	}
	// "untriaged" nie jest waga: producent jeszcze nie ocenil.
	if ustalenie.VendorSeverity != "medium" {
		t.Fatalf("waga = %q", ustalenie.VendorSeverity)
	}
}

func TestJadroMaUstalenieZWersjaWariantu(t *testing.T) {
	wedlug := ustaleniaTestowe(t)
	ustalenie, ok := wedlug["CVE-2026-3333/linux"]
	if !ok {
		t.Fatal("brak ustalenia dla jadra - CVE jadra znikaja z oceny")
	}
	if ustalenie.Status != vuln.StatusNaprawione || ustalenie.FixedVersion != "6.8.0-35.35" {
		t.Fatalf("jadro: status = %q, wersja = %q", ustalenie.Status, ustalenie.FixedVersion)
	}
	// Kryterium "czy dziala" nie jest osobnym ustaleniem: nie ma wersji,
	// wiec nie ma o czym mowic.
	if len(wedlug) != 3 {
		t.Fatalf("ustalen = %d, chcemy 3: %v", len(wedlug), wedlug)
	}
}

func TestDokumentUrwanyNieJestKompletem(t *testing.T) {
	urwany := przykladOVAL[:len(przykladOVAL)/2]
	if _, err := Parsuj(strings.NewReader(urwany), "noble"); err == nil {
		t.Fatal("urwany dokument przeszedl jako komplet")
	}
}

func TestDefinicjeBezUstalenSaBledem(t *testing.T) {
	// Dokument poprawny skladniowo, w ktorym definicja nie wskazuje zadnego
	// testu, jaki panel rozumie. Cisza jest tu najgorsza odpowiedzia.
	obcy := `<oval_definitions><definitions>
      <definition id="oval:com.ubuntu.noble:def:1" class="vulnerability" version="1">
        <metadata>
          <reference source="CVE" ref_id="CVE-2026-9999" />
          <description>nowy ksztalt dokumentu</description>
        </metadata>
        <criteria><criterion test_ref="oval:com.ubuntu.noble:tst:999" comment="cos nowego" /></criteria>
      </definition>
    </definitions></oval_definitions>`
	if _, err := Parsuj(strings.NewReader(obcy), "noble"); err == nil {
		t.Fatal("dokument bez ustalen przeszedl jako pusty feed")
	}
}

func TestZnacznikiWydanSaOsobne(t *testing.T) {
	znaczniki := map[string]string{"noble": `"aaa"`, "jammy": `"bbb"`, "focal": "z spacja"}
	zlozone := ZlozZnaczniki(znaczniki)
	odczytane := ParsujZnaczniki(zlozone)
	if odczytane["noble"] != `"aaa"` || odczytane["jammy"] != `"bbb"` {
		t.Fatalf("znaczniki po odczycie: %v", odczytane)
	}
	// Znacznik ze spacja rozpadlby sie na dwa wpisy - lepiej pobrac
	// bezwarunkowo niz pobrac warunkowo bledna wartoscia.
	if _, jest := odczytane["focal"]; jest {
		t.Fatalf("znacznik ze spacja przeszedl: %v", odczytane)
	}
}

func TestOdciskNieZalezyOdKolejnosci(t *testing.T) {
	ustalenia, err := Parsuj(strings.NewReader(przykladOVAL), "noble")
	if err != nil {
		t.Fatalf("parsowanie: %v", err)
	}
	odwrotne := make([]vuln.Advisory, 0, len(ustalenia))
	for i := len(ustalenia) - 1; i >= 0; i-- {
		odwrotne = append(odwrotne, ustalenia[i])
	}
	Uporzadkuj(odwrotne)
	if Odcisk(ustalenia) != Odcisk(odwrotne) {
		t.Fatal("odcisk zalezy od kolejnosci - kazde pobranie zakladaloby nowy snapshot")
	}
}
