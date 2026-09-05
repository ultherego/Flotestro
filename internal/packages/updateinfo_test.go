package packages

import "testing"

// wyjscieUpdateinfo jest prawdziwym wyjsciem "dnf updateinfo info" z Fedory 42.
const wyjscieUpdateinfo = `Name        : FEDORA-2025-191738fa1f
Title       : firewalld-2.3.2-1.fc42
Severity    : None
Type        : bugfix
Status      : stable
Vendor      : updates@fedoraproject.org
Issued      : 2025-11-25 01:34:32
Description : rebase to v2.3.2
Message     : 
Rights      : Copyright (C) 2026 Red Hat, Inc. and others.
Collection  : 
  Packages  : firewalld-2.3.2-1.fc42.src
            : firewalld-2.3.2-1.fc42.noarch

Name        : FEDORA-2026-d08c298940
Title       : openssh-9.9p1-14.fc42
Severity    : Important
Type        : security
Status      : stable
Vendor      : updates@fedoraproject.org
Issued      : 2026-05-02 01:57:11
Description : Fixes high severity CVE:
            : - CVE-2026-35385: Fix privilege escalation via scp legacy protocol
Message     : 
Rights      : Copyright (C) 2026 Red Hat, Inc. and others.
Reference   : 
  Title     : CVE-2026-35385 openssh: Privilege escalation [fedora-all]
  Id        : 2454941
  Type      : bugzilla
  Url       : https://bugzilla.redhat.com/show_bug.cgi?id=2454941
Collection  : 
  Packages  : openssh-9.9p1-14.fc42.src
            : openssh-clients-9.9p1-14.fc42.x86_64
            : openssh-server-9.9p1-14.fc42.x86_64
            : openssh-9.9p1-14.fc42.x86_64
`

func TestParsujUpdateinfoCzytaUstaleniaProducenta(t *testing.T) {
	ustalenia := ParsujUpdateinfo(wyjscieUpdateinfo)
	if len(ustalenia) != 2 {
		t.Fatalf("odczytano %d ustalen: %+v", len(ustalenia), ustalenia)
	}

	poprawka := ustalenia[0]
	if poprawka.ID != "FEDORA-2025-191738fa1f" || poprawka.Type != "bugfix" {
		t.Fatalf("pierwsze ustalenie: %+v", poprawka)
	}
	// "None" nie jest waga: to brak wagi i tak ma zostac.
	if poprawka.Severity != "" {
		t.Errorf("waga poprawki bledu = %q", poprawka.Severity)
	}
	if len(poprawka.CVEIDs) != 0 {
		t.Errorf("poprawka bledu dostala CVE: %v", poprawka.CVEIDs)
	}

	bezpieczenstwo := ustalenia[1]
	if bezpieczenstwo.Type != TypSecurity || bezpieczenstwo.Severity != "high" {
		t.Fatalf("ustalenie bezpieczenstwa: %+v", bezpieczenstwo)
	}
	// CVE wystepuje i w opisie, i w tytule odnosnika - ma zostac jedno.
	if len(bezpieczenstwo.CVEIDs) != 1 || bezpieczenstwo.CVEIDs[0] != "CVE-2026-35385" {
		t.Fatalf("CVE = %v", bezpieczenstwo.CVEIDs)
	}
	if bezpieczenstwo.IssuedAt == nil || bezpieczenstwo.IssuedAt.Year() != 2026 {
		t.Errorf("data wydania = %v", bezpieczenstwo.IssuedAt)
	}
	if len(bezpieczenstwo.Packages) != 4 {
		t.Fatalf("odczytano %d pakietow: %+v", len(bezpieczenstwo.Packages), bezpieczenstwo.Packages)
	}
	// Nazwa pakietu bywa dluzsza niz nazwa ustalenia i zawiera myslniki.
	znaleziony := false
	for _, pakiet := range bezpieczenstwo.Packages {
		if pakiet.Name == "openssh-clients" {
			znaleziony = true
			if pakiet.EVR != "9.9p1-14.fc42" || pakiet.Architecture != "x86_64" {
				t.Errorf("pakiet z myslnikiem odczytany jako %+v", pakiet)
			}
		}
	}
	if !znaleziony {
		t.Errorf("pakiet openssh-clients nie trafil na liste: %+v", bezpieczenstwo.Packages)
	}
}

func TestParsujNEVRACzytaNazweZMyslnikami(t *testing.T) {
	przypadki := map[string]AdvisoryPackage{
		"openssh-9.9p1-14.fc42.x86_64":       {Name: "openssh", EVR: "9.9p1-14.fc42", Architecture: "x86_64"},
		"openssh-clients-9.9p1-14.fc42.i686": {Name: "openssh-clients", EVR: "9.9p1-14.fc42", Architecture: "i686"},
		"python3-dnf-plugin-versionlock-4.5.0-1.fc42.noarch": {
			Name: "python3-dnf-plugin-versionlock", EVR: "4.5.0-1.fc42", Architecture: "noarch",
		},
		"kernel-6.17.4-200.fc42.src": {Name: "kernel", EVR: "6.17.4-200.fc42", Architecture: "src"},
	}
	for wpis, oczekiwany := range przypadki {
		wynik, ok := ParsujNEVRA(wpis)
		if !ok || wynik != oczekiwany {
			t.Errorf("%s -> %+v (ok=%v), oczekiwano %+v", wpis, wynik, ok, oczekiwany)
		}
	}
	for _, zly := range []string{"", "bezmyslnikow", "nazwa-bezarch"} {
		if _, ok := ParsujNEVRA(zly); ok {
			t.Errorf("%q zostal przyjety jako NEVRA", zly)
		}
	}
}
