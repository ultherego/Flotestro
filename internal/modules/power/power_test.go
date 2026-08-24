package power

import (
	"testing"
	"time"
)

func TestInhibitoryCzytaneZKolumnANiePoSpacjach(t *testing.T) {
	wyjscie := "WHO            UID USER PID COMM           WHAT  WHY                                       MODE\n" +
		"ModemManager   0   root 678 ModemManager   sleep ModemManager needs to reset devices       delay\n" +
		"UnattendedUpgr 0   root 912 unattended-upg shutdown Stop ordered but upgrade in progress   block\n" +
		"\n2 inhibitors listed.\n"
	blokady, znane := ParsujInhibitory(wyjscie)

	if !znane {
		t.Fatal("odczyt inhibitorow uznany za nieudany")
	}
	if len(blokady) != 2 {
		t.Fatalf("blokad = %d", len(blokady))
	}
	// Uzasadnienie ma spacje: podzial po bialych znakach urwalby je po
	// pierwszym slowie i zgubil kolumne trybu.
	if blokady[0].Why != "ModemManager needs to reset devices" {
		t.Errorf("powod = %q", blokady[0].Why)
	}
	if blokady[0].Mode != "delay" || blokady[0].PID != 678 {
		t.Errorf("blokada = %+v", blokady[0])
	}
	// "delay" opoznia, "block" nie pozwala w ogole - to dwie rozne odpowiedzi.
	if blokady[0].Blokuje() {
		t.Error("opoznienie uznane za blokade")
	}
	if !blokady[1].Blokuje() {
		t.Error("blokada uznana za opoznienie")
	}
}

// Brak blokad jest odpowiedzia hosta, a nie brakiem odpowiedzi.
func TestBrakInhibitorowToOdpowiedz(t *testing.T) {
	blokady, znane := ParsujInhibitory("No inhibitors.\n")
	if len(blokady) != 0 {
		t.Fatalf("blokad = %d", len(blokady))
	}
	if !znane {
		t.Error("pusta lista uznana za nieznana")
	}

	if _, znane := ParsujInhibitory("systemd-inhibit: command not found\n"); znane {
		t.Error("brak narzedzia uznany za pusta liste")
	}
}

func TestListaStartowCzytaIdentyfikatoryICzasy(t *testing.T) {
	wyjscie := " -2 684cfa5e381c4dcfa57c572f7c1036b6 Sun 2026-08-23 08:30:41 UTC Sun 2026-08-23 19:23:13 UTC\n" +
		" -1 3c4c6a15649744c8a69cd02c33b364c2 Sun 2026-08-23 19:23:48 UTC Sun 2026-08-23 20:54:46 UTC\n" +
		"  0 90b4ac23c8304fc4816e609ee28c9ea8 Mon 2026-08-24 16:40:09 UTC Mon 2026-08-24 17:17:35 UTC\n"
	starty := ParsujListeStartow(wyjscie)

	if len(starty) != 3 {
		t.Fatalf("startow = %d", len(starty))
	}
	if starty[2].Index != 0 || starty[2].BootID != "90b4ac23c8304fc4816e609ee28c9ea8" {
		t.Errorf("biezacy start = %+v", starty[2])
	}
	if starty[0].FirstEntry.IsZero() || starty[0].LastEntry.Before(starty[0].FirstEntry) {
		t.Errorf("czasy startu = %+v", starty[0])
	}
}

func TestZaplanowaneWylaczenieJestFaktem(t *testing.T) {
	chwila := time.Date(2026, 8, 24, 20, 0, 0, 0, time.UTC)
	tresc := "USEC=" + itoa(chwila.UnixMicro()) + "\nWARN_WALL=1\nMODE=poweroff\n"
	wylaczenie := ParsujZaplanowane(tresc)

	if wylaczenie == nil {
		t.Fatal("zaplanowane wylaczenie nieodczytane")
	}
	if wylaczenie.Mode != TrybWylaczyc || !wylaczenie.At.Equal(chwila) {
		t.Errorf("wylaczenie = %+v", wylaczenie)
	}
	// Plik bez czasu nie opisuje niczego, co da sie pokazac operatorowi.
	if ParsujZaplanowane("MODE=reboot\n") != nil {
		t.Error("wpis bez czasu uznany za zaplanowane wylaczenie")
	}
}

func TestUptimeNieZmyslaZera(t *testing.T) {
	if sekundy := ParsujUptime("12345.67 98765.43\n"); sekundy == nil || *sekundy != 12345.67 {
		t.Fatalf("uptime = %v", sekundy)
	}
	// Host dzialajacy zero sekund nie istnieje: nieodczytany plik zostaje
	// pustym wskaznikiem.
	if sekundy := ParsujUptime(""); sekundy != nil {
		t.Fatalf("pusty odczyt stal sie %v", *sekundy)
	}
}

func TestWylaczenieWymagaPowodu(t *testing.T) {
	if err := WalidujPowodWylaczenia("bo tak"); err == nil {
		t.Error("wylaczenie przeszlo bez powodu")
	}
	if err := WalidujPowodWylaczenia("wymiana zasilacza w szafie B12"); err != nil {
		t.Errorf("sensowny powod odrzucony: %v", err)
	}
	if err := WalidujPowodWylaczenia("wymiana zasilacza\nMODE=reboot"); err == nil {
		t.Error("powod z nowa linia przeszedl walidacje")
	}
	if err := WalidujOpoznienie(7200); err == nil {
		t.Error("opoznienie ponad godzine przeszlo walidacje")
	}
}

func itoa(wartosc int64) string {
	if wartosc == 0 {
		return "0"
	}
	var cyfry []byte
	for wartosc > 0 {
		cyfry = append([]byte{byte('0' + wartosc%10)}, cyfry...)
		wartosc /= 10
	}
	return string(cyfry)
}
