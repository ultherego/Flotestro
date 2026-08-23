package network

import "os"

// Nazwy adapterow zapisu. Panel nie zaklada, ze host da sie skonfigurowac:
// maszyna z recznie utrzymywanym /etc/network/interfaces jest dla tego modulu
// tylko do odczytu i ma to powiedziec wprost.
const (
	AdapterNetworkManager = "networkmanager"
	AdapterNmstate        = "nmstate"
	AdapterNetplan        = "netplan"
)

// WykryjAdapter wskazuje mechanizm, ktorym da sie zmieniac konfiguracje sieci.
//
// Kolejnosc nie jest przypadkowa: nmstate i NetworkManager opisuja stan
// docelowy i potrafia go wycofac, netplan wymaga wygenerowania konfiguracji
// dla warstwy nizej. Pusty wynik oznacza host, na ktorym panel tylko czyta -
// i to jest odpowiedz, a nie brak odpowiedzi.
func WykryjAdapter(istnieje func(string) bool) string {
	switch {
	case istnieje("/usr/bin/nmstatectl") || istnieje("/usr/sbin/nmstatectl"):
		return AdapterNmstate
	case istnieje("/usr/bin/nmcli") && istnieje("/run/NetworkManager"):
		return AdapterNetworkManager
	case istnieje("/usr/sbin/netplan") && istnieje("/etc/netplan"):
		return AdapterNetplan
	}
	return ""
}

// Istnieje sprawdza obecnosc sciezki w systemie plikow.
func Istnieje(sciezka string) bool {
	_, err := os.Stat(sciezka)
	return err == nil
}

// PowodBrakuZapisu tlumaczy, dlaczego panel nie zmieni tu konfiguracji.
func PowodBrakuZapisu(adapter string) string {
	if adapter != "" {
		return ""
	}
	return "this host has no NetworkManager, nmstate or netplan; network configuration is read-only here"
}
