package opspec

import (
	"strings"
	"testing"
)

// Identyfikator kontenera trafia do sciezki zapytania Engine API, wiec nie
// moze niesc niczego, co ta sciezke zmienia. Nazwa kontenera nie jest
// dozwolona celowo: jest etykieta i moze zostac przypisana innemu obiektowi
// miedzy planem a wykonaniem.
func TestCelKontenerowyMusiBycIdentyfikatorem(t *testing.T) {
	zle := []string{
		"", "moj-kontener", "../../images/json", "abc", "ABCDEF012345",
		"5c5b63d3119a/json", "5c5b63d3119a?all=1",
	}
	for _, id := range zle {
		payload := Payload{DockerContainer: &DockerContainerPayload{ContainerID: id}}
		if err := Validate(ActionDockerStop, payload); err == nil {
			t.Errorf("identyfikator %q zostal przyjety", id)
		}
	}
	dobre := Payload{DockerContainer: &DockerContainerPayload{
		ContainerID: "5c5b63d3119a59ac7a7a7f2a18342dbd01f459a88ca81487ba987ddcc5c4bc00",
	}}
	if err := Validate(ActionDockerStop, dobre); err != nil {
		t.Errorf("poprawny identyfikator odrzucony: %v", err)
	}
}

// Wolumen przezywa kontener wlasnie po to, zeby dane przezyly. Usuwanie
// wolumenow jest dozwolone tylko przy usuwaniu kontenera i tylko jawnie.
func TestUsuwanieWolumenowTylkoPrzyUsuwaniuKontenera(t *testing.T) {
	payload := Payload{DockerContainer: &DockerContainerPayload{
		ContainerID:   "5c5b63d3119a59ac7a7a7f2a18342dbd01f459a88ca81487ba987ddcc5c4bc00",
		RemoveVolumes: true,
	}}
	if err := Validate(ActionDockerStop, payload); err == nil {
		t.Error("zatrzymanie kontenera przyjelo usuwanie wolumenow")
	}
	if err := Validate(ActionDockerRemove, payload); err != nil {
		t.Errorf("usuniecie kontenera odrzucilo usuwanie wolumenow: %v", err)
	}
}

// Sprzatanie usuwa dokladnie to, co zostalo pokazane operatorowi. Pusta lista
// nie jest zleceniem "usun wszystko" - jest brakiem decyzji.
func TestSprzatanieWymagaJawnejListy(t *testing.T) {
	if err := Validate(ActionDockerPrune, Payload{DockerPrune: &DockerPrunePayload{}}); err == nil {
		t.Error("sprzatanie bez wskazanych obiektow zostalo przyjete")
	}

	dobre := Payload{DockerPrune: &DockerPrunePayload{
		ImageIDs: []string{"sha256:" + strings.Repeat("a", 64)},
	}}
	if err := Validate(ActionDockerPrune, dobre); err != nil {
		t.Errorf("poprawna lista odrzucona: %v", err)
	}

	zle := Payload{DockerPrune: &DockerPrunePayload{ImageIDs: []string{"nginx:latest"}}}
	if err := Validate(ActionDockerPrune, zle); err == nil {
		t.Error("tag obrazu przyjety jako identyfikator")
	}
}

// Odwolanie do obrazu jest sprawdzane, choc nie trafia do powloki: wezsza
// walidacja jest tansza niz ufanie.
func TestOdwolanieDoObrazuJestSprawdzane(t *testing.T) {
	dobre := []string{
		"nginx", "nginx:alpine", "docker.io/library/nginx:1.27",
		"rejestr.firma.pl:5000/zespol/aplikacja:2.1",
		"nginx@sha256:" + strings.Repeat("a", 64),
	}
	for _, odwolanie := range dobre {
		payload := Payload{DockerImage: &DockerImagePayload{Reference: odwolanie}}
		if err := Validate(ActionDockerPull, payload); err != nil {
			t.Errorf("odrzucono poprawne odwolanie %q: %v", odwolanie, err)
		}
	}
	zle := []string{"", "nginx latest", "nginx;reboot", "NGINX:latest", "-x"}
	for _, odwolanie := range zle {
		payload := Payload{DockerImage: &DockerImagePayload{Reference: odwolanie}}
		if err := Validate(ActionDockerPull, payload); err == nil {
			t.Errorf("przyjeto nieprawidlowe odwolanie %q", odwolanie)
		}
	}
}

// Poziom ryzyka nie jest etykieta: usuwanie kontenera i sprzatanie sa
// niszczace, wiec wymagaja swiezego uwierzytelnienia i wpisania nazwy celu.
func TestOperacjeNiszczaceWymagajaPotwierdzeniaCelu(t *testing.T) {
	for _, action := range []ActionType{ActionDockerRemove, ActionDockerPrune} {
		if action.Risk() != RiskDestructive {
			t.Errorf("%s ma ryzyko %s", action, action.Risk())
		}
		if !action.RequiresFreshAuth() || !action.RequiresTargetConfirmation() {
			t.Errorf("%s nie wymaga potwierdzenia celu", action)
		}
	}
	if ActionDockerStart.RequiresTargetConfirmation() {
		t.Error("uruchomienie kontenera wymaga wpisania nazwy celu")
	}
}
