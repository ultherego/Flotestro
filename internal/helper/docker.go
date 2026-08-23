package helper

import (
	"context"
	"encoding/json"
	"regexp"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/docker"
)

// readDocker odczytuje stan silnika kontenerow.
//
// Gniazdo Dockera nalezy do roota, a czlonkostwo w grupie docker jest
// rownowazne rootowi - agent dzialajacy bez uprawnien nie moze go dostac.
// Dlatego rozmowa z silnikiem odbywa sie tutaj, a helper przyjmuje wylacznie
// wyliczony zakres odczytu, nie sciezke do Engine API.
func (s *Server) readDocker(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DockerReadRequest) *helperv1.HelperResponse {
	client, err := docker.New()
	if err != nil {
		return &helperv1.HelperResponse{
			Accepted: true,
			DockerResult: &helperv1.DockerReadResult{
				UnavailableReason: err.Error(),
			},
		}
	}

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = time.Minute
	}
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	snapshot := docker.Collect(readCtx, client)
	// Zakres podsumowania nie niesie pelnych list: inventory ma byc lekkie,
	// a lista kontenerow hosta budowlanego potrafi miec setki pozycji.
	if action.GetScope() != helperv1.DockerReadRequest_SCOPE_FULL {
		snapshot.Containers = nil
		snapshot.Images = nil
		snapshot.Networks = nil
		snapshot.Volumes = nil
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		DockerResult: &helperv1.DockerReadResult{
			Snapshot:          encoded,
			UnavailableReason: snapshot.Summary.UnavailableReason,
		},
	}
}

// applyDocker wykonuje operacje na silniku kontenerow.
//
// Identyfikator kontenera jest sprawdzany ponownie, choc panel juz go
// sprawdzil. Helper dziala jako root i nie moze ufac tresci wiadomosci:
// identyfikator trafia do sciezki zapytania Engine API.
func (s *Server) applyDocker(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DockerActionRequest) *helperv1.HelperResponse {
	client, err := docker.New()
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}

	// Jednoczesnie wykonuje sie najwyzej jedna mutacja kontenerow: rownolegly
	// restart i usuniecie tego samego kontenera daja nieprzewidywalny wynik.
	if !s.containerMutex.TryLock() {
		return reject(ErrorLocked, "inna operacja na kontenerach jest w toku")
	}
	defer s.containerMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > time.Hour {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	identyfikator := action.GetContainerId()
	if wymagaKontenera(action.GetOperation()) {
		if !identyfikatorKontenera.MatchString(identyfikator) {
			return reject(ErrorMalformed, "nieprawidlowy identyfikator kontenera")
		}
	}

	wynik := docker.Result{}
	if wymagaKontenera(action.GetOperation()) {
		wynik.Before = client.ContainerByID(actionCtx, identyfikator)
		if wynik.Before == nil {
			return reject(ErrorUnsupported, "kontener nie istnieje na tym hoscie")
		}
	}

	switch action.GetOperation() {
	case helperv1.DockerActionRequest_OPERATION_START:
		err = client.StartContainer(actionCtx, identyfikator)
	case helperv1.DockerActionRequest_OPERATION_STOP:
		err = client.StopContainer(actionCtx, identyfikator, action.GetTimeoutSeconds())
	case helperv1.DockerActionRequest_OPERATION_RESTART:
		err = client.RestartContainer(actionCtx, identyfikator, action.GetTimeoutSeconds())
	case helperv1.DockerActionRequest_OPERATION_REMOVE:
		err = client.RemoveContainer(actionCtx, identyfikator, action.GetRemoveVolumes())
	case helperv1.DockerActionRequest_OPERATION_PULL_IMAGE:
		var digest string
		digest, err = client.PullImage(actionCtx, action.GetImageReference())
		wynik.ImageDigest = digest
	case helperv1.DockerActionRequest_OPERATION_PRUNE:
		wynik, err = docker.Prune(actionCtx, client,
			action.GetImageIds(), action.GetVolumeNames(), action.GetNetworkIds())
	default:
		return reject(ErrorUnknownAction, "nieznana operacja na kontenerach")
	}

	// Stan po operacji jest odczytywany takze wtedy, gdy operacja padla:
	// bez tego nie wiadomo, czy zmiana zdazyla wejsc w zycie.
	if wymagaKontenera(action.GetOperation()) {
		wynik.After = client.ContainerByID(actionCtx, identyfikator)
	}

	odpowiedz := &helperv1.DockerActionResult{
		Before:         zakoduj(wynik.Before),
		After:          zakoduj(wynik.After),
		Removed:        wynik.Removed,
		ReclaimedBytes: wynik.ReclaimedBytes,
		ImageDigest:    wynik.ImageDigest,
	}
	if err != nil {
		response := reject(ErrorExecFailed, err.Error())
		response.DockerActionResult = odpowiedz
		return response
	}
	return &helperv1.HelperResponse{Accepted: true, DockerActionResult: odpowiedz}
}

// wymagaKontenera mowi, czy operacja dotyczy konkretnego kontenera.
func wymagaKontenera(operation helperv1.DockerActionRequest_Operation) bool {
	switch operation {
	case helperv1.DockerActionRequest_OPERATION_START,
		helperv1.DockerActionRequest_OPERATION_STOP,
		helperv1.DockerActionRequest_OPERATION_RESTART,
		helperv1.DockerActionRequest_OPERATION_REMOVE:
		return true
	}
	return false
}

// identyfikatorKontenera powtarza walidacje panelu. Helper nie ufa tresci
// wiadomosci, bo dziala jako root.
var identyfikatorKontenera = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// zakoduj zamienia stan kontenera na JSON. Brak kontenera zostaje pusty:
// kontener usuniety nie ma stanu po operacji i nie wolno go zmyslac.
func zakoduj(kontener *docker.Container) []byte {
	if kontener == nil {
		return nil
	}
	encoded, err := json.Marshal(kontener)
	if err != nil {
		return nil
	}
	return encoded
}
