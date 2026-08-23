package helper

import (
	"context"
	"encoding/json"
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
