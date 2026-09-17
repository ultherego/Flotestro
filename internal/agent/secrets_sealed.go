package agent

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/relayproof"
)

// fetchSecret fetches the value of a secret for one task.
//
// The request carries the host's own proof whenever the session can sign:
// the identity envelope over the request, and a one-time X25519 key signed
// by the host key for this task and this secret. On a direct connection
// the gateway ignores both and answers with the value as it is; through a
// relay it answers sealed to the one-time key, and the value exists in
// the clear only here, after the cipher text authenticated. A relay on
// the way carries the routing and the cipher text, never the plaintext.
// The one-time key lives for this call and is written nowhere.
func fetchSecret(ctx context.Context, client agentv1connect.AgentServiceClient,
	signer *relayproof.Signer, taskID, name string, version int) ([]byte, error) {
	request := &agentv1.FetchSecretRequest{
		TaskId: taskID, SecretName: name, SecretVersion: uint32(version),
	}
	var ephemeral *relayproof.EphemeralKey
	if signer != nil {
		call := signer.ForCall()
		key, err := relayproof.NewEphemeralKey()
		if err != nil {
			return nil, err
		}
		ephemeral = key
		request.EphemeralPublicKey = key.PublicKey()
		request.EphemeralKeySignature, err = relayproof.SignEphemeralKey(call.Key(), taskID, name, key.PublicKey())
		if err != nil {
			return nil, err
		}
		// The envelope signs the request as it stands without the envelope
		// itself; the gateway clears the field before it digests.
		envelope, err := call.SignRequest(relayproof.KindFetchSecret, request)
		if err != nil {
			return nil, err
		}
		request.Identity = envelope
	}

	response, err := client.FetchSecret(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	answer := response.Msg
	if answer.GetSealing() != "" || len(answer.GetSealedValue()) > 0 {
		return openSealedSecret(ephemeral, answer, taskID, name)
	}
	value := answer.GetValue()
	// The panel gives the digest of what it issued: this checks that
	// exactly that arrived and not content damaged on the way.
	if digest := answer.GetSha256(); digest != "" && digest != valueDigest(value) {
		return nil, errors.New("the digest of the fetched secret does not match the one given by the panel")
	}
	return value, nil
}

// openSealedSecret opens a sealed answer with the one-time key of the
// call. A scheme this release does not know is refused by name rather than
// tried: the host must not guess at a cipher.
func openSealedSecret(ephemeral *relayproof.EphemeralKey, answer *agentv1.FetchSecretResponse,
	taskID, name string) ([]byte, error) {
	if answer.GetSealing() != relayproof.Sealing {
		return nil, errors.New("the panel sealed the secret with a scheme this agent does not know: " + answer.GetSealing())
	}
	if ephemeral == nil {
		return nil, errors.New("the panel answered sealed, but this fetch offered no one-time key")
	}
	if len(answer.GetValue()) > 0 {
		// A sealed answer carries no plaintext. One that does is not the
		// panel's answer.
		return nil, errors.New("the sealed answer also carries the value in the clear")
	}
	value, err := ephemeral.Open(answer.GetServerPublicKey(), answer.GetSealedValue(), answer.GetSealedNonce(),
		relayproof.SecretAAD(taskID, name, answer.GetVersion()))
	if err != nil {
		return nil, errors.New("the sealed secret did not open: " + err.Error())
	}
	return value, nil
}
