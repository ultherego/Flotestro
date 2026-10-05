package helpercap

import (
	"fmt"
	"sort"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Every operation that spends a secret has the same question to answer: are
// these the bytes the panel released, or bytes the agent chose. The receipt
// answers it, and until now only one consumer asked.
//
// The file write got a receipt first, because writing a secret into a path is
// writing any file on the host as root. The others are not milder: the
// repository password of a backup decides what the copy is encrypted with, so
// a substituted one makes a backup nobody can open with the stored secret; the
// environment of a backup carries the credentials of its object store; a
// certificate's private key is the identity of a service; the password of a
// package repository is what the host authenticates to a source of packages
// with. Each took the bytes of the request and the binding said only that *a*
// secret travelled.

// receiptsByName indexes the receipts of a request. A name given twice is
// refused rather than resolved: two receipts for one secret is not a question
// this has an answer to.
func receiptsByName(request *helperv1.HelperRequest) (map[string]*helperv1.SecretReceipt, error) {
	found := map[string]*helperv1.SecretReceipt{}
	for _, receipt := range request.GetSecretReceipts() {
		name := receipt.GetSecretName()
		if name == "" {
			return nil, refusal(ErrorPayloadBinding, "a receipt of the request names no secret")
		}
		if _, twice := found[name]; twice {
			return nil, refusal(ErrorPayloadBinding,
				fmt.Sprintf("the request carries two receipts for the secret %q", name))
		}
		found[name] = receipt
	}
	return found, nil
}

// secretSpend is one place a request carries the bytes of a secret: the name
// the consent gave the secret, the version it pinned if it pinned one, the
// bytes themselves, and what to call the field in a refusal.
type secretSpend struct {
	where     string
	reference *opspec.SecretRef
	bytes     []byte
}

// spentSecrets lists what a request spends, from the payload the panel signed
// beside the request that carries the bytes. The payload decides which secrets
// are expected; the request only supplies the bytes.
func spentSecrets(request *helperv1.HelperRequest, payload *BoundPayload) []secretSpend {
	var spent []secretSpend
	switch action := request.GetAction().(type) {
	case *helperv1.HelperRequest_File:
		if payload.Payload.File != nil && !payload.Payload.File.ContentSecret.Empty() && action.File.GetFromSecret() {
			spent = append(spent, secretSpend{"the content of the file",
				payload.Payload.File.ContentSecret, action.File.GetContent()})
		}
	case *helperv1.HelperRequest_Backup:
		if payload.Payload.Backup == nil {
			return nil
		}
		if !payload.Payload.Backup.PasswordSecret.Empty() && len(action.Backup.GetPassword()) > 0 {
			spent = append(spent, secretSpend{"the repository password",
				payload.Payload.Backup.PasswordSecret, action.Backup.GetPassword()})
		}
		names := make([]string, 0, len(payload.Payload.Backup.EnvSecrets))
		for name := range payload.Payload.Backup.EnvSecrets {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			reference := payload.Payload.Backup.EnvSecrets[name]
			value, carried := action.Backup.GetEnv()[name]
			if !carried {
				continue
			}
			spent = append(spent, secretSpend{"the environment value " + name, &reference, value})
		}
	case *helperv1.HelperRequest_Certificate:
		if payload.Payload.Certificate != nil && !payload.Payload.Certificate.KeySecret.Empty() &&
			len(action.Certificate.GetKey()) > 0 {
			spent = append(spent, secretSpend{"the private key",
				payload.Payload.Certificate.KeySecret, action.Certificate.GetKey()})
		}
	case *helperv1.HelperRequest_Repository:
		if payload.Payload.Repository != nil && !payload.Payload.Repository.PasswordSecret.Empty() &&
			len(action.Repository.GetPassword()) > 0 {
			spent = append(spent, secretSpend{"the repository password",
				payload.Payload.Repository.PasswordSecret, action.Repository.GetPassword()})
		}
	}
	return spent
}

// checkSpentSecrets binds every byte of a secret the request carries to the
// receipt the panel signed when it released it.
func (v *Verifier) checkSpentSecrets(request *helperv1.HelperRequest,
	capability *helperv1.HelperCapability, payload *BoundPayload) error {
	spent := spentSecrets(request, payload)
	if len(spent) == 0 {
		return nil
	}
	receipts, err := receiptsByName(request)
	if err != nil {
		return err
	}
	for _, place := range spent {
		receipt, carried := receipts[place.reference.Name]
		if !carried {
			return refusal(ErrorPayloadBinding, fmt.Sprintf(
				"%s comes from the secret %s and the request carries no receipt for its bytes",
				place.where, place.reference.Name))
		}
		// The signature and the clock first: an unsigned receipt's fields are
		// worth nothing.
		if err := v.VerifyReceipt(receipt); err != nil {
			return err
		}
		if receipt.GetHostId() != capability.GetHostId() {
			return refusal(ErrorPayloadBinding, fmt.Sprintf(
				"the receipt of %s names the host %q, the capability %q",
				place.reference.Name, receipt.GetHostId(), capability.GetHostId()))
		}
		if receipt.GetTaskId() != capability.GetTaskId() {
			return refusal(ErrorPayloadBinding, fmt.Sprintf(
				"the receipt of %s names the task %q, the capability %q",
				place.reference.Name, receipt.GetTaskId(), capability.GetTaskId()))
		}
		// Version 0 in the consent means "whatever is current when the task is
		// delivered", so there is nothing to compare it with; the receipt says
		// which version that turned out to be.
		if place.reference.Version != 0 && int(receipt.GetSecretVersion()) != place.reference.Version {
			return refusal(ErrorPayloadBinding, fmt.Sprintf(
				"the receipt of %s is for version %d and the consent pinned %d",
				place.reference.Name, receipt.GetSecretVersion(), place.reference.Version))
		}
		if got := contentDigest(place.bytes); got != receipt.GetSha256() {
			return refusal(ErrorPayloadBinding, fmt.Sprintf(
				"%s is not the bytes the panel released as %s", place.where, place.reference.Name))
		}
	}
	return nil
}
