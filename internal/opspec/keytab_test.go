package opspec

import "testing"

// A keytab renewal replaces the credential a service authenticates with:
// critical, the identity lock, the rotation's own permission, never in
// bulk, and a payload that names a service principal and never the host's
// own.
func TestKeytabRenewContract(t *testing.T) {
	action := ActionIdentityKeytabRenew
	if !action.Known() || !action.Mutating() || action.RequiredCapability() != "systemd" {
		t.Error("a keytab renewal is a mutation on a systemd host")
	}
	if action.Permission() != "identity.keytab.rotate" {
		t.Errorf("a keytab renewal has the permission %s", action.Permission())
	}
	if action.Risk() != RiskCritical || !action.RequiresFreshAuth() {
		t.Error("a keytab renewal has to be critical")
	}
	if action.LockClass() != LockIdentity {
		t.Errorf("a keytab renewal locks %q, expected identity", action.LockClass())
	}
	if action.CampaignMode() != CampaignNone {
		t.Error("a keytab renewal is one host's credential; it does not run in bulk")
	}
	if action.OfflinePolicy() != OfflineRequireOnline {
		t.Error("a keytab renewal requires the host online: the directory has already retired the old key")
	}
	contract := action.Contract()
	if contract.CancelMode != CancelImpossibleAfterStart || contract.RetryClass != RetryReadState ||
		contract.Rollback != RollbackNone || contract.Verification != VerifyCustom {
		t.Errorf("contract = %+v", contract)
	}

	valid := Payload{Keytab: &KeytabPayload{Principal: "HTTP/web1.flotestro.test@FLOTESTRO.TEST"}}
	if err := Validate(action, valid); err != nil {
		t.Errorf("a valid renewal was rejected: %v", err)
	}
	if err := Validate(action, Payload{Keytab: &KeytabPayload{Principal: "nfs/db1.flotestro.test"}}); err != nil {
		t.Errorf("a principal without a realm was rejected: %v", err)
	}
	for name, principal := range map[string]string{
		"empty":          "",
		"no host":        "HTTP",
		"a short host":   "HTTP/web1",
		"the host's own": "host/web1.flotestro.test@FLOTESTRO.TEST",
		"a space":        "HTTP/web1.flotestro.test -x",
		"a shell":        "HTTP/web1.flotestro.test;id",
	} {
		if err := Validate(action, Payload{Keytab: &KeytabPayload{Principal: principal}}); err == nil {
			t.Errorf("%s: %q passed", name, principal)
		}
	}
	if err := Validate(action, Payload{}); err == nil {
		t.Error("a renewal without a payload passed")
	}
}
