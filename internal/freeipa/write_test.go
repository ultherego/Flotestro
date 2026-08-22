package freeipa

import "testing"

func TestValidateSSHPublicKeyOdrzucaKluczPrywatny(t *testing.T) {
	// Klucz prywatny nigdy nie moze trafic do katalogu ani do logow.
	private := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----"
	if err := validateSSHPublicKey(private); err == nil {
		t.Fatal("klucz prywatny zostal przyjety")
	}
}

func TestValidateSSHPublicKeyOdrzucaSmieci(t *testing.T) {
	for _, key := range []string{"", "   ", "abcdef", "ssh-ed25519", "nieznany-typ AAAA"} {
		if err := validateSSHPublicKey(key); err == nil {
			t.Errorf("przyjeto nieprawidlowy klucz %q", key)
		}
	}
}

func TestValidateSSHPublicKeyPrzyjmujePoprawne(t *testing.T) {
	valid := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample uzytkownik@host",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC bez-komentarza",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=",
	}
	for _, key := range valid {
		if err := validateSSHPublicKey(key); err != nil {
			t.Errorf("odrzucono poprawny klucz %q: %v", key, err)
		}
	}
}

func TestUserSpecValidate(t *testing.T) {
	valid := UserSpec{UID: "jkowalski", LastName: "Kowalski"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("poprawny opis odrzucony: %v", err)
	}

	cases := map[string]UserSpec{
		"brak nazwiska":          {UID: "jkowalski"},
		"wielka litera w nazwie": {UID: "JKowalski", LastName: "Kowalski"},
		"nazwa ze spacja":        {UID: "jan kowalski", LastName: "Kowalski"},
		"nazwa ze sciezka":       {UID: "../root", LastName: "Kowalski"},
		"zla nazwa grupy":        {UID: "jkowalski", LastName: "Kowalski", Groups: []string{"grupa; rm"}},
		"klucz prywatny":         {UID: "jkowalski", LastName: "Kowalski", SSHKeys: []string{"-----BEGIN OPENSSH PRIVATE KEY-----"}},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if err := spec.Validate(); err == nil {
				t.Fatal("nieprawidlowy opis przeszedl walidacje")
			}
		})
	}
}

func TestZapisMaZamknietaListePolecen(t *testing.T) {
	// Adapter nie udostepnia polecen usuwajacych konta ani zmieniajacych
	// konfiguracje samego katalogu.
	for _, method := range []string{"user_add", "user_mod", "user_disable",
		"user_enable", "group_add_member", "group_remove_member"} {
		if !allowedMethod(method) {
			t.Errorf("polecenie zapisu %s powinno byc dozwolone", method)
		}
	}
	for _, method := range []string{"user_del", "group_del", "config_mod",
		"permission_add", "role_add_member", "hbacrule_add", "sudorule_add"} {
		if allowedMethod(method) {
			t.Errorf("polecenie %s nie powinno byc dostepne przez adapter", method)
		}
	}
}
