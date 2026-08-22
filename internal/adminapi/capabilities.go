package adminapi

import "net/http"

// serverCapabilities opisuje, ktore integracje sa w tej instalacji wlaczone.
//
// Flotestro jest panelem zarzadzania flota; integracja z katalogiem tozsamosci
// i z zewnetrznym dostawca logowania sa opcjonalne. Panel bez nich dziala
// w pelni, a interfejs nie moze pokazywac sekcji, ktore nie maja pokrycia
// w tej instalacji.
type serverCapabilities struct {
	// IdentityProvider mowi, czy operatorzy loguja sie przez OIDC.
	// Bez niego dziala uwierzytelnianie tokenem API.
	IdentityProvider bool   `json:"identity_provider"`
	Issuer           string `json:"issuer,omitempty"`
	// Directory mowi, czy skonfigurowany jest connector katalogu.
	Directory bool `json:"directory"`
	// DirectoryWrite mowi, czy panel moze zmieniac zawartosc katalogu.
	// Zmiany w katalogu sa osobnym modulem: klient moze chciec wylacznie
	// widoku, a zmiany robic swoimi narzedziami.
	DirectoryWrite bool `json:"directory_write"`
	// LocalUsers mowi, czy panel zarzadza kontami lokalnymi na hostach.
	LocalUsers bool `json:"local_users"`
}

// handleCapabilities zwraca wlaczone integracje. Endpoint nie wymaga
// uprawnien: opisuje instalacje, a nie jej dane.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	capabilities := serverCapabilities{
		IdentityProvider: s.oidc != nil,
		Directory:        s.directory != nil,
		DirectoryWrite:   s.directory != nil && s.directoryWrite,
		LocalUsers:       true,
	}
	if s.oidc != nil {
		capabilities.Issuer = s.oidc.Issuer()
	}
	writeJSON(w, http.StatusOK, capabilities)
}
