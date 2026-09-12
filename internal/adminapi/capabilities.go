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
	// CampaignV2 mowi, czy ta instalacja prowadzi kampanie z faza planowania:
	// planem per host, zgoda na zestaw planow, budzetami i kwalifikacja celow.
	// Interfejs nie moze pokazywac kreatora masowego tam, gdzie backend go nie
	// obsluguje - zamowienie skonczyloby sie bledem po wypelnieniu formularza.
	//
	// Odstepstwo od dokumentu: rozdzial o zgodnosci API kaze oznaczyc stare
	// /api/v1/campaigns jako legacy i zwracac link deprecation. W tej
	// instalacji nie ma starego silnika - pod tym adresem od poczatku stoi
	// ten z faza planowania, wiec nie ma czego oznaczac jako przestarzale.
	CampaignV2 bool `json:"campaign_v2"`
}

// handleCapabilities zwraca wlaczone integracje. Endpoint nie wymaga
// uprawnien: opisuje instalacje, a nie jej dane.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	capabilities := serverCapabilities{
		IdentityProvider: s.oidc != nil,
		Directory:        s.directory != nil,
		DirectoryWrite:   s.directory != nil && s.directoryWrite,
		LocalUsers:       true,
		// Kampanie sa opcjonalne: panel bez ich magazynu nadal prowadzi
		// operacje na pojedynczych hostach.
		CampaignV2: s.campaigns != nil,
	}
	if s.oidc != nil {
		capabilities.Issuer = s.oidc.Issuer()
	}
	writeJSON(w, http.StatusOK, capabilities)
}
