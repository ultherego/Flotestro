package helper

import (
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// TestSprzatanieOdrzucaNazweZeSciezka pilnuje granicy zaufania helpera:
// nazwa wolumenu trafia do sciezki zapytania Engine API, a helper dziala
// jako root i nie moze ufac tresci wiadomosci, choc panel juz ja sprawdzil.
func TestSprzatanieOdrzucaNazweZeSciezka(t *testing.T) {
	przypadki := []struct {
		nazwa   string
		zadanie *helperv1.DockerActionRequest
	}{
		{"wolumen ze sciezka", &helperv1.DockerActionRequest{
			VolumeNames: []string{"../containers/aaaa/kill"}}},
		{"wolumen z ukosnikiem", &helperv1.DockerActionRequest{
			VolumeNames: []string{"dane/../.."}}},
		{"obraz bez algorytmu", &helperv1.DockerActionRequest{
			ImageIds: []string{"latest"}}},
		{"siec spoza szesnastkowych", &helperv1.DockerActionRequest{
			NetworkIds: []string{"sklep_default"}}},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.nazwa, func(t *testing.T) {
			if powod := sprawdzListeSprzatania(przypadek.zadanie); powod == "" {
				t.Fatal("helper przyjal zadanie, ktore powinien odrzucic")
			}
		})
	}
}

func TestSprzatanieDopuszczaPoprawneObiekty(t *testing.T) {
	zadanie := &helperv1.DockerActionRequest{
		ImageIds:    []string{"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		VolumeNames: []string{"sklep_dane"},
		NetworkIds:  []string{"2701db76242ee094c5535ecd6ddde9ffea5d38c4ce5de57f13bfd924da4a9a10"},
	}
	if powod := sprawdzListeSprzatania(zadanie); powod != "" {
		t.Fatalf("poprawne zadanie odrzucone: %s", powod)
	}
}
