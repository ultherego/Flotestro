package adminapi

import "testing"

func TestLocalPathOdrzucaPrzekierowaniaNaZewnatrz(t *testing.T) {
	// Cel przekierowania po zalogowaniu pochodzi z parametru zapytania. Bez
	// walidacji logowanie stalo by sie otwartym przekierowaniem uzywanym
	// w phishingu: uzytkownik widzi zaufany adres panelu i laduje gdzie indziej.
	rejected := []string{
		"https://zly.example.com/",
		"//zly.example.com/",
		"http://zly.example.com",
		"javascript:alert(1)",
		"zly.example.com/sciezka",
	}
	for _, value := range rejected {
		if got := localPath(value); got != "" {
			t.Errorf("przyjeto zewnetrzny cel %q jako %q", value, got)
		}
	}
}

func TestLocalPathPrzyjmujeSciezkiLokalne(t *testing.T) {
	accepted := map[string]string{
		"/":               "/",
		"/hosts":          "/hosts",
		"/campaigns/123":  "/campaigns/123",
		"/hosts?site=lab": "/hosts",
	}
	for value, want := range accepted {
		if got := localPath(value); got != want {
			t.Errorf("localPath(%q) = %q, oczekiwano %q", value, got, want)
		}
	}
	if got := localPath(""); got != "" {
		t.Errorf("pusty cel dal %q", got)
	}
}
