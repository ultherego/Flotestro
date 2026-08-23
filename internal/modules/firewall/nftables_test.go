package firewall

import (
	"strings"
	"testing"
)

// Wyjscie przepisane z hosta floty testowej: tablice dockera zarzadzane przez
// iptables-nft oraz wlasna tablica panelu.
const wyjscieNft = `# Warning: table ip nat is managed by iptables-nft, do not touch!
table ip nat { # handle 1
	chain DOCKER { # handle 1
		iifname "docker0" counter packets 0 bytes 0 return # handle 4
		iifname != "docker0" tcp dport 8081 counter packets 12 bytes 640 dnat to 172.17.0.2:80 # handle 13
	}

	chain POSTROUTING { # handle 2
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 172.17.0.0/16 oifname != "docker0" counter packets 3 bytes 180 masquerade # handle 3
	}
}
table inet flotestro { # handle 7
	chain wejscie { # handle 1
		type filter hook input priority filter; policy accept;
		tcp dport 8443 counter packets 5 bytes 300 accept comment "flotestro: kanal zarzadzania" # handle 2
		ip saddr 10.0.0.0/8 drop # handle 3
	}
}`

func TestRegulyNiosaTrescZNft(t *testing.T) {
	snapshot := ParsujRuleset(wyjscieNft)

	if snapshot.Adapter != AdapterNftables || snapshot.Hash == "" {
		t.Fatalf("adapter = %q, odcisk = %q", snapshot.Adapter, snapshot.Hash)
	}
	if len(snapshot.Tables) != 2 || len(snapshot.Chains) != 3 || len(snapshot.Rules) != 5 {
		t.Fatalf("tablic = %d, lancuchow = %d, regul = %d",
			len(snapshot.Tables), len(snapshot.Chains), len(snapshot.Rules))
	}

	// Tresc reguly jest tekstem od nft, bez uchwytu doklejonego na koncu:
	// operator zna ten zapis z wiersza polecen.
	var dnat Rule
	for _, regula := range snapshot.Rules {
		if regula.Handle == 13 {
			dnat = regula
		}
	}
	if strings.Contains(dnat.Text, "handle") {
		t.Errorf("tresc reguly niesie uchwyt: %q", dnat.Text)
	}
	if !strings.HasSuffix(dnat.Text, "dnat to 172.17.0.2:80") {
		t.Errorf("tresc reguly = %q", dnat.Text)
	}
	if dnat.Packets == nil || *dnat.Packets != 12 || dnat.Bytes == nil || *dnat.Bytes != 640 {
		t.Errorf("liczniki = %v / %v", dnat.Packets, dnat.Bytes)
	}
	// Regula bez licznika nie moze udawac, ze przeszlo przez nia zero pakietow.
	for _, regula := range snapshot.Rules {
		if regula.Handle == 3 && regula.Table == TabelaFlotestro && regula.Packets != nil {
			t.Errorf("regula bez licznika dostala zero: %+v", regula)
		}
	}
}

// Tablica nalezaca do innego programu jest przepisywana bez udzialu panelu,
// wiec regula w niej nie jest ani nasza, ani trwala.
func TestPochodzenieOdrozniaCudzeTablice(t *testing.T) {
	snapshot := ParsujRuleset(wyjscieNft)

	po := map[string]Table{}
	for _, tabela := range snapshot.Tables {
		po[tabela.Name] = tabela
	}
	if po["nat"].Source != SourceForeign || po["nat"].Owner != "iptables-nft" {
		t.Errorf("tablica nat = %+v", po["nat"])
	}
	if po["flotestro"].Source != SourceManaged {
		t.Errorf("tablica panelu = %+v", po["flotestro"])
	}
	for _, regula := range snapshot.Rules {
		if regula.Table == "nat" && regula.Source != SourceForeign {
			t.Errorf("regula w cudzej tablicy = %+v", regula)
		}
		if regula.Table == TabelaFlotestro && regula.Source != SourceManaged {
			t.Errorf("regula panelu = %+v", regula)
		}
	}
}

func TestZaczepienieLancuchaJestCzytane(t *testing.T) {
	snapshot := ParsujRuleset(wyjscieNft)

	po := map[string]Chain{}
	for _, lancuch := range snapshot.Chains {
		po[lancuch.Table+"/"+lancuch.Name] = lancuch
	}
	postrouting := po["nat/POSTROUTING"]
	if postrouting.Hook != "postrouting" || postrouting.Policy != "accept" ||
		postrouting.Type != "nat" || postrouting.Priority != "srcnat" {
		t.Errorf("lancuch bazowy = %+v", postrouting)
	}
	// Lancuch zwykly nie jest zaczepiony w sciezce pakietu i nie ma polityki;
	// wpisanie tam "accept" byloby falszem.
	if po["nat/DOCKER"].Hook != "" || po["nat/DOCKER"].Policy != "" {
		t.Errorf("lancuch zwykly dostal zaczepienie: %+v", po["nat/DOCKER"])
	}
}

// Liczniki rosna same, wiec nie moga zmieniac odcisku: inaczej kazdy odczyt
// uniewaznialby plan zlozony chwile wczesniej.
func TestOdciskNieZalezyOdLicznikow(t *testing.T) {
	pierwszy := ParsujRuleset(wyjscieNft).Hash
	drugi := ParsujRuleset(strings.ReplaceAll(wyjscieNft,
		"counter packets 12 bytes 640", "counter packets 99 bytes 9999")).Hash
	if pierwszy != drugi {
		t.Errorf("odcisk zmienil sie po zmianie licznikow: %q vs %q", pierwszy, drugi)
	}
	inny := ParsujRuleset(strings.ReplaceAll(wyjscieNft, "tcp dport 8443", "tcp dport 8444")).Hash
	if pierwszy == inny {
		t.Error("odcisk nie zmienil sie po zmianie reguly")
	}
}
