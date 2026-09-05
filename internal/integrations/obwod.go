// Package integrations laczy panel z systemami, ktore juz w instalacji sa:
// z Prometheusem, Alertmanagerem i systemem logow. Panel ich nie zastepuje
// i nie kopiuje ich danych do siebie - pokazuje, co one mowia, razem
// z zakresem czasu i nazwa zrodla.
//
// Kazde z tych polaczen moze pasc, a panel ma dzialac dalej: awaria
// monitoringu nie moze zabrac operatorowi mozliwosci zarzadzania hostem.
// Stad wspolny bezpiecznik: krotki limit czasu na kazde pytanie i przerwa
// po serii bledow, zeby ekran hosta nie czekal na system, ktory nie
// odpowiada.
package integrations

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrOtwartyObwod oznacza, ze bezpiecznik jest otwarty i pytania nie ida
// dalej. To nie jest awaria panelu: to odpowiedz "to zrodlo teraz nie
// odpowiada", udzielona bez czekania.
var ErrOtwartyObwod = errors.New("integracja nie odpowiada; pytania sa wstrzymane")

const (
	// ProgBledow to liczba kolejnych bledow, po ktorej przestajemy pytac.
	ProgBledow = 3
	// PrzerwaObwodu to czas, po ktorym probujemy ponownie - jedno pytanie,
	// zeby sprawdzic, czy zrodlo wrocilo.
	PrzerwaObwodu = 30 * time.Second
	// DomyslnyLimitCzasu obowiazuje pojedyncze pytanie do integracji.
	// Ekran hosta ma sie narysowac takze wtedy, gdy monitoring milczy.
	DomyslnyLimitCzasu = 5 * time.Second
)

// Obwod jest bezpiecznikiem jednej integracji.
type Obwod struct {
	mu        sync.Mutex
	bledy     int
	otwartyDo time.Time
	// zegar pozwala sprawdzic zachowanie bez czekania.
	zegar func() time.Time
}

// NowyObwod tworzy bezpiecznik.
func NowyObwod() *Obwod {
	return &Obwod{zegar: time.Now}
}

// teraz zwraca biezaca chwile wedlug zegara bezpiecznika.
func (o *Obwod) teraz() time.Time {
	if o.zegar == nil {
		return time.Now()
	}
	return o.zegar()
}

// Wykonaj przepuszcza wywolanie albo odmawia od reki.
//
// Odmowa jest natychmiastowa i ma wlasny blad: ekran, ktory czeka piec sekund
// na kazdy z osmiu paneli, jest ekranem, ktorego nikt nie otworzy drugi raz.
func (o *Obwod) Wykonaj(wywolanie func() error) error {
	if err := o.przepusc(); err != nil {
		return err
	}
	err := wywolanie()
	o.zapisz(err)
	return err
}

func (o *Obwod) przepusc() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.otwartyDo.IsZero() || o.teraz().After(o.otwartyDo) {
		return nil
	}
	return ErrOtwartyObwod
}

func (o *Obwod) zapisz(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err == nil {
		// Jedna udana odpowiedz zamyka bezpiecznik: zrodlo wrocilo.
		o.bledy = 0
		o.otwartyDo = time.Time{}
		return
	}
	o.bledy++
	if o.bledy >= ProgBledow {
		o.otwartyDo = o.teraz().Add(PrzerwaObwodu)
		o.bledy = 0
	}
}

// Otwarty mowi, czy bezpiecznik wstrzymuje teraz pytania.
func (o *Obwod) Otwarty() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.otwartyDo.IsZero() && !o.teraz().After(o.otwartyDo)
}

// Stan opisuje dostepnosc integracji.
//
// Trzy odpowiedzi, nie dwie: integracja nieskonfigurowana to nie to samo, co
// integracja, ktora nie odpowiada. Pierwsza jest decyzja instalacji, druga
// awaria - i operator ma je rozroznic bez czytania konfiguracji.
type Stan struct {
	Name string `json:"name"`
	// Configured mowi, czy instalacja w ogole wskazala to zrodlo.
	Configured bool `json:"configured"`
	// Healthy mowi, czy zrodlo odpowiedzialo na ostatnie pytanie.
	Healthy bool   `json:"healthy"`
	URL     string `json:"url,omitempty"`
	// Reason opisuje, dlaczego zrodlo nie odpowiada.
	Reason string `json:"reason,omitempty"`
	// LatencyMillis mowi, jak dlugo trwala odpowiedz.
	LatencyMillis *int64     `json:"latency_millis,omitempty"`
	CheckedAt     *time.Time `json:"checked_at,omitempty"`
}

// ZLimitem zaweza kontekst do limitu czasu integracji.
func ZLimitem(ctx context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	if limit <= 0 {
		limit = DomyslnyLimitCzasu
	}
	return context.WithTimeout(ctx, limit)
}
