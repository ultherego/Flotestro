// Package events rozglasza zmiany stanu operacji do otwartych ekranow panelu.
//
// Zrodlem jest powiadomienie z PostgreSQL, a nie kanal w pamieci procesu.
// Panel moze dzialac w kilku instancjach, a agent laczy sie z ta, ktora
// akurat go przyjela - operator patrzacy przez inna instancje musi widziec
// to samo.
package events

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Kanaly powiadomien w bazie. Postep jest osobny, bo jest ulotny: nie
// zapisujemy go i nie wolno wnioskowac z niego o wyniku.
const (
	kanal         = "flotestro_zadania"
	kanalPostep   = "flotestro_postep"
	kanalKampanie = "flotestro_kampanie"
	kanalLogow    = "flotestro_logi"
)

// Event opisuje zmiane stanu jednej operacji albo jej postep.
type Event struct {
	JobID      string `json:"job_id"`
	State      string `json:"state,omitempty"`
	CampaignID string `json:"campaign_id,omitempty"`
	// Progress jest wypelniony dla zdarzen postepu. Postep nie zmienia stanu
	// operacji i nie zastepuje jej wyniku.
	Progress *Progress `json:"progress,omitempty"`
	// Log jest wypelniony dla podgladu dziennika. Linie sa ulotne: nie sa
	// zapisywane i nie da sie ich odczytac po fakcie.
	Log *LogLines `json:"log,omitempty"`
}

// LogLines to kawalek podgladu dziennika.
type LogLines struct {
	Lines []string `json:"lines"`
	// Dropped mowi, ile linii pominieto przez limit tempa. Ciche pominiecie
	// kazaloby operatorowi wierzyc, ze widzi wszystko.
	Dropped uint32 `json:"dropped,omitempty"`
}

// Progress opisuje postep operacji w toku.
type Progress struct {
	Step    uint32  `json:"step,omitempty"`
	Total   uint32  `json:"total,omitempty"`
	Percent *uint32 `json:"percent,omitempty"`
	Message string  `json:"message,omitempty"`
}

// Bus rozglasza zdarzenia do subskrybentow w tym procesie.
type Bus struct {
	pool *pgxpool.Pool

	mu          sync.Mutex
	subskrypcje map[int]subskrypcja
	nastepny    int
}

type subskrypcja struct {
	filtr func(Event) bool
	kanal chan Event
}

func NewBus(pool *pgxpool.Pool) *Bus {
	return &Bus{pool: pool, subskrypcje: map[int]subskrypcja{}}
}

// Run nasluchuje powiadomien do konca kontekstu. Zerwane polaczenie jest
// odtwarzane: utrata nasluchu nie moze cicho zatrzymac postepu na ekranach.
func (b *Bus) Run(ctx context.Context, log interface{ Error(string, ...any) }) {
	odstep := time.Second
	for ctx.Err() == nil {
		if err := b.nasluchuj(ctx); err != nil && ctx.Err() == nil {
			log.Error("nasluch powiadomien przerwany", "err", err, "ponowienie_za", odstep.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(odstep):
			}
			if odstep < 30*time.Second {
				odstep *= 2
			}
			continue
		}
		odstep = time.Second
	}
}

func (b *Bus) nasluchuj(ctx context.Context) error {
	// Nasluch zajmuje polaczenie na wylacznosc, wiec bierzemy je z puli
	// i trzymamy, zamiast wypozyczac przy kazdym powiadomieniu.
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	for _, nazwa := range []string{kanal, kanalPostep, kanalKampanie, kanalLogow} {
		if _, err := conn.Exec(ctx, "listen "+nazwa); err != nil {
			return err
		}
	}
	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		switch notification.Channel {
		case kanalPostep:
			b.rozglos(parsujPostep(notification.Payload))
		case kanalKampanie:
			b.rozglos(parsujCel(notification.Payload))
		case kanalLogow:
			b.rozglos(parsujPostep(notification.Payload))
		default:
			b.rozglos(parsuj(notification.Payload))
		}
	}
}

// parsuj czyta tresc powiadomienia: identyfikator, stan i opcjonalna kampanie.
func parsuj(payload string) Event {
	czesci := strings.SplitN(payload, " ", 3)
	event := Event{}
	if len(czesci) > 0 {
		event.JobID = czesci[0]
	}
	if len(czesci) > 1 {
		event.State = czesci[1]
	}
	if len(czesci) > 2 {
		event.CampaignID = strings.TrimSpace(czesci[2])
	}
	return event
}

// parsujCel czyta powiadomienie o zmianie stanu celu kampanii. Cel nie jest
// operacja: przechodzi przez wlasne stany, ktorych zadne zadanie nie
// odzwierciedla, wiec jego zdarzenie nie niesie identyfikatora operacji.
func parsujCel(payload string) Event {
	czesci := strings.SplitN(payload, " ", 2)
	event := Event{}
	if len(czesci) > 0 {
		event.CampaignID = czesci[0]
	}
	if len(czesci) > 1 {
		event.State = strings.TrimSpace(czesci[1])
	}
	return event
}

// parsujPostep czyta powiadomienie o postepie zapisane jako JSON.
func parsujPostep(payload string) Event {
	var event Event
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		return Event{}
	}
	return event
}

// PublishLog rozglasza kawalek podgladu dziennika. Linie ida osobnym kanalem
// niz postep: postep opisuje operacje, a podglad jest jej trescia.
func (b *Bus) PublishLog(ctx context.Context, event Event) error {
	if event.JobID == "" {
		return nil
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = b.pool.Exec(ctx, "select pg_notify($1, $2)", kanalLogow, string(payload))
	return err
}

// PublishProgress rozglasza postep operacji. Postep nie jest zapisywany:
// idzie przez powiadomienie i znika. Ekran, ktory sie wlasnie podlaczyl,
// zobaczy dopiero nastepny - i to wystarczy, bo wynik i tak jest w bazie.
func (b *Bus) PublishProgress(ctx context.Context, event Event) error {
	if event.JobID == "" {
		return nil
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = b.pool.Exec(ctx, "select pg_notify($1, $2)", kanalPostep, string(payload))
	return err
}

func (b *Bus) rozglos(event Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, sub := range b.subskrypcje {
		if !sub.filtr(event) {
			continue
		}
		select {
		case sub.kanal <- event:
		default:
			// Wolny odbiorca nie moze wstrzymac rozglaszania. Zgubione
			// zdarzenie nie gubi stanu: ekran i tak odczytuje go z bazy,
			// a kolejne zdarzenie go dogoni.
		}
	}
}

// Subscribe zwraca kanal zdarzen pasujacych do filtru oraz funkcje konczaca
// subskrypcje.
func (b *Bus) Subscribe(filtr func(Event) bool) (<-chan Event, func()) {
	kanalZdarzen := make(chan Event, 16)
	b.mu.Lock()
	id := b.nastepny
	b.nastepny++
	b.subskrypcje[id] = subskrypcja{filtr: filtr, kanal: kanalZdarzen}
	b.mu.Unlock()

	return kanalZdarzen, func() {
		b.mu.Lock()
		delete(b.subskrypcje, id)
		b.mu.Unlock()
	}
}

// ForJob filtruje zdarzenia jednej operacji.
func ForJob(jobID string) func(Event) bool {
	return func(event Event) bool { return event.JobID == jobID }
}

// ForCampaign filtruje zdarzenia operacji jednej kampanii.
func ForCampaign(campaignID string) func(Event) bool {
	return func(event Event) bool { return event.CampaignID == campaignID }
}
