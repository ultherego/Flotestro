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
	kanal       = "flotestro_zadania"
	kanalPostep = "flotestro_postep"
)

// Event opisuje zmiane stanu jednej operacji albo jej postep.
type Event struct {
	JobID      string `json:"job_id"`
	State      string `json:"state,omitempty"`
	CampaignID string `json:"campaign_id,omitempty"`
	// Progress jest wypelniony dla zdarzen postepu. Postep nie zmienia stanu
	// operacji i nie zastepuje jej wyniku.
	Progress *Progress `json:"progress,omitempty"`
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

	for _, nazwa := range []string{kanal, kanalPostep} {
		if _, err := conn.Exec(ctx, "listen "+nazwa); err != nil {
			return err
		}
	}
	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		if notification.Channel == kanalPostep {
			b.rozglos(parsujPostep(notification.Payload))
			continue
		}
		b.rozglos(parsuj(notification.Payload))
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

// parsujPostep czyta powiadomienie o postepie zapisane jako JSON.
func parsujPostep(payload string) Event {
	var event Event
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		return Event{}
	}
	return event
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
