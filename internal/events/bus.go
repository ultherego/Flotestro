// Package events rozglasza zmiany stanu operacji do otwartych ekranow panelu.
//
// Zrodlem jest powiadomienie z PostgreSQL, a nie kanal w pamieci procesu.
// Panel moze dzialac w kilku instancjach, a agent laczy sie z ta, ktora
// akurat go przyjela - operator patrzacy przez inna instancje musi widziec
// to samo.
package events

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Kanal powiadomien w bazie.
const kanal = "flotestro_zadania"

// Event opisuje zmiane stanu jednej operacji.
type Event struct {
	JobID      string `json:"job_id"`
	State      string `json:"state"`
	CampaignID string `json:"campaign_id,omitempty"`
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

	if _, err := conn.Exec(ctx, "listen "+kanal); err != nil {
		return err
	}
	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
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
