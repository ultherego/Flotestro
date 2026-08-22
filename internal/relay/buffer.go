// Package relay implementuje relay lokalizacji: konczy polaczenia agentow,
// utrzymuje jedno polaczenie do centrali i buforuje wyniki na czas awarii
// lacza.
package relay

import (
	"errors"
	"sync"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"google.golang.org/protobuf/proto"
)

// ErrBufferFull oznacza wyczerpanie bufora. Relay zglasza to wprost zamiast
// po cichu gubic wyniki: utracony wynik zadania wyglada dla panelu jak zadanie
// nadal trwajace.
var ErrBufferFull = errors.New("bufor relaya jest pelny")

// Buffer przechowuje wiadomosci agentow na czas przerwy w lacznosci
// z centrala.
//
// Dokument wymaga bufora ograniczonego: relay w odcietej lokalizacji nie moze
// rosnac do wyczerpania dysku, bo wtedy zabiera lokalizacje takze to, co
// dziala lokalnie. Limit jest liczony w bajtach, bo to on odpowiada zajetosci
// zasobu, a nie liczba wiadomosci.
type Buffer struct {
	mu       sync.Mutex
	items    []*bufferedMessage
	bytes    int
	maxBytes int
	dropped  int
}

type bufferedMessage struct {
	hostID  string
	payload []byte
	size    int
}

func NewBuffer(maxBytes int) *Buffer {
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	return &Buffer{maxBytes: maxBytes}
}

// Add odklada wiadomosc agenta. Po przekroczeniu limitu nowe wiadomosci sa
// odrzucane, a nie kasuja starszych: starszy wynik zwykle dotyczy zadania,
// ktore juz sie skonczylo, i jest blizej dostarczenia niz nowszy.
func (b *Buffer) Add(hostID string, message *agentv1.AgentMessage) error {
	payload, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.bytes+len(payload) > b.maxBytes {
		b.dropped++
		return ErrBufferFull
	}
	b.items = append(b.items, &bufferedMessage{hostID: hostID, payload: payload, size: len(payload)})
	b.bytes += len(payload)
	return nil
}

// Take pobiera najstarsza wiadomosc bez usuwania jej z bufora. Wiadomosc
// znika dopiero po potwierdzonym wyslaniu: utrata na granicy sieci nie moze
// oznaczac utraty wyniku.
func (b *Buffer) Take() (hostID string, message *agentv1.AgentMessage, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) == 0 {
		return "", nil, false
	}
	item := b.items[0]
	decoded := &agentv1.AgentMessage{}
	if err := proto.Unmarshal(item.payload, decoded); err != nil {
		// Uszkodzonej wiadomosci nie da sie dostarczyc; usuwamy ja, zeby nie
		// zablokowala calej kolejki.
		b.removeFirstLocked()
		return "", nil, false
	}
	return item.hostID, decoded, true
}

// Commit usuwa potwierdzona wiadomosc.
func (b *Buffer) Commit() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removeFirstLocked()
}

func (b *Buffer) removeFirstLocked() {
	if len(b.items) == 0 {
		return
	}
	b.bytes -= b.items[0].size
	b.items = b.items[1:]
}

// Stats opisuje zajetosc bufora do metryk i do decyzji operatora.
type Stats struct {
	Messages int
	Bytes    int
	MaxBytes int
	Dropped  int
}

func (b *Buffer) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{Messages: len(b.items), Bytes: b.bytes, MaxBytes: b.maxBytes, Dropped: b.dropped}
}

// TakeFor zwraca najstarsza wiadomosc danego hosta bez usuwania jej z bufora.
// Bufor jest wspolny dla lokalizacji, ale odsyla sie go w sesji konkretnego
// hosta: centrala wiaze strumien z jedna tozsamoscia.
func (b *Buffer) TakeFor(hostID string) (*agentv1.AgentMessage, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, item := range b.items {
		if item.hostID != hostID {
			continue
		}
		decoded := &agentv1.AgentMessage{}
		if err := proto.Unmarshal(item.payload, decoded); err != nil {
			b.removeLocked(item)
			return nil, false
		}
		return decoded, true
	}
	return nil, false
}

// CommitFor usuwa najstarsza wiadomosc danego hosta.
func (b *Buffer) CommitFor(hostID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, item := range b.items {
		if item.hostID == hostID {
			b.removeLocked(item)
			return
		}
	}
}

func (b *Buffer) removeLocked(target *bufferedMessage) {
	for index, item := range b.items {
		if item != target {
			continue
		}
		b.bytes -= item.size
		b.items = append(b.items[:index], b.items[index+1:]...)
		return
	}
}
