package gateway

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// kanalEpok jest kanalem powiadomien o nowej sesji hosta.
//
// Powiadomienie idzie przez baze, bo baza jest jedynym punktem, ktory widzi
// obie bramy. Brama, ktora trzyma starsza sesje, nie ma innego sposobu, zeby
// dowiedziec sie, ze host przelaczyl sie gdzie indziej: jej stream nadal
// wyglada na zywy, dopoki nie sprobuje przez niego czegos wyslac.
const kanalEpok = "flotestro_sesje"

// NasluchujEpok zamyka sesje, ktore zostaly zastapione na innej bramie.
//
// Bez tego dwie bramy uwazalyby sie za wlasciwe dla tego samego hosta i to
// samo zadanie pojechaloby dwa razy - a operacje nieodwracalne wykonalyby sie
// podwojnie.
func NasluchujEpok(ctx context.Context, pool *pgxpool.Pool, registry *Registry,
	gatewayID string, log interface {
		Info(string, ...any)
		Error(string, ...any)
	}) {
	for ctx.Err() == nil {
		if err := nasluchujEpok(ctx, pool, registry, gatewayID, log); err != nil && ctx.Err() == nil {
			log.Error("nasluch epok sesji przerwany", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func nasluchujEpok(ctx context.Context, pool *pgxpool.Pool, registry *Registry,
	gatewayID string, log interface {
		Info(string, ...any)
		Error(string, ...any)
	}) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "listen "+kanalEpok); err != nil {
		return err
	}
	for {
		powiadomienie, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		hostID, epoka, zrodlo, ok := rozbijPowiadomienie(powiadomienie.Payload)
		if !ok || zrodlo == gatewayID {
			// Wlasnego powiadomienia nie obslugujemy: to ta brama wlasnie
			// otworzyla nowa sesje i sama zamknela poprzednia.
			continue
		}
		sesja, trwa := registry.Get(hostID)
		if !trwa || sesja.Epoka >= epoka {
			continue
		}
		sesja.Zakoncz("superseded")
		log.Info("sesja zastapiona na innej bramie",
			"host_id", hostID, "session_id", sesja.ID,
			"epoka", sesja.Epoka, "nowa_epoka", epoka, "brama", zrodlo)
	}
}

// rozbijPowiadomienie czyta "host_id epoka gateway_id".
func rozbijPowiadomienie(payload string) (hostID string, epoka int64, gatewayID string, ok bool) {
	czesci := strings.SplitN(payload, " ", 3)
	if len(czesci) != 3 {
		return "", 0, "", false
	}
	numer, err := strconv.ParseInt(czesci[1], 10, 64)
	if err != nil {
		return "", 0, "", false
	}
	return czesci[0], numer, czesci[2], true
}

// ogloszEpoke mowi pozostalym bramom, ze host ma nowsza sesje.
func ogloszEpoke(ctx context.Context, pool *pgxpool.Pool, hostID string,
	epoka int64, gatewayID string) error {
	_, err := pool.Exec(ctx, "select pg_notify($1, $2)", kanalEpok,
		fmt.Sprintf("%s %d %s", hostID, epoka, gatewayID))
	return err
}
