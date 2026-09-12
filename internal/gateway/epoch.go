package gateway

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// epochChannel is the channel of the notifications about a new session of a
// host.
//
// The notification goes through the database, because the database is the only
// point that sees both gateways. A gateway holding an older session has no
// other way of learning that the host has switched somewhere else: its stream
// still looks alive until it tries to send something over it.
//
// The name of the channel stays as it is until a migration renames it together
// with the trigger that publishes on it.
const epochChannel = "flotestro_sesje"

// WatchEpochs closes the sessions that have been superseded on another
// gateway.
//
// Without it two gateways would consider themselves the right one for the same
// host and the same job would go out twice - and irreversible operations would
// be carried out twice.
func WatchEpochs(ctx context.Context, pool *pgxpool.Pool, registry *Registry,
	gatewayID string, log interface {
		Info(string, ...any)
		Error(string, ...any)
	}) {
	for ctx.Err() == nil {
		if err := watchEpochs(ctx, pool, registry, gatewayID, log); err != nil && ctx.Err() == nil {
			log.Error("the listening for session epochs was interrupted", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func watchEpochs(ctx context.Context, pool *pgxpool.Pool, registry *Registry,
	gatewayID string, log interface {
		Info(string, ...any)
		Error(string, ...any)
	}) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "listen "+epochChannel); err != nil {
		return err
	}
	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		hostID, epoch, source, ok := splitNotification(notification.Payload)
		if !ok || source == gatewayID {
			// We do not handle our own notification: it is this gateway that
			// has just opened the new session and closed the previous one
			// itself.
			continue
		}
		session, running := registry.Get(hostID)
		if !running || session.Epoch >= epoch {
			continue
		}
		session.End("superseded")
		log.Info("the session was superseded on another gateway",
			"host_id", hostID, "session_id", session.ID,
			"epoch", session.Epoch, "new_epoch", epoch, "gateway", source)
	}
}

// splitNotification reads "host_id epoch gateway_id".
func splitNotification(payload string) (hostID string, epoch int64, gatewayID string, ok bool) {
	parts := strings.SplitN(payload, " ", 3)
	if len(parts) != 3 {
		return "", 0, "", false
	}
	number, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0, "", false
	}
	return parts[0], number, parts[2], true
}

// announceEpoch tells the other gateways that a host has a newer session.
func announceEpoch(ctx context.Context, pool *pgxpool.Pool, hostID string,
	epoch int64, gatewayID string) error {
	_, err := pool.Exec(ctx, "select pg_notify($1, $2)", epochChannel,
		fmt.Sprintf("%s %d %s", hostID, epoch, gatewayID))
	return err
}
