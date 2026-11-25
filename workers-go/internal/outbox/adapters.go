package outbox

import (
	"context"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgStore implementa Store com pgx v5.
type PgStore struct{ Pool *pgxpool.Pool }

func (s PgStore) InTx(ctx context.Context, fn func(Tx) error) error {
	tctx, cancel := context.WithTimeout(ctx, callTimeout)
	tx, err := s.Pool.Begin(tctx)
	cancel()
	if err != nil {
		return err
	}
	if err := fn(pgTx{tx}); err != nil {
		rctx, c := context.WithTimeout(context.WithoutCancel(ctx), callTimeout)
		defer c()
		_ = tx.Rollback(rctx)
		return err
	}
	cctx, c := context.WithTimeout(context.WithoutCancel(ctx), callTimeout)
	defer c()
	return tx.Commit(cctx)
}

type pgTx struct{ tx pgx.Tx }

func (t pgTx) FetchUnpublished(ctx context.Context, limit int) ([]Event, error) {
	rows, err := t.tx.Query(ctx, `SELECT id::text, tenant_id::text, aggregate, aggregate_id::text, event_type, payload, created_at
FROM outbox_events WHERE published_at IS NULL ORDER BY created_at, id LIMIT $1 FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TenantID, &e.Aggregate, &e.AggregateID, &e.EventType, &e.Payload, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (t pgTx) MarkPublished(ctx context.Context, ids []string) error {
	_, err := t.tx.Exec(ctx, `UPDATE outbox_events SET published_at = now() WHERE id = ANY($1::uuid[])`, ids)
	return err
}

// AsynqEnqueuer implementa Enqueuer com asynq.Client.
type AsynqEnqueuer struct{ Client *asynq.Client }

func (e AsynqEnqueuer) Enqueue(ctx context.Context, taskID, eventType string, envelope []byte) error {
	_, err := e.Client.EnqueueContext(ctx, asynq.NewTask(eventType, envelope),
		asynq.TaskID(taskID), asynq.Queue("events"), asynq.MaxRetry(10), asynq.Retention(24*time.Hour))
	return err
}
