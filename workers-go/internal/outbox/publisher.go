// Package outbox publica outbox_events no Asynq com semântica pelo-menos-uma-vez.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
)

const callTimeout = 5 * time.Second

// Event é uma linha de outbox_events ainda não publicada.
type Event struct {
	ID          string
	TenantID    *string
	Aggregate   string
	AggregateID string
	EventType   string
	Payload     json.RawMessage
	CreatedAt   time.Time
}

// Tx opera dentro de uma única transação de BD (um lote).
type Tx interface {
	FetchUnpublished(ctx context.Context, limit int) ([]Event, error)
	MarkPublished(ctx context.Context, ids []string) error
}

// Store executa fn numa transação: commit se fn devolver nil, rollback caso contrário.
type Store interface {
	InTx(ctx context.Context, fn func(Tx) error) error
}

// Enqueuer enfileira uma tarefa com TaskID = id do evento.
type Enqueuer interface {
	Enqueue(ctx context.Context, taskID, eventType string, envelope []byte) error
}

type envelope struct {
	ID          string          `json:"id"`
	TenantID    *string         `json:"tenant_id"`
	Aggregate   string          `json:"aggregate"`
	AggregateID string          `json:"aggregate_id"`
	EventType   string          `json:"event_type"`
	CreatedAt   time.Time       `json:"created_at"`
	Payload     json.RawMessage `json:"payload"`
}

type Publisher struct {
	Store    Store
	Enqueuer Enqueuer
	Batch    int
	Log      *slog.Logger
}

// RunOnce processa um lote; devolve o número de eventos marcados como publicados.
func (p *Publisher) RunOnce(ctx context.Context) (int, error) {
	published := 0
	err := p.Store.InTx(ctx, func(tx Tx) error {
		published = 0
		fctx, cancel := context.WithTimeout(ctx, callTimeout)
		events, err := tx.FetchUnpublished(fctx, p.Batch)
		cancel()
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(events))
		for _, ev := range events {
			if err := ctx.Err(); err != nil {
				return err // nada é marcado: rollback
			}
			body, err := json.Marshal(envelope{ev.ID, ev.TenantID, ev.Aggregate, ev.AggregateID, ev.EventType, ev.CreatedAt, ev.Payload})
			if err != nil {
				p.warn("envelope inválido", ev.ID, err)
				continue
			}
			ectx, cancel := context.WithTimeout(ctx, callTimeout)
			err = p.Enqueuer.Enqueue(ectx, ev.ID, ev.EventType, body)
			cancel()
			if err != nil && !errors.Is(err, asynq.ErrTaskIDConflict) && !errors.Is(err, asynq.ErrDuplicateTask) {
				p.warn("falha ao enfileirar", ev.ID, err)
				continue // fica para o ciclo seguinte
			}
			ids = append(ids, ev.ID)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		mctx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		if err := tx.MarkPublished(mctx, ids); err != nil {
			return err
		}
		published = len(ids)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return published, nil
}

// Run corre RunOnce a cada interval até ctx terminar.
func (p *Publisher) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := p.RunOnce(ctx); err != nil {
			if ctx.Err() == nil && p.Log != nil {
				p.Log.Error("ciclo do outbox falhou", "err", err.Error())
			}
		} else if n > 0 && p.Log != nil {
			p.Log.Info("outbox publicado", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Publisher) warn(msg, id string, err error) {
	if p.Log != nil {
		p.Log.Warn(msg, "event_id", id, "err", err.Error())
	}
}
