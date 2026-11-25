package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hibiken/asynq"
)

type fakeTx struct {
	events []Event
	marked []string
}

func (f *fakeTx) FetchUnpublished(context.Context, int) ([]Event, error) { return f.events, nil }
func (f *fakeTx) MarkPublished(_ context.Context, ids []string) error {
	f.marked = append(f.marked, ids...)
	return nil
}

type fakeStore struct{ tx *fakeTx }

func (s fakeStore) InTx(_ context.Context, fn func(Tx) error) error { return fn(s.tx) }

type fakeEnq struct {
	ids    []string
	bodies [][]byte
	errs   map[string]error
	hook   func()
}

func (f *fakeEnq) Enqueue(_ context.Context, id, _ string, body []byte) error {
	if f.hook != nil {
		f.hook()
	}
	if err := f.errs[id]; err != nil {
		return err
	}
	f.ids = append(f.ids, id)
	f.bodies = append(f.bodies, body)
	return nil
}

func events() []Event {
	t := "11111111-1111-1111-1111-111111111111"
	var out []Event
	for i := 1; i <= 3; i++ {
		out = append(out, Event{ID: fmt.Sprintf("e%d", i), TenantID: &t, Aggregate: "order", AggregateID: "a", EventType: "order.paid", Payload: json.RawMessage(`{}`), CreatedAt: time.Now()})
	}
	return out
}

func TestPublisher(t *testing.T) {
	t.Run("lote de 3", func(t *testing.T) {
		tx := &fakeTx{events: events()}
		enq := &fakeEnq{}
		n, err := (&Publisher{Store: fakeStore{tx}, Enqueuer: enq, Batch: 100}).RunOnce(context.Background())
		if err != nil || n != 3 || len(enq.ids) != 3 || len(tx.marked) != 3 {
			t.Fatalf("n=%d err=%v enq=%v marked=%v", n, err, enq.ids, tx.marked)
		}
		for i, id := range enq.ids {
			if tx.marked[i] != id {
				t.Errorf("marcado %q != taskID %q", tx.marked[i], id)
			}
		}
		var env map[string]any
		if err := json.Unmarshal(enq.bodies[0], &env); err != nil {
			t.Fatal(err)
		}
		if env["id"] != "e1" || env["tenant_id"] != "11111111-1111-1111-1111-111111111111" {
			t.Errorf("envelope: %v", env)
		}
	})
	t.Run("falha no 2.º", func(t *testing.T) {
		tx := &fakeTx{events: events()}
		enq := &fakeEnq{errs: map[string]error{"e2": errors.New("redis em baixo")}}
		n, err := (&Publisher{Store: fakeStore{tx}, Enqueuer: enq, Batch: 100}).RunOnce(context.Background())
		if err != nil || n != 2 || fmt.Sprint(tx.marked) != "[e1 e3]" {
			t.Fatalf("n=%d err=%v marked=%v", n, err, tx.marked)
		}
	})
	t.Run("conflito conta como publicado", func(t *testing.T) {
		tx := &fakeTx{events: events()}
		enq := &fakeEnq{errs: map[string]error{"e1": fmt.Errorf("x: %w", asynq.ErrTaskIDConflict), "e2": asynq.ErrDuplicateTask}}
		n, err := (&Publisher{Store: fakeStore{tx}, Enqueuer: enq, Batch: 100}).RunOnce(context.Background())
		if err != nil || n != 3 || len(tx.marked) != 3 {
			t.Fatalf("n=%d err=%v marked=%v", n, err, tx.marked)
		}
	})
	t.Run("contexto cancelado", func(t *testing.T) {
		tx := &fakeTx{events: events()}
		ctx, cancel := context.WithCancel(context.Background())
		enq := &fakeEnq{hook: cancel}
		n, err := (&Publisher{Store: fakeStore{tx}, Enqueuer: enq, Batch: 100}).RunOnce(ctx)
		if err == nil || n != 0 || len(tx.marked) != 0 {
			t.Fatalf("n=%d err=%v marked=%v", n, err, tx.marked)
		}
	})
}
