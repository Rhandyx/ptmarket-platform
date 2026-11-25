package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	callTimeout = 5 * time.Second
	txTimeout   = 30 * time.Second
	appendSQL   = `SELECT audit.audit_append_event($1::jsonb)`
)

// TxBeginner é satisfeito por *pgxpool.Pool.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// PoisonError: o evento foi recusado pela BD por ser inválido (nunca vai gravar).
type PoisonError struct {
	Index int    // posição no lote
	Code  string // SQLSTATE
	Msg   string // mensagem da BD (só cita chaves, nunca valores)
}

func (e *PoisonError) Error() string {
	return fmt.Sprintf("evento venenoso (SQLSTATE %s): %s", e.Code, e.Msg)
}

// asPoison devolve o PoisonError se err for PTA02 ou jsonb ilegível (22P02 / 22P05).
func asPoison(err error, i int) *PoisonError {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return nil
	}
	switch pg.Code {
	case "PTA02", "22P02", "22P05":
		return &PoisonError{Index: i, Code: pg.Code, Msg: pg.Message}
	}
	return nil
}

// PgStore grava eventos do stream por audit.audit_append_event (papel ptmarket_worker).
type PgStore struct {
	DB TxBeginner
}

// WriteAll grava o lote numa só transação: tudo ou nada. Devolve quantos eram novos.
// Um evento venenoso aborta tudo e devolve *PoisonError (o chamador repete com WriteEach).
func (s PgStore) WriteAll(ctx context.Context, events [][]byte) (int, error) {
	inserted := 0
	err := s.inTx(ctx, func(tctx context.Context, tx pgx.Tx) error {
		inserted = 0
		for i, ev := range events {
			ok, err := appendOne(tctx, tx, ev)
			if err != nil {
				if p := asPoison(err, i); p != nil {
					return p
				}
				return err
			}
			if ok {
				inserted++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return inserted, nil
}

// WriteEach grava o lote numa só transação, um a um com SAVEPOINT: os venenosos ficam de fora
// (devolvidos por índice), os restantes gravam. Qualquer outro erro aborta tudo (nada gravado).
func (s PgStore) WriteEach(ctx context.Context, events [][]byte) (int, map[int]*PoisonError, error) {
	var (
		inserted int
		poison   map[int]*PoisonError
	)
	err := s.inTx(ctx, func(tctx context.Context, tx pgx.Tx) error {
		inserted, poison = 0, map[int]*PoisonError{}
		for i, ev := range events {
			if _, err := tx.Exec(tctx, `SAVEPOINT audit_ev`); err != nil {
				return err
			}
			ok, err := appendOne(tctx, tx, ev)
			if err != nil {
				p := asPoison(err, i)
				if p == nil {
					return err
				}
				poison[i] = p
				if _, err := tx.Exec(tctx, `ROLLBACK TO SAVEPOINT audit_ev`); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.Exec(tctx, `RELEASE SAVEPOINT audit_ev`); err != nil {
				return err
			}
			if ok {
				inserted++
			}
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return inserted, poison, nil
}

func appendOne(ctx context.Context, tx pgx.Tx, ev []byte) (bool, error) {
	var ok bool
	// json.RawMessage: o JSON segue tal e qual, sem ser reinterpretado pelo Go.
	err := tx.QueryRow(ctx, appendSQL, json.RawMessage(ev)).Scan(&ok)
	return ok, err
}

func (s PgStore) inTx(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	tctx, cancel := context.WithTimeout(ctx, txTimeout)
	defer cancel()
	tx, err := s.DB.Begin(tctx)
	if err != nil {
		return err
	}
	if err := fn(tctx, tx); err != nil {
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), callTimeout)
		defer rcancel()
		_ = tx.Rollback(rctx)
		return err
	}
	return tx.Commit(tctx)
}
