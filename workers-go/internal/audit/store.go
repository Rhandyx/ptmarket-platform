package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	callTimeout = 5 * time.Second
	appendSQL   = `SELECT audit.audit_append_event($1::jsonb)`

	// Lote curto: as cabeças de cadeia ficam bloqueadas (FOR UPDATE) até ao COMMIT. O audit_append das
	// transações de negócio espera no máximo 2 s (lock_timeout); o escritor segura-as no máximo MaxTx.
	defaultMaxTx       = time.Second            // prazo duro da transação (BEGIN → COMMIT)
	defaultLockTimeout = 250 * time.Millisecond // espera do escritor por uma cabeça bloqueada
	defaultAttempts    = 4                      // tentativas em 55P03/40P01
	backoffBase        = 50 * time.Millisecond
	backoffCap         = 800 * time.Millisecond
)

// TxBeginner é satisfeito por *pgxpool.Pool.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// PoisonError: o evento foi recusado pela BD por ser inválido (nunca vai gravar).
// Só o SQLSTATE: a mensagem da BD pode citar valores (dados pessoais) e nunca sai daqui.
type PoisonError struct {
	Index int    // posição no lote
	Code  string // SQLSTATE
}

func (e *PoisonError) Error() string {
	return fmt.Sprintf("evento venenoso (SQLSTATE %s)", e.Code)
}

// DBError: erro da BD reduzido ao SQLSTATE (a mensagem e o detalhe podem citar valores).
type DBError struct {
	Code string
}

func (e *DBError) Error() string { return fmt.Sprintf("erro da BD (SQLSTATE %s)", e.Code) }

// Retryable: conflito de bloqueios (55P03 lock_not_available, 40P01 deadlock_detected).
func (e *DBError) Retryable() bool { return e.Code == "55P03" || e.Code == "40P01" }

// Infra: a BD não está em condições (ligação, recursos, paragem, cancelamento, E/S). Não é culpa do
// evento: nunca conta para a fila morta.
func (e *DBError) Infra() bool {
	if len(e.Code) < 2 {
		return true
	}
	switch e.Code[:2] {
	case "08", "53", "57", "58":
		return true
	}
	return false
}

// poisonCodes: PTA02 (contrato inválido), PTA03 (id repetido com conteúdo diferente) e jsonb ilegível.
func isPoisonCode(code string) bool {
	switch code {
	case "PTA02", "PTA03", "22P02", "22P05":
		return true
	}
	return false
}

// asPoison devolve o PoisonError se err for um SQLSTATE venenoso.
func asPoison(err error, i int) *PoisonError {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && isPoisonCode(pg.Code) {
		return &PoisonError{Index: i, Code: pg.Code}
	}
	return nil
}

// sanitize troca um *pgconn.PgError por *DBError (só o SQLSTATE); os restantes erros passam.
func sanitize(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return &DBError{Code: pg.Code}
	}
	return err
}

// WriteResult: Done = eventos do início do lote confirmados (COMMIT); Inserted = quantos eram novos.
type WriteResult struct {
	Done     int
	Inserted int
}

// PgStore grava eventos do stream por audit.audit_append_event (papel ptmarket_worker).
// Campos a zero = valores por omissão.
type PgStore struct {
	DB          TxBeginner
	MaxTx       time.Duration // prazo duro da transação (1 s); deixa de pegar em eventos a meio dele
	LockTimeout time.Duration // SET LOCAL lock_timeout (250 ms)
	Attempts    int           // tentativas em 55P03/40P01 (4), com backoff exponencial e jitter
}

func (s PgStore) maxTx() time.Duration {
	if s.MaxTx <= 0 {
		return defaultMaxTx
	}
	return s.MaxTx
}

func (s PgStore) lockTimeout() time.Duration {
	if s.LockTimeout <= 0 {
		return defaultLockTimeout
	}
	return s.LockTimeout
}

func (s PgStore) attempts() int {
	if s.Attempts <= 0 {
		return defaultAttempts
	}
	return s.Attempts
}

// Write grava um prefixo de events numa transação curta (tudo ou nada). Para de pegar em eventos a
// meio de MaxTx: Done pode ser < len(events) (o chamador continua com o resto).
// Erros: *PoisonError (Index = posição em events; nada gravado), *DBError (só SQLSTATE; nada gravado)
// ou erro de ligação. 55P03/40P01 repetem-se aqui com backoff exponencial e jitter.
func (s PgStore) Write(ctx context.Context, events [][]byte) (WriteResult, error) {
	if len(events) == 0 {
		return WriteResult{}, nil
	}
	for attempt := 0; ; attempt++ {
		res, err := s.writeOnce(ctx, events)
		var db *DBError
		if err == nil || !errors.As(err, &db) || !db.Retryable() || attempt+1 >= s.attempts() {
			return res, err
		}
		if err := sleep(ctx, backoff(attempt)); err != nil {
			return WriteResult{}, err
		}
	}
}

// backoff: exponencial com teto e jitter ("equal jitter": metade fixa, metade aleatória).
func backoff(attempt int) time.Duration {
	d := backoffBase << attempt
	if d > backoffCap || d <= 0 {
		d = backoffCap
	}
	return d/2 + rand.N(d/2+1)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (s PgStore) writeOnce(ctx context.Context, events [][]byte) (res WriteResult, err error) {
	bctx, bcancel := context.WithTimeout(ctx, callTimeout)
	tx, err := s.DB.Begin(bctx)
	bcancel()
	if err != nil {
		return WriteResult{}, sanitize(err)
	}
	start := time.Now()
	tctx, cancel := context.WithDeadline(ctx, start.Add(s.maxTx()))
	defer cancel()
	defer func() {
		if err != nil {
			rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), callTimeout)
			defer rcancel()
			_ = tx.Rollback(rctx)
			res = WriteResult{}
		}
	}()

	lt := strconv.FormatInt(s.lockTimeout().Milliseconds(), 10) + "ms"
	if _, err := tx.Exec(tctx, `SELECT set_config('lock_timeout', $1::text, true)`, lt); err != nil {
		return res, sanitize(err)
	}
	// Margem para o último evento (≤ lock_timeout + execução) e o COMMIT caberem no prazo duro.
	soft := start.Add(s.maxTx() / 2)
	for i, ev := range events {
		if i > 0 && time.Now().After(soft) {
			break
		}
		ok, err := appendOne(tctx, tx, ev)
		if err != nil {
			if p := asPoison(err, i); p != nil {
				return res, p
			}
			return res, sanitize(err)
		}
		res.Done++
		if ok {
			res.Inserted++
		}
	}
	if err := tx.Commit(tctx); err != nil {
		return res, sanitize(err)
	}
	return res, nil
}

func appendOne(ctx context.Context, tx pgx.Tx, ev []byte) (bool, error) {
	var ok bool
	// json.RawMessage: o JSON segue tal e qual, sem ser reinterpretado pelo Go.
	err := tx.QueryRow(ctx, appendSQL, json.RawMessage(ev)).Scan(&ok)
	return ok, err
}
