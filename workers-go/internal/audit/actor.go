package audit

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Execer é satisfeito por pgx.Tx (e por *pgxpool.Pool, mas só faz sentido numa transação).
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// SetSystemActor fixa o ator 'system' até ao fim da transação (set_config local).
// Obrigatório antes de qualquer INSERT/UPDATE/DELETE do worker (exceto outbox_events):
// sem ele a BD aborta com SQLSTATE PTA01. job identifica o job (vai para actor_label).
func SetSystemActor(ctx context.Context, tx Execer, job string) error {
	if job == "" {
		return errors.New("audit: SetSystemActor exige o nome do job")
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, err := tx.Exec(cctx,
		`SELECT set_config('app.actor_type', 'system', true), set_config('app.actor_label', $1::text, true)`,
		job)
	return err
}
