package audit

// Relay dos alertas da caixa negra (spec 13 §1): audit.audit_alerts por publicar (FOR UPDATE SKIP LOCKED,
// lotes de 100, a cada 30 s e no arranque) → WORM t/<tenant>/events/… (idempotente: se existe, compara) →
// se kind não é NULL (crítico, cartão 09a) → Alerter → published_at. Qualquer falha deixa a linha por
// publicar (volta na ronda seguinte). O worker só muda published_at de NULL para um valor; nunca apaga.
// Linha por publicar há mais de 15 min → alerta 'audit.alert_backlog'.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

const (
	defaultRelayBatch    = 100
	defaultRelayInterval = 30 * time.Second
	defaultBacklog       = 15 * time.Minute
	relayTxTimeout       = 5 * time.Minute
)

// Relay: Tenants = âmbito (testes); vazio = todos.
type Relay struct {
	DB        DB
	Worm      WormStore
	Alert     Alerter
	Retention time.Duration // WORM_EVENTS_RETENTION_DAYS
	Batch     int
	Interval  time.Duration
	Backlog   time.Duration
	Tenants   []string
	Now       func() time.Time
	Log       *slog.Logger

	lastBacklog time.Time
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

type alertRow struct {
	ID        string
	CreatedAt time.Time
	EventType string
	Kind      *string
	Payload   json.RawMessage
}

// wormAlert: o objeto gravado em events/ (ordem de campos fixa; payload tal como a BD o devolve).
type wormAlert struct {
	ID        string          `json:"id"`
	CreatedAt string          `json:"created_at"`
	EventType string          `json:"event_type"`
	Kind      *string         `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
}

// alertFields: só o que entra no resumo (sem dados pessoais; changes/reason nunca).
type alertFields struct {
	TenantID   *string `json:"tenant_id"`
	ActorType  string  `json:"actor_type"`
	ActorID    *string `json:"actor_id"`
	Action     string  `json:"action"`
	TargetType *string `json:"target_type"`
	TargetID   *string `json:"target_id"`
}

func deref(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func (r *Relay) scopeArg() []string {
	sc := scope(r.Tenants)
	if sc == nil {
		return nil
	}
	out := make([]string, 0, len(sc))
	for t := range sc {
		out = append(out, t)
	}
	return out
}

const tenantExpr = `COALESCE(lower(payload->>'tenant_id'), 'platform')`

// RunOnce publica um lote. Devolve quantas linhas ficaram publicadas.
func (r *Relay) RunOnce(ctx context.Context) (int, error) {
	batch := r.Batch
	if batch <= 0 {
		batch = defaultRelayBatch
	}
	tctx, cancel := context.WithTimeout(ctx, relayTxTimeout)
	defer cancel()
	tx, err := r.DB.Begin(tctx)
	if err != nil {
		return 0, sanitize(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(tctx)) }()
	if err := SetSystemActor(tctx, tx, "audit-alert-relay"); err != nil {
		return 0, sanitize(err)
	}
	rows, err := tx.Query(tctx, `SELECT id::text, created_at, event_type, kind, payload::text
		FROM audit.audit_alerts
		WHERE published_at IS NULL AND ($2::text[] IS NULL OR `+tenantExpr+` = ANY($2::text[]))
		ORDER BY created_at, id
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, batch, r.scopeArg())
	if err != nil {
		return 0, sanitize(err)
	}
	var list []alertRow
	for rows.Next() {
		var a alertRow
		var payload string
		if err := rows.Scan(&a.ID, &a.CreatedAt, &a.EventType, &a.Kind, &payload); err != nil {
			rows.Close()
			return 0, sanitize(err)
		}
		a.Payload = json.RawMessage(payload)
		list = append(list, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, sanitize(err)
	}

	var errs []error
	done := 0
	for _, a := range list {
		if err := r.relayOne(tctx, a); err != nil {
			errs = append(errs, fmt.Errorf("alerta %s: %w", a.ID, err))
			continue
		}
		ectx, ecancel := context.WithTimeout(tctx, callTimeout)
		_, err := tx.Exec(ectx, `UPDATE audit.audit_alerts SET published_at = clock_timestamp()
			WHERE id = $1::uuid AND published_at IS NULL`, a.ID)
		ecancel()
		if err != nil {
			errs = append(errs, sanitize(err))
			return 0, errors.Join(errs...) // a transação abortou: nada fica publicado
		}
		done++
	}
	if err := tx.Commit(tctx); err != nil {
		return 0, errors.Join(append(errs, sanitize(err))...)
	}
	return done, errors.Join(errs...)
}

func (r *Relay) relayOne(ctx context.Context, a alertRow) error {
	var f alertFields
	if err := json.Unmarshal(a.Payload, &f); err != nil {
		return errors.New("payload ilegível")
	}
	body, err := json.Marshal(wormAlert{
		ID: a.ID, CreatedAt: a.CreatedAt.UTC().Format(time.RFC3339Nano), EventType: a.EventType,
		Kind: a.Kind, Payload: a.Payload,
	})
	if err != nil {
		return err
	}
	tenant := platformTenant
	if f.TenantID != nil {
		tenant = tenantOf(*f.TenantID)
	}
	if err := putOnce(ctx, r.Worm, eventKey(tenant, a.CreatedAt, a.ID), body, r.now().Add(r.Retention), nil); err != nil {
		return err
	}
	if a.Kind == nil {
		return nil // ação de superadmin não crítica: só WORM
	}
	if r.Alert == nil {
		return errors.New("sem Alerter")
	}
	return r.Alert.Notify(ctx, Alert{
		Kind: *a.Kind,
		Summary: fmt.Sprintf("ator %s/%s · ação %s · alvo %s/%s · %s", f.ActorType, deref(f.ActorID),
			f.Action, deref(f.TargetType), deref(f.TargetID), a.CreatedAt.UTC().Format(time.RFC3339)),
		EventID: a.ID,
	})
}

// checkBacklog: linha por publicar há mais de Backlog → alerta (no máximo um por Backlog).
func (r *Relay) checkBacklog(ctx context.Context) error {
	backlog := r.Backlog
	if backlog <= 0 {
		backlog = defaultBacklog
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var oldest *time.Time
	var n int64
	if err := r.DB.QueryRow(cctx, `SELECT min(created_at), count(*) FROM audit.audit_alerts
		WHERE published_at IS NULL AND ($1::text[] IS NULL OR `+tenantExpr+` = ANY($1::text[]))`,
		r.scopeArg()).Scan(&oldest, &n); err != nil {
		return sanitize(err)
	}
	now := r.now()
	if oldest == nil || now.Sub(*oldest) <= backlog || now.Sub(r.lastBacklog) < backlog {
		return nil
	}
	a := Alert{Kind: KindAlertBacklog, Summary: fmt.Sprintf("%d alerta(s) da caixa negra por publicar; o mais antigo de %s",
		n, oldest.UTC().Format(time.RFC3339))}
	if r.Log != nil {
		r.Log.Error("alerta da caixa negra", "kind", a.Kind, "summary", a.Summary)
	}
	if r.Alert == nil {
		return errors.New("alerta: sem Alerter")
	}
	if err := r.Alert.Notify(ctx, a); err != nil {
		return err
	}
	r.lastBacklog = now
	return nil
}

// Round: lotes até esvaziar (ou falhar), depois o alerta de atraso.
func (r *Relay) Round(ctx context.Context) error {
	batch := r.Batch
	if batch <= 0 {
		batch = defaultRelayBatch
	}
	var errs []error
	for ctx.Err() == nil {
		n, err := r.RunOnce(ctx)
		if err != nil {
			errs = append(errs, err)
			break
		}
		if n < batch {
			break
		}
	}
	if err := r.checkBacklog(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Run: no arranque e a cada Interval até ctx terminar.
func (r *Relay) Run(ctx context.Context) {
	every := r.Interval
	if every <= 0 {
		every = defaultRelayInterval
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := r.Round(ctx); err != nil && r.Log != nil {
			r.Log.Error("relay de alertas da caixa negra", "err", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
