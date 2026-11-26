package audit

// Raiz diária (spec 13 §3.4): tarefa Asynq às 00:10 UTC do dia anterior (TaskID audit-root-YYYY-MM-DD).
// Por tenant, um manifesto em t/<tenant_id|platform>/roots/YYYY/MM/DD.json só com as cadeias desse tenant.
// Já existe → compara (sem generated_at): igual = ok; diferente = alerta + erro (nunca sobrescreve).
// Dias em falta (marcador do dia anterior ausente) são recuperados por ordem. No mesmo job:
// audit_ensure_partitions(3) e audit_default_partition_rows() > 0 → alerta.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
)

const (
	RootTaskType   = "audit:root"
	RootQueue      = "audit"
	rootHourUTC    = 0
	rootMinuteUTC  = 10
	defaultBackfil = 31
	dayLayout      = "2006-01-02"
)

// ErrRootMismatch: o manifesto do WORM difere do recalculado (adulteração da BD ou do WORM).
var ErrRootMismatch = errors.New("audit: manifesto no WORM difere da BD")

// DB é satisfeito por *pgxpool.Pool.
type DB interface {
	TxBeginner
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ManifestChain: uma cadeia (chain_key, classe) num dia.
type ManifestChain struct {
	ChainKey       string `json:"chain_key"`
	RetentionClass string `json:"retention_class"`
	FirstSeq       int64  `json:"first_seq"`
	LastSeq        int64  `json:"last_seq"`
	LastHash       string `json:"last_hash"` // hex
	Events         int64  `json:"events"`
}

// Manifest: raiz diária de um tenant.
type Manifest struct {
	Day                string          `json:"day"`
	GeneratedAt        string          `json:"generated_at"`
	Chains             []ManifestChain `json:"chains"`
	PrevManifestSHA256 string          `json:"prev_manifest_sha256"`
}

// sameManifest: igual em tudo exceto generated_at.
func sameManifest(stored, want []byte) bool {
	var a, b Manifest
	if json.Unmarshal(stored, &a) != nil || json.Unmarshal(want, &b) != nil {
		return false
	}
	a.GeneratedAt, b.GeneratedAt = "", ""
	if a.Chains == nil {
		a.Chains = []ManifestChain{}
	}
	if b.Chains == nil {
		b.Chains = []ManifestChain{}
	}
	return reflect.DeepEqual(a, b)
}

// RootJob publica as raízes diárias. Campos a zero = valores por omissão.
type RootJob struct {
	DB          DB
	Worm        WormStore
	Alert       Alerter
	Retention   time.Duration // WORM_ROOTS_RETENTION_DAYS
	Tenants     []string      // âmbito (testes/reposição); vazio = todos
	MaxBackfill int           // dias recuperados no máximo (31)
	Now         func() time.Time
	Log         *slog.Logger
}

func (j *RootJob) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

func dayUTC(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// scope normaliza j.Tenants; nil = todos.
func scope(tenants []string) map[string]bool {
	if len(tenants) == 0 {
		return nil
	}
	m := make(map[string]bool, len(tenants))
	for _, t := range tenants {
		m[tenantOf(t)] = true
	}
	return m
}

// marker: o manifesto escrito em último lugar em cada dia (platform; com âmbito, o 1.º tenant).
func (j *RootJob) marker() string {
	if len(j.Tenants) > 0 {
		return tenantOf(j.Tenants[0])
	}
	return platformTenant
}

// Run publica a raiz de day e, antes, a dos dias em falta (por ordem). Erros: ErrRootMismatch (permanente)
// ou de infraestrutura (repetir).
func (j *RootJob) Run(ctx context.Context, day time.Time) error {
	day = dayUTC(day)
	maxBack := j.MaxBackfill
	if maxBack <= 0 {
		maxBack = defaultBackfil
	}
	days := []time.Time{day}
	started := false
	for d, i := day.AddDate(0, 0, -1), 0; i < maxBack; d, i = d.AddDate(0, 0, -1), i+1 {
		_, err := j.Worm.Get(ctx, rootKey(j.marker(), d))
		if err == nil {
			started = true
			break
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		days = append(days, d)
	}
	slices.Reverse(days)

	var errs []error
	for _, d := range days {
		roots, err := dayRoots(ctx, j.DB, d)
		if err != nil {
			return err
		}
		sc := scope(j.Tenants)
		byTenant := map[string][]ManifestChain{}
		for _, c := range roots {
			t := tenantOf(c.ChainKey)
			if sc == nil || sc[t] {
				byTenant[t] = append(byTenant[t], c)
			}
		}
		if !started && len(byTenant) == 0 {
			continue // antes do 1.º evento: nada a ancorar
		}
		started = true
		tenants, err := j.tenants(ctx, byTenant)
		if err != nil {
			return err
		}
		for _, t := range tenants {
			if err := j.publish(ctx, t, d, byTenant[t]); err != nil {
				if !errors.Is(err, ErrRootMismatch) {
					return errors.Join(append(errs, err)...)
				}
				errs = append(errs, err)
			}
		}
		if j.Log != nil {
			j.Log.Info("raiz diária publicada", "day", d.Format(dayLayout), "tenants", len(tenants))
		}
	}
	if err := j.maintain(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// tenants do dia: com âmbito, os do âmbito; sem âmbito, platform + os das cabeças + os do dia. O marcador
// fica em último (só existe se o dia inteiro foi publicado).
func (j *RootJob) tenants(ctx context.Context, byTenant map[string][]ManifestChain) ([]string, error) {
	set := map[string]bool{}
	if sc := scope(j.Tenants); sc != nil {
		set = sc
	} else {
		set[platformTenant] = true
		for t := range byTenant {
			set[t] = true
		}
		chains, err := listChains(ctx, j.DB)
		if err != nil {
			return nil, err
		}
		for _, c := range chains {
			set[tenantOf(c.ChainKey)] = true
		}
	}
	m := j.marker()
	out := make([]string, 0, len(set))
	for t := range set {
		if t != m {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return append(out, m), nil
}

func (j *RootJob) publish(ctx context.Context, tenant string, day time.Time, chains []ManifestChain) error {
	prev := ""
	pb, err := j.Worm.Get(ctx, rootKey(tenant, day.AddDate(0, 0, -1)))
	switch {
	case err == nil:
		sum := sha256.Sum256(pb)
		prev = hex.EncodeToString(sum[:])
	case !errors.Is(err, ErrNotFound):
		return err
	}
	if chains == nil {
		chains = []ManifestChain{}
	}
	body, err := json.Marshal(Manifest{
		Day: day.Format(dayLayout), GeneratedAt: j.now().UTC().Format(time.RFC3339),
		Chains: chains, PrevManifestSHA256: prev,
	})
	if err != nil {
		return err
	}
	key := rootKey(tenant, day)
	err = putOnce(ctx, j.Worm, key, body, j.now().Add(j.Retention), sameManifest)
	if errors.Is(err, ErrMismatch) {
		aerr := j.notify(ctx, Alert{Kind: KindRootMismatch,
			Summary: fmt.Sprintf("raiz de %s do tenant %s difere da BD (%s); o WORM não foi alterado",
				day.Format(dayLayout), tenant, key)})
		return errors.Join(fmt.Errorf("%w: %s", ErrRootMismatch, key), aerr)
	}
	return err
}

func (j *RootJob) notify(ctx context.Context, a Alert) error {
	if j.Log != nil {
		j.Log.Error("alerta da caixa negra", "kind", a.Kind, "summary", a.Summary)
	}
	if j.Alert == nil {
		return errors.New("alerta: sem Alerter")
	}
	return j.Alert.Notify(ctx, a)
}

// maintain: partições dos próximos 3 meses e linhas na DEFAULT (> 0 = faltam partições → alerta).
func (j *RootJob) maintain(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := j.DB.Begin(cctx)
	if err != nil {
		return sanitize(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(cctx)) }()
	if err := SetSystemActor(cctx, tx, "audit-root"); err != nil {
		return sanitize(err)
	}
	if _, err := tx.Exec(cctx, `SELECT audit.audit_ensure_partitions(3::int)`); err != nil {
		return sanitize(err)
	}
	if err := tx.Commit(cctx); err != nil {
		return sanitize(err)
	}
	var n int64
	if err := j.DB.QueryRow(cctx, `SELECT audit.audit_default_partition_rows()`).Scan(&n); err != nil {
		return sanitize(err)
	}
	if n > 0 {
		return j.notify(ctx, Alert{Kind: KindDefaultPartition,
			Summary: fmt.Sprintf("%d eventos de auditoria na partição DEFAULT (faltam partições mensais)", n)})
	}
	return nil
}

// dayRoots: audit.audit_day_root(day).
func dayRoots(ctx context.Context, db DB, day time.Time) ([]ManifestChain, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	rows, err := db.Query(cctx, `SELECT chain_key::text, retention_class, first_seq, last_seq, last_hash, events
		FROM audit.audit_day_root($1::date)`, day.Format(dayLayout))
	if err != nil {
		return nil, sanitize(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ManifestChain, error) {
		var c ManifestChain
		var h []byte
		err := r.Scan(&c.ChainKey, &c.RetentionClass, &c.FirstSeq, &c.LastSeq, &h, &c.Events)
		c.LastHash = hex.EncodeToString(h)
		return c, err
	})
	return out, sanitize(err)
}

type chainHead struct {
	ChainKey string
	Class    string
	LastSeq  int64
}

// listChains: audit.audit_chains().
func listChains(ctx context.Context, db DB) ([]chainHead, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := db.Query(cctx, `SELECT chain_key::text, retention_class, last_seq FROM audit.audit_chains()`)
	if err != nil {
		return nil, sanitize(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (chainHead, error) {
		var c chainHead
		err := r.Scan(&c.ChainKey, &c.Class, &c.LastSeq)
		return c, err
	})
	return out, sanitize(err)
}

// --- Asynq ---------------------------------------------------------------------------------------

type rootPayload struct {
	Day string `json:"day"`
}

// RootTask: tarefa da raiz de day (TaskID audit-root-YYYY-MM-DD, fila audit).
func RootTask(day time.Time) (*asynq.Task, []asynq.Option) {
	d := dayUTC(day).Format(dayLayout)
	b, _ := json.Marshal(rootPayload{Day: d})
	return asynq.NewTask(RootTaskType, b), []asynq.Option{
		asynq.TaskID("audit-root-" + d), asynq.Queue(RootQueue), asynq.MaxRetry(20),
		asynq.Retention(7 * 24 * time.Hour), asynq.Timeout(30 * time.Minute),
	}
}

// Handle processa a tarefa. Divergência = permanente (SkipRetry; o alerta já saiu).
func (j *RootJob) Handle(ctx context.Context, t *asynq.Task) error {
	var p rootPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("audit:root payload: %w", asynq.SkipRetry)
	}
	day, err := time.Parse(dayLayout, p.Day)
	if err != nil {
		return fmt.Errorf("audit:root dia inválido: %w", asynq.SkipRetry)
	}
	err = j.Run(ctx, day)
	if err != nil && onlyMismatch(err) {
		return fmt.Errorf("%w (%w)", err, asynq.SkipRetry)
	}
	return err
}

func onlyMismatch(err error) bool {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			if !onlyMismatch(e) {
				return false
			}
		}
		return true
	}
	return errors.Is(err, ErrRootMismatch)
}

// Enqueuer é satisfeito por *asynq.Client.
type Enqueuer interface {
	EnqueueContext(ctx context.Context, task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error)
}

// EnqueueRoot põe na fila a raiz de day; TaskID repetido (outro worker ou já feita) = ok.
func EnqueueRoot(ctx context.Context, e Enqueuer, day time.Time) error {
	task, opts := RootTask(day)
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, err := e.EnqueueContext(cctx, task, opts...)
	if errors.Is(err, asynq.ErrTaskIDConflict) {
		return nil
	}
	return err
}

// nextRootRun: próxima ocorrência de 00:10 UTC depois de now.
func nextRootRun(now time.Time) time.Time {
	t := dayUTC(now).Add(rootHourUTC*time.Hour + rootMinuteUTC*time.Minute)
	if !t.After(now) {
		t = t.AddDate(0, 0, 1)
	}
	return t
}

// ScheduleRoots: no arranque (se já passou das 00:10 UTC) e todos os dias às 00:10 UTC põe na fila a raiz
// do dia anterior. Corre até ctx terminar.
func ScheduleRoots(ctx context.Context, e Enqueuer, log *slog.Logger) {
	enqueue := func(now time.Time) {
		day := dayUTC(now).AddDate(0, 0, -1)
		if err := EnqueueRoot(ctx, e, day); err != nil && log != nil {
			log.Error("raiz diária: enqueue falhou", "day", day.Format(dayLayout), "err", err.Error())
		}
	}
	now := time.Now().UTC()
	if now.Sub(dayUTC(now)) >= rootHourUTC*time.Hour+rootMinuteUTC*time.Minute {
		enqueue(now)
	}
	for {
		next := nextRootRun(time.Now().UTC())
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			enqueue(next)
		}
	}
}
