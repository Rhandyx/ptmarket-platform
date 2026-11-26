package audit

// verify-audit (spec 13 §3.4): por cadeia e por dia, audit_verify_chain + audit_verify_actors, continuidade
// entre dias e comparação com o manifesto do WORM; uma vez por execução, audit_guc_defaults. Devolve as
// quebras (id, seq, problema), nunca o conteúdo dos eventos.
//
// StreamWatch (a cada 60 s, no worker): fila morta (> 0 → alerta; exporta para o WORM antes de aparar),
// stream parado (pendente com mais de 3 dias → alerta) e varredura dos resumos de 429 (script do cartão 07).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

// Break: uma quebra. ID/Seq vazios quando o problema é do dia ou da BD.
type Break struct {
	Day      string
	ChainKey string
	Class    string
	ID       string
	Seq      int64
	Problem  string
}

func (b Break) String() string {
	return fmt.Sprintf("day=%s chain=%s class=%s id=%s seq=%d problem=%s",
		or(b.Day, "-"), or(b.ChainKey, "-"), or(b.Class, "-"), or(b.ID, "-"), b.Seq, b.Problem)
}

// Verifier: Tenants = âmbito (vazio = todos). Grace: tempo depois do fim do dia até o manifesto em falta
// contar como quebra (1 h; a raiz corre às 00:10 UTC).
type Verifier struct {
	DB      DB
	Worm    WormStore
	Tenants []string
	Grace   time.Duration
	Now     func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify verifica os dias [from, to] (UTC, inclusivos).
func (v *Verifier) Verify(ctx context.Context, from, to time.Time) ([]Break, error) {
	from, to = dayUTC(from), dayUTC(to)
	if to.Before(from) {
		return nil, errors.New("verify: from depois de to")
	}
	grace := v.Grace
	if grace <= 0 {
		grace = time.Hour
	}
	var out []Break

	gucs, err := gucDefaults(ctx, v.DB)
	if err != nil {
		return nil, err
	}
	for _, g := range gucs {
		out = append(out, Break{Problem: "guc_default:" + g})
	}

	sc := scope(v.Tenants)
	heads, err := listChains(ctx, v.DB)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, h := range heads {
		if t := tenantOf(h.ChainKey); sc == nil || sc[t] {
			known[t] = true
		}
	}
	for t := range sc {
		known[t] = true
	}

	lastSeq := map[[2]string]int64{} // (chain, classe) → last_seq do último dia com eventos
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		ds := d.Format(dayLayout)
		roots, err := dayRoots(ctx, v.DB, d)
		if err != nil {
			return nil, err
		}
		byTenant := map[string]map[[2]string]ManifestChain{}
		for _, c := range roots {
			t := tenantOf(c.ChainKey)
			if sc != nil && !sc[t] {
				continue
			}
			if byTenant[t] == nil {
				byTenant[t] = map[[2]string]ManifestChain{}
			}
			k := [2]string{c.ChainKey, c.RetentionClass}
			byTenant[t][k] = c
			known[t] = true

			bs, err := v.chainWindow(ctx, c, d)
			if err != nil {
				return nil, err
			}
			out = append(out, bs...)
			if p, ok := lastSeq[k]; ok && c.FirstSeq != p+1 {
				out = append(out, Break{Day: ds, ChainKey: c.ChainKey, Class: c.RetentionClass, Seq: c.FirstSeq, Problem: "day_gap"})
			}
			lastSeq[k] = c.LastSeq
		}
		due := !v.now().Before(d.AddDate(0, 0, 1).Add(grace))
		for t := range known {
			bs, err := v.manifest(ctx, t, d, byTenant[t], due)
			if err != nil {
				return nil, err
			}
			out = append(out, bs...)
		}
	}
	return out, nil
}

// chainWindow: audit_verify_chain + audit_verify_actors numa janela de 1 dia.
func (v *Verifier) chainWindow(ctx context.Context, c ManifestChain, d time.Time) ([]Break, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ds := d.Format(dayLayout)
	from, to := d, d.AddDate(0, 0, 1)
	var out []Break
	rows, err := v.DB.Query(cctx, `SELECT broken_id::text, broken_seq, problem
		FROM audit.audit_verify_chain($1::uuid, $2::text, $3::timestamptz, $4::timestamptz)`,
		c.ChainKey, c.RetentionClass, from, to)
	if err != nil {
		return nil, sanitize(err)
	}
	bs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Break, error) {
		b := Break{Day: ds, ChainKey: c.ChainKey, Class: c.RetentionClass}
		err := r.Scan(&b.ID, &b.Seq, &b.Problem)
		return b, err
	})
	if err != nil {
		return nil, sanitize(err)
	}
	out = append(out, bs...)
	rows, err = v.DB.Query(cctx, `SELECT event_id::text, chain_seq, problem
		FROM audit.audit_verify_actors($1::uuid, $2::text, $3::timestamptz, $4::timestamptz)`,
		c.ChainKey, c.RetentionClass, from, to)
	if err != nil {
		return nil, sanitize(err)
	}
	bs, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Break, error) {
		b := Break{Day: ds, ChainKey: c.ChainKey, Class: c.RetentionClass}
		err := r.Scan(&b.ID, &b.Seq, &b.Problem)
		b.Problem = "actor:" + b.Problem
		return b, err
	})
	if err != nil {
		return nil, sanitize(err)
	}
	return append(out, bs...), nil
}

// manifest compara o manifesto do tenant no WORM com a BD (cadeia a cadeia, nos dois sentidos).
func (v *Verifier) manifest(ctx context.Context, tenant string, d time.Time, db map[[2]string]ManifestChain, due bool) ([]Break, error) {
	ds := d.Format(dayLayout)
	b, err := v.Worm.Get(ctx, rootKey(tenant, d))
	if errors.Is(err, ErrNotFound) {
		if due && len(db) > 0 {
			return []Break{{Day: ds, ChainKey: tenant, Problem: "manifest_missing"}}, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil || m.Day != ds {
		return []Break{{Day: ds, ChainKey: tenant, Problem: "manifest_invalid"}}, nil
	}
	var out []Break
	seen := map[[2]string]bool{}
	for _, mc := range m.Chains {
		k := [2]string{mc.ChainKey, mc.RetentionClass}
		seen[k] = true
		if tenantOf(mc.ChainKey) != tenant {
			out = append(out, Break{Day: ds, ChainKey: mc.ChainKey, Class: mc.RetentionClass, Problem: "manifest_foreign_chain"})
			continue
		}
		got, ok := db[k]
		switch {
		case !ok:
			out = append(out, Break{Day: ds, ChainKey: mc.ChainKey, Class: mc.RetentionClass, Seq: mc.LastSeq, Problem: "manifest_chain_missing_in_db"})
		case got != mc:
			out = append(out, Break{Day: ds, ChainKey: mc.ChainKey, Class: mc.RetentionClass, Seq: mc.LastSeq, Problem: "manifest_mismatch"})
		}
	}
	for k, c := range db {
		if !seen[k] {
			out = append(out, Break{Day: ds, ChainKey: c.ChainKey, Class: c.RetentionClass, Seq: c.LastSeq, Problem: "chain_missing_in_manifest"})
		}
	}
	return out, nil
}

func gucDefaults(ctx context.Context, db DB) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	rows, err := db.Query(cctx, `SELECT setting FROM audit.audit_guc_defaults()`)
	if err != nil {
		return nil, sanitize(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (string, error) {
		var s string
		err := r.Scan(&s)
		name, _, _ := strings.Cut(s, "=") // só o nome (o valor não sai)
		return name, err
	})
	return out, sanitize(err)
}

// VerifyAlert: resumo para o alerta crítico (sem conteúdo de eventos).
func VerifyAlert(breaks []Break) Alert {
	s := fmt.Sprintf("verify-audit: %d quebra(s)", len(breaks))
	if len(breaks) > 0 {
		s += "; 1.ª: " + breaks[0].String()
	}
	return Alert{Kind: KindVerifyFailed, Summary: s}
}

// --- StreamWatch -----------------------------------------------------------------------------------

const (
	RLPendingKey       = "audit:rl:pending"
	defaultWatchEvery  = 60 * time.Second
	defaultStaleAfter  = 72 * time.Hour
	defaultExportAbove = deadMaxLen * 9 / 10
	defaultDeadKeep    = deadMaxLen * 8 / 10
	exportBatch        = 500
)

// rlSweepScript: cópia exata do SWEEP_SCRIPT do cartão 07 (backend-rust/src/http/audit_layer.rs).
// KEYS: pending, stream · ARGV: now_ms. Mudar lá = mudar aqui.
const rlSweepScript = `
local function flush(ck, pending, stream)
  local c = redis.call('HGET', ck, 'n')
  local t = redis.call('HGET', ck, 'tpl')
  redis.call('DEL', ck)
  redis.call('ZREM', pending, ck)
  if c and t then
    local i, j = string.find(t, '"__RL_COUNT__"', 1, true)
    if i then t = string.sub(t, 1, i - 1) .. c .. string.sub(t, j + 1) end
    redis.call('XADD', stream, '*', 'event', t)
    return 1
  end
  return 0
end

local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, 500)
local n = 0
for _, ck in ipairs(due) do
  n = n + flush(ck, KEYS[1], KEYS[2])
end
return n
`

var rlSweep = redis.NewScript(rlSweepScript)

// StreamWatch: vigia o stream de auditoria. Campos a zero = valores por omissão.
type StreamWatch struct {
	Redis       redis.UniversalClient
	Worm        WormStore
	Alert       Alerter
	Retention   time.Duration // WORM_EVENTS_RETENTION_DAYS (fila morta exportada)
	Stream      string        // audit:stream
	Dead        string        // audit:stream:dead
	RLPending   string        // audit:rl:pending
	Interval    time.Duration // 60 s
	StaleAfter  time.Duration // 3 dias (o audit_append_event recusa occurred_at com mais de 7)
	ExportAbove int64         // exporta e apara quando XLEN > isto (90 % do MAXLEN do toDead)
	Keep        int64         // fica com isto depois de aparar (80 %)
	Now         func() time.Time
	Log         *slog.Logger

	lastDead  string // último id da fila morta já alertado
	lastStale string // id pendente mais antigo já alertado
}

func (w *StreamWatch) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// RunOnce: varredura de 429, exportação da fila morta, alertas de fila morta e de stream parado.
func (w *StreamWatch) RunOnce(ctx context.Context) error {
	return errors.Join(w.sweep(ctx), w.exportDead(ctx), w.checkDead(ctx), w.checkStale(ctx))
}

// Run: no arranque e a cada Interval até ctx terminar.
func (w *StreamWatch) Run(ctx context.Context) {
	every := w.Interval
	if every <= 0 {
		every = defaultWatchEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := w.RunOnce(ctx); err != nil && w.Log != nil {
			w.Log.Error("vigia do stream de auditoria", "err", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *StreamWatch) sweep(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	n, err := rlSweep.Run(cctx, w.Redis, []string{or(w.RLPending, RLPendingKey), or(w.Stream, StreamKey)},
		w.now().UnixMilli()).Int64()
	if err != nil {
		return fmt.Errorf("varredura de 429: %w", err)
	}
	if n > 0 && w.Log != nil {
		w.Log.Info("resumos de 429 publicados", "n", n)
	}
	return nil
}

// checkDead: alerta quando a fila morta tem entradas novas desde o último alerta.
func (w *StreamWatch) checkDead(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	dead := or(w.Dead, DeadKey)
	last, err := w.Redis.XRevRangeN(cctx, dead, "+", "-", 1).Result()
	if err != nil {
		return fmt.Errorf("fila morta: %w", err)
	}
	if len(last) == 0 || last[0].ID == w.lastDead {
		return nil
	}
	n, err := w.Redis.XLen(cctx, dead).Result()
	if err != nil {
		return fmt.Errorf("fila morta: %w", err)
	}
	if err := w.notify(ctx, Alert{Kind: KindStreamDeadLetter,
		Summary: fmt.Sprintf("fila morta da auditoria com %d entrada(s); última %s", n, last[0].ID)}); err != nil {
		return err
	}
	w.lastDead = last[0].ID
	return nil
}

// checkStale: a mensagem mais antiga do stream (pendente ou por ler) com mais de StaleAfter.
func (w *StreamWatch) checkStale(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	first, err := w.Redis.XRangeN(cctx, or(w.Stream, StreamKey), "-", "+", 1).Result()
	if err != nil {
		return fmt.Errorf("stream: %w", err)
	}
	if len(first) == 0 {
		return nil
	}
	ms, _ := splitStreamID(first[0].ID)
	age := w.now().Sub(time.UnixMilli(int64(ms)))
	stale := w.StaleAfter
	if stale <= 0 {
		stale = defaultStaleAfter
	}
	if age <= stale || first[0].ID == w.lastStale {
		return nil
	}
	if err := w.notify(ctx, Alert{Kind: KindStreamStale,
		Summary: fmt.Sprintf("stream de auditoria parado: mensagem %s com %s (o limite da BD é 7 dias)",
			first[0].ID, age.Truncate(time.Minute))}); err != nil {
		return err
	}
	w.lastStale = first[0].ID
	return nil
}

// exportDead: acima de ExportAbove, as entradas mais antigas vão para o WORM (deadletter/…) e só depois
// se apara (XTRIM MINID exato), até ficarem Keep. O MAXLEN do toDead nunca chega a cortar nada.
func (w *StreamWatch) exportDead(ctx context.Context) error {
	above, keep := w.ExportAbove, w.Keep
	if above <= 0 {
		above = defaultExportAbove
	}
	if keep <= 0 || keep > above {
		keep = min(defaultDeadKeep, above)
	}
	dead := or(w.Dead, DeadKey)
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	n, err := w.Redis.XLen(cctx, dead).Result()
	cancel()
	if err != nil {
		return fmt.Errorf("fila morta: %w", err)
	}
	if n <= above {
		return nil
	}
	todo := n - keep
	start := "-"
	for todo > 0 {
		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		msgs, err := w.Redis.XRangeN(cctx, dead, start, "+", min(todo, exportBatch)).Result()
		cancel()
		if err != nil {
			return fmt.Errorf("fila morta: %w", err)
		}
		if len(msgs) == 0 {
			return nil
		}
		for _, m := range msgs {
			if err := w.exportOne(ctx, m); err != nil {
				return err
			}
		}
		lastID := msgs[len(msgs)-1].ID
		ms, seq := splitStreamID(lastID)
		minID := strconv.FormatUint(ms, 10) + "-" + strconv.FormatUint(seq+1, 10)
		cctx, cancel = context.WithTimeout(ctx, callTimeout)
		err = w.Redis.XTrimMinID(cctx, dead, minID).Err()
		cancel()
		if err != nil {
			return fmt.Errorf("fila morta XTRIM: %w", err)
		}
		todo -= int64(len(msgs))
		start = minID
		if w.Log != nil {
			w.Log.Info("fila morta exportada para o WORM e aparada", "n", len(msgs), "until", lastID)
		}
	}
	return nil
}

func (w *StreamWatch) exportOne(ctx context.Context, m redis.XMessage) error {
	fields := make(map[string]string, len(m.Values))
	for k, v := range m.Values {
		fields[k] = fmt.Sprint(v)
	}
	body, err := json.Marshal(struct {
		StreamID string            `json:"stream_id"`
		Fields   map[string]string `json:"fields"`
	}{m.ID, fields})
	if err != nil {
		return err
	}
	tenant := platformTenant
	var ev struct {
		TenantID string `json:"tenant_id"`
	}
	if json.Unmarshal([]byte(fields[EventField]), &ev) == nil {
		tenant = tenantOf(ev.TenantID)
	}
	ms, _ := splitStreamID(m.ID)
	return putOnce(ctx, w.Worm, deadletterKey(tenant, time.UnixMilli(int64(ms)), m.ID), body,
		w.now().Add(w.Retention), nil)
}

func (w *StreamWatch) notify(ctx context.Context, a Alert) error {
	if w.Log != nil {
		w.Log.Error("alerta da caixa negra", "kind", a.Kind, "summary", a.Summary)
	}
	if w.Alert == nil {
		return errors.New("alerta: sem Alerter")
	}
	return w.Alert.Notify(ctx, a)
}
