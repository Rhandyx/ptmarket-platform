// Package audit grava os eventos da caixa negra (Redis Stream audit:stream) em audit_events.
// ACK só depois do COMMIT; nada se perde (pendentes reclamados, venenosos e esgotados na fila morta) e
// nada se duplica (audit_append_event é idempotente pelo id).
//
// Concorrência com as transações de negócio: cada transação do escritor bloqueia as cabeças de cadeia
// sempre pela mesma ordem (chain_key, classe) e dura no máximo 1 s (PgStore.MaxTx); 55P03/40P01 repetem
// com backoff. Logs e fila morta só levam SQLSTATE e ids do stream, nunca a mensagem da BD nem valores.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	StreamKey  = "audit:stream"
	DeadKey    = "audit:stream:dead"
	GroupName  = "audit-writers"
	EventField = "event"

	defaultBatch         = 200
	defaultBlock         = 2 * time.Second
	defaultMinIdle       = 60 * time.Second
	defaultMaxDeliveries = 5
	deadMaxLen           = 100000 // XADD MAXLEN ~
	metricsEvery         = time.Minute
	retryPause           = time.Second
)

// Writer grava lotes (PgStore em produção); ver PgStore.Write.
type Writer interface {
	Write(ctx context.Context, events [][]byte) (WriteResult, error)
}

// Consumer consome audit:stream no grupo audit-writers. Campos vazios = valores por omissão.
type Consumer struct {
	Redis         redis.UniversalClient
	Store         Writer
	Batch         int           // AUDIT_BATCH (200)
	Name          string        // hostname-pid
	Block         time.Duration // 2 s
	MinIdle       time.Duration // 60 s (XAUTOCLAIM)
	MaxDeliveries int64         // 5: entregas falhadas (XPENDING) até à fila morta
	Stream        string        // audit:stream
	Dead          string        // audit:stream:dead
	Group         string        // audit-writers
	Log           *slog.Logger

	deadTotal atomic.Int64
}

// DeadTotal: mensagens enviadas para a fila morta por este consumidor desde o arranque
// (o cartão 09 liga-o ao alerta).
func (c *Consumer) DeadTotal() int64 { return c.deadTotal.Load() }

// ConsumerName devolve hostname-pid.
func ConsumerName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "worker"
	}
	return fmt.Sprintf("%s-%d", h, os.Getpid())
}

func (c *Consumer) stream() string { return or(c.Stream, StreamKey) }
func (c *Consumer) dead() string   { return or(c.Dead, DeadKey) }
func (c *Consumer) group() string  { return or(c.Group, GroupName) }
func (c *Consumer) name() string {
	if c.Name == "" {
		c.Name = ConsumerName()
	}
	return c.Name
}
func (c *Consumer) batch() int64 {
	if c.Batch <= 0 {
		return defaultBatch
	}
	return int64(c.Batch)
}
func (c *Consumer) block() time.Duration {
	if c.Block <= 0 {
		return defaultBlock
	}
	return c.Block
}
func (c *Consumer) minIdle() time.Duration {
	if c.MinIdle <= 0 {
		return defaultMinIdle
	}
	return c.MinIdle
}
func (c *Consumer) maxDeliveries() int64 {
	if c.MaxDeliveries <= 0 {
		return defaultMaxDeliveries
	}
	return c.MaxDeliveries
}

func or(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// Setup cria o grupo (XGROUP CREATE … $ MKSTREAM); BUSYGROUP = já existe.
func (c *Consumer) Setup(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	err := c.Redis.XGroupCreateMkStream(cctx, c.stream(), c.group(), "$").Err()
	if err != nil && !strings.HasPrefix(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}

// RunOnce processa um lote: pendentes deste consumidor, depois pendentes de consumidores mortos
// (XAUTOCLAIM), depois novos (XREADGROUP BLOCK). Devolve o número de mensagens confirmadas (XACK).
// O lote corre até ao fim mesmo que ctx seja cancelado (paragem limpa).
func (c *Consumer) RunOnce(ctx context.Context) (int, error) {
	ctx = context.WithoutCancel(ctx)
	msgs, err := c.next(ctx)
	if err != nil || len(msgs) == 0 {
		return 0, err
	}
	return c.process(ctx, msgs)
}

// next: cada leitura (incluindo a releitura dos pendentes com "0" e o XAUTOCLAIM) soma 1 ao contador de
// entregas da mensagem no XPENDING.
func (c *Consumer) next(ctx context.Context) ([]redis.XMessage, error) {
	// 1) Pendentes deste consumidor (ex.: a BD falhou no ciclo anterior).
	msgs, err := c.read(ctx, "0", -1)
	if err != nil || len(msgs) > 0 {
		return msgs, err
	}
	// 2) Pendentes de consumidores mortos.
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	msgs, _, err = c.Redis.XAutoClaim(cctx, &redis.XAutoClaimArgs{
		Stream: c.stream(), Group: c.group(), Consumer: c.name(),
		MinIdle: c.minIdle(), Start: "0-0", Count: c.batch(),
	}).Result()
	cancel()
	if err != nil || len(msgs) > 0 {
		return msgs, err
	}
	// 3) Novos.
	return c.read(ctx, ">", c.block())
}

func (c *Consumer) read(ctx context.Context, id string, block time.Duration) ([]redis.XMessage, error) {
	timeout := callTimeout
	if block > 0 {
		timeout += block
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := c.Redis.XReadGroup(cctx, &redis.XReadGroupArgs{
		Group: c.group(), Consumer: c.name(), Streams: []string{c.stream(), id},
		Count: c.batch(), Block: block,
	}).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []redis.XMessage
	for _, s := range res {
		out = append(out, s.Messages...)
	}
	return out, nil
}

// Motivos da fila morta (texto fixo: nunca a mensagem da BD).
const (
	deadMissing   = "missing_event"
	deadJSON      = "invalid_json"
	deadPoison    = "poison"
	deadExhausted = "deliveries_exhausted"
)

var deadReason = map[string]string{
	deadMissing:   "campo event em falta ou não texto",
	deadJSON:      "JSON ilegível",
	deadPoison:    "recusado pelo contrato da BD",
	deadExhausted: "falhou em todas as entregas",
}

type deadMsg struct {
	msg        redis.XMessage
	kind       string // deadMissing, deadJSON, deadPoison, deadExhausted
	code       string // SQLSTATE ou = kind
	deliveries int64
}

// item: evento a gravar, com a chave de ordenação dos bloqueios.
type item struct {
	msg   redis.XMessage
	raw   []byte
	chain [16]byte // COALESCE(tenant_id, uuid zero)
	class string   // audit.audit_retention_class(action, outcome)
}

func (c *Consumer) process(ctx context.Context, msgs []redis.XMessage) (int, error) {
	var (
		items []item
		dead  []deadMsg
	)
	for _, m := range msgs {
		raw, ok := m.Values[EventField].(string)
		switch {
		case !ok:
			dead = append(dead, deadMsg{msg: m, kind: deadMissing, code: deadMissing})
		case !json.Valid([]byte(raw)):
			dead = append(dead, deadMsg{msg: m, kind: deadJSON, code: deadJSON})
		default:
			chain, class := chainOrder([]byte(raw))
			items = append(items, item{msg: m, raw: []byte(raw), chain: chain, class: class})
		}
	}
	sortItems(items)

	ack, deadMore, err := c.write(ctx, items)
	dead = append(dead, deadMore...)

	// Fila morta: XADD e só então ACK. Se o XADD falhar, fica pendente (nunca se descarta).
	for _, d := range dead {
		if derr := c.toDead(ctx, d); derr != nil {
			err = errors.Join(err, derr)
			continue
		}
		ack = append(ack, d.msg.ID)
	}
	if aerr := c.ack(ctx, ack); aerr != nil {
		return 0, errors.Join(aerr, err)
	}
	return len(ack), err
}

// write grava os itens (já ordenados) em transações curtas. Devolve os ids gravados (para ACK) e os que
// vão para a fila morta. O que não está em nenhum dos dois fica pendente (reentregue depois).
//   - Venenoso (PTA02/PTA03/22P02/22P05): fila morta já; o resto repete sem ele.
//   - Erro de infraestrutura (ligação, BD parada): para tudo; nada conta para a fila morta.
//   - Outro erro (ex.: 55P03/40P01 depois das tentativas): passa a um evento por transação, para isolar
//     o culpado; o culpado fica pendente até MaxDeliveries entregas e depois vai para a fila morta.
func (c *Consumer) write(ctx context.Context, items []item) (ack []string, dead []deadMsg, err error) {
	var (
		single     bool
		deliveries map[string]int64
	)
	for len(items) > 0 {
		n := len(items)
		if single {
			n = 1
		}
		payloads := make([][]byte, n)
		for i := range n {
			payloads[i] = items[i].raw
		}
		res, werr := c.Store.Write(ctx, payloads)
		if werr == nil {
			if res.Done <= 0 || res.Done > n {
				return ack, dead, fmt.Errorf("audit: Store.Write devolveu Done=%d para %d eventos", res.Done, n)
			}
			for _, it := range items[:res.Done] {
				ack = append(ack, it.msg.ID)
			}
			items = items[res.Done:]
			continue
		}
		var p *PoisonError
		if errors.As(werr, &p) && p.Index >= 0 && p.Index < n {
			dead = append(dead, deadMsg{msg: items[p.Index].msg, kind: deadPoison, code: p.Code})
			items = slices.Delete(items, p.Index, p.Index+1)
			continue
		}
		if isInfra(werr) {
			return ack, dead, werr
		}
		if !single {
			single = true // isolar o culpado
			continue
		}
		// Evento único com erro não venenoso: conta as entregas.
		if deliveries == nil {
			deliveries = c.deliveries(ctx, items)
		}
		it := items[0]
		items = items[1:]
		if d := deliveries[it.msg.ID]; d >= c.maxDeliveries() {
			dead = append(dead, deadMsg{msg: it.msg, kind: deadExhausted, code: errCode(werr), deliveries: d})
			continue
		}
		err = errors.Join(err, werr) // fica pendente; os seguintes avançam
	}
	return ack, dead, err
}

// isInfra: erros que não são culpa do evento (rede, BD parada, prazo, cancelamento).
func isInfra(err error) bool {
	var db *DBError
	if errors.As(err, &db) {
		return db.Infra()
	}
	return true
}

func errCode(err error) string {
	var db *DBError
	if errors.As(err, &db) {
		return db.Code
	}
	return "unknown"
}

// deliveries: contador de entregas (XPENDING) de cada item deste consumidor. Em erro devolve vazio
// (sem contador não se manda nada para a fila morta).
func (c *Consumer) deliveries(ctx context.Context, items []item) map[string]int64 {
	out := make(map[string]int64, len(items))
	if len(items) == 0 {
		return out
	}
	lo, hi := items[0].msg.ID, items[0].msg.ID
	for _, it := range items[1:] {
		if streamIDLess(it.msg.ID, lo) {
			lo = it.msg.ID
		}
		if streamIDLess(hi, it.msg.ID) {
			hi = it.msg.ID
		}
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	res, err := c.Redis.XPendingExt(cctx, &redis.XPendingExtArgs{
		Stream: c.stream(), Group: c.group(), Consumer: c.name(),
		Start: lo, End: hi, Count: c.batch(),
	}).Result()
	if err != nil {
		c.logErr("XPENDING do stream de auditoria", err)
		return out
	}
	for _, p := range res {
		out[p.ID] = p.RetryCount
	}
	return out
}

// streamIDLess compara ids "ms-seq" do Redis.
func streamIDLess(a, b string) bool {
	am, as := splitStreamID(a)
	bm, bs := splitStreamID(b)
	if am != bm {
		return am < bm
	}
	return as < bs
}

func splitStreamID(id string) (uint64, uint64) {
	ms, seq, _ := strings.Cut(id, "-")
	m, _ := strconv.ParseUint(ms, 10, 64)
	s, _ := strconv.ParseUint(seq, 10, 64)
	return m, s
}

// sortItems: ordem total e igual em todos os escritores (chain_key, classe) — evita 40P01 entre
// escritores e com as transações de negócio; estável para manter a ordem do stream dentro da cadeia.
func sortItems(items []item) {
	slices.SortStableFunc(items, func(a, b item) int {
		if r := bytes.Compare(a.chain[:], b.chain[:]); r != 0 {
			return r
		}
		return strings.Compare(a.class, b.class)
	})
}

// chainOrder calcula (chain_key, classe) como audit._chain_insert (migration 0008):
// chain_key = COALESCE(tenant_id, uuid zero); classe = audit.audit_retention_class(action, outcome).
// Eventos com campos ilegíveis são recusados pela BD antes de bloquear, por isso a ordem deles é
// indiferente. Mapa (e não struct) porque o jsonb distingue maiúsculas nas chaves e o encoding/json não.
func chainOrder(raw []byte) (chain [16]byte, class string) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return chain, "standard"
	}
	var tenant, action, outcome string
	_ = json.Unmarshal(m["tenant_id"], &tenant)
	_ = json.Unmarshal(m["action"], &action)
	_ = json.Unmarshal(m["outcome"], &outcome)
	if u, ok := parseUUID(tenant); ok {
		chain = u
	}
	return chain, retentionClass(action, outcome)
}

// parseUUID aceita tudo o que o tipo uuid do PostgreSQL aceita (maiúsculas, chavetas, hífenes
// opcionais), para a ordem do Go coincidir com o bloqueio feito pela BD.
func parseUUID(s string) ([16]byte, bool) {
	var u [16]byte
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		s = s[1 : len(s)-1]
	}
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return u, false
	}
	if _, err := hex.Decode(u[:], []byte(s)); err != nil {
		return u, false
	}
	return u, true
}

// fiscalPrefixes: cópia de audit.audit_retention_class (migration 0008). Mudar lá = mudar aqui.
var fiscalPrefixes = []string{
	"orders.", "sub_orders.", "sub_order_items.", "payments.", "refunds.", "payouts.",
	"invoices.", "loyalty_ledger.", "product_price_history.", "product_variants.",
	"order.", "payment.", "refund.", "payout.", "invoice.", "price.",
}

func retentionClass(action, outcome string) string {
	if outcome == "denied" {
		return "security"
	}
	for _, p := range fiscalPrefixes {
		if strings.HasPrefix(action, p) {
			return "fiscal"
		}
	}
	return "standard"
}

// toDead: XADD na fila morta (MAXLEN ~ 100000): id de origem, código, motivo fixo, hash, tamanho e o
// payload inteiro (spec 13: um evento recusado continua a ser uma ação que aconteceu). O payload já vem
// mascarado pela app e já estava no stream principal: a fila morta tem a mesma sensibilidade. O log
// leva só id, código e motivo, nunca o payload.
func (c *Consumer) toDead(ctx context.Context, d deadMsg) error {
	raw, _ := d.msg.Values[EventField].(string)
	sum := sha256.Sum256([]byte(raw))
	vals := map[string]any{
		"source_id":      d.msg.ID,
		"error_code":     d.code,
		"error":          deadReason[d.kind],
		"field":          EventField,
		"payload_sha256": hex.EncodeToString(sum[:]),
		"payload_bytes":  len(raw),
		"deliveries":     d.deliveries,
	}
	if _, ok := d.msg.Values[EventField].(string); ok {
		vals[EventField] = raw
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if err := c.Redis.XAdd(cctx, &redis.XAddArgs{
		Stream: c.dead(), MaxLen: deadMaxLen, Approx: true, Values: vals,
	}).Err(); err != nil {
		return err
	}
	n := c.deadTotal.Add(1)
	if c.Log != nil {
		c.Log.Error("evento de auditoria enviado para a fila morta",
			"stream_id", d.msg.ID, "code", d.code, "reason", d.kind, "deliveries", d.deliveries, "dead_total", n)
	}
	return nil
}

// ack: XACK + XDEL numa transação Redis (MULTI). Sem MAXLEN/XTRIM: só se apaga o que foi gravado.
func (c *Consumer) ack(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, err := c.Redis.TxPipelined(cctx, func(p redis.Pipeliner) error {
		p.XAck(cctx, c.stream(), c.group(), ids...)
		p.XDel(cctx, c.stream(), ids...)
		return nil
	})
	return err
}

// Metrics devolve as mensagens pendentes do grupo e o tamanho da fila morta.
func (c *Consumer) Metrics(ctx context.Context) (pending, dead int64, err error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	xp, err := c.Redis.XPending(cctx, c.stream(), c.group()).Result()
	if err != nil {
		return 0, 0, err
	}
	dead, err = c.Redis.XLen(cctx, c.dead()).Result()
	if err != nil {
		return 0, 0, err
	}
	return xp.Count, dead, nil
}

// Run consome até ctx terminar; acaba sempre o lote em curso. Métricas em log a cada minuto.
func (c *Consumer) Run(ctx context.Context) {
	ready := false
	lastMetrics := time.Now()
	for ctx.Err() == nil {
		if !ready {
			if err := c.Setup(ctx); err != nil {
				c.logErr("grupo do stream de auditoria", err)
				pause(ctx)
				continue
			}
			ready = true
		}
		if _, err := c.RunOnce(ctx); err != nil {
			c.logErr("ciclo do stream de auditoria falhou", err)
			if strings.Contains(err.Error(), "NOGROUP") {
				ready = false
			}
			pause(ctx)
		}
		if time.Since(lastMetrics) >= metricsEvery {
			lastMetrics = time.Now()
			if p, d, err := c.Metrics(ctx); err != nil {
				c.logErr("métricas do stream de auditoria", err)
			} else if c.Log != nil {
				c.Log.Info("stream de auditoria", "pending", p, "dead", d, "dead_total", c.DeadTotal())
			}
		}
	}
}

// logErr: os erros da BD chegam aqui já reduzidos ao SQLSTATE (DBError/PoisonError).
func (c *Consumer) logErr(msg string, err error) {
	if c.Log != nil {
		c.Log.Error(msg, "err", err.Error())
	}
}

func pause(ctx context.Context) {
	t := time.NewTimer(retryPause)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
