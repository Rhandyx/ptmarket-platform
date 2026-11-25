// Package audit grava os eventos da caixa negra (Redis Stream audit:stream) em audit_events.
// ACK só depois do COMMIT; nada se perde (pendentes reclamados, venenosos na fila morta) e nada se
// duplica (audit_append_event é idempotente pelo id).
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	StreamKey  = "audit:stream"
	DeadKey    = "audit:stream:dead"
	GroupName  = "audit-writers"
	EventField = "event"

	defaultBatch   = 200
	defaultBlock   = 2 * time.Second
	defaultMinIdle = 60 * time.Second
	metricsEvery   = time.Minute
	retryPause     = time.Second
)

// Writer grava lotes (PgStore em produção).
type Writer interface {
	WriteAll(ctx context.Context, events [][]byte) (int, error)
	WriteEach(ctx context.Context, events [][]byte) (int, map[int]*PoisonError, error)
}

// Consumer consome audit:stream no grupo audit-writers. Campos vazios = valores por omissão.
type Consumer struct {
	Redis   redis.UniversalClient
	Store   Writer
	Batch   int           // AUDIT_BATCH (200)
	Name    string        // hostname-pid
	Block   time.Duration // 2 s
	MinIdle time.Duration // 60 s (XAUTOCLAIM)
	Stream  string        // audit:stream
	Dead    string        // audit:stream:dead
	Group   string        // audit-writers
	Log     *slog.Logger
}

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

type deadMsg struct {
	msg    redis.XMessage
	code   string
	reason string
}

func (c *Consumer) process(ctx context.Context, msgs []redis.XMessage) (int, error) {
	var (
		events  [][]byte
		eventID []string // id da mensagem de cada evento enviado à BD
		dead    []deadMsg
	)
	for _, m := range msgs {
		raw, ok := m.Values[EventField].(string)
		switch {
		case !ok:
			dead = append(dead, deadMsg{m, "missing_event", "campo event em falta ou não texto"})
		case !json.Valid([]byte(raw)):
			dead = append(dead, deadMsg{m, "invalid_json", "JSON ilegível"})
		default:
			events = append(events, []byte(raw))
			eventID = append(eventID, m.ID)
		}
	}

	written := eventID
	if len(events) > 0 {
		_, err := c.Store.WriteAll(ctx, events)
		var p *PoisonError
		if errors.As(err, &p) {
			var poison map[int]*PoisonError
			_, poison, err = c.Store.WriteEach(ctx, events)
			if err == nil && len(poison) > 0 {
				written = make([]string, 0, len(eventID))
				byID := make(map[string]redis.XMessage, len(msgs))
				for _, m := range msgs {
					byID[m.ID] = m
				}
				for i, id := range eventID {
					if pe, bad := poison[i]; bad {
						dead = append(dead, deadMsg{byID[id], pe.Code, pe.Msg})
						continue
					}
					written = append(written, id)
				}
			}
		}
		if err != nil {
			return 0, err // antes do COMMIT: sem ACK, tudo fica pendente
		}
	}

	// Venenosos: XADD na fila morta e só então ACK. Se o XADD falhar, fica pendente (nunca se descarta).
	ack := written
	var deadErr error
	for _, d := range dead {
		if err := c.toDead(ctx, d); err != nil {
			deadErr = errors.Join(deadErr, err)
			continue
		}
		ack = append(ack, d.msg.ID)
	}
	if err := c.ack(ctx, ack); err != nil {
		return 0, errors.Join(err, deadErr)
	}
	return len(ack), deadErr
}

func (c *Consumer) toDead(ctx context.Context, d deadMsg) error {
	vals := make(map[string]any, len(d.msg.Values)+3)
	for k, v := range d.msg.Values {
		vals[k] = v
	}
	vals["error"] = d.reason
	vals["error_code"] = d.code
	vals["source_id"] = d.msg.ID
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if err := c.Redis.XAdd(cctx, &redis.XAddArgs{Stream: c.dead(), Values: vals}).Err(); err != nil {
		return err
	}
	if c.Log != nil {
		c.Log.Error("evento de auditoria venenoso enviado para a fila morta",
			"stream_id", d.msg.ID, "code", d.code, "err", d.reason)
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
			if strings.HasPrefix(err.Error(), "NOGROUP") {
				ready = false
			}
			pause(ctx)
		}
		if time.Since(lastMetrics) >= metricsEvery {
			lastMetrics = time.Now()
			if p, d, err := c.Metrics(ctx); err != nil {
				c.logErr("métricas do stream de auditoria", err)
			} else if c.Log != nil {
				c.Log.Info("stream de auditoria", "pending", p, "dead", d)
			}
		}
	}
}

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
