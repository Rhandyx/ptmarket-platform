package audit

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cartão 09: vigia do stream (Redis real, WORM em memória). Chaves Redis únicas por teste.
func TestStreamWatch(t *testing.T) {
	e := setupRedis(t)
	ctx := context.Background()
	sfx := uuidV7()
	tenant := uuidV7()
	mem := &memWorm{}
	al := &fakeAlerter{}
	w := &StreamWatch{
		Redis: e.rdb, Worm: mem, Alert: al, Retention: time.Hour,
		Stream: "audit:stream:test:" + sfx, Dead: "audit:stream:dead:test:" + sfx,
		RLPending: "audit:rl:pending:test:" + sfx, ExportAbove: 3, Keep: 1,
	}
	ck := "audit:rl:count:test:" + sfx
	t.Cleanup(func() { e.rdb.Del(context.Background(), w.Stream, w.Dead, w.RLPending, ck) })

	// Fila morta com 5 entradas (> ExportAbove).
	for i := range 5 {
		if err := e.rdb.XAdd(ctx, &redis.XAddArgs{Stream: w.Dead, Values: map[string]any{
			"source_id": "1-" + strconv.Itoa(i), "error_code": "PTA02", EventField: event(tenant, i),
		}}).Err(); err != nil {
			t.Fatal(err)
		}
	}
	// Mensagem com 4 dias no stream principal (consumidor parado).
	old := strconv.FormatInt(time.Now().Add(-96*time.Hour).UnixMilli(), 10) + "-0"
	if err := e.rdb.XAdd(ctx, &redis.XAddArgs{Stream: w.Stream, ID: old, Values: map[string]any{EventField: "{}"}}).Err(); err != nil {
		t.Fatal(err)
	}
	// Resumo de 429 de uma janela já fechada (instância da API morreu).
	e.rdb.HSet(ctx, ck, "n", 7, "tpl", `{"action":"security.rate_limit_summary","changes":{"count":"__RL_COUNT__"}}`)
	e.rdb.ZAdd(ctx, w.RLPending, redis.Z{Score: float64(time.Now().Add(-time.Second).UnixMilli()), Member: ck})

	if err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.rdb.XLen(ctx, w.Dead).Val(); n != 1 {
		t.Fatalf("fila morta com %d entradas depois de aparar (esperado 1)", n)
	}
	if keys := mem.keys("t/" + tenant + "/deadletter/"); len(keys) != 4 {
		t.Fatalf("exportadas para o WORM: %v", keys)
	}
	if len(al.kinds(KindStreamDeadLetter)) != 1 || len(al.kinds(KindStreamStale)) != 1 {
		t.Fatalf("alertas: %+v", al.got)
	}
	msgs := e.rdb.XRange(ctx, w.Stream, "-", "+").Val()
	if len(msgs) != 2 || !strings.Contains(msgs[1].Values[EventField].(string), `"count":7`) {
		t.Fatalf("resumo de 429: %+v", msgs)
	}
	if e.rdb.Exists(ctx, ck).Val() != 0 || e.rdb.ZCard(ctx, w.RLPending).Val() != 0 {
		t.Fatal("contagem de 429 não foi fechada")
	}
	var dumped struct {
		StreamID string            `json:"stream_id"`
		Fields   map[string]string `json:"fields"`
	}
	b, _ := mem.Get(ctx, mem.keys("t/" + tenant + "/deadletter/")[0])
	if json.Unmarshal(b, &dumped) != nil || dumped.Fields["error_code"] != "PTA02" || dumped.Fields[EventField] == "" {
		t.Fatalf("entrada exportada: %s", b)
	}

	// Sem novidades: sem alertas novos; 429 idempotente (nada por publicar).
	if err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(al.got) != 2 || e.rdb.XLen(ctx, w.Stream).Val() != 2 {
		t.Fatalf("2.ª ronda repetiu: %+v", al.got)
	}
	// Nova entrada na fila morta → novo alerta.
	e.rdb.XAdd(ctx, &redis.XAddArgs{Stream: w.Dead, Values: map[string]any{"error_code": "PTA02"}})
	if err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(al.kinds(KindStreamDeadLetter)) != 2 {
		t.Fatalf("fila morta nova sem alerta: %+v", al.got)
	}
}

// O script da varredura é o do cartão 07 (cópia exata): a função flush e o corpo do sweep.
func TestRLSweepScriptMatchesCard07(t *testing.T) {
	for _, s := range []string{
		`redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, 500)`,
		`string.find(t, '"__RL_COUNT__"', 1, true)`,
		`redis.call('XADD', stream, '*', 'event', t)`,
	} {
		if !strings.Contains(rlSweepScript, s) {
			t.Fatalf("script sem %q", s)
		}
	}
}

func TestBreakStringHasNoContent(t *testing.T) {
	b := Break{Day: "2026-11-25", ChainKey: "k", Class: "standard", ID: "i", Seq: 3, Problem: "hash"}
	if got := b.String(); got != "day=2026-11-25 chain=k class=standard id=i seq=3 problem=hash" {
		t.Fatal(got)
	}
	if a := VerifyAlert([]Break{b}); a.Kind != KindVerifyFailed || !strings.Contains(a.Summary, "1 quebra") {
		t.Fatal(a)
	}
}
