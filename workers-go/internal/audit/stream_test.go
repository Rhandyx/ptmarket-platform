package audit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Testes com PG (BD migrada, papel ptmarket_worker) e Redis reais. Chaves Redis e tenant únicos por teste.

type env struct {
	pool *pgxpool.Pool
	rdb  *redis.Client
}

func setup(t *testing.T) env {
	t.Helper()
	dbURL, redisURL := os.Getenv("WORKER_DATABASE_URL"), os.Getenv("REDIS_URL")
	if dbURL == "" || redisURL == "" {
		t.Skip("WORKER_DATABASE_URL e REDIS_URL não definidas (teste com PG e Redis reais)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })
	return env{pool, rdb}
}

func uuidV7() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixMilli()))
	copy(b[:6], ts[2:])
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func event(tenant string, i int) string {
	b, _ := json.Marshal(map[string]any{
		"id": uuidV7(), "tenant_id": tenant, "store_id": nil,
		"actor_type": "merchant", "actor_id": uuidV7(), "actor_label": "loja@teste",
		"impersonator_id": nil, "action": "test.audit_stream", "target_type": "product",
		"target_id": fmt.Sprint(i), "outcome": "success", "reason": nil,
		"changes": map[string]any{"i": i}, "request_id": uuidV7(), "ip": "192.0.2.1",
		"user_agent_hash": "ab01", "occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
	return string(b)
}

func newConsumer(t *testing.T, e env, name string, store Writer) *Consumer {
	t.Helper()
	suffix := uuidV7()
	c := &Consumer{
		Redis: e.rdb, Store: store, Batch: 200, Name: name,
		Block: 50 * time.Millisecond, MinIdle: 100 * time.Millisecond,
		Stream: "audit:stream:test:" + suffix, Dead: "audit:stream:dead:test:" + suffix,
		Group: GroupName,
	}
	if err := c.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Setup(context.Background()); err != nil { // BUSYGROUP ignorado
		t.Fatalf("2.º Setup: %v", err)
	}
	t.Cleanup(func() { e.rdb.Del(context.Background(), c.Stream, c.Dead) })
	return c
}

func publish(t *testing.T, e env, stream string, payloads ...string) {
	t.Helper()
	for _, p := range payloads {
		if err := e.rdb.XAdd(context.Background(), &redis.XAddArgs{Stream: stream, Values: map[string]any{EventField: p}}).Err(); err != nil {
			t.Fatal(err)
		}
	}
}

func drain(t *testing.T, c *Consumer) int {
	t.Helper()
	total := 0
	for range 100 {
		n, err := c.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return total
		}
		total += n
	}
	t.Fatal("o stream não esvaziou")
	return 0
}

// rows: linhas gravadas na cadeia do tenant (soma de last_seq das cabeças) — o worker não tem SELECT
// em audit_events; com a cadeia sem quebras nem falhas, last_seq = número de linhas.
func rows(t *testing.T, e env, tenant string) int64 {
	t.Helper()
	var n int64
	err := e.pool.QueryRow(context.Background(),
		`SELECT COALESCE(sum(last_seq), 0)::bigint FROM audit.audit_chains() WHERE chain_key = $1::uuid`, tenant).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func assertChain(t *testing.T, e env, tenant string) {
	t.Helper()
	ctx := context.Background()
	r, err := e.pool.Query(ctx, `SELECT retention_class FROM audit.audit_chains() WHERE chain_key = $1::uuid`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	classes, err := pgx.CollectRows(r, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, cl := range classes {
		var broken int
		err := e.pool.QueryRow(ctx, `SELECT count(*) FROM audit.audit_verify_chain($1::uuid, $2::text,
			(now() - interval '1 hour')::timestamptz, (now() + interval '1 hour')::timestamptz)`, tenant, cl).Scan(&broken)
		if err != nil {
			t.Fatal(err)
		}
		if broken != 0 {
			t.Fatalf("cadeia %s/%s com %d quebras", tenant, cl, broken)
		}
	}
}

func assertDrained(t *testing.T, c *Consumer) {
	t.Helper()
	ctx := context.Background()
	if n := c.Redis.XLen(ctx, c.Stream).Val(); n != 0 {
		t.Errorf("stream com %d mensagens", n)
	}
	if p, _, err := c.Metrics(ctx); err != nil || p != 0 {
		t.Errorf("pendentes=%d err=%v", p, err)
	}
}

func TestStream500(t *testing.T) {
	e := setup(t)
	c := newConsumer(t, e, "w1", PgStore{DB: e.pool})
	tenant := uuidV7()
	evs := make([]string, 500)
	for i := range evs {
		evs[i] = event(tenant, i)
	}
	publish(t, e, c.Stream, evs...)
	if n := drain(t, c); n != 500 {
		t.Fatalf("confirmadas %d, esperado 500", n)
	}
	if n := rows(t, e, tenant); n != 500 {
		t.Fatalf("linhas %d, esperado 500", n)
	}
	assertChain(t, e, tenant)
	assertDrained(t, c)
}

func TestCrashAfterCommitBeforeAck(t *testing.T) {
	e := setup(t)
	store := PgStore{DB: e.pool}
	dead := newConsumer(t, e, "morto", store)
	tenant := uuidV7()
	evs := []string{event(tenant, 1), event(tenant, 2), event(tenant, 3)}
	publish(t, e, dead.Stream, evs...)

	// O consumidor "morto" lê, grava (COMMIT) e morre antes do XACK.
	msgs, err := dead.read(context.Background(), ">", -1)
	if err != nil || len(msgs) != 3 {
		t.Fatalf("msgs=%d err=%v", len(msgs), err)
	}
	payloads := make([][]byte, len(msgs))
	for i, m := range msgs {
		payloads[i] = []byte(m.Values[EventField].(string))
	}
	if n, err := store.WriteAll(context.Background(), payloads); err != nil || n != 3 {
		t.Fatalf("1.ª gravação n=%d err=%v", n, err)
	}

	// Outro consumidor reclama (XAUTOCLAIM) e reentrega: nada é duplicado e o ACK acontece.
	alive := *dead
	alive.Name = "vivo"
	time.Sleep(2 * alive.MinIdle)
	if n := drain(t, &alive); n != 3 {
		t.Fatalf("confirmadas %d, esperado 3", n)
	}
	if n, err := store.WriteAll(context.Background(), payloads); err != nil || n != 0 {
		t.Fatalf("reentrega gravou n=%d err=%v (esperado 0)", n, err)
	}
	if n := rows(t, e, tenant); n != 3 {
		t.Fatalf("linhas %d, esperado 3", n)
	}
	assertChain(t, e, tenant)
	assertDrained(t, &alive)
}

// killBeginner: a k-ésima chamada à BD na transação mata a própria ligação (falha real da BD a meio).
type killBeginner struct {
	pool *pgxpool.Pool
	at   int
}

func (b *killBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &killTx{Tx: tx, at: b.at}, nil
}

type killTx struct {
	pgx.Tx
	at, calls int
}

func (k *killTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	k.calls++
	if k.calls == k.at {
		return k.Tx.QueryRow(ctx, `SELECT pg_terminate_backend(pg_backend_pid())`)
	}
	return k.Tx.QueryRow(ctx, sql, args...)
}

func TestDBFailureMidBatch(t *testing.T) {
	e := setup(t)
	c := newConsumer(t, e, "w1", PgStore{DB: &killBeginner{pool: e.pool, at: 6}})
	tenant := uuidV7()
	evs := make([]string, 10)
	for i := range evs {
		evs[i] = event(tenant, i)
	}
	publish(t, e, c.Stream, evs...)

	if n, err := c.RunOnce(context.Background()); err == nil || n != 0 {
		t.Fatalf("esperado erro sem ACK; n=%d err=%v", n, err)
	}
	if n := rows(t, e, tenant); n != 0 {
		t.Fatalf("gravou %d linhas com a BD em falha", n)
	}
	if p, _, _ := c.Metrics(context.Background()); p != 10 {
		t.Fatalf("pendentes %d, esperado 10 (nenhum XACK)", p)
	}

	c.Store = PgStore{DB: e.pool} // a BD recupera
	if n := drain(t, c); n != 10 {
		t.Fatalf("confirmadas %d, esperado 10", n)
	}
	if n := rows(t, e, tenant); n != 10 {
		t.Fatalf("linhas %d, esperado 10", n)
	}
	assertChain(t, e, tenant)
	assertDrained(t, c)
}

func TestPoisonMidBatch(t *testing.T) {
	e := setup(t)
	c := newConsumer(t, e, "w1", PgStore{DB: e.pool})
	tenant := uuidV7()
	var bad map[string]any
	_ = json.Unmarshal([]byte(event(tenant, 99)), &bad)
	bad["actor_type"] = "db" // exclusivo do trigger: PTA02
	badJSON, _ := json.Marshal(bad)
	evs := []string{event(tenant, 1), event(tenant, 2), string(badJSON), event(tenant, 3), "{ilegível", event(tenant, 4)}
	publish(t, e, c.Stream, evs...)

	if n := drain(t, c); n != 6 {
		t.Fatalf("confirmadas %d, esperado 6", n)
	}
	if n := rows(t, e, tenant); n != 4 {
		t.Fatalf("linhas %d, esperado 4", n)
	}
	assertChain(t, e, tenant)
	assertDrained(t, c)

	dl, err := e.rdb.XRange(context.Background(), c.Dead, "-", "+").Result()
	if err != nil || len(dl) != 2 {
		t.Fatalf("fila morta=%d err=%v", len(dl), err)
	}
	want := map[string]string{string(badJSON): "PTA02", "{ilegível": "invalid_json"}
	for _, m := range dl {
		orig, _ := m.Values[EventField].(string)
		code, ok := want[orig]
		if !ok || m.Values["error_code"] != code || m.Values["error"] == "" || m.Values["source_id"] == "" {
			t.Errorf("entrada morta inesperada: code=%v", m.Values["error_code"])
		}
		delete(want, orig)
	}
}

func TestSetSystemActor(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tenant := uuidV7()
	// p_tenant_id só é aceite com app.actor_type = 'system': gravar com ele prova o ator 'system'.
	const appendSQL = `SELECT audit.audit_append('test.system_actor'::text, 'test'::text, NULL::text,
		'success'::text, NULL::text, NULL::jsonb, NULL::uuid, $1::uuid)`

	t.Run("sem ator falha com PTA01", func(t *testing.T) {
		tx, err := e.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var id string
		err = tx.QueryRow(ctx, appendSQL, tenant).Scan(&id)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "PTA01" {
			t.Fatalf("esperado PTA01, obtido %v", err)
		}
	})

	t.Run("com SetSystemActor grava como system", func(t *testing.T) {
		tx, err := e.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := SetSystemActor(ctx, tx, "test.audit_stream"); err != nil {
			t.Fatal(err)
		}
		var typ, label string
		if err := tx.QueryRow(ctx, `SELECT current_setting('app.actor_type'), current_setting('app.actor_label')`).Scan(&typ, &label); err != nil {
			t.Fatal(err)
		}
		if typ != "system" || label != "test.audit_stream" {
			t.Fatalf("actor_type=%q actor_label=%q", typ, label)
		}
		var id string
		if err := tx.QueryRow(ctx, appendSQL, tenant).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if n := rows(t, e, tenant); n != 1 {
			t.Fatalf("linhas %d, esperado 1", n)
		}
		assertChain(t, e, tenant)
	})

	t.Run("sem job recusa", func(t *testing.T) {
		if err := SetSystemActor(ctx, e.pool, ""); err == nil {
			t.Fatal("esperado erro")
		}
	})
}
