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
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
)

// Cartão 08b: ordem dos bloqueios, lotes curtos, contador de entregas, sem dados pessoais nos logs.

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// clone: mesmo stream/grupo, outro consumidor (o Consumer tem um atomic: não se copia).
func clone(c *Consumer, name string) *Consumer {
	return &Consumer{
		Redis: c.Redis, Store: c.Store, Batch: c.Batch, Name: name, Block: c.Block, MinIdle: c.MinIdle,
		MaxDeliveries: c.MaxDeliveries, Stream: c.Stream, Dead: c.Dead, Group: c.Group, Log: c.Log,
	}
}

// setupRedis: só Redis (Writer falso).
func setupRedis(t *testing.T) env {
	t.Helper()
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		t.Skip("REDIS_URL não definida (teste com Redis real)")
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })
	return env{rdb: rdb}
}

// eventAs: evento válido com ação e resultado escolhidos (definem a classe).
func eventAs(tenant, action, outcome string, i int) string {
	var m map[string]any
	_ = json.Unmarshal([]byte(event(tenant, i)), &m)
	m["action"], m["outcome"] = action, outcome
	b, _ := json.Marshal(m)
	return string(b)
}

// mixedBatch: 3 tenants × 3 classes, por ordem aleatória.
func mixedBatch(tenants []string, per int) []string {
	kinds := [][2]string{{"orders.update", "success"}, {"test.audit_stream", "success"}, {"test.audit_stream", "denied"}}
	var evs []string
	for _, tn := range tenants {
		for i := range per {
			k := kinds[i%len(kinds)]
			evs = append(evs, eventAs(tn, k[0], k[1], i))
		}
	}
	rand.Shuffle(len(evs), func(i, j int) { evs[i], evs[j] = evs[j], evs[i] })
	return evs
}

// fakeStore: grava em memória pela ordem recebida; fail decide o erro de cada evento.
type fakeStore struct {
	mu      sync.Mutex
	written []string
	calls   map[string]int
	fail    func(ev string) error
}

func (f *fakeStore) Write(_ context.Context, events [][]byte) (WriteResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	for i, ev := range events {
		f.calls[string(ev)]++
		if f.fail != nil {
			if err := f.fail(string(ev)); err != nil {
				var p *PoisonError
				if errors.As(err, &p) {
					return WriteResult{}, &PoisonError{Index: i, Code: p.Code}
				}
				return WriteResult{}, err
			}
		}
	}
	for _, ev := range events {
		f.written = append(f.written, string(ev))
	}
	return WriteResult{Done: len(events), Inserted: len(events)}, nil
}

func TestClassification(t *testing.T) {
	// Venenos (PTA03 simulado: ainda não existe na BD, vem do cartão 03c).
	for _, code := range []string{"PTA02", "PTA03", "22P02", "22P05"} {
		err := fmt.Errorf("embrulho: %w", &pgconn.PgError{Code: code, Message: "valor 'maria@example.pt'"})
		p := asPoison(err, 3)
		if p == nil || p.Code != code || p.Index != 3 {
			t.Errorf("%s não é veneno: %v", code, p)
		}
		if strings.Contains(p.Error(), "maria") {
			t.Errorf("PoisonError cita a mensagem da BD: %q", p.Error())
		}
	}
	for _, code := range []string{"55P03", "40P01", "XX000", "23505"} {
		if asPoison(&pgconn.PgError{Code: code}, 0) != nil {
			t.Errorf("%s classificado como veneno", code)
		}
	}
	// sanitize: só o SQLSTATE.
	err := sanitize(&pgconn.PgError{Code: "23505", Message: "chave (nif)=(123456789)", Detail: "maria"})
	if strings.Contains(err.Error(), "123456789") || strings.Contains(err.Error(), "maria") || !strings.Contains(err.Error(), "23505") {
		t.Errorf("sanitize: %q", err.Error())
	}
	cases := map[string][2]bool{ // retryable, infra
		"55P03": {true, false}, "40P01": {true, false}, "XX000": {false, false},
		"08006": {false, true}, "57P01": {false, true}, "57014": {false, true}, "53300": {false, true},
	}
	for code, want := range cases {
		e := &DBError{Code: code}
		if e.Retryable() != want[0] || e.Infra() != want[1] {
			t.Errorf("%s: retryable=%v infra=%v", code, e.Retryable(), e.Infra())
		}
	}
	if !isInfra(errors.New("dial tcp: connection refused")) {
		t.Error("erro de rede tem de ser infraestrutura")
	}
	// Ordem: uuid em formatos aceites pelo PostgreSQL dá a mesma chave.
	u := "0190a3c4-1b2c-7d3e-8f40-123456789abc"
	a, _ := chainOrder([]byte(`{"tenant_id":"` + u + `"}`))
	for _, alt := range []string{strings.ToUpper(u), "{" + u + "}", strings.ReplaceAll(u, "-", "")} {
		if b, _ := chainOrder([]byte(`{"tenant_id":"` + alt + `"}`)); b != a {
			t.Errorf("%s ≠ %s", alt, u)
		}
	}
	if z, _ := chainOrder([]byte(`{"tenant_id":null}`)); z != [16]byte{} {
		t.Error("tenant null tem de dar o uuid zero")
	}
	if _, cl := chainOrder([]byte(`{"action":"orders.update","outcome":"denied"}`)); cl != "security" {
		t.Errorf("denied → %s", cl)
	}
	if _, cl := chainOrder([]byte(`{"action":"price.change","outcome":"success"}`)); cl != "fiscal" {
		t.Errorf("price. → %s", cl)
	}
	if _, cl := chainOrder([]byte(`{"Action":"orders.update","outcome":"success"}`)); cl != "standard" {
		t.Errorf("chave com maiúsculas não é 'action' no jsonb → %s", cl)
	}
	for range 20 {
		if d := backoff(10); d > backoffCap || d < backoffCap/2 {
			t.Fatalf("backoff fora de [cap/2, cap]: %v", d)
		}
	}
}

// Lote com 3 tenants por ordem aleatória → escrito por (chain_key, classe), estável dentro da cadeia.
func TestBatchOrderThreeTenants(t *testing.T) {
	e := setupRedis(t)
	store := &fakeStore{}
	c := newConsumer(t, e, "w1", store)
	tenants := []string{uuidV7(), uuidV7(), uuidV7()}
	evs := mixedBatch(tenants, 9)
	publish(t, e, c.Stream, evs...)
	if n := drain(t, c); n != len(evs) {
		t.Fatalf("confirmadas %d, esperado %d", n, len(evs))
	}
	if len(store.written) != len(evs) {
		t.Fatalf("escritos %d", len(store.written))
	}
	type key struct {
		chain [16]byte
		class string
	}
	keyOf := func(s string) key { ch, cl := chainOrder([]byte(s)); return key{ch, cl} }
	for i := 1; i < len(store.written); i++ {
		a, b := keyOf(store.written[i-1]), keyOf(store.written[i])
		if r := bytes.Compare(a.chain[:], b.chain[:]); r > 0 || (r == 0 && a.class > b.class) {
			t.Fatalf("fora de ordem na posição %d", i)
		}
	}
	// Dentro de cada cadeia, a ordem do stream mantém-se.
	pos := map[string]int{}
	for i, ev := range evs {
		pos[ev] = i
	}
	last := map[key]int{}
	for _, ev := range store.written {
		k := keyOf(ev)
		if p, ok := last[k]; ok && pos[ev] < p {
			t.Fatal("ordem do stream trocada dentro da cadeia")
		}
		last[k] = pos[ev]
	}
	if len(last) != 9 {
		t.Fatalf("cadeias %d, esperado 9", len(last))
	}
	assertDrained(t, c)
}

// A classe calculada no Go coincide com a da BD (senão a ordem dos bloqueios não seria a da BD).
func TestClassMatchesDB(t *testing.T) {
	e := setup(t)
	c := newConsumer(t, e, "w1", PgStore{DB: e.pool})
	tenants := []string{uuidV7(), uuidV7(), uuidV7()}
	evs := mixedBatch(tenants, 6)
	publish(t, e, c.Stream, evs...)
	if n := drain(t, c); n != len(evs) {
		t.Fatalf("confirmadas %d", n)
	}
	want := map[string]int64{}
	for _, ev := range evs {
		var m map[string]string
		_ = json.Unmarshal([]byte(ev), &m)
		_, cl := chainOrder([]byte(ev))
		want[m["tenant_id"]+"/"+cl]++
	}
	got := map[string]int64{}
	for _, tn := range tenants {
		r, err := e.pool.Query(context.Background(),
			`SELECT retention_class, last_seq FROM audit.audit_chains() WHERE chain_key = $1::uuid`, tn)
		if err != nil {
			t.Fatal(err)
		}
		for r.Next() {
			var cl string
			var n int64
			if err := r.Scan(&cl, &n); err != nil {
				t.Fatal(err)
			}
			got[tn+"/"+cl] = n
		}
		r.Close()
		assertChain(t, e, tn)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("classes da BD %v ≠ Go %v", got, want)
	}
}

// Dois escritores em paralelo sobre os mesmos tenants, 100 rondas cada: nunca 40P01.
func TestParallelWritersNoDeadlock(t *testing.T) {
	e := setup(t)
	// lock_timeout acima do deadlock_timeout (1 s): um ciclo de bloqueios aparece como 40P01 e não é
	// mascarado por 55P03 (sem a ordenação, este teste dá dezenas de 40P01).
	store := PgStore{DB: e.pool, LockTimeout: 3 * time.Second, MaxTx: 10 * time.Second}
	tenants := []string{uuidV7(), uuidV7(), uuidV7()}
	const rounds = 100
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		deadlocks int
		lockWaits int
		total     int
	)
	for range 2 {
		wg.Go(func() {
			for r := range rounds {
				evs := mixedBatch(tenants, 3)
				items := make([]item, len(evs))
				for i, ev := range evs {
					ch, cl := chainOrder([]byte(ev))
					items[i] = item{raw: []byte(ev), chain: ch, class: cl}
				}
				sortItems(items)
				payloads := make([][]byte, len(items))
				for i, it := range items {
					payloads[i] = it.raw
				}
				for len(payloads) > 0 {
					res, err := store.writeOnce(context.Background(), payloads) // sem repetições: vê tudo
					var db *DBError
					switch {
					case err == nil:
						payloads = payloads[res.Done:]
						mu.Lock()
						total += res.Done
						mu.Unlock()
						continue
					case errors.As(err, &db) && db.Code == "40P01":
						mu.Lock()
						deadlocks++
						mu.Unlock()
					case errors.As(err, &db) && db.Code == "55P03":
						mu.Lock()
						lockWaits++
						mu.Unlock()
					default:
						t.Errorf("ronda %d: %v", r, err)
						return
					}
					time.Sleep(backoff(0))
				}
			}
		})
	}
	wg.Wait()
	if deadlocks != 0 {
		t.Fatalf("%d deadlocks (40P01)", deadlocks)
	}
	if total != 2*rounds*9 {
		t.Fatalf("gravados %d, esperado %d", total, 2*rounds*9)
	}
	t.Logf("55P03 repetidos: %d", lockWaits)
	for _, tn := range tenants {
		if n := rows(t, e, tn); n != int64(2*rounds*3) {
			t.Fatalf("tenant %s: %d linhas", tn, n)
		}
		assertChain(t, e, tn)
	}
}

// Erro transitório sempre no mesmo evento → fila morta ao fim de 5 entregas; os outros avançam.
func TestTransientDeadAfterMaxDeliveries(t *testing.T) {
	e := setupRedis(t)
	tenant := uuidV7()
	bad := event(tenant, 666)
	store := &fakeStore{fail: func(ev string) error {
		if ev == bad {
			return &DBError{Code: "55P03"}
		}
		return nil
	}}
	c := newConsumer(t, e, "w1", store)
	var logs bytes.Buffer
	c.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	ok1, ok2 := event(tenant, 1), event(tenant, 2)
	publish(t, e, c.Stream, ok1, bad, ok2)
	ctx := context.Background()

	for round := 1; round <= 4; round++ {
		n, err := c.RunOnce(ctx)
		var db *DBError
		if !errors.As(err, &db) || db.Code != "55P03" {
			t.Fatalf("ronda %d: esperado 55P03, obtido %v", round, err)
		}
		if round == 1 && n != 2 {
			t.Fatalf("ronda 1: confirmadas %d, esperado 2 (os bons avançam)", n)
		}
		if p, d, _ := c.Metrics(ctx); p != 1 || d != 0 {
			t.Fatalf("ronda %d: pendentes=%d mortas=%d", round, p, d)
		}
	}
	// 5.ª entrega: vai para a fila morta.
	if n, err := c.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("5.ª entrega: n=%d err=%v", n, err)
	}
	dl, err := e.rdb.XRange(ctx, c.Dead, "-", "+").Result()
	if err != nil || len(dl) != 1 {
		t.Fatalf("fila morta=%d err=%v", len(dl), err)
	}
	v := dl[0].Values
	if v["error_code"] != "55P03" || v["deliveries"] != "5" || v[EventField] != bad || v["payload_sha256"] != sha(bad) {
		t.Fatalf("entrada morta: code=%v deliveries=%v", v["error_code"], v["deliveries"])
	}
	if c.DeadTotal() != 1 || !strings.Contains(logs.String(), `"dead_total":1`) {
		t.Fatalf("contador dead=%d", c.DeadTotal())
	}
	// O lote seguinte avança.
	ok3 := event(tenant, 3)
	publish(t, e, c.Stream, ok3)
	if n := drain(t, c); n != 1 {
		t.Fatalf("lote seguinte: confirmadas %d", n)
	}
	if !slices.Equal(store.written, []string{ok1, ok2, ok3}) {
		t.Fatalf("gravados %d (esperado ok1, ok2, ok3)", len(store.written))
	}
	assertDrained(t, c)
}

// BD em baixo (erro de infraestrutura) nunca manda para a fila morta, por mais entregas que haja.
func TestInfraErrorNeverDead(t *testing.T) {
	e := setupRedis(t)
	down := true
	store := &fakeStore{fail: func(string) error {
		if down {
			return errors.New("dial tcp 127.0.0.1:5432: connection refused")
		}
		return nil
	}}
	c := newConsumer(t, e, "w1", store)
	tenant := uuidV7()
	publish(t, e, c.Stream, event(tenant, 1), event(tenant, 2))
	ctx := context.Background()
	for range 8 {
		if n, err := c.RunOnce(ctx); err == nil || n != 0 {
			t.Fatalf("n=%d err=%v", n, err)
		}
	}
	if p, d, _ := c.Metrics(ctx); p != 2 || d != 0 {
		t.Fatalf("pendentes=%d mortas=%d", p, d)
	}
	down = false
	if n := drain(t, c); n != 2 {
		t.Fatalf("confirmadas %d", n)
	}
	assertDrained(t, c)
}

// uuid inválido → PTA02 da BD (a mensagem cita o valor): o log não o contém; a fila morta guarda o payload inteiro.
func TestPoisonValueNotLeaked(t *testing.T) {
	e := setup(t)
	c := newConsumer(t, e, "w1", PgStore{DB: e.pool})
	var logs bytes.Buffer
	c.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	tenant := uuidV7()
	secret := "maria.silva-" + uuidV7()[:8] + "@example.pt"
	var m map[string]any
	_ = json.Unmarshal([]byte(event(tenant, 7)), &m)
	m["actor_id"] = secret
	bad, _ := json.Marshal(m)
	publish(t, e, c.Stream, event(tenant, 1), string(bad), event(tenant, 2))

	// Prova de que a BD cita o valor (senão o teste não provaria nada).
	_, err := PgStore{DB: e.pool}.writeOnce(context.Background(), [][]byte{bad})
	var p *PoisonError
	if !errors.As(err, &p) || p.Code != "PTA02" {
		t.Fatalf("esperado PTA02, obtido %v", err)
	}

	if n := drain(t, c); n != 3 {
		t.Fatalf("confirmadas %d", n)
	}
	dl, err := e.rdb.XRange(context.Background(), c.Dead, "-", "+").Result()
	if err != nil || len(dl) != 1 {
		t.Fatalf("fila morta=%d err=%v", len(dl), err)
	}
	if dl[0].Values["error_code"] != "PTA02" {
		t.Fatalf("code=%v", dl[0].Values["error_code"])
	}
	if n := strings.Count(logs.String(), secret); n != 0 {
		t.Fatalf("valor aparece %d vez(es) no log", n)
	}
	if dl[0].Values[EventField] != string(bad) || dl[0].Values["payload_sha256"] != sha(string(bad)) {
		t.Fatal("payload do venenoso não está inteiro na fila morta")
	}
	if !strings.Contains(logs.String(), `"code":"PTA02"`) {
		t.Fatal("log Error da fila morta em falta")
	}
	if n := rows(t, e, tenant); n != 2 {
		t.Fatalf("linhas %d, esperado 2", n)
	}
	assertDrained(t, c)
}
