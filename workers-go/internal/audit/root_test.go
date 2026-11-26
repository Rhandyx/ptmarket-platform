package audit

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hibiken/asynq"
)

// Cartão 09: raiz diária com PG e WORM reais (âmbito = tenants do teste; prefixo test/<uuid>/ no bucket).

type fakeAlerter struct {
	mu  sync.Mutex
	got []Alert
	err error
}

func (f *fakeAlerter) Notify(_ context.Context, a Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, a)
	return f.err
}

func (f *fakeAlerter) kinds(kind string) []Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Alert
	for _, a := range f.got {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

// memWorm: WormStore em memória (testes sem o WORM de dev).
type memWorm struct {
	mu     sync.Mutex
	m      map[string][]byte
	putErr error
}

func (w *memWorm) Put(_ context.Context, key string, body []byte, _ time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.putErr != nil {
		return w.putErr
	}
	if w.m == nil {
		w.m = map[string][]byte{}
	}
	if _, ok := w.m[key]; ok {
		return ErrExists
	}
	w.m[key] = slices.Clone(body)
	return nil
}

func (w *memWorm) Get(_ context.Context, key string) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, ok := w.m[key]
	if !ok {
		return nil, ErrNotFound
	}
	return slices.Clone(b), nil
}

func (w *memWorm) keys(prefix string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for k := range w.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// appendEvent grava um evento diretamente (audit_append_event, papel ptmarket_worker).
func appendEvent(t *testing.T, e env, ev string) {
	t.Helper()
	var ok bool
	if err := e.pool.QueryRow(context.Background(), appendSQL, json.RawMessage(ev)).Scan(&ok); err != nil || !ok {
		t.Fatalf("audit_append_event: %v %v", ok, err)
	}
}

func readManifest(t *testing.T, w WormStore, key string) Manifest {
	t.Helper()
	b, err := w.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get %s: %v", key, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRootTwoTenantsIdempotentMismatch(t *testing.T) {
	e := setup(t)
	w := testWorm(t)
	ctx := context.Background()
	a, b := uuidV7(), uuidV7()
	for i := range 3 {
		appendEvent(t, e, event(a, i))
	}
	appendEvent(t, e, eventAs(a, "orders.update", "success", 9)) // 2.ª cadeia de A (fiscal)
	for i := range 2 {
		appendEvent(t, e, event(b, i))
	}
	al := &fakeAlerter{}
	job := &RootJob{DB: e.pool, Worm: w, Alert: al, Retention: 24 * time.Hour, Tenants: []string{a, b}}
	today := time.Now().UTC()
	if err := job.Run(ctx, today); err != nil {
		t.Fatalf("1.ª execução: %v", err)
	}

	// Cada manifesto no prefixo do seu tenant, só com as cadeias dele, com retenção GOVERNANCE.
	for tenant, want := range map[string][]string{a: {"fiscal", "standard"}, b: {"standard"}} {
		key := rootKey(tenant, today)
		m := readManifest(t, w, key)
		var classes []string
		for _, c := range m.Chains {
			if c.ChainKey != tenant {
				t.Fatalf("manifesto de %s tem a cadeia %s", tenant, c.ChainKey)
			}
			if len(c.LastHash) != 64 || c.Events < 1 || c.LastSeq < c.FirstSeq {
				t.Fatalf("cadeia inválida: %+v", c)
			}
			classes = append(classes, c.RetentionClass)
		}
		slices.Sort(classes)
		if !slices.Equal(classes, want) || m.Day != today.Format(dayLayout) || m.PrevManifestSHA256 != "" {
			t.Fatalf("manifesto de %s: %+v", tenant, m)
		}
		lockedVersion(t, w, key, time.Now().Add(23*time.Hour))
	}

	// 2.ª execução: idempotente (igual exceto generated_at), sem alerta.
	if err := job.Run(ctx, today); err != nil {
		t.Fatalf("2.ª execução: %v", err)
	}
	if n := len(al.kinds(KindRootMismatch)); n != 0 {
		t.Fatalf("%d alertas de divergência na 2.ª execução", n)
	}

	// Manifesto divergente no WORM: erro + alerta; o objeto fica intacto.
	w2 := testWorm(t)
	m := readManifest(t, w, rootKey(a, today))
	m.Chains[0].LastHash = strings.Repeat("0", 64)
	forged, _ := json.Marshal(m)
	if err := w2.Put(ctx, rootKey(a, today), forged, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	job2 := &RootJob{DB: e.pool, Worm: w2, Alert: al, Retention: 24 * time.Hour, Tenants: []string{a, b}}
	err := job2.Run(ctx, today)
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("esperado ErrRootMismatch, veio %v", err)
	}
	if got := al.kinds(KindRootMismatch); len(got) != 1 || !strings.Contains(got[0].Summary, a) {
		t.Fatalf("alertas de divergência: %+v", got)
	}
	if got, _ := w2.Get(ctx, rootKey(a, today)); string(got) != string(forged) {
		t.Fatal("o manifesto do WORM foi alterado")
	}
	readManifest(t, w2, rootKey(b, today)) // o outro tenant foi publicado na mesma

	// Pela tarefa Asynq: divergência = permanente (sem repetições).
	task, _ := RootTask(today)
	if err := job2.Handle(ctx, task); !errors.Is(err, asynq.SkipRetry) || !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("Handle: %v", err)
	}
}

// Dias em falta recuperados por ordem; prev_manifest_sha256 encadeia os manifestos.
func TestRootBackfillChainsManifests(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a := uuidV7()
	appendEvent(t, e, event(a, 0))
	w := &memWorm{}
	today := dayUTC(time.Now())
	// Marcador de há 3 dias: os 2 dias seguintes (sem eventos de A) e hoje são publicados.
	if err := w.Put(ctx, rootKey(a, today.AddDate(0, 0, -3)), []byte(`{"day":"x"}`), time.Time{}); err != nil {
		t.Fatal(err)
	}
	job := &RootJob{DB: e.pool, Worm: w, Alert: &fakeAlerter{}, Retention: time.Hour, Tenants: []string{a}}
	if err := job.Run(ctx, today); err != nil {
		t.Fatal(err)
	}
	keys := w.keys("t/" + a + "/roots/")
	if len(keys) != 4 {
		t.Fatalf("manifestos: %v", keys)
	}
	prev, _ := w.Get(ctx, keys[0])
	for _, k := range keys[1:] {
		m := readManifest(t, w, k)
		if m.PrevManifestSHA256 != sha(string(prev)) {
			t.Fatalf("%s: prev_manifest_sha256 não encadeia", k)
		}
		prev, _ = w.Get(ctx, k)
	}
	if m := readManifest(t, w, keys[3]); len(m.Chains) != 1 {
		t.Fatalf("hoje: %+v", m)
	}
}

func TestNextRootRun(t *testing.T) {
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	for now, want := range map[string]string{
		"2026-11-26T00:00:00Z": "2026-11-26T00:10:00Z",
		"2026-11-26T00:10:00Z": "2026-11-27T00:10:00Z",
		"2026-11-26T23:59:00Z": "2026-11-27T00:10:00Z",
	} {
		if got := nextRootRun(at(now)); !got.Equal(at(want)) {
			t.Errorf("nextRootRun(%s) = %s", now, got)
		}
	}
	task, opts := RootTask(at("2026-11-25T13:00:00Z"))
	if task.Type() != RootTaskType || string(task.Payload()) != `{"day":"2026-11-25"}` {
		t.Fatal(string(task.Payload()))
	}
	found := false
	for _, o := range opts {
		if o.Type() == asynq.TaskIDOpt && o.Value() == "audit-root-2026-11-25" {
			found = true
		}
	}
	if !found {
		t.Fatal("TaskID audit-root-YYYY-MM-DD em falta")
	}
}
