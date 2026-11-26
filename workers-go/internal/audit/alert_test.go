package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/segjar/ptmarket/workers-go/internal/logx"
)

func TestNewChannels(t *testing.T) {
	cases := []struct {
		s    AlertSettings
		n    int
		fail string
	}{
		{AlertSettings{}, 0, "nenhum canal de alerta"},
		{AlertSettings{TelegramBotToken: "x"}, 0, "têm de vir juntas"},
		{AlertSettings{Sink: "stdout://"}, 0, "ALERT_SINK"},
		{AlertSettings{DiscordWebhookURL: "http://example.com/hook/SECRET"}, 0, "ALERT_DISCORD_WEBHOOK_URL"},
		{AlertSettings{Sink: "log://"}, 0, "ALERT_DEV_LOG_ONLY=1"},
		{AlertSettings{Sink: "log://", DevLogOnly: true}, 1, ""},
		{AlertSettings{Sink: "log://", DiscordWebhookURL: "https://discord.com/api/webhooks/1/x"}, 2, ""},
		{AlertSettings{TelegramBotToken: "t", TelegramChatID: "c", DiscordWebhookURL: "https://discord.com/api/webhooks/1/x"}, 2, ""},
	}
	for _, c := range cases {
		ch, err := NewChannels(c.s, nil)
		if c.fail != "" {
			if err == nil || !strings.Contains(err.Error(), c.fail) || strings.Contains(err.Error(), "SECRET") {
				t.Errorf("%+v: %v", c.s, err)
			}
			continue
		}
		if err != nil || len(ch) != c.n {
			t.Errorf("%+v: %d canais, %v", c.s, len(ch), err)
		}
	}
}

// Erros nunca citam o token (vai no caminho do URL do Telegram) nem o URL do webhook.
func TestAlertErrorsHideSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	url := srv.URL
	srv.Close() // ligação recusada
	ctx := context.Background()
	for _, c := range []Channel{
		&Telegram{Token: "123:TGSECRET", ChatID: "1", BaseURL: url},
		&Discord{WebhookURL: url + "/api/webhooks/1/DCSECRET"},
	} {
		err := c.Send(ctx, Alert{Kind: "k", Summary: "s"})
		if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "127.0.0.1") {
			t.Fatalf("%s: %v", c.Name(), err)
		}
	}
}

func TestAlertTextRedacts(t *testing.T) {
	txt := alertText(Alert{Kind: "iban_change", Summary: "alvo " + testIBAN + " nif 123456789", EventID: "e1"})
	if strings.Contains(txt, testIBAN) || strings.Contains(txt, "123456789") || !strings.Contains(txt, "evento e1") {
		t.Fatal(txt)
	}
	long := alertText(Alert{Kind: "k", Summary: strings.Repeat("é", 2000)})
	if len(long) > alertMaxText || !strings.HasPrefix(long, "[PTMarket") {
		t.Fatal(len(long))
	}
}

// Fan-out: um canal falha → erro; os outros entregam; sem memória de envios cada chamada envia.
func TestFanoutPartialFailure(t *testing.T) {
	ok := &fakeChat{tg: true}
	bad := &fakeChat{fail: 1}
	s1, s2 := httptest.NewServer(ok), httptest.NewServer(bad)
	defer s1.Close()
	defer s2.Close()
	f := &Fanout{Channels: []Channel{&Telegram{Token: "t", ChatID: "c", BaseURL: s1.URL}, &Discord{WebhookURL: s2.URL}}}
	if err := f.Notify(context.Background(), Alert{Kind: KindStreamStale, Summary: "x"}); err == nil {
		t.Fatal("esperado erro do canal que falhou")
	}
	if len(ok.all()) != 1 || len(bad.all()) != 1 {
		t.Fatal("fan-out não chegou aos dois canais")
	}
	if err := (&Fanout{}).Notify(context.Background(), Alert{}); err == nil {
		t.Fatal("Fanout sem canais tem de falhar")
	}
}

// Cartão 02/09b: um 3xx nunca é seguido (alertas e WORM); o 2.º servidor recebe 0 pedidos e o erro não
// cita o URL (nem o Location).
func TestNoRedirects(t *testing.T) {
	var hits atomic.Int64
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/LOCATIONSECRET", http.StatusFound)
	}))
	defer first.Close()
	ctx := context.Background()
	clean := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: esperado erro no 302", what)
		}
		s := err.Error()
		if strings.Contains(s, "127.0.0.1") || strings.Contains(s, "LOCATIONSECRET") || strings.Contains(s, "SECRET") {
			t.Fatalf("%s: erro cita o URL: %s", what, s)
		}
		if !strings.Contains(s, "HTTP 302") {
			t.Fatalf("%s: erro sem o estado: %s", what, s)
		}
	}
	// Clientes do worker (HTTP nil = cliente próprio).
	clean("telegram", (&Telegram{Token: "1:TGSECRET", ChatID: "1", BaseURL: first.URL}).Send(ctx, Alert{Kind: "k", Summary: "s"}))
	clean("discord", (&Discord{WebhookURL: first.URL + "/api/webhooks/1/DCSECRET"}).Send(ctx, Alert{Kind: "k", Summary: "s"}))
	w, err := NewS3Worm(first.URL, "us-east-1", "b", "ak", "WORMSECRET")
	if err != nil {
		t.Fatal(err)
	}
	clean("worm put", w.Put(ctx, "t/platform/events/x.json", []byte(`{}`), time.Now().Add(time.Hour)))
	_, err = w.Get(ctx, "t/platform/events/x.json")
	clean("worm get", err)
	_, err = (&S3Worm{Endpoint: first.URL, // HTTP nil = cliente por omissão
		Region: "r", Bucket: "b", AccessKey: "a", SecretKey: "s"}).Get(ctx, "k")
	clean("worm sem cliente", err)
	if n := hits.Load(); n != 0 {
		t.Fatalf("o 2.º servidor recebeu %d pedido(s)", n)
	}
}

// Cartão 02/09b: o Discord recebe o texto num bloco de código, sem acentos graves no conteúdo, ≤ 2000.
func TestDiscordCodeBlock(t *testing.T) {
	txt := discordText(Alert{Kind: "k", Summary: "x ``` [clique](http://evil) " + strings.Repeat("é", 2000)})
	if !strings.HasPrefix(txt, "```\n") || !strings.HasSuffix(txt, "\n```") || len(txt) > discordMax {
		t.Fatalf("bloco: %d %q…", len(txt), txt[:40])
	}
	if strings.Count(txt, "`") != 6 {
		t.Fatal("acento grave do conteúdo dentro do bloco")
	}
}

// throttleEnv: Redis de dev com prefixo único por teste (limpo no fim; o Redis é partilhado). A hora do
// Throttle é a do Redis: as janelas dos testes são curtas (testWindow) e fecham com espera real; o relógio
// falso só serve o created_at do relay.
type throttleEnv struct {
	rdb    *redis.Client
	prefix string
	now    time.Time
	mu     sync.Mutex
}

func newThrottleEnv(t *testing.T) *throttleEnv {
	t.Helper()
	e := setupRedis(t)
	te := &throttleEnv{rdb: e.rdb, prefix: "test:throttle:{" + uuidV7() + "}:",
		now: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)}
	t.Cleanup(func() {
		ctx := context.Background()
		keys, _ := te.rdb.Keys(ctx, te.prefix+"*").Result()
		if len(keys) > 0 {
			_ = te.rdb.Del(ctx, keys...).Err()
		}
	})
	return te
}

func (e *throttleEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *throttleEnv) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

const testWindow = 1200 * time.Millisecond

func (e *throttleEnv) throttle(next Alerter) *Throttle {
	return &Throttle{Next: next, Redis: e.rdb, Prefix: e.prefix, Window: testWindow}
}

// closeWindow: espera (tempo real, o do Redis) até a janela em curso ter fechado.
func (e *throttleEnv) closeWindow() { time.Sleep(testWindow + 200*time.Millisecond) }

func eventN(i int) string { return fmt.Sprintf("0194f0a0-0000-7000-8000-%012d", i) }

// Cartão 02/09c: 8 iban_change do tenant A + 1 do tenant B em 5 min → A: 5 um a um + 1 resumo com os 3
// event_id retidos; B: 1 um a um; outro kind não é afetado; nada se perde no WORM.
func TestThrottleBurstByTenant(t *testing.T) {
	e := newThrottleEnv(t)
	ctx := context.Background()
	next := &fakeAlerter{}
	th := e.throttle(next)
	w := &memWorm{}
	relay := &Relay{Worm: w, Alert: th, Retention: time.Hour, Now: e.clock}
	tenantA, tenantB := "0194f0a0-0000-7000-8000-00000000000a", "0194f0a0-0000-7000-8000-00000000000b"
	kind, other := "iban_change", "payment_failure"
	send := func(i int, tenant, k string) {
		t.Helper()
		e.advance(10 * time.Second)
		row := alertRow{ID: eventN(i), CreatedAt: e.clock(), EventType: "x", Kind: &k,
			Payload: json.RawMessage(`{"tenant_id":"` + tenant + `","actor_type":"merchant","action":"stores.iban_update"}`)}
		if err := relay.relayOne(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 8; i++ {
		send(i, tenantA, kind)
	}
	send(9, tenantB, kind)
	send(10, tenantA, other)
	if got := len(w.keys("t/"+tenantA+"/events/")) + len(w.keys("t/"+tenantB+"/events/")); got != 10 {
		t.Fatalf("WORM: %d objetos, esperado 10", got)
	}
	byTenant := func(tenant string) []Alert {
		var out []Alert
		for _, a := range next.kinds(kind) {
			if a.TenantID == tenant {
				out = append(out, a)
			}
		}
		return out
	}
	if a, b, o := len(byTenant(tenantA)), len(byTenant(tenantB)), len(next.kinds(other)); a != 5 || b != 1 || o != 1 {
		t.Fatalf("um a um: A=%d (5) B=%d (1) %s=%d (1)", a, b, other, o)
	}
	if err := th.Flush(ctx); err != nil || len(byTenant(tenantA)) != 5 {
		t.Fatalf("resumo antes do fim da janela: %v", err)
	}
	e.closeWindow()
	if err := th.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got := byTenant(tenantA)
	if len(got) != 6 {
		t.Fatalf("A: %d alertas, esperado 5 + resumo", len(got))
	}
	sum := got[5]
	for _, want := range []string{"mais 3 alerta(s)", kind, tenantA, eventN(6), eventN(7), eventN(8)} {
		if !strings.Contains(sum.Summary, want) {
			t.Fatalf("resumo sem %q: %s", want, sum.Summary)
		}
	}
	if sum.EventID != "" || strings.Contains(sum.Summary, eventN(5)) || strings.Contains(sum.Summary, "+") {
		t.Fatalf("resumo: %+v", sum)
	}
	if len(byTenant(tenantB)) != 1 {
		t.Fatal("B recebeu um resumo sem nada retido")
	}
	if err := th.Flush(ctx); err != nil || len(byTenant(tenantA)) != 6 {
		t.Fatal("resumo repetido")
	}
	// Nova janela: volta a sair um a um.
	send(11, tenantA, kind)
	if len(byTenant(tenantA)) != 7 {
		t.Fatal("nova janela não enviou o alerta")
	}
}

// Cartão 02/09c: kinds "audit.*", os críticos verify_failure/superadmin_login e alertas sem tenant nunca
// são agrupados.
func TestThrottleNeverGroupsAudit(t *testing.T) {
	e := newThrottleEnv(t)
	next := &fakeAlerter{}
	th := e.throttle(next)
	tenant := "0194f0a0-0000-7000-8000-00000000000a"
	for i := range 10 {
		if err := th.Notify(context.Background(), Alert{Kind: KindVerifyFailed, Summary: "x", EventID: eventN(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(next.kinds(KindVerifyFailed)); got != 10 {
		t.Fatalf("%d de 10 um a um", got)
	}
	for _, c := range []struct{ kind, tenant string }{
		{"superadmin_login", tenant}, {"verify_failure", tenant}, {"iban_change", ""}, {"iban_change", "nao-uuid"},
	} {
		before := len(next.kinds(c.kind))
		for i := range 8 {
			if err := th.Notify(context.Background(), Alert{Kind: c.kind, TenantID: c.tenant, EventID: eventN(100 + i)}); err != nil {
				t.Fatal(err)
			}
		}
		if got := len(next.kinds(c.kind)) - before; got != 8 {
			t.Fatalf("%s/%q: %d de 8 um a um", c.kind, c.tenant, got)
		}
	}
	if n, _ := e.rdb.Keys(context.Background(), e.prefix+"*").Result(); len(n) != 0 {
		t.Fatalf("estado no Redis para audit.*: %v", n)
	}
}

// Cartão 02/09c: duas réplicas no mesmo Redis → o resumo sai uma só vez; uma instância nova depois de um
// "crash" (sem Flush) envia o resumo pendente da janela fechada (no arranque de Run).
func TestThrottleReplicasAndCrash(t *testing.T) {
	e := newThrottleEnv(t)
	ctx := context.Background()
	next := &fakeAlerter{}
	r1, r2 := e.throttle(next), e.throttle(next)
	tenant := "0194f0a0-0000-7000-8000-00000000000a"
	for i := 1; i <= 8; i++ { // alternam entre as réplicas: o limite é partilhado
		r := r1
		if i%2 == 0 {
			r = r2
		}
		if err := r.Notify(ctx, Alert{Kind: "iban_change", TenantID: tenant, EventID: eventN(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(next.kinds("iban_change")); got != 5 {
		t.Fatalf("%d um a um com 2 réplicas, esperado 5", got)
	}
	e.closeWindow()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { _ = r1.Flush(ctx) })
		wg.Go(func() { _ = r2.Flush(ctx) })
	}
	wg.Wait()
	if got := len(next.kinds("iban_change")); got != 6 {
		t.Fatalf("%d alertas, esperado 5 + 1 resumo", got)
	}

	// "Crash": r1 retém e desaparece sem Flush; r3 (nova) arranca com a janela já fechada.
	for i := 20; i < 28; i++ {
		if err := r1.Notify(ctx, Alert{Kind: "iban_change", TenantID: tenant, EventID: eventN(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(next.kinds("iban_change")); got != 11 {
		t.Fatalf("%d alertas, esperado 11", got)
	}
	e.closeWindow()
	r3 := e.throttle(next)
	r3.Tick = time.Hour
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { r3.Run(rctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(next.kinds("iban_change")) < 12 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	got := next.kinds("iban_change")
	if len(got) != 12 || !strings.Contains(got[11].Summary, "mais 3 alerta(s)") || !strings.Contains(got[11].Summary, eventN(27)) {
		t.Fatalf("resumo pendente depois do crash: %d %+v", len(got), got[len(got)-1])
	}
}

// Cartão 02/09c: Redis inacessível → tudo um a um, sem erro (nem no Flush de Run).
func TestThrottleRedisDown(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond, MaxRetries: -1})
	defer rdb.Close()
	var buf bytes.Buffer
	next := &fakeAlerter{}
	th := &Throttle{Next: next, Redis: rdb, Log: logx.NewTo(&buf)}
	for i := range 8 {
		if err := th.Notify(context.Background(), Alert{Kind: "iban_change", TenantID: tenantK, EventID: eventN(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(next.kinds("iban_change")); got != 8 {
		t.Fatalf("%d de 8 com o Redis em baixo", got)
	}
	if !strings.Contains(buf.String(), `"level":"WARN"`) {
		t.Fatalf("sem aviso: %s", buf.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	th.Run(ctx) // não bloqueia nem rebenta
}

// Um envio falhado não gasta lugar; um resumo falhado fica para o Flush seguinte (e liberta o claim).
func TestThrottleFailures(t *testing.T) {
	e := newThrottleEnv(t)
	ctx := context.Background()
	next := &fakeAlerter{err: errors.New("canal em baixo")}
	th := e.throttle(next)
	th.Limit = 2
	for i := range 3 {
		if err := th.Notify(ctx, Alert{Kind: "k", TenantID: tenantK, EventID: eventN(i)}); err == nil {
			t.Fatal("esperado erro")
		}
	}
	next.mu.Lock()
	next.err = nil
	next.mu.Unlock()
	for i := 10; i < 14; i++ {
		if err := th.Notify(ctx, Alert{Kind: "k", TenantID: tenantK, EventID: eventN(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if len(next.kinds("k")) != 5 { // 3 falhados + 2 entregues
		t.Fatalf("%d chamadas", len(next.kinds("k")))
	}
	e.closeWindow()
	next.mu.Lock()
	next.err = errors.New("canal em baixo")
	next.mu.Unlock()
	if err := th.Flush(ctx); err == nil {
		t.Fatal("esperado erro do resumo")
	}
	next.mu.Lock()
	next.err = nil
	next.mu.Unlock()
	if err := th.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got := next.kinds("k")
	if len(got) != 7 || !strings.Contains(got[6].Summary, "mais 2 alerta(s)") || !strings.Contains(got[6].Summary, eventN(13)) {
		t.Fatalf("%+v", got)
	}
}

// Resumo: até 20 event_id, depois "+N"; ids repetidos (reentrega do relay) não contam duas vezes.
func TestThrottleSummaryCapsIDs(t *testing.T) {
	e := newThrottleEnv(t)
	ctx := context.Background()
	next := &fakeAlerter{}
	th := e.throttle(next)
	th.Limit = 1
	for i := range 31 {
		if err := th.Notify(ctx, Alert{Kind: "k", TenantID: tenantK, EventID: eventN(i)}); err != nil {
			t.Fatal(err)
		}
	}
	_ = th.Notify(ctx, Alert{Kind: "k", TenantID: tenantK, EventID: eventN(30)}) // repetido
	e.closeWindow()
	if err := th.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got := next.kinds("k")
	if len(got) != 2 {
		t.Fatalf("%d alertas", len(got))
	}
	s := got[1].Summary
	if !strings.Contains(s, "mais 30 alerta(s)") || !strings.Contains(s, "+10") || strings.Count(s, "0194f0a0-") != 20 {
		t.Fatalf("resumo: %s", s)
	}
}

const tenantK = "0294f0a0-0000-7000-8000-0000000000cc"

// Cartão 02/09c: relógio único — o Throttle não tem relógio injetável e os scripts tiram a hora do TIME
// do Redis (nenhum argumento de hora).
func TestThrottleRedisClock(t *testing.T) {
	clock := reflect.TypeFor[func() time.Time]()
	for f := range reflect.TypeFor[Throttle]().Fields() {
		if f.Type == clock {
			t.Fatalf("Throttle.%s: relógio local", f.Name)
		}
	}
	for name, src := range map[string]string{"hit": throttleHitSrc, "closed": throttleClosedSrc} {
		if !strings.Contains(src, "redis.call('TIME')") {
			t.Fatalf("%s sem TIME do Redis", name)
		}
	}
	if strings.Contains(throttleHitSrc, "ARGV[7]") || !strings.Contains(throttleHitSrc, "ARGV[6]") {
		t.Fatal("o hit recebe 6 argumentos (sem a hora)")
	}
}

// Cartão 02/09c: resposta inesperada do script → não retém (o Notify envia um a um com Warn).
func TestParseHit(t *testing.T) {
	cases := []struct {
		in       any
		send, ok bool
	}{
		{[]any{int64(1), "1764150000000"}, true, true},
		{[]any{int64(0), "1764150000000"}, false, true},
		{[]any{int64(2), "1764150000000"}, false, false},
		{[]any{"0", "1764150000000"}, false, false},
		{[]any{int64(0), int64(1764150000000)}, false, false},
		{[]any{int64(0), "1.76415e+12"}, false, false},
		{[]any{int64(0), ""}, false, false},
		{[]any{int64(0)}, false, false},
		{"OK", false, false},
		{nil, false, false},
	}
	for _, c := range cases {
		send, _, ok := parseHit(c.in)
		if send != c.send || ok != c.ok {
			t.Errorf("%#v: send=%v ok=%v", c.in, send, ok)
		}
	}
}
