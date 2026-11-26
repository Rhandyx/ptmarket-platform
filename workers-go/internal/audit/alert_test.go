package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// Cartão 02/09b: mais de 5 alertas do mesmo kind em 5 min → 5 um a um + 1 resumo no fim da janela;
// outros kinds não são afetados; nada se perde no WORM.
func TestThrottleBurst(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	next := &fakeAlerter{}
	th := &Throttle{Next: next, Now: clock}
	w := &memWorm{}
	relay := &Relay{Worm: w, Alert: th, Retention: time.Hour, Now: clock}
	tenant := "0194f0a0-0000-7000-8000-000000000001"
	kind, other := "iban_change", "payment_failure"
	for i := range 12 {
		k := kind
		if i == 11 {
			k = other
		}
		now = now.Add(10 * time.Second)
		row := alertRow{ID: fmt.Sprintf("0194f0a0-0000-7000-8000-%012d", i+1), CreatedAt: now, EventType: "x", Kind: &k,
			Payload: json.RawMessage(`{"tenant_id":"` + tenant + `","actor_type":"merchant","action":"stores.iban_update"}`)}
		if err := relay.relayOne(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(w.keys("t/" + tenant + "/events/")); got != 12 {
		t.Fatalf("WORM: %d objetos, esperado 12", got)
	}
	if got := len(next.kinds(kind)); got != 5 {
		t.Fatalf("%s: %d enviados um a um, esperado 5", kind, got)
	}
	if got := len(next.kinds(other)); got != 1 {
		t.Fatalf("%s afetado pelo agrupamento: %d", other, got)
	}
	if err := th.Flush(ctx); err != nil || len(next.kinds(kind)) != 5 {
		t.Fatal("resumo antes do fim da janela")
	}
	now = now.Add(5 * time.Minute)
	if err := th.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got := next.kinds(kind)
	if len(got) != 6 || !strings.Contains(got[5].Summary, "mais 6 alerta(s)") || got[5].EventID != "" {
		t.Fatalf("resumo: %+v", got)
	}
	if err := th.Flush(ctx); err != nil || len(next.kinds(kind)) != 6 {
		t.Fatal("resumo repetido")
	}
	// Nova janela: volta a sair um a um.
	k := kind
	if err := relay.relayOne(ctx, alertRow{ID: "0194f0a0-0000-7000-8000-0000000000ff", CreatedAt: now, Kind: &k,
		Payload: json.RawMessage(`{"tenant_id":"` + tenant + `"}`)}); err != nil {
		t.Fatal(err)
	}
	if len(next.kinds(kind)) != 7 {
		t.Fatal("nova janela não enviou o alerta")
	}
}

// Um envio falhado não gasta lugar; um resumo falhado fica para o Flush seguinte.
func TestThrottleFailures(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	next := &fakeAlerter{err: errors.New("canal em baixo")}
	th := &Throttle{Next: next, Limit: 2, Now: func() time.Time { return now }}
	for range 3 {
		if err := th.Notify(ctx, Alert{Kind: "k"}); err == nil {
			t.Fatal("esperado erro")
		}
	}
	next.mu.Lock()
	next.err = nil
	next.mu.Unlock()
	for range 4 {
		if err := th.Notify(ctx, Alert{Kind: "k"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(next.kinds("k")) != 5 { // 3 falhados + 2 entregues
		t.Fatalf("%d chamadas", len(next.kinds("k")))
	}
	now = now.Add(defaultThrottleWindow)
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
	if len(got) != 7 || !strings.Contains(got[6].Summary, "mais 2 alerta(s)") {
		t.Fatalf("%+v", got)
	}
}
