package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
		{AlertSettings{Sink: "log://"}, 1, ""},
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
