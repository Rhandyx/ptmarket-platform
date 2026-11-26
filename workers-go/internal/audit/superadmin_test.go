package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Cartão 09: relay audit_alerts → WORM (+ Telegram/Discord só se kind crítico). PG, Redis e WORM reais;
// Telegram e Discord são servidores HTTP de teste.

type fakeChat struct {
	mu     sync.Mutex
	bodies []string
	fail   int // falha os primeiros N pedidos com HTTP 500
	tg     bool
}

func (f *fakeChat) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies = append(f.bodies, r.URL.Path+" "+string(b))
	if f.fail > 0 {
		f.fail--
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if f.tg {
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeChat) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bodies...)
}

func withFields(ev string, kv map[string]any) string {
	var m map[string]any
	_ = json.Unmarshal([]byte(ev), &m)
	for k, v := range kv {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

const testIBAN = "PT50000201231234567890154"

func TestRelayCriticalAndSuperadmin(t *testing.T) {
	e := setup(t)
	w := testWorm(t)
	ctx := context.Background()
	tenant := uuidV7()
	admin := withFields(event(tenant, 1), map[string]any{"actor_type": "admin", "action": "test.superadmin_action"})
	payment := withFields(event(tenant, 2), map[string]any{"action": "payments.failed", "outcome": "error"})
	iban := withFields(event(tenant, 3), map[string]any{"action": "stores.iban_update",
		"changes": map[string]any{"iban": testIBAN}, "reason": "IBAN " + testIBAN})
	for _, ev := range []string{admin, payment, iban} {
		appendEvent(t, e, ev)
	}

	tg := &fakeChat{tg: true}
	dc := &fakeChat{fail: 1}
	tgs, dcs := httptest.NewServer(tg), httptest.NewServer(dc)
	defer tgs.Close()
	defer dcs.Close()
	fan := &Fanout{
		Channels: []Channel{
			&Telegram{Token: "123:TGSECRET", ChatID: "42", BaseURL: tgs.URL},
			&Discord{WebhookURL: dcs.URL + "/api/webhooks/1/DCSECRET"},
		},
		Sent: RedisSent{Redis: e.rdb, Prefix: "audit:alert:sent:test:" + uuidV7() + ":"},
	}
	relay := &Relay{DB: e.pool, Worm: w, Alert: fan, Retention: 24 * time.Hour, Tenants: []string{tenant}}

	// 1.ª ronda: o Discord falha no 1.º crítico → essa linha fica por publicar; as outras duas saem.
	n, err := relay.RunOnce(ctx)
	if n != 2 || err == nil {
		t.Fatalf("1.ª ronda: n=%d err=%v", n, err)
	}
	if s := err.Error(); strings.Contains(s, "SECRET") || !strings.Contains(s, "discord: HTTP 500") {
		t.Fatalf("erro: %s", s)
	}
	// 2.ª ronda (reentrega): só o Discord recebe; o Telegram não repete; o objeto já existe e é igual.
	if n, err := relay.RunOnce(ctx); n != 1 || err != nil {
		t.Fatalf("2.ª ronda: n=%d err=%v", n, err)
	}
	if n, err := relay.RunOnce(ctx); n != 0 || err != nil {
		t.Fatalf("3.ª ronda: n=%d err=%v", n, err)
	}

	tgAll, dcAll := tg.all(), dc.all()
	if len(tgAll) != 2 || len(dcAll) != 3 {
		t.Fatalf("pedidos: telegram=%d discord=%d (esperado 2 e 3)", len(tgAll), len(dcAll))
	}
	for _, b := range append(tgAll, dcAll...) {
		if strings.Contains(b, "test.superadmin_action") {
			t.Fatal("ação de superadmin não crítica foi alertada")
		}
		if strings.Contains(b, testIBAN) || strings.Contains(b, "0201231234567890154") || strings.Contains(b, "loja@teste") {
			t.Fatalf("alerta com dados pessoais: %s", b)
		}
	}
	if !strings.Contains(strings.Join(tgAll, "\n"), "payment_failure") || !strings.Contains(strings.Join(tgAll, "\n"), "iban_change") {
		t.Fatalf("telegram: %v", tgAll)
	}

	// 3 objetos em t/<tenant>/events/…, todos publicados; iban_change sem changes nem reason.
	rows, err := e.pool.Query(ctx, `SELECT id::text, created_at, kind, published_at IS NOT NULL
		FROM audit.audit_alerts WHERE payload->>'tenant_id' = $1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		var at time.Time
		var kind *string
		var published bool
		if err := rows.Scan(&id, &at, &kind, &published); err != nil {
			t.Fatal(err)
		}
		count++
		if !published {
			t.Fatalf("alerta %s por publicar", id)
		}
		b, err := w.Get(ctx, eventKey(tenant, at, id))
		if err != nil {
			t.Fatalf("objeto do alerta %s: %v", id, err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(b, &obj); err != nil || string(obj["id"]) != `"`+id+`"` {
			t.Fatalf("objeto: %s", b)
		}
		if kind != nil && *kind == "iban_change" && (strings.Contains(string(b), testIBAN) || strings.Contains(string(b), `"changes"`)) {
			t.Fatalf("iban_change no WORM com changes/IBAN: %s", b)
		}
	}
	if count != 3 {
		t.Fatalf("%d alertas na BD, esperado 3", count)
	}
}

// Falha do WORM: nada publicado, nada alertado; depois de 15 min → 'audit.alert_backlog'.
func TestRelayWormFailureAndBacklog(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tenant := uuidV7()
	appendEvent(t, e, withFields(event(tenant, 1), map[string]any{"action": "payments.failed", "outcome": "error"}))
	al := &fakeAlerter{}
	relay := &Relay{DB: e.pool, Worm: &memWorm{putErr: errors.New("worm em baixo")}, Alert: al,
		Tenants: []string{tenant}, Now: func() time.Time { return time.Now().Add(time.Hour) }}
	if err := relay.Round(ctx); err == nil {
		t.Fatal("esperado erro do WORM")
	}
	if len(al.kinds("payment_failure")) != 0 {
		t.Fatal("alertou sem gravar no WORM")
	}
	if got := al.kinds(KindAlertBacklog); len(got) != 1 {
		t.Fatalf("alertas de atraso: %+v", got)
	}
	_ = relay.Round(ctx) // no máximo um alerta de atraso por janela
	if got := al.kinds(KindAlertBacklog); len(got) != 1 {
		t.Fatalf("alertas de atraso repetidos: %d", len(got))
	}
	// Recupera: o WORM volta, a linha sai e o alerta crítico também.
	relay.Worm = &memWorm{}
	if err := relay.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if len(al.kinds("payment_failure")) != 1 {
		t.Fatal("alerta crítico em falta depois de recuperar")
	}
}

// Cartão 02/09b: o resumo nunca leva um e-mail nem um link disfarçado; com UUID leva o UUID; o Discord
// recebe o texto num bloco de código; o Telegram em texto simples (sem parse_mode).
func TestRelaySummaryNoPIINoMarkdown(t *testing.T) {
	ctx := context.Background()
	actor, target := "0194f0a0-1111-7000-8000-00000000abcd", "0194f0a0-2222-7000-8000-00000000beef"
	cases := []struct {
		name   string
		fields string
		bad    []string
		good   []string
	}{
		{"e-mail", `"actor_id":"joao@x.pt","target_type":"store","target_id":"joao@x.pt"`, []string{"joao", "x.pt"}, nil},
		{"link mascarado", `"actor_id":"[clique](http://evil)","target_type":"[a](http://evil)","target_id":"[clique](http://evil)"`,
			[]string{"clique", "evil", "]("}, nil},
		{"ação e tipo com markdown", `"actor_type":"**x**","action":"[a](http://evil)","target_id":"` + target + `"`,
			[]string{"evil", "**"}, []string{target}},
		{"uuid", `"actor_id":"` + actor + `","target_type":"store","target_id":"` + target + `"`, nil, []string{actor, target, "store"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tg, dc := &fakeChat{tg: true}, &fakeChat{}
			tgs, dcs := httptest.NewServer(tg), httptest.NewServer(dc)
			defer tgs.Close()
			defer dcs.Close()
			fan := &Fanout{Channels: []Channel{
				&Telegram{Token: "1:T", ChatID: "42", BaseURL: tgs.URL},
				&Discord{WebhookURL: dcs.URL + "/api/webhooks/1/x"},
			}}
			kind := "iban_change"
			payload := `{"tenant_id":"0194f0a0-0000-7000-8000-000000000001","actor_type":"admin","action":"stores.iban_update",` + c.fields + `}`
			relay := &Relay{Worm: &memWorm{}, Alert: fan, Retention: time.Hour}
			if err := relay.relayOne(ctx, alertRow{ID: uuidV7(), CreatedAt: time.Now(), EventType: "x", Kind: &kind,
				Payload: json.RawMessage(payload)}); err != nil {
				t.Fatal(err)
			}
			tgAll, dcAll := tg.all(), dc.all()
			if len(tgAll) != 1 || len(dcAll) != 1 {
				t.Fatalf("pedidos: telegram=%d discord=%d", len(tgAll), len(dcAll))
			}
			for _, raw := range []string{tgAll[0], dcAll[0]} {
				body := raw[strings.Index(raw, " ")+1:]
				var m map[string]any
				if err := json.Unmarshal([]byte(body), &m); err != nil {
					t.Fatal(err)
				}
				text, _ := m["text"].(string)
				if text == "" {
					text, _ = m["content"].(string)
				}
				for _, b := range c.bad {
					if strings.Contains(text, b) {
						t.Fatalf("corpo contém %q: %s", b, text)
					}
				}
				for _, g := range c.good {
					if !strings.Contains(text, g) {
						t.Fatalf("corpo sem %q: %s", g, text)
					}
				}
				if _, ok := m["parse_mode"]; ok {
					t.Fatal("telegram com parse_mode")
				}
			}
			var dm map[string]any
			_ = json.Unmarshal([]byte(dcAll[0][strings.Index(dcAll[0], " ")+1:]), &dm)
			content, _ := dm["content"].(string)
			if !strings.HasPrefix(content, "```\n") || !strings.HasSuffix(content, "\n```") {
				t.Fatalf("discord fora do bloco de código: %q", content)
			}
			if am, _ := dm["allowed_mentions"].(map[string]any); am == nil || len(am["parse"].([]any)) != 0 {
				t.Fatalf("allowed_mentions: %v", dm["allowed_mentions"])
			}
		})
	}
}
