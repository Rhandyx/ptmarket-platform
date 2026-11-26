package audit

// Alertas imediatos ao owner (spec 13 §1): Telegram (bot API) e Discord (webhook), fan-out para os canais
// configurados. SÓ eventos críticos. Sem dados pessoais: ator-id, ação, alvo, hora (IBAN nunca, nem
// mascarado). Os erros nunca citam URLs nem tokens (o token do Telegram vai no caminho do URL).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/segjar/ptmarket/workers-go/internal/logx"
)

// Kinds internos do worker (os da BD são os de audit_alerts.kind).
const (
	KindRootMismatch     = "audit.root_mismatch"
	KindDefaultPartition = "audit.default_partition_rows"
	KindVerifyFailed     = "audit.verify_failed"
	KindStreamDeadLetter = "audit.stream_dead_letter"
	KindStreamStale      = "audit.stream_stale"
	KindAlertBacklog     = "audit.alert_backlog"
)

const (
	alertTimeout   = 5 * time.Second
	alertMaxText   = 1800
	sentTTL        = 30 * 24 * time.Hour
	telegramAPI    = "https://api.telegram.org"
	sentKeyPrefix  = "audit:alert:sent:"
	alertBodyLimit = 64 << 10
)

// Alert: Summary sem dados pessoais; EventID = id do evento (vazio nos alertas internos).
type Alert struct {
	Kind    string
	Summary string
	EventID string
}

// Alerter envia um alerta para todos os canais.
type Alerter interface {
	Notify(ctx context.Context, a Alert) error
}

// Channel: um destino (Telegram, Discord, log).
type Channel interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}

func alertText(a Alert) string {
	t := "[PTMarket caixa negra] " + a.Kind + "\n" + logx.Redact(a.Summary)
	if a.EventID != "" {
		t += "\nevento " + a.EventID
	}
	if len(t) > alertMaxText {
		t = strings.ToValidUTF8(t[:alertMaxText], "")
	}
	return t
}

func alertClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: alertTimeout}
}

// postJSON: POST com timeout de 5 s; erros só com o canal e o estado HTTP (nunca o URL).
func postJSON(ctx context.Context, c *http.Client, name, u string, body any) (*http.Response, []byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: corpo inválido", name)
	}
	cctx, cancel := context.WithTimeout(ctx, alertTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: pedido inválido", name)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := alertClient(c).Do(req)
	if err != nil {
		if cctx.Err() != nil {
			return nil, nil, fmt.Errorf("%s: sem resposta em %s", name, alertTimeout)
		}
		return nil, nil, fmt.Errorf("%s: falha de rede", name)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, alertBodyLimit))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp, rb, fmt.Errorf("%s: HTTP %d", name, resp.StatusCode)
	}
	return resp, rb, nil
}

// Telegram: bot API sendMessage (texto simples, sem parse_mode).
type Telegram struct {
	Token   string
	ChatID  string
	BaseURL string // testes; vazio = https://api.telegram.org
	HTTP    *http.Client
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Send(ctx context.Context, a Alert) error {
	base := t.BaseURL
	if base == "" {
		base = telegramAPI
	}
	_, rb, err := postJSON(ctx, t.HTTP, t.Name(), strings.TrimRight(base, "/")+"/bot"+t.Token+"/sendMessage",
		map[string]any{"chat_id": t.ChatID, "text": alertText(a), "disable_web_page_preview": true})
	if err != nil {
		return err
	}
	var r struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(rb, &r) != nil || !r.OK {
		return errors.New("telegram: resposta sem ok=true")
	}
	return nil
}

// Discord: webhook (sem menções).
type Discord struct {
	WebhookURL string
	HTTP       *http.Client
}

func (d *Discord) Name() string { return "discord" }

func (d *Discord) Send(ctx context.Context, a Alert) error {
	_, _, err := postJSON(ctx, d.HTTP, d.Name(), d.WebhookURL,
		map[string]any{"content": alertText(a), "allowed_mentions": map[string]any{"parse": []string{}}})
	return err
}

// LogSink: ALERT_SINK=log:// (só dev): o alerta vai para o log do worker.
type LogSink struct{ Log *slog.Logger }

func (l *LogSink) Name() string { return "log" }

func (l *LogSink) Send(_ context.Context, a Alert) error {
	if l.Log != nil {
		l.Log.Warn("ALERTA "+a.Kind, "summary", logx.Redact(a.Summary), "event_id", a.EventID)
	}
	return nil
}

// AlertSettings: valores das variáveis ALERT_* (lidas em internal/config).
type AlertSettings struct {
	TelegramBotToken  string
	TelegramChatID    string
	DiscordWebhookURL string
	Sink              string // "log://" ou vazio
}

// NewChannels constrói os canais configurados; nenhum canal = erro (não há forma de desligar).
func NewChannels(s AlertSettings, log *slog.Logger) ([]Channel, error) {
	var out []Channel
	if (s.TelegramBotToken == "") != (s.TelegramChatID == "") {
		return nil, errors.New("ALERT_TELEGRAM_BOT_TOKEN e ALERT_TELEGRAM_CHAT_ID têm de vir juntas")
	}
	if s.TelegramBotToken != "" {
		out = append(out, &Telegram{Token: s.TelegramBotToken, ChatID: s.TelegramChatID})
	}
	if s.DiscordWebhookURL != "" {
		if err := checkURL(s.DiscordWebhookURL); err != nil {
			return nil, fmt.Errorf("ALERT_DISCORD_WEBHOOK_URL: %w", err)
		}
		out = append(out, &Discord{WebhookURL: s.DiscordWebhookURL})
	}
	switch s.Sink {
	case "":
	case "log://":
		out = append(out, &LogSink{Log: log})
	default:
		return nil, errors.New("ALERT_SINK só aceita log://")
	}
	if len(out) == 0 {
		return nil, errors.New("nenhum canal de alerta: definir ALERT_TELEGRAM_BOT_TOKEN + ALERT_TELEGRAM_CHAT_ID " +
			"e/ou ALERT_DISCORD_WEBHOOK_URL (dev: ALERT_SINK=log://)")
	}
	return out, nil
}

// SentStore lembra os envios por (canal, evento): uma reentrega não repete o alerta no canal que já o recebeu.
type SentStore interface {
	Seen(ctx context.Context, channel, eventID string) (bool, error)
	Mark(ctx context.Context, channel, eventID string) error
}

// RedisSent: audit:alert:sent:<canal>:<evento>, 30 dias.
type RedisSent struct {
	Redis  redis.UniversalClient
	Prefix string // testes; vazio = audit:alert:sent:
}

func (r RedisSent) key(channel, id string) string {
	return or(r.Prefix, sentKeyPrefix) + channel + ":" + id
}

func (r RedisSent) Seen(ctx context.Context, channel, id string) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	n, err := r.Redis.Exists(cctx, r.key(channel, id)).Result()
	return n > 0, err
}

func (r RedisSent) Mark(ctx context.Context, channel, id string) error {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return r.Redis.Set(cctx, r.key(channel, id), "1", sentTTL).Err()
}

// Fanout envia para todos os canais; devolve erro se algum falhar (o chamador repete; os canais que já
// receberam o evento não o recebem outra vez, via Sent).
type Fanout struct {
	Channels []Channel
	Sent     SentStore // nil = sem memória de envios
	Log      *slog.Logger
}

func (f *Fanout) Notify(ctx context.Context, a Alert) error {
	if len(f.Channels) == 0 {
		return errors.New("alerta: nenhum canal configurado")
	}
	var errs []error
	for _, c := range f.Channels {
		dedupe := f.Sent != nil && a.EventID != ""
		if dedupe {
			seen, err := f.Sent.Seen(ctx, c.Name(), a.EventID)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: memória de envios indisponível", c.Name()))
				continue
			}
			if seen {
				continue
			}
		}
		if err := c.Send(ctx, a); err != nil {
			errs = append(errs, err)
			if f.Log != nil {
				f.Log.Error("alerta não entregue", "channel", c.Name(), "kind", a.Kind, "event_id", a.EventID, "err", err.Error())
			}
			continue
		}
		if dedupe {
			if err := f.Sent.Mark(ctx, c.Name(), a.EventID); err != nil && f.Log != nil {
				f.Log.Error("memória de envios", "channel", c.Name(), "event_id", a.EventID)
			}
		}
	}
	return errors.Join(errs...)
}
