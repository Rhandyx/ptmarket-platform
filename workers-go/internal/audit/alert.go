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
	"regexp"
	"strings"
	"sync"
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
	discordMax     = 2000 // limite do campo content do webhook
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

// noRedirect: os clientes do worker nunca seguem redirects (um 3xx levaria o corpo do alerta ou os
// cabeçalhos assinados do S3 para outro host). O 3xx volta ao chamador como resposta e conta como falha.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func alertClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: alertTimeout, CheckRedirect: noRedirect}
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
		map[string]any{"content": discordText(a), "allowed_mentions": map[string]any{"parse": []string{}}})
	return err
}

// discordText: o texto num bloco de código (o Discord não renderiza markdown nem links mascarados lá
// dentro); os acentos graves do conteúdo são trocados antes para o bloco não poder ser fechado.
func discordText(a Alert) string {
	const open, closing = "```\n", "\n```"
	t := strings.ReplaceAll(alertText(a), "`", "'")
	if lim := discordMax - len(open) - len(closing); len(t) > lim {
		t = strings.ToValidUTF8(t[:lim], "")
	}
	return open + t + closing
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
	DevLogOnly        bool   // ALERT_DEV_LOG_ONLY=1: aceita log:// como único canal (só dev)
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
			"e/ou ALERT_DISCORD_WEBHOOK_URL (dev: ALERT_SINK=log:// com ALERT_DEV_LOG_ONLY=1)")
	}
	if len(out) == 1 && out[0].Name() == "log" {
		// Alertas críticos só no log = ninguém é avisado: só com a variável explícita de dev.
		if !s.DevLogOnly {
			return nil, errors.New("ALERT_SINK=log:// sozinho não avisa ninguém: configurar Telegram e/ou Discord " +
				"(em dev: ALERT_DEV_LOG_ONLY=1; nunca em produção)")
		}
		if log != nil {
			log.Warn("alertas críticos só no log do worker (ALERT_DEV_LOG_ONLY=1): ninguém é avisado; nunca em produção")
		}
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

// Throttle agrupa rajadas (cartão 02/09b: o onboarding em massa gera um iban_change por loja): por kind,
// numa janela de Window a contar do 1.º alerta, só os Limit primeiros saem um a um; os seguintes não são
// enviados e, no fim da janela, sai um único resumo com a contagem. Não toca no WORM (o relay grava cada
// alerta antes de chamar Notify). Estado em memória: um rearranque perde a contagem por enviar (o detalhe
// continua no WORM e em audit_alerts); Run faz um último Flush ao parar.
type Throttle struct {
	Next   Alerter
	Limit  int           // 0 = 5
	Window time.Duration // 0 = 5 min
	Tick   time.Duration // 0 = 30 s (frequência do Flush em Run)
	Now    func() time.Time
	Log    *slog.Logger

	mu      sync.Mutex
	buckets map[string]*throttleBucket
	pending map[string]*throttleSummary
}

const (
	defaultThrottleLimit  = 5
	defaultThrottleWindow = 5 * time.Minute
	defaultThrottleTick   = 30 * time.Second
	throttleFlushTimeout  = 30 * time.Second
)

type throttleBucket struct {
	start      time.Time
	sent, held int
}

type throttleSummary struct {
	from, to time.Time
	held     int
}

func (t *Throttle) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Throttle) limit() int {
	if t.Limit > 0 {
		return t.Limit
	}
	return defaultThrottleLimit
}

func (t *Throttle) window() time.Duration {
	if t.Window > 0 {
		return t.Window
	}
	return defaultThrottleWindow
}

// closeExpired (com mu): janelas terminadas passam a resumo por enviar (somado por kind).
func (t *Throttle) closeExpired(now time.Time) {
	w := t.window()
	for kind, b := range t.buckets {
		if now.Sub(b.start) < w {
			continue
		}
		if b.held > 0 {
			if t.pending == nil {
				t.pending = map[string]*throttleSummary{}
			}
			end := b.start.Add(w)
			if p := t.pending[kind]; p != nil {
				p.held += b.held
				p.to = end
			} else {
				t.pending[kind] = &throttleSummary{from: b.start, to: end, held: b.held}
			}
		}
		delete(t.buckets, kind)
	}
}

func (t *Throttle) Notify(ctx context.Context, a Alert) error {
	if t.Next == nil {
		return errors.New("alerta: Throttle sem destino")
	}
	now := t.now()
	t.mu.Lock()
	t.closeExpired(now)
	if t.buckets == nil {
		t.buckets = map[string]*throttleBucket{}
	}
	b := t.buckets[a.Kind]
	if b == nil {
		b = &throttleBucket{start: now}
		t.buckets[a.Kind] = b
	}
	if b.sent >= t.limit() {
		b.held++
		t.mu.Unlock()
		return nil
	}
	b.sent++ // reserva o lugar; libertado se o envio falhar (o chamador repete)
	t.mu.Unlock()
	if err := t.Next.Notify(ctx, a); err != nil {
		t.mu.Lock()
		if t.buckets[a.Kind] == b {
			b.sent--
		}
		t.mu.Unlock()
		return err
	}
	return nil
}

// Flush envia os resumos das janelas terminadas. Um resumo que falha fica para o Flush seguinte.
func (t *Throttle) Flush(ctx context.Context) error {
	if t.Next == nil {
		return errors.New("alerta: Throttle sem destino")
	}
	t.mu.Lock()
	t.closeExpired(t.now())
	todo := t.pending
	t.pending = nil
	t.mu.Unlock()
	var errs []error
	for kind, p := range todo {
		err := t.Next.Notify(ctx, Alert{Kind: kind, Summary: fmt.Sprintf(
			"resumo: mais %d alerta(s) deste tipo entre %s e %s (só os %d primeiros de cada %s saem um a um; "+
				"todos estão no WORM)", p.held, p.from.UTC().Format(time.RFC3339), p.to.UTC().Format(time.RFC3339),
			t.limit(), t.window())})
		if err == nil {
			continue
		}
		errs = append(errs, err)
		t.mu.Lock()
		if t.pending == nil {
			t.pending = map[string]*throttleSummary{}
		}
		if q := t.pending[kind]; q != nil {
			q.held += p.held
			if p.from.Before(q.from) {
				q.from = p.from
			}
		} else {
			t.pending[kind] = p
		}
		t.mu.Unlock()
	}
	return errors.Join(errs...)
}

// Run: Flush a cada Tick até ctx terminar; ao parar, um último Flush com prazo próprio.
func (t *Throttle) Run(ctx context.Context) {
	every := t.Tick
	if every <= 0 {
		every = defaultThrottleTick
	}
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), throttleFlushTimeout)
			t.mu.Lock()
			for _, b := range t.buckets { // fecha as janelas em curso para o resumo sair já
				b.start = b.start.Add(-t.window())
			}
			t.mu.Unlock()
			if err := t.Flush(fctx); err != nil && t.Log != nil {
				t.Log.Error("resumo de alertas agrupados", "err", err.Error())
			}
			cancel()
			return
		case <-tk.C:
			if err := t.Flush(ctx); err != nil && t.Log != nil {
				t.Log.Error("resumo de alertas agrupados", "err", err.Error())
			}
		}
	}
}

// Campos do resumo de um alerta (cartão 02/09b): ids só com forma de UUID; tipos e ação só tokens simples.
var (
	reAlertUUID  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reAlertToken = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)
)

func uuidOrDash(s *string) string {
	if s == nil || !reAlertUUID.MatchString(*s) {
		return "-"
	}
	return *s
}

func tokenOrDash(s *string) string {
	if s == nil || !reAlertToken.MatchString(*s) {
		return "-"
	}
	return *s
}
