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
	"strconv"
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
	discordMax     = 2000 // limite do campo content do webhook
	sentTTL        = 30 * 24 * time.Hour
	telegramAPI    = "https://api.telegram.org"
	sentKeyPrefix  = "audit:alert:sent:"
	alertBodyLimit = 64 << 10
)

// Alert: Summary sem dados pessoais; EventID = id do evento (vazio nos alertas internos e nos resumos);
// TenantID = tenant do evento (só com forma de UUID; senão "-"), chave do agrupamento com o Kind.
type Alert struct {
	Kind     string
	Summary  string
	EventID  string
	TenantID string
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

// Throttle agrupa rajadas (cartões 02/09b e 02/09c: o onboarding em massa gera um iban_change por loja).
// Chave do agrupamento = (kind, tenant): numa janela de Window a contar do 1.º alerta dessa chave, só os
// Limit primeiros saem um a um; os seguintes não são enviados e, depois do fim da janela, sai um único
// resumo com a contagem e os event_id retidos. Nunca agrupados (saem sempre um a um): kinds "audit.*"
// (alertas da própria caixa negra), os críticos da BD em neverThrottle e qualquer alerta sem tenant ("-").
// Não toca no WORM (o relay grava cada alerta antes de chamar Notify).
//
// Relógio único (cartão 02/09c): a hora é sempre a do Redis (redis.call('TIME') dentro dos scripts), tanto
// na abertura/fecho das janelas como no corte do Flush; o relógio das réplicas nunca entra.
//
// Estado no Redis (partilhado pelas réplicas e sobrevive a um crash), chaves com Prefix (por omissão
// "audit:alert:{throttle}:"; a hash tag põe tudo no mesmo slot):
//
//	cur:<kind>|<tenant>              início da janela em curso (ms), TTL janela + margem
//	w:<kind>|<tenant>|<início>       hash: sent (lugares um a um), noid/more (retidos sem id/acima do teto)
//	w:<kind>|<tenant>|<início>:ids   zset dos event_id retidos (score = hora; sem repetidos), TTL idem
//	pending                          zset "<kind>|<tenant>|<início>" → fim da janela (ms): resumos por enviar
//	claim:<kind>|<tenant>|<início>   SET NX PX: a réplica que envia o resumo (apagado no fim, com ou sem êxito)
//
// Flush (a cada Tick e no arranque de Run) envia os resumos das janelas fechadas (fim <= TIME do Redis);
// êxito → apaga a janela e o membro de pending; falha → só liberta o claim (sai no Flush seguinte). Redis
// em baixo → fail-open: o alerta sai um a um e fica um log Warn (nunca se perde um alerta por causa do
// agrupamento).
type Throttle struct {
	Next   Alerter
	Redis  redis.UniversalClient // nil = sem agrupamento (tudo um a um)
	Prefix string                // testes; vazio = audit:alert:{throttle}:
	Limit  int                   // 0 = 5
	Window time.Duration         // 0 = 5 min
	Tick   time.Duration         // 0 = 30 s (frequência do Flush em Run)
	Log    *slog.Logger
}

const (
	defaultThrottleLimit  = 5
	defaultThrottleWindow = 5 * time.Minute
	defaultThrottleTick   = 30 * time.Second
	throttleFlushTimeout  = 30 * time.Second
	throttlePrefix        = "audit:alert:{throttle}:"
	throttleMargin        = 7 * 24 * time.Hour // a janela fica no Redis até ao resumo sair (canais em baixo)
	throttleClaimTTL      = 2 * time.Minute    // > tempo de um Notify (Fanout: 5 s por canal)
	throttleRedisTimeout  = 2 * time.Second    // Redis lento → fail-open depressa
	throttleMaxIDs        = 1000               // teto do zset de ids por janela (o resto só conta)
	throttleShowIDs       = 20
	throttleFlushBatch    = 100
	auditKindPrefix       = "audit."
)

// neverThrottle: críticos da BD (audit.critical_kind, migration 0015) que saem sempre um a um.
var neverThrottle = map[string]bool{"verify_failure": true, "superadmin_login": true}

// redisNowLua: agora em ms segundo o Redis (texto inteiro, sem notação científica).
const redisNowLua = `local tm = redis.call('TIME')
local now = tonumber(tm[1]) * 1000 + math.floor(tonumber(tm[2]) / 1000)
`

// throttleHit (atómico): fecha a janela vencida e abre outra; reserva um lugar um a um (1) ou retém (0).
// KEYS[1] = cur, KEYS[2] = pending. ARGV: janela ms, limite, TTL ms, event_id, prefixo da janela,
// prefixo do membro (a hora vem do TIME do Redis, nunca de um argumento). As chaves da janela dependem do
// início (lido aqui) e partilham a hash tag.
var throttleHitSrc = redisNowLua + `
local w = tonumber(ARGV[1])
local s = redis.call('GET', KEYS[1])
if (not s) or (now - tonumber(s) >= w) then
  s = string.format('%.0f', now)
  redis.call('SET', KEYS[1], s, 'PX', ARGV[3])
end
local win = ARGV[5] .. s
local ids = win .. ':ids'
local sent = tonumber(redis.call('HGET', win, 'sent') or '0')
if sent < tonumber(ARGV[2]) then
  redis.call('HINCRBY', win, 'sent', 1)
  redis.call('PEXPIRE', win, ARGV[3])
  return {1, s}
end
if ARGV[4] == '' then
  redis.call('HINCRBY', win, 'noid', 1)
elseif redis.call('ZSCORE', ids, ARGV[4]) == false then
  if redis.call('ZCARD', ids) < ` + fmt.Sprint(throttleMaxIDs) + ` then
    redis.call('ZADD', ids, now, ARGV[4])
    redis.call('PEXPIRE', ids, ARGV[3])
  else
    redis.call('HINCRBY', win, 'more', 1)
  end
end
redis.call('PEXPIRE', win, ARGV[3])
redis.call('ZADD', KEYS[2], string.format('%.0f', tonumber(s) + w), ARGV[6] .. s)
return {0, s}
`

var throttleHit = redis.NewScript(throttleHitSrc)

// throttleClosed: membros de pending com fim <= TIME do Redis. KEYS[1] = pending; ARGV[1] = máximo.
var throttleClosedSrc = redisNowLua + `
return redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', string.format('%.0f', now), 'LIMIT', 0, tonumber(ARGV[1]))
`

var throttleClosed = redis.NewScript(throttleClosedSrc)

// throttleRelease: um envio falhado devolve o lugar (só se a janela ainda existe).
var throttleRelease = redis.NewScript(`
local n = tonumber(redis.call('HGET', KEYS[1], 'sent') or '0')
if n > 0 then redis.call('HINCRBY', KEYS[1], 'sent', -1) end
return n
`)

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

func (t *Throttle) key(parts ...string) string {
	return or(t.Prefix, throttlePrefix) + strings.Join(parts, "")
}

func (t *Throttle) warn(msg string, args ...any) {
	if t.Log != nil {
		t.Log.Warn(msg, args...)
	}
}

// throttleTenant: só UUIDs (minúsculas); o resto "-".
func throttleTenant(s string) string {
	s = strings.ToLower(s)
	if !reAlertUUID.MatchString(s) {
		return "-"
	}
	return s
}

func (t *Throttle) Notify(ctx context.Context, a Alert) error {
	if t.Next == nil {
		return errors.New("alerta: Throttle sem destino")
	}
	a.TenantID = throttleTenant(a.TenantID)
	// Alertas da caixa negra, críticos da BD, alertas sem tenant e kinds fora do formato (não cabem numa
	// chave) saem sempre um a um.
	if t.Redis == nil || strings.HasPrefix(a.Kind, auditKindPrefix) || neverThrottle[a.Kind] ||
		a.TenantID == "-" || !reAlertToken.MatchString(a.Kind) {
		return t.Next.Notify(ctx, a)
	}
	id := a.EventID
	if !reAlertUUID.MatchString(id) {
		id = ""
	}
	group := a.Kind + "|" + a.TenantID
	rctx, cancel := context.WithTimeout(ctx, throttleRedisTimeout)
	res, err := throttleHit.Run(rctx, t.Redis, []string{t.key("cur:", group), t.key("pending")},
		t.window().Milliseconds(), t.limit(), (t.window() + throttleMargin).Milliseconds(),
		id, t.key("w:", group, "|"), group+"|").Result()
	cancel()
	if err != nil {
		t.warn("agrupamento de alertas indisponível (Redis): o alerta sai um a um", "kind", a.Kind)
		return t.Next.Notify(ctx, a)
	}
	send, start, ok := parseHit(res)
	if !ok {
		t.warn("agrupamento de alertas: resposta inesperada do Redis; o alerta sai um a um", "kind", a.Kind)
		return t.Next.Notify(ctx, a)
	}
	if !send {
		return nil // retido: entra no resumo da janela
	}
	if err := t.Next.Notify(ctx, a); err != nil {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), throttleRedisTimeout)
		if rerr := throttleRelease.Run(rctx, t.Redis, []string{t.key("w:", group, "|", start)}).Err(); rerr != nil {
			t.warn("agrupamento de alertas: lugar não devolvido (Redis)", "kind", a.Kind)
		}
		cancel()
		return err
	}
	return nil
}

// parseHit: {1|0, "<início ms>"}; qualquer outra forma → ok=false (o chamador envia um a um).
func parseHit(res any) (send bool, start string, ok bool) {
	l, isList := res.([]any)
	if !isList || len(l) != 2 {
		return false, "", false
	}
	n, isInt := l[0].(int64)
	s, isStr := l[1].(string)
	if !isInt || (n != 0 && n != 1) || !isStr || s == "" || len(s) > 20 {
		return false, "", false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false, "", false
		}
	}
	return n == 1, s, true
}

// Flush envia os resumos das janelas fechadas (de qualquer réplica, incluindo as que terminaram sem
// Flush). Um resumo que falha fica para o Flush seguinte.
func (t *Throttle) Flush(ctx context.Context) error {
	if t.Next == nil {
		return errors.New("alerta: Throttle sem destino")
	}
	if t.Redis == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, throttleRedisTimeout)
	members, err := throttleClosed.Run(rctx, t.Redis, []string{t.key("pending")}, throttleFlushBatch).StringSlice()
	cancel()
	if err != nil {
		return errors.New("resumos de alertas: Redis indisponível")
	}
	var errs []error
	for _, m := range members {
		if err := t.flushOne(ctx, m); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// flushOne: claim (SET NX PX) → lê a janela → Notify → apaga (êxito) ou só liberta o claim (falha).
func (t *Throttle) flushOne(ctx context.Context, member string) error {
	parts := strings.Split(member, "|")
	if len(parts) != 3 {
		return t.dropPending(ctx, member, "membro inválido")
	}
	kind, tenant := parts[0], parts[1]
	ms, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return t.dropPending(ctx, member, "início inválido")
	}
	from := time.UnixMilli(ms)
	claim := t.key("claim:", member)
	rctx, cancel := context.WithTimeout(ctx, throttleRedisTimeout)
	defer cancel()
	ok, err := t.Redis.SetNX(rctx, claim, "1", throttleClaimTTL).Result()
	if err != nil {
		return errors.New("resumo de alertas: Redis indisponível")
	}
	if !ok {
		return nil // outra réplica está a enviá-lo
	}
	win := t.key("w:", member)
	ids := win + ":ids"
	var (
		inPending *redis.FloatCmd
		extra     *redis.SliceCmd
		total     *redis.IntCmd
		first     *redis.StringSliceCmd
	)
	_, err = t.Redis.Pipelined(rctx, func(p redis.Pipeliner) error {
		inPending = p.ZScore(rctx, t.key("pending"), member)
		extra = p.HMGet(rctx, win, "noid", "more")
		total = p.ZCard(rctx, ids)
		first = p.ZRange(rctx, ids, 0, throttleShowIDs-1)
		return nil
	})
	if err != nil && !errors.Is(err, redis.Nil) {
		t.release(ctx, claim)
		return errors.New("resumo de alertas: Redis indisponível")
	}
	if inPending.Err() != nil { // já enviado por outra réplica entre a listagem e o claim
		t.release(ctx, claim)
		return nil
	}
	held := total.Val()
	for _, v := range extra.Val() {
		if s, ok := v.(string); ok {
			n, _ := strconv.ParseInt(s, 10, 64)
			held += n
		}
	}
	if held <= 0 {
		t.release(ctx, claim)
		return t.dropPending(ctx, member, "janela expirada antes do resumo (os eventos estão no WORM)")
	}
	err = t.Next.Notify(ctx, Alert{Kind: kind, TenantID: tenant, Summary: t.summary(kind, tenant, from, held, first.Val())})
	dctx, dcancel := context.WithTimeout(context.WithoutCancel(ctx), throttleRedisTimeout)
	defer dcancel()
	if err != nil {
		t.release(dctx, claim)
		return err
	}
	if _, derr := t.Redis.TxPipelined(dctx, func(p redis.Pipeliner) error {
		p.ZRem(dctx, t.key("pending"), member)
		p.Del(dctx, win, ids, claim)
		return nil
	}); derr != nil {
		t.warn("resumo de alertas enviado mas não apagado (pode repetir)", "kind", kind)
	}
	return nil
}

func (t *Throttle) release(ctx context.Context, claim string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), throttleRedisTimeout)
	defer cancel()
	if err := t.Redis.Del(rctx, claim).Err(); err != nil {
		t.warn("resumo de alertas: claim não libertado (expira sozinho)")
	}
}

func (t *Throttle) dropPending(ctx context.Context, member, why string) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), throttleRedisTimeout)
	defer cancel()
	if t.Log != nil {
		t.Log.Error("resumo de alertas descartado", "reason", why)
	}
	if err := t.Redis.ZRem(rctx, t.key("pending"), member).Err(); err != nil {
		return errors.New("resumo de alertas: Redis indisponível")
	}
	return nil
}

// summary: contagem, kind, tenant, janela e os event_id retidos (só UUIDs; até 20, depois "+N").
func (t *Throttle) summary(kind, tenant string, from time.Time, held int64, ids []string) string {
	shown := make([]string, 0, len(ids))
	for _, id := range ids {
		if reAlertUUID.MatchString(id) {
			shown = append(shown, id)
		}
	}
	list := strings.Join(shown, ", ")
	if rest := held - int64(len(shown)); rest > 0 {
		if list != "" {
			list += " "
		}
		list += fmt.Sprintf("+%d", rest)
	}
	return fmt.Sprintf("resumo: mais %d alerta(s) %s do tenant %s entre %s e %s (só os %d primeiros de cada %s "+
		"por tipo e tenant saem um a um; todos estão no WORM) · retidos: %s", held, kind, tenant,
		from.UTC().Format(time.RFC3339), from.Add(t.window()).UTC().Format(time.RFC3339), t.limit(), t.window(), list)
}

// Run: Flush no arranque (resumos de janelas fechadas por enviar, ex.: depois de um crash) e a cada Tick
// até ctx terminar; ao parar, um último Flush com prazo próprio (as janelas em curso ficam no Redis e o
// resumo sai pela réplica seguinte que fizer Flush).
func (t *Throttle) Run(ctx context.Context) {
	every := t.Tick
	if every <= 0 {
		every = defaultThrottleTick
	}
	flush := func(c context.Context) {
		if err := t.Flush(c); err != nil && t.Log != nil {
			t.Log.Error("resumo de alertas agrupados", "err", err.Error())
		}
	}
	flush(ctx)
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), throttleFlushTimeout)
			flush(fctx)
			cancel()
			return
		case <-tk.C:
			flush(ctx)
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
