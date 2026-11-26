// Package config lê a configuração do worker apenas por variáveis de ambiente.
package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env é o ambiente de execução (APP_ENV). Obrigatório e exato: sem valor por omissão.
type Env string

const (
	EnvDevelopment Env = "development"
	EnvTest        Env = "test"
	EnvStaging     Env = "staging"
	EnvProduction  Env = "production"
)

// Strict: staging e production recusam as válvulas de dev.
func (e Env) Strict() bool { return e == EnvStaging || e == EnvProduction }

// LoadEnv lê APP_ENV (development | test | staging | production, minúsculas). Ausente ou outro valor = erro.
func LoadEnv() (Env, error) {
	switch e := Env(os.Getenv("APP_ENV")); e {
	case EnvDevelopment, EnvTest, EnvStaging, EnvProduction:
		return e, nil
	}
	return "", errors.New("APP_ENV obrigatória: development | test | staging | production")
}

// Validate recusa, em ambientes Strict, ALERT_DEV_LOG_ONLY=1 e WORM_ENDPOINT sem https://.
// As mensagens nunca incluem tokens nem URLs de alerta.
func Validate(env Env, w Worm, a Alerts) error {
	if !env.Strict() {
		return nil
	}
	if a.DevLogOnly {
		return errors.New("ALERT_DEV_LOG_ONLY não é permitido com APP_ENV=" + string(env))
	}
	if !strings.HasPrefix(w.Endpoint, "https://") {
		return errors.New("WORM_ENDPOINT tem de começar por https:// com APP_ENV=" + string(env))
	}
	return nil
}

type Config struct {
	Env          Env
	DatabaseURL  string
	RedisURL     string
	PollInterval time.Duration
	Batch        int
	AuditBatch   int // AUDIT_BATCH: mensagens por lote do stream de auditoria
	Worm         Worm
	Alerts       Alerts
}

// Worm: armazenamento WORM externo da caixa negra (S3 com Object Lock). Obrigatório: sem interruptor.
type Worm struct {
	Endpoint            string // WORM_ENDPOINT
	Region              string // WORM_REGION (us-east-1)
	Bucket              string // WORM_BUCKET
	AccessKey           string // WORM_ACCESS_KEY (segredo)
	SecretKey           string // WORM_SECRET_KEY (segredo)
	RootsRetentionDays  int    // WORM_ROOTS_RETENTION_DAYS (3650)
	EventsRetentionDays int    // WORM_EVENTS_RETENTION_DAYS (730)
}

// Alerts: canais de alerta crítico. Pelo menos um; ALERT_SINK=log:// como único canal só com
// ALERT_DEV_LOG_ONLY=1 (só dev; nunca em produção).
type Alerts struct {
	TelegramBotToken  string // ALERT_TELEGRAM_BOT_TOKEN (segredo)
	TelegramChatID    string // ALERT_TELEGRAM_CHAT_ID
	DiscordWebhookURL string // ALERT_DISCORD_WEBHOOK_URL (segredo)
	Sink              string // ALERT_SINK
	DevLogOnly        bool   // ALERT_DEV_LOG_ONLY=1
}

// LoadWorm lê WORM_*. Sem WORM_BUCKET (ou endpoint/chaves) = erro: a caixa negra não arranca sem WORM.
func LoadWorm() (Worm, error) {
	w := Worm{
		Endpoint:            os.Getenv("WORM_ENDPOINT"),
		Region:              os.Getenv("WORM_REGION"),
		Bucket:              os.Getenv("WORM_BUCKET"),
		AccessKey:           os.Getenv("WORM_ACCESS_KEY"),
		SecretKey:           os.Getenv("WORM_SECRET_KEY"),
		RootsRetentionDays:  3650,
		EventsRetentionDays: 730,
	}
	if w.Region == "" {
		w.Region = "us-east-1"
	}
	if w.Bucket == "" {
		return w, errors.New("WORM_BUCKET é obrigatória (a caixa negra não arranca sem WORM)")
	}
	if w.Endpoint == "" || w.AccessKey == "" || w.SecretKey == "" {
		return w, errors.New("WORM_ENDPOINT, WORM_ACCESS_KEY e WORM_SECRET_KEY são obrigatórias")
	}
	for name, dst := range map[string]*int{
		"WORM_ROOTS_RETENTION_DAYS":  &w.RootsRetentionDays,
		"WORM_EVENTS_RETENTION_DAYS": &w.EventsRetentionDays,
	} {
		if v := os.Getenv(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n > 36500 {
				return w, errors.New(name + " inválido (dias, 1..36500)")
			}
			*dst = n
		}
	}
	return w, nil
}

// LoadAlerts lê ALERT_*. A validação (pelo menos um canal) é de audit.NewChannels.
func LoadAlerts() Alerts {
	return Alerts{
		TelegramBotToken:  os.Getenv("ALERT_TELEGRAM_BOT_TOKEN"),
		TelegramChatID:    os.Getenv("ALERT_TELEGRAM_CHAT_ID"),
		DiscordWebhookURL: os.Getenv("ALERT_DISCORD_WEBHOOK_URL"),
		Sink:              os.Getenv("ALERT_SINK"),
		DevLogOnly:        os.Getenv("ALERT_DEV_LOG_ONLY") == "1",
	}
}

func Load() (Config, error) {
	env, err := LoadEnv()
	if err != nil {
		return Config{}, err
	}
	c := Config{
		Env:          env,
		DatabaseURL:  os.Getenv("WORKER_DATABASE_URL"),
		RedisURL:     os.Getenv("REDIS_URL"),
		PollInterval: time.Second,
		Batch:        100,
		AuditBatch:   200,
	}
	if c.DatabaseURL == "" || c.RedisURL == "" {
		return c, errors.New("WORKER_DATABASE_URL e REDIS_URL são obrigatórias")
	}
	if v := os.Getenv("OUTBOX_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return c, errors.New("OUTBOX_POLL_INTERVAL inválido")
		}
		c.PollInterval = d
	}
	if v := os.Getenv("OUTBOX_BATCH"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return c, errors.New("OUTBOX_BATCH inválido")
		}
		c.Batch = n
	}
	if v := os.Getenv("AUDIT_BATCH"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return c, errors.New("AUDIT_BATCH inválido")
		}
		c.AuditBatch = n
	}
	w, err := LoadWorm()
	if err != nil {
		return c, err
	}
	c.Worm = w
	c.Alerts = LoadAlerts()
	if err := Validate(env, c.Worm, c.Alerts); err != nil {
		return c, err
	}
	return c, nil
}
