// Comando worker: publicador do outbox + servidor Asynq + escritor do stream de auditoria + raiz diária
// em WORM + relay de alertas da caixa negra + vigia do stream. Sem WORM ou sem canal de alerta não arranca.
package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/segjar/ptmarket/workers-go/internal/audit"
	"github.com/segjar/ptmarket/workers-go/internal/config"
	"github.com/segjar/ptmarket/workers-go/internal/logx"
	"github.com/segjar/ptmarket/workers-go/internal/outbox"
)

func main() { os.Exit(run()) }

const day = 24 * time.Hour

func run() int {
	log := logx.New()
	cfg, err := config.Load()
	if err != nil {
		log.Error("configuração inválida", "err", err.Error())
		return 1
	}
	channels, err := audit.NewChannels(audit.AlertSettings{
		TelegramBotToken: cfg.Alerts.TelegramBotToken, TelegramChatID: cfg.Alerts.TelegramChatID,
		DiscordWebhookURL: cfg.Alerts.DiscordWebhookURL, Sink: cfg.Alerts.Sink,
	}, log)
	if err != nil {
		log.Error("configuração inválida", "err", err.Error())
		return 1
	}
	worm, err := audit.NewS3Worm(cfg.Worm.Endpoint, cfg.Worm.Region, cfg.Worm.Bucket, cfg.Worm.AccessKey, cfg.Worm.SecretKey)
	if err != nil {
		log.Error("configuração inválida", "err", err.Error())
		return 1
	}
	ropts, err := goredis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Error("REDIS_URL inválido") // sem err: o texto pode citar o URL (com a password)
		return 1
	}
	redis, err := asynq.ParseRedisURI(cfg.RedisURL)
	if err != nil {
		log.Error("REDIS_URL inválido") // sem err: o texto pode citar o URL (com a password)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("pool de BD", "err", err.Error())
		return 1
	}
	defer pool.Close()

	client := asynq.NewClient(redis)
	defer client.Close()

	rdb := goredis.NewClient(ropts)
	defer rdb.Close()
	alerter := &audit.Fanout{Channels: channels, Sent: audit.RedisSent{Redis: rdb}, Log: log}
	roots := &audit.RootJob{
		DB: pool, Worm: worm, Alert: alerter,
		Retention: time.Duration(cfg.Worm.RootsRetentionDays) * day, Log: log,
	}
	mux := asynq.NewServeMux()
	mux.HandleFunc(audit.RootTaskType, roots.Handle)
	srv := asynq.NewServer(redis, asynq.Config{Queues: map[string]int{"events": 1, audit.RootQueue: 1}})
	if err := srv.Start(mux); err != nil {
		log.Error("servidor asynq", "err", err.Error())
		return 1
	}

	pub := &outbox.Publisher{
		Store:    outbox.PgStore{Pool: pool},
		Enqueuer: outbox.AsynqEnqueuer{Client: client},
		Batch:    cfg.Batch,
		Log:      log,
	}
	// Sem interruptor: o escritor da caixa negra arranca sempre com o worker.
	auditor := &audit.Consumer{
		Redis: rdb,
		Store: audit.PgStore{DB: pool},
		Batch: cfg.AuditBatch,
		Name:  audit.ConsumerName(),
		Log:   log,
	}
	eventsRetention := time.Duration(cfg.Worm.EventsRetentionDays) * day
	relay := &audit.Relay{DB: pool, Worm: worm, Alert: alerter, Retention: eventsRetention, Log: log}
	watch := &audit.StreamWatch{Redis: rdb, Worm: worm, Alert: alerter, Retention: eventsRetention, Log: log}
	log.Info("worker iniciado")
	var wg sync.WaitGroup
	wg.Go(func() { auditor.Run(ctx) })
	wg.Go(func() { relay.Run(ctx) })
	wg.Go(func() { watch.Run(ctx) })
	wg.Go(func() { audit.ScheduleRoots(ctx, client, log) })
	pub.Run(ctx, cfg.PollInterval)
	log.Info("a parar")
	wg.Wait() // acaba o lote de auditoria em curso
	srv.Shutdown()
	return 0
}
