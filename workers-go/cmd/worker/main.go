// Comando worker: publicador do outbox + servidor Asynq.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/segjar/ptmarket/workers-go/internal/config"
	"github.com/segjar/ptmarket/workers-go/internal/logx"
	"github.com/segjar/ptmarket/workers-go/internal/outbox"
)

func main() {
	log := logx.New()
	cfg, err := config.Load()
	if err != nil {
		log.Error("configuração inválida", "err", err.Error())
		os.Exit(1)
	}
	redis, err := asynq.ParseRedisURI(cfg.RedisURL)
	if err != nil {
		log.Error("REDIS_URL inválido", "err", err.Error())
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("pool de BD", "err", err.Error())
		os.Exit(1)
	}
	defer pool.Close()

	client := asynq.NewClient(redis)
	defer client.Close()

	srv := asynq.NewServer(redis, asynq.Config{Queues: map[string]int{"events": 1}})
	if err := srv.Start(asynq.NewServeMux()); err != nil {
		log.Error("servidor asynq", "err", err.Error())
		os.Exit(1)
	}

	pub := &outbox.Publisher{
		Store:    outbox.PgStore{Pool: pool},
		Enqueuer: outbox.AsynqEnqueuer{Client: client},
		Batch:    cfg.Batch,
		Log:      log,
	}
	log.Info("worker iniciado")
	pub.Run(ctx, cfg.PollInterval)
	log.Info("a parar")
	srv.Shutdown()
}
