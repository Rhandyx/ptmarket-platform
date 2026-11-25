// Package config lê a configuração do worker apenas por variáveis de ambiente.
package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL  string
	RedisURL     string
	PollInterval time.Duration
	Batch        int
}

func Load() (Config, error) {
	c := Config{
		DatabaseURL:  os.Getenv("WORKER_DATABASE_URL"),
		RedisURL:     os.Getenv("REDIS_URL"),
		PollInterval: time.Second,
		Batch:        100,
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
	return c, nil
}
