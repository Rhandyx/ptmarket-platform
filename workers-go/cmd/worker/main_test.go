package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/segjar/ptmarket/workers-go/internal/logx"
)

// Cartão 09: sem WORM_BUCKET ou sem canal de alerta o worker termina com erro claro (sem interruptor).
// O próprio binário de teste faz de worker (PTM_WORKER_MAIN=1); a config falha antes de ligar a PG/Redis.

func TestMain(m *testing.M) {
	if os.Getenv("PTM_WORKER_MAIN") == "1" {
		os.Exit(run())
	}
	os.Exit(m.Run())
}

func TestStartupRequiresWormAndAlerts(t *testing.T) {
	base := []string{
		"PTM_WORKER_MAIN=1", "APP_ENV=test",
		"WORKER_DATABASE_URL=postgres://u:dbsecret-xyz@127.0.0.1:1/x",
		"REDIS_URL=redis://127.0.0.1:1",
		"WORM_ENDPOINT=http://127.0.0.1:1", "WORM_BUCKET=b",
		"WORM_ACCESS_KEY=ak", "WORM_SECRET_KEY=wormsecret-xyz",
	}
	without := func(env []string, name string) []string {
		var out []string
		for _, e := range env {
			if !strings.HasPrefix(e, name+"=") {
				out = append(out, e)
			}
		}
		return out
	}
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"sem WORM_BUCKET", append(without(base, "WORM_BUCKET"), "ALERT_SINK=log://", "ALERT_DEV_LOG_ONLY=1"), "WORM_BUCKET é obrigatória"},
		{"sem canal de alerta", base, "nenhum canal de alerta"},
		{"telegram incompleto", append(base, "ALERT_TELEGRAM_BOT_TOKEN=tgsecret-xyz"), "ALERT_TELEGRAM_CHAT_ID"},
		{"WORM em http remoto", append(append(without(base, "WORM_ENDPOINT"), "WORM_ENDPOINT=http://example.com"), "ALERT_SINK=log://", "ALERT_DEV_LOG_ONLY=1"), "WORM_ENDPOINT"},
		// Cartão 02/09b: log:// como único canal não avisa ninguém → só com ALERT_DEV_LOG_ONLY=1.
		{"só log:// sem ALERT_DEV_LOG_ONLY", append(base, "ALERT_SINK=log://"), "ALERT_DEV_LOG_ONLY=1"},
		{"sem APP_ENV", without(base, "APP_ENV"), "APP_ENV obrigatória"},
		{"APP_ENV=prod", append(without(base, "APP_ENV"), "APP_ENV=prod"), "APP_ENV obrigatória"},
		{"production com ALERT_DEV_LOG_ONLY=1", append(without(base, "APP_ENV"), "APP_ENV=production", "ALERT_SINK=log://", "ALERT_DEV_LOG_ONLY=1"), "ALERT_DEV_LOG_ONLY não é permitido com APP_ENV=production"},
		{"staging com WORM em http", append(without(base, "APP_ENV"), "APP_ENV=staging", "ALERT_SINK=log://"), "WORM_ENDPOINT tem de começar por https://"},
		{"só log:// com ALERT_DEV_LOG_ONLY=0", append(base, "ALERT_SINK=log://", "ALERT_DEV_LOG_ONLY=0"), "ALERT_DEV_LOG_ONLY=1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^$")
			cmd.Env = c.env
			out, err := cmd.CombinedOutput()
			ee, ok := err.(*exec.ExitError)
			if !ok || ee.ExitCode() != 1 {
				t.Fatalf("esperado exit 1, veio %v\n%s", err, out)
			}
			s := string(out)
			if !strings.Contains(s, c.want) {
				t.Fatalf("erro pouco claro (falta %q):\n%s", c.want, s)
			}
			if strings.Contains(s, "secret-xyz") {
				t.Fatalf("segredo no log:\n%s", s)
			}
		})
	}
}

// Cartão 02/09b: arranque (validação completa antes de ligar a PG/Redis) com log:// só em dev e com
// Discord + log:// sem a variável.
func TestStartupAlertChannels(t *testing.T) {
	env := map[string]string{
		"APP_ENV": "test",
		"WORKER_DATABASE_URL": "postgres://u:p@127.0.0.1:1/x", "REDIS_URL": "redis://127.0.0.1:1",
		"WORM_ENDPOINT": "http://127.0.0.1:1", "WORM_REGION": "", "WORM_BUCKET": "b",
		"WORM_ACCESS_KEY": "ak", "WORM_SECRET_KEY": "sk",
		"WORM_ROOTS_RETENTION_DAYS": "", "WORM_EVENTS_RETENTION_DAYS": "",
		"OUTBOX_POLL_INTERVAL": "", "OUTBOX_BATCH": "", "AUDIT_BATCH": "",
		"ALERT_TELEGRAM_BOT_TOKEN": "", "ALERT_TELEGRAM_CHAT_ID": "", "ALERT_DISCORD_WEBHOOK_URL": "",
		"ALERT_SINK": "", "ALERT_DEV_LOG_ONLY": "",
	}
	cases := []struct {
		name     string
		set      map[string]string
		channels int
		warn     bool
	}{
		{"só log:// com ALERT_DEV_LOG_ONLY=1", map[string]string{"ALERT_SINK": "log://", "ALERT_DEV_LOG_ONLY": "1"}, 1, true},
		{"Discord + log:// sem a variável", map[string]string{"ALERT_SINK": "log://",
			"ALERT_DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1/x"}, 2, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			for k, v := range c.set {
				t.Setenv(k, v)
			}
			var buf bytes.Buffer
			st, err := prepare(logx.NewTo(&buf))
			if err != nil {
				t.Fatalf("não arrancou: %v", err)
			}
			if len(st.channels) != c.channels {
				t.Fatalf("%d canais, esperado %d", len(st.channels), c.channels)
			}
			warned := strings.Contains(buf.String(), "ALERT_DEV_LOG_ONLY=1") && strings.Contains(buf.String(), `"level":"WARN"`)
			if warned != c.warn {
				t.Fatalf("aviso de modo só-log: %v, esperado %v\n%s", warned, c.warn, buf.String())
			}
		})
	}
}
