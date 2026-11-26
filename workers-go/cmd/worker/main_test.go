package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
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
		"PTM_WORKER_MAIN=1",
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
		{"sem WORM_BUCKET", append(without(base, "WORM_BUCKET"), "ALERT_SINK=log://"), "WORM_BUCKET é obrigatória"},
		{"sem canal de alerta", base, "nenhum canal de alerta"},
		{"telegram incompleto", append(base, "ALERT_TELEGRAM_BOT_TOKEN=tgsecret-xyz"), "ALERT_TELEGRAM_CHAT_ID"},
		{"WORM em http remoto", append(append(without(base, "WORM_ENDPOINT"), "WORM_ENDPOINT=http://example.com"), "ALERT_SINK=log://"), "WORM_ENDPOINT"},
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
