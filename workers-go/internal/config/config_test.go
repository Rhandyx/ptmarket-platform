package config

import (
	"strconv"
	"testing"
)

func TestEnvValidation(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{"sem APP_ENV", map[string]string{}, true},
		{"APP_ENV=prod", map[string]string{"APP_ENV": "prod"}, true},
		{"APP_ENV=Production", map[string]string{"APP_ENV": "Production"}, true},
		{"production + DEV_LOG_ONLY", map[string]string{"APP_ENV": "production", "ALERT_DEV_LOG_ONLY": "1", "WORM_ENDPOINT": "https://s3.example.com"}, true},
		{"staging + http", map[string]string{"APP_ENV": "staging", "WORM_ENDPOINT": "http://s3.example.com"}, true},
		{"production + https + telegram", map[string]string{"APP_ENV": "production", "WORM_ENDPOINT": "https://s3.example.com", "ALERT_TELEGRAM_BOT_TOKEN": "t", "ALERT_TELEGRAM_CHAT_ID": "1"}, false},
		{"production + eventos 729 dias", map[string]string{"APP_ENV": "production", "WORM_ENDPOINT": "https://s3.example.com", "WORM_EVENTS_RETENTION_DAYS": "729"}, true},
		{"staging + raízes 3649 dias", map[string]string{"APP_ENV": "staging", "WORM_ENDPOINT": "https://s3.example.com", "WORM_ROOTS_RETENTION_DAYS": "3649"}, true},
		{"production + retenções mínimas", map[string]string{"APP_ENV": "production", "WORM_ENDPOINT": "https://s3.example.com", "WORM_EVENTS_RETENTION_DAYS": "730", "WORM_ROOTS_RETENTION_DAYS": "3650"}, false},
		{"development + retenções curtas", map[string]string{"APP_ENV": "development", "WORM_EVENTS_RETENTION_DAYS": "1", "WORM_ROOTS_RETENTION_DAYS": "1"}, false},
		{"development + DEV_LOG_ONLY + http", map[string]string{"APP_ENV": "development", "ALERT_DEV_LOG_ONLY": "1", "WORM_ENDPOINT": "http://127.0.0.1:9000"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range []string{"APP_ENV", "ALERT_DEV_LOG_ONLY", "WORM_ENDPOINT", "ALERT_TELEGRAM_BOT_TOKEN", "ALERT_TELEGRAM_CHAT_ID", "WORM_EVENTS_RETENTION_DAYS", "WORM_ROOTS_RETENTION_DAYS"} {
				t.Setenv(k, "")
			}
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			env, err := LoadEnv()
			if err == nil {
				w := Worm{Endpoint: c.env["WORM_ENDPOINT"], EventsRetentionDays: 730, RootsRetentionDays: 3650}
				if v, ok := c.env["WORM_EVENTS_RETENTION_DAYS"]; ok {
					w.EventsRetentionDays, _ = strconv.Atoi(v)
				}
				if v, ok := c.env["WORM_ROOTS_RETENTION_DAYS"]; ok {
					w.RootsRetentionDays, _ = strconv.Atoi(v)
				}
				err = Validate(env, w, LoadAlerts())
			}
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}
