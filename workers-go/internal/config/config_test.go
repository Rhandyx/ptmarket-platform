package config

import "testing"

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
		{"development + DEV_LOG_ONLY + http", map[string]string{"APP_ENV": "development", "ALERT_DEV_LOG_ONLY": "1", "WORM_ENDPOINT": "http://127.0.0.1:9000"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range []string{"APP_ENV", "ALERT_DEV_LOG_ONLY", "WORM_ENDPOINT", "ALERT_TELEGRAM_BOT_TOKEN", "ALERT_TELEGRAM_CHAT_ID"} {
				t.Setenv(k, "")
			}
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			env, err := LoadEnv()
			if err == nil {
				err = Validate(env, Worm{Endpoint: c.env["WORM_ENDPOINT"]}, LoadAlerts())
			}
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}
