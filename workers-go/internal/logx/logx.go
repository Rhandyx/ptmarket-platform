// Package logx fornece logging estruturado com redação de dados sensíveis.
package logx

import (
	"log/slog"
	"os"
	"regexp"
	"strings"
)

const mask = "***"

var (
	reURLCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]*:[^\s/@]+@`)
	reKV       = regexp.MustCompile(`(?i)\b(password|passwd|pass|token|secret|nif|iban|api[_-]?key)(["']?\s*[:=]\s*["']?)[^\s,"'&;}]+`)
	reIBAN     = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?\b`)
	reNIF      = regexp.MustCompile(`\b[1-9]\d{8}\b`)
	sensitive  = []string{"password", "passwd", "pass", "token", "secret", "nif", "iban", "apikey", "api_key", "authorization"}
)

// Redact mascara credenciais em URLs, tokens, passwords, NIF e IBAN.
func Redact(s string) string {
	s = reURLCreds.ReplaceAllString(s, "${1}"+mask+":"+mask+"@")
	s = reKV.ReplaceAllString(s, "${1}${2}"+mask)
	s = reIBAN.ReplaceAllString(s, mask)
	s = reNIF.ReplaceAllString(s, mask)
	return s
}

func isSensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range sensitive {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// New devolve um slog.Logger JSON que redige atributos e mensagens.
func New() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey, slog.LevelKey:
				return a
			}
			if a.Key != slog.MessageKey && isSensitiveKey(a.Key) {
				return slog.String(a.Key, mask)
			}
			if a.Value.Kind() == slog.KindString || a.Value.Kind() == slog.KindAny {
				a.Value = slog.StringValue(Redact(a.Value.String()))
			}
			return a
		},
	}))
}
