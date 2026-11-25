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
	reBearer   = regexp.MustCompile(`(?i)bearer\s+\S+`)
	rePAN      = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	sensitive  = []string{"password", "passwd", "pass", "token", "secret", "nif", "iban", "apikey", "api_key", "authorization"}
)

// Redact mascara credenciais em URLs, tokens, passwords, NIF e IBAN.
func Redact(s string) string {
	s = reURLCreds.ReplaceAllString(s, "${1}"+mask+":"+mask+"@")
	s = reKV.ReplaceAllString(s, "${1}${2}"+mask)
	s = reBearer.ReplaceAllString(s, "Bearer "+mask)
	s = rePAN.ReplaceAllStringFunc(s, maskPAN)
	s = reIBAN.ReplaceAllString(s, mask)
	s = reNIF.ReplaceAllString(s, mask)
	return s
}

// maskPAN mascara números que passam Luhn (13-19 dígitos), deixando os 4 últimos.
func maskPAN(m string) string {
	digits := make([]int, 0, 19)
	for _, c := range m {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return m
	}
	sum := 0
	for i, alt := len(digits)-1, false; i >= 0; i-- {
		d := digits[i]
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	if sum%10 != 0 {
		return m
	}
	last := m[len(m)-4:]
	return mask + last
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
