package logx

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"password=hunter2":                        "hunter2",
		"token: abc123secret":                     "abc123secret",
		"nif=123456789":                           "123456789",
		"cliente 123456789 pagou":                 "123456789",
		"iban PT50000201231234567890154":          "PT50000201231234567890154",
		"conta PT50 0002 0123 1234 5678 9015 4":   "5678",
		"dsn postgres://user:pass@db:5432/x":      "user:pass",
		"Key (nif)=(123456789)":                   "123456789",
		"postgres://u:p@h/db":                     "u:p",
		"cartao 4111 1111 1111 1111":              "4111 1111 1111",
		"cartao 4111-1111-1111-1111":              "4111-1111",
		"Authorization: Bearer abc.def":           "abc.def",
		"redis://default:s3cr3t@127.0.0.1:6379/0": "s3cr3t",
	}
	for in, leak := range cases {
		out := Redact(in)
		if strings.Contains(out, leak) {
			t.Errorf("Redact(%q)=%q ainda contém %q", in, out, leak)
		}
		if !strings.Contains(out, "***") {
			t.Errorf("Redact(%q)=%q sem máscara", in, out)
		}
	}
	if got := Redact("evento publicado"); got != "evento publicado" {
		t.Errorf("alterou texto inócuo: %q", got)
	}
	if got := Redact("ref 1234567890123456"); got != "ref 1234567890123456" {
		t.Errorf("mascarou número sem Luhn: %q", got)
	}
	if got := Redact("4111 1111 1111 1111"); !strings.HasSuffix(got, "1111") {
		t.Errorf("deve manter os 4 últimos: %q", got)
	}
}
