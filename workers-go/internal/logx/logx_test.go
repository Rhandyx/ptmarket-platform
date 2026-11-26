package logx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"reflect"
	"slices"
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

// Cartão 02/09b: os vetores partilhados com a BD e o Rust (layers com "go").
type vector struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	Input          json.RawMessage `json:"input"`
	MustNotContain []string        `json:"must_not_contain"`
	MustEqualInput bool            `json:"must_equal_input"`
	Layers         []string        `json:"layers"`
}

func TestRedactionVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/testdata/redaction-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range vs {
		if !slices.Contains(v.Layers, "go") {
			continue
		}
		n++
		t.Run(v.ID, func(t *testing.T) {
			switch v.Kind {
			case "text":
				var in string
				if err := json.Unmarshal(v.Input, &in); err != nil {
					t.Fatal(err)
				}
				out := Redact(in)
				checkLeak(t, out, v.MustNotContain)
				if v.MustEqualInput && out != in {
					t.Fatalf("Redact(%q)=%q, esperado igual à entrada", in, out)
				}
			case "json":
				var in map[string]any
				if err := json.Unmarshal(v.Input, &in); err != nil {
					t.Fatal(err)
				}
				keys := slices.Sorted(maps.Keys(in))
				args := make([]any, 0, len(keys))
				for _, k := range keys {
					args = append(args, slog.Any(k, in[k]))
				}
				var buf bytes.Buffer
				NewTo(&buf).Info("vetor", args...)
				line := buf.String()
				var out map[string]any
				if err := json.Unmarshal([]byte(line), &out); err != nil {
					t.Fatalf("linha inválida %q: %v", line, err)
				}
				// A hora da linha não faz parte da verificação (pode conter dígitos de um vetor).
				if ts, ok := out[slog.TimeKey].(string); ok {
					line = strings.Replace(line, ts, "", 1)
				}
				checkLeak(t, line, v.MustNotContain)
				if v.MustEqualInput {
					for _, k := range keys {
						if !reflect.DeepEqual(out[k], in[k]) {
							t.Fatalf("%s: %v → %v (esperado igual à entrada)", k, in[k], out[k])
						}
					}
				}
			default:
				t.Fatalf("kind desconhecido %q", v.Kind)
			}
		})
	}
	if n == 0 {
		t.Fatal("nenhum vetor com layer go")
	}
}

func checkLeak(t *testing.T, out string, leaks []string) {
	t.Helper()
	for _, l := range leaks {
		if strings.Contains(out, l) {
			t.Fatalf("saída %q contém %q", out, l)
		}
	}
}
