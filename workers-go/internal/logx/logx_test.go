package logx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// Cartão 02/09c: structs, []byte, json.RawMessage e error passam pelo redator; números colados a "_" ou
// letras também; um UUID fica intacto.
func TestRedactAnyValues(t *testing.T) {
	type creds struct {
		Password string
		Email    string
	}
	type tagged struct {
		Login string `json:"login"`
		Tax   string `json:"nif"`
		Ref   int64  `json:"ref"`
	}
	const uuid = "0194f0a0-0000-7000-8000-000000000001"
	var buf bytes.Buffer
	NewTo(&buf).Info("valores",
		slog.Any("creds", creds{Password: "hunter2-pw", Email: "ana@example.pt"}),
		slog.Any("ptr", &tagged{Login: "ana", Tax: "234567891", Ref: 345678912}),
		slog.Any("raw", []byte("iban PT50000201231234567890154")),
		slog.Any("rawjson", json.RawMessage(`{"nif":"123456789","outro":{"phone":"912345678"}}`)),
		slog.Any("err", errors.New("falhou para ana@example.pt")),
		slog.Any("canal", make(chan int)),
		slog.String("ids", "id_123456789 nif987654321 x_912 345 678"),
		slog.String("uuid", uuid),
	)
	line := buf.String()
	for _, leak := range []string{"hunter2-pw", "ana@example.pt", "234567891", "345678912", "PT50000201231234567890154",
		"123456789", "912345678", "987654321", "912 345 678"} {
		if strings.Contains(line, leak) {
			t.Fatalf("linha contém %q: %s", leak, line)
		}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatal(err)
	}
	if out["uuid"] != uuid {
		t.Fatalf("UUID alterado: %v", out["uuid"])
	}
	if p, _ := out["ptr"].(map[string]any); p == nil || p["login"] != "ana" {
		t.Fatalf("struct: %v", out["ptr"])
	}
	if out["canal"] != "***" {
		t.Fatalf("sem JSON → máscara: %v", out["canal"])
	}
	// Números que não são NIF/telefone ficam; colados a outro dígito também.
	for in, want := range map[string]string{
		"ref 1234567890":    "ref 1234567890",
		"pedido 12345":      "pedido 12345",
		"id_123456789":      "id_***",
		"1ab123456789":      "1***",
		"tel:912345678;":    "tel:***;",
		uuid + " 123456789": uuid + " ***",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q)=%q, esperado %q", in, got, want)
		}
	}
}

// Cartão 02/09c (auditoria): []byte dentro de struct não sai em base64 (escaparia aos regex).
func TestRedactBytesInStruct(t *testing.T) {
	const iban, nif = "PT50 0002 0123 1234 5678 9015 4", "234567891"
	type rec struct {
		Raw   []byte
		Notes [][]byte
		Ptr   *[]byte
		Map   map[string][]byte
	}
	b := []byte("nif " + nif)
	var buf bytes.Buffer
	NewTo(&buf).Info("bytes", slog.Any("rec", rec{
		Raw: []byte("conta " + iban), Notes: [][]byte{[]byte(nif)}, Ptr: &b, Map: map[string][]byte{"x": []byte(iban)},
	}))
	line := buf.String()
	for _, leak := range []string{iban, nif, "5678", base64.StdEncoding.EncodeToString([]byte("conta " + iban)),
		base64.StdEncoding.EncodeToString([]byte(nif)), base64.StdEncoding.EncodeToString([]byte(iban))} {
		if strings.Contains(line, leak) {
			t.Fatalf("linha contém %q: %s", leak, line)
		}
	}
	if !strings.Contains(line, `"Raw":"conta ***"`) {
		t.Fatalf("[]byte não passou a texto: %s", line)
	}
}

// Cartão 02/09c (auditoria): números (int, uint, float) com forma de NIF/telefone mascarados; o resto intacto.
func TestRedactNumbers(t *testing.T) {
	var buf bytes.Buffer
	NewTo(&buf).Info("números", slog.Int("x", 234567891), slog.Any("y", 912345678), slog.Uint64("u", 4111111111111111),
		slog.Float64("f", 912345678), slog.Int("count", 42), slog.Float64("ratio", 0.5))
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"x", "y", "u", "f"} {
		if out[k] != "***" {
			t.Errorf("%s=%v, esperado ***", k, out[k])
		}
	}
	if out["count"] != float64(42) || out["ratio"] != 0.5 {
		t.Errorf("números inócuos alterados: %v %v", out["count"], out["ratio"])
	}
}
