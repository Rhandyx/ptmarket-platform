// Package logx fornece logging estruturado com redação de dados sensíveis.
//
// Os vetores partilhados com a BD e o Rust estão em docs/testdata/redaction-vectors.json (cartão 02/09b):
// mascarar a mais é aceitável; deixar passar não. A máscara de Go é "***".
package logx

import (
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"unicode"
)

const mask = "***"

// Separadores aceites dentro de IBAN/NIB/telefone: espaço(s), NBSP, '-' e '.'.
const sep = `[\s\x{00A0}.-]`

var (
	reUUID     = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	reURLCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]*:[^\s/@]+@`)
	reKV       = regexp.MustCompile(`(?i)\b(password|passwd|pass|pwd|senha|token|secret|nif|iban|nib|api[_-]?key)(["']?\s*[:=]\s*["']?)[^\s,"'&;}]+`)
	reBearer   = regexp.MustCompile(`(?i)bearer\s+\S+`)
	reJWT      = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	reAPIKey   = regexp.MustCompile(`\b(?:(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]+|(?:AKIA|ASIA)[0-9A-Z]{16})\b`)
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	// IBAN: 2 letras + 2 dígitos + grupos de 4 (qualquer caixa, com ou sem separadores).
	reIBAN = regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}(?:` + sep + `{0,3}[A-Z0-9]{4}){2,7}(?:` + sep + `{0,3}[A-Z0-9]{1,4})?\b`)
	// NIB: 21 dígitos (com ou sem separadores).
	reNIB     = regexp.MustCompile(`\b\d(?:` + sep + `{0,3}\d){20}\b`)
	rePAN     = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	rePhone   = regexp.MustCompile(`(?:\+|\b00)\d{1,3}` + sep + `{0,3}\d(?:` + sep + `{0,3}\d){6,13}\b`)
	rePhonePT = regexp.MustCompile(`\b[29]\d{2}(?:` + sep + `{0,3}\d{3}){2}\b`)
	// NIF (com prefixo de país opcional), DNI e NIE.
	reNIF = regexp.MustCompile(`\b(?:[A-Za-z]{2})?[1-9]\d{8}\b`)
	reDNI = regexp.MustCompile(`\b(?:[XYZxyz]\d{7}|\d{8})[A-Za-z]\b`)
)

// Palavras (depois de normalizar a chave) que tornam a chave sensível.
var sensitiveWords = map[string]bool{
	"password": true, "passwd": true, "pass": true, "passe": true, "pwd": true, "senha": true,
	"token": true, "secret": true, "segredo": true, "apikey": true, "authorization": true,
	"session": true, "cookie": true, "signature": true, "hmac": true, "pin": true, "jwt": true,
	"bearer": true, "chave": true, "credential": true, "credentials": true, "otp": true, "cvv": true, "cvc": true,
	"nif": true, "nipc": true, "iban": true, "nib": true, "pan": true, "cartao": true,
	"passport": true, "passaporte": true, "dni": true, "nie": true, "ssn": true,
	"mobile": true, "phone": true, "telefone": true, "telemovel": true, "email": true,
	"nome": true, "apelido": true, "nascimento": true, "contribuinte": true, "morada": true,
}

// Pares de palavras seguidas (snake_case) que tornam a chave sensível.
var sensitivePairs = map[string]bool{
	"api_key": true, "access_key": true, "secret_key": true, "private_key": true,
	"tax_id": true, "vat_id": true, "vat_number": true, "national_id": true,
	"account_number": true, "card_number": true, "card_pan": true,
	"data_nascimento": true, "palavra_passe": true, "chave_api": true,
}

// Sufixos da chave compacta (sem separadores): apanha "dbpassword", "xapikey", ….
var sensitiveSuffixes = []string{"password", "passwd", "token", "secret", "apikey", "authorization", "iban", "nif"}

// Num objeto {name: "<chave>", value: …}, se a chave nomeada é sensível, os campos de valor são mascarados.
var (
	pairNameKeys  = map[string]bool{"key": true, "k": true, "name": true, "field": true, "path": true, "attr": true, "attribute": true, "param": true, "column": true}
	pairValueKeys = map[string]bool{"value": true, "v": true, "val": true, "values": true, "new": true, "old": true, "new_value": true, "old_value": true}
)

// Redact mascara credenciais em URLs, tokens, passwords, e-mails, telefones, NIF/DNI/NIE, IBAN, NIB e PAN.
// Os UUID ficam intactos (nunca são dados pessoais e não podem ser confundidos com IBAN/PAN).
func Redact(s string) string {
	locs := reUUID.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return redactText(s)
	}
	var b strings.Builder
	last := 0
	for _, l := range locs {
		b.WriteString(redactText(s[last:l[0]]))
		b.WriteString(s[l[0]:l[1]])
		last = l[1]
	}
	b.WriteString(redactText(s[last:]))
	return b.String()
}

func redactText(s string) string {
	if s == "" {
		return s
	}
	s = reURLCreds.ReplaceAllString(s, "${1}"+mask+":"+mask+"@")
	s = reKV.ReplaceAllString(s, "${1}${2}"+mask)
	s = reBearer.ReplaceAllString(s, "Bearer "+mask)
	s = reJWT.ReplaceAllString(s, mask)
	s = reAPIKey.ReplaceAllString(s, mask)
	s = reEmail.ReplaceAllString(s, mask)
	s = reIBAN.ReplaceAllString(s, mask)
	s = reNIB.ReplaceAllString(s, mask)
	s = rePAN.ReplaceAllStringFunc(s, maskPAN)
	s = rePhone.ReplaceAllString(s, mask)
	s = rePhonePT.ReplaceAllString(s, mask)
	s = reNIF.ReplaceAllString(s, mask)
	s = reDNI.ReplaceAllString(s, mask)
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

var accents = strings.NewReplacer(
	"á", "a", "à", "a", "â", "a", "ã", "a", "ä", "a",
	"é", "e", "è", "e", "ê", "e", "ë", "e",
	"í", "i", "ì", "i", "î", "i", "ï", "i",
	"ó", "o", "ò", "o", "ô", "o", "õ", "o", "ö", "o",
	"ú", "u", "ù", "u", "û", "u", "ü", "u", "ç", "c", "ñ", "n",
)

// keyWords normaliza a chave: camelCase → snake_case, minúsculas, sem acentos; devolve as palavras.
func keyWords(k string) []string {
	var b strings.Builder
	rs := []rune(k)
	for i, r := range rs {
		if unicode.IsUpper(r) && i > 0 {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	norm := accents.Replace(b.String())
	return strings.FieldsFunc(norm, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

func isSensitiveKey(k string) bool {
	words := keyWords(k)
	for i, w := range words {
		if sensitiveWords[w] {
			return true
		}
		if i > 0 && sensitivePairs[words[i-1]+"_"+w] {
			return true
		}
	}
	compact := strings.Join(words, "")
	for _, s := range sensitiveSuffixes {
		if strings.HasSuffix(compact, s) {
			return true
		}
	}
	return false
}

// namesSensitive: o valor de um campo "nome" (key/name/field/path…) designa uma chave sensível.
func namesSensitive(v any) bool {
	s, ok := v.(string)
	return ok && len(s) <= 128 && isSensitiveKey(s)
}

// redactValue percorre mapas e listas (ex.: JSON descodificado): chaves sensíveis, pares nome/valor,
// tuplos ["nif", "…"] e texto livre.
func redactValue(v any) any {
	switch t := v.(type) {
	case string:
		return Redact(t)
	case map[string]any:
		maskValues := false
		for k, x := range t {
			if pairNameKeys[strings.ToLower(k)] && namesSensitive(x) {
				maskValues = true
			}
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			switch {
			case isSensitiveKey(k), maskValues && pairValueKeys[strings.ToLower(k)]:
				out[k] = mask
			default:
				out[k] = redactValue(x)
			}
		}
		return out
	case map[string]string:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = x
		}
		return redactValue(m)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			if i > 0 && namesSensitive(t[i-1]) {
				out[i] = mask
				continue
			}
			out[i] = redactValue(x)
		}
		return out
	case []string:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = x
		}
		return redactValue(l)
	}
	return v
}

// replaceAttr: o redator de atributos (chave sensível → máscara; texto, mapas e listas redigidos).
func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey, slog.LevelKey:
		return a
	}
	if a.Key != slog.MessageKey && isSensitiveKey(a.Key) {
		return slog.String(a.Key, mask)
	}
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(Redact(a.Value.String()))
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case map[string]any, map[string]string, []any, []string:
			a.Value = slog.AnyValue(redactValue(v))
		default:
			a.Value = slog.StringValue(Redact(a.Value.String()))
		}
	}
	return a
}

// pairHandler aplica a regra nome/valor entre atributos irmãos (ex.: "key","password","value","…"),
// que o ReplaceAttr não vê (é chamado atributo a atributo).
type pairHandler struct{ slog.Handler }

func maskPairs(attrs []slog.Attr) []slog.Attr {
	sensitive := false
	for _, a := range attrs {
		if pairNameKeys[strings.ToLower(a.Key)] && a.Value.Kind() == slog.KindString && namesSensitive(a.Value.String()) {
			sensitive = true
			break
		}
	}
	if !sensitive {
		return attrs
	}
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		if pairValueKeys[strings.ToLower(a.Key)] {
			a = slog.String(a.Key, mask)
		}
		out[i] = a
	}
	return out
}

func (h pairHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	nr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	nr.AddAttrs(maskPairs(attrs)...)
	return h.Handler.Handle(ctx, nr)
}

func (h pairHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return pairHandler{h.Handler.WithAttrs(maskPairs(attrs))}
}

func (h pairHandler) WithGroup(name string) slog.Handler {
	return pairHandler{h.Handler.WithGroup(name)}
}

func newHandler(w io.Writer) slog.Handler {
	return pairHandler{slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: replaceAttr})}
}

// New devolve um slog.Logger JSON que redige atributos e mensagens.
func New() *slog.Logger { return slog.New(newHandler(os.Stderr)) }

// NewTo: o mesmo logger a escrever em w (testes).
func NewTo(w io.Writer) *slog.Logger { return slog.New(newHandler(w)) }
