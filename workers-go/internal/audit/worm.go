package audit

// WORM externo (spec 13 §3.4): um só bucket da plataforma com prefixo por tenant.
//   t/<tenant_id|platform>/roots/YYYY/MM/DD.json            raiz diária (manifesto do tenant)
//   t/<tenant_id|platform>/events/YYYY/MM/DD/<id>.json      alertas (superadmin e críticos)
//   t/<tenant_id|platform>/deadletter/YYYY/MM/DD/<sid>.json fila morta exportada antes do XTRIM
//
// Cliente S3 sem dependências (SigV4 com a biblioteca padrão): só PutObject e GetObject, Object Lock em
// modo GOVERNANCE com retain-until por objeto (nunca COMPLIANCE; em produção a chave da app não tem
// Delete nem bypassGovernance). Nunca sobrescreve: Get antes do Put e If-None-Match: * no Put.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // Content-MD5 é exigido pelo S3 com Object Lock; não é uso criptográfico
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// WormStore: armazenamento WORM (Object Lock). Get devolve ErrNotFound se a chave não existe;
// Put devolve ErrExists se a chave já existe (nunca sobrescreve).
type WormStore interface {
	Put(ctx context.Context, key string, body []byte, retainUntil time.Time) error
	Get(ctx context.Context, key string) ([]byte, error)
}

var (
	ErrNotFound = errors.New("worm: objeto não existe")
	ErrExists   = errors.New("worm: objeto já existe")
	// ErrMismatch: o objeto já existe com conteúdo diferente (nunca se sobrescreve).
	ErrMismatch = errors.New("worm: objeto já existe com conteúdo diferente")
)

const (
	wormTimeout    = 15 * time.Second
	wormMaxObject  = 4 << 20 // leitura máxima de um objeto (manifestos e alertas são pequenos)
	wormErrBodyMax = 4 << 10
	platformTenant = "platform"
)

// S3Worm: WormStore S3 compatível (Backblaze B2, R2, AWS S3, Versity Gateway em dev).
type S3Worm struct {
	Endpoint  string // https://s3.<região>.backblazeb2.com (http só em loopback)
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	Prefix    string       // prefixo extra das chaves (testes); vazio em produção
	HTTP      *http.Client // nil = cliente próprio com timeout
	now       func() time.Time
}

// NewS3Worm valida o endpoint (https, ou http só em loopback) e devolve o cliente.
func NewS3Worm(endpoint, region, bucket, accessKey, secretKey string) (*S3Worm, error) {
	if err := checkURL(endpoint); err != nil {
		return nil, fmt.Errorf("WORM_ENDPOINT: %w", err)
	}
	if region == "" || bucket == "" || accessKey == "" || secretKey == "" {
		return nil, errors.New("worm: região, bucket e chaves são obrigatórios")
	}
	return &S3Worm{
		Endpoint: strings.TrimRight(endpoint, "/"), Region: region, Bucket: bucket,
		AccessKey: accessKey, SecretKey: secretKey,
		HTTP: &http.Client{Timeout: wormTimeout + 5*time.Second},
	}, nil
}

// checkURL: https obrigatório; http só para 127.0.0.1/::1/localhost (dev e testes). Nunca cita o URL.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("URL inválido")
	}
	if u.User != nil {
		return errors.New("URL com credenciais não é aceite")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return errors.New("http só em loopback; usar https")
	}
	return errors.New("esquema tem de ser https")
}

func (s *S3Worm) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: wormTimeout + 5*time.Second}
}

// Put grava com Object Lock GOVERNANCE até retainUntil. 412 (If-None-Match) = ErrExists.
func (s *S3Worm) Put(ctx context.Context, key string, body []byte, retainUntil time.Time) error {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-MD5", md5b64(body))
	h.Set("If-None-Match", "*")
	h.Set("X-Amz-Object-Lock-Mode", "GOVERNANCE")
	h.Set("X-Amz-Object-Lock-Retain-Until-Date", retainUntil.UTC().Truncate(time.Second).Format(time.RFC3339))
	resp, err := s.Do(ctx, http.MethodPut, key, nil, h, body)
	if err != nil {
		return err
	}
	defer drainClose(resp)
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusPreconditionFailed || resp.StatusCode == http.StatusConflict:
		return ErrExists
	}
	return s3Err(http.MethodPut, key, resp)
}

// Get lê o objeto (até 4 MiB). 404 = ErrNotFound.
func (s *S3Worm) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := s.Do(ctx, http.MethodGet, key, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp)
	switch resp.StatusCode {
	case http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(resp.Body, wormMaxObject+1))
		if err != nil {
			return nil, fmt.Errorf("worm: leitura de %s: %w", key, err)
		}
		if len(b) > wormMaxObject {
			return nil, fmt.Errorf("worm: %s maior que %d bytes", key, wormMaxObject)
		}
		return b, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	}
	return nil, s3Err(http.MethodGet, key, resp)
}

// Do assina (SigV4) e envia um pedido ao objeto key (com o Prefix). query = sub-recursos
// (ex.: versionId, retention). O chamador fecha resp.Body.
func (s *S3Worm) Do(ctx context.Context, method, key string, query url.Values, hdr http.Header, body []byte) (*http.Response, error) {
	base, err := url.Parse(s.Endpoint)
	if err != nil {
		return nil, errors.New("worm: WORM_ENDPOINT inválido")
	}
	path := "/" + s.Bucket + "/" + s.Prefix + key
	u := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: path, RawPath: uriEncode(path, false)}
	u.RawQuery = canonicalQuery(query)

	cctx, cancel := context.WithTimeout(ctx, wormTimeout)
	req, err := http.NewRequestWithContext(cctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, errors.New("worm: pedido inválido")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.ContentLength = int64(len(body))
	s.sign(req, u, body)
	resp, err := s.client().Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("worm: %s %s: %w", method, key, errors.Unwrap(err))
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

func drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, wormErrBodyMax))
	_ = resp.Body.Close()
}

// s3Err: só o estado HTTP e o código S3 (nunca o corpo inteiro).
func s3Err(method, key string, resp *http.Response) error {
	var e struct {
		Code string `xml:"Code"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, wormErrBodyMax))
	_ = xml.Unmarshal(b, &e)
	code := e.Code
	if code == "" {
		code = "sem código"
	}
	return fmt.Errorf("worm: %s %s: HTTP %d (%s)", method, key, resp.StatusCode, code)
}

// sign: AWS Signature Version 4 (serviço s3), payload assinado (sha256 do corpo).
func (s *S3Worm) sign(req *http.Request, u *url.URL, body []byte) {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	t := now().UTC()
	amzDate := t.Format("20060102T150405Z")
	day := t.Format("20060102")
	ph := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(ph[:])
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	names := []string{"host"}
	vals := map[string]string{"host": u.Host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		names = append(names, lk)
		vals[lk] = strings.TrimSpace(strings.Join(v, ","))
	}
	slices.Sort(names)
	names = slices.Compact(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + vals[n] + "\n")
	}
	signed := strings.Join(names, ";")
	creq := strings.Join([]string{req.Method, u.EscapedPath(), u.RawQuery, ch.String(), signed, payloadHash}, "\n")
	ch2 := sha256.Sum256([]byte(creq))
	scope := day + "/" + s.Region + "/s3/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(ch2[:])
	k := hmacSHA256([]byte("AWS4"+s.SecretKey), day)
	k = hmacSHA256(k, s.Region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.AccessKey+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}

func md5b64(b []byte) string {
	sum := md5.Sum(b) //nolint:gosec // ver import
	return base64.StdEncoding.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// uriEncode: codificação SigV4 (não reservados A-Z a-z 0-9 - _ . ~; '/' mantém-se no caminho).
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var parts []string
	for _, k := range keys {
		vs := slices.Clone(q[k])
		slices.Sort(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// putOnce grava body em key se ainda não existe; se existe, compara com same (nil = bytes iguais).
// Igual = ok (idempotente); diferente = ErrMismatch (o objeto fica intacto).
func putOnce(ctx context.Context, w WormStore, key string, body []byte, retainUntil time.Time,
	same func(stored, want []byte) bool) error {
	if same == nil {
		same = bytes.Equal
	}
	check := func() error {
		got, err := w.Get(ctx, key)
		if err != nil {
			return err
		}
		if !same(got, body) {
			return fmt.Errorf("%w: %s", ErrMismatch, key)
		}
		return nil
	}
	switch err := check(); {
	case err == nil:
		return nil
	case !errors.Is(err, ErrNotFound):
		return err
	}
	err := w.Put(ctx, key, body, retainUntil)
	if errors.Is(err, ErrExists) {
		return check()
	}
	return err
}

// tenantOf: chain_key/tenant_id → segmento do prefixo (uuid zero ou vazio = platform).
func tenantOf(id string) string {
	u, ok := parseUUID(id)
	if !ok || u == ([16]byte{}) {
		return platformTenant
	}
	return formatUUID(u)
}

func formatUUID(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func rootKey(tenant string, day time.Time) string {
	return "t/" + tenant + "/roots/" + day.UTC().Format("2006/01/02") + ".json"
}

func eventKey(tenant string, at time.Time, id string) string {
	return "t/" + tenant + "/events/" + at.UTC().Format("2006/01/02") + "/" + id + ".json"
}

func deadletterKey(tenant string, at time.Time, streamID string) string {
	return "t/" + tenant + "/deadletter/" + at.UTC().Format("2006/01/02") + "/" + streamID + ".json"
}
