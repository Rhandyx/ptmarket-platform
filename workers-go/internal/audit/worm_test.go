package audit

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Testes com o WORM de dev (Versity Gateway, bucket com Object Lock). Chaves sob test/<uuid>/ com retenção
// curta (1 dia): o WORM não deixa apagar, por isso ficam até expirar.

func testWorm(t *testing.T) *S3Worm {
	t.Helper()
	if os.Getenv("WORM_BUCKET") == "" {
		t.Skip("WORM_* não definidas (teste com o WORM de dev)")
	}
	w, err := NewS3Worm(os.Getenv("WORM_ENDPOINT"), os.Getenv("WORM_REGION"), os.Getenv("WORM_BUCKET"),
		os.Getenv("WORM_ACCESS_KEY"), os.Getenv("WORM_SECRET_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	w.Prefix = "test/" + uuidV7() + "/"
	return w
}

func TestWormPutGetOnce(t *testing.T) {
	w := testWorm(t)
	ctx := context.Background()
	retain := time.Now().Add(24 * time.Hour)
	if _, err := w.Get(ctx, "x.json"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get de chave inexistente: %v", err)
	}
	if err := w.Put(ctx, "x.json", []byte(`{"a":1}`), retain); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(ctx, "x.json", []byte(`{"a":3}`), retain); !errors.Is(err, ErrExists) {
		t.Fatalf("2.º Put na mesma chave (If-None-Match): %v", err)
	}
	got, err := w.Get(ctx, "x.json")
	if err != nil || string(got) != `{"a":1}` {
		t.Fatalf("Get: %q %v", got, err)
	}
	if err := putOnce(ctx, w, "x.json", []byte(`{"a":1}`), retain, nil); err != nil {
		t.Fatalf("putOnce igual: %v", err)
	}
	if err := putOnce(ctx, w, "x.json", []byte(`{"a":2}`), retain, nil); !errors.Is(err, ErrMismatch) {
		t.Fatalf("putOnce diferente: %v", err)
	}
	got, _ = w.Get(ctx, "x.json")
	if string(got) != `{"a":1}` {
		t.Fatalf("objeto alterado: %q", got)
	}
}

// A chave da app só faz Put/Get: sem bypass, apagar a versão e encurtar a retenção são recusados.
func TestWormCannotDeleteOrShorten(t *testing.T) {
	w := testWorm(t)
	ctx := context.Background()
	retain := time.Now().Add(24 * time.Hour)
	if err := w.Put(ctx, "lock.json", []byte(`{}`), retain); err != nil {
		t.Fatal(err)
	}
	vid := lockedVersion(t, w, "lock.json", retain)

	resp, err := w.Do(ctx, http.MethodDelete, "lock.json", url.Values{"versionId": {vid}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	drainClose(resp)
	if resp.StatusCode < 300 {
		t.Fatalf("DELETE da versão protegida foi aceite (%d)", resp.StatusCode)
	}
	body := []byte(`<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>GOVERNANCE</Mode>` +
		`<RetainUntilDate>` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `</RetainUntilDate></Retention>`)
	h := http.Header{}
	h.Set("Content-MD5", md5b64(body))
	resp, err = w.Do(ctx, http.MethodPut, "lock.json", url.Values{"retention": {""}, "versionId": {vid}}, h, body)
	if err != nil {
		t.Fatal(err)
	}
	drainClose(resp)
	if resp.StatusCode < 300 {
		t.Fatalf("encurtar a retenção foi aceite (%d)", resp.StatusCode)
	}
	if got, err := w.Get(ctx, "lock.json"); err != nil || string(got) != `{}` {
		t.Fatalf("objeto desapareceu: %q %v", got, err)
	}
}

// lockedVersion confirma GOVERNANCE + retain-until no objeto e devolve a versão.
func lockedVersion(t *testing.T, w *S3Worm, key string, retain time.Time) string {
	t.Helper()
	resp, err := w.Do(context.Background(), http.MethodHead, key, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD %s: %d", key, resp.StatusCode)
	}
	if m := resp.Header.Get("X-Amz-Object-Lock-Mode"); m != "GOVERNANCE" {
		t.Fatalf("modo de retenção = %q, esperado GOVERNANCE", m)
	}
	until, err := time.Parse(time.RFC3339, resp.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"))
	if err != nil || until.Before(retain.Add(-2*time.Second)) {
		t.Fatalf("retain-until = %q (%v)", resp.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"), err)
	}
	vid := resp.Header.Get("X-Amz-Version-Id")
	if vid == "" {
		t.Fatal("objeto sem versão (bucket sem versionamento)")
	}
	return vid
}

func TestCheckURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://s3.eu-central-003.backblazeb2.com": true,
		"http://127.0.0.1:7070":                     true,
		"http://localhost:7070":                     true,
		"http://example.com":                        false,
		"https://user:pw@example.com":               false,
		"ftp://example.com":                         false,
		"":                                          false,
	} {
		if err := checkURL(raw); (err == nil) != ok {
			t.Errorf("checkURL(%q) = %v", raw, err)
		}
	}
	if _, err := NewS3Worm("http://example.com", "r", "b", "a", "s"); err == nil || strings.Contains(err.Error(), "example.com") {
		t.Fatalf("NewS3Worm: %v", err)
	}
}

func TestTenantOfAndKeys(t *testing.T) {
	day := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	if got := rootKey(tenantOf("00000000-0000-0000-0000-000000000000"), day); got != "t/platform/roots/2026/11/25.json" {
		t.Fatal(got)
	}
	if got := tenantOf(""); got != platformTenant {
		t.Fatal(got)
	}
	if got := tenantOf("0192F0E1-0000-7000-8000-000000000001"); got != "0192f0e1-0000-7000-8000-000000000001" {
		t.Fatal(got)
	}
	if got := eventKey("x", day.Add(23*time.Hour), "id"); got != "t/x/events/2026/11/25/id.json" {
		t.Fatal(got)
	}
}
