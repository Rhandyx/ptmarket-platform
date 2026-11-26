package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/segjar/ptmarket/workers-go/internal/audit"
)

// Cartão 09: verify-audit sai 0 com a cadeia íntegra e ≠ 0 quando o manifesto do WORM não bate com a BD.
// PG e WORM de dev reais; âmbito = o tenant do teste; prefixo test/<uuid>/ no bucket.

type fakeAlert struct {
	mu  sync.Mutex
	got []audit.Alert
}

func (f *fakeAlert) Notify(_ context.Context, a audit.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, a)
	return nil
}

func uuidV7() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixMilli()))
	copy(b[:6], ts[2:])
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func testWorm(t *testing.T) *audit.S3Worm {
	t.Helper()
	w, err := audit.NewS3Worm(os.Getenv("WORM_ENDPOINT"), os.Getenv("WORM_REGION"), os.Getenv("WORM_BUCKET"),
		os.Getenv("WORM_ACCESS_KEY"), os.Getenv("WORM_SECRET_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	w.Prefix = "test/" + uuidV7() + "/"
	return w
}

func TestVerifyAudit(t *testing.T) {
	dbURL := os.Getenv("WORKER_DATABASE_URL")
	if dbURL == "" || os.Getenv("WORM_BUCKET") == "" {
		t.Skip("WORKER_DATABASE_URL e WORM_* não definidas (teste com PG e WORM reais)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	tenant := uuidV7()
	for i := range 3 {
		ev, _ := json.Marshal(map[string]any{
			"id": uuidV7(), "tenant_id": tenant, "actor_type": "merchant", "actor_id": uuidV7(),
			"actor_label": "loja@teste", "action": "test.verify_audit", "target_type": "product",
			"target_id": fmt.Sprint(i), "outcome": "success", "changes": map[string]any{"segredo": "conteudo-xyz"},
			"request_id": uuidV7(), "occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
		})
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT audit.audit_append_event($1::jsonb)`, json.RawMessage(ev)).Scan(&ok); err != nil || !ok {
			t.Fatalf("audit_append_event: %v", err)
		}
	}
	w := testWorm(t)
	al := &fakeAlert{}
	today := time.Now().UTC()
	job := &audit.RootJob{DB: pool, Worm: w, Alert: al, Retention: 24 * time.Hour, Tenants: []string{tenant}}
	if err := job.Run(ctx, today); err != nil {
		t.Fatal(err)
	}
	args := []string{"-from", today.Format(dayLayout), "-to", today.Format(dayLayout), "-tenant", tenant}

	var out bytes.Buffer
	if code := run(ctx, args, &out, deps{DB: pool, Worm: w, Alert: al}); code != exitOK {
		t.Fatalf("cadeia íntegra: saída %d\n%s", code, out.String())
	}
	if len(al.got) != 0 {
		t.Fatalf("alertas com a cadeia íntegra: %+v", al.got)
	}

	// Bucket de teste com o manifesto trocado (last_hash e events diferentes).
	key := "t/" + tenant + "/roots/" + today.Format("2006/01/02") + ".json"
	b, err := w.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	var m audit.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m.Chains[0].LastHash = strings.Repeat("ab", 32)
	m.Chains[0].Events++
	forged, _ := json.Marshal(m)
	w2 := testWorm(t)
	if err := w2.Put(ctx, key, forged, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	code := run(ctx, args, &out, deps{DB: pool, Worm: w2, Alert: al})
	if code == exitOK || !strings.Contains(out.String(), "problem=manifest_mismatch") {
		t.Fatalf("manifesto trocado: saída %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "conteudo-xyz") || strings.Contains(out.String(), "loja@teste") {
		t.Fatalf("o verify imprimiu conteúdo de eventos:\n%s", out.String())
	}
	if len(al.got) != 1 || al.got[0].Kind != audit.KindVerifyFailed {
		t.Fatalf("alerta crítico do verify: %+v", al.got)
	}
}

func TestVerifyAuditBadFlags(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"-to", "ontem"}, &out, deps{}); code != exitError {
		t.Fatalf("saída %d", code)
	}
}
