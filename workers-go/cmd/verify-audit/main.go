// Comando verify-audit (spec 13 §3.4): recalcula as cadeias da caixa negra dia a dia, confirma o ator e
// compara com as raízes no WORM. Imprime as quebras (id, seq, problema), nunca o conteúdo dos eventos.
// Saída: 0 = íntegra; 1 = quebras (alerta crítico enviado); 2 = não foi possível verificar (alerta enviado).
//
//	verify-audit [-from YYYY-MM-DD] [-to YYYY-MM-DD] [-tenant uuid|platform[,…]]
//
// Variáveis: WORKER_DATABASE_URL, WORM_*, ALERT_* (as mesmas do worker).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/segjar/ptmarket/workers-go/internal/audit"
	"github.com/segjar/ptmarket/workers-go/internal/config"
	"github.com/segjar/ptmarket/workers-go/internal/logx"
)

const (
	exitOK     = 0
	exitBreaks = 1
	exitError  = 2
	dayLayout  = "2006-01-02"
)

func main() { os.Exit(realMain()) }

func realMain() int {
	log := logx.New()
	env, err := config.LoadEnv()
	if err != nil {
		log.Error("configuração inválida", "err", err.Error())
		return exitError
	}
	dbURL := os.Getenv("WORKER_DATABASE_URL")
	if dbURL == "" {
		log.Error("configuração inválida", "err", "WORKER_DATABASE_URL é obrigatória")
		return exitError
	}
	wcfg, err := config.LoadWorm()
	if err != nil {
		log.Error("configuração inválida", "err", err.Error())
		return exitError
	}
	acfg := config.LoadAlerts()
	if err := config.Validate(env, wcfg, acfg); err != nil {
		log.Error("configuração inválida", "err", err.Error())
		return exitError
	}
	channels, err := audit.NewChannels(audit.AlertSettings{
		TelegramBotToken: acfg.TelegramBotToken, TelegramChatID: acfg.TelegramChatID,
		DiscordWebhookURL: acfg.DiscordWebhookURL, Sink: acfg.Sink, DevLogOnly: acfg.DevLogOnly,
	}, log)
	if err != nil {
		log.Error("configuração inválida", "err", err.Error())
		return exitError
	}
	worm, err := audit.NewS3Worm(wcfg.Endpoint, wcfg.Region, wcfg.Bucket, wcfg.AccessKey, wcfg.SecretKey)
	if err != nil {
		log.Error("configuração inválida", "err", err.Error())
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Error("pool de BD", "err", err.Error())
		return exitError
	}
	defer pool.Close()
	return run(ctx, os.Args[1:], os.Stdout, deps{
		DB: pool, Worm: worm, Alert: &audit.Fanout{Channels: channels, Log: log}, Log: log,
	})
}

type deps struct {
	DB    audit.DB
	Worm  audit.WormStore
	Alert audit.Alerter
	Log   *slog.Logger
	Now   func() time.Time
}

func run(ctx context.Context, args []string, out io.Writer, d deps) int {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	today := now().UTC().Format(dayLayout)
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	fs.SetOutput(out)
	fromS := fs.String("from", "", "primeiro dia UTC (YYYY-MM-DD); omissão: 6 dias antes de -to")
	toS := fs.String("to", today, "último dia UTC (YYYY-MM-DD)")
	tenants := fs.String("tenant", "", "âmbito: uuid ou platform, separados por vírgulas (omissão: todos)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	to, err := time.Parse(dayLayout, *toS)
	if err != nil {
		fmt.Fprintln(out, "verify-audit: -to inválido")
		return exitError
	}
	from := to.AddDate(0, 0, -6)
	if *fromS != "" {
		if from, err = time.Parse(dayLayout, *fromS); err != nil {
			fmt.Fprintln(out, "verify-audit: -from inválido")
			return exitError
		}
	}
	var scope []string
	for t := range strings.SplitSeq(*tenants, ",") {
		if t = strings.TrimSpace(t); t != "" {
			scope = append(scope, t)
		}
	}

	v := &audit.Verifier{DB: d.DB, Worm: d.Worm, Tenants: scope, Now: d.Now}
	breaks, err := v.Verify(ctx, from, to)
	if err != nil {
		fmt.Fprintln(out, "verify-audit: não foi possível verificar:", err)
		notify(ctx, d, audit.Alert{Kind: audit.KindVerifyFailed, Summary: "verify-audit não correu: " + err.Error()})
		return exitError
	}
	for _, b := range breaks {
		fmt.Fprintln(out, b.String())
	}
	if len(breaks) > 0 {
		fmt.Fprintf(out, "verify-audit: %d quebra(s) entre %s e %s\n", len(breaks), from.Format(dayLayout), to.Format(dayLayout))
		notify(ctx, d, audit.VerifyAlert(breaks))
		return exitBreaks
	}
	fmt.Fprintf(out, "verify-audit: OK (%s a %s)\n", from.Format(dayLayout), to.Format(dayLayout))
	return exitOK
}

// notify: alerta crítico direto; se nem o alerta sai, fica no log (o código de saída já diz que falhou).
func notify(ctx context.Context, d deps, a audit.Alert) {
	if d.Alert == nil {
		return
	}
	if err := d.Alert.Notify(context.WithoutCancel(ctx), a); err != nil && d.Log != nil {
		d.Log.Error("alerta do verify-audit não entregue", "err", err.Error())
	}
}
