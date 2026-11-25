# Custos recorrentes e manutenção

> Fonte única dos custos fixos da plataforma. Sempre que um cartão traz um serviço pago novo, acrescenta aqui uma linha.
> Valores em estimativa. Confirmar o preço no dia em que se abre cada conta e registar a data.

## Custos mensais

| Serviço | Para quê | Origem | Estimativa/mês | Estado |
|---|---|---|---|---|
| VPS (1, depois 2) | API, workers, Postgres, Redis | spec 08 | a preencher quando se escolher o fornecedor | por contratar |
| Backup da BD (WAL-G / pg_dump encriptado) num bucket externo (B2 ou R2) | recuperar a BD se o disco falhar | spec 08 | < 2 € | por contratar |
| Cloudflare for SaaS | domínios das Câmaras | spec 12 | 0 € até 100 hostnames; depois 0,10 $ por hostname | conta Cloudflare |
| **Amazon S3 com Object Lock (COMPLIANCE)**, numa conta AWS separada | caixa negra: raiz diária, ações de superadmin e, mais tarde, os logs do pgaudit, sem que ninguém os possa apagar | spec 13, épico 02 cartão 09 (decisão do owner, 25/11/2026) | < 1 € nos primeiros anos (ver abaixo) | por contratar antes de produção |
| Email (SMTP) para alertas | alertas de superadmin; emails aos clientes mais tarde | épico 02 cartão 09 | a definir (há planos gratuitos para volumes baixos) | por escolher |
| Telegram e Discord | alertas de superadmin | épico 02 cartão 09 | 0 € | — |

### S3 WORM: como se chega ao valor
- **Preço:** armazenamento S3 Standard ≈ 0,023 $/GB/mês; os pedidos de escrita custam cêntimos por milhar. O Object Lock não tem custo próprio: paga-se o espaço ocupado durante o período de bloqueio.
- **Volume:**
  - raiz diária: alguns KB por dia;
  - ações de superadmin: poucas por dia, alguns KB cada;
  - logs do pgaudit (quando forem enviados): talvez centenas de MB a 1 GB por ano.
- **Os dados acumulam:** com retenção de 10 anos, nada se apaga durante esse prazo. Com 1 GB/ano, ao fim de 10 anos são ~10 GB, ou seja ≈ 0,25 $/mês. Os objetos com mais de 90 dias podem passar para Glacier Instant Retrieval, que também suporta Object Lock, se o volume crescer.
- **Atenção:** em modo COMPLIANCE, o que se grava paga-se até ao fim do prazo, mesmo que se feche o projeto. Por isso, gravar só o necessário e nunca dados de teste no bucket de produção.

### S3 WORM: quem paga (decisão do owner, 25/11/2026)
- **Câmaras:** cada Câmara tem o seu próprio bucket WORM, na conta dela, e paga-o ela. A plataforma só tem permissão para escrever e ler, nunca para apagar; a prova fica do lado da Câmara (cartões 09 e 09a). Faz parte da lista de onboarding de cada Câmara, antes de entrar em produção.
- **Comércio direto** (lojistas onde a plataforma recebe comissão), eventos de plataforma, dev e demo: bucket da plataforma, com custo nosso (cêntimos por mês).
- **Retenção no nosso bucket** (default até à revisão jurídica): raízes 10 anos, porque são KB por dia e mantêm a prova da cadeia fiscal; detalhes de superadmin 2 anos. O Object Lock deixa prolongar mas nunca encurtar. As faturas em si ficam no software de faturação certificado (Moloni), que trata da sua própria retenção legal.

## Manutenção recorrente

| Tarefa | Frequência | Quem |
|---|---|---|
| Alerta de faturação na AWS (ex.: > 5 $/mês) e na Cloudflare | configurar uma vez; rever por mês | owner (contas) |
| Rodar as chaves do S3 WORM (utilizador IAM só com `PutObject`/`GetObject` naquele bucket, sem `Delete`) | a cada 90 dias | supervisor prepara, owner aplica |
| Confirmar que a raiz diária chegou ao WORM e que o `verify-audit` passa | diário (automático, com alerta se falhar) | worker (cartão 09) |
| Testar a reposição de um backup da BD | por trimestre | supervisor |
| Renovação dos domínios próprios | anual | owner |
