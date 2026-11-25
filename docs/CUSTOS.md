# Custos recorrentes e manutenção

> Fonte única dos custos fixos da plataforma. Sempre que um cartão traz um serviço pago novo, acrescenta aqui uma linha.
> Valores em estimativa. Confirmar o preço no dia em que se abre cada conta e registar a data.

## Custos mensais

| Serviço | Para quê | Origem | Estimativa/mês | Estado |
|---|---|---|---|---|
| VPS (1, depois 2) | API, workers, Postgres, Redis | spec 08 | a preencher quando se escolher o fornecedor | por contratar |
| Backup da BD (WAL-G / pg_dump encriptado) num bucket externo (B2 ou R2) | recuperar a BD se o disco falhar | spec 08 | < 2 € | por contratar |
| Cloudflare for SaaS | domínios das Câmaras | spec 12 | 0 € até 100 hostnames; depois 0,10 $ por hostname | conta Cloudflare |
| **Backblaze B2 com Object Lock (GOVERNANCE)**, um só bucket da plataforma, com prefixo por tenant | caixa negra: raiz diária e eventos críticos (o pgaudit não vai) | spec 13, épico 02 cartões 09/09a (decisão do owner, 26/11/2026) | 0 € (cabe nos 10 GB gratuitos do B2 durante anos) | por contratar antes de produção |
| Telegram e Discord | alertas imediatos de eventos críticos | épico 02 cartão 09 | 0 € | — |

### WORM: como se chega ao valor (decisão do owner, 26/11/2026)
- **Fornecedor:** Backblaze B2 (compatível com S3, Object Lock em modo GOVERNANCE, nunca COMPLIANCE). É o mesmo fornecedor previsto para os backups (spec 08), mas num bucket e com chaves separadas.
- **Preço:** ≈ 6 $/TB/mês (0,006 $/GB) e os primeiros 10 GB são gratuitos.
- **Volume:**
  - raízes diárias: alguns KB por dia, guardadas 10 anos;
  - eventos críticos e ações de superadmin: poucos por dia, guardados 2 anos;
  - o pgaudit não vai para o WORM: fica no servidor, com rotação.
- **Total:** bem abaixo de 1 GB em vários anos, ou seja 0 € dentro do plano gratuito.
- **Quem paga:** a plataforma. Não há contas de armazenamento para as Câmaras. Um bucket externo por tenant fica como opção futura, desligada por defeito.
- **GOVERNANCE vs COMPLIANCE:** em GOVERNANCE, um administrador da conta B2 com a permissão de bypass consegue apagar antes do prazo. A chave da app nunca tem essa permissão, e a chave mestra da conta B2 fica só com o owner, fora do servidor. Aceite pelo owner em troca de menos responsabilidade e menos atrito.

## Manutenção recorrente

| Tarefa | Frequência | Quem |
|---|---|---|
| Alerta de faturação no Backblaze (ex.: > 5 $/mês) e na Cloudflare | configurar uma vez; rever por mês | owner (contas) |
| Rodar a chave de aplicação do B2 WORM (só leitura e escrita naquele bucket, sem delete nem bypass de governance) | a cada 90 dias | supervisor prepara, owner aplica |
| Confirmar que a raiz diária chegou ao WORM e que o `verify-audit` passa | diário (automático, com alerta se falhar) | worker (cartão 09) |
| Testar a reposição de um backup da BD | por trimestre | supervisor |
| Renovação dos domínios próprios | anual | owner |
