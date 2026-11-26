# 25 — Go: job de eliminação dos ficheiros de `store_verifications` (`delete_after`) (épico: 03-patrocinio-comissoes)

**Agente:** go-integrations · **Modelo:** sonnet · **Depende de:** 09, 21 (formato das chaves e diretório privado), 24 (o mesmo `main.go`) · **Paralelo com:** 22–23 (Rust) e 26 (frontend)

## Objetivo
Todos os dias o worker apaga do armazenamento privado os documentos de verificação cujo prazo acabou e regista-o; o hash e os metadados ficam como prova.

## Pode alterar
- `workers-go/internal/verification/{cleanup.go,cleanup_test.go,storage.go}` (criar); `workers-go/cmd/worker/main.go`, `workers-go/internal/config/{config.go,config_test.go}`; `workers-go/.env.example` (se existir), `infra/README.md` (variável nova)

## Não tocar
- `workers-go/internal/audit/**`, `internal/outbox/**`, `internal/sponsorship/**`; `migrations/`, `backend-rust/`. Nunca ler `.env`.

## Contexto exato (spec 14 §6; RGPD art. 5.º/1/e, limitação da conservação)
```
store_verifications: o ficheiro é apagado até 30 dias depois da decisão. O hash e os metadados ficam (prova). Evento: store_verification.file_deleted.
BD (cartão 09): o worker só vê linhas com storage_key IS NOT NULL AND delete_after <= now(); colunas visíveis: id, tenant_id, store_id, storage_key, delete_after; só pode fazer UPDATE (storage_key, file_deleted_at), e só para storage_key = NULL.
Chaves (cartões 21/22): "verifications/<store_id>/<uuid>.pdf", relativas a PRIVATE_STORAGE_DIR (o mesmo diretório/volume da API, montado no worker). Só [a-z0-9/_.-], sem "..", sem barra inicial.
Interface: type PrivateDeleter interface { Delete(ctx context.Context, key string) error }. Implementação local (LocalPrivate{root}): valida a chave, resolve o caminho e confirma que fica DENTRO de root depois de resolver symlinks; ficheiro inexistente = nil (idempotente). Um backend S3 futuro implementa a mesma interface: nada preso a um fornecedor.
Em cada execução, por lotes de 100 (máximo 50 lotes), linha a linha:
  1. SELECT … FOR UPDATE SKIP LOCKED das linhas vencidas.
  2. Delete(key) no armazenamento. Se falhar: NÃO fazer UPDATE dessa linha; log + contar; seguir para a próxima.
  3. Só depois de apagar: audit.SetSystemActor(ctx, tx, "verification_file_cleanup") e UPDATE store_verifications SET storage_key = NULL, file_deleted_at = now() WHERE id = $1.
  Ordem obrigatória ficheiro → BD: se o processo morrer a meio, a linha continua com a chave e a execução seguinte repete (Delete de inexistente = nil). Nunca o contrário (ficaria um ficheiro órfão com dados pessoais e sem referência).
Evento nomeado 'store_verification.file_deleted': a mesma regra do cartão 24 (usar a função do worker para eventos nomeados, se existir; senão fica a L1 'store_verifications.update' com ator de sistema, e diz-se no relatório).
Linhas vencidas há mais de 24 h que continuam com ficheiro (falhas repetidas) → log de erro em cada execução, com a contagem. Alerta crítico dedicado: fora deste cartão (seria um kind selado novo).
Config: PRIVATE_STORAGE_DIR obrigatória em staging/production (como as outras em config.go); em development sem ela o job não é agendado e o arranque avisa. Tarefa "verification:cleanup", diária, única. Os logs nunca incluem o conteúdo nem o caminho absoluto do ficheiro.
```

## Feito quando
- [ ] `cleanup_test` (BD real + diretório temporário): linha vencida → ficheiro apagado, `storage_key` NULL, `file_deleted_at` preenchido, `sha256` e `metadata` intactos; linha por vencer e linha `pending` ficam com o ficheiro
- [ ] Falha simulada do `Delete` → a linha fica igual e é repetida na execução seguinte; ficheiro já inexistente → a linha fecha sem erro
- [ ] Chave com `..`, absoluta, ou symlink para fora de root → erro e nenhum ficheiro fora de root é tocado
- [ ] Produção sem `PRIVATE_STORAGE_DIR` → o worker recusa arrancar (`config_test`)

## Prova (um comando)
`cd workers-go && go test -race ./...` → esperado: `ok` em todos os pacotes

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Worker e job de patrocínios — o mesmo comando cobre `internal/audit`, `internal/sponsorship`, `internal/config`, `cmd/worker`
