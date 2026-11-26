# 15 — Rust: passkeys de staff com um só `rp_id` (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 14 · **Paralelo com:** — (Rust em série) · **Auditoria:** security-auditor obrigatório (ASVS L3)

## Objetivo
As passkeys de staff registam-se e usam-se só em `PLATFORM_ADMIN_HOST` (`rp_id` único); as passkeys de clientes continuam por canal, sem alteração.

## Pode alterar
- `backend-rust/src/identity/passkey.rs`; `backend-rust/tests/passkey.rs`; `src/http/openapi.rs`, `openapi.json`, `.sqlx/**` (se mudar)

## Não tocar
- `src/identity/{rbac,staff,login,session,elevate}.rs` (fechados nos cartões 13–14; `elevate.rs` só se usa); o fluxo de passkeys de clientes; `src/tenancy/`; `migrations/` (a tabela `user_passkeys` não muda).

## Contexto exato (spec 14 §8 + estado atual de `passkey.rs`)
```
Spec 14 §8: passkeys de staff: um só rp_id (admin.ptmarket.pt).
Estado atual: o rp_id é o host conhecido do pedido (tenant ou PLATFORM_ADMIN_HOST; nunca um cabeçalho cru) e origin = https://<host>. Uma passkey só serve no host onde foi registada: o rp_id fica guardado com a credencial (credential = {"v":1,"rp_id":…,"passkey":…}) e é comparado no login (passkey.rs:1125, `stored.rp_id != site.host`); passkey.rs:1156 usa staff.may_log_in_here(); a remoção só conta as passkeys do MESMO rp_id (linhas 746–750).
Passa a (só para sujeitos 'user'; clientes ficam como estão):
  Registo, login e remoção de passkeys de staff só respondem em PLATFORM_ADMIN_HOST, com rp_id = esse host e origin = https://<PLATFORM_ADMIN_HOST>.
  Num Host de canal: registo → 404; login por passkey de staff → 401 genérico + denied (a mesma resposta de credencial desconhecida; não revela que a conta é de staff).
  Passkeys de staff antigas com rp_id de um canal (dados de dev) deixam de servir: o login recusa-as com a resposta genérica e a listagem do próprio marca-as como inválidas neste painel, para as poder apagar. Não migrar nem reescrever o rp_id (uma passkey está presa ao rp_id em que nasceu).
  "Última credencial": um utilizador de staff sem password não pode apagar a sua última passkey VÁLIDA em PLATFORM_ADMIN_HOST (as de rp_id antigo não contam).
Mantêm-se: reautenticação de 10 min (REAUTH_WINDOW) para gerir passkeys, Origin exigida no passkey anónimo, throttle, verificação de utilizador (UV), os eventos de auditoria existentes e os seus nomes.
```

## Feito quando
- [ ] `passkey`: staff regista e entra por passkey no host de plataforma; a mesma tentativa num Host de canal falha como descrito, com `denied` na caixa negra
- [ ] Uma credencial de staff com `rp_id` de canal (semeada no teste) não autentica em lado nenhum, aparece marcada na listagem e pode ser apagada
- [ ] Staff só com passkeys: apagar a última válida é recusado mesmo havendo outra com `rp_id` antigo
- [ ] Os testes de passkeys de clientes passam sem mudar o que provam (registo e login por canal, `rp_id` do canal)

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test passkey` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Login, 2FA, RBAC, clientes — `cargo test -p ptmarket-api --test login --test totp --test rbac --test customers` (mesmas variáveis). Pendente conhecido, fora deste cartão: passkeys sem prova em browser real (repetir a nota no relatório).
