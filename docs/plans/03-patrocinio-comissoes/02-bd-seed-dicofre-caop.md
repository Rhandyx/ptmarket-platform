# 02 — BD: script de seed do DICOFRE a partir de um ficheiro local (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** sonnet · **Depende de:** 01 · **Paralelo com:** — (BD em série; entra em qualquer ponto depois do 01)

## Objetivo
Um comando carrega e recarrega (idempotente) `geo_dicofre` a partir de um CSV local, regista a versão da CAOP e fecha com `valid_to` os códigos que desapareceram, sem apagar linhas.

## Pode alterar
- `infra/scripts/seed-dicofre.sh`, `infra/scripts/tests/seed-dicofre-test.sh`, `infra/scripts/tests/fixtures/dicofre_v1.csv`, `dicofre_v2.csv` (criar); `infra/README.md` (secção curta "Seed DICOFRE")

## Não tocar
- `migrations/` (o seed não é migration); `backend-rust/`, `workers-go/`. Nunca ler `.env` (a ligação vem de `DATABASE_URL` passada por quem corre, ou do contentor descartável, como no `run.sh`).

## Contexto exato (decisão técnica do supervisor)
```
Fonte: dados abertos oficiais da CAOP/DGT, versão mais recente. PASSO DO SUPERVISOR (antes de carregar dados reais, não do executor): obter o ficheiro oficial e convertê-lo para o CSV intermédio abaixo. Este cartão NÃO descarrega nada e NÃO lê o formato da DGT: só carrega o CSV intermédio e prova-se com fixtures.
Uso: infra/scripts/seed-dicofre.sh <ficheiro.csv> <caop_version> [--retire-missing]
CSV intermédio (contrato nosso; UTF-8, cabeçalho, vírgula): code,name — code com 2, 4 ou 6 caracteres (distrito, concelho, freguesia), regex igual ao CHECK da 0027: ^[0-9]{2}([0-9]{2}([0-9A-Z]{2})?)?$ (Os códigos DTMNFR da CAOP 2025 (INE) têm 18 freguesias com letras maiúsculas nos 2 últimos caracteres (ex.: 0302FA, Barcelos); distrito e concelho são só algarismos.); o pai e o level derivam-se do code.
Numa só transação, ligado como migrator (ator 'db' na caixa negra; a tabela tem L1):
  1. \copy para tabela TEMP; validar regex do code, nomes não vazios, sem duplicados, cada pai presente no ficheiro ou já na tabela. Qualquer falha → abortar tudo, com a linha na mensagem.
  2. Upsert por ordem de level: INSERT … ON CONFLICT (code) DO UPDATE SET name, caop_version, valid_to = NULL, updated_at = now() (só se algo mudar).
  3. Só com --retire-missing: valid_to = now() nos códigos em vigor que não vieram no ficheiro (mantêm a caop_version antiga). Nunca DELETE.
  4. Imprimir contagens: inseridos, atualizados, retirados; sem --retire-missing, só quantos faltam.
Segurança: o caminho do ficheiro é argumento, nunca interpolado em SQL; o script não executa nada do ficheiro. Os fixtures são dados FICTÍCIOS de teste (dizê-lo no README), não uma amostra oficial.
Carga com histórico (README): se houver uma versão anterior a 2025, carregar primeiro a antiga e depois a mais recente com --retire-missing, para os patrocínios antigos continuarem a resolver.
```

## Feito quando
- [ ] `dicofre_v1.csv` (inclui uma freguesia alfanumérica, ex.: `0302FA`) carrega numa BD descartável; correr 2 vezes dá o mesmo estado (0 inseridos e 0 atualizados na 2.ª)
- [ ] `dicofre_v2.csv` (uma freguesia a menos, uma nova, um nome mudado) com `--retire-missing`: a extinta fica com `valid_to` e a `caop_version` antiga; as outras ficam com a nova; um código retirado que volta a aparecer fica de novo com `valid_to` NULL
- [ ] CSV com código inválido, duplicado ou sem pai → sai com erro e a tabela fica igual; o README diz o contrato do CSV e o passo do supervisor

## Prova (um comando)
`infra/scripts/tests/seed-dicofre-test.sh` → esperado: `OK` em todos os casos e o contentor descartável removido no fim

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `geo_dicofre` — `migrations/tests/run.sh`
