# 05. Migração Automática de Clientes, Onboarding e Cláusula de Saída

> Atualizada a 26/11/2026: canais, patrocínio, comissões e planos seguem a spec 14 (prevalece).

**Objetivo:** Remover o maior obstáculo psicológico e operacional tanto para Câmaras com plataformas antigas como para comerciantes sem tempo: a transferência de catálogos sem digitação manual e a garantia de que os dados nunca ficam "presos".

---

## 1. Motor de Importação Multi-Fonte (`workers-go/migration`)

```text
[Origem do Comerciante / Câmara]         [Worker de Migração (Go)]            [PT Market]
┌──────────────────────────────┐        ┌──────────────────────────┐        ┌────────────────────────┐
│ A. WooCommerce REST API      │ ─────► │ 1. Leitura Paginada      │ ─────► │ PostgreSQL (products)  │
│ B. Moloni / InvoiceX / Vendus│        │ 2. Conversão Fotos WebP  │        │ Storage Local / R2     │
│ C. Excel / CSV Qualquer      │        │ 3. Mapeamento IVA/SKU    │        │ Fila IA (Cat + ES)     │
└──────────────────────────────┘        └──────────────────────────┘        └────────────────────────┘
```

---

## 2. Os 3 Modos de Migração Assistida

### Modo A: Resgate de Marketplaces Municipais Antigos (WooCommerce / WCFM / Dokan)
Usado diretamente no argumento comercial de substituição de plataformas lentas do PRR:
1. O comerciante ou técnico da Associação insere o URL antigo + `Consumer Key` / `Consumer Secret` (apenas leitura).
2. O importador Go descarrega paginadamente produtos, variações, preços, stocks e SKUs.
3. Todas as imagens são descarregadas, convertidas para **WebP otimizado** e guardadas no teu servidor (cortando 100% a dependência do servidor antigo).
4. O sistema preserva o mapa de URLs antigos -> novos (`301 Redirects`) para não perder posicionamento no Google.

### Modo B: Importação Direta do ERP / Faturação Física (Moloni, InvoiceXpress, Vendus)
Para lojas de rua que nunca venderam online mas já têm artigos e códigos de barras no software de faturação:
1. No passo de ligação fiscal (*onboarding*), o sistema oferece: *"Encontrámos 340 artigos no seu Moloni. Deseja importá-los agora?"*.
2. Os artigos entram com preço, IVA e stock sincronizados; o comerciante só precisa de tirar foto no telemóvel aos artigos sem imagem e a IA gera as descrições e categorias.

### Modo C: Importador Universal Excel / CSV Assistido por IA
Para produtores locais e artesãos:
- O lojista sobe qualquer folha Excel/CSV sem precisar de formatar colunas. Um passo rápido de IA analisa o cabeçalho e propõe o mapeamento automático (`Designação -> title.pt`, `PVP -> price_cents`, `Qtd -> stock_qty`) para confirmação em 1 clique.

---

## 3. Período de Transição Segura (30 Dias de Sincronização Dupla)

Durante o primeiro mês após o lançamento da loja municipal, um *cron job* em Go (a correr a cada 15 minutos via `Asynq`) mantém os stocks sincronizados entre o sistema anterior do lojista (WooCommerce ou Moloni) e o `PT Market`, impedindo que uma venda na loja física ou no site antigo provoque rutura de stock online.

---

## 4. Onboarding do Lojista em 10 Minutos (Fluxo Guiado)

Para evitar telefonemas de suporte constantes, o painel do comerciante apresenta um assistente linear em 5 passos:
1. **Identificação & KYC (DSA):** NIF (validação automática de formato/VIES), morada, horários de abertura (`business_hours`).
2. **Recebimento (Split):** Botão guiado para criar/ligar subconta Eupago ou Stripe Connect + validação de IBAN.
3. **Faturação AT & IVA:** Escolher regime (Normal vs. Isento Art. 53.º) e colar chave API do Moloni/InvoiceXpress/Vendus (ou marcar "Emissão Manual" caso não tenha ERP com API).
4. **Entregas:** Ativar *Click & Collect*, Estafeta Local ou CTT/DPD.
5. **Catálogo & Canal Nacional:** Importar produtos (Modo A/B/C). A presença no `lojaportugal.pt` é **obrigatória, sem opt-out**; as restrições de entrega controlam-se por `shipping_scope` (`national` / `local_only` / `pickup_only`), não escondem a loja (ver spec 14 §1.1).

### 4.1 Fluxo de registo da loja (ver spec 14 §5–§6)
1. **Morada física** (`storefront_address`): o código postal sugere o concelho e as freguesias possíveis; o lojista **confirma a freguesia** (`storefront_dicofre`).
2. **Deteção de patrocinadores** pela freguesia confirmada: mostra `~~8%~~ 0%` com os logótipos das entidades parceiras e avisa que a isenção depende de validação e que, se cessar, se aplica a comissão padrão do plano escolhido.
3. **Escolha do plano:** `commission_payg` (por defeito) ou `tiered_subscription` (spec 14 §4).
4. **NIF e documentos por tipo** (módulo 11): empresa (`5…`) com código da Certidão Permanente; ENI (`1`, `2`, `3`) com Declaração de Atividade ou Comprovativo de Domicílio Fiscal; outros prefixos em revisão manual. Ficheiros em armazenamento privado, apagados até 30 dias após a decisão (spec 14 §6).
5. **Aceitação contratual** (`accepted_base_commission_bps`, `terms_version`, `terms_accepted_at`) gravada na mesma transação do registo e auditada.

---

## 5. Cláusula de Saída e Portabilidade de Dados (Confiança B2G)

Uma objeção frequente dos juristas das Câmaras Municipais em contratos SaaS é o receio de *vendor lock-in* ("Se terminarmos o contrato no Ano 4, perdemos os nossos dados?").
- **Solução nativa no Backoffice da Câmara:** Botão **"Exportação Integral de Dados do Município"** que gera um arquivo `.zip` com todos os catálogos (CSV/JSON), imagens dos lojistas, relatórios de vendas e histórico anonimizado. Isto desarma a objeção jurídica na hora e reforça a transparência do contrato.