# 05. Migração Automática de Clientes, Onboarding e Cláusula de Saída

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
5. **Catálogo & Canal Nacional:** Importar produtos (Modo A/B/C) e escolher se deseja ativar o interruptor *"Publicar também em `lojaportugal.pt` (Comissão 6,5%)"*.

---

## 5. Cláusula de Saída e Portabilidade de Dados (Confiança B2G)

Uma objeção frequente dos juristas das Câmaras Municipais em contratos SaaS é o receio de *vendor lock-in* ("Se terminarmos o contrato no Ano 4, perdemos os nossos dados?").
- **Solução nativa no Backoffice da Câmara:** Botão **"Exportação Integral de Dados do Município"** que gera um arquivo `.zip` com todos os catálogos (CSV/JSON), imagens dos lojistas, relatórios de vendas e histórico anonimizado. Isto desarma a objeção jurídica na hora e reforça a transparência do contrato.