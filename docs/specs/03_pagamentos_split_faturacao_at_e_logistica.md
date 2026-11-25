# 03. Pagamentos Split (Eupago & Stripe), Faturação AT, IVA e Logística

**Regra de Ouro Financeira:** A **Segjar Soluções, Lda** nunca detém custódia do dinheiro dos comerciantes (evitando enquadramento como Instituição de Pagamento junto do Banco de Portugal) e nunca absorve taxas variáveis de gateways nem subscrições de faturação de terceiros.

---

## 1. Quem Paga Cada Taxa e Serviço (Matriz de Custos Variáveis)

| Custo / Serviço | Quem Suporta? | Como Funciona na Prática |
| :--- | :--- | :--- |
| **Taxas Eupago (MB WAY / Multibanco) ou Stripe Connect** | **O Lojista** (deduzido automaticamente no *split*). | O gateway desconta a taxa transacional da parcela do comerciante antes de liquidar o valor líquido no IBAN da loja. Custo **0€** para a Segjar. |
| **Comissão da Plataforma (`commission_bps`)** | **0% nas Câmaras** / **5% a 8% no Portal Nacional**. | Calculada dinamicamente no Rust: `COALESCE(store.custom_commission_bps, tenant.default_commission_bps)`. O mesmo produto paga **0%** no site da Câmara e **6,5%** se vendido em `lojaportugal.pt`. |
| **Software de Faturação AT (Moloni, InvoiceXpress, Vendus)** | **O Lojista** (*BYOK — Bring Your Own Key*). | O lojista já paga o seu programa de faturação na loja física (API incluída). Só insere a chave API no painel. Custo **0€** para a Segjar. |
| **Portes e Guias de Transporte (CTT, DPD, Sendcloud)** | **Comprador** (no checkout) ou **Lojista**. | A etiqueta é gerada via API usando o contrato do próprio lojista ou conta agregadora. |
| **Emails Transacionais (AWS SES / Resend)** | **Segjar Soluções** (coberto pela avença anual). | Custo residual (~5€/mês para 50.000 emails de encomendas e faturas PDF). |

---

## 2. Arquitetura de Pagamentos Split (Eupago + Stripe Connect)

### 2.1 Fluxo de um Checkout Multi-Loja (1 Pagamento, Vários IBANs)

```text
[Cliente] paga 90,00 € via MB WAY (Carrinho com 2 lojas: Padaria = 30€ | Sapataria = 60€)
                                       │
                                       ▼
                [Gateway Split: Eupago Split / Stripe Connect]
                       │                                   │
        ┌──────────────┴──────────────┐     ┌──────────────┴──────────────┐
        ▼                             ▼     ▼                             ▼
[Padaria: 30,00 €]            [Segjar Soluções]           [Sapataria: 60,00 €]
 • Canal Câmara: 0% comissão   • Canal Câmara: 0,00 €      • Canal Câmara: 0% comissão
 • Canal Nacional: -6,5%       • Canal Nacional: +5,85 €   • Canal Nacional: -6,5%
        │                                                           │
        ▼                                                           ▼
[IBAN da Padaria]                                           [IBAN da Sapataria]
```

### 2.2 Guião de Negociação com a Eupago (Conta Segjar Soluções)
Como a empresa já possui conta Eupago, a abordagem ao gestor comercial deve solicitar migração para o **Tier Marketplace / Split Payments**, validando 4 pontos:
1. **Tabela de Volume Agregado:** Negociar redução nas taxas fixas e percentuais de MB WAY e Multibanco (crucial porque no comércio tradicional os carrinhos médios rondam 15€ a 45€).
2. **Onboarding / KYC de Subcontas via API:** Confirmar como automatizar o registo de cada beneficiário (NIF, IBAN, certidão permanente) para evitar gestão manual por email.
3. **Suporte Explícito a Comissão `0.00€`:** Confirmar na documentação da API que o parâmetro de comissão da plataforma aceita zero absoluto nos *tenants* municipais.
4. **Prazo de Liquidação (D+N):** Negociar liquidação direta ao IBAN do lojista (ex: D+2 ou D+5 para proteção contra chargebacks ou anulações imediatas).

### 2.3 Estratégia Dual-Gateway (Portugal + Espanha)
No backend Rust, o pagamento usa uma interface abstrata (`PaymentProvider`):
- **Eupago Split:** Método preferencial em Portugal para **MB WAY** e **Referência Multibanco**.
- **Stripe Connect (Standard/Express):** Método preferencial para **Cartões Visa/Mastercard, Apple Pay, Google Pay** e expansão para **Espanha** (onde não existe MB WAY, dominando Cartão e Bizum).

---

## 3. Regras Fiscais Ibéricas (IVA PT/ES, Art. 53.º e B2B VIES)

O motor financeiro em Rust (`backend-rust/src/domain/tax.rs`) resolve todas as regras fiscais automaticamente:

1. **Isenção Artigo 53.º do CIVA (Pequenos Artesãos/Produtores):** Se `store.vat_exempt_art53 == true`, todas as vendas dessa loja são liquidadas a **0,00% de IVA**, enviando automaticamente o motivo de isenção (`M10` no Moloni/AT) para o software de faturação.
2. **Hierarquia de Taxas:**
   - A **Categoria** define a taxa por defeito (ex: Livros e Bens Essenciais = **6%** em PT Continente / **4%** Açores-Madeira / **4%** em ES; Produtos Gerais = **23%** PT / **21%** ES).
   - O **Produto** pode sobrescrever a taxa da categoria se necessário.
3. **Vendas B2B Intracomunitárias (PT <-> ES):** Validação automática do NIF/CIF europeu via serviço oficial da Comissão Europeia (**VIES API**) para aplicar autoliquidação (0% IVA intracomunitário) em transações B2B válidas entre Portugal e Espanha.

---

## 4. Emissão Automática de Faturas AT, Devoluções Parciais e Notas de Crédito

### 4.1 Ciclo de Faturação (Worker Go)
Assim que o webhook confirma o pagamento (`PaymentConfirmed`):
1. O worker Go lê as `sub_orders` criadas pelo Rust.
2. Para cada loja com conector configurado (**Moloni, InvoiceXpress ou Vendus**), envia um pedido idempotente (`idempotency_key`) para emitir a **Fatura-Recibo** em nome do comerciante com o NIF do comprador.
3. **Documento de Transporte AT:** A fatura-recibo inclui automaticamente a morada de carga (loja), morada de descarga (cliente) e data/hora prevista de expedição, servindo legalmente como documento de transporte sem exigir guia separada.
4. O PDF é guardado no armazenamento e enviado por email ao cliente.

### 4.2 Devoluções Parciais e Notas de Crédito (Crítico em Multi-Vendor)
Quando um cliente compra em 3 lojas e exerce o direito de livre resolução (14 dias — DL n.º 24/2014) **apenas num artigo da Loja B**:
1. O cliente ou lojista abre o pedido de devolução sobre a `sub_order` da Loja B (bloqueado automaticamente se o produto tiver `is_perishable = true`, conforme exceção legal para alimentos frescos/padaria).
2. Ao aprovar, o backend Rust dispara 4 ações atómicas/orquestradas:
   - **Estorno Parcial no Gateway:** Devolve apenas o valor correspondente à Loja B a partir da conta conectada da Loja B.
   - **Emissão Automática de Nota de Crédito AT:** O worker Go invoca a API do Moloni/InvoiceXpress da Loja B para emitir a Nota de Crédito associada à fatura original.
   - **Reposição de Stock (Opcional):** Se o artigo voltar vendável, incrementa `stock_qty`.
   - **Reversão de Fidelização:** Lanca movimento negativo (`refund_reversal`) no `loyalty_ledger` proporcional aos pontos ganhos naquele item.

---

## 5. Logística Multi-Vendedor (Local + Nacional + Ibérica)

Cada `sub_order` pode ter um método de envio independente no mesmo carrinho:
1. ***Click & Collect* (Gratuito, 0€):** O cliente escolhe uma janela horária (*pickup slot*) dentro do horário (`business_hours`) da loja física.
2. **Estafeta Municipal / Local:** Para Câmaras ou Associações que disponham de distribuição local (carrinha elétrica/bicicleta), o sistema gera uma lista de recolhas agrupadas por código postal e horário.
3. **Transportadoras Nacionais e Ibéricas (CTT Expresso, DPD, Nacex, Sendcloud):** O worker Go envia a morada de recolha da **loja específica** (remetente dinâmico) e a morada do cliente, gerando o PDF da etiqueta A6 pronto a imprimir no balcão do lojista.