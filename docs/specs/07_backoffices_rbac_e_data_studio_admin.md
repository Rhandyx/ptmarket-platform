# 07. Ecossistema de Backoffices (RBAC) e Data Studio Admin

**Objetivo:** Centralizar numa única aplicação Next.js (`admin.ptmarket.pt`) a operação diária dos comerciantes, a governação das Câmaras/Associações e uma consola técnica completa para a **Segjar Soluções, Lda**, incluindo um explorador visual avançado de PostgreSQL (com os recursos de um phpMyAdmin/Supabase Studio, mas com interface moderna e travões anti-erro).

---

## 1. Os 3 Níveis de Acesso (RBAC + RLS)

```text
                       [ PORTAL UNIFICADO: admin.ptmarket.pt ]
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
[1. LOJISTA (Merchant)]        [2. CÂMARA / ASSOCIAÇÃO]         [3. SUPER-ADMIN (Segjar)]
 • Scope: store_id              • Scope: tenant_id               • Scope: Global (Todos Tenants)
 • Encomendas & Etiquetas       • Aprovar/Suspender Lojas        • Provisionar Novos Municípios
 • Catálogo IA & Stocks         • Temas, Banners, 3 Templates    • Monitorização Filas Go (Asynq)
 • Modo Férias & Horários       • Relatórios PRR / Fundos UE     • Impersonation ("Entrar como")
 • Moloni / Eupago / Art. 53    • Exportação Saída (Portabil.)   • Data Studio (SQL & Tabelas)
 • Devoluções & Leitor QR       • ZERO acesso a IBANs/Chaves     • Logs de Auditoria Imutáveis
```

---

## 2. Funcionalidades Detalhadas por Painel

### 2.1 Painel do Lojista (`merchant_owner` / `merchant_staff`) — *Mobile-First*
- **Gestão de Sub-Encomendas (`sub_orders`):** Alertas sonoros de novos pedidos, botões de 1 toque (*Aceitar*, *Pronto para Levantamento*, *Gerar Etiqueta CTT/DPD*), gestão de pedidos de devolução (14 dias) com emissão automática de Nota de Crédito.
- **Gestão de Operação Local:** Definir horários de abertura (`business_hours`), janelas de *Click & Collect* e interruptor de **Modo Férias / Pausa Temporária** (suspende novas encomendas sem apagar o catálogo).
- **Catálogo Inteligente:** Adicionar produto com foto + título (IA categoriza, traduz para ES e sugere SEO), ajustar stock rapidamente, ver histórico de preços 30 dias (alerta automático Diretiva Omnibus), importar via WooCommerce/Moloni/CSV e ativar visibilidade no `lojaportugal.pt`.
- **Financeiro & Fiscal:** Ligar subconta Eupago/Stripe, configurar Isenção Art. 53.º ou taxas normais, colar *API Key* do Moloni/InvoiceXpress/Vendus e descarregar extratos de liquidações.
- **Terminal Cartão da Cidade:** Leitor de QR Code na câmara do telemóvel para atribuir ou descontar cashback local no balcão.

### 2.2 Painel da Câmara / Associação (`tenant_admin`)
- **Governação & KYC (DSA):** Aprovar pedidos de adesão de comerciantes do concelho após validar NIF e morada local; suspender lojas em incumprimento.
- **Identidade & Acessibilidade:** Carregar logótipo/brasão, definir cores (com validador automático de contraste WCAG 2.1 AA), escolher entre os **3 Templates** (`bairro`, `editorial`, `catalogo`) e gerir banners de campanhas municipais.
- **Observatório do Comércio Local (Relatórios PRR / Portugal 2030):** Dashboards exportáveis (PDF/Excel) com volume de vendas do concelho, nº de lojas ativas, adesão ao Cartão da Cidade e setores mais dinâmicos — sem acesso a dados bancários privados nem credenciais fiscais dos lojistas.
- **Portabilidade (Cláusula de Saída):** Exportação completa dos dados públicos/estatísticos do município em formato aberto (CSV/JSON).

### 2.3 Consola Super-Admin / Developer (`super_admin` — 2FA Obrigatório)
- **Gestão Multi-Tenant:** Criar novas Câmaras, apontar domínios customizados (ativando automaticamente o certificado SSL no Caddy), configurar `default_commission_bps` (0% vs. 6,5%) e ativar/desativar módulos.
- **Monitorização de Workers (`Asynq / Redis`):** Ver filas de faturas AT, webhooks Eupago/Stripe, etiquetas CTT e enriquecimento IA; inspecionar erros de payload e clicar em **Reprocessar (*Retry*)**.
- **Suporte Técnico por *Impersonation*:** Entrar temporariamente na sessão de qualquer lojista ou Câmara para diagnosticar problemas sem pedir senhas (banner vermelho permanente no topo + registo obrigatório em `admin_audit_logs`).

---

## 3. Data Studio Integrado (Alternativa Moderna ao phpMyAdmin)

Construído sobre **Rust (`/api/v1/superadmin/db/*` + `pg_catalog`)** e **Next.js (`TanStack Table` + `Monaco Editor`)**:

### 3.1 Recursos Incluídos
1. **Explorador de Esquema e Relações:** Lista de todas as tabelas, contagem exata de linhas, tamanho em disco, índices e navegação clicável por Chaves Estrangeiras (`tenant_id` -> `stores` -> `products` -> `sub_orders`).
2. **Grelha Interativa de Alta Velocidade:** Paginação *cursor-based*, filtros por coluna, ordenação e edição inline de células.
3. **Editor Visual `JSONB`:** Drawer lateral com validação de esquema JSON para editar facilmente `theme_config`, `attributes`, `business_hours` ou traduções `{"pt": "...", "es": "..."}`.
4. **Consola SQL Completa:** Realce de sintaxe, autocompletar de tabelas/colunas, histórico de queries guardadas e exportação direta para **CSV, JSON ou SQL Insert**.
5. **Gestão de Backups & Saúde BD:** Lista de *migrations* SQLx aplicadas, visualização de queries lentas (`pg_stat_statements`) e botão para disparar um *snapshot* imediato antes de intervenções delicadas.

### 3.2 Os 4 Travões de Segurança Anti-Desastre (No Backend Rust)
1. **2FA (TOTP) Obrigatório:** O grupo `/api/v1/superadmin/*` bloqueia qualquer pedido sem sessão 2FA válida.
2. **Modo *Read-Only* por Defeito:** Ao abrir o Data Studio, qualquer tentativa de `INSERT/UPDATE/DELETE/ALTER/DROP` é recusada. Para escrever, o administrador ativa um desbloqueio explícito válido por **15 minutos** reintroduzindo o código 2FA.
3. **Preview Transacional (*Dry-Run*):** Antes de confirmar uma query SQL de escrita manual, o Rust executa `BEGIN; <query>;` devolve *"Esta instrução vai afetar exatamente N linhas"* e faz `ROLLBACK;`. Só após confirmação explícita do utilizador executa o `COMMIT`.
4. **Auditoria Imutável (`admin_audit_logs`):** Tabela *append-only* (sem permissão `DELETE`/`UPDATE` para a role da aplicação) que regista autor, IP, valores antes/depois e SQL executado.

---

## 4. Esquema SQL de Utilizadores, RBAC e Auditoria

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,                          -- Argon2id
    full_name VARCHAR(255) NOT NULL,
    totp_secret_enc TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL,                            -- 'super_admin', 'tenant_admin', 'merchant_owner', 'merchant_staff'
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    store_id UUID REFERENCES stores(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, role, tenant_id, store_id)
);
CREATE INDEX idx_user_roles_user ON user_roles(user_id);

CREATE TABLE admin_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_user_id UUID NOT NULL REFERENCES users(id),
    impersonated_user_id UUID REFERENCES users(id),
    action_type VARCHAR(50) NOT NULL,                     -- 'db_query_write', 'row_edit', 'impersonate_start', 'tenant_create'
    target_table VARCHAR(100),
    target_record_id TEXT,
    old_data JSONB,
    new_data JSONB,
    executed_sql TEXT,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_logs_created ON admin_audit_logs(created_at DESC);
```