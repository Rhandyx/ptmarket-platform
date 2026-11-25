# 10. Auditoria de Pontos Cegos: Tudo o que Faltava Prever (Legal, Técnico e Operacional)

**Objetivo:** Antecipar problemas jurídicos, fiscais, operacionais e de engenharia que normalmente só aparecem depois de o sistema estar em produção ou durante a assinatura do primeiro contrato com uma Câmara Municipal.

---

## 1. Blind Spots Legais e Regulatórios (Portugal & União Europeia)

| Tema Crítico | O Problema Real (Que Quase Todos Esquecem) | Solução Já Incorporada na Arquitetura |
| :--- | :--- | :--- |
| **1. Diretiva Omnibus — Histórico de Preços 30 Dias (DL 70/2007)** | Em Portugal/UE, é ilegal mostrar um "desconto" sem apresentar o **preço mais baixo praticado nos últimos 30 dias**. A ASAE aplica coimas pesadas. | Tabela `product_price_history` + coluna `lowest_price_30d_cents` atualizada automaticamente em cada alteração de preço. |
| **2. Acessibilidade Obrigatória no Setor Público (WCAG 2.1 AA / DL 83/2018)** | Portais de Câmaras Municipais são legalmente obrigados a cumprir WCAG 2.1 AA e exibir a Declaração de Acessibilidade (`acessibilidade.gov.pt`). | Templates `shadcn/ui` (Radix) acessíveis por teclado/leitor de ecrã + validador de contraste no Backoffice + página `/acessibilidade` automática por município. |
| **3. RGPD + DPA com Câmaras vs. 10 Anos Fiscais da AT** | Câmaras exigem um **DPA (Acordo de Subcontratação de Dados)** e servidores estritamente na UE. Além disso, se um cliente pedir o "direito ao esquecimento", **não podes apagar a encomenda** porque a AT obriga a guardar registos fiscais por 10 anos! | Alojamento exclusivo na UE (Alemanha/França/Portugal) + botão de **Anonimização RGPD** (`customer_anonymized = true` que substitui nome/email/telefone por hash anónimo na tabela `orders`, mantendo intactos os totais e registos fiscais do lojista). |
| **4. Digital Services Act (DSA — UE)** | Marketplaces online são obrigados a validar a identidade comercial do vendedor (KYC: denominação social, NIF, morada, contacto) e disponibilizar um botão de *"Denunciar conteúdo/produto ilegal"*. | Campos `legal_name`, `nif`, `kyc_verified` na tabela `stores` + formulário simples de denúncia no rodapé da ficha de produto. |
| **5. Livro de Reclamações Eletrónico e RAL (DL 74/2017)** | Obrigatório no rodapé de qualquer loja online em Portugal, juntamente com a indicação da entidade de Resolução Alternativa de Litígios (ex: CNIACC / CICAP). | Campos configuráveis em `tenants.legal_config` exibidos automaticamente no rodapé de todos os portais. |
| **6. Direito de Livre Resolução (14 Dias — DL 24/2014) vs. Perecíveis** | O cliente tem 14 dias para devolver compras online, **exceto** bens perecíveis (padaria, talho, flores) ou personalizados. | Flag `is_perishable` nos produtos bloqueia devolução automática pós-entrega e exibe o aviso legal claro antes do pagamento no checkout. |

---

## 2. Blind Spots Operacionais do Comércio Tradicional

1. **Produtos ao Peso / Horários de Loja / Férias:**
   - Lojas de rua fecham para almoço, feriados municipais ou férias em agosto. Sem **Modo Férias (`is_vacation_mode`)** e **Horários (`business_hours`)**, entram encomendas que ninguém prepara, queimando a reputação do portal da Câmara.
2. **Encomendas *Click & Collect* Não Levantadas:**
   - Definir prazo automático (ex: 48h para bens duradouros, fim do dia para padaria/perecíveis) com lembrete automático por email ao cliente após 24h.
3. **Gestão de Disputas e Chargebacks:**
   - Nos Termos e Condições de cada portal deve ficar explícito que o contrato de compra e venda é celebrado **diretamente entre o Consumidor e o Comerciante** (a Câmara e a Segjar atuam exclusivamente como fornecedores da infraestrutura tecnológica de intermediação).
4. **Email Deliverability (SPF, DKIM, DMARC):**
   - Se os emails de confirmação de encomenda e faturas em PDF caírem no SPAM do Gmail/Outlook, o cliente acha que foi burlado. Configurar obrigatoriamente registos DNS **SPF, DKIM e DMARC** no domínio de envio (`mail.ptmarket.pt`) via Resend ou AWS SES antes do primeiro cliente real.

---

## 3. Blind Spots Técnicos e de Segurança (Cibersegurança CNCS / NIS2)

1. **SSL Automático sem Intervenção Manual:**
   - Usar **Caddy Server** com `on_demand_tls` validado contra o endpoint interno Rust `/internal/tls-check?domain=...`. Evita ataques de exaustão de certificados (porque só emite SSL para domínios registados na tabela `tenants`) e elimina trabalho manual sempre que entra uma nova Câmara.
2. **Encriptação de Credenciais em Repouso (Envelope Encryption):**
   - As chaves API do Moloni/InvoiceXpress/Vendus e segredos 2FA (`totp_secret_enc`) **nunca** são gravados em texto limpo na base de dados; são encriptados em Rust com **AES-256-GCM** usando uma chave mestra injetada apenas por variável de ambiente (`MASTER_ENCRYPTION_KEY`) fora do repositório Git.
3. **Rate Limiting e Proteção contra Bots/Abuso:**
   - Proteger endpoints críticos (`/auth/login`, `/checkout`, `/webhooks`, `/ai-enrich`) via Redis Rate Limiter (ex: `tower_governor` em Rust) e Cloudflare WAF, impedindo que um bot dispare milhares de chamadas pagas à API de IA ou spam de referências Multibanco.
4. **Observabilidade Leve para Operação a Solo (Sem Custos Altos):**
   - **Uptime Kuma** (self-hosted gratuito) a vigiar `api.ptmarket.pt/health` e os domínios das Câmaras de 60 em 60 segundos com **alerta imediato no teu Telegram** se algo falhar.
   - **GlitchTip / Sentry (Free Tier)** para capturar qualquer erro não tratado no Next.js ou Go Workers antes de o cliente telefonar.
   - **Testes de Restauro de Backup:** Um backup que nunca foi restaurado não existe. Agendar teste trimestral de restauro do dump PostgreSQL num container local.
5. **SLA Realista nos Contratos Públicos:**
   - Nunca prometer "suporte 24/7 com resposta em 15 minutos" operando a solo. Contratualizar **Disponibilidade Alvo de 99,5%** e **Suporte Técnico em Dias Úteis (09h00–18h00)** com resposta até 4 horas úteis para incidentes críticos (checkout parado) e 24h úteis para dúvidas normais.

---

## 4. Checklist Mestre de Execução (Da Semana 1 ao 1.º Contrato)

### Fase A — Fundação Jurídica e Presença Digital (Semana 1)
- [ ] Pedir ao contabilista a inclusão do **CAE 62010** na Segjar Soluções, Lda (gratuito).
- [ ] Criar e publicar no Cloudflare Pages as 3 páginas estáticas limpas: `segjarsolucoes.pt`, `ptsolucoes.pt`, `ptmarket.pt` (e página de pré-lançamento em `lojaportugal.pt`).
- [ ] Contactar o gestor comercial da **Eupago** para negociar tabela *Tier Marketplace* + acesso à documentação da API de *Split Payments* em Sandbox.
- [ ] Criar conta **Stripe Connect** em modo Sandbox para testes de Cartão/Apple Pay e Espanha.

### Fase B — Construção do Núcleo Técnico (Semanas 2 a 6)
- [ ] Inicializar o monorepo `ptmarket-platform` com os ficheiros `/docs`, `CLAUDE.md`, `.claude/agents/` e `.agent/`.
- [ ] Correr `migrations` PostgreSQL 17 (RLS, tabelas base, Omnibus, RBAC, auditoria) + `seed_taxonomy`.
- [ ] Implementar API Core em **Rust (`Axum`)**: Auth JWT+2FA, gestão de *tenants*, catálogo, carrinho multi-loja, cálculo de *split* + IVA (PT/ES/Art. 53.º), stock atómico e `LocalDiskStorage`.
- [ ] Implementar Workers em **Go (`Asynq`)**: Webhooks Eupago/Stripe, conector Moloni/InvoiceXpress (sandbox), enriquecimento IA de produtos e importador WooCommerce/CSV.
- [ ] Construir Frontend **Next.js**: 3 templates White-Label (WCAG 2.1 AA), PWA, Backoffice do Lojista, Backoffice da Câmara e **Data Studio** com Dry-Run.

### Fase C — Demo Comercial e Primeiras Reuniões (Semanas 7 e 8)
- [ ] Executar `seed_demo` no servidor e colocar `demo.ptmarket.pt` online com HTTPS automático (Caddy).
- [ ] Correr auditoria completa com o `security-auditor` (Sonnet) e QA visual com o Browser Subagent (AGY).
- [ ] Preparar proposta comercial padrão em PDF (14.500€ Ano 1 + 2.700€/ano Ano 2 e 3, respeitando a regra trienal do Art. 113.º CCP) + Minuta DPA (RGPD).
- [ ] Marcar as primeiras 5 a 10 reuniões presenciais com **Associações Comerciais** e **Câmaras Municipais** (começando por Vila Nova de Gaia e distrito do Porto) levando a demo pronta no telemóvel.