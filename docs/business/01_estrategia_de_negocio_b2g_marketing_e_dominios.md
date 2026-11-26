# 01. Estratégia de Negócio B2G/B2C, Marketing, Jurídico e Ecossistema de Domínios

**Entidade Detentora:** Segjar Soluções, Lda (NIPC: 506925544 — Sede: Av. da República, 1336, s/loja 7, 4430-192 Vila Nova de Gaia)  
**Enquadramento Fiscal:** Contabilidade Organizada — Regime Misto de IVA (Mediação de Seguros isenta ao abrigo do Art. 9.º do CIVA devidamente segregada das operações tecnológicas e comerciais sujeitas a IVA)  
**Data de Referência:** Novembro de 2026

> **Atualizado a 26/11/2026 (decisões do owner):** catálogo universal em `lojaportugal.pt` + domínios white-label filtrados, patrocínio múltiplo (Câmara, Junta, Associação), comissão pelo patrocínio da loja e planos para lojas independentes. Regras técnicas e financeiras completas: `docs/specs/14_canais_patrocinio_comissoes_e_planos.md`.

---

## 1. Arquitetura do Ecossistema de Marcas e Domínios

Para evitar misturar a atividade histórica de mediação de seguros com a venda de tecnologia ao setor público (B2G) e a operação comercial ao consumidor final (B2C), o projeto divide-se em **4 domínios principais** mais os domínios próprios das autarquias:

```text
[ SEGJAR SOLUÇÕES, LDA ]  ──►  segjarsolucoes.pt (Entidade Jurídica, Contratos e Faturação)
         │
         ├──► ptsolucoes.pt  (Marca Comercial TI / Software House para Setor Público e Empresas)
         │
         └──► ptmarket.pt    (O Produto SaaS / Motor Tecnológico Multi-Tenant)
                   │           • admin.ptmarket.pt (Painel Unificado: Lojistas, Câmaras/Juntas/Associações e Super-Admin; âmbito pelo papel)
                   │           • api.ptmarket.pt   (API Core Rust + Webhooks Go)
                   │           • demo.ptmarket.pt  (Município Fictício de Demonstração Comercial)
                   │
                   ├──► Canal Nacional (B2C): lojaportugal.pt — CATÁLOGO UNIVERSAL
                   │      • TODAS as lojas ativas aparecem (sem opt-out); entrega limitada por shipping_scope
                   │      • Loja patrocinada (≥1 patrocínio ativo): ~~8%~~ 0% em qualquer canal
                   │      • Loja independente: Plano 1 (8% / 6% marginal) ou Plano 2 (subscrição por escalões)
                   │
                   ├──► Canais White-Label: domínio próprio da entidade (ex: compreem[concelho].pt)
                   │      • Vista filtrada do mesmo catálogo: só lojas patrocinadas pela entidade
                   │      • Tema (theme_config), 1 dos 3 templates (bairro/editorial/catalogo) e PWA próprios
                   │      • Pago pela entidade (Setup + Avença); comissão da loja segue o patrocínio, não o domínio
                   │
                   ├──► Patrocinadores (N:N com as lojas): Câmara Municipal · Junta de Freguesia · Associação
                   │      • Uma loja pode ter 0, 1, 2 ou mais patrocinadores ativos (vigência independente)
                   │      • Com ou sem domínio próprio; sem domínio = selos + página/filtro no lojaportugal.pt
                   │
                   └──► Canal Futuro — Nichos Verticais / Ibérico PT+ES:
                          • Mesma infraestrutura, configurável por canal
```

### 1.1 Especificação das Páginas Básicas por Domínio

Antes de contactar Câmaras Municipais, Associações Comerciais ou o departamento comercial da Eupago, todos os domínios devem apresentar páginas limpas e coerentes. Para custo zero de manutenção e velocidade instantânea, as 3 páginas institucionais ficam alojadas gratuitamente no **Cloudflare Pages** (HTML + Tailwind estático), enquanto o `lojaportugal.pt` e os portais municipais apontam para o motor Next.js no VPS:

| Domínio | Função | Alojamento | Conteúdo Essencial da Página |
| :--- | :--- | :--- | :--- |
| **`segjarsolucoes.pt`** | **Holding / Empresa-Mãe.** Respaldo jurídico para contratos públicos, Eupago, Stripe e fornecedores. | Cloudflare Pages (0€/mês) | Apresentação institucional (NIPC 506925544, sede em Gaia), divisão visual em 2 pilares claros (**Mediação de Seguros** vs. **Tecnologia & Soluções Digitais**), contactos, Política de Privacidade (RGPD) e Livro de Reclamações Eletrónico. |
| **`ptsolucoes.pt`** | **Divisão de Software & Consultoria TI.** Imagem corporativa puramente tecnológica para vereadores e decisores B2G. | Cloudflare Pages (0€/mês) | Serviços de desenvolvimento de software, automação, integração de ERPs/APIs e destaque principal para o produto **PT Market** (modernização do comércio local e Bairros Comerciais Digitais). |
| **`ptmarket.pt`** | **Landing Page de Vendas do SaaS.** A página comercial que explica o produto e converte reuniões. | Cloudflare Pages (0€/mês) + subdomínios no VPS | Proposta de valor em 4 pilares (Pagamento único com *Split* MB WAY direto ao IBAN do lojista, Faturação AT automática Moloni/InvoiceXpress, Logística Local+Nacional, Cartão da Cidade QR), tabela transparente de enquadramento em Ajuste Direto e botão **"Testar Demo ao Vivo"** (`demo.ptmarket.pt`). |
| **`lojaportugal.pt`** | **Portal Agregador Nacional (B2C).** Segunda linha de receita (comissão por venda) e efeito de rede para os comerciantes locais. | VPS Principal (Next.js) | *Fase Pré-Lançamento:* Página de captação de interesse para produtores e comerciantes portugueses (recolha de leads).<br>*Fase Ativa:* Marketplace nacional completo com pesquisa global e filtros avançados. |

*(Nota sobre `lojadeportugal.pt`: Pertence atualmente à 100 Limites. Não empatar capital agora a negociar a compra; o `lojaportugal.pt` e o `ptmarket.pt` resolvem integralmente a estratégia e só faz sentido negociar a compra mais tarde se houver forte retorno financeiro).*

---

## 2. Análise de Mercado, Concorrência e Lacunas (Portugal 2026)

### 2.1 Radiografia dos Concorrentes Atuais
1. **Agências Web Tradicionais (WordPress + WooCommerce + WCFM/Dokan):**
   - *Realidade verificada:* Vários projetos de Bairros Comerciais Digitais (como o *Marketplace @Baixa Coimbra*) correm sobre WordPress/WooCommerce.
   - *Falhas crónicas:* Lentidão severa em mobile, custos elevados de manutenção (uma instalação isolada por município), plugins dos CTT/DPD que não suportam múltiplos remetentes, incapacidade de gerir faturação certificada por comerciante e ausência de *split* bancário limpo.
2. **Grandes Operadoras e Integradores (MEO Empresas, Partteam, Smartgov, Wingsys):**
   - *Realidade:* Dominam concursos públicos de grande dimensão focados em hardware urbano (mupis digitais, sensores de estacionamento, Wi-Fi de rua, cacifos).
   - *Lacuna:* O software de e-commerce é um módulo secundário, rígido, lento a adaptar e com custos de manutenção proibitivos para municípios pequenos/médios.
3. **Apps de Diretório e Fidelização (ex: Bargly):**
   - *Realidade:* Focadas em descontos e cartões de selos, mas não resolvem o ciclo completo de venda online (carrinho multi-loja, pagamento dividido, faturação AT e logística).

### 2.2 Oportunidades de Mercado (Onde Entrar e Ganhar)
1. **A Onda de "Resgate Pós-PRR" (2026–2027):** Dezenas de Câmaras Municipais e Associações Comerciais que lançaram marketplaces lentos na primeira vaga dos Bairros Comerciais Digitais estão agora com contratos iniciais a expirar e com plataformas abandonadas pelos lojistas. Elas têm a obrigação perante os auditores dos fundos europeus de manter os projetos operacionais, criando procura imediata por uma solução rápida, estável e com **migração gratuita de catálogo**.
2. **Municípios Pequenos/Médios e Juntas de Freguesia:** Entidades fora dos grandes contratos da MEO que podem avançar rapidamente via Ajuste Direto ou Consulta Prévia.
3. **Eurocidades e Comércio Transfronteiriço (Portugal + Espanha):** Zonas raianas (Valença/Tui, Chaves/Verín, Bragança/Zamora, Elvas/Badajoz) com acesso a fundos europeus **Interreg POCTEP** para comércio ibérico. A arquitetura nasce bilingue (PT/ES) e preparada para IVA português e espanhol.

### 2.3 Matriz SWOT Consolidada

| Pontos Fortes | Pontos Fracos / Riscos |
| :--- | :--- |
| • Motor próprio em Rust + Go (latência mínima, custo de servidor 10x inferior ao PHP/WordPress).<br>• Arquitetura Multi-Tenant (1 instalação serve 50 Câmaras).<br>• Resolve os 3 bloqueios reais em Portugal: Split direto ao IBAN (zero dinheiro na conta da Câmara), Faturação AT automática e Logística multi-remetente.<br>• Combina E-commerce + Cartão da Cidade (fidelização em loja física via QR Code). | • Execução inicial a solo (mitigada por orquestração estruturada de IA e testes automáticos).<br>• Tempo de decisão burocrático em Câmaras Municipais (mitigado por começar pelas Associações Comerciais).<br>• Dependência inicial de aprovação comercial do *Split* na Eupago / Stripe Connect. |

---

## 3. Enquadramento Jurídico, Fiscal e Contratação Pública (CCP)

### 3.1 Situação da Segjar Soluções, Lda
- **Objeto Social (Certidão Permanente):** Já cobre expressamente *"Portais Web"*, *"Atividades de programação informática"*, *"Atividades de consultoria em informática"*, *"Outras atividades relacionadas com as tecnologias e informação"* e *"Comércio a retalho por correspondência ou via internet"*.
- **Ações Administrativas Recomendadas (Custo Zero):**
  1. Pedir ao contabilista a adição do **CAE Secundário 62010** (*Atividades de programação informática*) no Portal das Finanças para alinhamento direto com os códigos CPV dos procedimentos públicos.
  2. Validar contratualmente que não existe cláusula de exclusividade com alguma seguradora que limite a prestação de serviços tecnológicos acessórios (no regime de mediação não exclusiva e já estando em regime misto de IVA, não há entrave contabilístico).

### 3.2 Contratação Pública: Ajuste Direto, Regra Trienal e Consulta Prévia
Ao abrigo do Código dos Contratos Públicos (CCP) em Portugal:

1. **Ajuste Direto Geral (Serviços):** Limite legal de **20.000,00 € (+ IVA)** por entidade adjudicante.
2. **Regra do Limite Trienal (Artigo 113.º do CCP):** A mesma Câmara Municipal não pode adjudicar à mesma empresa mais de **20.000,00 € (+ IVA)** em ajustes diretos para serviços da mesma natureza no período de **3 anos económicos** (ano corrente + 2 anteriores).
3. **Estrutura Comercial Recomendada para Respeitar o Triénio:**
   - **Ano 1 (Setup + Parametrização + Formação + Licença 12 meses):** **14.500,00 € + IVA**.
   - **Ano 2 (Renovação SaaS + Alojamento + Suporte):** **2.700,00 € + IVA** (225€/mês).
   - **Ano 3 (Renovação SaaS + Alojamento + Suporte):** **2.700,00 € + IVA** (225€/mês).
   - *Total no triénio:* **19.900,00 € + IVA** (totalmente dentro da lei sem exigir concurso público).
4. **Consulta Prévia (Para Municípios Maiores ou Pacotes com App Nativa):** A entidade convida 3 empresas e o limite sobe para **75.000,00 € (+ IVA)**, onde a proposta se destaca pelas exigências técnicas reais (Split bancário nativo, conformidade WCAG 2.1 AA, APIs AT).
5. **Cláusula de Propriedade Intelectual (Obrigatória no Contrato):**
   - O contrato deve definir o objeto como **"Licenciamento de Utilização Não Exclusiva de Plataforma Software como Serviço (SaaS), Parametrização e Suporte"**.
   - **Nunca** ceder direitos de autor do código-fonte. O motor `PT Market` permanece 100% propriedade da **Segjar Soluções, Lda**, permitindo revender a licença a dezenas de municípios.

---

## 4. Plano de Marketing, Abordagem Comercial e Preçário

### 4.1 Pacotes Comerciais

| Módulo / Pacote | Preço Indicativo (s/ IVA) | O que Inclui |
| :--- | :--- | :--- |
| **Câmara Municipal — Preço Único (Ano 1)** | **12.500€ a 14.500€** | O mesmo valor com ou sem domínio próprio. Inclui patrocínio com selos e página/filtro em `lojaportugal.pt`, painel de aprovação em `admin.ptmarket.pt`, integração Eupago/Stripe + Moloni/InvoiceXpress, Cartão da Cidade (PWA + QR Code), migração assistida de catálogo, formação presencial/remota aos comerciantes e 12 meses de alojamento/suporte. **Opção incluída a 0€:** canal white-label no domínio da Câmara (vista filtrada do catálogo universal: lojas patrocinadas), com 1 dos 3 templates e PWA, ativável no arranque ou mais tarde. |
| **Câmara Municipal — Renovação Anual SaaS (Ano 2+)** | **2.700€ a 3.600€ / ano** | O mesmo valor com ou sem domínio. Alojamento em servidor europeu, backups diários, atualizações de segurança e conformidade legal, suporte técnico de 2.º nível. |
| **Add-on: App Nativa iOS & Android (Capacitor)** | **+3.000€ setup + 600€/ano** | Compilação e publicação da app personalizada na Apple App Store e Google Play (na conta institucional da própria Câmara). |
| **Canal Nacional (`lojaportugal.pt`)** | **0€ adesão** | Presença obrigatória de todas as lojas ativas (sem opt-out). Loja patrocinada: **0%** (âncora `~~8%~~ 0%`). Loja independente escolhe um dos planos abaixo. |
| **Plano 1 — Comissão (`commission_payg`, por defeito)** | **0€/mês + 8%** por venda até 20.000€/mês; **6%** só sobre o excedente | Escalões marginais (tipo IRS), sem saltos. Base configurável em `platform_settings`. |
| **Plano 2 — Subscrição (`tiered_subscription`)** | **5€ / 10€ / 50€ por mês** até 1.000€ / 5.000€ / 10.000€ (0%); 10.000€–20.000€: **50€ + 8%** sobre o excedente; >20.000€: **850€ + 6%** sobre o excedente | Escalões marginais editáveis pelo Super-Admin (`billing_plan_tiers`). |
| **Junta de Freguesia / Associação Local** | **750€–1.500€ setup + 1.200€–1.800€/ano** | Pacote à escala da freguesia/associação, com o mesmo valor com ou sem domínio. Inclui página/filtro em `lojaportugal.pt`, selos nas lojas patrocinadas, painel de aprovação em `admin.ptmarket.pt` e relatórios agregados (sem dupla contagem). Pode operar só com selos/página dedicada ou ativar o domínio próprio (3 templates + PWA). |

### 4.2 Estratégia de Vendas no Terreno (Passo a Passo)
1. **Alvo Primário (Ciclo Rápido):** Associações Comerciais e Empresariais locais (decisão em 2 a 4 semanas, gestão direta dos fundos dos Bairros Comerciais Digitais) e Juntas de Freguesia urbanas.
2. **Alvo Secundário (Ticket Maior):** Vereadores do Desenvolvimento Económico e Turismo das Câmaras Municipais (começando pelo distrito do Porto / Norte pela proximidade física à sede em Gaia).
3. **O "Pitch" de 15 Minutos (Zero PowerPoint, 100% Demo ao Vivo):**
   - Abrir `demo.ptmarket.pt` no telemóvel do decisor.
   - Colocar no carrinho 3 artigos de 3 lojas diferentes (uma com IVA 6%, uma com IVA 23%, uma isenta Art. 53.º).
   - Mostrar o checkout em 15 segundos, a divisão do dinheiro sem passar pela conta da Câmara, a geração das faturas certificadas e o leitor de QR Code do Cartão da Cidade.
   - Fechar eliminando o maior medo: *"Se já têm uma plataforma antiga em WordPress que ninguém usa, migramos os produtos dos vossos lojistas automaticamente sem custos extra."*

---

## 5. Projeção Financeira e Custos Reais de Infraestrutura (Valores 2026)

Ajustado à subida real do hardware (servidores Ryzen/EPYC NVMe na Europa em 2026):

| Fase Operacional | Receita Estimada (s/ IVA) | Infraestrutura Necessária | Custo Mensal Real | Margem Bruta |
| :--- | :--- | :--- | :--- | :--- |
| **Fase 0: Desenvolvimento & Demo** | 0€ | 1 VPS modesto (4 vCPU, 8–16GB RAM, NVMe, Storage Local sem R2) + Cloudflare Free | **15€ – 30€/mês** | — |
| **Fase 1: 1 a 5 Câmaras Ativas** | 14.500€ a 72.500€ (Ano 1) | 1 Servidor Dedicado/VPS Alta Performance (8–12 vCPU, 32GB RAM DDR5, NVMe RAID) + Backups externos encriptados (Backblaze B2 / WAL-G) + Resend/SES | **95€ – 130€/mês** (~1.320€/ano) | **> 90%** |
| **Fase 2: 6 a 20 Câmaras + Portal Nacional** | 87.000€ a 290.000€ + Renovações | **2 VPS ligados em Rede Privada/WireGuard:** VPS 1 App (Rust/Go/Next.js) + VPS 2 PostgreSQL Dedicado/Réplica + Cloudflare R2/Pro | **240€ – 350€/mês** (~3.500€/ano) | **> 96%** |
| **Fase 3: Escala Ibérica (20 a 50+ Tenants)** | > 400.000€/ano | Load Balancer + 2 Nós App + Cluster PostgreSQL Primary/Standby HA + Monitorização | **450€ – 650€/mês** (~6.500€/ano) | **> 98%** |