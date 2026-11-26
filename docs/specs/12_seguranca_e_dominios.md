# 12. Segurança ("nível máximo anti-hacker") e Domínios das Câmaras

> Atualizada a 26/11/2026: canais, patrocínio, comissões e planos seguem a spec 14 (prevalece).

**Estado:** aprovado pelo owner em 25/11/2026. **Prevalece sobre as specs 02 e 10** em TLS/edge e segurança.
**Padrão medível:** **OWASP ASVS 5.0 — nível 2 em toda a plataforma, nível 3 em `payments`, `admin` e `identity`.** O `security-auditor` revê cada diff contra esta lista.

---

## 1. Edge: Cloudflare (plano gratuito) + Cloudflare for SaaS

- Os nossos domínios (`ptmarket.pt`, `lojaportugal.pt`, `segjarsolucoes.pt`, …) ficam na **nossa** conta Cloudflare, proxied.
- **Domínios das Câmaras via Cloudflare for SaaS** na nossa conta (Free: **100 hostnames incluídos**, depois 0,10 $/hostname/mês — verificado 25/11/2026 em developers.cloudflare.com).
  - A Câmara **só cria 1 CNAME** no DNS que já usa: `mercado.<dominio-camara> → clientes.ptmarket.pt`. Não precisa de conta Cloudflare.
  - O backoffice (`tenancy`) regista o hostname pela API (*Create Custom Hostname*), faz polling até `status = active` e `ssl.status = active`, e mostra o estado ao super_admin.
  - **Só subdomínios** (o domínio raiz exige add-on Enterprise).
  - Sem Cloudflare for SaaS, um CNAME de outra conta Cloudflare para nós dá **erro 1014** — por isso é obrigatório.
- **TLS na edge é da Cloudflare** (emissão e renovação automáticas). O Caddy fica como reverse proxy interno com certificado *Origin CA* da Cloudflare. O `on_demand_tls` das specs 02/10 passa a **fallback** (só se um cliente recusar Cloudflare).
- **Origem fechada:** o servidor só aceita tráfego dos IP ranges da Cloudflare (firewall). *Cloudflare Tunnel* (sem portas abertas) a avaliar na Fase 2 — não confirmado como origem de custom hostnames.
- **DDoS/WAF:** proteção da Cloudflare + regras WAF gratuitas (bloquear países/ASN só se houver ataque medido; nada de geobloqueio às cegas).

### 1.1 Quem tem domínio (ver spec 14 §1)
- **Só os canais têm domínio:** `tenants.custom_domain` continua `NOT NULL`. As entidades patrocinadoras sem domínio próprio vivem em `sponsor_entities` e não geram hostname.

## 2. Anti-bot e anti-spam (duas camadas, sempre as duas)

**Camada 1 — Cloudflare Turnstile** (gratuito, invisível na maioria dos casos, sem puzzles de imagens, melhor para RGPD que reCAPTCHA):
- Sempre: registo (cliente e lojista), recuperação de password, contacto, avaliações/comentários, candidatura de lojista.
- Condicional: login após 3 falhas; checkout só com sinais de risco (velocidade anómala, IP em lista).
- Nunca: navegação no catálogo.
- **Token verificado no servidor** (Rust → `siteverify`), nunca só no browser; token de uso único com validade curta.

**Camada 2 — nativa em Rust/infra** (funciona mesmo que um bot resolva o captcha):
- Rate limiting (`tower_governor`) por IP, por conta e por endpoint; bloqueio progressivo no login (backoff exponencial, nunca bloqueio permanente que permita DoS a contas alheias).
- Honeypot (campo invisível) + tempo mínimo de preenchimento em todos os formulários públicos.
- **CrowdSec** (open source, gratuito) com bouncer no Caddy: bane IPs atacantes e partilha reputação.

## 3. Checklist ASVS aplicada (o que cada cartão de backend tem de respeitar)

**Identidade e sessões**
- Passwords com **Argon2id** (parâmetros OWASP), verificação contra passwords vazadas (k-anonymity HIBP) no registo. O hash corre numa fila com espera máxima de 2 s; depois disso, 503 com Retry-After (decisão do owner, 25/11/2026).
- **Passkeys (WebAuthn)** para lojistas e admin; **2FA TOTP obrigatório** para `super_admin` e `tenant_admin`.
- Cookies de sessão `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax` (Strict no admin); rotação do ID de sessão no login; expiração por inatividade.
- **Duração das sessões** (decisão do owner, 25/11/2026): cliente 7 dias absolutos no máximo; staff 12 h, ou 30 min de inatividade; plataforma 8 h, ou 15 min.
- **CSRF:** token em todos os formulários que alteram estado (além de SameSite).

**Login do staff** (ver spec 14 §8)
- Todo o staff (lojistas, `sponsor_admin`, `super_admin`) autentica-se **só em `admin.ptmarket.pt`**. O âmbito vem do **papel**, nunca do Host. Há **um só `rp_id`** de passkeys (`admin.ptmarket.pt`).
- Os **clientes** continuam a comprar e a autenticar-se em qualquer canal.

**Autorização**
- RLS no PostgreSQL **e** verificação de dono/tenant em **cada** handler (defesa em profundidade). Cada endpoint que recebe um ID tem um teste que tenta aceder ao recurso de outro tenant/cliente e **tem de falhar** (anti-IDOR).
- Princípio do menor privilégio: utilizador de BD da API sem `SUPERUSER`/`BYPASSRLS`; Data Studio com utilizador próprio.

**Entrada e injeção**
- Só queries SQLx verificadas em compilação (`query!`/`query_as!`); proibido montar SQL com texto.
- DTOs com `#[serde(deny_unknown_fields)]` + validação (`validator`/`garde`); limites de tamanho em todos os campos e no corpo do pedido.
- JSONB: passar `serde_json::Value`/tipos diretamente — **nunca** serializar para string e fazer `$1::jsonb` (dupla codificação).

**Browser**
- **CSP estrita com nonces** (Next.js middleware), `frame-ancestors 'none'`, HSTS (`max-age` ≥ 1 ano; `includeSubDomains` + `preload` **só nos nossos domínios** — nos subdomínios das Câmaras só `max-age`, porque o preload abrange o domínio inteiro delas), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` mínima, COOP `same-origin`.
- Nenhum HTML enviado por utilizadores é servido; descrições de produto em Markdown sanitizado.

**Pagamentos e webhooks**
- Cada webhook (Eupago, Stripe, Moloni, CTT) verifica: **assinatura HMAC** (comparação em tempo constante) · **valor e moeda** iguais à encomenda · **destinatário/conta** correta · **idempotência** por ID do evento · **janela anti-replay** (timestamp ≤ 5 min).
- Nunca marcar `paid` sem estas 5 verificações; divergência = alerta + estado `review`.

**Uploads**
- **Documentos privados** (verificação de lojas): armazenamento privado, nunca servidos como `/media`; acesso só por **URL assinado de 5 min**, auditado (ver spec 14 §6).
- Imagens recodificadas no servidor (decodificar → reencodar AVIF/WebP): remove EXIF e mata ficheiros poliglotas; limite de tamanho e de dimensões; nome de ficheiro gerado (UUID), nunca o original.

**Segredos e logs**
- Credenciais de terceiros (Moloni, Eupago) **encriptadas em repouso** (AES-256-GCM, chave fora da BD).
- Logs estruturados com **redação automática** (passwords, tokens, NIF, IBAN, cartões); nunca logar corpos de pedidos de pagamento.
- `admin_audit_logs` para toda a ação de admin (quem, o quê, antes/depois, IP).

**Cadeia de fornecimento** (local, sem CI pago)
- `cargo audit` + `cargo deny`, `govulncheck`, `npm audit --omit=dev` antes de cada release; lockfiles no git; versões fixadas; dependências novas só com justificação.

**Antes de cada release**
- OWASP ZAP (baseline) contra staging; backups encriptados com **restauro testado**; staging antes de produção, nunca editar no servidor.

## 4. Conformidade

RGPD (consentimentos, esquecimento via `customers.anonymized_at` mantendo dados fiscais), NIS2/CNCS (spec 10), registo de incidentes e notificação em 72 h.
