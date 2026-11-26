# 08. Pipeline de Imagens (Local -> R2), Seed Demo e Guia de Escalagem (1 VPS -> 2 VPS)

> Atualizada a 26/11/2026: canais, patrocínio, comissões e planos seguem a spec 14 (prevalece).

**Objetivo:** Garantir uma demonstração comercial realista e autocontida (`demo.ptmarket.pt`) **sem depender de Cloudflare R2 na fase inicial**, e documentar passo a passo como escalar para 2 servidores VPS com replicação PostgreSQL quando o número de Câmaras crescer.

---

## 1. Armazenamento de Imagens Abstraído (Demo Local sem R2 -> S3/R2 Futuro)

Na Fase de Demo e nas primeiras 1 a 5 Câmaras, **não é necessário configurar Cloudflare R2**. Todas as fotografias são otimizadas para **WebP** no backend Rust (usando a crate `image`, gerando `thumb_300px`, `card_800px` e `full_1600px` e removendo metadados EXIF pesados) e gravadas numa pasta local do VPS.

### Interface em Rust (`backend-rust/src/storage/mod.rs`)
```rust
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put_object(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<String, StorageError>;
    async fn delete_object(&self, key: &str) -> Result<(), StorageError>;
}
```
- **Modo Demo / Fase 1 (`STORAGE_DRIVER=local`):** `LocalDiskStorage` grava em `/var/data/ptmarket/media/{tenant_id}/{product_id}/...` (volume Docker persistente) e o Caddy serve `/media/*` com cache HTTP longa (`Cache-Control: public, max-age=31536000, immutable`).
- **Documentos de verificação de lojas (`store_verifications`):** vão para um **armazenamento privado**, nunca para `/media` nem para qualquer pasta servida publicamente. Só são acessíveis por **URL assinado de 5 min** (gerado por um `super_admin` em revisão e auditado), são **eliminados até 30 dias depois da decisão** e fica guardado o `sha256` (ver spec 14 §6).
- **Modo Escala / Fase 2 (`STORAGE_DRIVER=r2`):** Altera-se apenas a variável `.env` para ativar `S3CompatibleStorage` (Cloudflare R2 ou Backblaze B2) sem alterar uma única rota da API.

---

## 2. Automação da Demonstração Comercial (`demo.ptmarket.pt`)

Dois binários Rust dentro de `/backend-rust/src/bin/` constroem todo o ambiente de apresentação em menos de 60 segundos:

### 2.1 Binário 1: `seed_taxonomy` (Categorias PT/ES)
- Lê o ficheiro oficial da **Shopify Standard Product Taxonomy** ou **Google Product Taxonomy** guardado em `/seeds/taxonomy_pt_es.json`.
- Insere categorias e subcategorias na tabela `categories` com `default_vat_rate` correto (6% alimentação/livros, 23% geral) e marca as 12 categorias do comércio tradicional com `is_featured = true`.

### 2.1b Seed do DICOFRE (`geo_dicofre`)
- A tabela `geo_dicofre` é carregada da **CAOP da DGT** (dados abertos) por script de seed, não por migration, e regista a `caop_version` (ver spec 14 §5).

### 2.2 Binário 2: `seed_demo` (Município Fictício Completo)
Cria automaticamente um cenário pronto a mostrar a qualquer vereador ou presidente de associação comercial:

| Elemento Criado | Configuração de Demonstração | O que Prova na Reunião |
| :--- | :--- | :--- |
| **2 Tenants (canais) + entidades** | • `demo.ptmarket.pt` ("Bairro Digital Demo", template `bairro`): é um canal **e** uma `sponsor_entity` (município fictício) com lojas patrocinadas.<br>• `lojaportugal.pt` ("Loja Portugal", template `catalogo`): canal nacional, onde estão todas as lojas.<br>• Uma **Junta de Freguesia co-patrocinadora** (`sponsor_entity` sem domínio) de pelo menos uma das lojas patrocinadas pelo município.<br>• Uma **loja independente** (sem patrocínio, comissão do plano). | Mudança automática de visual/domínio no mesmo servidor, patrocínio múltiplo e loja sem patrocínio. Comissões e planos: spec 14 §3 e §4. |
| **6 Lojas Realistas** | 1. **Padaria Central** (IVA 6%, *Perecível*, *Click & Collect* 30 min)<br>2. **Garrafeira do Douro** (IVA 23%, envio CTT + visível no `lojaportugal.pt`)<br>3. **Sapataria Tradição** (Variantes tamanho/cor em `JSONB`, IVA 23%)<br>4. **Livraria Letras** (IVA 6% Livros)<br>5. **Artesanato & Linho** (Isento **Art. 53.º** -> 0% IVA)<br>6. **Talho da Praça** (Entrega por Estafeta Municipal) | Comprova todos os cenários fiscais (0%, 6%, 23%), variantes e logísticas locais/nacionais. |
| **75 Produtos + Imagens** | Fotos reais pré-selecionadas (Unsplash API / imagens geradas em `/seeds/assets/`) já convertidas para WebP local, com títulos/descrições PT e ES e histórico de preços 30 dias. | Montra cheia, rápida e apelativa sem espaços vazios. |
| **15 Encomendas Históricas** | Encomendas geradas nos últimos 30 dias para alimentar os gráficos do Backoffice da Câmara. | Dashboard de métricas PRR com números e gráficos vivos. |
| **Cartão da Cidade + Carrinho Teste** | Conta cliente teste com 12,50€ em saldo de cashback + QR Code pronto a ler no telemóvel. | Demonstração ao vivo de fidelização presencial + checkout multi-loja em 30 segundos. |

---

## 3. Guia Prático de Escalagem: De 1 VPS para 2 VPS + Replicação PostgreSQL

### 3.1 Fase 1 (1 Único VPS — Demo até ~5 Câmaras)
Tudo corre no mesmo servidor via `docker-compose.yml` (Caddy + Next.js + Rust API + Go Workers + PostgreSQL 17 + Redis).
- **Backup de Segurança Imediato (Sem precisar de 2.º servidor):** Usar **WAL-G** ou `pg_dump` encriptado diário enviado para um bucket externo (Backblaze B2 ou Cloudflare R2 — custo inferior a 2€/mês). Os custos recorrentes estão consolidados em `docs/CUSTOS.md` (decisão do owner, 25/11/2026). Garante recuperação ao segundo (*Point-in-Time Recovery*) mesmo que o disco do VPS avarie.

### 3.2 Fase 2 (2 VPS Separados — 6 a 20+ Câmaras)

```text
[ INTERNET ]
      │ (HTTPS 443)
      ▼
+---------------------------------------------+
| VPS 1 — APLICAÇÃO (Exposto à Internet)      |
| • Caddy + Next.js + Rust API + Go Workers   |
| • Redis 7                                   |
| • IP Privado WireGuard / vSwitch: 10.10.0.1 |
+---------------------------------------------+
                      │
                      │ Túnel Privado Encriptado (WireGuard wg0 ou Private Network)
                      │ Porta 5432 NUNCA exposta à internet pública!
                      ▼
+---------------------------------------------+
| VPS 2 — BASE DE DADOS (Isolado da Internet) |
| • PostgreSQL 17 Primary (Escritas)          |
| • (Opcional) PostgreSQL Standby / Réplica   |
| • Toda a RAM e NVMe dedicados à BD          |
| • IP Privado WireGuard / vSwitch: 10.10.0.2 |
+---------------------------------------------+
```

### 3.3 Passos Simples para Ligar os 2 VPS em Segurança
1. **Rede Privada:** Se ambos os VPS forem no mesmo datacenter (ex: Hetzner Cloud Network ou OVH vRack), ativar a rede privada interna (`10.10.0.x`, latência abaixo de `0.5 ms`). Se forem fornecedores diferentes, criar túnel **WireGuard** ponto-a-ponto entre ambos.
2. **Firewall (UFW) no VPS 2 (BD):** Bloquear tudo de entrada exceto SSH (com chave) e porta `5432` **apenas** a partir do IP privado do VPS 1 (`ufw allow from 10.10.0.1 to any port 5432`).
3. **Configuração da Replicação Streaming (Primary -> Standby):**
   - No `postgresql.conf` do Primary: `wal_level = replica`, `max_wal_senders = 5`, `wal_keep_size = 1024MB`.
   - Criar utilizador dedicado `replicator` com permissão `REPLICATION`.
   - No Standby, inicializar com `pg_basebackup -h 10.10.0.2 -U replicator -D /var/lib/postgresql/data -Fp -Xs -P -R`.
4. **Ativação no Código Rust (Zero Alteração de Código):**
   - Basta editar duas linhas no `.env` do VPS 1 e reiniciar o container:
     ```env
     DATABASE_PRIMARY_URL=postgres://app:pass@10.10.0.2:5432/ptmarket
     DATABASE_REPLICA_URL=postgres://app_ro:pass@10.10.0.3:5432/ptmarket
     ```
   - Todas as pesquisas de catálogo e dashboards das Câmaras passam imediatamente a ler da Réplica, deixando o Primary dedicado a checkouts e pagamentos.