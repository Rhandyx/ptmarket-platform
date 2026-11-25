---
description: Auditoria visual e funcional automática da Demo Municipal usando o Browser Subagent do AGY.
---
1. Garante que o backend Rust, worker Go e frontend Next.js estão a correr localmente.
2. Usa o **Browser Subagent** para abrir a montra simulando o domínio municipal (`demo.ptmarket.pt`) em viewport Desktop (1440px) e Mobile (390px):
   - Verifica se as cores, logótipo e template `bairro` carregam sem erros na consola.
   - Adiciona ao carrinho 1 artigo da Padaria Central (IVA 6%) + 1 da Garrafeira (IVA 23%) + 1 do Artesanato (Art. 53.º 0%).
   - Percorre o fluxo de checkout até à geração do pedido multi-loja e valida o cálculo exato do total e das 3 sub-encomendas.
3. Abre `admin.ptmarket.pt` como `super_admin` e verifica o carregamento do **Data Studio** em modo Read-Only.
4. Tira capturas de ecrã (screenshots) e inclui no Artifact de relatório de QA.
