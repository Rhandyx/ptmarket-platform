---
description: Fluxo estruturado para implementar uma nova funcionalidade ponta-a-ponta com Artifact de Planeamento.
---
1. **Fase de Planeamento (Cérebro Mestre):** Lê os documentos relevantes em `docs/specs/` e cria um Artifact `Implementation Plan` detalhando:
   - Alterações SQL em `/migrations`
   - Endpoints/Structs em `/backend-rust` + atualização OpenAPI
   - Tarefas assíncronas em `/workers-go` (se aplicável)
   - Componentes em `/frontend-web`
   - Plano de verificação e testes
2. **Aguarda aprovação do utilizador** no Artifact antes de editar ficheiros críticos.
3. **Execução Sequencial:** Aplica SQL -> Backend Rust -> Go Workers -> Regeneração OpenAPI -> Frontend Next.js.
4. **Verificação:** Corre `cargo test`, `go test ./...` e `npm run typecheck`.
5. **Walkthrough:** Gera um Artifact `Walkthrough` resumindo o que foi construído e os resultados dos testes.
