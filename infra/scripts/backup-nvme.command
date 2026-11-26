#!/bin/bash
# Backup do ptmarket-platform (duplo clique no Finder) → NVMe externo E Google Drive pessoal (pasta sincronizada).
# Tudo numa única imagem encriptada (AES-256; a password é pedida aqui, no Terminal, e nunca fica escrita):
#   git bundle verificado (histórico completo) + memórias do Claude Code deste projeto + os .env reais.
# Fora da imagem só ficam SHA256.txt e LEIA-ME.txt (sem segredos).
# Destinos (decisão do owner, 26/11/2026; exceção à regra 2 do ~/.claude/CLAUDE.md):
#   - NVMe:  /Volumes/NVME-externo/Projetos_backup/
#   - Drive: <Google Drive pessoal>/O meu disco/Backups_PTMarket/ — cópia local que a app do Drive envia sozinha;
#            NUNCA pelo conector do claude.ai (esse pertence à conta da organização). No Drive ficam os 10 mais recentes.
# Basta um destino disponível; sem nenhum, falha.
# Restaurar: abrir ptmarket-backup.dmg (pede a password) → git clone ptmarket-platform.bundle ptmarket-platform;
#            memorias/ → ~/.claude/projects/-Users-nuno-ptmarket-platform/memory/; env/ → mesmo caminho no repo.
set -uo pipefail

REPO="$HOME/ptmarket-platform"
MEM="$HOME/.claude/projects/-Users-nuno-ptmarket-platform/memory"
DISCO="/Volumes/NVME-externo"
NVME_BASE="$DISCO/Projetos_backup"
DRIVE_KEEP=10
NOME="ptmarket-platform-$(date +%Y-%m-%d_%H%M)"

falha() {
  echo
  echo "ERRO: $1"
  echo
  read -r -p "Carrega em Enter para fechar..." _
  exit 1
}

echo "== Backup ptmarket-platform → NVMe + Google Drive =="

[ -d "$REPO/.git" ] || falha "não encontrei o repositório em $REPO"

# --- Destinos disponíveis -------------------------------------------------------------------------------------
DESTINOS=()
if ls "$DISCO" >/dev/null 2>&1; then
  mkdir -p "$NVME_BASE" 2>/dev/null
  if [ -w "$NVME_BASE" ]; then DESTINOS+=("$NVME_BASE"); else echo "AVISO: sem permissão de escrita em $NVME_BASE"; fi
elif [ -e "$DISCO" ]; then
  echo "AVISO: o macOS não deixa ler $DISCO (Definições → Privacidade e Segurança → Acesso total ao disco → Terminal)."
else
  echo "AVISO: o NVMe não está ligado; o backup vai só para o Drive."
fi

DRIVE_RAIZ=""
for d in "$HOME"/Library/CloudStorage/GoogleDrive-*/"O meu disco" "$HOME"/Library/CloudStorage/GoogleDrive-*/"My Drive"; do
  [ -d "$d" ] && { DRIVE_RAIZ="$d"; break; }
done
DRIVE_BASE=""
if [ -n "$DRIVE_RAIZ" ]; then
  DRIVE_BASE="$DRIVE_RAIZ/Backups_PTMarket"
  mkdir -p "$DRIVE_BASE" 2>/dev/null
  if [ -w "$DRIVE_BASE" ]; then DESTINOS+=("$DRIVE_BASE"); else echo "AVISO: sem permissão de escrita em $DRIVE_BASE"; DRIVE_BASE=""; fi
else
  echo "AVISO: não encontrei o Google Drive sincronizado (app Google Drive para computador)."
fi

[ "${#DESTINOS[@]}" -gt 0 ] || falha "nenhum destino disponível (nem NVMe nem Google Drive)"

# --- Preparar o conteúdo (só em disco local, numa pasta 700 apagada no fim) -------------------------------------
STAGE="$(mktemp -d)" || falha "mktemp falhou"
chmod 700 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT
C="$STAGE/conteudo"
mkdir -p "$C"

cd "$REPO" || falha "não consegui entrar em $REPO"
git bundle create "$C/ptmarket-platform.bundle" --all || falha "git bundle falhou"
git bundle verify "$C/ptmarket-platform.bundle" >/dev/null 2>&1 || falha "o bundle não passou na verificação"
git log --oneline -1 > "$C/HEAD.txt"

if [ -d "$MEM" ]; then
  cp -R "$MEM" "$C/memorias" || falha "não consegui copiar as memórias"
else
  echo "AVISO: não encontrei memórias em $MEM"
fi

N=0
while IFS= read -r -d '' f; do
  rel="${f#"$REPO"/}"
  mkdir -p "$C/env/$(dirname "$rel")"
  cp -p "$f" "$C/env/$rel" || falha "não consegui copiar um .env"
  N=$((N + 1))
done < <(find "$REPO" \( -name .git -o -name node_modules -o -name target -o -name .next -o -name worktrees \) -prune \
          -o -type f -name '.env*' ! -name '*.example' -print0)
[ "$N" -gt 0 ] || echo "AVISO: não encontrei ficheiros .env"

echo
echo "Código, memórias e $N ficheiro(s) .env prontos. Escolhe a password da imagem encriptada (pedida duas vezes)."
echo "Guarda-a no teu gestor de passwords: sem ela o backup não se recupera."
IMG="$STAGE/ptmarket-backup.dmg"
hdiutil create -encryption AES-256 -fs APFS -volname "ptmarket-backup" -srcfolder "$C" "$IMG" \
  || falha "hdiutil falhou (a imagem encriptada não foi criada)"
rm -rf "$C"

( cd "$STAGE" && shasum -a 256 ptmarket-backup.dmg > SHA256.txt )
printf 'Último commit: %s\nRestaurar: abrir ptmarket-backup.dmg (pede a password), depois:\n- código: git clone ptmarket-platform.bundle ptmarket-platform\n- memórias: copiar memorias/ para ~/.claude/projects/-Users-nuno-ptmarket-platform/memory/\n- .env: copiar cada ficheiro de env/ para o mesmo caminho dentro do repo\nVerificar: shasum -a 256 -c SHA256.txt\n' \
  "$(cd "$REPO" && git log --oneline -1)" > "$STAGE/LEIA-ME.txt"

# --- Copiar para cada destino e verificar -----------------------------------------------------------------------
OK=0
for base in "${DESTINOS[@]}"; do
  D="$base/$NOME"
  if mkdir -p "$D" && cp "$IMG" "$STAGE/SHA256.txt" "$STAGE/LEIA-ME.txt" "$D/" \
     && ( cd "$D" && shasum -a 256 -c SHA256.txt >/dev/null 2>&1 ); then
    echo "OK: $D"
    OK=$((OK + 1))
  else
    echo "ERRO: a cópia para $D falhou ou não passou na verificação"
  fi
done
[ "$OK" -gt 0 ] || falha "nenhuma cópia ficou verificada"

# Drive: manter só os $DRIVE_KEEP backups mais recentes (os antigos vão para o lixo do Drive).
if [ -n "$DRIVE_BASE" ]; then
  ls -1d "$DRIVE_BASE"/ptmarket-platform-* 2>/dev/null | sort -r | tail -n +"$((DRIVE_KEEP + 1))" | while IFS= read -r velho; do
    rm -rf "$velho" && echo "Drive: removido o backup antigo $(basename "$velho")"
  done
fi

echo
echo "Backup feito em $OK destino(s). No Drive, o envio acaba sozinho em segundo plano (ícone da app do Drive)."
echo
read -r -p "Carrega em Enter para fechar..." _
