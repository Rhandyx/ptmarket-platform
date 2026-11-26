#!/bin/bash
# Backup do repositório ptmarket-platform para o NVMe externo (duplo clique no Finder).
# Cria um git bundle verificado (histórico completo), uma cópia das memórias do Claude Code deste projeto e
# os .env numa imagem encriptada (AES-256; a password é pedida aqui, no Terminal, e nunca fica escrita).
# Exceção à regra 2 do ~/.claude/CLAUDE.md, decidida pelo owner a 26/11/2026: só para este disco pessoal.
# Restaurar: git clone ptmarket-platform.bundle ptmarket-platform · memorias/ → ~/.claude/projects/<projeto>/memory/
#            .env: abrir segredos-env.dmg (pede a password) e copiar cada ficheiro para o mesmo caminho no repo.
set -uo pipefail

REPO="$HOME/ptmarket-platform"
MEM="$HOME/.claude/projects/-Users-nuno-ptmarket-platform/memory"
DISCO="/Volumes/NVME-externo"
BASE="$DISCO/Projetos_backup"

falha() {
  echo
  echo "ERRO: $1"
  echo
  read -r -p "Carrega em Enter para fechar..." _
  exit 1
}

echo "== Backup ptmarket-platform → NVMe =="

[ -d "$REPO/.git" ] || falha "não encontrei o repositório em $REPO"

if ! ls "$DISCO" >/dev/null 2>&1; then
  echo "O macOS não deixa esta app ler $DISCO."
  echo "A abrir Definições do Sistema → Privacidade e Segurança → Acesso total ao disco."
  echo "Liga o Terminal (ou o iTerm) na lista, fecha-o completamente e volta a fazer duplo clique neste ficheiro."
  open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null
  falha "sem acesso ao disco externo ($DISCO). O disco está ligado? Aparece no Finder?"
fi

[ -w "$BASE" ] || [ -w "$DISCO" ] || falha "sem permissão de escrita em $BASE"

D="$BASE/ptmarket-platform-$(date +%Y-%m-%d_%H%M)"
mkdir -p "$D" || falha "não consegui criar $D"

cd "$REPO" || falha "não consegui entrar em $REPO"
git bundle create "$D/ptmarket-platform.bundle" --all || falha "git bundle falhou"
git bundle verify "$D/ptmarket-platform.bundle" >/dev/null 2>&1 || falha "o bundle não passou na verificação"
git log --oneline -1 > "$D/HEAD.txt"

# Memórias (texto; ficam só neste disco pessoal).
if [ -d "$MEM" ]; then
  cp -R "$MEM" "$D/memorias" || falha "não consegui copiar as memórias"
else
  echo "AVISO: não encontrei memórias em $MEM"
fi

# .env (reais, não os .example) → imagem encriptada. Nada é mostrado no ecrã.
STAGE="$(mktemp -d)" || falha "mktemp falhou"
chmod 700 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT
N=0
while IFS= read -r -d '' f; do
  rel="${f#"$REPO"/}"
  mkdir -p "$STAGE/env/$(dirname "$rel")"
  cp -p "$f" "$STAGE/env/$rel" || falha "não consegui copiar um .env"
  N=$((N + 1))
done < <(find "$REPO" \( -name .git -o -name node_modules -o -name target -o -name .next -o -name worktrees \) -prune \
          -o -type f -name '.env*' ! -name '*.example' -print0)
if [ "$N" -gt 0 ]; then
  echo
  echo "Encontrei $N ficheiro(s) .env. Escolhe a password da imagem encriptada (pedida duas vezes)."
  echo "Guarda-a fora deste disco (ex.: no teu gestor de passwords): sem ela os .env não se recuperam."
  hdiutil create -encryption AES-256 -fs APFS -volname "ptmarket-env" \
    -srcfolder "$STAGE/env" "$D/segredos-env.dmg" || falha "hdiutil falhou (a imagem encriptada não foi criada)"
else
  echo "AVISO: não encontrei ficheiros .env"
fi
rm -rf "$STAGE"

if [ -f "$D/segredos-env.dmg" ]; then
  ( cd "$D" && shasum -a 256 ptmarket-platform.bundle segredos-env.dmg > SHA256.txt )
else
  ( cd "$D" && shasum -a 256 ptmarket-platform.bundle > SHA256.txt )
fi
printf 'Restaurar:\n- código: git clone ptmarket-platform.bundle ptmarket-platform (último commit em HEAD.txt)\n- memórias: copiar memorias/ para ~/.claude/projects/-Users-nuno-ptmarket-platform/memory/\n- .env: abrir segredos-env.dmg (pede a password) e copiar cada ficheiro para o mesmo caminho dentro do repo\n' > "$D/LEIA-ME.txt"

echo
echo "OK: backup criado em $D"
ls -lh "$D"
echo
read -r -p "Carrega em Enter para fechar..." _
