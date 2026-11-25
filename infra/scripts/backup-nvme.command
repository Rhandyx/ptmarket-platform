#!/bin/bash
# Backup do repositório ptmarket-platform para o NVMe externo (duplo clique no Finder).
# Cria um git bundle verificado (histórico completo). Sem .env nem memórias, por regra.
# Restaurar: git clone ptmarket-platform.bundle ptmarket-platform
set -uo pipefail

REPO="$HOME/ptmarket-platform"
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
shasum -a 256 "$D/ptmarket-platform.bundle" > "$D/SHA256.txt"
printf 'Restaurar: git clone ptmarket-platform.bundle ptmarket-platform\nSem .env nem memórias (por regra). Último commit em HEAD.txt.\n' > "$D/LEIA-ME.txt"

echo
echo "OK: backup criado em $D"
ls -lh "$D"
echo
read -r -p "Carrega em Enter para fechar..." _
