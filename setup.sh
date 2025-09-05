#!/usr/bin/env bash
set -euo pipefail

# chmod +x setup-markdown-to-document.sh
# sudo ./setup-markdown-to-document.sh
# pandoc template.md -o teste.pdf --from markdown --template eisvogel --pdf-engine xelatex -V mainfont="DejaVu Serif" -V sansfont="DejaVu Sans" -V monofont="DejaVu Sans Mono"

EISVOGEL_VERSION="3.2.0"
EISVOGEL_TAR_URL="https://github.com/Wandmalfarbe/pandoc-latex-template/releases/download/v${EISVOGEL_VERSION}/Eisvogel-${EISVOGEL_VERSION}.tar.gz"

# Flags
INSTALL_SYSTEM=true
INSTALL_USER=true
if [[ "${1:-}" == "--user-only" ]]; then
  INSTALL_SYSTEM=false
  INSTALL_USER=true
fi

echo "==> Detectando gerenciador de pacotes..."
if command -v apt-get >/dev/null 2>&1; then
  PKG_MGR="apt"
else
  echo "Este script foi feito para Debian/Ubuntu (apt)."
  echo "Saindo."
  exit 1
fi

echo "==> Atualizando índices de pacotes..."
sudo apt-get update -y

echo "==> Instalando Pandoc, XeLaTeX e pacotes LaTeX necessários..."
sudo apt-get install -y \
  pandoc \
  texlive-xetex \
  texlive-fonts-recommended \
  texlive-latex-recommended \
  texlive-latex-extra \
  texlive-plain-generic

echo "==> Instalando fontes livres (DejaVu, Noto, Ubuntu) ..."
sudo apt-get install -y \
  fonts-dejavu \
  fonts-dejavu-core \
  fonts-dejavu-extra \
  fonts-noto-core \
  fonts-noto-mono \
  fonts-ubuntu \
  fonts-ubuntu-console

echo "==> Instalando Microsoft Core Fonts (inclui Georgia)..."
# instalação não-interativa da EULA
sudo debconf-set-selections <<< "ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true" || true
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ttf-mscorefonts-installer || {
  echo "Aviso: falha ao instalar ttf-mscorefonts-installer. Você pode tentar novamente manualmente depois."
}

echo "==> Atualizando cache de fontes..."
fc-cache -f -v >/dev/null || true

# Locais de templates do Pandoc
USER_TEMPLATES_DIR="${HOME}/.local/share/pandoc/templates"
SYSTEM_TEMPLATES_DIR="/usr/share/pandoc/data/templates"

if $INSTALL_USER; then
  echo "==> Criando diretório de templates do usuário: ${USER_TEMPLATES_DIR}"
  mkdir -p "${USER_TEMPLATES_DIR}"
fi

if $INSTALL_SYSTEM; then
  echo "==> Criando diretório de templates de sistema: ${SYSTEM_TEMPLATES_DIR}"
  sudo mkdir -p "${SYSTEM_TEMPLATES_DIR}"
fi

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "${WORKDIR}"; }
trap cleanup EXIT

echo "==> Baixando Eisvogel v${EISVOGEL_VERSION}..."
wget -q "${EISVOGEL_TAR_URL}" -O "${WORKDIR}/Eisvogel.tar.gz"

echo "==> Extraindo Eisvogel..."
tar -xzf "${WORKDIR}/Eisvogel.tar.gz" -C "${WORKDIR}"

EISVOGEL_DIR="${WORKDIR}/Eisvogel-${EISVOGEL_VERSION}"
if [[ ! -f "${EISVOGEL_DIR}/eisvogel.tex" ]]; then
  echo "Falha: não encontrei eisvogel.tex no tarball."
  exit 1
fi

echo "==> Instalando template 'eisvogel.tex'..."
if $INSTALL_USER; then
  install -m 0644 "${EISVOGEL_DIR}/eisvogel.tex" "${USER_TEMPLATES_DIR}/eisvogel.tex"
  echo "   → Instalado para o usuário em: ${USER_TEMPLATES_DIR}/eisvogel.tex"
fi
if $INSTALL_SYSTEM; then
  sudo install -m 0644 "${EISVOGEL_DIR}/eisvogel.tex" "${SYSTEM_TEMPLATES_DIR}/eisvogel.tex"
  echo "   → Instalado no sistema em: ${SYSTEM_TEMPLATES_DIR}/eisvogel.tex"
fi

echo "==> Verificando presença das fontes-chave..."
for FONT in "Ubuntu" "Georgia" "DejaVu Serif" "DejaVu Sans" "DejaVu Sans Mono" "Noto Serif" "Noto Sans" "Noto Sans Mono"; do
  if fc-list | grep -iq "${FONT}"; then
    echo "   ✔ Fonte encontrada: ${FONT}"
  else
    echo "   ⚠ Fonte NÃO encontrada (pode não ser crítica): ${FONT}"
  fi
done

echo "==> Instalação do Eisvogel concluída!"

cat <<'EOF'

Uso típico (exemplos):

1) Usar as fontes padrão do template (requer que elas estejam instaladas):
   pandoc SEU.md -o saida.pdf --template eisvogel --pdf-engine xelatex

2) Forçar fontes livres que normalmente já estão disponíveis (robusto para CI/servidor):
   pandoc SEU.md -o saida.pdf --template eisvogel --pdf-engine xelatex \
     -V mainfont="DejaVu Serif" \
     -V sansfont="DejaVu Sans" \
     -V monofont="DejaVu Sans Mono"

3) Alternativa com Noto:
   pandoc SEU.md -o saida.pdf --template eisvogel --pdf-engine xelatex \
     -V mainfont="Noto Serif" \
     -V sansfont="Noto Sans" \
     -V monofont="Noto Sans Mono"

Dica:
- Para checar onde o Pandoc procura templates:
    pandoc -v | grep -E 'USER DATA DIR|DATA DIR'
- O seu repo (markdown-to-document) pode chamar o pandoc com as flags acima.

EOF

# Teste opcional (descomentando abaixo, criará um PDF de teste no diretório atual):
#: <<'TESTBLOCK'
# echo "==> Gerando PDF de teste (teste_eisvogel.pdf) usando DejaVu..."
# echo -e "# Título\n\nEste é um teste do template Eisvogel.\n" > /tmp/pandoc_test.md
# pandoc /tmp/pandoc_test.md -o ./teste_eisvogel.pdf --template eisvogel --pdf-engine xelatex \
#   -V mainfont="DejaVu Serif" \
#   -V sansfont="DejaVu Sans" \
#   -V monofont="DejaVu Sans Mono"
# echo "PDF gerado: ./teste_eisvogel.pdf"
# TESTBLOCK
