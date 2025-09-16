#!/usr/bin/env bash
set -euo pipefail
# pandoc lumma_report.md -o lumma_report.pdf --template eisvogel --pdf-engine xelatex -V mainfont="DejaVu Serif" -V sansfont="DejaVu Sans" -V monofont="DejaVu Sans Mono"
FILE="${FILE:-lumma_report.md}"
PDF="${PDF:-lumma_report.pdf}"

hash_file() { md5sum "$FILE" | awk '{print $1}'; }

build_pdf() {
  echo -ne "\nTime: $(date +"%d/%m/%Y %H:%M:%S") - (re)construindo PDF 🛠️ "
  pandoc "$FILE" -o "$PDF" --from markdown --template eisvogel --pdf-engine xelatex \
    -V mainfont="DejaVu Serif" -V sansfont="DejaVu Sans" -V monofont="DejaVu Sans Mono" \
    && echo "✅" || echo "❌"
}

md5_old="$(hash_file)"

# Compila logo no início se o PDF não existir
if [[ ! -f "$PDF" ]]; then
  build_pdf
fi

while true; do
  sleep 5
  md5_new="$(hash_file)"

  if [[ "$md5_old" != "$md5_new" || ! -f "$PDF" ]]; then
    build_pdf
    md5_old="$md5_new"
  else
    echo -ne "\nTime: $(date +"%d/%m/%Y %H:%M:%S") - Nenhuma mudança ❌"
  fi
done
