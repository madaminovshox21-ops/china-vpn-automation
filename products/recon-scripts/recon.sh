#!/usr/bin/env bash
# recon.sh - bir domenga to'liq passiv+aktiv recon quvuri
# Foydalanish: ./recon.sh target.com
# ⚠️ Faqat ruxsat berilgan (in-scope) domenlarda ishlating.
set -euo pipefail

DOMAIN="${1:?Foydalanish: ./recon.sh target.com}"
OUT="recon_${DOMAIN}"
mkdir -p "$OUT"
echo "[*] Recon: $DOMAIN -> $OUT/"

echo "[1/6] Subdomenlar..."
{ subfinder -d "$DOMAIN" -all -silent 2>/dev/null || true; \
  assetfinder --subs-only "$DOMAIN" 2>/dev/null || true; } \
  | sort -u > "$OUT/subs.txt"
echo "    topildi: $(wc -l < "$OUT/subs.txt")"

echo "[2/6] Tirik hostlar..."
httpx -l "$OUT/subs.txt" -silent -sc -title -tech-detect -o "$OUT/live.txt" 2>/dev/null || true

echo "[3/6] DNS..."
dnsx -l "$OUT/subs.txt" -a -resp -silent -o "$OUT/dns.txt" 2>/dev/null || true

echo "[4/6] URL yig'ish (arxiv)..."
{ gau "$DOMAIN" 2>/dev/null || true; waybackurls "$DOMAIN" 2>/dev/null || true; } \
  | sort -u > "$OUT/urls.txt"

echo "[5/6] Portlar (top-1000)..."
naabu -host "$DOMAIN" -top-ports 1000 -silent -o "$OUT/ports.txt" 2>/dev/null || true

echo "[6/6] Nuclei (critical,high)..."
if [ -s "$OUT/live.txt" ]; then
  cut -d' ' -f1 "$OUT/live.txt" | nuclei -silent -severity critical,high \
    -o "$OUT/nuclei.txt" 2>/dev/null || true
fi

echo "[+] Tayyor. Natijalar: $OUT/"
