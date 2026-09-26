#!/usr/bin/env bash
# quick-ssl.sh - domen SSL/TLS va xavfsizlik header'larini tez tekshirish
# Foydalanish: ./quick-ssl.sh target.com
set -euo pipefail
D="${1:?Foydalanish: ./quick-ssl.sh target.com}"

echo "=== SSL sertifikat: $D ==="
echo | openssl s_client -servername "$D" -connect "$D:443" 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates 2>/dev/null || echo "SSL ulanmadi"

echo; echo "=== Xavfsizlik header'lari ==="
curl -sSI "https://$D" | grep -iE \
  "strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy" \
  || echo "Muhim header'lar topilmadi"

echo; echo "=== TLS versiyalari ==="
for v in tls1 tls1_1 tls1_2 tls1_3; do
  if echo | openssl s_client -"$v" -connect "$D:443" >/dev/null 2>&1; then
    echo "  $v: yoqilgan"
  fi
done
