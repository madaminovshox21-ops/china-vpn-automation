# Recon Scripts Pack

Bir domenga to'liq recon uchun tayyor bash skriptlar to'plami.

## Skriptlar

- **recon.sh** — subdomen → tirik host → DNS → arxiv URL → port → nuclei quvuri.
- **quick-ssl.sh** — SSL sertifikat, xavfsizlik header'lari, TLS versiyalari.

## Kerakli toollar

`subfinder`, `assetfinder`, `httpx`, `dnsx`, `gau`, `waybackurls`, `naabu`, `nuclei`,
`openssl`, `curl`. (ProjectDiscovery toollari: https://github.com/projectdiscovery)

## Foydalanish

```bash
chmod +x *.sh
./recon.sh target.com
./quick-ssl.sh target.com
```

> ⚠️ Faqat sizga tegishli yoki yozma ruxsat berilgan domenlarda ishlating.
