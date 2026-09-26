# Nuclei Templates Pack

Keng tarqalgan noto'g'ri sozlamalarni aniqlash uchun tayyor Nuclei shablonlari.

## Shablonlar

- **exposed-env.yaml** — ochiq `.env` (maxfiy kalitlar sizishi) — high
- **exposed-git.yaml** — ochiq `.git/config` (manba kod sizishi) — medium
- **missing-security-headers.yaml** — HSTS/CSP/X-Frame yo'qligi — info

## Foydalanish

```bash
nuclei -u https://target.com -t exposed-env.yaml
# yoki butun papka:
nuclei -l live.txt -t ./nuclei-templates/
```

Nuclei: https://github.com/projectdiscovery/nuclei

> ⚠️ Faqat ruxsat berilgan nishonlarda ishlating.
