# SentryScan — Xavfsizlik tekshiruvi + Raqamli do'kon (Telegram)

Ikki funksiyali Telegram bot:

1. **🛒 Do'kon** — raqamli mahsulotlar (cheat sheet, lab, skript, yopiq kanal)
   Telegram Stars (⭐ XTR) evaziga sotiladi, to'lovdan keyin avtomatik yetkaziladi.
2. **🛡 Xavfsizlik tekshiruvi**
   - **Passiv** (bepul, hammaga): SSL/TLS, HTTP xavfsizlik header'lari, DNS (SPF/DMARC), security.txt.
   - **Faol** (port skani): **faqat tasdiqlangan domenga** — quyidagi chegara bilan.

## ⚖️ Huquqiy chegara (muhim)

Faol skan begona tizimga ishlamaydi. Ruxsat uch yo'l bilan beriladi:

- Foydalanuvchi domenni **DNS-TXT** yoki **fayl** orqali tasdiqlaydi (boshqaruv isboti), yoki
- **Admin** o'sha domen uchun **engagement** (yozma ruxsatga asoslangan) yaratadi — keyin xodimlar skan qila oladi.

Bu bot egasini va mijozni qonuniy himoya qiladi. **Hech qachon ruxsatsiz domenni engagementga qo'shmang.**

## Rollar

- **admin** — to'liq boshqaruv (`.env` dagi `ADMIN_IDS` yoki DB'da `role=admin`).
- **operator** — engagement bor domenlarga faol skan qila oladi (`/addop <tg_id>`).
- **user** — do'kon + passiv skan + o'z domenini tasdiqlab faol skan.

## O'rnatish

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # keyin .env ni to'ldiring
python -m bot.main
```

### `.env`
- `BOT_TOKEN` — @BotFather dan.
- `ADMIN_IDS` — sizning Telegram ID (@userinfobot dan), vergul bilan bir nechta.
- `ENABLE_ACTIVE_SCAN` — `true`/`false`.

## Telegram Stars

To'lov `XTR` valyutasida ishlaydi, provayder token kerak emas. Yig'ilgan Stars'ni
Telegram qoidalari bo'yicha yechib olasiz. To'lovlarni yoqish uchun @BotFather →
bot sozlamalarida hech narsa qo'shimcha shart emas (Stars standart yoqilgan).

## Buyruqlar

| Buyruq | Kim | Vazifa |
|---|---|---|
| `/start`, `/help` | hamma | menyu, yordam |
| `/shop` | hamma | do'kon |
| `/verify` | hamma | domen tasdiqlash |
| `/check <domen>` | hamma | tasdiqni tekshirish |
| `/admin` | admin | admin panel |
| `/addop`, `/delop <id>` | admin | operator qo'shish/olib tashlash |
| `/addeng` | admin | engagement yaratish |
| `/toggle <id>` | admin | mahsulotni yoq/o'chir |

## Struktura

```
bot/
  config.py          # .env sozlamalari
  db.py              # SQLite (aiosqlite)
  access.py          # rol va ruxsat chegarasi
  states.py          # FSM holatlari
  keyboards.py       # tugmalar
  main.py            # kirish nuqtasi
  services/
    scanner.py       # passiv + gated faol skan
    verify.py        # DNS-TXT / fayl tasdiqlash
  handlers/
    common.py store.py security.py admin.py
```

## Do'kon mahsulotlari (avtomatik seed)

Bot ishga tushganda `products/catalog.json` o'qiladi va mahsulotlar bazaga
avtomatik qo'shiladi (idempotent — takror qo'shilmaydi). Tayyor mahsulotlar:

| Mahsulot | Narx | Fayl |
|---|---|---|
| Web Pentest Cheat Sheet | ⭐150 | `web-pentest-cheatsheet.pdf` |
| CTF Writeups Pack | ⭐120 | `ctf-writeups.pdf` |
| Recon Scripts Pack | ⭐200 | `recon-scripts.zip` |
| Nuclei Templates Pack | ⭐180 | `nuclei-templates.zip` |

Yangi mahsulot qo'shish: faylni `products/` ga qo'ying, `catalog.json` ga yozuv
qo'shing (`kind: "path"`, `file: "..."`). Markdown'dan PDF: `python tools/build_cheatsheet_pdf.py products/yangi.md`.

Yetkazish turlari: `path` (lokal fayl), `file` (Telegram file_id), `link`, `text`.

## Mijoz jalb qilish

`docs/` papkada tayyor matnlar:
- `docs/upwork-profile.md` — Upwork profil (title, overview, skills, narx)
- `docs/client-outreach.md` — taklif xatlari, bepul→pullik voronka, bot lead-magnet

## Deploy (server)

Oddiy VPS'da systemd bilan doimiy ishlatish:

```ini
# /etc/systemd/system/sentryscan.service
[Unit]
Description=SentryScan
After=network.target
[Service]
WorkingDirectory=/opt/sentryscan
ExecStart=/opt/sentryscan/.venv/bin/python -m bot.main
Restart=always
[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now sentryscan
```
